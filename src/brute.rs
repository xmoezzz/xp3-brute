use crate::compute::{
    gpu_adler_search, gpu_slot_scores, note_cpu_slot_job, AdlerGpuChoice, AdlerGpuProblem,
    AdlerGpuSlot, ComputeMode,
};
use crate::repeating_xor::PeriodCandidate;
use std::collections::HashMap;

const ADLER_MOD: u32 = 65_521;

#[derive(Clone, Debug)]
pub struct PlainByteConstraint {
    pub offset: u64,
    pub allowed: Vec<u8>,
}

impl PlainByteConstraint {
    pub fn new(offset: u64, allowed: impl AsRef<[u8]>) -> Self {
        Self {
            offset,
            allowed: allowed.as_ref().to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeyByteCandidate {
    pub value: u8,
    /// Optional heuristic score. Hard constraints are represented by removing
    /// impossible candidates, never merely by lowering this score.
    pub score: f64,
}

#[derive(Clone, Debug)]
pub struct KeySlotCandidates {
    pub slot: usize,
    pub candidates: Vec<KeyByteCandidate>,
}

#[derive(Clone, Debug)]
pub struct KeySpace {
    pub period: usize,
    /// Only slots that are actually referenced by this file need a value.
    pub used_slots: usize,
    pub slots: Vec<KeySlotCandidates>,
    pub ambiguous_slots: usize,
    pub entropy_bits: f64,
    pub combinations: Option<u128>,
}

impl KeySpace {
    pub fn is_complete(&self) -> bool {
        self.slots.iter().all(|slot| slot.candidates.len() == 1)
    }

    pub fn key_if_complete(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut key = vec![0u8; self.period];
        for slot in &self.slots {
            key[slot.slot] = slot.candidates[0].value;
        }
        Some(key)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BruteLimits {
    /// Exhaustive enumeration is allowed below this many full combinations.
    pub max_combinations: u128,
    /// Meet-in-the-middle is allowed when each half fits below this limit.
    pub max_mitm_half_combinations: u128,
    pub max_solutions: usize,
}

impl Default for BruteLimits {
    fn default() -> Self {
        Self {
            max_combinations: 1u128 << 24,
            max_mitm_half_combinations: 1u128 << 20,
            max_solutions: 4,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BruteSearchResult {
    pub keys: Vec<Vec<u8>>,
    pub used_mitm: bool,
    pub used_gpu: bool,
    pub gpu_adapter: Option<String>,
    pub combinations_considered: u128,
}

pub fn candidate_is_complete_for_len(candidate: &PeriodCandidate, len: usize) -> bool {
    let used = candidate.period.min(len);
    candidate.conflicts == 0 && candidate.key.iter().take(used).all(|value| value.is_some())
}

/// Build the exact candidate set for every used key slot. Known plaintext cribs
/// have already populated `candidate.key`; non-singleton plaintext constraints
/// intersect the remaining 0..255 key-byte possibilities.
pub fn build_key_space(
    ciphertext: &[u8],
    candidate: &PeriodCandidate,
    constraints: &[PlainByteConstraint],
) -> Option<KeySpace> {
    if candidate.period == 0 || candidate.conflicts != 0 {
        return None;
    }
    let used_slots = candidate.period.min(ciphertext.len());
    let mut allowed = vec![[true; 256]; used_slots];

    for slot in 0..used_slots {
        if let Some(value) = candidate.key.get(slot).copied().flatten() {
            allowed[slot].fill(false);
            allowed[slot][value as usize] = true;
        }
    }

    for constraint in constraints {
        let Ok(offset) = usize::try_from(constraint.offset) else {
            continue;
        };
        if offset >= ciphertext.len() || constraint.allowed.is_empty() {
            continue;
        }
        let slot = offset % candidate.period;
        if slot >= used_slots {
            continue;
        }
        let mut permitted_keys = [false; 256];
        for &plain in &constraint.allowed {
            permitted_keys[(ciphertext[offset] ^ plain) as usize] = true;
        }
        for value in 0..256 {
            allowed[slot][value] &= permitted_keys[value];
        }
    }

    let mut slots = Vec::with_capacity(used_slots);
    let mut ambiguous_slots = 0usize;
    let mut entropy_bits = 0.0f64;
    let mut combinations = Some(1u128);

    for (slot, bits) in allowed.into_iter().enumerate() {
        let candidates: Vec<KeyByteCandidate> = bits
            .iter()
            .enumerate()
            .filter_map(|(value, &yes)| {
                yes.then_some(KeyByteCandidate {
                    value: value as u8,
                    score: 0.0,
                })
            })
            .collect();
        if candidates.is_empty() {
            return None;
        }
        if candidates.len() > 1 {
            ambiguous_slots += 1;
            entropy_bits += (candidates.len() as f64).log2();
        }
        combinations = combinations.and_then(|total| total.checked_mul(candidates.len() as u128));
        slots.push(KeySlotCandidates { slot, candidates });
    }

    Some(KeySpace {
        period: candidate.period,
        used_slots,
        slots,
        ambiguous_slots,
        entropy_bits,
        combinations,
    })
}

fn fwht(values: &mut [f64; 256]) {
    let mut width = 1usize;
    while width < 256 {
        let step = width * 2;
        let mut base = 0usize;
        while base < 256 {
            for offset in 0..width {
                let a = values[base + offset];
                let b = values[base + offset + width];
                values[base + offset] = a + b;
                values[base + offset + width] = a - b;
            }
            base += step;
        }
        width = step;
    }
}

fn xor_correlation(histogram: &[u64; 256], log_probability: &[f64; 256]) -> [f64; 256] {
    let mut left = [0.0f64; 256];
    let mut right = *log_probability;
    for i in 0..256 {
        left[i] = histogram[i] as f64;
    }
    fwht(&mut left);
    fwht(&mut right);
    for i in 0..256 {
        left[i] *= right[i];
    }
    fwht(&mut left);
    for value in &mut left {
        *value /= 256.0;
    }
    left
}

/// Score all 256 candidate bytes for unresolved key slots against a plaintext
/// byte-distribution template learned from already-known residues of the same
/// file. This is a heuristic accelerator, not a correctness oracle: pruning is
/// performed only when the sample count and likelihood separation exceed the
/// supplied thresholds, and callers must still validate the final key.
pub fn refine_key_space_with_histogram(
    ciphertext: &[u8],
    candidate: &PeriodCandidate,
    space: &mut KeySpace,
    top_k: usize,
    min_slot_samples: usize,
    min_log_likelihood_gap: f64,
    singleton_log_likelihood_gap: f64,
) -> (usize, usize) {
    refine_key_space_with_histogram_compute(
        ciphertext,
        candidate,
        space,
        top_k,
        min_slot_samples,
        min_log_likelihood_gap,
        singleton_log_likelihood_gap,
        ComputeMode::Cpu,
        usize::MAX,
    )
    .unwrap_or((0, 0))
}

/// GPU-assisted 256-way residue scoring. The GPU evaluates the same XOR byte
/// likelihood table for every eligible key slot in one dispatch. It is only a
/// heuristic reducer: final plaintext still has to pass the independent format
/// grammar and XP3 Adler validation. Auto/hybrid fall back to the exact CPU
/// FWHT scorer when the accelerator is unavailable or busy.
pub fn refine_key_space_with_histogram_compute(
    ciphertext: &[u8],
    candidate: &PeriodCandidate,
    space: &mut KeySpace,
    top_k: usize,
    min_slot_samples: usize,
    min_log_likelihood_gap: f64,
    singleton_log_likelihood_gap: f64,
    compute_mode: ComputeMode,
    gpu_min_slot_candidates: usize,
) -> Result<(usize, usize), String> {
    if top_k == 0 || candidate.period == 0 || ciphertext.is_empty() {
        return Ok((0, 0));
    }

    let mut template = [0u64; 256];
    let mut template_total = 0u64;
    let used = candidate.period.min(ciphertext.len());
    for slot in 0..used {
        let Some(key) = candidate.key.get(slot).copied().flatten() else {
            continue;
        };
        let mut position = slot;
        while position < ciphertext.len() {
            template[(ciphertext[position] ^ key) as usize] += 1;
            template_total += 1;
            position += candidate.period;
        }
    }
    if template_total < 512 {
        return Ok((0, 0));
    }

    let alpha = 0.5f64;
    let denominator = template_total as f64 + alpha * 256.0;
    let mut log_probability = [0.0f64; 256];
    for value in 0..256 {
        log_probability[value] = ((template[value] as f64 + alpha) / denominator).ln();
    }

    struct ScoreJob {
        space_index: usize,
        hist_u64: [u64; 256],
        hist_u32: [u32; 256],
    }
    let mut jobs = Vec::new();
    for (space_index, slot) in space.slots.iter().enumerate() {
        if slot.candidates.len() <= top_k || slot.candidates.len() <= 1 {
            continue;
        }
        let mut hist_u64 = [0u64; 256];
        let mut samples = 0usize;
        let mut position = slot.slot;
        while position < ciphertext.len() {
            hist_u64[ciphertext[position] as usize] += 1;
            samples += 1;
            position += candidate.period;
        }
        if samples < min_slot_samples {
            continue;
        }
        let mut hist_u32 = [0u32; 256];
        for i in 0..256 {
            hist_u32[i] = hist_u64[i].min(u32::MAX as u64) as u32;
        }
        jobs.push(ScoreJob {
            space_index,
            hist_u64,
            hist_u32,
        });
    }
    if jobs.is_empty() {
        return Ok((0, 0));
    }

    let gpu_histograms: Vec<[u32; 256]> = jobs.iter().map(|job| job.hist_u32).collect();
    let gpu = gpu_slot_scores(
        compute_mode,
        &gpu_histograms,
        &log_probability,
        gpu_min_slot_candidates,
    )?;
    let gpu_scores = gpu.map(|result| result.scores);
    if gpu_scores.is_none() {
        note_cpu_slot_job();
    }

    let mut reduced = 0usize;
    let mut singleton = 0usize;
    for (job_index, job) in jobs.iter().enumerate() {
        let scores = if let Some(rows) = gpu_scores.as_ref() {
            rows[job_index]
        } else {
            xor_correlation(&job.hist_u64, &log_probability)
        };
        let slot = &mut space.slots[job.space_index];
        for key_candidate in &mut slot.candidates {
            key_candidate.score = scores[key_candidate.value as usize];
        }
        slot.candidates.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.value.cmp(&b.value))
        });

        if slot.candidates.len() > 1 {
            let best = slot.candidates[0].score;
            let second = slot.candidates[1].score;
            if best - second >= singleton_log_likelihood_gap {
                slot.candidates.truncate(1);
                reduced += 1;
                singleton += 1;
                continue;
            }
        }
        if slot.candidates.len() > top_k {
            let best = slot.candidates[0].score;
            let first_excluded = slot.candidates[top_k].score;
            if best - first_excluded >= min_log_likelihood_gap {
                slot.candidates.truncate(top_k);
                reduced += 1;
            }
        }
    }

    space.ambiguous_slots = 0;
    space.entropy_bits = 0.0;
    space.combinations = Some(1);
    for slot in &space.slots {
        if slot.candidates.len() > 1 {
            space.ambiguous_slots += 1;
            space.entropy_bits += (slot.candidates.len() as f64).log2();
        }
        space.combinations = space
            .combinations
            .and_then(|total| total.checked_mul(slot.candidates.len() as u128));
    }
    Ok((reduced, singleton))
}

#[derive(Clone, Copy, Debug)]
struct Contribution {
    a: u32,
    b: u32,
}

#[derive(Clone, Debug)]
struct PreparedSlot {
    slot: usize,
    choices: Vec<(u8, Contribution)>,
}

fn slot_contribution(ciphertext: &[u8], period: usize, slot: usize, key: u8) -> Contribution {
    let n = ciphertext.len();
    let mut a = 0u64;
    let mut b = 0u64;
    let mut position = slot;
    while position < n {
        let plain = ciphertext[position] ^ key;
        a += plain as u64;
        b += ((n - position) as u64) * plain as u64;
        position += period;
    }
    Contribution {
        a: (a % ADLER_MOD as u64) as u32,
        b: (b % ADLER_MOD as u64) as u32,
    }
}

fn mod_sub(lhs: u32, rhs: u32) -> u32 {
    (lhs + ADLER_MOD - (rhs % ADLER_MOD)) % ADLER_MOD
}

fn pack_pair(a: u32, b: u32) -> u32 {
    (a & 0xffff) | ((b & 0xffff) << 16)
}

fn assignment_product(slots: &[PreparedSlot]) -> Option<u128> {
    slots.iter().try_fold(1u128, |acc, slot| {
        acc.checked_mul(slot.choices.len() as u128)
    })
}

fn build_base_key(space: &KeySpace) -> Vec<u8> {
    let mut key = vec![0u8; space.period];
    for slot in &space.slots {
        if slot.candidates.len() == 1 {
            key[slot.slot] = slot.candidates[0].value;
        }
    }
    key
}

fn fixed_contribution(ciphertext: &[u8], space: &KeySpace) -> Contribution {
    let mut a = 0u32;
    let mut b = 0u32;
    for slot in &space.slots {
        if slot.candidates.len() == 1 {
            let c = slot_contribution(
                ciphertext,
                space.period,
                slot.slot,
                slot.candidates[0].value,
            );
            a = (a + c.a) % ADLER_MOD;
            b = (b + c.b) % ADLER_MOD;
        }
    }
    Contribution { a, b }
}

fn prepare_ambiguous_slots(ciphertext: &[u8], space: &KeySpace) -> Vec<PreparedSlot> {
    space
        .slots
        .iter()
        .filter(|slot| slot.candidates.len() > 1)
        .map(|slot| PreparedSlot {
            slot: slot.slot,
            choices: slot
                .candidates
                .iter()
                .map(|candidate| {
                    (
                        candidate.value,
                        slot_contribution(ciphertext, space.period, slot.slot, candidate.value),
                    )
                })
                .collect(),
        })
        .collect()
}

fn split_balanced(slots: &[PreparedSlot]) -> (Vec<PreparedSlot>, Vec<PreparedSlot>) {
    let mut sorted = slots.to_vec();
    sorted.sort_by_key(|slot| std::cmp::Reverse(slot.choices.len()));
    let mut left = Vec::new();
    let mut right = Vec::new();
    let mut left_log = 0.0f64;
    let mut right_log = 0.0f64;
    for slot in sorted {
        let cost = (slot.choices.len() as f64).log2();
        if left_log <= right_log {
            left.push(slot);
            left_log += cost;
        } else {
            right.push(slot);
            right_log += cost;
        }
    }
    (left, right)
}

fn enumerate_group<F>(
    slots: &[PreparedSlot],
    index: usize,
    sum_a: u32,
    sum_b: u32,
    values: &mut Vec<u8>,
    callback: &mut F,
) -> bool
where
    F: FnMut(u32, u32, &[u8]) -> bool,
{
    if index == slots.len() {
        return callback(sum_a, sum_b, values);
    }
    let slot = &slots[index];
    for &(value, contribution) in &slot.choices {
        values.push(value);
        let stop = enumerate_group(
            slots,
            index + 1,
            (sum_a + contribution.a) % ADLER_MOD,
            (sum_b + contribution.b) % ADLER_MOD,
            values,
            callback,
        );
        values.pop();
        if stop {
            return true;
        }
    }
    false
}

fn target_sums(expected_adler: u32, len: usize) -> (u32, u32) {
    let final_a = expected_adler & 0xffff;
    let final_b = expected_adler >> 16;
    let target_a = mod_sub(final_a, 1);
    let target_b = mod_sub(final_b, (len as u64 % ADLER_MOD as u64) as u32);
    (target_a, target_b)
}

/// Exhaustively enumerate a key space when it is already small enough. This is
/// the fallback for entries without XP3 `adlr`; callers must validate every
/// returned plaintext with an independent format parser.
pub fn enumerate_key_space(space: &KeySpace, limits: BruteLimits) -> BruteSearchResult {
    let Some(total) = space.combinations else {
        return BruteSearchResult::default();
    };
    if total > limits.max_combinations {
        return BruteSearchResult::default();
    }
    let ambiguous: Vec<&KeySlotCandidates> = space
        .slots
        .iter()
        .filter(|slot| slot.candidates.len() > 1)
        .collect();
    if ambiguous.is_empty() {
        return BruteSearchResult {
            keys: space.key_if_complete().into_iter().collect(),
            used_mitm: false,
            used_gpu: false,
            gpu_adapter: None,
            combinations_considered: 1,
        };
    }
    let base = build_base_key(space);
    let mut result = BruteSearchResult::default();
    fn walk(
        slots: &[&KeySlotCandidates],
        index: usize,
        key: &mut Vec<u8>,
        limits: BruteLimits,
        result: &mut BruteSearchResult,
    ) -> bool {
        if index == slots.len() {
            result.combinations_considered = result.combinations_considered.saturating_add(1);
            result.keys.push(key.clone());
            return result.keys.len() >= limits.max_solutions;
        }
        let slot = slots[index];
        for candidate in &slot.candidates {
            key[slot.slot] = candidate.value;
            if walk(slots, index + 1, key, limits, result) {
                return true;
            }
        }
        false
    }
    let mut key = base;
    walk(&ambiguous, 0, &mut key, limits, &mut result);
    result
}

/// Exhaustively search a bounded key space and retain only keys accepted by an
/// independent predicate. This is useful when `adlr` is absent but a strong
/// file-format validator is available.
pub fn search_key_space_with_predicate<F>(
    space: &KeySpace,
    limits: BruteLimits,
    mut accept: F,
) -> BruteSearchResult
where
    F: FnMut(&[u8]) -> bool,
{
    let Some(total) = space.combinations else {
        return BruteSearchResult::default();
    };
    if total > limits.max_combinations {
        return BruteSearchResult::default();
    }
    let ambiguous: Vec<&KeySlotCandidates> = space
        .slots
        .iter()
        .filter(|slot| slot.candidates.len() > 1)
        .collect();
    let mut result = BruteSearchResult::default();
    let mut key = build_base_key(space);

    fn walk<F>(
        slots: &[&KeySlotCandidates],
        index: usize,
        key: &mut [u8],
        limits: BruteLimits,
        result: &mut BruteSearchResult,
        accept: &mut F,
    ) -> bool
    where
        F: FnMut(&[u8]) -> bool,
    {
        if index == slots.len() {
            result.combinations_considered = result.combinations_considered.saturating_add(1);
            if accept(key) {
                result.keys.push(key.to_vec());
                return result.keys.len() >= limits.max_solutions;
            }
            return false;
        }
        let slot = slots[index];
        for candidate in &slot.candidates {
            key[slot.slot] = candidate.value;
            if walk(slots, index + 1, key, limits, result, accept) {
                return true;
            }
        }
        false
    }

    walk(&ambiguous, 0, &mut key, limits, &mut result, &mut accept);
    result
}

/// GPU-assisted variant of the direct Adler search.  The GPU evaluates only
/// the two modular Adler equations.  Every checksum hit is reconstructed into a
/// full key and passed through `accept` on the CPU, so GPU use cannot weaken the
/// final file-format validation.
pub fn search_key_space_with_adler_predicate_compute<F>(
    ciphertext: &[u8],
    space: &KeySpace,
    expected_adler: u32,
    limits: BruteLimits,
    compute_mode: ComputeMode,
    gpu_min_combinations: u128,
    mut accept: F,
) -> Result<BruteSearchResult, String>
where
    F: FnMut(&[u8]) -> bool,
{
    let ambiguous = prepare_ambiguous_slots(ciphertext, space);
    let total = assignment_product(&ambiguous);

    // The first accelerator intentionally targets the exhaustive branch.  The
    // existing CPU MITM stays authoritative for larger spaces; this keeps the
    // GPU kernel branch-free and makes fallback lossless.
    if !ambiguous.is_empty()
        && total.is_some_and(|count| count <= limits.max_combinations && count <= u32::MAX as u128)
    {
        let fixed = fixed_contribution(ciphertext, space);
        let (target_a, target_b) = target_sums(expected_adler, ciphertext.len());
        let need_a = mod_sub(target_a, fixed.a);
        let need_b = mod_sub(target_b, fixed.b);
        let total_u32 = total.unwrap() as u32;
        let problem = AdlerGpuProblem {
            total_combinations: total_u32,
            need_a,
            need_b,
            slots: ambiguous
                .iter()
                .map(|slot| AdlerGpuSlot {
                    key_slot: slot.slot,
                    choices: slot
                        .choices
                        .iter()
                        .map(|&(value, contribution)| AdlerGpuChoice {
                            value,
                            a: contribution.a,
                            b: contribution.b,
                        })
                        .collect(),
                })
                .collect(),
        };

        if let Some(gpu) = gpu_adler_search(compute_mode, &problem, gpu_min_combinations)? {
            let base = build_base_key(space);
            let mut result = BruteSearchResult {
                keys: Vec::new(),
                used_mitm: false,
                used_gpu: true,
                gpu_adapter: Some(gpu.adapter_name),
                combinations_considered: total.unwrap(),
            };

            for assignment_index in gpu.hit_indices {
                let mut mixed = assignment_index as usize;
                let mut key = base.clone();
                for slot in &ambiguous {
                    let radix = slot.choices.len();
                    let digit = mixed % radix;
                    mixed /= radix;
                    key[slot.slot] = slot.choices[digit].0;
                }
                if accept(&key) {
                    result.keys.push(key);
                    if result.keys.len() >= limits.max_solutions {
                        break;
                    }
                }
            }
            return Ok(result);
        }
    } else if compute_mode == ComputeMode::Gpu
        && total.is_some_and(|count| count > limits.max_combinations)
    {
        // Explicit GPU mode still falls through to CPU MITM. GPU acceleration
        // currently covers direct enumeration, not the hash-table MITM branch.
    }

    Ok(search_key_space_with_adler_predicate(
        ciphertext,
        space,
        expected_adler,
        limits,
        accept,
    ))
}

/// Search a candidate key space using the XP3 Adler-32 as two modular global
/// equations. Small spaces are exhaustively enumerated. Larger but separable
/// spaces use meet-in-the-middle over `(sum(bytes), weighted_sum(bytes))`.
///
/// Adler-32 is only a 32-bit constraint, so callers that need a unique plaintext
/// should prefer [`search_key_space_with_adler_predicate`] and apply an
/// independent file-format grammar to every checksum-consistent key.
pub fn search_key_space_with_adler(
    ciphertext: &[u8],
    space: &KeySpace,
    expected_adler: u32,
    limits: BruteLimits,
) -> BruteSearchResult {
    search_key_space_with_adler_predicate(ciphertext, space, expected_adler, limits, |_| true)
}

/// Adler-32 constrained brute force with an independent acceptance predicate.
/// The predicate is evaluated only for checksum-consistent complete keys.  This
/// is important because Adler-32 collisions are expected once the searched key
/// space becomes large; the checksum narrows the search, while the format
/// grammar decides correctness.
pub fn search_key_space_with_adler_predicate<F>(
    ciphertext: &[u8],
    space: &KeySpace,
    expected_adler: u32,
    limits: BruteLimits,
    mut accept: F,
) -> BruteSearchResult
where
    F: FnMut(&[u8]) -> bool,
{
    let ambiguous = prepare_ambiguous_slots(ciphertext, space);

    if ambiguous.is_empty() {
        let Some(key) = space.key_if_complete() else {
            return BruteSearchResult::default();
        };
        return BruteSearchResult {
            keys: accept(&key).then_some(key).into_iter().collect(),
            used_mitm: false,
            used_gpu: false,
            gpu_adapter: None,
            combinations_considered: 1,
        };
    }

    let fixed = fixed_contribution(ciphertext, space);
    let (target_a, target_b) = target_sums(expected_adler, ciphertext.len());
    let need_a = mod_sub(target_a, fixed.a);
    let need_b = mod_sub(target_b, fixed.b);
    let total = assignment_product(&ambiguous);

    if total.is_some_and(|count| count <= limits.max_combinations) {
        let mut result = BruteSearchResult::default();
        let mut values = Vec::with_capacity(ambiguous.len());
        let base = build_base_key(space);
        let mut callback = |sum_a: u32, sum_b: u32, assignment: &[u8]| {
            result.combinations_considered = result.combinations_considered.saturating_add(1);
            if sum_a == need_a && sum_b == need_b {
                let mut key = base.clone();
                for (slot, &value) in ambiguous.iter().zip(assignment) {
                    key[slot.slot] = value;
                }
                if accept(&key) {
                    result.keys.push(key);
                    if result.keys.len() >= limits.max_solutions {
                        return true;
                    }
                }
            }
            false
        };
        enumerate_group(&ambiguous, 0, 0, 0, &mut values, &mut callback);
        return result;
    }

    let (left, right) = split_balanced(&ambiguous);
    let Some(left_count) = assignment_product(&left) else {
        return BruteSearchResult::default();
    };
    let Some(right_count) = assignment_product(&right) else {
        return BruteSearchResult::default();
    };
    if left_count > limits.max_mitm_half_combinations
        || right_count > limits.max_mitm_half_combinations
    {
        return BruteSearchResult::default();
    }

    // Keep every assignment that maps to a given checksum pair.  Retaining only
    // the first one is unsound: distinct half-keys can have identical Adler
    // contributions and the format-valid complete key may use a later one.
    // Assignments have a fixed width, so concatenating them avoids a Vec<Vec<_>>
    // allocation per hash bucket.
    let left_width = left.len();
    let mut table: HashMap<u32, Vec<u8>> = HashMap::with_capacity(left_count as usize);
    let mut values = Vec::with_capacity(left.len());
    let mut left_callback = |a: u32, b: u32, assignment: &[u8]| {
        let bucket = table.entry(pack_pair(a, b)).or_default();
        if left_width == 0 {
            if bucket.is_empty() {
                bucket.push(0); // sentinel for the single empty assignment
            }
        } else {
            bucket.extend_from_slice(assignment);
        }
        false
    };
    enumerate_group(&left, 0, 0, 0, &mut values, &mut left_callback);

    let base = build_base_key(space);
    let mut result = BruteSearchResult {
        keys: Vec::new(),
        used_mitm: true,
        used_gpu: false,
        gpu_adapter: None,
        combinations_considered: left_count,
    };
    let mut right_values = Vec::with_capacity(right.len());
    let mut right_callback = |a: u32, b: u32, assignment: &[u8]| {
        result.combinations_considered = result.combinations_considered.saturating_add(1);
        let want_a = mod_sub(need_a, a);
        let want_b = mod_sub(need_b, b);
        let Some(left_assignments) = table.get(&pack_pair(want_a, want_b)) else {
            return false;
        };

        if left_width == 0 {
            let mut key = base.clone();
            for (slot, &value) in right.iter().zip(assignment) {
                key[slot.slot] = value;
            }
            if accept(&key) {
                result.keys.push(key);
                return result.keys.len() >= limits.max_solutions;
            }
            return false;
        }

        for left_assignment in left_assignments.chunks_exact(left_width) {
            let mut key = base.clone();
            for (slot, &value) in left.iter().zip(left_assignment) {
                key[slot.slot] = value;
            }
            for (slot, &value) in right.iter().zip(assignment) {
                key[slot.slot] = value;
            }
            if accept(&key) {
                result.keys.push(key);
                if result.keys.len() >= limits.max_solutions {
                    return true;
                }
            }
        }
        false
    };
    enumerate_group(&right, 0, 0, 0, &mut right_values, &mut right_callback);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xp3::adler32;

    #[test]
    fn adler_mitm_recovers_four_unknown_bytes() {
        let key = [0x12, 0x34, 0x56, 0x78];
        let plain: Vec<u8> = (0..4096)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &p)| p ^ key[i % key.len()])
            .collect();
        let candidate = PeriodCandidate {
            period: 4,
            conflicts: 0,
            conflict_weight: 0.0,
            agreements: 0,
            agreement_weight: 0.0,
            known_slots: 0,
            used_slots: 0,
            implied_plaintext_bytes: 0,
            key: vec![None; 4],
        };
        let space = build_key_space(&cipher, &candidate, &[]).unwrap();
        assert_eq!(space.ambiguous_slots, 4);
        assert_eq!(space.combinations, Some(1u128 << 32));
        let result = search_key_space_with_adler_predicate(
            &cipher,
            &space,
            adler32(&plain),
            BruteLimits {
                max_combinations: 1 << 20,
                max_mitm_half_combinations: 1 << 16,
                max_solutions: 4,
            },
            |candidate| candidate == key.as_slice(),
        );
        assert!(result.used_mitm);
        assert!(result
            .keys
            .iter()
            .any(|candidate| candidate.as_slice() == key.as_slice()));
    }

    #[test]
    fn plaintext_constraint_reduces_slot_candidates() {
        let cipher = vec![0xaa; 8];
        let candidate = PeriodCandidate {
            period: 4,
            conflicts: 0,
            conflict_weight: 0.0,
            agreements: 0,
            agreement_weight: 0.0,
            known_slots: 0,
            used_slots: 0,
            implied_plaintext_bytes: 0,
            key: vec![None; 4],
        };
        let space = build_key_space(
            &cipher,
            &candidate,
            &[PlainByteConstraint::new(1, vec![0x00, 0x01])],
        )
        .unwrap();
        assert_eq!(space.slots[1].candidates.len(), 2);
    }

    #[test]
    fn histogram_recovers_strongly_biased_residues() {
        let key = [0x12, 0x34, 0x56, 0x78];
        let mut plain = Vec::with_capacity(32_768);
        for i in 0..32_768usize {
            let value = if i % 5 != 0 {
                0
            } else {
                (i as u8).wrapping_mul(17)
            };
            plain.push(value);
        }
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &p)| p ^ key[i % 4])
            .collect();
        let candidate = PeriodCandidate {
            period: 4,
            conflicts: 0,
            conflict_weight: 0.0,
            agreements: 0,
            agreement_weight: 0.0,
            known_slots: 1,
            used_slots: 1,
            implied_plaintext_bytes: 0,
            key: vec![Some(key[0]), None, None, None],
        };
        let mut space = build_key_space(&cipher, &candidate, &[]).unwrap();
        let (_, singleton) =
            refine_key_space_with_histogram(&cipher, &candidate, &mut space, 8, 64, 12.0, 24.0);
        assert!(singleton >= 1);
        for slot in 1..4 {
            if space.slots[slot].candidates.len() == 1 {
                assert_eq!(space.slots[slot].candidates[0].value, key[slot]);
            }
        }
    }
}
