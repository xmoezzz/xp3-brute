use crate::brute::{
    build_key_space, candidate_is_complete_for_len, refine_key_space_with_histogram_compute,
    search_key_space_with_adler_predicate_compute, search_key_space_with_predicate, BruteLimits,
    KeySpace,
};
use crate::compute::{gpu_period_scores, note_cpu_period_job, ComputeMode};
use crate::error::{Error, Result};
use crate::format::{
    discover_dynamic_cribs, hard_plaintext_constraints, length_derived_cribs, DynamicModel,
    FormatHypothesis,
};
use crate::repeating_xor::{partial_decrypt, rank_periods, Crib, PeriodCandidate};
use crate::text::{
    guess_text_keys, period_is_parity_sensitive, period_score_from_counts,
    period_score_with_parity, rank_statistical_periods_from_scores, recovery_model_for_hypothesis,
};
use crate::validate::{validate_hypothesis, ValidationResult};
use crate::xp3::adler32;
use rayon::prelude::*;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    pub min_period: usize,
    pub max_period: usize,
    pub top_periods_per_hypothesis: usize,
    /// Dynamic format refinement can scan the complete ciphertext for repeated
    /// structural anchors. Exhaustively doing that for every period from
    /// 1..1024 is intentionally opt-in; the default fast path tests short
    /// periods plus common 64-byte multiples/powers of two.
    pub exhaustive_dynamic_periods: bool,
    pub max_refinement_rounds: usize,
    /// Maximum complete candidate combinations to enumerate directly.
    pub brute_max_combinations: u128,
    /// Maximum combinations stored/evaluated on either side of an Adler-32
    /// meet-in-the-middle search.
    pub brute_max_mitm_half_combinations: u128,
    /// Stop after this many checksum-consistent key candidates per period.
    pub brute_max_solutions: usize,
    /// Keep at most this many statistically plausible key-byte candidates when
    /// a residue has enough samples and a strong likelihood separation. Set to
    /// zero to disable histogram pruning entirely.
    pub histogram_top_k: usize,
    pub histogram_min_slot_samples: usize,
    pub histogram_min_log_likelihood_gap: f64,
    pub histogram_singleton_log_likelihood_gap: f64,
    pub max_histogram_dynamic_rounds: usize,
    /// CPU/GPU policy for bounded Adler-32 exhaustive search. Structural
    /// parsing and final validation always stay on the CPU.
    pub compute_mode: ComputeMode,
    /// Auto/hybrid modes avoid GPU submission overhead for tiny search spaces.
    pub gpu_min_combinations: u128,
    /// Minimum ciphertext size for GPU text-period coincidence ranking.
    pub gpu_min_period_bytes: usize,
    /// Minimum number of `(slot,key-byte)` likelihood candidates for a GPU
    /// histogram-scoring dispatch.
    pub gpu_min_slot_candidates: usize,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            min_period: 1,
            max_period: 1024,
            top_periods_per_hypothesis: 8,
            exhaustive_dynamic_periods: false,
            max_refinement_rounds: 12,
            brute_max_combinations: 1u128 << 24,
            brute_max_mitm_half_combinations: 1u128 << 20,
            brute_max_solutions: 4,
            histogram_top_k: 8,
            histogram_min_slot_samples: 64,
            histogram_min_log_likelihood_gap: 12.0,
            histogram_singleton_log_likelihood_gap: 24.0,
            max_histogram_dynamic_rounds: 4,
            compute_mode: ComputeMode::Auto,
            gpu_min_combinations: 1u128 << 16,
            gpu_min_period_bytes: 16 * 1024,
            gpu_min_slot_candidates: 4 * 256,
        }
    }
}

impl RecoveryConfig {
    fn brute_limits(&self) -> BruteLimits {
        BruteLimits {
            max_combinations: self.brute_max_combinations,
            max_mitm_half_combinations: self.brute_max_mitm_half_combinations,
            max_solutions: self.brute_max_solutions,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BruteSummary {
    pub used_slots: usize,
    pub ambiguous_slots: usize,
    pub entropy_bits: f64,
    pub combinations: Option<u128>,
    pub direct_feasible: bool,
    pub mitm_feasible: bool,
    pub histogram_reduced_slots: usize,
    pub histogram_singleton_slots: usize,
}

#[derive(Clone, Debug)]
pub struct RecoveryCandidate {
    pub hypothesis: String,
    pub period: PeriodCandidate,
    pub refinement_rounds: usize,
    pub brute: Option<BruteSummary>,
}

#[derive(Clone, Debug, Default)]
pub struct RecoveryReport {
    pub candidates: Vec<RecoveryCandidate>,
}

#[derive(Clone, Debug)]
pub struct ValidatedRecovery {
    pub hypothesis: String,
    pub period: PeriodCandidate,
    pub plaintext: Vec<u8>,
    pub adler_match: Option<bool>,
    pub format_validation: ValidationResult,
    pub refinement_rounds: usize,
    pub brute_used: bool,
    pub brute_used_mitm: bool,
    pub brute_used_gpu: bool,
    pub gpu_adapter: Option<String>,
    pub brute_combinations_considered: u128,
}

fn validate_config(config: &RecoveryConfig) -> Result<()> {
    if config.min_period == 0 || config.max_period < config.min_period {
        return Err(Error::invalid("invalid period range"));
    }
    if config.brute_max_solutions == 0 {
        return Err(Error::invalid("brute_max_solutions must be non-zero"));
    }
    Ok(())
}

fn merge_dynamic_cribs(existing: &mut Vec<Crib>, discovered: Vec<Crib>) -> usize {
    let mut seen: HashSet<(u64, Vec<u8>)> = existing
        .iter()
        .map(|crib| (crib.offset, crib.plaintext.clone()))
        .collect();
    let mut added = 0usize;
    for crib in discovered {
        let key = (crib.offset, crib.plaintext.clone());
        if seen.insert(key) {
            existing.push(crib);
            added += 1;
        }
    }
    added
}

fn initial_cribs(ciphertext_len: usize, hypothesis: &FormatHypothesis) -> Vec<Crib> {
    let mut cribs = hypothesis.cribs.clone();
    merge_dynamic_cribs(&mut cribs, length_derived_cribs(hypothesis, ciphertext_len));
    cribs
}

fn text_period_scores_compute(
    ciphertext: &[u8],
    parity_sensitive: bool,
    config: &RecoveryConfig,
) -> Result<Vec<f64>> {
    if let Some(gpu) = gpu_period_scores(
        config.compute_mode,
        ciphertext,
        config.min_period,
        config.max_period,
        parity_sensitive,
        config.gpu_min_period_bytes,
    )
    .map_err(Error::unsupported)?
    {
        let scores = gpu
            .counts
            .into_iter()
            .enumerate()
            .map(|(index, (equal, total))| {
                period_score_from_counts(equal, total, config.min_period + index)
            })
            .collect();
        return Ok(scores);
    }

    note_cpu_period_job();
    Ok((config.min_period..=config.max_period)
        .into_par_iter()
        .map(|period| period_score_with_parity(ciphertext, period, parity_sensitive))
        .collect())
}

#[derive(Default)]
struct TextPeriodScoreCache {
    byte_aligned: Option<Vec<f64>>,
    parity_sensitive: Option<Vec<f64>>,
}

impl TextPeriodScoreCache {
    fn build(
        ciphertext: &[u8],
        hypotheses: &[FormatHypothesis],
        config: &RecoveryConfig,
    ) -> Result<Self> {
        let mut need_byte_aligned = false;
        let mut need_parity_sensitive = false;
        for hypothesis in hypotheses {
            let Some(model) = recovery_model_for_hypothesis(hypothesis.name) else {
                continue;
            };
            if period_is_parity_sensitive(model) {
                need_parity_sensitive = true;
            } else {
                need_byte_aligned = true;
            }
        }
        Ok(Self {
            byte_aligned: if need_byte_aligned {
                Some(text_period_scores_compute(ciphertext, false, config)?)
            } else {
                None
            },
            parity_sensitive: if need_parity_sensitive {
                Some(text_period_scores_compute(ciphertext, true, config)?)
            } else {
                None
            },
        })
    }

    fn for_hypothesis(&self, hypothesis: &FormatHypothesis) -> Option<&[f64]> {
        let model = recovery_model_for_hypothesis(hypothesis.name)?;
        if period_is_parity_sensitive(model) {
            self.parity_sensitive.as_deref()
        } else {
            self.byte_aligned.as_deref()
        }
    }
}

fn rank_hypothesis_periods(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    config: &RecoveryConfig,
    text_scores: Option<&[f64]>,
) -> Result<Vec<PeriodCandidate>> {
    let cribs = initial_cribs(ciphertext.len(), hypothesis);

    let mut ranked = if cribs.is_empty() {
        let Some(scores) = text_scores else {
            return Err(Error::invalid(
                "format hypothesis has no plaintext evidence",
            ));
        };
        rank_statistical_periods_from_scores(scores, config.min_period)
    } else {
        rank_periods(ciphertext, &cribs, config.min_period, config.max_period)?
    };

    // Exact crib contradictions always dominate. Within the consistent set,
    // the precomputed ciphertext coincidence score supplies the period signal
    // for text. Scores are cached per ciphertext/parity class, so UTF-8 and
    // CP932 share one scan while UTF-16LE/BE and Kirikiri 16-bit text share
    // another instead of launching duplicate CPU/GPU period jobs.
    if let Some(scores) = text_scores {
        ranked.sort_by(|a, b| {
            let sa = scores[a.period - config.min_period];
            let sb = scores[b.period - config.min_period];
            a.conflict_weight
                .total_cmp(&b.conflict_weight)
                .then_with(|| a.conflicts.cmp(&b.conflicts))
                .then_with(|| sb.total_cmp(&sa))
                .then_with(|| b.known_slots.cmp(&a.known_slots))
                .then_with(|| a.period.cmp(&b.period))
        });
    }
    Ok(ranked)
}

fn refine_period(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    initial: PeriodCandidate,
    config: &RecoveryConfig,
) -> Result<(PeriodCandidate, usize)> {
    if hypothesis.dynamic == DynamicModel::None || config.max_refinement_rounds == 0 {
        return Ok((initial, 0));
    }

    let mut candidate = initial;
    let mut cribs = initial_cribs(ciphertext.len(), hypothesis);
    let mut rounds = 0usize;

    for _ in 0..config.max_refinement_rounds {
        let discovered = discover_dynamic_cribs(ciphertext, hypothesis, &candidate);
        if merge_dynamic_cribs(&mut cribs, discovered) == 0 {
            break;
        }
        let mut reranked = rank_periods(ciphertext, &cribs, candidate.period, candidate.period)?;
        let Some(next) = reranked.pop() else {
            break;
        };

        // Dynamic cribs are supposed to be exact consequences of already-known
        // structure. If a refinement round introduces new contradictions, do
        // not poison the key state with it; retain the previous round.
        if next.conflict_weight > candidate.conflict_weight || next.conflicts > candidate.conflicts
        {
            break;
        }
        let changed = next.known_slots > candidate.known_slots;
        candidate = next;
        rounds += 1;
        if !changed || candidate_is_complete_for_len(&candidate, ciphertext.len()) {
            break;
        }
    }

    Ok((candidate, rounds))
}

fn should_refine_period(period: usize, rank: usize, config: &RecoveryConfig) -> bool {
    if config.exhaustive_dynamic_periods {
        return true;
    }
    rank < config.top_periods_per_hypothesis
        || period <= 64
        || period.is_power_of_two()
        || period % 64 == 0
}

fn should_histogram_period(period: usize, rank: usize, config: &RecoveryConfig) -> bool {
    config.exhaustive_dynamic_periods
        || rank < 4
        || period <= 16
        || period.is_power_of_two()
        || period % 64 == 0
}

fn key_space_for(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    period: &PeriodCandidate,
    config: &RecoveryConfig,
    use_histogram: bool,
) -> Result<Option<(KeySpace, usize, usize)>> {
    let constraints = hard_plaintext_constraints(hypothesis, ciphertext.len());
    let Some(mut space) = build_key_space(ciphertext, period, &constraints) else {
        return Ok(None);
    };
    let (reduced, singleton) = if use_histogram {
        refine_key_space_with_histogram_compute(
            ciphertext,
            period,
            &mut space,
            config.histogram_top_k,
            config.histogram_min_slot_samples,
            config.histogram_min_log_likelihood_gap,
            config.histogram_singleton_log_likelihood_gap,
            config.compute_mode,
            config.gpu_min_slot_candidates,
        )
        .map_err(Error::unsupported)?
    } else {
        (0, 0)
    };
    Ok(Some((space, reduced, singleton)))
}

fn project_space_singletons(base: &PeriodCandidate, space: &KeySpace) -> (PeriodCandidate, usize) {
    let mut projected = base.clone();
    let mut added = 0usize;
    for slot in &space.slots {
        if projected.key[slot.slot].is_none() && slot.candidates.len() == 1 {
            projected.key[slot.slot] = Some(slot.candidates[0].value);
            added += 1;
        }
    }
    projected.known_slots = projected.key.iter().filter(|value| value.is_some()).count();
    (projected, added)
}

/// Feed very high-confidence histogram singletons back into the dynamic parser.
/// The guessed bytes are never committed directly. They are used only to reach
/// additional structural anchors; those anchors are converted to exact cribs
/// and re-ranked from ciphertext. A wrong statistical guess therefore fails to
/// create durable key state unless it also satisfies the file grammar.
fn refine_histogram_dynamic(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    initial: PeriodCandidate,
    config: &RecoveryConfig,
) -> Result<(PeriodCandidate, usize)> {
    if hypothesis.dynamic == DynamicModel::None || config.max_histogram_dynamic_rounds == 0 {
        return Ok((initial, 0));
    }
    let mut candidate = initial;
    let mut cribs = initial_cribs(ciphertext.len(), hypothesis);
    merge_dynamic_cribs(
        &mut cribs,
        discover_dynamic_cribs(ciphertext, hypothesis, &candidate),
    );
    let mut rounds = 0usize;

    for _ in 0..config.max_histogram_dynamic_rounds {
        let Some((space, _, singleton)) =
            key_space_for(ciphertext, hypothesis, &candidate, config, true)?
        else {
            break;
        };
        if singleton == 0 {
            break;
        }
        let (projected, added_guesses) = project_space_singletons(&candidate, &space);
        if added_guesses == 0 {
            break;
        }
        let discovered = discover_dynamic_cribs(ciphertext, hypothesis, &projected);
        if merge_dynamic_cribs(&mut cribs, discovered) == 0 {
            break;
        }
        let mut reranked = rank_periods(ciphertext, &cribs, candidate.period, candidate.period)?;
        let Some(next) = reranked.pop() else {
            break;
        };
        if next.conflicts != 0 || next.conflict_weight > candidate.conflict_weight {
            break;
        }
        if next.known_slots <= candidate.known_slots {
            break;
        }
        candidate = next;
        rounds += 1;
        if candidate_is_complete_for_len(&candidate, ciphertext.len()) {
            break;
        }
    }
    Ok((candidate, rounds))
}

fn mitm_half_products(space: &KeySpace) -> Option<(u128, u128)> {
    let mut sizes: Vec<u128> = space
        .slots
        .iter()
        .filter(|slot| slot.candidates.len() > 1)
        .map(|slot| slot.candidates.len() as u128)
        .collect();
    if sizes.is_empty() {
        return Some((1, 1));
    }
    sizes.sort_by(|a, b| b.cmp(a));
    let mut left = 1u128;
    let mut right = 1u128;
    for size in sizes {
        if left <= right {
            left = left.checked_mul(size)?;
        } else {
            right = right.checked_mul(size)?;
        }
    }
    Some((left, right))
}

fn brute_summary(
    space: &KeySpace,
    config: &RecoveryConfig,
    histogram_reduced_slots: usize,
    histogram_singleton_slots: usize,
) -> BruteSummary {
    let direct_feasible = space
        .combinations
        .is_some_and(|count| count <= config.brute_max_combinations);
    let mitm_feasible = mitm_half_products(space).is_some_and(|(left, right)| {
        left <= config.brute_max_mitm_half_combinations
            && right <= config.brute_max_mitm_half_combinations
    });
    BruteSummary {
        used_slots: space.used_slots,
        ambiguous_slots: space.ambiguous_slots,
        entropy_bits: space.entropy_bits,
        combinations: space.combinations,
        direct_feasible,
        mitm_feasible,
        histogram_reduced_slots,
        histogram_singleton_slots,
    }
}

fn full_period_from_key(mut base: PeriodCandidate, key: &[u8], len: usize) -> PeriodCandidate {
    let used = base.period.min(len);
    for slot in 0..used {
        if slot < key.len() {
            base.key[slot] = Some(key[slot]);
        }
    }
    base.known_slots = base.key.iter().filter(|value| value.is_some()).count();
    base
}

fn validate_full_candidate(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    period: PeriodCandidate,
    expected_adler: Option<u32>,
    refinement_rounds: usize,
    brute_used: bool,
    brute_used_mitm: bool,
    brute_used_gpu: bool,
    gpu_adapter: Option<String>,
    brute_combinations_considered: u128,
) -> Option<ValidatedRecovery> {
    if !candidate_is_complete_for_len(&period, ciphertext.len()) {
        return None;
    }
    let plaintext = partial_decrypt(ciphertext, &period, 0);
    let adler_match = expected_adler.map(|expected| adler32(&plaintext) == expected);
    let format_validation = validate_hypothesis(hypothesis.name, &plaintext);
    let valid = match adler_match {
        // Adler-32 is a powerful global search constraint, but it is only
        // 32 bits and therefore is not a proof of plaintext identity.  A
        // checksum-consistent brute-force result must also satisfy the format
        // grammar for the active hypothesis.
        Some(true) => format_validation.is_strong(),
        Some(false) => false,
        None => format_validation.is_strong(),
    };
    valid.then_some(ValidatedRecovery {
        hypothesis: hypothesis.name.to_string(),
        period,
        plaintext,
        adler_match,
        format_validation,
        refinement_rounds,
        brute_used,
        brute_used_mitm,
        brute_used_gpu,
        gpu_adapter,
        brute_combinations_considered,
    })
}

/// Jointly evaluates format hypotheses and repeating-XOR periods. Dynamic
/// models may use a partial key to discover new exact structural cribs. Every
/// candidate additionally reports the exact residual key-space size after hard
/// non-singleton format constraints have been applied.
pub fn recover_stream(
    ciphertext: &[u8],
    hypotheses: &[FormatHypothesis],
    config: &RecoveryConfig,
) -> Result<RecoveryReport> {
    if hypotheses.is_empty() {
        return Err(Error::invalid("no format hypotheses available"));
    }
    validate_config(config)?;
    let text_period_cache = TextPeriodScoreCache::build(ciphertext, hypotheses, config)?;

    let nested: Vec<Result<Vec<RecoveryCandidate>>> = hypotheses
        .par_iter()
        .map(|hypothesis| {
            let ranked = rank_hypothesis_periods(
                ciphertext,
                hypothesis,
                config,
                text_period_cache.for_hypothesis(hypothesis),
            )?;
            let mut out = Vec::new();
            for (rank, period) in ranked.into_iter().enumerate() {
                let histogram_enabled = should_histogram_period(period.period, rank, config);
                if rank >= config.top_periods_per_hypothesis
                    && !should_refine_period(period.period, rank, config)
                {
                    continue;
                }
                let (period, mut refinement_rounds) =
                    if period.conflicts == 0 && should_refine_period(period.period, rank, config) {
                        refine_period(ciphertext, hypothesis, period, config)?
                    } else {
                        (period, 0)
                    };
                let (period, histogram_rounds) = if period.conflicts == 0 && histogram_enabled {
                    refine_histogram_dynamic(ciphertext, hypothesis, period, config)?
                } else {
                    (period, 0)
                };
                refinement_rounds += histogram_rounds;
                let brute =
                    key_space_for(ciphertext, hypothesis, &period, config, histogram_enabled)?.map(
                        |(space, reduced, singleton)| {
                            brute_summary(&space, config, reduced, singleton)
                        },
                    );
                out.push(RecoveryCandidate {
                    hypothesis: hypothesis.name.to_string(),
                    period,
                    refinement_rounds,
                    brute,
                });
            }
            Ok(out)
        })
        .collect();

    let mut candidates = Vec::new();
    for item in nested {
        candidates.extend(item?);
    }
    candidates.sort_by(|a, b| {
        a.period
            .conflict_weight
            .total_cmp(&b.period.conflict_weight)
            .then_with(|| a.period.conflicts.cmp(&b.period.conflicts))
            .then_with(|| {
                let ae = a
                    .brute
                    .as_ref()
                    .map(|x| x.entropy_bits)
                    .unwrap_or(f64::INFINITY);
                let be = b
                    .brute
                    .as_ref()
                    .map(|x| x.entropy_bits)
                    .unwrap_or(f64::INFINITY);
                ae.total_cmp(&be)
            })
            .then_with(|| b.period.known_slots.cmp(&a.period.known_slots))
            .then_with(|| {
                b.period
                    .agreement_weight
                    .total_cmp(&a.period.agreement_weight)
            })
            .then_with(|| b.period.agreements.cmp(&a.period.agreements))
            .then_with(|| a.period.period.cmp(&b.period.period))
    });

    Ok(RecoveryReport { candidates })
}

/// Return complete-key candidates that survive an independent validator.
///
/// The recovery order is: exact cribs -> dynamic structure propagation -> hard
/// candidate-set reduction -> direct brute force / Adler-32 meet-in-the-middle.
/// XP3 `adlr` therefore participates in the search instead of being used only
/// after all key bytes happened to be inferred independently.
pub fn recover_complete_stream(
    ciphertext: &[u8],
    hypotheses: &[FormatHypothesis],
    config: &RecoveryConfig,
    expected_adler: Option<u32>,
) -> Result<Vec<ValidatedRecovery>> {
    if hypotheses.is_empty() {
        return Err(Error::invalid("no format hypotheses available"));
    }
    validate_config(config)?;
    let text_period_cache = TextPeriodScoreCache::build(ciphertext, hypotheses, config)?;

    let nested: Vec<Result<Vec<ValidatedRecovery>>> = hypotheses
        .par_iter()
        .map(|hypothesis| {
            let ranked = rank_hypothesis_periods(
                ciphertext,
                hypothesis,
                config,
                text_period_cache.for_hypothesis(hypothesis),
            )?;
            let mut accepted = Vec::new();
            let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();

            for (rank, original) in ranked.into_iter().enumerate() {
                let histogram_enabled = should_histogram_period(original.period, rank, config);
                if original.conflicts != 0 {
                    continue;
                }
                if rank >= config.top_periods_per_hypothesis
                    && !should_refine_period(original.period, rank, config)
                {
                    continue;
                }

                let (period, mut refinement_rounds) =
                    if candidate_is_complete_for_len(&original, ciphertext.len()) {
                        (original, 0)
                    } else if should_refine_period(original.period, rank, config) {
                        refine_period(ciphertext, hypothesis, original, config)?
                    } else {
                        (original, 0)
                    };
                let (period, histogram_rounds) = if period.conflicts == 0 && histogram_enabled {
                    refine_histogram_dynamic(ciphertext, hypothesis, period, config)?
                } else {
                    (period, 0)
                };
                refinement_rounds += histogram_rounds;

                if period.conflicts != 0 {
                    continue;
                }

                // Text resources rarely provide enough fixed cribs to fill a
                // 31/256-byte key directly.  Enumerate all 256 values per key
                // residue under the active encoding model and use the result as
                // a *guess only*.  A guessed key is accepted solely through the
                // same independent strong validator + XP3 adlr path as every
                // other recovery.
                if let Some(model) = recovery_model_for_hypothesis(hypothesis.name) {
                    let coordinate_rounds = if rank < 12 { 2 } else { 0 };
                    for key in guess_text_keys(ciphertext, &period, model, coordinate_rounds) {
                        if !seen_keys.insert(key.clone()) {
                            continue;
                        }
                        let full = full_period_from_key(period.clone(), &key, ciphertext.len());
                        if let Some(recovery) = validate_full_candidate(
                            ciphertext,
                            hypothesis,
                            full,
                            expected_adler,
                            refinement_rounds,
                            false,
                            false,
                            false,
                            None,
                            0,
                        ) {
                            accepted.push(recovery);
                        }
                    }
                    if !accepted.is_empty() {
                        // Keep trying smaller/equivalent periods so final sorting
                        // can still select the primitive minimal period, but do
                        // not make text guesses durable without validation.
                    }
                }

                if candidate_is_complete_for_len(&period, ciphertext.len()) {
                    if let Some(recovery) = validate_full_candidate(
                        ciphertext,
                        hypothesis,
                        period,
                        expected_adler,
                        refinement_rounds,
                        false,
                        false,
                        false,
                        None,
                        0,
                    ) {
                        accepted.push(recovery);
                    }
                    continue;
                }

                let Some((space, reduced, singleton)) =
                    key_space_for(ciphertext, hypothesis, &period, config, histogram_enabled)?
                else {
                    continue;
                };
                let summary = brute_summary(&space, config, reduced, singleton);
                if !summary.direct_feasible && !(expected_adler.is_some() && summary.mitm_feasible)
                {
                    continue;
                }

                let hypothesis_name = hypothesis.name;
                let candidate_period = period.period;
                let search = if let Some(expected) = expected_adler {
                    search_key_space_with_adler_predicate_compute(
                        ciphertext,
                        &space,
                        expected,
                        config.brute_limits(),
                        config.compute_mode,
                        config.gpu_min_combinations,
                        |key| {
                            let plaintext: Vec<u8> = ciphertext
                                .iter()
                                .enumerate()
                                .map(|(i, &byte)| byte ^ key[i % candidate_period])
                                .collect();
                            validate_hypothesis(hypothesis_name, &plaintext).is_strong()
                        },
                    )
                    .map_err(Error::unsupported)?
                } else {
                    search_key_space_with_predicate(&space, config.brute_limits(), |key| {
                        let plaintext: Vec<u8> = ciphertext
                            .iter()
                            .enumerate()
                            .map(|(i, &byte)| byte ^ key[i % candidate_period])
                            .collect();
                        validate_hypothesis(hypothesis_name, &plaintext).is_strong()
                    })
                };

                for key in search.keys {
                    if !seen_keys.insert(key.clone()) {
                        continue;
                    }
                    let full = full_period_from_key(period.clone(), &key, ciphertext.len());
                    if let Some(recovery) = validate_full_candidate(
                        ciphertext,
                        hypothesis,
                        full,
                        expected_adler,
                        refinement_rounds,
                        true,
                        search.used_mitm,
                        search.used_gpu,
                        search.gpu_adapter.clone(),
                        search.combinations_considered,
                    ) {
                        accepted.push(recovery);
                    }
                }
            }
            Ok(accepted)
        })
        .collect();

    let mut out = Vec::new();
    for item in nested {
        out.extend(item?);
    }

    out.sort_by(|a, b| {
        a.period
            .period
            .cmp(&b.period.period)
            .then_with(|| {
                b.format_validation
                    .strength
                    .cmp(&a.format_validation.strength)
            })
            .then_with(|| {
                a.brute_combinations_considered
                    .cmp(&b.brute_combinations_considered)
            })
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brute::search_key_space_with_adler_predicate;
    use crate::format::hypotheses_for_name;

    #[test]
    fn adler_validates_complete_short_period() {
        use crate::validate::crc32_ieee;

        let key = [0x11, 0x22, 0x33, 0x44];
        let mut plain = Vec::new();
        plain.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        plain.extend_from_slice(&13u32.to_be_bytes());
        let mut ihdr = Vec::from(&b"IHDR"[..]);
        ihdr.extend_from_slice(&[
            0, 0, 0, 1, // width
            0, 0, 0, 1, // height
            8, 6, 0, 0, 0, // RGBA8, standard compression/filter/interlace
        ]);
        plain.extend_from_slice(&ihdr);
        plain.extend_from_slice(&crc32_ieee(&ihdr).to_be_bytes());
        plain.extend_from_slice(&0u32.to_be_bytes());
        plain.extend_from_slice(b"IEND");
        plain.extend_from_slice(&crc32_ieee(b"IEND").to_be_bytes());

        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let hypotheses = hypotheses_for_name("test.png");
        let recovered = recover_complete_stream(
            &cipher,
            &hypotheses,
            &RecoveryConfig {
                min_period: 1,
                max_period: 16,
                top_periods_per_hypothesis: 4,
                exhaustive_dynamic_periods: false,
                max_refinement_rounds: 4,
                ..RecoveryConfig::default()
            },
            Some(adler32(&plain)),
        )
        .unwrap();
        assert!(!recovered.is_empty());
        assert_eq!(recovered[0].period.period, 4);
        assert_eq!(recovered[0].plaintext, plain);
        assert_eq!(recovered[0].adler_match, Some(true));
    }

    #[test]
    fn statistical_utf16le_recovers_period31_script() {
        let mut plain = vec![0xff, 0xfe];
        for unit in "// startup.tjs\r\nvar value = 123;\r\nfunction test() { return value; }\r\n"
            .repeat(80)
            .encode_utf16()
        {
            plain.extend_from_slice(&unit.to_le_bytes());
        }
        let key: Vec<u8> = (0..31).map(|i| (i * 37 + 9) as u8).collect();
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect();
        let hypothesis = hypotheses_for_name("startup.tjs")
            .into_iter()
            .find(|h| h.name == "Text/UTF-16LE-BOM")
            .unwrap();
        let recovered = recover_complete_stream(
            &cipher,
            &[hypothesis],
            &RecoveryConfig {
                min_period: 31,
                max_period: 31,
                top_periods_per_hypothesis: 1,
                ..RecoveryConfig::default()
            },
            Some(adler32(&plain)),
        )
        .unwrap();
        assert!(!recovered.is_empty());
        assert_eq!(recovered[0].period.period, 31);
        assert_eq!(recovered[0].plaintext, plain);
        assert!(!recovered[0].brute_used);
    }

    #[test]
    fn brute_adler_finishes_four_unknown_slots() {
        // The crib fixes no key byte here; hard PNG constraints plus the short
        // period leave a small enough exact space for Adler MITM to finish.
        let key = [0x21, 0x43, 0x65, 0x87];
        let mut plain = vec![0u8; 80];
        plain[..8].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        // Minimal synthetic content need not pass PNG validation for the low-level
        // brute primitive; the dedicated brute module tests the checksum search.
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 4])
            .collect();
        let period = PeriodCandidate {
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
        let space = build_key_space(&cipher, &period, &[]).unwrap();
        let search = search_key_space_with_adler_predicate(
            &cipher,
            &space,
            adler32(&plain),
            RecoveryConfig::default().brute_limits(),
            |candidate| candidate == key.as_slice(),
        );
        assert!(search
            .keys
            .iter()
            .any(|candidate| candidate.as_slice() == key.as_slice()));
    }
}
