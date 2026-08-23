use crate::error::{Error, Result};
use rayon::prelude::*;
use std::cmp::Ordering;

/// A known or hypothesized plaintext fragment.
#[derive(Clone, Debug, PartialEq)]
pub struct Crib {
    pub offset: u64,
    pub plaintext: Vec<u8>,
    pub weight: f64,
}

impl Crib {
    pub fn new(offset: u64, plaintext: impl AsRef<[u8]>) -> Self {
        Self {
            offset,
            plaintext: plaintext.as_ref().to_vec(),
            weight: 1.0,
        }
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeyObservation {
    /// Offset within the file. Repeating keys are assumed to restart at offset 0
    /// for every sample when observations from several files are combined.
    pub offset: u64,
    pub key_byte: u8,
    pub weight: f64,
}

pub struct SharedSample<'a> {
    pub ciphertext: &'a [u8],
    pub cribs: &'a [Crib],
}

#[derive(Clone, Debug)]
pub struct PeriodCandidate {
    pub period: usize,
    pub conflicts: usize,
    pub conflict_weight: f64,
    pub agreements: usize,
    pub agreement_weight: f64,
    pub known_slots: usize,
    pub used_slots: usize,
    pub implied_plaintext_bytes: u64,
    pub key: Vec<Option<u8>>,
}

impl PeriodCandidate {
    pub fn coverage(&self) -> f64 {
        if self.period == 0 {
            0.0
        } else {
            self.known_slots as f64 / self.period as f64
        }
    }

    pub fn is_consistent(&self) -> bool {
        self.conflicts == 0
    }
}

pub fn derive_key_observations(ciphertext: &[u8], cribs: &[Crib]) -> Vec<KeyObservation> {
    let mut out = Vec::new();
    for crib in cribs {
        let Ok(base) = usize::try_from(crib.offset) else {
            continue;
        };
        if base >= ciphertext.len() {
            continue;
        }
        let available = ciphertext.len() - base;
        for (delta, &plain) in crib.plaintext.iter().take(available).enumerate() {
            let absolute = base + delta;
            out.push(KeyObservation {
                offset: absolute as u64,
                key_byte: ciphertext[absolute] ^ plain,
                weight: crib.weight,
            });
        }
    }
    out
}

fn evaluate_observations(
    observations: &[KeyObservation],
    file_lengths: &[usize],
    period: usize,
) -> PeriodCandidate {
    // Observations are normally sparse. Do not allocate a 256-candidate table
    // for every key slot: bucket only slots that actually receive evidence.
    let mut by_slot: Vec<Vec<(u8, f64)>> = (0..period).map(|_| Vec::new()).collect();
    for observation in observations {
        let slot = observation.offset as usize % period;
        by_slot[slot].push((observation.key_byte, observation.weight));
    }

    let mut out = PeriodCandidate {
        period,
        conflicts: 0,
        conflict_weight: 0.0,
        agreements: 0,
        agreement_weight: 0.0,
        known_slots: 0,
        used_slots: 0,
        implied_plaintext_bytes: 0,
        key: vec![None; period],
    };

    for (slot, slot_observations) in by_slot.iter().enumerate() {
        if slot_observations.is_empty() {
            continue;
        }
        out.used_slots += 1;

        let mut votes = [0.0_f64; 256];
        let mut counts = [0_u32; 256];
        for &(value, weight) in slot_observations {
            votes[value as usize] += weight;
            counts[value as usize] = counts[value as usize].saturating_add(1);
        }

        let mut winner = 0usize;
        for value in 1..256 {
            let lhs = votes[value];
            let rhs = votes[winner];
            if lhs > rhs || (lhs == rhs && counts[value] > counts[winner]) {
                winner = value;
            }
        }

        out.key[slot] = Some(winner as u8);
        out.known_slots += 1;

        let winner_count = counts[winner] as usize;
        let winner_weight = votes[winner];
        if winner_count > 1 {
            out.agreements += winner_count - 1;
            out.agreement_weight +=
                winner_weight * ((winner_count - 1) as f64 / winner_count as f64);
        }

        for value in 0..256 {
            if value == winner || counts[value] == 0 {
                continue;
            }
            out.conflicts += counts[value] as usize;
            out.conflict_weight += votes[value];
        }
    }

    for &length in file_lengths {
        for slot in 0..period.min(length) {
            if out.key[slot].is_some() {
                out.implied_plaintext_bytes += (1 + (length - 1 - slot) / period) as u64;
            }
        }
    }

    out
}

fn candidate_order(a: &PeriodCandidate, b: &PeriodCandidate) -> Ordering {
    a.conflict_weight
        .total_cmp(&b.conflict_weight)
        .then_with(|| a.conflicts.cmp(&b.conflicts))
        .then_with(|| b.agreement_weight.total_cmp(&a.agreement_weight))
        .then_with(|| b.agreements.cmp(&a.agreements))
        // When observations cannot distinguish an exact period from one of its
        // multiples, the smaller period is the minimal-description hypothesis.
        .then_with(|| a.period.cmp(&b.period))
}

/// Rank candidate repeating-XOR periods using known/hypothesized plaintext.
///
/// This searches periods, not complete keys. For a fixed period, each observed
/// plaintext byte directly determines one candidate key byte at `offset % period`.
pub fn rank_periods(
    ciphertext: &[u8],
    cribs: &[Crib],
    min_period: usize,
    max_period: usize,
) -> Result<Vec<PeriodCandidate>> {
    if min_period == 0 || max_period < min_period {
        return Err(Error::invalid("invalid period range"));
    }
    if cribs.is_empty() {
        return Err(Error::invalid("at least one plaintext crib is required"));
    }

    let observations = derive_key_observations(ciphertext, cribs);
    let mut out: Vec<_> = (min_period..=max_period)
        .into_par_iter()
        .map(|period| evaluate_observations(&observations, &[ciphertext.len()], period))
        .collect();
    out.sort_by(candidate_order);
    Ok(out)
}

/// Rank periods for a key that is hypothesized to be shared by several files.
/// Each file begins at keystream offset zero; observations from different files
/// therefore constrain the same key slots and can fill one another's gaps.
pub fn rank_shared_periods(
    samples: &[SharedSample<'_>],
    min_period: usize,
    max_period: usize,
) -> Result<Vec<PeriodCandidate>> {
    if min_period == 0 || max_period < min_period {
        return Err(Error::invalid("invalid period range"));
    }
    if samples.is_empty() {
        return Err(Error::invalid("at least one shared-key sample is required"));
    }

    let mut observations = Vec::new();
    let mut file_lengths = Vec::with_capacity(samples.len());
    for sample in samples {
        observations.extend(derive_key_observations(sample.ciphertext, sample.cribs));
        file_lengths.push(sample.ciphertext.len());
    }
    if observations.is_empty() {
        return Err(Error::invalid(
            "shared-key samples produced no observations",
        ));
    }

    let mut out: Vec<_> = (min_period..=max_period)
        .into_par_iter()
        .map(|period| evaluate_observations(&observations, &file_lengths, period))
        .collect();
    out.sort_by(candidate_order);
    Ok(out)
}

/// Decrypt every byte whose residue has a recovered key byte.
pub fn partial_decrypt(
    ciphertext: &[u8],
    candidate: &PeriodCandidate,
    unknown_fill: u8,
) -> Vec<u8> {
    let mut out = vec![unknown_fill; ciphertext.len()];
    if candidate.period == 0 {
        return out;
    }
    for (i, (&cipher, plain)) in ciphertext.iter().zip(out.iter_mut()).enumerate() {
        if let Some(key) = candidate.key[i % candidate.period] {
            *plain = cipher ^ key;
        }
    }
    out
}

pub fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let filtered: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'_' && *b != b':')
        .collect();
    if filtered.len() % 2 != 0 {
        return Err(Error::invalid(
            "hex string must contain an even number of digits",
        ));
    }

    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(filtered.len() / 2);
    for pair in filtered.chunks_exact(2) {
        let hi = nibble(pair[0]).ok_or_else(|| Error::invalid("invalid hex digit"))?;
        let lo = nibble(pair[1]).ok_or_else(|| Error::invalid("invalid hex digit"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Parse `OFFSET:HEX` where OFFSET accepts decimal or `0x` hexadecimal.
pub fn parse_crib(spec: &str) -> Result<Crib> {
    let (offset, bytes) = spec
        .split_once(':')
        .ok_or_else(|| Error::invalid("crib must be OFFSET:HEX"))?;
    let offset = parse_integer(offset)?;
    Ok(Crib::new(offset, parse_hex(bytes)?))
}

fn parse_integer(text: &str) -> Result<u64> {
    let s = text.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| Error::invalid("invalid crib offset"))
    } else {
        s.parse::<u64>()
            .map_err(|_| Error::invalid("invalid crib offset"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_minimal_period_from_separated_cribs() {
        let key = [0x10, 0x20, 0x30, 0x40];
        let plain: Vec<u8> = (0..128).map(|i| ((i * 13 + 7) & 0xff) as u8).collect();
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let cribs = vec![
            Crib::new(0, plain[0..8].to_vec()),
            Crib::new(12, plain[12..20].to_vec()),
        ];

        let ranked = rank_periods(&cipher, &cribs, 1, 16).unwrap();
        let p4 = ranked.iter().find(|x| x.period == 4).unwrap();
        assert_eq!(p4.conflicts, 0);
        assert_eq!(p4.known_slots, 4);
        assert_eq!(p4.key, key.into_iter().map(Some).collect::<Vec<_>>());

        let rank4 = ranked.iter().position(|x| x.period == 4).unwrap();
        let rank8 = ranked.iter().position(|x| x.period == 8).unwrap();
        assert!(rank4 < rank8);
    }

    #[test]
    fn shared_files_fill_key_slots() {
        let key = [0x12, 0x34, 0x56, 0x78];
        let plain_a = b"ABxxxxxx";
        let plain_b = b"xxCDxxxx";
        let cipher_a: Vec<u8> = plain_a
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        let cipher_b: Vec<u8> = plain_b
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        let cribs_a = vec![Crib::new(0, b"AB")];
        let cribs_b = vec![Crib::new(2, b"CD")];
        let samples = [
            SharedSample {
                ciphertext: &cipher_a,
                cribs: &cribs_a,
            },
            SharedSample {
                ciphertext: &cipher_b,
                cribs: &cribs_b,
            },
        ];
        let ranked = rank_shared_periods(&samples, 4, 4).unwrap();
        assert_eq!(ranked[0].known_slots, 4);
        assert_eq!(ranked[0].key, key.into_iter().map(Some).collect::<Vec<_>>());
    }

    #[test]
    fn parses_crib() {
        let crib = parse_crib("0x10:89 50_4e47").unwrap();
        assert_eq!(crib.offset, 16);
        assert_eq!(crib.plaintext, vec![0x89, 0x50, 0x4e, 0x47]);
    }
}
