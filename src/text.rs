use crate::repeating_xor::PeriodCandidate;
use crate::simd::count_equal_sampled;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextRecoveryModel {
    Utf16Le,
    Utf16Be,
    Utf8,
    Cp932,
    KirikiriMode0,
    KirikiriMode1,
}

pub fn recovery_model_for_hypothesis(name: &str) -> Option<TextRecoveryModel> {
    match name {
        "Text/UTF-16LE-BOM" | "Text/UTF-16LE" => Some(TextRecoveryModel::Utf16Le),
        "Text/UTF-16BE-BOM" | "Text/UTF-16BE" => Some(TextRecoveryModel::Utf16Be),
        "Text/UTF-8-BOM" | "Text/UTF-8" => Some(TextRecoveryModel::Utf8),
        "Text/CP932" => Some(TextRecoveryModel::Cp932),
        "Kirikiri/Text-mode0" => Some(TextRecoveryModel::KirikiriMode0),
        "Kirikiri/Text-mode1" => Some(TextRecoveryModel::KirikiriMode1),
        _ => None,
    }
}

pub fn period_is_parity_sensitive(model: TextRecoveryModel) -> bool {
    matches!(
        model,
        TextRecoveryModel::Utf16Le
            | TextRecoveryModel::Utf16Be
            | TextRecoveryModel::KirikiriMode0
            | TextRecoveryModel::KirikiriMode1
    )
}

pub fn period_score_from_counts(equal: u32, total: u32, period: usize) -> f64 {
    if total == 0 {
        return -(period as f64 * 1.0e-9);
    }
    const PRIOR: f64 = 512.0;
    let base = (equal as f64 + PRIOR / 256.0) / (total as f64 + PRIOR);
    base - (period as f64 * 1.0e-9)
}

fn empty_period(period: usize) -> PeriodCandidate {
    PeriodCandidate {
        period,
        conflicts: 0,
        conflict_weight: 0.0,
        agreements: 0,
        agreement_weight: 0.0,
        known_slots: 0,
        used_slots: 0,
        implied_plaintext_bytes: 0,
        key: vec![None; period],
    }
}

fn coincidence(bytes: &[u8], lag: usize) -> f64 {
    if lag == 0 || lag >= bytes.len() {
        return 0.0;
    }
    // Long scenario scripts can be several MiB. Period discovery does not need
    // every byte; deterministic sampling keeps 1..1024 period scans bounded.
    // When the full comparison fits under the cap, the CPU path uses AVX2/SSE2
    // on x86_64 or NEON on AArch64 through `count_equal_sampled`.
    const MAX_COMPARISONS: usize = 32_768;
    let (equal, total) = count_equal_sampled(bytes, lag, MAX_COMPARISONS);
    if total == 0 {
        0.0
    } else {
        // Shrink small-sample lags toward the random-byte coincidence baseline
        // (1/256). Without this, periods close to the file length can win from
        // a handful of lucky equalities.
        const PRIOR: f64 = 512.0;
        (equal as f64 + PRIOR / 256.0) / (total as f64 + PRIOR)
    }
}

/// Ciphertext-only period score for text-like plaintext. Repeating XOR preserves
/// equality across one keystream period. UTF-16 needs byte parity to line up as
/// well, so odd periods are tested at 2*period.
pub fn period_score_with_parity(bytes: &[u8], period: usize, parity_sensitive: bool) -> f64 {
    let lag = if parity_sensitive && period % 2 == 1 {
        period.saturating_mul(2)
    } else {
        period
    };
    let base = coincidence(bytes, lag);
    // A tiny MDL-style bias makes the primitive/minimal period win ties against
    // its exact multiples without drowning out real statistical evidence.
    base - (period as f64 * 1.0e-9)
}

pub fn period_score(bytes: &[u8], period: usize, model: TextRecoveryModel) -> f64 {
    period_score_with_parity(bytes, period, period_is_parity_sensitive(model))
}

pub fn rank_statistical_periods(
    bytes: &[u8],
    model: TextRecoveryModel,
    min_period: usize,
    max_period: usize,
) -> Vec<PeriodCandidate> {
    let mut periods: Vec<_> = (min_period..=max_period)
        .map(|period| (period_score(bytes, period, model), empty_period(period)))
        .collect();
    periods.sort_by(|(sa, a), (sb, b)| sb.total_cmp(sa).then_with(|| a.period.cmp(&b.period)));
    periods.into_iter().map(|(_, p)| p).collect()
}

pub fn rank_statistical_periods_from_scores(
    scores: &[f64],
    min_period: usize,
) -> Vec<PeriodCandidate> {
    let mut periods: Vec<_> = scores
        .iter()
        .copied()
        .enumerate()
        .map(|(index, score)| {
            let period = min_period + index;
            (score, empty_period(period))
        })
        .collect();
    periods.sort_by(|(sa, a), (sb, b)| sb.total_cmp(sa).then_with(|| a.period.cmp(&b.period)));
    periods.into_iter().map(|(_, period)| period).collect()
}

fn ascii_low_score(byte: u8) -> f64 {
    match byte {
        b'\r' | b'\n' => 9.0,
        b' ' => 8.0,
        b'\t' => 6.0,
        b'{' | b'}' | b'[' | b']' | b'(' | b')' | b';' | b'=' | b',' | b'.' | b'@' | b'/'
        | b'*' | b'+' | b'-' | b'_' | b'<' | b'>' | b'"' | b'\'' | b'\\' | b':' | b'#' | b'$'
        | b'%' | b'&' | b'|' | b'!' | b'?' => 6.0,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => 4.5,
        0x21..=0x7e => 2.5,
        0 => -3.0,
        _ => 0.25,
    }
}

fn utf16_byte_score(offset: usize, byte: u8, little_endian: bool) -> f64 {
    let high = if little_endian {
        offset % 2 == 1
    } else {
        offset % 2 == 0
    };
    if high {
        match byte {
            0 => 10.0,
            0x20..=0x9f => 0.8,
            0xd8..=0xdf => -3.0,
            _ => 0.0,
        }
    } else {
        ascii_low_score(byte)
    }
}

fn utf8_byte_score(byte: u8) -> f64 {
    match byte {
        b'\r' | b'\n' => 8.0,
        b' ' => 7.0,
        b'\t' => 5.0,
        b'{' | b'}' | b'[' | b']' | b'(' | b')' | b';' | b'=' | b',' | b'.' | b'@' | b'/'
        | b'*' | b'+' | b'-' | b'_' | b'<' | b'>' | b'"' | b'\'' | b'\\' | b':' | b'#' | b'$'
        | b'%' | b'&' | b'|' | b'!' | b'?' => 5.0,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => 3.5,
        0x21..=0x7e => 1.75,
        0x80..=0xbf => 0.9,
        0xc2..=0xdf => 0.7,
        0xe0..=0xef => 0.8,
        0xf0..=0xf4 => 0.35,
        0 => -2.0,
        _ => -6.0,
    }
}

fn cp932_byte_score(byte: u8) -> f64 {
    match byte {
        b'\r' | b'\n' => 8.0,
        b' ' => 7.0,
        b'\t' => 5.0,
        b'{' | b'}' | b'[' | b']' | b'(' | b')' | b';' | b'=' | b',' | b'.' | b'@' | b'/'
        | b'*' | b'+' | b'-' | b'_' | b'<' | b'>' | b'"' | b'\'' | b'\\' | b':' | b'#' | b'$'
        | b'%' | b'&' | b'|' | b'!' | b'?' => 5.0,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => 3.5,
        0x21..=0x7e => 1.75,
        0xa1..=0xdf => 1.0,
        0x81..=0x9f | 0xe0..=0xfc => 0.9,
        0x80 | 0xa0 | 0xfd..=0xff => -5.0,
        0 => -2.0,
        _ => 0.25,
    }
}

fn swap_adjacent_bits(ch: u16) -> u16 {
    ((ch & 0xaaaa) >> 1) | ((ch & 0x5555) << 1)
}

fn decode_mode0_char(ch: u16) -> u16 {
    if ch >= 0x20 {
        ch ^ (((ch & 0x00fe) << 8) ^ 1)
    } else {
        ch
    }
}

fn encoded_mode0_byte_score(offset: usize, byte: u8) -> f64 {
    if offset < 5 {
        return 0.0;
    }
    // For an ASCII decoded character d, mode-0 stores low=(d_low^1) and
    // high=(low&0xfe). Both bytes therefore retain a strong ASCII-like bias.
    ascii_low_score(byte)
}

fn encoded_mode1_byte_score(offset: usize, byte: u8) -> f64 {
    if offset < 5 {
        return 0.0;
    }
    let high = (offset - 5) % 2 == 1;
    if high {
        if byte == 0 {
            10.0
        } else {
            0.0
        }
    } else {
        // Adjacent-bit swapping preserves the rough printable-byte range.
        ascii_low_score(swap_adjacent_bits(byte as u16) as u8)
    }
}

fn char_score(ch: u16) -> f64 {
    match ch {
        0xfeff => 10.0,
        0x0009 | 0x000a | 0x000d => 10.0,
        0x0020 => 8.0,
        0x0021..=0x007e => {
            let b = ch as u8;
            if b"{}[]();=,@/*+-_<>\"'\\:#$%&|!?".contains(&b) {
                7.0
            } else if b.is_ascii_alphanumeric() {
                5.0
            } else {
                3.0
            }
        }
        0x2000..=0x2fff => 2.5,
        0x3000..=0x30ff => 3.0,
        0x3400..=0x9fff => 2.25,
        0xff00..=0xffef => 2.5,
        0x0000..=0x001f => -18.0,
        0xd800..=0xdfff => -28.0,
        _ => 0.25,
    }
}

fn choose_independent_key(
    ciphertext: &[u8],
    period: &PeriodCandidate,
    model: TextRecoveryModel,
) -> (Vec<u8>, Vec<bool>) {
    let used = period.period.min(ciphertext.len());
    let mut key = vec![0u8; period.period];
    let mut fixed = vec![false; period.period];

    for slot in 0..used {
        if let Some(value) = period.key.get(slot).copied().flatten() {
            key[slot] = value;
            fixed[slot] = true;
            continue;
        }

        let mut low_hist = [0u32; 256];
        let mut high_hist = [0u32; 256];
        let mut all_hist = [0u32; 256];
        let mut pos = slot;
        while pos < ciphertext.len() {
            all_hist[ciphertext[pos] as usize] += 1;
            match model {
                TextRecoveryModel::Utf16Le => {
                    if pos % 2 == 1 {
                        high_hist[ciphertext[pos] as usize] += 1;
                    } else {
                        low_hist[ciphertext[pos] as usize] += 1;
                    }
                }
                TextRecoveryModel::Utf16Be => {
                    if pos % 2 == 0 {
                        high_hist[ciphertext[pos] as usize] += 1;
                    } else {
                        low_hist[ciphertext[pos] as usize] += 1;
                    }
                }
                _ => {}
            }
            pos += period.period;
        }

        let mut best = (f64::NEG_INFINITY, 0u8);
        for candidate in 0u16..=255 {
            let k = candidate as u8;
            let mut score = 0.0;
            match model {
                TextRecoveryModel::Utf16Le | TextRecoveryModel::Utf16Be => {
                    for cipher in 0..256 {
                        if low_hist[cipher] != 0 {
                            let plain = cipher as u8 ^ k;
                            let offset_parity = if matches!(model, TextRecoveryModel::Utf16Le) {
                                0
                            } else {
                                1
                            };
                            score += low_hist[cipher] as f64
                                * utf16_byte_score(
                                    offset_parity,
                                    plain,
                                    matches!(model, TextRecoveryModel::Utf16Le),
                                );
                        }
                        if high_hist[cipher] != 0 {
                            let plain = cipher as u8 ^ k;
                            let offset_parity = if matches!(model, TextRecoveryModel::Utf16Le) {
                                1
                            } else {
                                0
                            };
                            score += high_hist[cipher] as f64
                                * utf16_byte_score(
                                    offset_parity,
                                    plain,
                                    matches!(model, TextRecoveryModel::Utf16Le),
                                );
                        }
                    }
                }
                TextRecoveryModel::Utf8 => {
                    for cipher in 0..256 {
                        if all_hist[cipher] != 0 {
                            score += all_hist[cipher] as f64 * utf8_byte_score(cipher as u8 ^ k);
                        }
                    }
                }
                TextRecoveryModel::Cp932 => {
                    for cipher in 0..256 {
                        if all_hist[cipher] != 0 {
                            score += all_hist[cipher] as f64 * cp932_byte_score(cipher as u8 ^ k);
                        }
                    }
                }
                TextRecoveryModel::KirikiriMode0 => {
                    let mut p = slot;
                    while p < ciphertext.len() {
                        score += encoded_mode0_byte_score(p, ciphertext[p] ^ k);
                        p += period.period;
                    }
                }
                TextRecoveryModel::KirikiriMode1 => {
                    let mut p = slot;
                    while p < ciphertext.len() {
                        score += encoded_mode1_byte_score(p, ciphertext[p] ^ k);
                        p += period.period;
                    }
                }
            }
            if score > best.0 {
                best = (score, k);
            }
        }
        key[slot] = best.1;
    }
    (key, fixed)
}

fn code_unit_score(
    ciphertext: &[u8],
    key: &[u8],
    period: usize,
    offset: usize,
    model: TextRecoveryModel,
) -> f64 {
    if offset + 1 >= ciphertext.len() {
        return 0.0;
    }
    let a = ciphertext[offset] ^ key[offset % period];
    let b = ciphertext[offset + 1] ^ key[(offset + 1) % period];
    let raw = u16::from_le_bytes([a, b]);
    let ch = match model {
        TextRecoveryModel::Utf16Le => raw,
        TextRecoveryModel::Utf16Be => u16::from_be_bytes([a, b]),
        TextRecoveryModel::KirikiriMode0 => decode_mode0_char(raw),
        TextRecoveryModel::KirikiriMode1 => swap_adjacent_bits(raw),
        _ => return 0.0,
    };
    char_score(ch)
}

fn coordinate_refine(
    ciphertext: &[u8],
    period: usize,
    model: TextRecoveryModel,
    mut key: Vec<u8>,
    fixed: &[bool],
    rounds: usize,
) -> Vec<u8> {
    let payload_start = match model {
        TextRecoveryModel::KirikiriMode0 | TextRecoveryModel::KirikiriMode1 => 5,
        _ => 0,
    };
    if !matches!(
        model,
        TextRecoveryModel::Utf16Le
            | TextRecoveryModel::Utf16Be
            | TextRecoveryModel::KirikiriMode0
            | TextRecoveryModel::KirikiriMode1
    ) {
        return key;
    }

    let mut affected: Vec<Vec<usize>> = (0..period).map(|_| Vec::new()).collect();
    let mut offset = payload_start;
    while offset + 1 < ciphertext.len() {
        let a = offset % period;
        let b = (offset + 1) % period;
        affected[a].push(offset);
        if b != a {
            affected[b].push(offset);
        }
        offset += 2;
    }

    for _ in 0..rounds {
        let mut changed = false;
        for slot in 0..period.min(ciphertext.len()) {
            if fixed.get(slot).copied().unwrap_or(false) || affected[slot].is_empty() {
                continue;
            }
            let old = key[slot];
            let mut best = (f64::NEG_INFINITY, old);
            for candidate in 0u16..=255 {
                key[slot] = candidate as u8;
                let score: f64 = affected[slot]
                    .iter()
                    .map(|&at| code_unit_score(ciphertext, &key, period, at, model))
                    .sum();
                if score > best.0 {
                    best = (score, candidate as u8);
                }
            }
            key[slot] = best.1;
            changed |= best.1 != old;
        }
        if !changed {
            break;
        }
    }
    key
}

/// Produce one or two full-key heuristic guesses for a text model. These are
/// never trusted by themselves: callers must still require XP3 adlr and a
/// strong independent text/bytecode validator.
pub fn guess_text_keys(
    ciphertext: &[u8],
    period: &PeriodCandidate,
    model: TextRecoveryModel,
    coordinate_rounds: usize,
) -> Vec<Vec<u8>> {
    if period.period == 0 || ciphertext.is_empty() || period.conflicts != 0 {
        return Vec::new();
    }
    let (initial, fixed) = choose_independent_key(ciphertext, period, model);
    let mut out = vec![initial.clone()];
    if coordinate_rounds > 0 {
        let refined = coordinate_refine(
            ciphertext,
            period.period,
            model,
            initial,
            &fixed,
            coordinate_rounds,
        );
        if refined != out[0] {
            out.push(refined);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_score_matches_sampled_period_score() {
        let bytes: Vec<u8> = (0..50_000usize)
            .map(|i| ((i * 37 + (i / 31) * 11) & 0xff) as u8)
            .collect();
        for &(period, parity_sensitive) in &[(31usize, true), (32, true), (31, false), (97, false)]
        {
            let lag = if parity_sensitive && period % 2 == 1 {
                period * 2
            } else {
                period
            };
            let available = bytes.len() - lag;
            const MAX_COMPARISONS: usize = 32_768;
            let step = ((available + MAX_COMPARISONS - 1) / MAX_COMPARISONS).max(1);
            let mut equal = 0u32;
            let mut total = 0u32;
            let mut i = 0usize;
            while i < available {
                equal += u32::from(bytes[i] == bytes[i + lag]);
                total += 1;
                i += step;
            }
            let from_counts = period_score_from_counts(equal, total, period);
            let direct = period_score_with_parity(&bytes, period, parity_sensitive);
            assert!(
                (from_counts - direct).abs() < 1.0e-15,
                "period={period} parity={parity_sensitive}"
            );
        }
    }

    #[test]
    fn utf16le_period_score_prefers_true_period_family() {
        let plain = "// startup.tjs\r\nvar x = 1;\r\n"
            .repeat(40)
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let key: Vec<u8> = (0..31).map(|i| (i * 17 + 3) as u8).collect();
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 31])
            .collect();
        let ranked = rank_statistical_periods(&cipher, TextRecoveryModel::Utf16Le, 1, 128);
        assert!(ranked.iter().take(8).any(|p| p.period == 31));
    }

    #[test]
    fn utf16le_guess_recovers_ascii_heavy_script() {
        let mut plain = vec![0xff, 0xfe];
        for unit in "// startup.tjs - test\r\nvar value = 123;\r\n"
            .repeat(50)
            .encode_utf16()
        {
            plain.extend_from_slice(&unit.to_le_bytes());
        }
        let key: Vec<u8> = (0..31).map(|i| (i * 29 + 11) as u8).collect();
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 31])
            .collect();
        let mut period = empty_period(31);
        period.key[0] = Some(cipher[0] ^ 0xff);
        period.key[1] = Some(cipher[1] ^ 0xfe);
        period.known_slots = 2;
        let guesses = guess_text_keys(&cipher, &period, TextRecoveryModel::Utf16Le, 2);
        assert!(guesses.iter().any(|guess| guess == &key));
    }
}
