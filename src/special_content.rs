//! Validation bridge from a recovered Special-index repeating-XOR key to the
//! ordinary XP3 content stream.
//!
//! Recovering a key from the Special index proves only that the key decrypts
//! that index.  Some titles may reuse the same repeating key for entry content,
//! but this must be established independently.  This module therefore treats a
//! Special-index key as a high-priority *candidate* and accepts it for content
//! only when reconstructed entries provide strong, whole-stream evidence.

use crate::error::{Error, Result};
use crate::format::hypotheses_for_name;
use crate::repeating_xor::{partial_decrypt, PeriodCandidate};
use crate::special_index::{OrderedNameRecovery, SpecialXorRecovery};
use crate::validate::validate_hypothesis;
use crate::xp3::{adler32, Entry};

#[derive(Clone, Debug)]
pub struct SpecialContentValidation {
    /// Complete repeating-XOR candidate derived from the Special-index key.
    pub candidate: PeriodCandidate,
    /// Entry streams successfully reconstructed by the XP3 storage layer.
    pub reconstructed_entries: usize,
    /// Entries excluded because XP3 storage reconstruction failed.
    pub reconstruction_failures: usize,
    /// Reconstructed entries carrying an XP3 `adlr` checksum.
    pub adler_tested: usize,
    /// `adlr` checks that match after applying the candidate key.
    pub adler_matches: usize,
    /// Reconstructed entries whose extension-backed format grammar validates
    /// strongly after applying the candidate key.
    pub strong_format_matches: usize,
    /// Entries for which both a strong format grammar and `adlr` agree.
    pub joint_matches: usize,
    /// Whether the candidate is strong enough to use archive-wide.
    pub accepted: bool,
    /// Stable diagnostic describing the acceptance/rejection rule that fired.
    pub reason: &'static str,
}

/// Convert an exact byte key to the complete [`PeriodCandidate`] representation
/// used by the ordinary repeating-XOR decryptor.
pub fn complete_period_candidate_from_key(key: &[u8]) -> Result<PeriodCandidate> {
    if key.is_empty() {
        return Err(Error::invalid("repeating-XOR key must not be empty"));
    }
    Ok(PeriodCandidate {
        period: key.len(),
        conflicts: 0,
        conflict_weight: 0.0,
        agreements: 0,
        agreement_weight: 0.0,
        known_slots: key.len(),
        used_slots: key.len(),
        implied_plaintext_bytes: 0,
        key: key.iter().copied().map(Some).collect(),
    })
}

/// Test whether a repeating-XOR key recovered from the Special index is also
/// the archive-wide content key.
///
/// Reconstruction failures are deliberately excluded from key validation: a
/// malformed/unsupported XP3 storage entry is not evidence that a cryptographic
/// candidate is wrong.  For reconstructed entries, however, every available
/// `adlr` must match.  At least one independently strong format validation is
/// also required.  If the archive has no `adlr` metadata at all, two strong
/// format validations are required instead.
pub fn validate_special_xor_as_content_key(
    entries: &[Entry],
    streams: &[Result<Vec<u8>>],
    xor: &SpecialXorRecovery,
    ordered_names: Option<&OrderedNameRecovery>,
) -> Result<SpecialContentValidation> {
    if entries.len() != streams.len() {
        return Err(Error::invalid(
            "entry/stream count mismatch while validating Special content key",
        ));
    }

    let candidate = complete_period_candidate_from_key(&xor.key)?;
    let mut reconstructed_entries = 0usize;
    let mut reconstruction_failures = 0usize;
    let mut adler_tested = 0usize;
    let mut adler_matches = 0usize;
    let mut strong_format_matches = 0usize;
    let mut joint_matches = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let Ok(stream) = &streams[index] else {
            reconstruction_failures += 1;
            continue;
        };
        reconstructed_entries += 1;

        let plaintext = partial_decrypt(stream, &candidate, 0);
        let adler_ok = if let Some(expected) = entry.adler {
            adler_tested += 1;
            let matches = adler32(&plaintext) == expected;
            if matches {
                adler_matches += 1;
            }
            Some(matches)
        } else {
            None
        };

        let name = ordered_names
            .and_then(|recovery| recovery.names.get(index))
            .map(String::as_str)
            .unwrap_or_else(|| entry.preferred_name());
        let strong = hypotheses_for_name(name)
            .iter()
            .any(|hypothesis| validate_hypothesis(hypothesis.name, &plaintext).is_strong());
        if strong {
            strong_format_matches += 1;
            if adler_ok == Some(true) {
                joint_matches += 1;
            }
        }
    }

    let all_adler_match = adler_tested != 0 && adler_matches == adler_tested;
    let (accepted, reason) = if reconstructed_entries == 0 {
        (false, "no reconstructed entries available")
    } else if adler_tested != 0 && adler_matches != adler_tested {
        (
            false,
            "one or more XP3 adlr checks reject the Special-derived key",
        )
    } else if all_adler_match && strong_format_matches != 0 {
        (
            true,
            "all available adlr checks and strong format grammar agree",
        )
    } else if adler_tested == 0 && strong_format_matches >= 2 {
        (
            true,
            "no adlr metadata; at least two strong format grammars agree",
        )
    } else if adler_tested == 0 {
        (
            false,
            "insufficient independent format evidence without adlr metadata",
        )
    } else {
        (
            false,
            "adlr agrees but no strong extension-backed format grammar validates",
        )
    };

    Ok(SpecialContentValidation {
        candidate,
        reconstructed_entries,
        reconstruction_failures,
        adler_tested,
        adler_matches,
        strong_format_matches,
        joint_matches,
        accepted,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::special_index::SpecialXorScope;

    fn encrypted_text_entry(name: &str, plain: &[u8], key: &[u8]) -> (Entry, Result<Vec<u8>>) {
        let cipher = plain
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect::<Vec<_>>();
        let entry = Entry {
            name: name.to_string(),
            original_size: plain.len() as u64,
            archive_size: plain.len() as u64,
            adler: Some(adler32(plain)),
            ..Entry::default()
        };
        (entry, Ok(cipher))
    }

    #[test]
    fn special_content_key_accepts_full_stream_evidence() {
        let key = vec![0x31, 0x72, 0xa4, 0x19];
        let plain1 = b"[storage]\nname=test\nvalue=123\n";
        let plain2 = b"@scenario main\nlabel=start\ntext=hello\n";
        let (entry1, stream1) = encrypted_text_entry("a.ks", plain1, &key);
        let (entry2, stream2) = encrypted_text_entry("b.tjs", plain2, &key);
        let xor = SpecialXorRecovery {
            key: key.clone(),
            scope: SpecialXorScope::Whole,
            table_start: 0,
        };

        let result =
            validate_special_xor_as_content_key(&[entry1, entry2], &[stream1, stream2], &xor, None)
                .unwrap();
        assert!(result.accepted, "{}", result.reason);
        assert_eq!(result.adler_matches, 2);
        assert_eq!(result.strong_format_matches, 2);
    }

    #[test]
    fn reconstruction_failure_does_not_reject_valid_special_key() {
        let key = vec![0x11, 0x22, 0x33, 0x44];
        let plain = b"[config]\nfoo=bar\nanswer=42\n";
        let (entry1, stream1) = encrypted_text_entry("ok.ks", plain, &key);
        let entry2 = Entry {
            name: "broken.bin".to_string(),
            adler: Some(0x1234_5678),
            ..Entry::default()
        };
        let streams = vec![
            stream1,
            Err(Error::format("synthetic reconstruction failure")),
        ];
        let xor = SpecialXorRecovery {
            key,
            scope: SpecialXorScope::Whole,
            table_start: 0,
        };

        let result =
            validate_special_xor_as_content_key(&[entry1, entry2], &streams, &xor, None).unwrap();
        assert!(result.accepted, "{}", result.reason);
        assert_eq!(result.reconstruction_failures, 1);
        assert_eq!(result.adler_tested, 1);
        assert_eq!(result.adler_matches, 1);
    }

    #[test]
    fn wrong_special_key_falls_back() {
        let true_key = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let plain = b"[config]\nfoo=bar\nanswer=42\n";
        let (entry, stream) = encrypted_text_entry("a.ks", plain, &true_key);
        let xor = SpecialXorRecovery {
            key: vec![1, 2, 3, 4],
            scope: SpecialXorScope::Whole,
            table_start: 0,
        };

        let result = validate_special_xor_as_content_key(&[entry], &[stream], &xor, None).unwrap();
        assert!(!result.accepted);
        assert_eq!(result.adler_matches, 0);
    }
}
