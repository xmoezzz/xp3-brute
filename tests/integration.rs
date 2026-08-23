use xp3_brute::{hypotheses_for_name, recover_stream, RecoveryConfig};

#[test]
fn extension_hypothesis_drives_period_recovery() {
    let key = [0x11, 0x22, 0x33, 0x44];
    let mut plain = vec![0u8; 128];
    plain[..8].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    plain[8..12].copy_from_slice(&13u32.to_be_bytes());
    plain[12..16].copy_from_slice(b"IHDR");
    for i in 16..plain.len() {
        plain[i] = (i as u8).wrapping_mul(29).wrapping_add(3);
    }
    // Keep every exact PNG fact used by the recovery model internally
    // consistent.  In particular, compression/filter/interlace live in the
    // IHDR payload and every PNG ends with the fixed empty IEND chunk.
    plain[24..29].copy_from_slice(&[8, 6, 0, 0, 0]);
    let iend_offset = plain.len() - 12;
    plain[iend_offset..].copy_from_slice(&[
        0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
    ]);
    let cipher: Vec<u8> = plain
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    let hypotheses = hypotheses_for_name("cg/test.png");
    let report = recover_stream(
        &cipher,
        &hypotheses,
        &RecoveryConfig {
            min_period: 1,
            max_period: 16,
            top_periods_per_hypothesis: 16,
            exhaustive_dynamic_periods: false,
            max_refinement_rounds: 4,
            ..RecoveryConfig::default()
        },
    )
    .unwrap();

    let p4 = report
        .candidates
        .iter()
        .find(|candidate| candidate.period.period == 4)
        .unwrap();
    assert_eq!(p4.period.conflicts, 0);
}
