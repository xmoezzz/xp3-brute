//! Architecture-aware CPU kernels used when GPU work is unavailable or too small.
//!
//! The public API stays scalar-safe.  On x86_64 it dispatches to AVX2 when
//! available (SSE2 otherwise); on AArch64 it uses NEON, which is mandatory for
//! the architecture.  Other 64-bit targets use a word-at-a-time fallback.

/// Human-readable name of the CPU kernel selected on this machine.
pub fn cpu_backend_label() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return "x86_64-avx2";
        }
        return "x86_64-sse2";
    }
    #[cfg(target_arch = "aarch64")]
    {
        return "aarch64-neon";
    }
    #[cfg(all(
        target_pointer_width = "64",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        return "scalar-u64";
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        "scalar"
    }
}

/// Count equal bytes in two equally-sized slices.
pub fn count_equal(a: &[u8], b: &[u8]) -> u32 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 0;
    }
    let a = &a[..len];
    let b = &b[..len];

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: runtime feature detection guarantees AVX2 support; both
            // pointers are valid for `len` bytes and the kernel uses unaligned loads.
            return unsafe { count_equal_avx2(a, b) };
        }
        // SSE2 is part of the x86_64 baseline.
        // SAFETY: same slice validity argument as above.
        return unsafe { count_equal_sse2(a, b) };
    }

    #[cfg(target_arch = "aarch64")]
    {
        // NEON/Advanced SIMD is part of the AArch64 baseline.
        // SAFETY: the kernel uses unaligned-safe vector loads within bounds.
        return unsafe { count_equal_neon(a, b) };
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        count_equal_scalar64(a, b)
    }
}

/// Count equality at the deterministic sampling density used by period scoring.
pub fn count_equal_sampled(bytes: &[u8], lag: usize, max_comparisons: usize) -> (u32, u32) {
    if lag == 0 || lag >= bytes.len() || max_comparisons == 0 {
        return (0, 0);
    }
    let available = bytes.len() - lag;
    let step = ((available + max_comparisons - 1) / max_comparisons).max(1);
    if step == 1 {
        return (
            count_equal(&bytes[..available], &bytes[lag..lag + available]),
            available as u32,
        );
    }
    let mut equal = 0u32;
    let mut total = 0u32;
    let mut i = 0usize;
    while i < available {
        equal += u32::from(bytes[i] == bytes[i + lag]);
        total += 1;
        i = i.saturating_add(step);
    }
    (equal, total)
}

/// XOR a constant byte over a mutable range using the best CPU kernel.
pub fn xor_const_in_place(buf: &mut [u8], key: u8) {
    if key == 0 || buf.is_empty() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: feature detection and slice validity as documented above.
            unsafe {
                xor_const_avx2(buf, key);
            }
            return;
        }
        // SAFETY: SSE2 baseline on x86_64.
        unsafe {
            xor_const_sse2(buf, key);
        }
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON baseline on AArch64.
        unsafe {
            xor_const_neon(buf, key);
        }
        return;
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        xor_const_scalar64(buf, key);
    }
}

/// XOR a repeating byte key over `buf`, where `stream_offset` is the absolute
/// position of `buf[0]` in the encrypted stream.  The hot special-index periods
/// 1/2/4 divide all supported SIMD widths, so their vector mask is phase-stable
/// across blocks. Other periods use a safe scalar fallback.
pub fn xor_repeating_in_place(buf: &mut [u8], key: &[u8], stream_offset: usize) {
    if buf.is_empty() || key.is_empty() {
        return;
    }
    if key.len() == 1 {
        xor_const_in_place(buf, key[stream_offset % key.len()]);
        return;
    }
    if matches!(key.len(), 2 | 4) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime and the helper stays in bounds.
                unsafe {
                    xor_repeating_avx2(buf, key, stream_offset);
                }
                return;
            }
            // SAFETY: SSE2 is part of the x86_64 baseline.
            unsafe {
                xor_repeating_sse2(buf, key, stream_offset);
            }
            return;
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Advanced SIMD is part of the AArch64 baseline.
            unsafe {
                xor_repeating_neon(buf, key, stream_offset);
            }
            return;
        }
    }
    #[cfg(all(
        target_pointer_width = "64",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        if matches!(key.len(), 2 | 4) {
            xor_repeating_scalar64(buf, key, stream_offset);
            return;
        }
    }
    xor_repeating_scalar(buf, key, stream_offset);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn count_equal_avx2(a: &[u8], b: &[u8]) -> u32 {
    use std::arch::x86_64::*;
    let mut i = 0usize;
    let mut equal = 0u32;
    while i + 32 <= a.len() {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let cmp = _mm256_cmpeq_epi8(va, vb);
        equal += (_mm256_movemask_epi8(cmp) as u32).count_ones();
        i += 32;
    }
    while i < a.len() {
        equal += u32::from(*a.get_unchecked(i) == *b.get_unchecked(i));
        i += 1;
    }
    equal
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn count_equal_sse2(a: &[u8], b: &[u8]) -> u32 {
    use std::arch::x86_64::*;
    let mut i = 0usize;
    let mut equal = 0u32;
    while i + 16 <= a.len() {
        let va = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
        let vb = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);
        let cmp = _mm_cmpeq_epi8(va, vb);
        equal += (_mm_movemask_epi8(cmp) as u32).count_ones();
        i += 16;
    }
    while i < a.len() {
        equal += u32::from(*a.get_unchecked(i) == *b.get_unchecked(i));
        i += 1;
    }
    equal
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_const_avx2(buf: &mut [u8], key: u8) {
    use std::arch::x86_64::*;
    let k = _mm256_set1_epi8(key as i8);
    let mut i = 0usize;
    while i + 32 <= buf.len() {
        let p = buf.as_mut_ptr().add(i) as *mut __m256i;
        let v = _mm256_loadu_si256(p as *const __m256i);
        _mm256_storeu_si256(p, _mm256_xor_si256(v, k));
        i += 32;
    }
    while i < buf.len() {
        *buf.get_unchecked_mut(i) ^= key;
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn xor_const_sse2(buf: &mut [u8], key: u8) {
    use std::arch::x86_64::*;
    let k = _mm_set1_epi8(key as i8);
    let mut i = 0usize;
    while i + 16 <= buf.len() {
        let p = buf.as_mut_ptr().add(i) as *mut __m128i;
        let v = _mm_loadu_si128(p as *const __m128i);
        _mm_storeu_si128(p, _mm_xor_si128(v, k));
        i += 16;
    }
    while i < buf.len() {
        *buf.get_unchecked_mut(i) ^= key;
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn count_equal_neon(a: &[u8], b: &[u8]) -> u32 {
    use std::arch::aarch64::*;
    let mut i = 0usize;
    let mut equal = 0u32;
    while i + 16 <= a.len() {
        let va = vld1q_u8(a.as_ptr().add(i));
        let vb = vld1q_u8(b.as_ptr().add(i));
        let cmp = vceqq_u8(va, vb);
        let ones = vshrq_n_u8(cmp, 7);
        equal += vaddvq_u8(ones) as u32;
        i += 16;
    }
    while i < a.len() {
        equal += u32::from(*a.get_unchecked(i) == *b.get_unchecked(i));
        i += 1;
    }
    equal
}

#[cfg(target_arch = "aarch64")]
unsafe fn xor_const_neon(buf: &mut [u8], key: u8) {
    use std::arch::aarch64::*;
    let k = vdupq_n_u8(key);
    let mut i = 0usize;
    while i + 16 <= buf.len() {
        let p = buf.as_mut_ptr().add(i);
        let v = vld1q_u8(p as *const u8);
        vst1q_u8(p, veorq_u8(v, k));
        i += 16;
    }
    while i < buf.len() {
        *buf.get_unchecked_mut(i) ^= key;
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_repeating_avx2(buf: &mut [u8], key: &[u8], stream_offset: usize) {
    use std::arch::x86_64::*;
    let mut mask_bytes = [0u8; 32];
    for i in 0..32 {
        mask_bytes[i] = key[(stream_offset + i) % key.len()];
    }
    let mask = _mm256_loadu_si256(mask_bytes.as_ptr() as *const __m256i);
    let mut i = 0usize;
    while i + 32 <= buf.len() {
        let p = buf.as_mut_ptr().add(i) as *mut __m256i;
        let v = _mm256_loadu_si256(p as *const __m256i);
        _mm256_storeu_si256(p, _mm256_xor_si256(v, mask));
        i += 32;
    }
    while i < buf.len() {
        *buf.get_unchecked_mut(i) ^= key[(stream_offset + i) % key.len()];
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn xor_repeating_sse2(buf: &mut [u8], key: &[u8], stream_offset: usize) {
    use std::arch::x86_64::*;
    let mut mask_bytes = [0u8; 16];
    for i in 0..16 {
        mask_bytes[i] = key[(stream_offset + i) % key.len()];
    }
    let mask = _mm_loadu_si128(mask_bytes.as_ptr() as *const __m128i);
    let mut i = 0usize;
    while i + 16 <= buf.len() {
        let p = buf.as_mut_ptr().add(i) as *mut __m128i;
        let v = _mm_loadu_si128(p as *const __m128i);
        _mm_storeu_si128(p, _mm_xor_si128(v, mask));
        i += 16;
    }
    while i < buf.len() {
        *buf.get_unchecked_mut(i) ^= key[(stream_offset + i) % key.len()];
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn xor_repeating_neon(buf: &mut [u8], key: &[u8], stream_offset: usize) {
    use std::arch::aarch64::*;
    let mut mask_bytes = [0u8; 16];
    for i in 0..16 {
        mask_bytes[i] = key[(stream_offset + i) % key.len()];
    }
    let mask = vld1q_u8(mask_bytes.as_ptr());
    let mut i = 0usize;
    while i + 16 <= buf.len() {
        let p = buf.as_mut_ptr().add(i);
        let v = vld1q_u8(p as *const u8);
        vst1q_u8(p, veorq_u8(v, mask));
        i += 16;
    }
    while i < buf.len() {
        *buf.get_unchecked_mut(i) ^= key[(stream_offset + i) % key.len()];
        i += 1;
    }
}

#[cfg(all(
    target_pointer_width = "64",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn xor_repeating_scalar64(buf: &mut [u8], key: &[u8], stream_offset: usize) {
    debug_assert!(matches!(key.len(), 2 | 4));
    let mut mask_bytes = [0u8; 8];
    for (i, byte) in mask_bytes.iter_mut().enumerate() {
        *byte = key[(stream_offset + i) % key.len()];
    }
    let mask = u64::from_ne_bytes(mask_bytes);
    let full_len = (buf.len() / 8) * 8;
    let (head, tail) = buf.split_at_mut(full_len);
    for chunk in head.chunks_exact_mut(8) {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(chunk);
        let word = u64::from_ne_bytes(word_bytes) ^ mask;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    for (i, byte) in tail.iter_mut().enumerate() {
        *byte ^= key[(stream_offset + full_len + i) % key.len()];
    }
}

fn xor_repeating_scalar(buf: &mut [u8], key: &[u8], stream_offset: usize) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte ^= key[(stream_offset + i) % key.len()];
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn count_equal_scalar64(a: &[u8], b: &[u8]) -> u32 {
    let mut i = 0usize;
    let mut equal = 0u32;
    while i + 8 <= a.len() {
        let aa = u64::from_ne_bytes(a[i..i + 8].try_into().unwrap());
        let bb = u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
        let x = aa ^ bb;
        // A zero byte in x means equality.  Use the classic zero-byte detector,
        // then count bytes explicitly to avoid any endian-sensitive tricks.
        if x == 0 {
            equal += 8;
        } else {
            for j in 0..8 {
                equal += u32::from(a[i + j] == b[i + j]);
            }
        }
        i += 8;
    }
    while i < a.len() {
        equal += u32::from(a[i] == b[i]);
        i += 1;
    }
    equal
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn xor_const_scalar64(buf: &mut [u8], key: u8) {
    let word = u64::from_ne_bytes([key; 8]);
    let mut i = 0usize;
    while i + 8 <= buf.len() {
        let value = u64::from_ne_bytes(buf[i..i + 8].try_into().unwrap()) ^ word;
        buf[i..i + 8].copy_from_slice(&value.to_ne_bytes());
        i += 8;
    }
    while i < buf.len() {
        buf[i] ^= key;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_kernel_matches_scalar() {
        let a: Vec<u8> = (0..1000).map(|i| (i * 37) as u8).collect();
        let mut b = a.clone();
        for i in (0..b.len()).step_by(17) {
            b[i] ^= 0x5a;
        }
        let expected = a.iter().zip(&b).filter(|(x, y)| x == y).count() as u32;
        assert_eq!(count_equal(&a, &b), expected);
    }

    #[test]
    fn xor_kernel_roundtrip() {
        let original: Vec<u8> = (0..777).map(|i| (i * 13) as u8).collect();
        let mut data = original.clone();
        xor_const_in_place(&mut data, 0xa5);
        assert_ne!(data, original);
        xor_const_in_place(&mut data, 0xa5);
        assert_eq!(data, original);
    }

    #[test]
    fn repeating_xor_kernel_respects_stream_offset() {
        for key in [
            &[0x12u8][..],
            &[0x12, 0x34][..],
            &[1, 2, 3][..],
            &[1, 2, 3, 4][..],
        ] {
            let mut got: Vec<u8> = (0..257).map(|i| i as u8).collect();
            let mut expected = got.clone();
            for (i, byte) in expected.iter_mut().enumerate() {
                *byte ^= key[(7 + i) % key.len()];
            }
            xor_repeating_in_place(&mut got, key, 7);
            assert_eq!(got, expected);
        }
    }
}
