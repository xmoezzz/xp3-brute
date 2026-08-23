//! Pure-Rust implementation of the complemented-state ChaCha8 stream cipher
//! used by a class of Kirikiri Special/name metadata protectors.
//!
//! Detection is deliberately kept out of this module.  The cipher itself only
//! needs ten external fixed words: eight control words plus two seed words. A
//! PE/DLL/TPM/static-analysis backend may recover those words by any reliable
//! means and then instantiate the cipher. Historical section tags and
//! module names are not inputs to the algorithm.

/// Standard ChaCha "expand 32-byte k" constants.
pub(crate) const CHACHA_SIGMA: [u32; 4] = [
    0x6170_7865,
    0x3320_646e,
    0x7962_2d32,
    0x6b20_6574,
];

/// Stored/base-state representation used by this cipher.  The transform starts
/// by complementing all 16 words, therefore the sigma words are stored as
/// their bitwise complements.
pub(crate) const COMPLEMENTED_CHACHA_SIGMA: [u32; 4] = [
    !CHACHA_SIGMA[0],
    !CHACHA_SIGMA[1],
    !CHACHA_SIGMA[2],
    !CHACHA_SIGMA[3],
];

/// Complete external fixed parameters for the Special stream cipher.
///
/// These ten words are supplied by a game/profile. They are deliberately
/// separated from the cipher's own constants (sigma, round count, rotations,
/// counter layout and complement rules), which are algorithm implementation
/// details and are never part of parameter recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecialFixedParams {
    pub control_words: [u32; 8],
    pub seed0: u32,
    pub seed1: u32,
}

impl SpecialFixedParams {
    pub const fn new(control_words: [u32; 8], seed0: u32, seed1: u32) -> Self {
        Self {
            control_words,
            seed0,
            seed1,
        }
    }

    /// Construct the 16-word stored/base state used before per-block counter
    /// replacement.  This representation matches the original algorithm:
    ///
    ///   !sigma[4] || control[8] || 0xffffffff,0xffffffff || !seed0,!seed1
    pub const fn base_state(self) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0] = COMPLEMENTED_CHACHA_SIGMA[0];
        state[1] = COMPLEMENTED_CHACHA_SIGMA[1];
        state[2] = COMPLEMENTED_CHACHA_SIGMA[2];
        state[3] = COMPLEMENTED_CHACHA_SIGMA[3];
        state[4] = self.control_words[0];
        state[5] = self.control_words[1];
        state[6] = self.control_words[2];
        state[7] = self.control_words[3];
        state[8] = self.control_words[4];
        state[9] = self.control_words[5];
        state[10] = self.control_words[6];
        state[11] = self.control_words[7];
        state[12] = u32::MAX;
        state[13] = u32::MAX;
        state[14] = !self.seed0;
        state[15] = !self.seed1;
        state
    }
}

/// Backward-compatible type name. New code should use [`SpecialFixedParams`];
/// the word "profile" previously obscured the distinction between external
/// fixed parameters and constants that are intrinsic to the cipher.
pub type ComplementedChaCha8Profile = SpecialFixedParams;

/// XOR-symmetric stream cipher.  Applying it twice with the same fixed parameters
/// returns the original bytes, so the same method is used for encryption and
/// decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComplementedChaCha8Cipher {
    fixed: SpecialFixedParams,
}

impl ComplementedChaCha8Cipher {
    pub const fn new(fixed: SpecialFixedParams) -> Self {
        Self { fixed }
    }

    pub const fn fixed_params(self) -> SpecialFixedParams {
        self.fixed
    }

    /// Backward-compatible accessor. New code should use [`Self::fixed_params`].
    pub const fn profile(self) -> ComplementedChaCha8Profile {
        self.fixed
    }

    /// Apply the stream from block counter zero.
    pub fn apply(&self, data: &mut [u8]) {
        self.apply_at_block(0, data)
    }

    /// Apply starting at a 64-byte block counter.  This is mainly useful for
    /// deterministic tests and callers that already split the encrypted prefix
    /// on block boundaries.
    pub fn apply_at_block(&self, first_block: u64, data: &mut [u8]) {
        let base = self.fixed.base_state();
        for (index, chunk) in data.chunks_mut(64).enumerate() {
            let block = first_block.wrapping_add(index as u64);
            let mut input = base;
            // The stored state contains the bitwise complement of the logical
            // ChaCha counter.  The transform complements every input word
            // before the ChaCha rounds, yielding `block` in working state.
            let stored_counter = !block;
            input[12] = stored_counter as u32;
            input[13] = (stored_counter >> 32) as u32;

            let stream = complemented_chacha8_block(input);
            for (word, bytes) in stream.into_iter().zip(chunk.chunks_mut(4)) {
                let key = word.to_le_bytes();
                for (dst, src) in bytes.iter_mut().zip(key) {
                    *dst ^= src;
                }
            }
        }
    }
}

/// Transform one stored/complemented state into a 64-byte keystream block.
///
/// The original implementation is an optimized spelling of ordinary ChaCha8:
/// complement the 16 input words, perform four ChaCha double-rounds, then add
/// the complemented input state (ChaCha feed-forward).  Writing it in canonical
/// quarter-round form makes the semantics auditable and avoids subtle mistakes
/// introduced by hand-transcribing the optimized temporary-variable version.
pub fn complemented_chacha8_block(input: [u32; 16]) -> [u32; 16] {
    let initial = input.map(|word| !word);
    let mut working = initial;

    for _ in 0..4 {
        // Column round.
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal round.
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    std::array::from_fn(|index| working[index].wrapping_add(initial[index]))
}

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn garbro_compatible_reference_vector() {
        // Fixed reference vector independently generated from GARbro's
        // YuzDecryptor TransformState semantics.  It catches state-layout,
        // complement, counter, round-count and feed-forward mistakes.
        let profile = ComplementedChaCha8Profile::new(
            [
                0x0123_4567,
                0x89ab_cdef,
                0x0f1e_2d3c,
                0x4b5a_6978,
                0x8877_6655,
                0x4433_2211,
                0xcafe_babe,
                0xdead_beef,
            ],
            0xbdd7_2518,
            0xd541_d24c,
        );
        let mut actual = vec![0u8; 128];
        ComplementedChaCha8Cipher::new(profile).apply(&mut actual);
        let expected = hex_bytes(concat!(
            "8229e362d106b28e4a79ed939dbe2bb1",
            "8928719cefea0057eedf9055c35fdc42",
            "7986290ce2c3a64e15aaa0e3e00febd4",
            "d5c3f2dc2323bcf63bcc03a97af8a40b",
            "62b169d68ff9a0579be54668e4a7a65f",
            "b0ac545a024aee40c6099e371973b988",
            "e1689573a1b92ccc1e77a05f07b214e6",
            "94fcad3e36f869a8dc9a4c1b4983381e"
        ));
        assert_eq!(actual, expected);
    }

    #[test]
    fn riddle_joker_special_prefix_matches_real_archive_oracle() {
        // Public riddle.bin logical ControlBlock words + published title seeds.
        // The ciphertext is the first 16 bytes of the real Riddle Joker
        // scn.xp3 Special payload.  Correct decryption begins with a zlib
        // stream (78 DA) and matches this independently verified prefix.
        let profile = ComplementedChaCha8Profile::new(
            [
                0xbe81_1241,
                0x931d_b3bb,
                0xf37c_68d1,
                0xd90b_fe30,
                0x99e2_3016,
                0x2517_1bae,
                0xf410_5eb1,
                0x248f_f241,
            ],
            0xbdd7_2518,
            0xd541_d24c,
        );
        let mut ciphertext = hex_bytes("5457a29e07dbf182bc402f3a22ed432d");
        ComplementedChaCha8Cipher::new(profile).apply(&mut ciphertext);
        assert_eq!(
            ciphertext,
            hex_bytes("78daed977b5054551cc72f1a028d608a")
        );
    }

    #[test]
    fn xor_symmetric_roundtrip() {
        let profile = ComplementedChaCha8Profile::new(
            [0, 1, 2, 3, 4, 5, 6, 7],
            0x1122_3344,
            0x5566_7788,
        );
        let cipher = ComplementedChaCha8Cipher::new(profile);
        let original = (0..173u16).map(|value| value as u8).collect::<Vec<_>>();
        let mut data = original.clone();
        cipher.apply(&mut data);
        assert_ne!(data, original);
        cipher.apply(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn stored_state_layout_is_explicit() {
        let profile = ComplementedChaCha8Profile::new(
            [10, 11, 12, 13, 14, 15, 16, 17],
            0x1234_5678,
            0x9abc_def0,
        );
        let state = profile.base_state();
        assert_eq!(&state[..4], &COMPLEMENTED_CHACHA_SIGMA);
        assert_eq!(&state[4..12], &profile.control_words);
        assert_eq!(state[12], u32::MAX);
        assert_eq!(state[13], u32::MAX);
        assert_eq!(state[14], !profile.seed0);
        assert_eq!(state[15], !profile.seed1);
    }
}
