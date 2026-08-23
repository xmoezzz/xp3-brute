//! Reconstructed HXV4 ordinary-entry content filter.
//!
//! The HXV4 Special index stores a 64-bit `entry_key` for every protected
//! ordinary XP3 entry. The title's FilterManager deterministically expands the
//! game-wide PARAMS/control table into 128 DripValue programs. This module
//! reproduces the native flat `[param, handler]` program representation and the
//! interpreter used by `sub_10019300`; it does not execute emitted x86.
//!
//! The final transformation is XOR-only, therefore encryption and decryption
//! are the same operation. Adler verification remains the authority for whether
//! this reconstruction is correct for a particular title/entry.

#[derive(Clone, Debug)]
pub struct Hxv4NativeFilterManager {
    table: Vec<u32>,
    lanes: Vec<VmProgram>,
    mask: u32,
    offset: u32,
    control_mode: u8,
    random_type: u8,
    holder_low: u32,
    holder_high: u32,
}

/// One native FilterManager vector element: `[param:u32, handler]`.
///
/// The original vector stores a function pointer in the second word. Rust uses
/// an enum for that pointer while preserving the same instruction order and
/// interpreter state transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VmInstruction {
    param: u32,
    op: VmOp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VmProgram {
    instructions: Vec<VmInstruction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmOp {
    AddParam,           // sub_10017C50
    EnterBlock,         // sub_10017C60
    AddScratch,         // sub_10017CB0
    MulScratch,         // sub_10017CD0
    ScratchMinusResult, // sub_10017CF0
    ShlScratch,         // sub_10017D10
    ShrScratch,         // sub_10017D30
    SubScratch,         // sub_10017D50
    BitShuffle,         // sub_10017D70
    LoadImmediate,      // sub_10017DA0
    LoadSeed,           // sub_10017DB0
    Dec,                // sub_10017DD0
    Inc,                // sub_10017DE0
    Neg,                // sub_10017DF0
    Not,                // sub_10017E00
    LoadTableImmediate, // sub_10017E10
    LoadTableMasked,    // sub_10017E30
    SubParam,           // sub_10017E50
    StoreScratch,       // sub_10017E60
    XorParam,           // sub_10017E80
    Stop,               // sub_10051D90
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hxv4NativeBoundary {
    pub position0: u64,
    pub position1: u64,
    pub xor_byte: u8,
    pub correction0: u8,
    pub correction1: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hxv4NativeFilterState {
    pub entry_key: u64,
    pub local_flag: u16,
    pub open_flag: bool,
    pub split: u64,
    pub prefix_xor: [u8; 16],
    pub left_drip: u64,
    pub right_drip: u64,
    pub left: Hxv4NativeBoundary,
    pub right: Hxv4NativeBoundary,
}

impl Hxv4NativeFilterManager {
    /// Construct the reconstructed FilterManager from the 22-byte HXV4 PARAMS
    /// record and the 1024-word control table produced by the bootstrap KDF.
    pub fn from_params_and_table(params: &[u8], table: &[u32]) -> Result<Self, String> {
        if params.len() < 0x16 {
            return Err(format!("HXV4 PARAMS truncated: {} bytes", params.len()));
        }
        if table.len() != 1024 {
            return Err(format!(
                "HXV4 control table has {} words, expected 1024",
                table.len()
            ));
        }
        if !permutation_valid(&params[0..8], 8)
            || !permutation_valid(&params[8..14], 6)
            || !permutation_valid(&params[14..17], 3)
        {
            return Err("HXV4 PARAMS opcode maps are not permutations".to_string());
        }

        let control_mode = (params[17] & 1) + 1;
        let random_type = params[17] >> 7;
        if random_type > 1 {
            return Err(format!(
                "HXV4 PARAMS random type {} is unsupported",
                random_type
            ));
        }
        let mask = u16::from_le_bytes([params[18], params[19]]) as u32;
        let offset = u16::from_le_bytes([params[20], params[21]]) as u32;

        let mut lanes = Vec::with_capacity(128);
        for lane in 0..128u32 {
            let mut rng = GeneratorRng::for_lane(lane, random_type);
            let program = build_lane(params, &mut rng)
                .ok_or_else(|| format!("HXV4 DripValue lane {lane} exceeded the native 128-byte generator budget in all five attempts"))?;
            lanes.push(program);
        }

        Ok(Self {
            table: table.to_vec(),
            lanes,
            mask,
            offset,
            control_mode,
            random_type,
            // FilterManagerImpl starts these words at zero.  Storages.archiveUniqueKey
            // later derives and installs the real per-title holder state.  The
            // executable recovery path calls `with_holder_words` before use.
            holder_low: 0,
            holder_high: 0,
        })
    }

    pub fn mask(&self) -> u32 {
        self.mask
    }
    pub fn offset(&self) -> u32 {
        self.offset
    }
    pub fn control_mode(&self) -> u8 {
        self.control_mode
    }
    pub fn random_type(&self) -> u8 {
        self.random_type
    }
    pub fn random_type_label(&self) -> &'static str {
        if self.random_type == 0 {
            "xoroshiro128++"
        } else {
            "xoroshiro128**"
        }
    }

    /// Install the two words written by `sub_100157D0` after
    /// `Storages.archiveUniqueKey` is set.  `sub_10013C60` XORs them into the
    /// 64-bit entry key whenever the per-entry open flag is clear.
    pub fn with_holder_words(mut self, holder_low: u32, holder_high: u32) -> Self {
        self.holder_low = holder_low;
        self.holder_high = holder_high;
        self
    }

    pub fn holder_low(&self) -> u32 {
        self.holder_low
    }
    pub fn holder_high(&self) -> u32 {
        self.holder_high
    }

    /// Native DripValue `get64(u32)` operation. Low seven input bits select one
    /// of 128 generated lanes; the remaining bits are the lane seed.
    pub fn drip64(&self, value: u32) -> u64 {
        let lane = (value & 0x7f) as usize;
        let seed = value >> 7;
        let lo = self.eval_program(&self.lanes[lane], seed);
        let hi = self.eval_program(&self.lanes[lane], !seed);
        (u64::from(hi) << 32) | u64::from(lo)
    }

    /// Build the native runtime state for one Special-record `entry_key`.
    ///
    /// The engine forwards a per-entry 16-bit value and `sub_10013CF0` masks it
    /// to one bit before calling `sub_10013C60`.
    pub fn state_for_entry(&self, entry_key: u64, local_flag: u16) -> Hxv4NativeFilterState {
        self.state_for_entry_with_open_flag(entry_key, local_flag, local_flag & 1 != 0)
    }

    fn state_for_entry_with_open_flag(
        &self,
        entry_key: u64,
        local_flag: u16,
        open_flag: bool,
    ) -> Hxv4NativeFilterState {
        let mut lo = entry_key as u32;
        let mut hi = (entry_key >> 32) as u32;
        if !open_flag {
            lo ^= self.holder_low;
            hi ^= self.holder_high;
        }
        let key = (u64::from(hi) << 32) | u64::from(lo);

        let left_drip = self.drip64(lo);
        let right_drip = self.drip64(hi);
        let split = u64::from(self.offset.wrapping_add(self.mask & ((key >> 16) as u32)));

        let mut prefix_xor = [0u8; 16];
        let mut cursor = !key;
        for chunk in prefix_xor.chunks_mut(8) {
            cursor = !self.drip64(cursor as u32);
            chunk.copy_from_slice(&cursor.to_be_bytes());
        }

        Hxv4NativeFilterState {
            entry_key,
            local_flag,
            open_flag,
            split,
            prefix_xor,
            left_drip,
            right_drip,
            left: boundary_from_drip(left_drip, false),
            right: boundary_from_drip(right_drip, false),
        }
    }

    pub fn apply_entry(
        &self,
        entry_key: u64,
        local_flag: u16,
        logical_offset: u64,
        data: &mut [u8],
    ) {
        self.state_for_entry(entry_key, local_flag)
            .apply(logical_offset, data);
    }

    /// Interpreter equivalent of `sub_10019300`.
    fn eval_program(&self, program: &VmProgram, seed: u32) -> u32 {
        let mut pc = 0usize;
        let mut scratch = 0u32;
        let mut result = 0u32;
        self.execute_until_stop(program, seed, &mut pc, &mut scratch, &mut result);
        result
    }

    /// Execute vector elements until the first handler returning false (STOP).
    ///
    /// `EnterBlock` mirrors `sub_10017C60`: it recursively consumes the shared
    /// program counter, starts the nested result from the current value, and
    /// restores the caller's scratch word when the nested STOP is reached.
    fn execute_until_stop(
        &self,
        program: &VmProgram,
        seed: u32,
        pc: &mut usize,
        scratch: &mut u32,
        result: &mut u32,
    ) {
        while let Some(instruction) = program.instructions.get(*pc).copied() {
            *pc += 1;
            match instruction.op {
                VmOp::AddParam => *result = result.wrapping_add(instruction.param),
                VmOp::EnterBlock => {
                    let saved_scratch = *scratch;
                    let mut nested_result = *result;
                    self.execute_until_stop(program, seed, pc, scratch, &mut nested_result);
                    *result = nested_result;
                    *scratch = saved_scratch;
                }
                VmOp::AddScratch => *result = result.wrapping_add(*scratch),
                VmOp::MulScratch => *result = result.wrapping_mul(*scratch),
                VmOp::ScratchMinusResult => *result = scratch.wrapping_sub(*result),
                VmOp::ShlScratch => *result = result.wrapping_shl(*scratch & 0x0f),
                VmOp::ShrScratch => *result = result.wrapping_shr(*scratch & 0x0f),
                VmOp::SubScratch => *result = result.wrapping_sub(*scratch),
                VmOp::BitShuffle => {
                    let mask = instruction.param;
                    *result = 2u32.wrapping_mul(*result & !mask) | ((mask >> 1) & (*result >> 1));
                }
                VmOp::LoadImmediate => *result = instruction.param,
                VmOp::LoadSeed => *result = seed,
                VmOp::Dec => *result = result.wrapping_sub(1),
                VmOp::Inc => *result = result.wrapping_add(1),
                VmOp::Neg => *result = 0u32.wrapping_sub(*result),
                VmOp::Not => *result = !*result,
                VmOp::LoadTableImmediate => {
                    *result = self.table[instruction.param as usize];
                }
                VmOp::LoadTableMasked => {
                    *result = self.table[(instruction.param & *result) as usize];
                }
                VmOp::SubParam => *result = result.wrapping_sub(instruction.param),
                VmOp::StoreScratch => *scratch = *result,
                VmOp::XorParam => *result ^= instruction.param,
                VmOp::Stop => return,
            }
        }
        debug_assert!(false, "HXV4 DripValue program ended without STOP");
    }
}

impl Hxv4NativeFilterState {
    /// Apply the symmetric HXV4 stream XOR at an arbitrary logical file offset.
    pub fn apply(&self, logical_offset: u64, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let end = logical_offset.saturating_add(data.len() as u64);

        // First 16 logical bytes have an additional per-byte mask.
        let prefix_start = logical_offset.min(16);
        let prefix_end = end.min(16);
        if prefix_start < prefix_end {
            for position in prefix_start..prefix_end {
                data[(position - logical_offset) as usize] ^= self.prefix_xor[position as usize];
            }
        }

        // Body filter is one repeated byte before/after the split.
        if logical_offset < self.split {
            let left_end = end.min(self.split);
            xor_byte_range(
                data,
                logical_offset,
                logical_offset,
                left_end,
                self.left.xor_byte,
            );
        }
        if end > self.split {
            let right_start = logical_offset.max(self.split);
            xor_byte_range(data, logical_offset, right_start, end, self.right.xor_byte);
        }

        apply_boundary_corrections(&self.left, self.split, true, logical_offset, end, data);
        apply_boundary_corrections(&self.right, self.split, false, logical_offset, end, data);
    }
}

fn xor_byte_range(data: &mut [u8], base: u64, start: u64, end: u64, key: u8) {
    if key == 0 || start >= end {
        return;
    }
    let from = (start - base) as usize;
    let to = (end - base) as usize;
    for byte in &mut data[from..to] {
        *byte ^= key;
    }
}

fn apply_boundary_corrections(
    boundary: &Hxv4NativeBoundary,
    split: u64,
    left_side: bool,
    start: u64,
    end: u64,
    data: &mut [u8],
) {
    for (position, value) in [
        (boundary.position0, boundary.correction0),
        (boundary.position1, boundary.correction1),
    ] {
        if value == 0 || position < start || position >= end {
            continue;
        }
        if left_side && position >= split {
            continue;
        }
        if !left_side && position < split {
            continue;
        }
        data[(position - start) as usize] ^= value;
    }
}

fn boundary_from_drip(value: u64, null_mode: bool) -> Hxv4NativeBoundary {
    let position0 = (value >> 48) & 0xffff;
    let mut position1 = (value >> 32) & 0xffff;
    if position0 == position1 {
        position1 = position1.wrapping_add(1);
    }
    let mut xor_byte = value as u8;
    if xor_byte == 0 && !null_mode {
        xor_byte = 0xa5;
    }
    let (correction0, correction1) = if null_mode {
        (0, 0)
    } else {
        (((value >> 8) & 0xff) as u8, ((value >> 16) & 0xff) as u8)
    };
    Hxv4NativeBoundary {
        position0,
        position1,
        xor_byte,
        correction0,
        correction1,
    }
}

fn permutation_valid(data: &[u8], n: usize) -> bool {
    if data.len() != n {
        return false;
    }
    let mut seen = vec![false; n];
    for &value in data {
        let index = value as usize;
        if index >= n || seen[index] {
            return false;
        }
        seen[index] = true;
    }
    true
}

struct Generator<'a> {
    params: &'a [u8],
    rng: &'a mut GeneratorRng,
    code_len: usize,
    instructions: Vec<VmInstruction>,
}

impl Generator<'_> {
    fn add_len(&mut self, amount: usize) -> bool {
        let Some(next) = self.code_len.checked_add(amount) else {
            return false;
        };
        if next > 128 {
            return false;
        }
        self.code_len = next;
        true
    }

    fn emit(&mut self, op: VmOp, param: u32) {
        self.instructions.push(VmInstruction { param, op });
    }

    /// `sub_10018000`: emit one binary block into the same flat vector consumed
    /// by `sub_10019300`.
    fn gen_binary(&mut self, depth: u32) -> bool {
        if depth <= 1 {
            return self.gen_leaf();
        }
        let child_depth = depth - 1;

        if !self.add_len(1) {
            return false;
        } // push ebx
        self.emit(VmOp::EnterBlock, 0);

        let first_ok = if self.rng.next_u32() & 1 != 0 {
            self.gen_binary(child_depth)
        } else {
            self.gen_unary(child_depth)
        };
        if !first_ok {
            return false;
        }

        if !self.add_len(2) {
            return false;
        } // mov ebx,eax
        self.emit(VmOp::StoreScratch, 0);

        let second_ok = if self.rng.next_u32() & 1 != 0 {
            self.gen_binary(child_depth)
        } else {
            self.gen_unary(child_depth)
        };
        if !second_ok {
            return false;
        }

        let choice = (self.rng.next_u32() % 6) as u8;
        let (op, code_len) = if choice == self.params[8] {
            (VmOp::AddScratch, 2)
        } else if choice == self.params[9] {
            (VmOp::SubScratch, 2)
        } else if choice == self.params[10] {
            (VmOp::ScratchMinusResult, 4)
        } else if choice == self.params[11] {
            (VmOp::MulScratch, 3)
        } else if choice == self.params[12] {
            (VmOp::ShlScratch, 9)
        } else if choice == self.params[13] {
            (VmOp::ShrScratch, 9)
        } else {
            return false;
        };

        if !self.add_len(code_len) || !self.add_len(1) {
            return false;
        } // combine + pop ebx
        self.emit(op, 0);
        self.emit(VmOp::Stop, 0);
        true
    }

    /// `sub_10018610`: recursively emit a child, then one unary handler.
    fn gen_unary(&mut self, depth: u32) -> bool {
        if depth <= 1 {
            return self.gen_leaf();
        }
        let child_depth = depth - 1;

        let child_ok = if self.rng.next_u32() & 1 != 0 {
            self.gen_binary(child_depth)
        } else {
            self.gen_unary(child_depth)
        };
        if !child_ok {
            return false;
        }

        let choice = (self.rng.next_u32() & 7) as u8;
        if choice == self.params[0] {
            if !self.add_len(2) {
                return false;
            }
            self.emit(VmOp::Not, 0);
        } else if choice == self.params[1] {
            if !self.add_len(2) {
                return false;
            }
            self.emit(VmOp::Neg, 0);
        } else if choice == self.params[2] {
            if !self.add_len(1) {
                return false;
            }
            self.emit(VmOp::Inc, 0);
        } else if choice == self.params[3] {
            if !self.add_len(1) {
                return false;
            }
            self.emit(VmOp::Dec, 0);
        } else if choice == self.params[4] {
            if !self.add_len(21) {
                return false;
            }
            self.emit(VmOp::BitShuffle, 0xaaaa_aaaa);
        } else if choice == self.params[5] {
            if !self.add_len(1) {
                return false;
            }
            let imm = self.rng.next_u32();
            if !self.add_len(4) {
                return false;
            }
            self.emit(VmOp::XorParam, imm);
        } else if choice == self.params[6] {
            let add = self.rng.next_u32() & 1 != 0;
            if !self.add_len(1) {
                return false;
            }
            let imm = self.rng.next_u32();
            if !self.add_len(4) {
                return false;
            }
            self.emit(if add { VmOp::AddParam } else { VmOp::SubParam }, imm);
        } else if choice == self.params[7] {
            if !self.add_len(13) {
                return false;
            }
            self.emit(VmOp::LoadTableMasked, 1023);
        } else {
            return false;
        }
        true
    }

    /// `sub_10018410`: emit one leaf handler.
    fn gen_leaf(&mut self) -> bool {
        let choice = (self.rng.next_u32() % 3) as u8;
        if choice == self.params[14] {
            if !self.add_len(1) {
                return false;
            }
            let imm = self.rng.next_u32();
            if !self.add_len(4) {
                return false;
            }
            self.emit(VmOp::LoadImmediate, imm);
        } else if choice == self.params[15] {
            if !self.add_len(2) {
                return false;
            }
            self.emit(VmOp::LoadSeed, 0);
        } else if choice == self.params[16] {
            if !self.add_len(7) {
                return false;
            }
            let index = self.rng.next_u32() & 0x3ff;
            if !self.add_len(4) {
                return false;
            }
            self.emit(VmOp::LoadTableImmediate, index);
        } else {
            return false;
        }
        true
    }
}

fn build_lane(params: &[u8], rng: &mut GeneratorRng) -> Option<VmProgram> {
    // `sub_10017E90` starts at recursion depth 5. If the x86-equivalent form
    // exceeds 128 bytes it retries *without rewinding the PRNG* at depths
    // 5, 4, 3, 2, 1. The temporary VM vector itself is reset on each attempt.
    for depth in (1..=5u32).rev() {
        let mut generator = Generator {
            params,
            rng,
            code_len: 0,
            instructions: Vec::new(),
        };
        if !generator.add_len(9) {
            continue;
        } // native prologue
        if !generator.gen_binary(depth) {
            continue;
        }
        if !generator.add_len(6) {
            continue;
        } // native epilogue
        generator.emit(VmOp::Stop, 0); // final sub_10051D90 vector element
        return Some(VmProgram {
            instructions: generator.instructions,
        });
    }
    None
}

#[derive(Clone, Copy, Debug)]
struct GeneratorRng {
    s0: u64,
    s1: u64,
    random_type: u8,
}

impl GeneratorRng {
    fn for_lane(lane: u32, random_type: u8) -> Self {
        const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
        let base = (u64::from(!lane) << 32) | u64::from(lane);
        let s0 = splitmix64_final(base.wrapping_add(GAMMA));
        let s1 = splitmix64_final(base.wrapping_add(GAMMA.wrapping_mul(2)));
        Self {
            s0,
            s1,
            random_type,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        if self.random_type == 0 {
            // xoroshiro128++ (49,21,28), matching sub_10018F20.
            let result = self
                .s0
                .wrapping_add(self.s1)
                .rotate_left(17)
                .wrapping_add(self.s0);
            self.s1 ^= self.s0;
            self.s0 = self.s0.rotate_left(49) ^ self.s1 ^ (self.s1 << 21);
            self.s1 = self.s1.rotate_left(28);
            result
        } else {
            // xoroshiro128** (24,16,37), matching sub_10018FC0.
            let result = self.s0.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
            self.s1 ^= self.s0;
            self.s0 = self.s0.rotate_left(24) ^ self.s1 ^ (self.s1 << 16);
            self.s1 = self.s1.rotate_left(37);
            result
        }
    }
}

fn splitmix64_final(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMS: [u8; 22] = [
        2, 0, 6, 5, 1, 4, 3, 7, 1, 5, 3, 2, 0, 4, 1, 0, 2, 1, 0xe2, 0x02, 0x83, 0x02,
    ];

    #[test]
    fn title_params_build_all_128_lanes() {
        let table: Vec<u32> = (0..1024u32).map(|x| x.wrapping_mul(0x9e37_79b9)).collect();
        let manager = Hxv4NativeFilterManager::from_params_and_table(&PARAMS, &table).unwrap();
        assert_eq!(manager.lanes.len(), 128);
        assert_eq!(manager.control_mode(), 2);
        assert_eq!(manager.random_type_label(), "xoroshiro128++");
        assert_eq!(manager.mask(), 0x02e2);
        assert_eq!(manager.offset(), 0x0283);
    }

    #[test]
    fn flat_vm_matches_pre_flattening_drip_regression_values() {
        let table: Vec<u32> = (0..1024u32).map(|x| x.wrapping_mul(0x9e37_79b9)).collect();
        let manager = Hxv4NativeFilterManager::from_params_and_table(&PARAMS, &table).unwrap();
        for (input, expected) in [
            (0x0000_0000, 0xa9f8_3ae4_0417_f785),
            (0x0000_0001, 0xffcf_1e06_ffcf_1e07),
            (0x1234_5678, 0x01a0_37fc_83de_a20e),
            (0x5566_7788, 0x8a62_8ff1_4531_47f8),
            (0x1122_3344, 0x0001_9035_0004_376e),
            (0xffff_ffff, 0x000a_9f00_153e_0077),
        ] {
            assert_eq!(manager.drip64(input), expected, "input={input:08x}");
        }
    }

    #[test]
    fn stream_filter_is_symmetric_at_nonzero_offset() {
        let table: Vec<u32> = (0..1024u32)
            .map(|x| x.rotate_left(11) ^ 0xa5a5_5a5a)
            .collect();
        let manager = Hxv4NativeFilterManager::from_params_and_table(&PARAMS, &table).unwrap();
        let state = manager.state_for_entry(0x1122_3344_5566_7788, 1);
        let original: Vec<u8> = (0..200u16).map(|x| x as u8).collect();
        let mut data = original.clone();
        state.apply(7, &mut data);
        assert_ne!(data, original);
        state.apply(7, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn zero_boundary_key_uses_native_a5_fallback() {
        let boundary = boundary_from_drip(0, false);
        assert_eq!(boundary.xor_byte, 0xa5);
        assert_eq!(boundary.position0, 0);
        assert_eq!(boundary.position1, 1);
    }
}
