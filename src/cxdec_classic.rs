//! Parameterized native implementation of the CXDEC content-filter core.
//!
//! This module deliberately knows nothing about game names or PE layout.  A
//! recognizer supplies a complete [`CxdecProfile`]; callers may then
//! optionally attach a known-profile label for diagnostics and regression
//! testing.  The engine itself accepts previously unseen permutations.

use crate::{Error, Result};

pub const CLASSIC_CXDEC_CONTROL_BLOCK_SIZE: usize = 4096;

/// Generator used to build the shared CXDEC expression grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxdecGeneratorKind {
    Classic,
    Cabbage { random_seed: u32 },
}

/// Composable transforms layered around the shared CXDEC core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxdecContentWrapper {
    /// Riddle's hash-derived XOR over absolute file bytes 0..8.
    RiddlePrefix8,
}

/// Complete recovered parameter set for a CXDEC content filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxdecProfile {
    pub mask: u32,
    pub offset: u32,
    pub prolog_order: [u8; 3],
    pub even_branch_order: [u8; 8],
    pub odd_branch_order: [u8; 6],
    /// Raw 4096-byte CXDEC control table as encoded in the PE/TPM. Some
    /// generations place it after the historical `" Encryption control block"`
    /// marker; others expose the table only through code/data-flow semantics.
    /// GARbro's loader materializes `decoded[i] = !raw[i]`, while the generated
    /// `MOV_EAX_INDIRECT` operation complements that decoded word again.
    /// Keeping the raw representation here therefore matches the value seen
    /// by the generated content program. Name/Special ciphers that consume
    /// GARbro's decoded ControlBlock must complement these words explicitly.
    pub control_block: Vec<u8>,
    pub generator: CxdecGeneratorKind,
    pub wrappers: Vec<CxdecContentWrapper>,
}

impl CxdecProfile {
    pub fn validate(&self) -> Result<()> {
        if self.control_block.len() != CLASSIC_CXDEC_CONTROL_BLOCK_SIZE {
            return Err(Error::invalid(format!(
                "classic CXDEC control block has {} bytes, expected {CLASSIC_CXDEC_CONTROL_BLOCK_SIZE}",
                self.control_block.len()
            )));
        }
        validate_permutation(&self.prolog_order, 3, "prolog")?;
        validate_permutation(&self.even_branch_order, 8, "even branch")?;
        validate_permutation(&self.odd_branch_order, 6, "odd branch")?;
        Ok(())
    }

    pub fn control_words(&self) -> Result<[u32; 1024]> {
        self.validate()?;
        let mut words = [0u32; 1024];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_le_bytes(self.control_block[start..start + 4].try_into().unwrap());
        }
        Ok(words)
    }
}

/// A complete native CXDEC evaluator. Its state is only recovered
/// scheme data and generated expression programs; it contains no emulator or
/// raw PE pointer.
#[derive(Clone, Debug)]
pub struct CxdecEngine {
    profile: CxdecProfile,
    words: [u32; 1024],
    lanes: Vec<Expr>,
}

impl CxdecEngine {
    pub fn new(profile: CxdecProfile) -> Result<Self> {
        let words = profile.control_words()?;
        let mut lanes = Vec::with_capacity(128);
        for lane in 0..128u32 {
            lanes.push(build_lane(lane, &profile)?);
        }
        Ok(Self {
            profile,
            words,
            lanes,
        })
    }

    pub fn profile(&self) -> &CxdecProfile {
        &self.profile
    }

    /// Compatibility name retained for callers of the original Classic-only
    /// API. The returned value is the complete generalized profile.
    pub fn scheme(&self) -> &CxdecProfile {
        &self.profile
    }

    /// Evaluate one generated lane directly. This is useful for recognizer
    /// differential checks and deterministic algorithm-reference vectors.
    pub fn evaluate_lane(&self, lane: u8, parameter: u32) -> u32 {
        self.eval(&self.lanes[(lane & 0x7f) as usize], parameter)
    }

    /// Classic CXDEC is XOR-symmetric, so this method serves decryption and
    /// re-encryption. `file_offset` is the logical, uncompressed entry offset.
    pub fn apply(&self, file_offset: u64, source_hash: u32, data: &mut [u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if file_offset > u32::MAX as u64 || data.len() > u32::MAX as usize {
            return Err(Error::unsupported(
                "classic CXDEC uses a 32-bit logical offset/length",
            ));
        }
        let offset = file_offset as u32;
        self.apply_wrappers(file_offset, source_hash, data);
        let boundary = (source_hash & self.profile.mask).wrapping_add(self.profile.offset);
        let first = if offset < boundary {
            data.len().min(boundary.wrapping_sub(offset) as usize)
        } else {
            0
        };
        if first != 0 {
            self.apply_region(source_hash, offset, &mut data[..first]);
        }
        if first != data.len() {
            let second_hash = (source_hash >> 16) ^ source_hash;
            self.apply_region(
                second_hash,
                offset.wrapping_add(first as u32),
                &mut data[first..],
            );
        }
        Ok(())
    }

    fn apply_wrappers(&self, file_offset: u64, source_hash: u32, data: &mut [u8]) {
        for wrapper in &self.profile.wrappers {
            match wrapper {
                CxdecContentWrapper::RiddlePrefix8 => {
                    apply_riddle_prefix8(file_offset, source_hash, data)
                }
            }
        }
    }

    fn apply_region(&self, hash: u32, offset: u32, data: &mut [u8]) {
        let lane = (hash & 0x7f) as usize;
        let seed = hash >> 7;
        let result = self.eval(&self.lanes[lane], seed);
        let inverse_result = self.eval(&self.lanes[lane], !seed);
        let sparse_high = inverse_result >> 16;
        let mut sparse_low = inverse_result & 0xffff;
        if sparse_high == sparse_low {
            sparse_low = sparse_low.wrapping_add(1);
        }
        let body = (result as u8).max(1);
        for byte in data.iter_mut() {
            *byte ^= body;
        }
        let end = u64::from(offset) + data.len() as u64;
        // These order/value pairings match the established CxEncryption
        // implementation: low sparse position gets result[23:16], high gets
        // result[15:8].
        for (position, value) in [
            (sparse_low, (result >> 16) as u8),
            (sparse_high, (result >> 8) as u8),
        ] {
            let position = u64::from(position);
            if position >= u64::from(offset) && position < end {
                data[(position - u64::from(offset)) as usize] ^= value;
            }
        }
    }

    fn eval(&self, expr: &Expr, seed: u32) -> u32 {
        match expr {
            Expr::Seed => seed,
            Expr::Immediate(value) => *value,
            Expr::Table(index) => self.words[*index as usize],
            Expr::Unary(op, inner) => {
                let value = self.eval(inner, seed);
                match *op {
                    Unary::Not => !value,
                    Unary::Dec => value.wrapping_sub(1),
                    Unary::Neg => 0u32.wrapping_sub(value),
                    Unary::Inc => value.wrapping_add(1),
                    Unary::Table => self.words[(value & 0x3ff) as usize],
                    Unary::Interlace => ((value & 0xaaaa_aaaa) >> 1) | ((value & 0x5555_5555) << 1),
                    Unary::Xor(value2) => value ^ value2,
                    Unary::Add(value2) => value.wrapping_add(value2),
                    Unary::Sub(value2) => value.wrapping_sub(value2),
                }
            }
            Expr::Binary(op, first, second) => {
                let ebx = self.eval(first, seed);
                let eax = self.eval(second, seed);
                match op {
                    Binary::Shr => eax.wrapping_shr(ebx & 0x0f),
                    Binary::Shl => eax.wrapping_shl(ebx & 0x0f),
                    Binary::Add => eax.wrapping_add(ebx),
                    Binary::ReverseSub => ebx.wrapping_sub(eax),
                    Binary::Mul => eax.wrapping_mul(ebx),
                    Binary::Sub => eax.wrapping_sub(ebx),
                }
            }
        }
    }
}

/// Backwards-compatible aliases for the original public Classic-only API.
pub type ClassicCxdecScheme = CxdecProfile;
pub type ClassicCxdecEngine = CxdecEngine;

#[derive(Clone, Debug)]
enum Expr {
    Seed,
    Immediate(u32),
    Table(u16),
    Unary(Unary, Box<Expr>),
    Binary(Binary, Box<Expr>, Box<Expr>),
}
#[derive(Clone, Copy, Debug)]
enum Unary {
    Not,
    Dec,
    Neg,
    Inc,
    Table,
    Interlace,
    Xor(u32),
    Add(u32),
    Sub(u32),
}
#[derive(Clone, Copy, Debug)]
enum Binary {
    Shr,
    Shl,
    Add,
    ReverseSub,
    Mul,
    Sub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GeneratorRng {
    seed: u32,
    kind: CxdecGeneratorKind,
    random_seed: u32,
}

impl GeneratorRng {
    fn new(seed: u32, kind: CxdecGeneratorKind) -> Self {
        let random_seed = match kind {
            CxdecGeneratorKind::Classic => 0,
            CxdecGeneratorKind::Cabbage { random_seed } => random_seed,
        };
        Self {
            seed,
            kind,
            random_seed,
        }
    }

    fn next(&mut self) -> u32 {
        match self.kind {
            CxdecGeneratorKind::Classic => {
                let old = self.seed;
                self.seed = 0x41c6_4e6du32.wrapping_mul(old).wrapping_add(0x3039);
                self.seed ^ old.wrapping_shl(16) ^ old.wrapping_shr(16)
            }
            CxdecGeneratorKind::Cabbage { .. } => {
                let mut s = self.seed ^ self.seed.wrapping_shl(17);
                s ^= s.wrapping_shl(18) | s.wrapping_shr(15);
                self.seed = !s;

                let mut r = self.random_seed ^ self.random_seed.wrapping_shl(13);
                r ^= r.wrapping_shr(17);
                self.random_seed = r ^ r.wrapping_shl(5);
                self.seed ^ self.random_seed
            }
        }
    }
}

struct Builder<'a> {
    rng: &'a mut GeneratorRng,
    profile: &'a CxdecProfile,
    length: usize,
}
impl Builder<'_> {
    fn reserve(&mut self, bytes: usize) -> bool {
        let Some(next) = self.length.checked_add(bytes) else {
            return false;
        };
        if next > 128 {
            return false;
        }
        self.length = next;
        true
    }
    fn prolog(&mut self) -> Option<Expr> {
        match self.profile.prolog_order[(self.rng.next() % 3) as usize] {
            0 => {
                if !self.reserve(1) {
                    return None;
                }
                let value = self.rng.next();
                self.reserve(4).then_some(Expr::Immediate(value))
            }
            1 => {
                if !self.reserve(2) {
                    None
                } else {
                    Some(Expr::Seed)
                }
            }
            2 => {
                if !self.reserve(5) || !self.reserve(2) {
                    return None;
                }
                let index = (self.rng.next() as u16) & 0x3ff;
                self.reserve(4).then_some(Expr::Table(index))
            }
            _ => None,
        }
    }
    fn stage0(&mut self, stage: u32) -> Option<Expr> {
        if stage == 1 {
            return self.prolog();
        }
        let child = if self.rng.next() & 1 != 0 {
            self.stage1(stage - 1)?
        } else {
            self.stage0(stage - 1)?
        };
        let op = match self.profile.even_branch_order[(self.rng.next() & 7) as usize] {
            0 => self.reserve(2).then_some(Unary::Not),
            1 => self.reserve(1).then_some(Unary::Dec),
            2 => self.reserve(2).then_some(Unary::Neg),
            3 => self.reserve(1).then_some(Unary::Inc),
            4 => (self.reserve(5) && self.reserve(1) && self.reserve(4) && self.reserve(3))
                .then_some(Unary::Table),
            5 => self
                .reserve(1 + 2 + 6 + 5 + 2 + 2 + 2 + 1)
                .then_some(Unary::Interlace),
            6 => {
                if !self.reserve(1) {
                    return None;
                }
                let value = self.rng.next();
                self.reserve(4).then_some(Unary::Xor(value))
            }
            7 => {
                let add = self.rng.next() & 1 != 0;
                if !self.reserve(1) {
                    return None;
                }
                let value = self.rng.next();
                if add {
                    self.reserve(4).then_some(Unary::Add(value))
                } else {
                    self.reserve(4).then_some(Unary::Sub(value))
                }
            }
            _ => None,
        }?;
        Some(Expr::Unary(op, Box::new(child)))
    }
    fn stage1(&mut self, stage: u32) -> Option<Expr> {
        if stage == 1 {
            return self.prolog();
        }
        if !self.reserve(1) {
            return None;
        }
        let first = if self.rng.next() & 1 != 0 {
            self.stage1(stage - 1)?
        } else {
            self.stage0(stage - 1)?
        };
        if !self.reserve(2) {
            return None;
        }
        let second = if self.rng.next() & 1 != 0 {
            self.stage1(stage - 1)?
        } else {
            self.stage0(stage - 1)?
        };
        let op = match self.profile.odd_branch_order[(self.rng.next() % 6) as usize] {
            0 => self.reserve(1 + 2 + 3 + 2 + 1).then_some(Binary::Shr),
            1 => self.reserve(1 + 2 + 3 + 2 + 1).then_some(Binary::Shl),
            2 => self.reserve(2).then_some(Binary::Add),
            3 => self.reserve(4).then_some(Binary::ReverseSub),
            4 => self.reserve(3).then_some(Binary::Mul),
            5 => self.reserve(2).then_some(Binary::Sub),
            _ => None,
        }?;
        if !self.reserve(1) {
            return None;
        }
        Some(Expr::Binary(op, Box::new(first), Box::new(second)))
    }
}

fn build_lane(lane: u32, profile: &CxdecProfile) -> Result<Expr> {
    let mut rng = GeneratorRng::new(lane, profile.generator);
    for stage in (1..=5u32).rev() {
        let mut builder = Builder {
            rng: &mut rng,
            profile,
            length: 9,
        };
        if let Some(expr) = builder.stage1(stage) {
            if builder.reserve(6) {
                return Ok(expr);
            }
        }
    }
    Err(Error::format(format!(
        "classic CXDEC lane {lane} exceeded the 128-byte generator budget"
    )))
}

/// Riddle's compositional Gen3 content wrapper. Only bytes whose absolute
/// logical offset intersects 0..8 are changed.
pub fn apply_riddle_prefix8(file_offset: u64, source_hash: u32, data: &mut [u8]) {
    if data.is_empty() || file_offset >= 8 {
        return;
    }
    let lo = source_hash ^ 0x5555_5555;
    let mut hi = source_hash.wrapping_shl(13) ^ source_hash;
    hi ^= hi.wrapping_shr(17);
    hi ^= hi.wrapping_shl(5) ^ 0xaaaa_aaaa;
    let key = (u64::from(hi) << 32) | u64::from(lo);
    let start = file_offset as usize;
    let count = data.len().min(8 - start);
    for (index, byte) in data[..count].iter_mut().enumerate() {
        *byte ^= (key >> ((start + index) * 8)) as u8;
    }
}

fn validate_permutation(values: &[u8], expected: u8, name: &str) -> Result<()> {
    let mut seen = vec![false; expected as usize];
    for &value in values {
        let Some(slot) = seen.get_mut(value as usize) else {
            return Err(Error::invalid(format!(
                "classic CXDEC {name} value {value} is out of range"
            )));
        };
        if *slot {
            return Err(Error::invalid(format!(
                "classic CXDEC {name} is not a permutation"
            )));
        }
        *slot = true;
    }
    if seen.iter().all(|value| *value) {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "classic CXDEC {name} is not a complete permutation"
        )))
    }
}

/// Published order and split parameters.  They are labels and regression
/// fixtures only: [`CxdecEngine`] never selects a profile by title.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownClassicCxdecProfile {
    pub id: &'static str,
    pub title: &'static str,
    pub mask: u32,
    pub offset: u32,
    pub prolog_order: [u8; 3],
    pub even_branch_order: [u8; 8],
    pub odd_branch_order: [u8; 6],
}

/// Public executable regression-fixture inventory. Every member is complete;
/// parameterless titles belong in documentation, not this array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassicCxdecFixture {
    pub id: &'static str,
    pub title: &'static str,
    pub profile: &'static KnownClassicCxdecProfile,
}

pub const KNOWN_CLASSIC_CXDEC_PROFILES: &[KnownClassicCxdecProfile] = &[
    KnownClassicCxdecProfile {
        id: "fate-hollow-ataraxia",
        title: "Fate/Hollow Ataraxia",
        mask: 0x143,
        offset: 0x787,
        prolog_order: [0, 1, 2],
        even_branch_order: [0, 1, 2, 3, 4, 5, 6, 7],
        odd_branch_order: [0, 1, 2, 3, 4, 5],
    },
    KnownClassicCxdecProfile {
        id: "comyu",
        title: "Comyu",
        mask: 0x1a3,
        offset: 0x0b6,
        prolog_order: [0, 1, 2],
        even_branch_order: [0, 7, 5, 6, 3, 1, 4, 2],
        odd_branch_order: [4, 3, 2, 1, 5, 0],
    },
    KnownClassicCxdecProfile {
        id: "mahoutsukai-no-yoru",
        title: "Mahoutsukai no Yoru",
        mask: 0x22a,
        offset: 0x2a2,
        prolog_order: [1, 0, 2],
        even_branch_order: [7, 6, 5, 1, 0, 3, 4, 2],
        odd_branch_order: [3, 2, 1, 4, 5, 0],
    },
    KnownClassicCxdecProfile {
        id: "natsuzora-kanata",
        title: "Natsuzora Kanata",
        mask: 0x2f5,
        offset: 0x6f0,
        prolog_order: [2, 0, 1],
        even_branch_order: [7, 2, 3, 6, 1, 0, 5, 4],
        odd_branch_order: [2, 3, 4, 0, 1, 5],
    },
    KnownClassicCxdecProfile {
        id: "tenshin-ranman",
        title: "Tenshin Ranman",
        mask: 0x167,
        offset: 0x498,
        prolog_order: [1, 0, 2],
        even_branch_order: [4, 2, 3, 5, 6, 1, 7, 0],
        odd_branch_order: [1, 0, 5, 4, 3, 2],
    },
    KnownClassicCxdecProfile {
        id: "dracu-riot",
        title: "Dracu-Riot!",
        mask: 0x2f0,
        offset: 0x418,
        prolog_order: [2, 0, 1],
        even_branch_order: [5, 3, 0, 2, 1, 4, 6, 7],
        odd_branch_order: [0, 3, 5, 4, 2, 1],
    },
    KnownClassicCxdecProfile {
        id: "lavender",
        title: "Kourin no Machi, Lavender no Shoujo",
        mask: 0x181,
        offset: 0x635,
        prolog_order: [2, 1, 0],
        even_branch_order: [7, 5, 2, 3, 6, 1, 4, 0],
        odd_branch_order: [4, 0, 1, 5, 2, 3],
    },
    KnownClassicCxdecProfile {
        id: "karakara",
        title: "Karakara",
        mask: 0x190,
        offset: 0x4a7,
        prolog_order: [1, 0, 2],
        even_branch_order: [2, 0, 7, 3, 5, 1, 4, 6],
        odd_branch_order: [2, 1, 0, 5, 4, 3],
    },
    KnownClassicCxdecProfile {
        id: "ushinawareta-mirai",
        title: "Ushinawareta Mirai o Motomete",
        mask: 0x23c,
        offset: 0x60f,
        prolog_order: [2, 0, 1],
        even_branch_order: [1, 5, 0, 3, 2, 7, 6, 4],
        odd_branch_order: [4, 5, 2, 1, 0, 3],
    },
];

pub fn known_classic_profile(
    candidate: &CxdecProfile,
) -> Option<&'static KnownClassicCxdecProfile> {
    if candidate.generator != CxdecGeneratorKind::Classic || !candidate.wrappers.is_empty() {
        return None;
    }
    KNOWN_CLASSIC_CXDEC_PROFILES.iter().find(|profile| {
        profile.mask == candidate.mask
            && profile.offset == candidate.offset
            && profile.prolog_order == candidate.prolog_order
            && profile.even_branch_order == candidate.even_branch_order
            && profile.odd_branch_order == candidate.odd_branch_order
    })
}

pub const KNOWN_CLASSIC_CXDEC_FIXTURES: &[ClassicCxdecFixture] = &[
    ClassicCxdecFixture {
        id: "fate-hollow-ataraxia",
        title: "Fate/Hollow Ataraxia",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[0],
    },
    ClassicCxdecFixture {
        id: "comyu",
        title: "Comyu",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[1],
    },
    ClassicCxdecFixture {
        id: "mahoutsukai-no-yoru",
        title: "Mahoutsukai no Yoru",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[2],
    },
    ClassicCxdecFixture {
        id: "natsuzora-kanata",
        title: "Natsuzora Kanata",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[3],
    },
    ClassicCxdecFixture {
        id: "tenshin-ranman",
        title: "Tenshin Ranman",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[4],
    },
    ClassicCxdecFixture {
        id: "dracu-riot",
        title: "Dracu-Riot!",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[5],
    },
    ClassicCxdecFixture {
        id: "lavender",
        title: "Kourin no Machi, Lavender no Shoujo",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[6],
    },
    ClassicCxdecFixture {
        id: "karakara",
        title: "Karakara",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[7],
    },
    ClassicCxdecFixture {
        id: "ushinawareta-mirai",
        title: "Ushinawareta Mirai o Motomete",
        profile: &KNOWN_CLASSIC_CXDEC_PROFILES[8],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    fn scheme(profile: KnownClassicCxdecProfile) -> ClassicCxdecScheme {
        let mut control_block = vec![0u8; CLASSIC_CXDEC_CONTROL_BLOCK_SIZE];
        for (i, byte) in control_block.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        ClassicCxdecScheme {
            mask: profile.mask,
            offset: profile.offset,
            prolog_order: profile.prolog_order,
            even_branch_order: profile.even_branch_order,
            odd_branch_order: profile.odd_branch_order,
            control_block,
            generator: CxdecGeneratorKind::Classic,
            wrappers: Vec::new(),
        }
    }
    #[test]
    fn published_profiles_are_complete_permutations() {
        for profile in KNOWN_CLASSIC_CXDEC_PROFILES {
            scheme(*profile).validate().unwrap();
        }
    }
    #[test]
    fn public_fixture_inventory_is_title_complete_without_driving_dispatch() {
        assert_eq!(KNOWN_CLASSIC_CXDEC_FIXTURES.len(), 9);
        assert!(KNOWN_CLASSIC_CXDEC_FIXTURES
            .iter()
            .all(|fixture| fixture.profile.id == fixture.id));
    }
    #[test]
    fn partial_buffers_match_whole_buffer_transform() {
        let engine = ClassicCxdecEngine::new(scheme(KNOWN_CLASSIC_CXDEC_PROFILES[1])).unwrap();
        let hash = 0x8a4b_192e;
        let mut whole = (0..8192).map(|i| i as u8).collect::<Vec<_>>();
        let mut pieces = whole.clone();
        engine.apply(0, hash, &mut whole).unwrap();
        for (offset, size) in [(0usize, 13usize), (13, 1024), (1037, 2000), (3037, 5155)] {
            engine
                .apply(offset as u64, hash, &mut pieces[offset..offset + size])
                .unwrap();
        }
        assert_eq!(whole, pieces);
    }
    #[test]
    fn unknown_parameter_set_is_accepted_without_a_profile_label() {
        let mut value = scheme(KNOWN_CLASSIC_CXDEC_PROFILES[0]);
        value.offset ^= 1;
        let engine = ClassicCxdecEngine::new(value.clone()).unwrap();
        assert!(known_classic_profile(engine.scheme()).is_none());
    }

    #[test]
    fn cabbage_prng_matches_independent_fixed_vectors() {
        for (seed, random_seed, expected) in [
            (
                0,
                0,
                [
                    0xffff_ffff,
                    0x0002_0003,
                    0xfff7_fff4,
                    0x0030_0034,
                    0xff77_ff7b,
                    0x0392_0387,
                ],
            ),
            (
                0x1234_5678,
                0x9abc_def0,
                [
                    0x35e3_c26e,
                    0xee55_4882,
                    0xed67_c7b3,
                    0x7516_9cb0,
                    0x15d0_9850,
                    0xa844_8eeb,
                ],
            ),
        ] {
            let mut rng = GeneratorRng::new(seed, CxdecGeneratorKind::Cabbage { random_seed });
            assert_eq!(expected.map(|_| rng.next()), expected);
        }
    }

    #[test]
    fn cabbage_lane_evaluation_matches_independent_reference_vectors() {
        let mut profile = scheme(KNOWN_CLASSIC_CXDEC_PROFILES[2]);
        profile.generator = CxdecGeneratorKind::Cabbage {
            random_seed: 0x9abc_def0,
        };
        for index in 0..1024usize {
            let word = (index as u32).wrapping_mul(0x9e37_79b9);
            profile.control_block[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let engine = CxdecEngine::new(profile).unwrap();
        for (lane, parameter, expected) in [
            (0u8, 0x0000_0000, 0x177e_71fb),
            (1, 0x0012_3456, 0x3a49_03ff),
            (17, 0x89ab_cdef, 0xa93b_fd53),
            (63, 0x0102_0304, 0x00bd_6d56),
            (127, 0xffff_ffff, 0x3efa_bb70),
        ] {
            assert_eq!(engine.evaluate_lane(lane, parameter), expected);
        }
    }

    #[test]
    fn riddle_prefix8_respects_absolute_partial_offsets() {
        let hash = 0x1234_5678;
        let key = 0x2d32_f00f_4761_032du64.to_le_bytes();
        for (offset, size) in [(0u64, 100usize), (3, 2), (6, 8), (8, 100), (100, 100)] {
            let mut data = vec![0u8; size];
            apply_riddle_prefix8(offset, hash, &mut data);
            for (index, actual) in data.into_iter().enumerate() {
                let absolute = offset as usize + index;
                let expected = if absolute < 8 { key[absolute] } else { 0 };
                assert_eq!(actual, expected, "offset={offset} index={index}");
            }
        }
    }

    #[test]
    fn riddle_wrapper_is_composed_with_cabbage_core() {
        let mut profile = scheme(KNOWN_CLASSIC_CXDEC_PROFILES[2]);
        profile.generator = CxdecGeneratorKind::Cabbage {
            random_seed: 0x9abc_def0,
        };
        profile.wrappers.push(CxdecContentWrapper::RiddlePrefix8);
        let engine = CxdecEngine::new(profile).unwrap();
        let original = (0..1024).map(|i| i as u8).collect::<Vec<_>>();
        let mut encrypted = original.clone();
        engine.apply(0, 0x1234_5678, &mut encrypted).unwrap();
        assert_ne!(encrypted, original);
        engine.apply(0, 0x1234_5678, &mut encrypted).unwrap();
        assert_eq!(encrypted, original);
    }
}
