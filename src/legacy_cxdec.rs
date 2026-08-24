//! Native implementation of the early and intermediate CXDEC extraction-filter families.
//!
//! This backend intentionally does **not** execute the x86 functions generated
//! by CXDEC.  The historical implementation used `hash & 0x7f` to select one
//! of 128 deterministic expression programs, generated machine code for that
//! program, then executed it twice.  We build the same expression tree in Rust
//! and evaluate it directly.
//!
//! Production native-CXDEC support is profile driven. EXE/DLL/TPM files are
//! static reverse-analysis inputs only: a known family is usable by this
//! backend only after its mask/offset, dispatch orders, control block and any
//! family-specific seeds/wrappers have been recovered into owned Rust data.
//! Generated x86 and module callbacks may remain as reverse-engineering oracles
//! elsewhere in this crate, but they do not substitute for missing profile
//! fields in the native runtime.
//!
//! Recognition is structural. The historical `.decc` marker, module filename,
//! archive tag, fixed RVA, and game title are only weak evidence and are never
//! used as the family identity.

use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

const CONTROL_BLOCK_SIZE: usize = 4096;
const CONTROL_BLOCK_SIGNATURE: &[u8] = b" Encryption control block";
const REFERENCE_KEY0: u32 = 0x161;
const REFERENCE_KEY1: u32 = 0x5c9;
const XCODE_LCG_MUL: u32 = 1_103_515_245; // 0x41c64e6d
const XCODE_LCG_ADD: u32 = 12_345; // 0x00003039
const KNOWN_DECC_MARKER: &[u8] = &[0xf5, 0x42, 0x2f, 0x3e, 0x90, 0x8b, 0xb4, 0x24];
const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SCAN_FILES: usize = 4096;
const MAX_SCAN_DEPTH: usize = 4;

#[derive(Clone, Debug)]
pub struct LegacyCxdecProbe {
    pub path: PathBuf,
    pub profile_name: &'static str,
    pub recognized: bool,
    pub confidence: u8,
    pub image_base: u32,
    pub decc_rva: Option<u32>,
    pub decc_size: Option<u32>,
    pub control_block_rva: Option<u32>,
    pub callback_config_rva: Option<u32>,
    pub xcode_builder_rva: Option<u32>,
    pub xcode_builder_in_decc: bool,
    /// Start RVA of an executable window containing both exact
    /// CxProgramNana xorshift state transitions.
    pub cabbage_prng_rva: Option<u32>,
    /// Compact callback/helper window proving Riddle's hash-derived Prefix8
    /// transform independently from any `yuz:` archive tag.
    pub riddle_prefix8_rva: Option<u32>,
    /// Statically recovered Cabbage title seed. A complete native profile
    /// requires it; captured/generated lanes are reverse-engineering evidence
    /// only and do not substitute for this parameter in production.
    pub random_seed: Option<u32>,
    pub key0: Option<u32>,
    pub key1: Option<u32>,
    /// Semantically recovered generator dispatch tables.  Native Classic
    /// initialization is incomplete unless all three are present.
    pub prolog_order: Option<[u8; 3]>,
    pub even_branch_order: Option<[u8; 8]>,
    pub odd_branch_order: Option<[u8; 6]>,
    pub known_marker_hits: usize,
    pub reasons: Vec<String>,
}

impl LegacyCxdecProbe {
    pub fn profile(&self) -> &'static str {
        self.profile_name
    }

    pub fn missing_native_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.key0.is_none() {
            missing.push("mask");
        }
        if self.key1.is_none() {
            missing.push("offset");
        }
        if self.control_block_rva.is_none() {
            missing.push("control_block");
        }
        if self.prolog_order.is_none() {
            missing.push("prolog_order[3]");
        }
        if self.even_branch_order.is_none() {
            missing.push("even_branch_order[8]");
        }
        if self.odd_branch_order.is_none() {
            missing.push("odd_branch_order[6]");
        }
        if self.cabbage_prng_rva.is_some() && self.random_seed.is_none() {
            missing.push("random_seed");
        }
        missing
    }

    pub fn native_complete(&self) -> bool {
        self.recognized && self.missing_native_fields().is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClassicDispatchOrders {
    prolog: [u8; 3],
    even: [u8; 8],
    odd: [u8; 6],
    stage0_va: u32,
}

#[derive(Clone, Debug)]
pub struct LegacyCxdecFilter {
    module_path: PathBuf,
    table: Box<[u32; 1024]>,
    lanes: Vec<LaneProgram>,
    key0: u32,
    key1: u32,
    /// Optional title-specific outer XOR stream recovered by comparing the
    /// original callback against the native CXDEC core during initialization.
    /// The bytes are indexed by absolute file offset modulo the table length.
    outer_xor: Option<Vec<u8>>,
    /// The canonical parameterized evaluator for the fully classic branch.
    /// Generated-lane variants retain the micro-op compatibility path below.
    classic: Option<crate::cxdec_classic::ClassicCxdecEngine>,
    probe: LegacyCxdecProbe,
}

#[derive(Clone, Debug)]
enum LaneProgram {
    // Retained as an independent reference implementation for vector tests.
    #[allow(dead_code)]
    LegacyAst(Expr),
    Generated(Vec<GeneratedOp>),
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
enum Expr {
    Seed,
    Immediate(u32),
    TableImmediate(u16),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
}

#[derive(Clone, Copy, Debug)]
enum GeneratedOp {
    MovEaxSeed,
    MovEaxImm(u32),
    SetTableBase(u32),
    LoadTableDisp(u16),
    LoadTableIndexed,
    NotEax,
    NegEax,
    IncEax,
    DecEax,
    PushEbx,
    PopEbx,
    MovEbxEax,
    AndEbx(u32),
    AndEax(u32),
    ShrEbx1,
    ShlEax1,
    OrEaxEbx,
    XorEax(u32),
    AddEaxImm(u32),
    SubEaxImm(u32),
    AddEaxEbx,
    SubEaxEbx,
    ImulEaxEbx,
    PushEcx,
    PopEcx,
    MovEcxEbx,
    AndEcx(u32),
    ShlEaxCl,
    ShrEaxCl,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum UnaryOp {
    Not,
    Neg,
    Inc,
    Dec,
    SwapAdjacentBits,
    Xor(u32),
    Add(u32),
    Sub(u32),
    TableMasked,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum BinaryOp {
    Add,
    SecondMinusFirst,
    FirstMinusSecond,
    Mul,
    Shl,
    Shr,
}

#[derive(Clone, Copy, Debug)]
struct XcodeRng(u32);

impl XcodeRng {
    fn new(seed: u32) -> Self {
        Self(seed)
    }

    fn next_u32(&mut self) -> u32 {
        let old = self.0;
        self.0 = XCODE_LCG_MUL.wrapping_mul(old).wrapping_add(XCODE_LCG_ADD);
        self.0 ^ old.wrapping_shl(16) ^ old.wrapping_shr(16)
    }
}

#[allow(dead_code)]
struct Generator<'a> {
    rng: &'a mut XcodeRng,
    code_len: usize,
}

fn recover_classic_dispatch_orders(
    capture: &crate::x86_filter::CxdecDispatchCapture,
) -> std::result::Result<ClassicDispatchOrders, String> {
    let mut prolog = [None; 3];
    let mut odd = [None; 6];
    for (seed, code) in &capture.odd_stage2 {
        let (first, first_len) = parse_generated_prolog(code, 1)?;
        let mov_ebx = 1 + first_len;
        if code.get(mov_ebx..mov_ebx + 2) != Some(&[0x89, 0xc3]) {
            return Err(format!(
                "stage1 depth-2 sample seed {seed} lacks MOV EBX,EAX after first prolog"
            ));
        }
        let second_start = mov_ebx + 2;
        let (second, second_len) = parse_generated_prolog(code, second_start)?;
        let suffix = code
            .get(second_start + second_len..)
            .ok_or_else(|| "truncated stage1 depth-2 suffix".to_string())?;
        let odd_semantic = classify_generated_binary_suffix(suffix)?;

        let mut rng = XcodeRng::new(*seed);
        let _first_branch = rng.next_u32();
        let first_slot = (rng.next_u32() % 3) as usize;
        record_dispatch(&mut prolog, first_slot, first, "prolog")?;
        if matches!(first, 0 | 2) {
            let _prolog_immediate = rng.next_u32();
        }
        let _second_branch = rng.next_u32();
        let second_slot = (rng.next_u32() % 3) as usize;
        record_dispatch(&mut prolog, second_slot, second, "prolog")?;
        if matches!(second, 0 | 2) {
            let _prolog_immediate = rng.next_u32();
        }
        let odd_slot = (rng.next_u32() % 6) as usize;
        record_dispatch(&mut odd, odd_slot, odd_semantic, "odd branch")?;
    }
    let prolog = complete_dispatch(prolog, "prolog")?;
    let odd = complete_dispatch(odd, "odd branch")?;

    let mut matches = Vec::new();
    for (stage0_va, samples) in &capture.even_stage2_candidates {
        let mut candidate_prolog = prolog.map(Some);
        let mut even = [None; 8];
        let result = samples.iter().try_for_each(|(seed, code)| {
            let (semantic, prolog_len) = parse_generated_prolog(code, 0)?;
            let even_semantic = classify_generated_unary_suffix(&code[prolog_len..])?;
            let mut rng = XcodeRng::new(*seed);
            let _child_branch = rng.next_u32();
            let prolog_slot = (rng.next_u32() % 3) as usize;
            record_dispatch(&mut candidate_prolog, prolog_slot, semantic, "prolog")?;
            if matches!(semantic, 0 | 2) {
                let _prolog_immediate = rng.next_u32();
            }
            let even_slot = (rng.next_u32() & 7) as usize;
            record_dispatch(&mut even, even_slot, even_semantic, "even branch")
        });
        if result.is_ok() && complete_dispatch(candidate_prolog, "prolog") == Ok(prolog) {
            if let Ok(even) = complete_dispatch(even, "even branch") {
                matches.push(ClassicDispatchOrders {
                    prolog,
                    even,
                    odd,
                    stage0_va: *stage0_va,
                });
            }
        }
    }
    matches.sort_by_key(|value| (value.prolog, value.even, value.odd));
    matches.dedup_by_key(|value| (value.prolog, value.even, value.odd));
    match matches.as_slice() {
        [recovered] => Ok(*recovered),
        [] => Err("no direct-call target matched the complete Classic stage0 grammar".to_string()),
        _ => Err(
            "multiple direct-call targets produced different complete Classic dispatch tables"
                .to_string(),
        ),
    }
}

fn parse_generated_prolog(code: &[u8], start: usize) -> std::result::Result<(u8, usize), String> {
    let tail = code
        .get(start..)
        .ok_or_else(|| "prolog starts beyond generated program".to_string())?;
    if tail.first() == Some(&0xb8) && tail.len() >= 5 {
        return Ok((0, 5));
    }
    if tail.get(..2) == Some(&[0x8b, 0xc7]) {
        return Ok((1, 2));
    }
    if tail.first() == Some(&0xbe) && tail.len() >= 11 && tail.get(5..7) == Some(&[0x8b, 0x86]) {
        return Ok((2, 11));
    }
    Err(format!("unrecognized generated prolog at +0x{start:x}"))
}

fn classify_generated_binary_suffix(code: &[u8]) -> std::result::Result<u8, String> {
    let code = code
        .strip_suffix(&[0x5b])
        .ok_or_else(|| "stage1 depth-2 program lacks POP EBX".to_string())?;
    match code {
        [0x51, 0x89, 0xd9, 0x83, 0xe1, 0x0f, 0xd3, 0xe8, 0x59] => Ok(0),
        [0x51, 0x89, 0xd9, 0x83, 0xe1, 0x0f, 0xd3, 0xe0, 0x59] => Ok(1),
        [0x01, 0xd8] => Ok(2),
        [0x29, 0xc3, 0x89, 0xd8] => Ok(3),
        [0x0f, 0xaf, 0xc3] => Ok(4),
        [0x29, 0xd8] => Ok(5),
        _ => Err(format!("unrecognized generated binary suffix {code:02x?}")),
    }
}

fn classify_generated_unary_suffix(code: &[u8]) -> std::result::Result<u8, String> {
    if code == [0xf7, 0xd0] {
        return Ok(0);
    }
    if code == [0x48] {
        return Ok(1);
    }
    if code == [0xf7, 0xd8] {
        return Ok(2);
    }
    if code == [0x40] {
        return Ok(3);
    }
    if code.len() == 13
        && code[0] == 0xbe
        && code.get(5..10) == Some(&[0x25, 0xff, 0x03, 0x00, 0x00])
        && code.get(10..13) == Some(&[0x8b, 0x04, 0x86])
    {
        return Ok(4);
    }
    if code
        == [
            0x53, 0x89, 0xc3, 0x81, 0xe3, 0xaa, 0xaa, 0xaa, 0xaa, 0x25, 0x55, 0x55, 0x55, 0x55,
            0xd1, 0xeb, 0xd1, 0xe0, 0x09, 0xd8, 0x5b,
        ]
    {
        return Ok(5);
    }
    if code.len() == 5 && code[0] == 0x35 {
        return Ok(6);
    }
    if code.len() == 5 && matches!(code[0], 0x05 | 0x2d) {
        return Ok(7);
    }
    Err(format!("unrecognized generated unary suffix {code:02x?}"))
}

fn record_dispatch<const N: usize>(
    slots: &mut [Option<u8>; N],
    index: usize,
    semantic: u8,
    label: &str,
) -> std::result::Result<(), String> {
    match slots[index] {
        None => slots[index] = Some(semantic),
        Some(previous) if previous == semantic => {}
        Some(previous) => {
            return Err(format!(
                "conflicting {label} mapping at slot {index}: {previous} vs {semantic}"
            ))
        }
    }
    Ok(())
}

fn complete_dispatch<const N: usize>(
    slots: [Option<u8>; N],
    label: &str,
) -> std::result::Result<[u8; N], String> {
    let mut result = [0u8; N];
    let mut seen = [false; N];
    for (index, value) in slots.into_iter().enumerate() {
        let value = value.ok_or_else(|| format!("missing {label} mapping at slot {index}"))?;
        if value as usize >= N || seen[value as usize] {
            return Err(format!("{label} mapping is not a permutation"));
        }
        seen[value as usize] = true;
        result[index] = value;
    }
    Ok(result)
}

#[allow(dead_code)]
impl Generator<'_> {
    fn reserve(&mut self, n: usize) -> bool {
        let Some(next) = self.code_len.checked_add(n) else {
            return false;
        };
        if next > 128 {
            return false;
        }
        self.code_len = next;
        true
    }

    fn first_stage(&mut self) -> Option<Expr> {
        match self.rng.next_u32() % 3 {
            1 => {
                if !self.reserve(2) {
                    return None;
                }
                Some(Expr::Seed)
            }
            2 => {
                // MOV EAX, imm32.  Preserve original short-circuit timing:
                // the random immediate is consumed only after the opcode fits.
                if !self.reserve(1) {
                    return None;
                }
                let imm = self.rng.next_u32();
                if !self.reserve(4) {
                    return None;
                }
                Some(Expr::Immediate(imm))
            }
            0 => {
                // MOV ESI, table; MOV EAX,[ESI+disp32]
                if !self.reserve(1) || !self.reserve(4) || !self.reserve(2) {
                    return None;
                }
                let index = (self.rng.next_u32() & 0x3ff) as u16;
                if !self.reserve(4) {
                    return None;
                }
                Some(Expr::TableImmediate(index))
            }
            _ => unreachable!(),
        }
    }

    fn stage0(&mut self, stage: u32) -> Option<Expr> {
        if stage == 1 {
            return self.first_stage();
        }
        let child = if self.rng.next_u32() & 1 != 0 {
            self.stage1(stage - 1)?
        } else {
            self.stage0(stage - 1)?
        };

        let op = match self.rng.next_u32() & 7 {
            4 => {
                if !self.reserve(2) {
                    return None;
                }
                UnaryOp::Not
            }
            5 => {
                if !self.reserve(2) {
                    return None;
                }
                UnaryOp::Neg
            }
            1 => {
                if !self.reserve(1) {
                    return None;
                }
                UnaryOp::Inc
            }
            0 => {
                if !self.reserve(1) {
                    return None;
                }
                UnaryOp::Dec
            }
            2 => {
                // push ebx; mov ebx,eax; and/and/shr/shl/or; pop ebx
                for n in [1usize, 2, 6, 5, 2, 2, 2, 1] {
                    if !self.reserve(n) {
                        return None;
                    }
                }
                UnaryOp::SwapAdjacentBits
            }
            6 => {
                if !self.reserve(1) {
                    return None;
                }
                let imm = self.rng.next_u32();
                if !self.reserve(4) {
                    return None;
                }
                UnaryOp::Xor(imm)
            }
            7 => {
                let add = self.rng.next_u32() & 1 != 0;
                if !self.reserve(1) {
                    return None;
                }
                let imm = self.rng.next_u32();
                if !self.reserve(4) {
                    return None;
                }
                if add {
                    UnaryOp::Add(imm)
                } else {
                    UnaryOp::Sub(imm)
                }
            }
            3 => {
                // mov esi,table; and eax,3ffh; mov eax,[esi+eax*4]
                for n in [1usize, 4, 1, 4, 3] {
                    if !self.reserve(n) {
                        return None;
                    }
                }
                UnaryOp::TableMasked
            }
            _ => unreachable!(),
        };
        Some(Expr::Unary(op, Box::new(child)))
    }

    fn stage1(&mut self, stage: u32) -> Option<Expr> {
        if stage == 1 {
            return self.first_stage();
        }
        if !self.reserve(1) {
            return None;
        } // PUSH EBX
        let first = if self.rng.next_u32() & 1 != 0 {
            self.stage1(stage - 1)?
        } else {
            self.stage0(stage - 1)?
        };
        if !self.reserve(2) {
            return None;
        } // MOV EBX,EAX
        let second = if self.rng.next_u32() & 1 != 0 {
            self.stage1(stage - 1)?
        } else {
            self.stage0(stage - 1)?
        };

        let op = match self.rng.next_u32() % 6 {
            0 => {
                if !self.reserve(2) {
                    return None;
                }
                BinaryOp::Add
            }
            4 => {
                if !self.reserve(2) {
                    return None;
                }
                BinaryOp::SecondMinusFirst
            }
            5 => {
                if !self.reserve(2) || !self.reserve(2) {
                    return None;
                }
                BinaryOp::FirstMinusSecond
            }
            1 => {
                if !self.reserve(3) {
                    return None;
                }
                BinaryOp::Mul
            }
            2 => {
                for n in [1usize, 2, 3, 2, 1] {
                    if !self.reserve(n) {
                        return None;
                    }
                }
                BinaryOp::Shl
            }
            3 => {
                for n in [1usize, 2, 3, 2, 1] {
                    if !self.reserve(n) {
                        return None;
                    }
                }
                BinaryOp::Shr
            }
            _ => unreachable!(),
        };
        if !self.reserve(1) {
            return None;
        } // POP EBX
        Some(Expr::Binary(op, Box::new(first), Box::new(second)))
    }
}

impl LegacyCxdecFilter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let normalized = crate::pe_normalize::normalize_pe_file(path)?;
        let (bytes, pe, probe) = probe_with_static_self_decode(path, normalized.bytes)?;
        if !probe.recognized {
            return Err(Error::unsupported(format!(
                "{} is not a recognized native CXDEC generator module (confidence={}, reasons={})",
                path.display(),
                probe.confidence,
                probe.reasons.join("; ")
            )));
        }

        let profile = static_profile_from_probe(&bytes, &pe, &probe)?.ok_or_else(|| {
            Error::unsupported(format!(
                "{} is a recognized {:?} CXDEC family candidate, but the static Rust profile is incomplete: missing {}. NativeRust never executes DllMain/V2Link, the xcode builder, or the original callback to synthesize missing parameters",
                path.display(),
                probe.profile(),
                probe.missing_native_fields().join(", ")
            ))
        })?;

        let key0 = profile.mask;
        let key1 = profile.offset;
        let words = profile.control_words()?;
        let table = Box::new(words);
        let classic = Some(crate::cxdec_classic::ClassicCxdecEngine::new(profile)?);

        Ok(Self {
            module_path: path.to_path_buf(),
            table,
            lanes: Vec::new(),
            key0,
            key1,
            outer_xor: None,
            classic,
            probe,
        })
    }

    pub fn module_path(&self) -> &Path {
        &self.module_path
    }
    pub fn key0(&self) -> u32 {
        self.key0
    }
    pub fn key1(&self) -> u32 {
        self.key1
    }
    pub fn probe(&self) -> &LegacyCxdecProbe {
        &self.probe
    }
    pub fn outer_xor_period(&self) -> Option<usize> {
        self.outer_xor.as_ref().map(Vec::len)
    }
    pub fn init_mode(&self) -> &'static str {
        "recovered-profile-native-rust"
    }

    /// Apply the complete recovered CXDEC extraction filter.  Both the core
    /// transform and an optional transition-era wrapper are XOR-only, so the
    /// transformation is identical for encryption and decryption.
    pub fn apply(&self, file_offset: u64, file_hash: u32, data: &mut [u8]) -> Result<()> {
        self.apply_core(file_offset, file_hash, data)?;
        if let Some(table) = self.outer_xor.as_deref() {
            let period = table.len() as u64;
            for (i, byte) in data.iter_mut().enumerate() {
                let slot = ((file_offset + i as u64) % period) as usize;
                *byte ^= table[slot];
            }
        }
        Ok(())
    }

    fn apply_core(&self, file_offset: u64, file_hash: u32, data: &mut [u8]) -> Result<()> {
        if let Some(classic) = &self.classic {
            return classic.apply(file_offset, file_hash, data);
        }
        if data.is_empty() {
            return Ok(());
        }
        if file_offset > u32::MAX as u64 || data.len() > u32::MAX as usize {
            return Err(Error::unsupported(
                "CXDEC uses a 32-bit logical offset/length",
            ));
        }
        let offset = file_offset as u32;
        let len = data.len() as u32;
        let boundary = (file_hash & self.key0).wrapping_add(self.key1);
        let mut first_len = 0u32;
        if offset < boundary {
            first_len = if u64::from(offset) + u64::from(len) > u64::from(boundary) {
                boundary - offset
            } else {
                len
            };
            self.apply_span(file_hash, offset, &mut data[..first_len as usize]);
        }
        let remaining = len.wrapping_sub(first_len);
        if remaining != 0 {
            let second_hash = (file_hash >> 16) ^ file_hash;
            self.apply_span(
                second_hash,
                offset.wrapping_add(first_len),
                &mut data[first_len as usize..],
            );
        }
        Ok(())
    }

    fn calibrate_outer_xor(&mut self) -> Result<()> {
        const PROBE_LEN: usize = 8192;
        const MAX_PERIOD: usize = 4096;
        const HASH0: u32 = 0x1357_9bdf;
        const HASH1: u32 = 0xa6c3_1e27;
        const SAMPLES: &[(u64, u32)] = &[(0, HASH0), (0, HASH1), (137, HASH0), (4099, HASH1)];

        let mut runtime =
            match crate::x86_filter::X86Xp3FilterRuntime::open(&self.module_path, false) {
                Ok(value) => value,
                Err(err) => {
                    self.probe.reasons.push(format!(
                        "outer-wrapper calibration unavailable; native core retained: {err}"
                    ));
                    return Ok(());
                }
            };

        let mut residuals = Vec::with_capacity(SAMPLES.len());
        for &(offset, hash) in SAMPLES {
            let mut original = vec![0u8; PROBE_LEN];
            if let Err(err) = runtime.apply(offset, hash, &mut original) {
                self.probe.reasons.push(format!(
                    "outer-wrapper calibration callback failed; native core retained: {err}"
                ));
                return Ok(());
            }
            let mut native = vec![0u8; PROBE_LEN];
            self.apply_core(offset, hash, &mut native)?;
            for (left, right) in original.iter_mut().zip(native) {
                *left ^= right;
            }
            residuals.push((offset, hash, original));
        }

        let offset_samples: Vec<(u64, Vec<u8>)> = residuals
            .into_iter()
            .map(|(offset, _hash, residual)| (offset, residual))
            .collect();
        match recover_offset_xor_table(&offset_samples, MAX_PERIOD) {
            Ok(None) => {
                self.probe.reasons.push(
                    "original callback validates against native CXDEC core (no outer wrapper)"
                        .to_string(),
                );
            }
            Ok(Some(table)) => {
                let period = table.len();
                self.outer_xor = Some(table);
                self.probe.reasons.push(format!(
                    "transition wrapper recovered by callback/core differential: offset XOR period={period}"
                ));
            }
            Err(message) => return Err(Error::unsupported(message)),
        }
        Ok(())
    }

    fn apply_span(&self, hash: u32, offset: u32, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let lane = (hash & 0x7f) as usize;
        let seed = hash >> 7;
        let ret0 = self.eval_lane(&self.lanes[lane], seed);
        let ret1 = self.eval_lane(&self.lanes[lane], !seed);

        let sparse0 = ret1 >> 16;
        let mut sparse1 = ret1 & 0xffff;
        if sparse0 == sparse1 {
            sparse1 = sparse1.wrapping_add(1);
        }
        let correction0 = (ret0 >> 8) as u8;
        let correction1 = (ret0 >> 16) as u8;
        let mut body = ret0 as u8;
        if body == 0 {
            body = 1;
        }

        for b in data.iter_mut() {
            *b ^= body;
        }
        let end = u64::from(offset) + data.len() as u64;
        for (position, correction) in [(sparse1, correction1), (sparse0, correction0)] {
            let p = u64::from(position);
            if p >= u64::from(offset) && p < end {
                data[(p - u64::from(offset)) as usize] ^= correction;
            }
        }
    }

    fn eval_lane(&self, lane: &LaneProgram, seed: u32) -> u32 {
        match lane {
            LaneProgram::LegacyAst(expr) => self.eval(expr, seed),
            LaneProgram::Generated(ops) => self.eval_generated(ops, seed),
        }
    }

    fn eval_generated(&self, ops: &[GeneratedOp], seed: u32) -> u32 {
        let mut eax = 0u32;
        let mut ebx = 0u32;
        let mut ecx = 0u32;
        let mut _esi = 0u32;
        let edi = seed;
        let mut stack = Vec::<u32>::with_capacity(16);
        for op in ops {
            match *op {
                GeneratedOp::MovEaxSeed => eax = edi,
                GeneratedOp::MovEaxImm(v) => eax = v,
                GeneratedOp::SetTableBase(v) => _esi = v,
                GeneratedOp::LoadTableDisp(index) => eax = self.table[index as usize],
                GeneratedOp::LoadTableIndexed => eax = self.table[(eax & 0x3ff) as usize],
                GeneratedOp::NotEax => eax = !eax,
                GeneratedOp::NegEax => eax = 0u32.wrapping_sub(eax),
                GeneratedOp::IncEax => eax = eax.wrapping_add(1),
                GeneratedOp::DecEax => eax = eax.wrapping_sub(1),
                GeneratedOp::PushEbx => stack.push(ebx),
                GeneratedOp::PopEbx => ebx = stack.pop().unwrap_or(0),
                GeneratedOp::MovEbxEax => ebx = eax,
                GeneratedOp::AndEbx(v) => ebx &= v,
                GeneratedOp::AndEax(v) => eax &= v,
                GeneratedOp::ShrEbx1 => ebx >>= 1,
                GeneratedOp::ShlEax1 => eax = eax.wrapping_shl(1),
                GeneratedOp::OrEaxEbx => eax |= ebx,
                GeneratedOp::XorEax(v) => eax ^= v,
                GeneratedOp::AddEaxImm(v) => eax = eax.wrapping_add(v),
                GeneratedOp::SubEaxImm(v) => eax = eax.wrapping_sub(v),
                GeneratedOp::AddEaxEbx => eax = eax.wrapping_add(ebx),
                GeneratedOp::SubEaxEbx => eax = eax.wrapping_sub(ebx),
                GeneratedOp::ImulEaxEbx => eax = eax.wrapping_mul(ebx),
                GeneratedOp::PushEcx => stack.push(ecx),
                GeneratedOp::PopEcx => ecx = stack.pop().unwrap_or(0),
                GeneratedOp::MovEcxEbx => ecx = ebx,
                GeneratedOp::AndEcx(v) => ecx &= v,
                GeneratedOp::ShlEaxCl => eax = eax.wrapping_shl(ecx & 0x1f),
                GeneratedOp::ShrEaxCl => eax = eax.wrapping_shr(ecx & 0x1f),
            }
        }
        eax
    }

    fn eval(&self, expr: &Expr, seed: u32) -> u32 {
        match expr {
            Expr::Seed => seed,
            Expr::Immediate(v) => *v,
            Expr::TableImmediate(i) => self.table[*i as usize],
            Expr::Unary(op, child) => {
                let x = self.eval(child, seed);
                match *op {
                    UnaryOp::Not => !x,
                    UnaryOp::Neg => 0u32.wrapping_sub(x),
                    UnaryOp::Inc => x.wrapping_add(1),
                    UnaryOp::Dec => x.wrapping_sub(1),
                    UnaryOp::SwapAdjacentBits => {
                        ((x & 0xaaaa_aaaa) >> 1) | ((x & 0x5555_5555) << 1)
                    }
                    UnaryOp::Xor(v) => x ^ v,
                    UnaryOp::Add(v) => x.wrapping_add(v),
                    UnaryOp::Sub(v) => x.wrapping_sub(v),
                    UnaryOp::TableMasked => self.table[(x & 0x3ff) as usize],
                }
            }
            Expr::Binary(op, first, second) => {
                // Original stage1 stores the first child in EBX and leaves the
                // second child in EAX before applying the combine instruction.
                let a = self.eval(first, seed);
                let b = self.eval(second, seed);
                match op {
                    BinaryOp::Add => b.wrapping_add(a),
                    BinaryOp::SecondMinusFirst => b.wrapping_sub(a),
                    BinaryOp::FirstMinusSecond => a.wrapping_sub(b),
                    BinaryOp::Mul => b.wrapping_mul(a),
                    BinaryOp::Shl => b.wrapping_shl(a & 0x0f),
                    BinaryOp::Shr => b.wrapping_shr(a & 0x0f),
                }
            }
        }
    }
}

fn recover_offset_xor_table(
    samples: &[(u64, Vec<u8>)],
    max_period: usize,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let Some((_, base)) = samples.first() else {
        return Ok(None);
    };
    if base.is_empty() {
        return Ok(None);
    }
    if base.iter().all(|&byte| byte == 0) {
        if samples.iter().all(|(_, residual)| {
            residual.len() == base.len() && residual.iter().all(|&byte| byte == 0)
        }) {
            return Ok(None);
        }
        return Err(
            "CXDEC callback residual depends on hash/offset and is not the recovered native core"
                .to_string(),
        );
    }
    if samples
        .iter()
        .any(|(_, residual)| residual.len() != base.len())
    {
        return Err(
            "CXDEC callback/core differential samples have inconsistent lengths".to_string(),
        );
    }

    // Requiring at least two repetitions prevents an arbitrary one-shot
    // residual from being accepted as a table equal to the whole probe.
    let limit = max_period.min(base.len() / 2);
    let period = (1..=limit).find(|&candidate| {
        (candidate..base.len()).all(|i| base[i] == base[i - candidate])
    }).ok_or_else(|| format!(
        "CXDEC callback has a non-core wrapper, but its residual is not an offset-only XOR period <= {max_period}"
    ))?;
    let table = base[..period].to_vec();

    for (offset, residual) in samples {
        let phase = (*offset % period as u64) as usize;
        for (i, &byte) in residual.iter().enumerate() {
            if byte != table[(phase + i) % period] {
                return Err(format!(
                    "CXDEC callback wrapper is not hash-independent offset-periodic XOR (candidate period {period})"
                ));
            }
        }
    }
    Ok(Some(table))
}

#[allow(dead_code)]
fn build_lane(lane: u32) -> Option<Expr> {
    let mut rng = XcodeRng::new(lane);
    for depth in (1..=5u32).rev() {
        let mut gen = Generator {
            rng: &mut rng,
            code_len: 0,
        };
        if !gen.reserve(5) || !gen.reserve(4) {
            continue;
        } // generated prologue
        let Some(expr) = gen.stage1(depth) else {
            continue;
        };
        if !gen.reserve(5) || !gen.reserve(1) {
            continue;
        } // epilogue + RET
        return Some(expr);
    }
    None
}

fn parse_generated_lane(
    code: &[u8],
    expected_table_va: Option<u32>,
) -> std::result::Result<(Vec<GeneratedOp>, Option<u32>), String> {
    let mut ops = Vec::new();
    let mut observed_table_va: Option<u32> = None;
    let mut i = 0usize;
    while i < code.len() {
        let b = code[i];
        match b {
            0x8b => {
                if code.get(i + 1) == Some(&0xc7) {
                    ops.push(GeneratedOp::MovEaxSeed);
                    i += 2;
                } else if code.get(i + 1) == Some(&0x86) {
                    let raw = code
                        .get(i + 2..i + 6)
                        .ok_or_else(|| format!("truncated 8b86 at +0x{i:x}"))?;
                    let disp = u32::from_le_bytes(raw.try_into().unwrap());
                    if disp & 3 != 0 || disp / 4 >= 1024 {
                        return Err(format!(
                            "table displacement 0x{disp:x} is outside 4096-byte control block"
                        ));
                    }
                    ops.push(GeneratedOp::LoadTableDisp((disp / 4) as u16));
                    i += 6;
                } else if code.get(i + 1) == Some(&0x04) && code.get(i + 2) == Some(&0x86) {
                    ops.push(GeneratedOp::LoadTableIndexed);
                    i += 3;
                } else {
                    return Err(format!("unknown 8b opcode at +0x{i:x}"));
                }
            }
            0xb8 => {
                let raw = code
                    .get(i + 1..i + 5)
                    .ok_or_else(|| format!("truncated b8 at +0x{i:x}"))?;
                ops.push(GeneratedOp::MovEaxImm(u32::from_le_bytes(
                    raw.try_into().unwrap(),
                )));
                i += 5;
            }
            0xbe => {
                let raw = code
                    .get(i + 1..i + 5)
                    .ok_or_else(|| format!("truncated be at +0x{i:x}"))?;
                let va = u32::from_le_bytes(raw.try_into().unwrap());
                if let Some(expected) = expected_table_va {
                    if va != expected {
                        return Err(format!(
                            "generated lane references control block 0x{va:08x}, expected 0x{expected:08x}"
                        ));
                    }
                }
                match observed_table_va {
                    None => observed_table_va = Some(va),
                    Some(previous) if previous == va => {}
                    Some(previous) => return Err(format!(
                        "generated lane references multiple control blocks: 0x{previous:08x} and 0x{va:08x}"
                    )),
                }
                ops.push(GeneratedOp::SetTableBase(va));
                i += 5;
            }
            0xf7 => match code.get(i + 1).copied() {
                Some(0xd0) => {
                    ops.push(GeneratedOp::NotEax);
                    i += 2;
                }
                Some(0xd8) => {
                    ops.push(GeneratedOp::NegEax);
                    i += 2;
                }
                other => return Err(format!("unknown f7 {:?} at +0x{i:x}", other)),
            },
            0x40 => {
                ops.push(GeneratedOp::IncEax);
                i += 1;
            }
            0x48 => {
                ops.push(GeneratedOp::DecEax);
                i += 1;
            }
            0x53 => {
                ops.push(GeneratedOp::PushEbx);
                i += 1;
            }
            0x5b => {
                ops.push(GeneratedOp::PopEbx);
                i += 1;
            }
            0x51 => {
                ops.push(GeneratedOp::PushEcx);
                i += 1;
            }
            0x59 => {
                ops.push(GeneratedOp::PopEcx);
                i += 1;
            }
            0x89 => match code.get(i + 1).copied() {
                Some(0xc3) => {
                    ops.push(GeneratedOp::MovEbxEax);
                    i += 2;
                }
                Some(0xd9) => {
                    ops.push(GeneratedOp::MovEcxEbx);
                    i += 2;
                }
                other => return Err(format!("unknown 89 {:?} at +0x{i:x}", other)),
            },
            0x81 => {
                if code.get(i + 1) != Some(&0xe3) {
                    return Err(format!("unknown 81 opcode at +0x{i:x}"));
                }
                let raw = code
                    .get(i + 2..i + 6)
                    .ok_or_else(|| format!("truncated 81e3 at +0x{i:x}"))?;
                ops.push(GeneratedOp::AndEbx(u32::from_le_bytes(
                    raw.try_into().unwrap(),
                )));
                i += 6;
            }
            0x25 => {
                let raw = code
                    .get(i + 1..i + 5)
                    .ok_or_else(|| format!("truncated 25 at +0x{i:x}"))?;
                ops.push(GeneratedOp::AndEax(u32::from_le_bytes(
                    raw.try_into().unwrap(),
                )));
                i += 5;
            }
            0xd1 => match code.get(i + 1).copied() {
                Some(0xeb) => {
                    ops.push(GeneratedOp::ShrEbx1);
                    i += 2;
                }
                Some(0xe0) => {
                    ops.push(GeneratedOp::ShlEax1);
                    i += 2;
                }
                other => return Err(format!("unknown d1 {:?} at +0x{i:x}", other)),
            },
            0x09 if code.get(i + 1) == Some(&0xd8) => {
                ops.push(GeneratedOp::OrEaxEbx);
                i += 2;
            }
            0x35 => {
                let raw = code
                    .get(i + 1..i + 5)
                    .ok_or_else(|| format!("truncated 35 at +0x{i:x}"))?;
                ops.push(GeneratedOp::XorEax(u32::from_le_bytes(
                    raw.try_into().unwrap(),
                )));
                i += 5;
            }
            0x05 => {
                let raw = code
                    .get(i + 1..i + 5)
                    .ok_or_else(|| format!("truncated 05 at +0x{i:x}"))?;
                ops.push(GeneratedOp::AddEaxImm(u32::from_le_bytes(
                    raw.try_into().unwrap(),
                )));
                i += 5;
            }
            0x2d => {
                let raw = code
                    .get(i + 1..i + 5)
                    .ok_or_else(|| format!("truncated 2d at +0x{i:x}"))?;
                ops.push(GeneratedOp::SubEaxImm(u32::from_le_bytes(
                    raw.try_into().unwrap(),
                )));
                i += 5;
            }
            0x01 if code.get(i + 1) == Some(&0xd8) => {
                ops.push(GeneratedOp::AddEaxEbx);
                i += 2;
            }
            0x29 if code.get(i + 1) == Some(&0xd8) => {
                ops.push(GeneratedOp::SubEaxEbx);
                i += 2;
            }
            0x0f if code.get(i + 1) == Some(&0xaf) && code.get(i + 2) == Some(&0xc3) => {
                ops.push(GeneratedOp::ImulEaxEbx);
                i += 3;
            }
            0x83 => {
                if code.get(i + 1) != Some(&0xe1) {
                    return Err(format!("unknown 83 opcode at +0x{i:x}"));
                }
                let imm = *code
                    .get(i + 2)
                    .ok_or_else(|| format!("truncated 83e1 at +0x{i:x}"))?
                    as u32;
                ops.push(GeneratedOp::AndEcx(imm));
                i += 3;
            }
            0xd3 => match code.get(i + 1).copied() {
                Some(0xe0) => {
                    ops.push(GeneratedOp::ShlEaxCl);
                    i += 2;
                }
                Some(0xe8) => {
                    ops.push(GeneratedOp::ShrEaxCl);
                    i += 2;
                }
                other => return Err(format!("unknown d3 {:?} at +0x{i:x}", other)),
            },
            _ => return Err(format!("unknown generated opcode 0x{b:02x} at +0x{i:x}")),
        }
    }
    // The generated grammar is balanced around EBX/ECX saves.  Rejecting
    // malformed stack programs prevents a false-positive PE signature from
    // silently becoming a native filter.
    let mut depth = 0i32;
    for op in &ops {
        match op {
            GeneratedOp::PushEbx | GeneratedOp::PushEcx => depth += 1,
            GeneratedOp::PopEbx | GeneratedOp::PopEcx => {
                depth -= 1;
                if depth < 0 {
                    return Err("generated lane has stack underflow".to_string());
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(format!("generated lane leaves stack depth {depth}"));
    }
    if ops.is_empty() {
        return Err("generated lane is empty".to_string());
    }
    Ok((ops, observed_table_va))
}

pub fn probe_legacy_cxdec_module(path: impl AsRef<Path>) -> Result<LegacyCxdecProbe> {
    let path = path.as_ref();
    let normalized = crate::pe_normalize::normalize_pe_file(path)?;
    // Known-family detection remains static.  Deterministic self-decoding
    // wrappers are unfolded as data transformations only after their output
    // proves the classic generator semantics; no DllMain/V2Link code executes.
    let (_, _, probe) = probe_with_static_self_decode(path, normalized.bytes)?;
    Ok(probe)
}

/// Byte-backed static probe used for PE images embedded in a game executable.
/// The label is diagnostic provenance only; no code from the module executes.
pub fn probe_legacy_cxdec_bytes(
    label: impl AsRef<Path>,
    raw_bytes: &[u8],
) -> Result<LegacyCxdecProbe> {
    let label = label.as_ref();
    let normalized = crate::pe_normalize::normalize_pe_bytes(raw_bytes)?;
    let (_, _, probe) = probe_with_static_self_decode(label, normalized.bytes)?;
    Ok(probe)
}

/// Probe disk PE files and structurally extracted embedded PE modules around a
/// game target. This is the family-identification API; it does not imply that
/// an embedded module can be opened as a filesystem-backed runtime.
pub fn probe_cxdec_game_modules(path: impl AsRef<Path>) -> Result<Vec<LegacyCxdecProbe>> {
    let path = path.as_ref();
    let mut probes = Vec::new();
    for module in cxdec_candidate_modules(path)? {
        let metadata = match fs::metadata(&module) {
            Ok(value) if value.len() != 0 && value.len() <= MAX_SCAN_BYTES => value,
            _ => continue,
        };
        let _ = metadata;
        let raw = match fs::read(&module) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if let Ok(probe) = probe_legacy_cxdec_bytes(&module, &raw) {
            if probe.recognized {
                probes.push(probe);
            }
        }

        for embedded in crate::embedded_pe::extract_embedded_pe_modules_from_bytes(&module, &raw) {
            let label = PathBuf::from(embedded.label());
            if let Ok(probe) = probe_legacy_cxdec_bytes(&label, &embedded.bytes) {
                if probe.recognized {
                    probes.push(probe);
                }
            }
        }
    }
    probes.sort_by_key(|probe| (std::cmp::Reverse(probe.confidence), probe.path.clone()));
    probes.dedup_by(|a, b| a.path == b.path && a.profile() == b.profile());
    Ok(probes)
}

/// Scan one module or a game/plugin directory for statically recognizable
/// native CXDEC generator profiles. Executing DllMain/V2Link or a generated
/// builder is not part of family detection.
pub fn probe_legacy_cxdec_path(path: impl AsRef<Path>) -> Result<Vec<LegacyCxdecProbe>> {
    let path = path.as_ref();
    let mut files = Vec::new();
    let direct_ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let direct_known_plugin = matches!(direct_ext.as_str(), "dll" | "tpm");
    let direct_game_root = path.is_file()
        && (direct_ext == "exe"
            || (!direct_known_plugin && crate::magic_sniff::path_looks_like_pe(path)));
    if direct_game_root {
        // Treat a game EXE as a game-root hint: CXDEC commonly lives in a
        // sibling TPM/DLL even though the user naturally points us at the EXE.
        files.push(path.to_path_buf());
        if let Some(parent) = path.parent() {
            let mut siblings = Vec::new();
            collect_candidate_files(parent, 0, &mut siblings)?;
            siblings.retain(|candidate| candidate != path);
            files.extend(siblings);
        }
    } else {
        collect_candidate_files(path, 0, &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.len() > MAX_SCAN_FILES {
        files.truncate(MAX_SCAN_FILES);
    }
    let mut probes = Vec::new();
    for candidate in files {
        let metadata = match fs::metadata(&candidate) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if metadata.len() == 0 || metadata.len() > MAX_SCAN_BYTES {
            continue;
        }
        match probe_legacy_cxdec_module(&candidate) {
            Ok(probe) if probe.recognized => probes.push(probe),
            _ => {}
        }
    }
    probes.sort_by_key(|probe| (std::cmp::Reverse(probe.confidence), probe.path.clone()));
    Ok(probes)
}

/// Preferred family-wide name.  Legacy aliases remain exported for API
/// compatibility with the first native-CXDEC implementation.
pub type CxdecNativeFilter = LegacyCxdecFilter;
pub type CxdecProbe = LegacyCxdecProbe;

pub fn probe_cxdec_module(path: impl AsRef<Path>) -> Result<CxdecProbe> {
    probe_legacy_cxdec_module(path)
}

pub fn probe_cxdec_path(path: impl AsRef<Path>) -> Result<Vec<CxdecProbe>> {
    probe_legacy_cxdec_path(path)
}

/// Enumerate bounded PE candidates around a game executable without executing
/// any module initialization. Detection uses the project's content magic/PE
/// validation rather than filenames.
pub fn cxdec_candidate_modules(path: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
        if let Some(parent) = path.parent() {
            collect_candidate_files(parent, 0, &mut files)?;
        }
    } else {
        collect_candidate_files(path, 0, &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.len() > MAX_SCAN_FILES {
        files.truncate(MAX_SCAN_FILES);
    }
    Ok(files)
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxdecParamSources {
    pub mask_offset: PathBuf,
    pub control_block: PathBuf,
    pub dispatch_orders: PathBuf,
    pub random_seed: Option<PathBuf>,
    pub wrapper: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct RecoveredCxdecParams {
    pub content: crate::cxdec_classic::CxdecProfile,
    pub sources: CxdecParamSources,
}

/// Statically recoverable facts used by the Special/name cipher.  Control
/// words and the two seeds are deliberately independent because different
/// builds can materialize them in different PE modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredSpecialParamFacts {
    pub control_words: Option<[u32; 8]>,
    pub seeds: Option<(u32, u32)>,
    pub evidence_rva: u32,
    pub control_file_offset: Option<usize>,
}

#[derive(Clone, Debug)]
struct StaticDispatchCandidate {
    prolog: [u8; 3],
    even: [u8; 8],
    odd: [u8; 6],
    distance: u32,
}

#[derive(Clone, Debug)]
struct ModuleParamFacts {
    path: PathBuf,
    mask_offset: Option<(u32, u32)>,
    control_blocks: Vec<Vec<u8>>,
    dispatch: Vec<StaticDispatchCandidate>,
    classic: bool,
    cabbage: bool,
    random_seeds: Vec<u32>,
    riddle_prefix8: bool,
    setup_archive_data_generator: bool,
    v2link: bool,
}

/// Scan every PE around a game executable/directory and combine CXDEC
/// parameters across module boundaries.  No DllMain/V2Link/callback/builder is
/// executed.  Multiple complete candidates are returned when static evidence
/// is ambiguous; the archive layer is responsible for selecting one by
/// decrypting real entries and checking their original adlr/format evidence.
fn collect_module_param_facts(source: PathBuf, raw_bytes: &[u8]) -> Option<ModuleParamFacts> {
    let normalized = crate::pe_normalize::normalize_pe_bytes(raw_bytes).ok()?;
    let bytes = normalized.bytes;
    let pe = PeImage::parse(&bytes).ok()?;
    if pe.machine != 0x014c {
        return None;
    }

    let callback = find_callback_config(&bytes, &pe);
    let dynamic_xcode = find_classic_dynamic_xcode(&bytes, &pe);
    let control_blocks = find_control_block_file_offsets(&bytes, &pe)
        .into_iter()
        .filter_map(|off| pe.file_offset_to_rva(off as u32))
        .filter_map(|rva| pe.slice_rva(&bytes, rva, CONTROL_BLOCK_SIZE).ok())
        .map(|value| value.to_vec())
        .collect::<Vec<_>>();
    let classic = contains_u32(&bytes, XCODE_LCG_MUL) && contains_u32(&bytes, XCODE_LCG_ADD);
    let boundary = find_classic_boundary_params(&bytes, &pe).or_else(|| {
        // Some early builds compute `(hash & mask) + offset` directly in the
        // extraction filter instead of materializing an object with boundary
        // fields at +4/+8.  Only enable the direct form after independent
        // classic-CXDEC and control-table evidence is already present.
        if classic && !control_blocks.is_empty() {
            find_classic_direct_boundary_params(&bytes, &pe)
        } else {
            None
        }
    });
    let cabbage_rva = find_cabbage_prng_window(&bytes, &pe);
    let riddle_prefix8 = find_riddle_prefix8_window(&bytes, &pe).is_some();
    let setup_archive_data_generator =
        crate::has_setup_archive_data_special_generator(&bytes);
    let builder_rva = callback
        .as_ref()
        .map(|value| value.builder_rva)
        .or_else(|| dynamic_xcode.map(|value| value.builder_rva));
    // Newer object-based builders do not materialize the old 16-byte callback
    // descriptor.  The dynamic 128-lane manager and the Cabbage PRNG are both
    // semantic anchors for the nearby 3/8/6 generator switches, so dispatch
    // recovery must not depend on the legacy descriptor.
    let dispatch_anchor = builder_rva.or(cabbage_rva);
    let dispatch = dispatch_anchor
        .map(|builder| find_static_dispatch_candidates(&bytes, &pe, builder))
        .unwrap_or_default();
    let random_seeds = match cabbage_rva {
        Some(prng) => find_static_cabbage_seed_candidates(&bytes, &pe, prng, builder_rva),
        None => Vec::new(),
    };
    if callback.is_none()
        && dynamic_xcode.is_none()
        && boundary.is_none()
        && control_blocks.is_empty()
        && dispatch.is_empty()
        && !classic
        && cabbage_rva.is_none()
        && !riddle_prefix8
    {
        return None;
    }

    Some(ModuleParamFacts {
        path: source,
        mask_offset: callback
            .map(|value| (value.key0, value.key1))
            .or_else(|| boundary.map(|value| (value.mask, value.offset))),
        control_blocks,
        dispatch,
        classic,
        cabbage: cabbage_rva.is_some(),
        random_seeds,
        riddle_prefix8,
        setup_archive_data_generator,
        v2link: contains_bytes(&bytes, b"V2Link\0"),
    })
}

#[derive(Clone, Debug)]
struct StaticCxdecSelfDecode {
    initialized_file: Vec<u8>,
    section_rva: u32,
    seed: u32,
}

fn collect_x86_mov_push_immediates(bytes: &[u8], pe: &PeImage) -> Vec<u32> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const MAX_SEEDS: usize = 4096;

    let mut out = Vec::new();
    // The clear bootstrap normally lives in an RX section while the encoded
    // program storage is writable/executable.  Prefer immediates from RX code
    // so random bytes in the encoded section do not flood the seed set.
    for prefer_non_writable in [true, false] {
        for section in &pe.sections {
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            if prefer_non_writable && section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                continue;
            }
            let start = section.raw_offset as usize;
            let size = section.raw_size as usize;
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            let Some(code) = bytes.get(start..end.min(bytes.len())) else {
                continue;
            };
            let mut i = 0usize;
            while i + 5 <= code.len() {
                let op = code[i];
                if (0xb8..=0xbf).contains(&op) || op == 0x68 {
                    let value = u32::from_le_bytes([
                        code[i + 1],
                        code[i + 2],
                        code[i + 3],
                        code[i + 4],
                    ]);
                    if !out.contains(&value) {
                        out.push(value);
                        if out.len() >= MAX_SEEDS {
                            out.sort_by_key(|value| {
                                if *value <= 0xffff {
                                    0u8
                                } else if *value <= 0x00ff_ffff {
                                    1u8
                                } else {
                                    2u8
                                }
                            });
                            return out;
                        }
                    }
                }
                i += 1;
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out.sort_by_key(|value| {
        if *value <= 0xffff {
            0u8
        } else if *value <= 0x00ff_ffff {
            1u8
        } else {
            2u8
        }
    });
    out
}

#[inline]
fn legacy_decc_bitperm_state(old: u32) -> u32 {
    // Algebraic form of the shift/add state transition emitted by this CXDEC
    // bootstrap family.  Keeping it as one wrapping multiply is independent of
    // compiler register allocation and instruction scheduling.
    old.wrapping_mul(12_869)
        .wrapping_add(0x1b01)
        ^ (old >> 3)
}

#[inline]
fn legacy_decc_bitperm_byte(value: u8, mode: u32) -> u8 {
    match mode & 3 {
        0 => value.rotate_left(1),
        1 => ((value & 0x55) << 1) | ((value >> 1) & 0x55),
        2 => value.rotate_left(4),
        _ => ((value & 0x33) << 2) | ((value >> 2) & 0x33),
    }
}

fn decode_legacy_decc_bitperm_region(input: &[u8], seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(input.len());
    for &byte in input {
        state = legacy_decc_bitperm_state(state);
        out.push(legacy_decc_bitperm_byte(byte, state));
    }
    out
}

fn try_static_cxdec_self_decode(raw_bytes: &[u8]) -> Option<StaticCxdecSelfDecode> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const PROBE_LIMIT: usize = 256 * 1024;

    let normalized = crate::pe_normalize::normalize_pe_bytes(raw_bytes).ok()?;
    let bytes = normalized.bytes;
    let pe = PeImage::parse(&bytes).ok()?;
    if pe.machine != 0x014c {
        return None;
    }
    // This path exists specifically for the state where the on-disk image does
    // not expose the classic generator yet.  Never transform an already-clear
    // CXDEC implementation.
    if contains_u32(&bytes, XCODE_LCG_MUL) && contains_u32(&bytes, XCODE_LCG_ADD) {
        return None;
    }

    let seeds = collect_x86_mov_push_immediates(&bytes, &pe);
    if seeds.is_empty() {
        return None;
    }

    // Prefer writable/executable storage, but allow any executable section as
    // a fallback.  The decoded candidate is accepted only if it reveals both
    // exact classic-CXDEC LCG constants, so section names are not identity.
    for require_write in [true, false] {
        for section in &pe.sections {
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            if require_write && section.characteristics & IMAGE_SCN_MEM_WRITE == 0 {
                continue;
            }
            let start = section.raw_offset as usize;
            let stored = section.raw_size as usize;
            let semantic = if section.virtual_size == 0 {
                stored
            } else {
                (section.virtual_size as usize).min(stored)
            };
            if semantic == 0 || start >= bytes.len() {
                continue;
            }
            let available = semantic.min(bytes.len() - start);
            if available == 0 {
                continue;
            }
            let probe_len = available.min(PROBE_LIMIT);
            let probe = &bytes[start..start + probe_len];

            for &seed in &seeds {
                let decoded_probe = decode_legacy_decc_bitperm_region(probe, seed);
                if !contains_u32(&decoded_probe, XCODE_LCG_MUL)
                    || !contains_u32(&decoded_probe, XCODE_LCG_ADD)
                {
                    continue;
                }

                let decoded = decode_legacy_decc_bitperm_region(
                    &bytes[start..start + available],
                    seed,
                );
                let mut initialized_file = bytes.clone();
                initialized_file[start..start + available].copy_from_slice(&decoded);
                return Some(StaticCxdecSelfDecode {
                    initialized_file,
                    section_rva: section.virtual_address,
                    seed,
                });
            }
        }
        // Do not try the same writable/executable section twice after a proof
        // was found; reaching here means no candidate in this preference pass.
    }
    None
}


fn probe_with_static_self_decode(
    path: &Path,
    normalized_bytes: Vec<u8>,
) -> Result<(Vec<u8>, PeImage, LegacyCxdecProbe)> {
    let pe = PeImage::parse(&normalized_bytes)?;
    let probe = probe_bytes(path, &normalized_bytes, &pe);
    if probe.recognized
        || probe.control_block_rva.is_none()
        || !contains_bytes(&normalized_bytes, b"V2Link\0")
    {
        return Ok((normalized_bytes, pe, probe));
    }

    let Some(decoded) = try_static_cxdec_self_decode(&normalized_bytes) else {
        return Ok((normalized_bytes, pe, probe));
    };
    let decoded_pe = PeImage::parse(&decoded.initialized_file)?;
    let mut decoded_probe = probe_bytes(path, &decoded.initialized_file, &decoded_pe);
    if !decoded_probe.recognized {
        return Ok((normalized_bytes, pe, probe));
    }
    decoded_probe.profile_name = "cxdec-cxencryption-bitperm-v1";
    decoded_probe.reasons.push(format!(
        "self-decoding CXDEC executable storage recovered statically: section_rva=0x{:x} seed=0x{:x}; decoded code proves classic LCG semantics",
        decoded.section_rva, decoded.seed
    ));
    Ok((decoded.initialized_file, decoded_pe, decoded_probe))
}

fn needs_runtime_cxdec_initialization(fact: &ModuleParamFacts) -> bool {
    // A file-backed CXDEC control block plus the KiriKiri plugin entry point is
    // strong structural evidence.  Older CxEncryption TPMs can keep the
    // generator itself encoded until DLL initialization, so absence of the LCG,
    // boundary constructor or 3/8/6 dispatch in the on-disk image is exactly
    // the condition in which a bounded initialization snapshot is useful.
    fact.v2link
        && !fact.control_blocks.is_empty()
        && (!fact.classic || fact.mask_offset.is_none() || fact.dispatch.is_empty())
}

fn runtime_fact_improves_static(
    static_fact: &ModuleParamFacts,
    runtime_fact: &ModuleParamFacts,
) -> bool {
    (!static_fact.classic && runtime_fact.classic)
        || (static_fact.mask_offset.is_none() && runtime_fact.mask_offset.is_some())
        || (static_fact.dispatch.is_empty() && !runtime_fact.dispatch.is_empty())
        || (!static_fact.cabbage && runtime_fact.cabbage)
        || (!static_fact.riddle_prefix8 && runtime_fact.riddle_prefix8)
}

fn collect_game_module_param_facts(path: &Path) -> Result<Vec<ModuleParamFacts>> {
    let modules = cxdec_candidate_modules(path)?;
    let mut facts = Vec::new();
    for module in modules {
        let metadata = match fs::metadata(&module) {
            Ok(value) if value.len() != 0 && value.len() <= MAX_SCAN_BYTES => value,
            _ => continue,
        };
        let _ = metadata;
        let raw = match fs::read(&module) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if let Some(static_fact) = collect_module_param_facts(module.clone(), &raw) {
            let needs_initialization = needs_runtime_cxdec_initialization(&static_fact);
            facts.push(static_fact.clone());

            if needs_initialization {
                let mut best_fact = static_fact.clone();

                // Some early CxEncryption modules keep the generator in a
                // deterministic bit-permuted executable section.  Recover that
                // layer statically first: it is both smaller and more reliable
                // than running an arbitrary DLL initializer, and acceptance is
                // proven by the two exact classic-CXDEC LCG constants appearing
                // in the decoded code.
                match try_static_cxdec_self_decode(&raw) {
                    Some(decoded) => {
                        let source = PathBuf::from(format!(
                            "{}[self-decode:legacy-bitperm-v1]",
                            module.display()
                        ));
                        if let Some(decoded_fact) =
                            collect_module_param_facts(source, &decoded.initialized_file)
                        {
                            if runtime_fact_improves_static(&static_fact, &decoded_fact) {
                                eprintln!(
                                    "[cxdec-decc    ] module={} route=legacy-bitperm-v1 section_rva=0x{:x} seed=0x{:x} classic={} mask_offset={} dispatch={}",
                                    module.display(),
                                    decoded.section_rva,
                                    decoded.seed,
                                    decoded_fact.classic,
                                    decoded_fact.mask_offset.is_some(),
                                    decoded_fact.dispatch.len(),
                                );
                                best_fact = decoded_fact.clone();
                                facts.push(decoded_fact);
                            } else {
                                eprintln!(
                                    "[cxdec-decc    ] module={} route=legacy-bitperm-v1 status=no-new-cxdec-facts",
                                    module.display()
                                );
                            }
                        } else {
                            eprintln!(
                                "[cxdec-decc    ] module={} route=legacy-bitperm-v1 status=decoded-image-unrecognized",
                                module.display()
                            );
                        }
                    }
                    None => {
                        eprintln!(
                            "[cxdec-decc    ] module={} route=legacy-bitperm-v1 status=no-proof",
                            module.display()
                        );
                    }
                }

                // Keep the bounded Unicorn initializer as a fallback for other
                // self-modifying CXDEC wrappers.  Do not run it when the static
                // self-decode already exposed every native field we need.
                if needs_runtime_cxdec_initialization(&best_fact) {
                    match crate::x86_filter::initialize_x86_module_for_static_analysis(&module) {
                        Ok(snapshots) => {
                            for snapshot in snapshots {
                                if snapshot.changed_executable_bytes == 0 {
                                    continue;
                                }
                                let source = PathBuf::from(format!(
                                    "{}[{}]",
                                    module.display(),
                                    snapshot.stage
                                ));
                                let Some(runtime_fact) = collect_module_param_facts(
                                    source,
                                    &snapshot.initialized_file,
                                ) else {
                                    continue;
                                };
                                if runtime_fact_improves_static(&best_fact, &runtime_fact) {
                                    eprintln!(
                                        "[cxdec-init    ] module={} stage={} changed_exec={} classic={} mask_offset={} dispatch={}",
                                        module.display(),
                                        snapshot.stage,
                                        snapshot.changed_executable_bytes,
                                        runtime_fact.classic,
                                        runtime_fact.mask_offset.is_some(),
                                        runtime_fact.dispatch.len(),
                                    );
                                    best_fact = runtime_fact.clone();
                                    facts.push(runtime_fact);
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "[cxdec-init    ] module={} status=failed error={}",
                                module.display(),
                                err
                            );
                        }
                    }
                }
            }
        }

        // Riddle-era executables can store the real CXDEC module as a zlib
        // `internal module` and manually map it at runtime. Analyze every
        // structurally valid embedded PE exactly like a disk PE.
        for embedded in crate::embedded_pe::extract_embedded_pe_modules_from_bytes(&module, &raw) {
            let source = PathBuf::from(embedded.label());
            if let Some(static_fact) = collect_module_param_facts(source.clone(), &embedded.bytes) {
                let needs_initialization = needs_runtime_cxdec_initialization(&static_fact);
                facts.push(static_fact.clone());

                if needs_initialization {
                    let mut best_fact = static_fact.clone();
                    match try_static_cxdec_self_decode(&embedded.bytes) {
                        Some(decoded) => {
                            let decoded_source = PathBuf::from(format!(
                                "{}[self-decode:legacy-bitperm-v1]",
                                source.display()
                            ));
                            if let Some(decoded_fact) = collect_module_param_facts(
                                decoded_source,
                                &decoded.initialized_file,
                            ) {
                                if runtime_fact_improves_static(&static_fact, &decoded_fact) {
                                    eprintln!(
                                        "[cxdec-decc    ] module={} route=legacy-bitperm-v1 section_rva=0x{:x} seed=0x{:x} classic={} mask_offset={} dispatch={}",
                                        source.display(),
                                        decoded.section_rva,
                                        decoded.seed,
                                        decoded_fact.classic,
                                        decoded_fact.mask_offset.is_some(),
                                        decoded_fact.dispatch.len(),
                                    );
                                    best_fact = decoded_fact.clone();
                                    facts.push(decoded_fact);
                                }
                            }
                        }
                        None => {
                            eprintln!(
                                "[cxdec-decc    ] module={} route=legacy-bitperm-v1 status=no-proof",
                                source.display()
                            );
                        }
                    }

                    if needs_runtime_cxdec_initialization(&best_fact) {
                        match crate::x86_filter::initialize_x86_module_bytes_for_static_analysis(
                            &embedded.bytes,
                        ) {
                            Ok(snapshots) => {
                                for snapshot in snapshots {
                                    if snapshot.changed_executable_bytes == 0 {
                                        continue;
                                    }
                                    let runtime_source = PathBuf::from(format!(
                                        "{}[{}]",
                                        source.display(),
                                        snapshot.stage
                                    ));
                                    let Some(runtime_fact) = collect_module_param_facts(
                                        runtime_source,
                                        &snapshot.initialized_file,
                                    ) else {
                                        continue;
                                    };
                                    if runtime_fact_improves_static(&best_fact, &runtime_fact) {
                                        eprintln!(
                                            "[cxdec-init    ] module={} stage={} changed_exec={} classic={} mask_offset={} dispatch={}",
                                            source.display(),
                                            snapshot.stage,
                                            snapshot.changed_executable_bytes,
                                            runtime_fact.classic,
                                            runtime_fact.mask_offset.is_some(),
                                            runtime_fact.dispatch.len(),
                                        );
                                        best_fact = runtime_fact.clone();
                                        facts.push(runtime_fact);
                                    }
                                }
                            }
                            Err(err) => {
                                eprintln!(
                                    "[cxdec-init    ] module={} status=failed error={}",
                                    source.display(),
                                    err
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(facts)
}

/// Scan the game PE files plus PE images embedded in those files.  Embedded
/// protection modules are analyzed from bytes after extraction; they do not
/// need to exist as files on disk.
pub fn recover_cxdec_params_from_game(
    path: impl AsRef<Path>,
) -> Result<Vec<RecoveredCxdecParams>> {
    recover_cxdec_params_from_game_with_control_blocks(path, &[])
}

/// Same as [`recover_cxdec_params_from_game`], with additional verified
/// 4096-byte control blocks produced by a runtime initializer such as
/// `Storages.setupArchiveData`.  The supplied blocks are parameters, not
/// detection hints: all remaining parameters still have to be recovered from
/// executable code and the complete combination is validated by the caller on
/// real archive contents.
pub fn recover_cxdec_params_from_game_with_control_blocks(
    path: impl AsRef<Path>,
    additional_controls: &[(Vec<u8>, PathBuf)],
) -> Result<Vec<RecoveredCxdecParams>> {
    recover_cxdec_params_from_game_with_generated_values(path, additional_controls, &[])
}

/// Recover content parameters while accepting values produced by a verified
/// runtime initializer.  This is used when the executable stores the CXDEC
/// implementation as an embedded PE and derives the split mask/offset and
/// 4096-byte control block from `Storages.setupArchiveData` instead of
/// materializing them as static PE data.
pub fn recover_cxdec_params_from_game_with_generated_values(
    path: impl AsRef<Path>,
    additional_controls: &[(Vec<u8>, PathBuf)],
    additional_mask_offsets: &[((u32, u32), PathBuf)],
) -> Result<Vec<RecoveredCxdecParams>> {
    let facts = collect_game_module_param_facts(path.as_ref())?;

    let mask_offsets = unique_facts(
        facts
            .iter()
            .filter_map(|f| f.mask_offset.map(|value| (value, f.path.clone())))
            .chain(additional_mask_offsets.iter().cloned()),
    );
    let controls = unique_vec_facts(
        facts
            .iter()
            .flat_map(|f| {
                f.control_blocks
                    .iter()
                    .cloned()
                    .map(|value| (value, f.path.clone()))
                    .collect::<Vec<_>>()
            })
            .chain(additional_controls.iter().cloned()),
    );
    let dispatches = unique_dispatch_facts(&facts);
    let classic_seen = facts.iter().any(|f| f.classic);
    let cabbage_seen = facts.iter().any(|f| f.cabbage);
    let mut wrappers: Vec<Option<PathBuf>> = vec![None];
    wrappers.extend(
        facts
            .iter()
            .filter(|f| f.riddle_prefix8)
            .map(|f| Some(f.path.clone())),
    );
    wrappers.sort();
    wrappers.dedup();
    let random_seeds = if cabbage_seen {
        unique_facts(facts.iter().flat_map(|f| {
            f.random_seeds
                .iter()
                .copied()
                .map(|seed| (seed, f.path.clone()))
                .collect::<Vec<_>>()
        }))
    } else {
        Vec::new()
    };

    if mask_offsets.is_empty() || controls.is_empty() || dispatches.is_empty() {
        return Ok(Vec::new());
    }
    if !classic_seen && (!cabbage_seen || random_seeds.is_empty()) {
        return Ok(Vec::new());
    }

    let mut generator_choices =
        Vec::<(crate::cxdec_classic::CxdecGeneratorKind, Option<PathBuf>)>::new();
    if classic_seen {
        generator_choices.push((crate::cxdec_classic::CxdecGeneratorKind::Classic, None));
    }
    if cabbage_seen {
        generator_choices.extend(random_seeds.iter().map(|(seed, source)| {
            (
                crate::cxdec_classic::CxdecGeneratorKind::Cabbage { random_seed: *seed },
                Some(source.clone()),
            )
        }));
    }

    const MAX_COMBINATIONS: usize = 4096;
    let mut out = Vec::new();
    'outer: for ((mask, offset), mask_source) in &mask_offsets {
        for (control, control_source) in &controls {
            for (dispatch, dispatch_source) in &dispatches {
                for (generator, random_source) in &generator_choices {
                    for wrapper_source in &wrappers {
                        let content = crate::cxdec_classic::CxdecProfile {
                            mask: *mask,
                            offset: *offset,
                            prolog_order: dispatch.prolog,
                            even_branch_order: dispatch.even,
                            odd_branch_order: dispatch.odd,
                            control_block: control.clone(),
                            generator: *generator,
                            wrappers: if wrapper_source.is_some() {
                                vec![crate::cxdec_classic::CxdecContentWrapper::RiddlePrefix8]
                            } else {
                                Vec::new()
                            },
                        };
                        if content.validate().is_err() {
                            continue;
                        }
                        out.push(RecoveredCxdecParams {
                            content,
                            sources: CxdecParamSources {
                                mask_offset: mask_source.clone(),
                                control_block: control_source.clone(),
                                dispatch_orders: dispatch_source.clone(),
                                random_seed: random_source.clone(),
                                wrapper: wrapper_source.clone(),
                            },
                        });
                        if out.len() >= MAX_COMBINATIONS {
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    dedup_recovered_params(&mut out);
    Ok(out)
}

/// Recover a coherent runtime-derived CXDEC content profile from one PE module.
///
/// This path is intentionally narrower than
/// [`recover_cxdec_params_from_game_with_generated_values`].  Runtime
/// `setupArchiveData` values provide the archive-specific mask/offset/control
/// block, while the generator grammar, Cabbage seed and content wrapper must
/// all come from the *same* structurally recognized PE.  This avoids the
/// cross-module Cartesian product used by the generic fallback.
pub fn recover_coherent_runtime_cxdec_params_from_game_with_generated_values(
    path: impl AsRef<Path>,
    additional_controls: &[(Vec<u8>, PathBuf)],
    additional_mask_offsets: &[((u32, u32), PathBuf)],
) -> Result<Vec<RecoveredCxdecParams>> {
    if additional_controls.is_empty() || additional_mask_offsets.is_empty() {
        return Ok(Vec::new());
    }

    let facts = collect_game_module_param_facts(path.as_ref())?;
    let mut out = Vec::new();

    for fact in &facts {
        // `setupArchiveData`, the Cabbage PRNG and Riddle's first-eight-byte
        // transform are independent structural anchors.  Requiring all three
        // keeps this a semantic fast path rather than a title/tag preset.
        if !fact.setup_archive_data_generator
            || !fact.cabbage
            || !fact.riddle_prefix8
            || fact.dispatch.is_empty()
            || fact.random_seeds.is_empty()
        {
            continue;
        }

        // Candidates are already ordered by dispatch distance and Cabbage-seed
        // evidence.  Keep every bounded dispatch recovered from this module and
        // a small seed ambiguity window; never mix these fields with another PE.
        for dispatch in &fact.dispatch {
            for &random_seed in fact.random_seeds.iter().take(8) {
                for ((mask, offset), mask_source) in additional_mask_offsets {
                    for (control, control_source) in additional_controls {
                        let content = crate::cxdec_classic::CxdecProfile {
                            mask: *mask,
                            offset: *offset,
                            prolog_order: dispatch.prolog,
                            even_branch_order: dispatch.even,
                            odd_branch_order: dispatch.odd,
                            control_block: control.clone(),
                            generator: crate::cxdec_classic::CxdecGeneratorKind::Cabbage {
                                random_seed,
                            },
                            wrappers: vec![crate::cxdec_classic::CxdecContentWrapper::RiddlePrefix8],
                        };
                        if content.validate().is_err() {
                            continue;
                        }
                        out.push(RecoveredCxdecParams {
                            content,
                            sources: CxdecParamSources {
                                mask_offset: mask_source.clone(),
                                control_block: control_source.clone(),
                                dispatch_orders: fact.path.clone(),
                                random_seed: Some(fact.path.clone()),
                                wrapper: Some(fact.path.clone()),
                            },
                        });
                    }
                }
            }
        }
    }

    dedup_recovered_params(&mut out);
    Ok(out)
}

fn unique_facts<T>(iter: impl IntoIterator<Item = (T, PathBuf)>) -> Vec<(T, PathBuf)>
where
    T: Copy + Ord,
{
    let mut values = std::collections::BTreeMap::<T, PathBuf>::new();
    for (value, source) in iter {
        values.entry(value).or_insert(source);
    }
    values.into_iter().collect()
}

fn unique_vec_facts(
    iter: impl IntoIterator<Item = (Vec<u8>, PathBuf)>,
) -> Vec<(Vec<u8>, PathBuf)> {
    let mut values = std::collections::BTreeMap::<Vec<u8>, PathBuf>::new();
    for (value, source) in iter {
        values.entry(value).or_insert(source);
    }
    values.into_iter().collect()
}

fn unique_dispatch_facts(facts: &[ModuleParamFacts]) -> Vec<(StaticDispatchCandidate, PathBuf)> {
    let mut values = std::collections::BTreeMap::<([u8; 3], [u8; 8], [u8; 6]), (StaticDispatchCandidate, PathBuf)>::new();
    for fact in facts {
        for dispatch in &fact.dispatch {
            let key = (dispatch.prolog, dispatch.even, dispatch.odd);
            match values.get(&key) {
                Some((current, _)) if current.distance <= dispatch.distance => {}
                _ => {
                    values.insert(key, (dispatch.clone(), fact.path.clone()));
                }
            }
        }
    }
    let mut values: Vec<_> = values.into_values().collect();
    values.sort_by_key(|(dispatch, source)| (dispatch.distance, source.clone()));
    values
}

fn dedup_recovered_params(values: &mut Vec<RecoveredCxdecParams>) {
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| {
        let generator = match value.content.generator {
            crate::cxdec_classic::CxdecGeneratorKind::Classic => (0u8, 0u32),
            crate::cxdec_classic::CxdecGeneratorKind::Cabbage { random_seed } => (1u8, random_seed),
        };
        let wrappers = value
            .content
            .wrappers
            .iter()
            .map(|wrapper| match wrapper {
                crate::cxdec_classic::CxdecContentWrapper::RiddlePrefix8 => 1u8,
            })
            .collect::<Vec<_>>();
        seen.insert((
            value.content.mask,
            value.content.offset,
            value.content.prolog_order,
            value.content.even_branch_order,
            value.content.odd_branch_order,
            value.content.control_block.clone(),
            generator,
            wrappers,
        ))
    });
}

/// Recover the 3/8/6 dispatch tables from compiler jump tables in the builder
/// code.  The table entry order is the random selector slot; each target block
/// is classified by the CXDEC byte-emission constants it contains.  This is a
/// static control-flow read: no x86 instruction from the game is executed.
fn find_static_dispatch_candidates(
    bytes: &[u8],
    pe: &PeImage,
    builder_rva: u32,
) -> Vec<StaticDispatchCandidate> {
    let mut prologs = find_dispatch_tables(bytes, pe, builder_rva, 3, DispatchKind::Prolog);
    prologs.extend(find_prolog_branch_dispatches(bytes, pe, builder_rva));
    prologs.sort_by_key(|(_, rva)| rva.abs_diff(builder_rva));
    prologs.dedup_by(|a, b| a.0 == b.0);
    prologs.truncate(8);
    let evens = find_dispatch_tables(bytes, pe, builder_rva, 8, DispatchKind::Even);
    let odds = find_dispatch_tables(bytes, pe, builder_rva, 6, DispatchKind::Odd);
    let mut out = Vec::new();
    for (prolog, prolog_rva) in &prologs {
        for (even, even_rva) in &evens {
            for (odd, odd_rva) in &odds {
                let mut p = [0u8; 3];
                let mut e = [0u8; 8];
                let mut o = [0u8; 6];
                p.copy_from_slice(prolog);
                e.copy_from_slice(even);
                o.copy_from_slice(odd);
                let distance = prolog_rva.abs_diff(builder_rva)
                    .saturating_add(even_rva.abs_diff(builder_rva))
                    .saturating_add(odd_rva.abs_diff(builder_rva));
                out.push(StaticDispatchCandidate {
                    prolog: p,
                    even: e,
                    odd: o,
                    distance,
                });
            }
        }
    }
    out.sort_by_key(|value| value.distance);
    out.dedup_by_key(|value| (value.prolog, value.even, value.odd));
    out.truncate(16);
    out
}

#[derive(Clone, Copy)]
enum DispatchKind {
    Prolog,
    Even,
    Odd,
}

fn find_dispatch_tables(
    bytes: &[u8],
    pe: &PeImage,
    builder_rva: u32,
    count: usize,
    kind: DispatchKind,
) -> Vec<(Vec<u8>, u32)> {
    let mut out = Vec::new();
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start.saturating_add(section.raw_size as usize).min(bytes.len());
        if end <= start + 7 {
            continue;
        }
        for off in start..=end - 7 {
            // FF /4 with [index*4 + disp32]: common MSVC/GCC dense-switch form.
            if bytes[off] != 0xff || bytes[off + 1] != 0x24 {
                continue;
            }
            let sib = bytes[off + 2];
            if (sib >> 6) != 2 || (sib & 7) != 5 || ((sib >> 3) & 7) == 4 {
                continue;
            }
            let table_va = u32::from_le_bytes(bytes[off + 3..off + 7].try_into().unwrap());
            let Some(table_off) = pe.va_to_file_offset(table_va).map(|value| value as usize) else {
                continue;
            };
            if table_off.checked_add(count * 4).is_none() || table_off + count * 4 > bytes.len() {
                continue;
            }
            let mut targets = Vec::with_capacity(count);
            let mut valid = true;
            for i in 0..count {
                let p = table_off + i * 4;
                let va = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                let Some(rva) = va.checked_sub(pe.image_base) else {
                    valid = false;
                    break;
                };
                if !pe.is_executable_rva(rva) {
                    valid = false;
                    break;
                }
                targets.push(rva);
            }
            if !valid {
                continue;
            }
            let mut order = Vec::with_capacity(count);
            for &target in &targets {
                let Some(target_off) = pe.rva_to_file_offset(target).map(|value| value as usize) else {
                    valid = false;
                    break;
                };
                let next_target = targets
                    .iter()
                    .copied()
                    .filter(|&candidate| candidate > target)
                    .min()
                    .and_then(|rva| pe.rva_to_file_offset(rva))
                    .map(|value| value as usize);
                let candidate_end = next_target
                    .filter(|&value| value > target_off)
                    .unwrap_or_else(|| target_off.saturating_add(160));
                let block_end = candidate_end
                    .min(target_off.saturating_add(160))
                    .min(bytes.len());
                if block_end <= target_off {
                    valid = false;
                    break;
                }
                let Some(semantic) =
                    classify_dispatch_target(bytes, pe, target_off, block_end, kind)
                else {
                    valid = false;
                    break;
                };
                order.push(semantic);
            }
            if !valid || !is_permutation(&order, count) {
                continue;
            }
            let Some(jmp_rva) = pe.file_offset_to_rva(off as u32) else {
                continue;
            };
            // The three builder switches are normally close to the callback's
            // stage1 entry.  Keep a generous bound for link-time reordering.
            if jmp_rva.abs_diff(builder_rva) > 0x20_000 {
                continue;
            }
            out.push((order, jmp_rva));
        }
    }
    out.sort_by_key(|(_, rva)| rva.abs_diff(builder_rva));
    out.dedup_by(|a, b| a.0 == b.0);
    out.truncate(8);
    out
}


/// Recover the three-way prolog selector emitted by MSVC builds that lower
/// `rng % 3` to a short conditional branch chain rather than a jump table.
/// The selector value is EDX after DIV; this form maps remainder 0 and 1 to
/// two explicit JE targets and lets remainder 2 fall through.
fn find_prolog_branch_dispatches(
    bytes: &[u8],
    pe: &PeImage,
    builder_rva: u32,
) -> Vec<(Vec<u8>, u32)> {
    let mut out = Vec::new();
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start.saturating_add(section.raw_size as usize).min(bytes.len());
        if end <= start + 32 {
            continue;
        }
        for off in start..end.saturating_sub(16) {
            // mov r32, 3 ; div r32
            let opcode = bytes[off];
            if !(0xb8..=0xbf).contains(&opcode)
                || bytes.get(off + 1..off + 5) != Some(&3u32.to_le_bytes()[..])
            {
                continue;
            }
            let reg = opcode - 0xb8;
            if bytes.get(off + 5) != Some(&0xf7)
                || bytes.get(off + 6).copied() != Some(0xf0 | reg)
            {
                continue;
            }
            let search_end = off.saturating_add(72).min(end);
            let mut first_je = None::<(usize, usize)>;
            let mut second_je = None::<(usize, usize)>;
            let mut cursor = off + 7;
            while cursor < search_end {
                let decoded = match bytes[cursor] {
                    0x74 if cursor + 1 < search_end => {
                        let target = (cursor as isize + 2 + bytes[cursor + 1] as i8 as isize) as usize;
                        Some((2usize, target))
                    }
                    0x0f if cursor + 5 < search_end && bytes[cursor + 1] == 0x84 => {
                        let rel = i32::from_le_bytes(bytes[cursor + 2..cursor + 6].try_into().unwrap());
                        let target = (cursor as isize + 6 + rel as isize) as usize;
                        Some((6usize, target))
                    }
                    _ => None,
                };
                if let Some((len, target)) = decoded {
                    if first_je.is_none() {
                        first_je = Some((cursor, target));
                    } else {
                        second_je = Some((cursor, target));
                        break;
                    }
                    cursor += len;
                } else {
                    cursor += 1;
                }
            }
            let (Some((_je0, target0)), Some((je1, target1))) = (first_je, second_je) else {
                continue;
            };

            // After the second JE, MSVC subtracts one more selector unit and
            // branches away on invalid values; the valid remainder-2 block is
            // the fallthrough immediately after that guard.
            let je1_len = if bytes[je1] == 0x74 { 2 } else { 6 };
            let guard_end = (je1 + je1_len).saturating_add(24).min(search_end);
            let mut target2 = None;
            let mut q = je1 + je1_len;
            while q < guard_end {
                if bytes[q] == 0x75 && q + 1 < guard_end {
                    target2 = Some(q + 2);
                    break;
                }
                if bytes[q] == 0x0f
                    && q + 5 < guard_end
                    && bytes[q + 1] == 0x85
                {
                    target2 = Some(q + 6);
                    break;
                }
                q += 1;
            }
            let Some(target2) = target2 else {
                continue;
            };
            let targets = [target0, target1, target2];
            if targets.iter().any(|&value| value < start || value >= end) {
                continue;
            }
            let mut order = Vec::with_capacity(3);
            let mut valid = true;
            for &target in &targets {
                let next_target = targets
                    .iter()
                    .copied()
                    .filter(|candidate| *candidate > target)
                    .min();
                let block_end = next_target
                    .unwrap_or_else(|| target.saturating_add(160))
                    .min(target.saturating_add(160))
                    .min(end);
                let Some(semantic) =
                    classify_dispatch_target(bytes, pe, target, block_end, DispatchKind::Prolog)
                else {
                    valid = false;
                    break;
                };
                order.push(semantic);
            }
            if !valid || !is_permutation(&order, 3) {
                continue;
            }
            let Some(selector_rva) = pe.file_offset_to_rva(off as u32) else {
                continue;
            };
            if selector_rva.abs_diff(builder_rva) > 0x20_000 {
                continue;
            }
            out.push((order, selector_rva));
        }
    }
    out.sort_by_key(|(_, rva)| rva.abs_diff(builder_rva));
    out.dedup_by(|a, b| a.0 == b.0);
    out.truncate(8);
    out
}

fn is_permutation(values: &[u8], count: usize) -> bool {
    if values.len() != count {
        return false;
    }
    let mut seen = vec![false; count];
    for &value in values {
        let index = value as usize;
        if index >= count || seen[index] {
            return false;
        }
        seen[index] = true;
    }
    true
}


fn classify_dispatch_target(
    bytes: &[u8],
    pe: &PeImage,
    target_off: usize,
    primary_end: usize,
    kind: DispatchKind,
) -> Option<u8> {
    let primary_end = primary_end.min(bytes.len());
    if target_off >= primary_end {
        return None;
    }
    let primary = &bytes[target_off..primary_end];
    if let Some(value) = classify_dispatch_block(primary, kind) {
        return Some(value);
    }

    // MSVC often shares an emission tail between two switch cases.  In that
    // form a case block contains the first opcode bytes and then a conditional
    // or unconditional branch to the common tail.  Looking only at the linear
    // bytes between adjacent jump-table targets loses half of the semantic
    // signature (for example NEG needs F7/D8 plus the shared push 01).
    // Follow only direct, nearby branches and keep the original block bytes in
    // front, so classification remains tied to this switch case.
    let origin_rva = pe.file_offset_to_rva(target_off as u32)?;
    let mut expanded = primary.to_vec();
    let scan_end = primary_end.min(target_off.saturating_add(160));
    let mut off = target_off;
    let mut followed = 0usize;
    while off < scan_end && followed < 8 {
        let decoded: Option<(usize, i32)> = match bytes[off] {
            0xeb if off + 1 < scan_end => Some((2, bytes[off + 1] as i8 as i32)),
            0x70..=0x7f if off + 1 < scan_end => {
                Some((2, bytes[off + 1] as i8 as i32))
            }
            0xe9 if off + 4 < scan_end => Some((
                5,
                i32::from_le_bytes(bytes[off + 1..off + 5].try_into().ok()?),
            )),
            0x0f if off + 5 < scan_end && (0x80..=0x8f).contains(&bytes[off + 1]) => {
                Some((
                    6,
                    i32::from_le_bytes(bytes[off + 2..off + 6].try_into().ok()?),
                ))
            }
            _ => None,
        };
        let Some((len, rel)) = decoded else {
            off += 1;
            continue;
        };
        let branch_rva = pe.file_offset_to_rva(off as u32)?;
        let target = i64::from(branch_rva) + len as i64 + i64::from(rel);
        let Ok(branch_target_rva) = u32::try_from(target) else {
            off += len;
            continue;
        };
        if branch_target_rva.abs_diff(origin_rva) > 0x4000 {
            off += len;
            continue;
        }
        let Some(branch_target_off) = pe
            .rva_to_file_offset(branch_target_rva)
            .map(|value| value as usize)
        else {
            off += len;
            continue;
        };
        if branch_target_off >= target_off && branch_target_off < primary_end {
            off += len;
            continue;
        }
        // Shared emission tails are tiny; keep this window deliberately short
        // so bytes from the next physical switch case cannot dominate the
        // semantic classifier.
        let tail_end = branch_target_off
            .saturating_add(24)
            .min(bytes.len());
        if branch_target_off < tail_end {
            expanded.extend_from_slice(&bytes[branch_target_off..tail_end]);
            followed += 1;
            if let Some(value) = classify_dispatch_block(&expanded, kind) {
                return Some(value);
            }
        }
        off += len;
    }
    None
}

fn classify_dispatch_block(bytes: &[u8], kind: DispatchKind) -> Option<u8> {
    let immediates = x86_push_immediates(bytes);
    let has = |value: u32| immediates.iter().any(|&candidate| candidate == value);
    let emitted = |value: u8| {
        has(value as u32)
            || bytes.windows(3).any(|window| {
                window[0] == 0xc6 && matches!(window[1], 0x00 | 0x01) && window[2] == value
            })
    };
    let raw32 = |value: u32| contains_u32(bytes, value);
    match kind {
        DispatchKind::Prolog => {
            if emitted(0xbe) && (emitted(0x86) || raw32(0x3ff)) {
                Some(2)
            } else if emitted(0x8b) && emitted(0xc7) {
                Some(1)
            } else if emitted(0xb8) {
                Some(0)
            } else {
                None
            }
        }
        DispatchKind::Even => {
            if (raw32(0xaaaa_aaaa) && raw32(0x5555_5555))
                || (immediates.iter().filter(|&&v| v == 0xaa).count() >= 4
                    && immediates.iter().filter(|&&v| v == 0x55).count() >= 4)
            {
                Some(5)
            } else if raw32(0x3ff) && (has(0xbe) || has(0x86) || has(0x25)) {
                Some(4)
            } else if has(0x35) {
                Some(6)
            } else if has(0x05) || has(0x2d) {
                Some(7)
            } else if has(0xf7) && has(0xd0) {
                Some(0)
            } else if has(0xf7) && has(0xd8) {
                Some(2)
            } else if has(0x48) {
                Some(1)
            } else if has(0x40) {
                Some(3)
            } else {
                None
            }
        }
        DispatchKind::Odd => {
            if has(0x0f) && has(0xaf) && has(0xc3) {
                Some(4)
            } else if has(0xf7) && has(0xd8) && has(0x01) {
                Some(3)
            } else if has(0x29) && has(0xd8) {
                Some(5)
            } else if has(0x01) && has(0xd8) {
                Some(2)
            } else if has(0xd3) && has(0xe8) {
                Some(0)
            } else if has(0xd3) && has(0xe0) {
                Some(1)
            } else {
                None
            }
        }
    }
}

fn x86_push_immediates(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            0x6a if i + 1 < bytes.len() => {
                out.push(bytes[i + 1] as u32);
                i += 2;
            }
            0x68 if i + 4 < bytes.len() => {
                out.push(u32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap()));
                i += 5;
            }
            _ => i += 1,
        }
    }
    out
}

/// Recover plausible Cabbage's second xorshift seed from static writes to the
/// state touched by the detected PRNG, plus tightly bounded builder-local
/// immediates for implementations that keep the seed in an object field.
/// Ambiguity is preserved as candidates and resolved against archive data.
fn find_static_cabbage_seed_candidates(
    bytes: &[u8],
    pe: &PeImage,
    prng_rva: u32,
    builder_rva: Option<u32>,
) -> Vec<u32> {
    let Some(prng_off) = pe.rva_to_file_offset(prng_rva).map(|value| value as usize) else {
        return Vec::new();
    };
    let mut state_addresses = std::collections::BTreeSet::<u32>::new();
    let prng_end = prng_off.saturating_add(768).min(bytes.len());
    let window = &bytes[prng_off..prng_end];
    let mut i = 0usize;
    while i < window.len() {
        match window[i] {
            0xa1 | 0xa3 if i + 4 < window.len() => {
                state_addresses.insert(u32::from_le_bytes(window[i + 1..i + 5].try_into().unwrap()));
                i += 5;
            }
            0x8b | 0x89 | 0x31 | 0x33 if i + 5 < window.len() => {
                let modrm = window[i + 1];
                if modrm & 0xc7 == 0x05 {
                    state_addresses.insert(u32::from_le_bytes(window[i + 2..i + 6].try_into().unwrap()));
                    i += 6;
                } else {
                    i += 2;
                }
            }
            _ => i += 1,
        }
    }

    let mut scored = std::collections::BTreeMap::<u32, u32>::new();

    // Object-based Cabbage generators commonly materialize the per-program
    // random seed in the small stack object passed to the recursive x86
    // builder.  Recognize the data-flow shape rather than a particular seed:
    //
    //   mov [esp+08], eax
    //   mov [esp+10], imm32      ; m_random_seed
    //   mov [esp+14], edx
    //   mov [esp+18], 0
    //   call ...                 ; build/emit program
    //
    // This is substantially stronger evidence than an arbitrary nearby
    // immediate, so rank it ahead of the broad compatibility scan below.
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        for off in start..end.saturating_sub(29) {
            if bytes.get(off..off + 4) != Some(&[0x89, 0x44, 0x24, 0x08])
                || bytes.get(off + 4..off + 8) != Some(&[0xc7, 0x44, 0x24, 0x10])
                || bytes.get(off + 12..off + 16) != Some(&[0x89, 0x54, 0x24, 0x14])
                || bytes.get(off + 16..off + 20) != Some(&[0xc7, 0x44, 0x24, 0x18])
                || bytes.get(off + 20..off + 24) != Some(&[0, 0, 0, 0])
                || bytes.get(off + 24) != Some(&0xe8)
            {
                continue;
            }
            let seed = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap());
            if seed_like(seed, pe) {
                *scored.entry(seed).or_default() += 1_000_000;
            }
        }
    }

    for &address in &state_addresses {
        let addr = address.to_le_bytes();
        for off in 0..bytes.len().saturating_sub(10) {
            // mov dword ptr [absolute], imm32
            if bytes[off] == 0xc7
                && bytes[off + 1] == 0x05
                && bytes[off + 2..off + 6] == addr[..]
            {
                let seed = u32::from_le_bytes(bytes[off + 6..off + 10].try_into().unwrap());
                if seed_like(seed, pe) {
                    *scored.entry(seed).or_default() += 100;
                }
            }
        }
    }

    // Object-based builds may initialize m_random_seed with MOV/PUSH immediates
    // near the builder/PRNG code rather than an absolute store.  Keep only
    // non-pointer, high-entropy constants and let real XP3 validation decide.
    for center_rva in builder_rva.into_iter().chain(std::iter::once(prng_rva)) {
        let Some(center) = pe.rva_to_file_offset(center_rva).map(|value| value as usize) else {
            continue;
        };
        let start = center.saturating_sub(0x2000);
        let end = center.saturating_add(0x2000).min(bytes.len());
        let local = &bytes[start..end];
        let mut j = 0usize;
        while j + 5 <= local.len() {
            let immediate = match local[j] {
                0x68 | 0xb8..=0xbf => Some((
                    u32::from_le_bytes(local[j + 1..j + 5].try_into().unwrap()),
                    5usize,
                )),
                // Object-based Cabbage builders commonly initialize the
                // second PRNG word as `mov dword ptr [esp+disp8], imm32`.
                // Decode that instruction instead of requiring the seed to be
                // a PUSH/MOV-register immediate.
                0xc7
                    if j + 8 <= local.len()
                        && local[j + 1] == 0x44
                        && local[j + 2] == 0x24 => Some((
                    u32::from_le_bytes(local[j + 4..j + 8].try_into().unwrap()),
                    8usize,
                )),
                _ => None,
            };
            if let Some((seed, insn_len)) = immediate {
                if seed_like(seed, pe) {
                    let distance = center.abs_diff(start + j) as u32;
                    let score = 16_384u32.saturating_sub(distance.min(16_383));
                    *scored.entry(seed).or_default() += 1 + score / 1024;
                    let call_end = j.saturating_add(insn_len + 40).min(local.len());
                    if local[j + insn_len..call_end].iter().any(|byte| *byte == 0xe8) {
                        *scored.entry(seed).or_default() += 48;
                    }
                }
            }
            j += 1;
        }
    }

    // The constructor call that supplies the title seed can be farther away
    // from the PRNG body. Scan executable code for high-entropy immediates that
    // participate in a short call setup. This is deliberately candidate
    // recovery, not blind selection: archive adlr/format validation is still
    // required before any value is accepted.
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        let mut off = start;
        while off + 5 <= end {
            let immediate = match bytes[off] {
                0x68 | 0xb8..=0xbf => Some((
                    u32::from_le_bytes(bytes[off + 1..off + 5].try_into().unwrap()),
                    5usize,
                )),
                0xc7
                    if off + 8 <= end
                        && bytes[off + 1] == 0x44
                        && bytes[off + 2] == 0x24 => Some((
                    u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()),
                    8usize,
                )),
                _ => None,
            };
            if let Some((seed, insn_len)) = immediate {
                if seed_like(seed, pe) {
                    let lookahead_end = off.saturating_add(insn_len + 40).min(end);
                    let call_nearby = bytes[off + insn_len..lookahead_end]
                        .iter()
                        .any(|byte| *byte == 0xe8);
                    if call_nearby {
                        *scored.entry(seed).or_default() += 20;
                    }
                }
            }
            off += 1;
        }
    }

    let mut values: Vec<_> = scored.into_iter().collect();
    values.sort_by_key(|(seed, score)| (std::cmp::Reverse(*score), *seed));
    values.into_iter().take(256).map(|(seed, _)| seed).collect()
}

fn seed_like(value: u32, pe: &PeImage) -> bool {
    if value < 0x1_0000
        || matches!(
            value,
            0x41c6_4e6d
                | 0x0000_3039
                | 0xaaaa_aaaa
                | 0x5555_5555
                | 0xffff_ffff
                | 0x3ff
        )
    {
        return false;
    }
    if pe.va_to_file_offset(value).is_some() {
        return false;
    }
    let bytes = value.to_le_bytes();
    bytes.iter().copied().collect::<std::collections::BTreeSet<_>>().len() >= 3
}

fn static_profile_from_probe(
    bytes: &[u8],
    pe: &PeImage,
    probe: &LegacyCxdecProbe,
) -> Result<Option<crate::cxdec_classic::CxdecProfile>> {
    if !probe.native_complete() {
        return Ok(None);
    }
    let table_rva = probe.control_block_rva.unwrap();
    let control_block = pe.slice_rva(bytes, table_rva, CONTROL_BLOCK_SIZE)?.to_vec();
    let generator = if probe.cabbage_prng_rva.is_some() {
        crate::cxdec_classic::CxdecGeneratorKind::Cabbage {
            random_seed: probe.random_seed.unwrap(),
        }
    } else {
        crate::cxdec_classic::CxdecGeneratorKind::Classic
    };
    let profile = crate::cxdec_classic::CxdecProfile {
        mask: probe.key0.unwrap(),
        offset: probe.key1.unwrap(),
        prolog_order: probe.prolog_order.unwrap(),
        even_branch_order: probe.even_branch_order.unwrap(),
        odd_branch_order: probe.odd_branch_order.unwrap(),
        control_block,
        generator,
        wrappers: if probe.riddle_prefix8_rva.is_some() {
            vec![crate::cxdec_classic::CxdecContentWrapper::RiddlePrefix8]
        } else {
            Vec::new()
        },
    };
    profile.validate()?;
    Ok(Some(profile))
}

/// Recover a complete owned CXDEC profile from file-backed PE data only.
/// Returning `None` means family evidence may exist but at least one required
/// parameter is not statically materialized/recoverable. No module code runs.
pub fn recover_static_cxdec_profile(
    path: impl AsRef<Path>,
) -> Result<Option<crate::cxdec_classic::CxdecProfile>> {
    let path = path.as_ref();
    let normalized = crate::pe_normalize::normalize_pe_file(path)?;
    let (bytes, pe, probe) = probe_with_static_self_decode(path, normalized.bytes)?;
    if !probe.recognized {
        return Ok(None);
    }
    static_profile_from_probe(&bytes, &pe, &probe)
}

/// Recover Special/name-cipher parameters from static x86 call sites.  The
/// anchor is the cipher's four-word complemented sigma constant followed by a
/// normal cdecl-style constructor call.  Merely finding the sigma bytes is not
/// enough: that pattern also occurs in unrelated ChaCha implementations.
///
/// The control pointer and seed arguments are resolved independently.  This is
/// what allows one DLL/TPM to contribute the control words and another module
/// to contribute the two seeds without executing either module.
pub fn recover_static_special_param_facts(
    path: impl AsRef<Path>,
) -> Result<Vec<RecoveredSpecialParamFacts>> {
    let path = path.as_ref();
    let normalized = crate::pe_normalize::normalize_pe_file(path)?;
    recover_static_special_param_facts_from_pe_bytes(&normalized.bytes)
}

/// Byte-backed Special parameter scan for a statically extracted embedded PE.
pub fn recover_static_special_param_facts_from_pe_bytes(
    bytes: &[u8],
) -> Result<Vec<RecoveredSpecialParamFacts>> {
    let pe = PeImage::parse(bytes)?;
    if pe.machine != 0x014c {
        return Ok(Vec::new());
    }

    let mut sigma_bytes = [0u8; 16];
    for (index, word) in crate::special_cipher::COMPLEMENTED_CHACHA_SIGMA
        .iter()
        .enumerate()
    {
        sigma_bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }

    let mut sigma_vas = std::collections::BTreeSet::<u32>::new();
    if bytes.len() >= sigma_bytes.len() {
        for file_offset in 0..=bytes.len() - sigma_bytes.len() {
            if bytes[file_offset..file_offset + sigma_bytes.len()] != sigma_bytes {
                continue;
            }
            if let Some(rva) = pe.file_offset_to_rva(file_offset as u32) {
                if let Some(va) = pe.image_base.checked_add(rva) {
                    sigma_vas.insert(va);
                }
            }
        }
    }
    if sigma_vas.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::<RecoveredSpecialParamFacts>::new();

    // Some builds keep a six-DWORD constant object
    // `!sigma || seed0 || seed1`.  Accept it only when code actually refers to
    // the object and the trailing DWORDs are values rather than PE pointers.
    // This rejects the PackinOne-style false hit where the same ChaCha sigma is
    // immediately followed by two function/data addresses.
    for &sigma_va in &sigma_vas {
        let Some(file_offset) = pe.va_to_file_offset(sigma_va) else {
            continue;
        };
        let file_offset = file_offset as usize;
        if file_offset + 24 > bytes.len() || count_u32_in_executable(&bytes, &pe, sigma_va) == 0 {
            continue;
        }
        let seed0 = u32::from_le_bytes(bytes[file_offset + 16..file_offset + 20].try_into().unwrap());
        let seed1 = u32::from_le_bytes(bytes[file_offset + 20..file_offset + 24].try_into().unwrap());
        if pe.va_to_file_offset(seed0).is_none() && pe.va_to_file_offset(seed1).is_none() {
            let evidence_rva = pe.file_offset_to_rva(file_offset as u32).unwrap_or(0);
            out.push(RecoveredSpecialParamFacts {
                control_words: None,
                seeds: Some((seed0, seed1)),
                evidence_rva,
                control_file_offset: None,
            });
        }
    }
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        if start >= end || end - start < 5 {
            continue;
        }

        // `push imm32` is used as the anchor because the sigma table itself is
        // static data.  Register-loaded variants are still handled for the
        // neighbouring control and seed arguments.
        for sigma_push in start..=end - 5 {
            if bytes[sigma_push] != 0x68 {
                continue;
            }
            let sigma_va = u32::from_le_bytes(
                bytes[sigma_push + 1..sigma_push + 5]
                    .try_into()
                    .unwrap(),
            );
            if !sigma_vas.contains(&sigma_va) {
                continue;
            }

            let call_limit = sigma_push.saturating_add(96).min(end.saturating_sub(4));
            for call_off in sigma_push + 5..=call_limit {
                if bytes[call_off] != 0xe8 {
                    continue;
                }
                let Some(call_rva) = pe.file_offset_to_rva(call_off as u32) else {
                    continue;
                };
                let rel = i32::from_le_bytes(
                    bytes[call_off + 1..call_off + 5]
                        .try_into()
                        .unwrap(),
                );
                let target = (call_rva as i64 + 5 + rel as i64) as u32;
                if !pe.is_executable_rva(target) {
                    continue;
                }

                let after_pushes = collect_push_offsets(
                    &bytes,
                    sigma_push + 5,
                    call_off,
                );
                if after_pushes.len() < 2 {
                    continue;
                }
                // cdecl pushes right-to-left: immediately before CALL we have
                // arg2(control), arg1(destination).  Therefore arg2 is the
                // second-to-last push after the sigma/arg3 push.
                let control_push = after_pushes[after_pushes.len() - 2];
                let control_va = resolve_static_push_value(
                    &bytes,
                    &pe,
                    control_push,
                    sigma_push + 5,
                );

                let before_start = sigma_push.saturating_sub(128).max(start);
                let before_pushes = collect_push_offsets(&bytes, before_start, sigma_push);
                // Immediately preceding sigma/arg3 are arg4(seed0) and then
                // arg5(seed1).  Resolve each independently; dynamic values are
                // intentionally left unknown instead of guessed.
                let seeds = if before_pushes.len() >= 2 {
                    let seed0_push = before_pushes[before_pushes.len() - 1];
                    let seed1_push = before_pushes[before_pushes.len() - 2];
                    match (
                        resolve_static_push_value(&bytes, &pe, seed0_push, before_start),
                        resolve_static_push_value(&bytes, &pe, seed1_push, before_start),
                    ) {
                        (Some(seed0), Some(seed1))
                            if pe.va_to_file_offset(seed0).is_none()
                                && pe.va_to_file_offset(seed1).is_none() =>
                        {
                            Some((seed0, seed1))
                        }
                        _ => None,
                    }
                } else {
                    None
                };

                let mut controls = Vec::<([u32; 8], usize)>::new();
                if let Some(control_va) = control_va {
                    if let Some(file_offset) = pe.va_to_file_offset(control_va) {
                        let file_offset = file_offset as usize;
                        if file_offset
                            .checked_add(32)
                            .is_some_and(|end| end <= bytes.len())
                        {
                            let mut direct = [0u32; 8];
                            for (index, word) in direct.iter_mut().enumerate() {
                                let p = file_offset + index * 4;
                                *word = u32::from_le_bytes(
                                    bytes[p..p + 4].try_into().unwrap(),
                                );
                            }
                            controls.push((direct, file_offset));
                            // Historical modules disagree on whether the
                            // file-backed table is stored logically or
                            // complemented.  Keep both representations here;
                            // the real Special payload selects the right one.
                            let mut complemented = direct;
                            for word in &mut complemented {
                                *word = !*word;
                            }
                            if complemented != direct {
                                controls.push((complemented, file_offset));
                            }
                        }
                    }
                }

                if controls.is_empty() {
                    if seeds.is_some() {
                        out.push(RecoveredSpecialParamFacts {
                            control_words: None,
                            seeds,
                            evidence_rva: call_rva,
                            control_file_offset: None,
                        });
                    }
                } else {
                    for (control_words, control_file_offset) in controls {
                        out.push(RecoveredSpecialParamFacts {
                            control_words: Some(control_words),
                            seeds,
                            evidence_rva: call_rva,
                            control_file_offset: Some(control_file_offset),
                        });
                    }
                }
            }
        }
    }

    out.sort_by_key(|fact| (
        fact.evidence_rva,
        fact.control_file_offset,
        fact.control_words,
        fact.seeds,
    ));
    out.dedup();
    Ok(out)
}

fn collect_push_offsets(bytes: &[u8], start: usize, end: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let end = end.min(bytes.len());
    let mut i = start.min(end);
    while i < end {
        let opcode = bytes[i];
        let len = match opcode {
            0x68 if i + 5 <= end => 5,
            0x6a if i + 2 <= end => 2,
            0x50..=0x57 => 1,
            _ => {
                i += 1;
                continue;
            }
        };
        out.push(i);
        i += len;
    }
    out
}

fn resolve_static_push_value(
    bytes: &[u8],
    pe: &PeImage,
    push_off: usize,
    lower_bound: usize,
) -> Option<u32> {
    let opcode = *bytes.get(push_off)?;
    match opcode {
        0x68 => {
            let raw = bytes.get(push_off + 1..push_off + 5)?;
            return Some(u32::from_le_bytes(raw.try_into().ok()?));
        }
        0x6a => {
            let value = *bytes.get(push_off + 1)? as i8 as i32;
            return Some(value as u32);
        }
        0x50..=0x57 => {}
        _ => return None,
    }

    let reg = opcode - 0x50;
    let start = lower_bound.min(push_off);
    let mut best = None::<(usize, u32)>;
    for i in start..push_off {
        // MOV r32, imm32
        if bytes.get(i).copied() == Some(0xb8 + reg) && i + 5 <= push_off {
            let value = u32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?);
            best = Some((i, value));
        }

        // XOR r32,r32 (31 /r or 33 /r) gives a static zero.
        if i + 2 <= push_off && matches!(bytes[i], 0x31 | 0x33) {
            let modrm = bytes[i + 1];
            if modrm & 0xc0 == 0xc0 {
                let dst = if bytes[i] == 0x31 { modrm & 7 } else { (modrm >> 3) & 7 };
                let src = if bytes[i] == 0x31 { (modrm >> 3) & 7 } else { modrm & 7 };
                if dst == reg && src == reg {
                    best = Some((i, 0));
                }
            }
        }

        // MOV r32,[abs32] or LEA r32,[abs32].  MOV resolves the global's
        // current file-backed DWORD; LEA resolves the address itself.
        if i + 6 <= push_off && matches!(bytes[i], 0x8b | 0x8d) {
            let modrm = bytes[i + 1];
            if modrm & 0xc7 == 0x05 && ((modrm >> 3) & 7) == reg {
                let absolute = u32::from_le_bytes(bytes[i + 2..i + 6].try_into().ok()?);
                if bytes[i] == 0x8d {
                    best = Some((i, absolute));
                } else if let Some(off) = pe.va_to_file_offset(absolute) {
                    let off = off as usize;
                    if off + 4 <= bytes.len() {
                        let value = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
                        best = Some((i, value));
                    }
                }
            }
        }

        // MOV EAX,[abs32] short form.
        if reg == 0 && bytes.get(i).copied() == Some(0xa1) && i + 5 <= push_off {
            let absolute = u32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?);
            if let Some(off) = pe.va_to_file_offset(absolute) {
                let off = off as usize;
                if off + 4 <= bytes.len() {
                    let value = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
                    best = Some((i, value));
                }
            }
        }
    }
    best.map(|(_, value)| value)
}

/// Recover every plausible file-backed 4096-byte CXDEC control block that is
/// statically tied to CXDEC code in this PE.  The historical ASCII header is a
/// fast path, not a requirement: newer builds can reference an opaque table
/// from the callback/builder code without retaining that text.
pub fn recover_static_cxdec_control_blocks(
    path: impl AsRef<Path>,
) -> Result<Vec<Vec<u8>>> {
    let path = path.as_ref();
    let normalized = crate::pe_normalize::normalize_pe_file(path)?;
    recover_static_cxdec_control_blocks_from_pe_bytes(&normalized.bytes)
}

/// Byte-backed form used for PE images embedded inside an executable.
/// The image is never mapped or initialized; it is parsed exactly like a
/// normal on-disk PE.
pub fn recover_static_cxdec_control_blocks_from_pe_bytes(
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let pe = PeImage::parse(bytes)?;
    let mut out = Vec::new();
    for file_off in find_control_block_file_offsets(bytes, &pe) {
        let Some(rva) = pe.file_offset_to_rva(file_off as u32) else {
            continue;
        };
        let Ok(block) = pe.slice_rva(bytes, rva, CONTROL_BLOCK_SIZE) else {
            continue;
        };
        let block = block.to_vec();
        if !out.iter().any(|value| *value == block) {
            out.push(block);
        }
    }
    Ok(out)
}

/// Backward-compatible single-result API.  New automatic recovery uses all
/// candidates and lets the real archive validation choose among them.
pub fn recover_static_cxdec_control_block(
    path: impl AsRef<Path>,
) -> Result<Option<Vec<u8>>> {
    Ok(recover_static_cxdec_control_blocks(path)?.into_iter().next())
}

fn find_control_block_file_offsets(bytes: &[u8], pe: &PeImage) -> Vec<usize> {
    let mut offsets = std::collections::BTreeSet::<usize>::new();
    if let Some(offset) = find_control_block_file_offset(bytes) {
        offsets.insert(offset);
    }

    let callback = find_callback_config(bytes, pe);
    let dynamic_xcode = find_classic_dynamic_xcode(bytes, pe);
    let cabbage = find_cabbage_prng_window(bytes, pe);
    let riddle = find_riddle_prefix8_window(bytes, pe);
    if let Some(dynamic) = dynamic_xcode {
        if let Some(file_off) = pe.rva_to_file_offset(dynamic.control_block_rva) {
            offsets.insert(file_off as usize);
        }
    }
    let mut anchors = Vec::<u32>::new();
    if let Some(callback) = callback {
        anchors.push(callback.builder_rva);
        anchors.push(callback.rva);
    }
    if let Some(dynamic) = dynamic_xcode {
        anchors.push(dynamic.manager_rva);
        anchors.push(dynamic.builder_rva);
    }
    if let Some(rva) = cabbage {
        anchors.push(rva);
    }
    if let Some(rva) = riddle {
        anchors.push(rva);
    }
    anchors.sort_unstable();
    anchors.dedup();

    for anchor in anchors {
        let Some(section) = pe.section_for_rva(anchor) else {
            continue;
        };
        if section.characteristics & 0x2000_0000 == 0 {
            // A callback configuration can itself be data.  Its builder RVA is
            // scanned separately; do not interpret arbitrary data bytes as x86.
            continue;
        }
        let Some(anchor_file) = pe.rva_to_file_offset(anchor) else {
            continue;
        };
        let section_start = section.raw_offset as usize;
        let section_end = section_start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        let anchor_file = anchor_file as usize;
        let scan_start = anchor_file.saturating_sub(0x8000).max(section_start);
        let scan_end = anchor_file
            .saturating_add(0x8000)
            .min(section_end);
        scan_control_pointer_instructions(bytes, pe, scan_start, scan_end, &mut offsets);
    }

    offsets.into_iter().collect()
}

fn scan_control_pointer_instructions(
    bytes: &[u8],
    pe: &PeImage,
    start: usize,
    end: usize,
    out: &mut std::collections::BTreeSet<usize>,
) {
    let end = end.min(bytes.len());
    let mut consider = |value: u32| {
        consider_control_pointer(bytes, pe, value, out);
        // Absolute memory operands often name a global pointer rather than the
        // table itself.  Follow one file-backed DWORD indirection as well.
        if let Some(pointer_off) = pe.va_to_file_offset(value) {
            let pointer_off = pointer_off as usize;
            if pointer_off + 4 <= bytes.len() {
                let indirect = u32::from_le_bytes(
                    bytes[pointer_off..pointer_off + 4]
                        .try_into()
                        .unwrap(),
                );
                consider_control_pointer(bytes, pe, indirect, out);
            }
        }
    };

    let mut i = start.min(end);
    while i < end {
        match bytes[i] {
            // PUSH imm32 / MOV reg,imm32 / MOV EAX,[abs] / MOV [abs],EAX.
            0x68 | 0xa1 | 0xa3 | 0xb8..=0xbf if i + 5 <= end => {
                let value = u32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap());
                consider(value);
                i += 5;
            }
            // MOV/LEA with the absolute disp32 ModRM form.
            0x8b | 0x8d if i + 6 <= end && bytes[i + 1] & 0xc7 == 0x05 => {
                let value = u32::from_le_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                consider(value);
                i += 6;
            }
            // MOV dword ptr [abs32], imm32: the immediate can itself be the
            // control-table address used by a tiny xcode emitter.
            0xc7 if i + 10 <= end && bytes[i + 1] == 0x05 => {
                let address = u32::from_le_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                let value = u32::from_le_bytes(bytes[i + 6..i + 10].try_into().unwrap());
                consider(address);
                consider(value);
                i += 10;
            }
            _ => i += 1,
        }
    }
}

fn consider_control_pointer(
    bytes: &[u8],
    pe: &PeImage,
    va: u32,
    out: &mut std::collections::BTreeSet<usize>,
) {
    let Some(rva) = va.checked_sub(pe.image_base) else {
        return;
    };
    let Some(section) = pe.section_for_rva(rva) else {
        return;
    };
    if section.characteristics & 0x2000_0000 != 0 {
        return;
    }
    let Some(file_off) = pe.va_to_file_offset(va) else {
        return;
    };
    let file_off = file_off as usize;
    let Some(end) = file_off.checked_add(CONTROL_BLOCK_SIZE) else {
        return;
    };
    if end > bytes.len() {
        return;
    }
    let section_file_end = (section.raw_offset as usize)
        .saturating_add(section.raw_size as usize)
        .min(bytes.len());
    if end > section_file_end || !looks_like_control_block(&bytes[file_off..end]) {
        return;
    }
    out.insert(file_off);
}

fn looks_like_control_block(block: &[u8]) -> bool {
    if block.len() != CONTROL_BLOCK_SIZE {
        return false;
    }
    let mut unique = std::collections::BTreeSet::<u32>::new();
    let mut zero = 0usize;
    let mut ff = 0usize;
    for chunk in block.chunks_exact(4) {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        unique.insert(word);
        if word == 0 {
            zero += 1;
        }
        if word == u32::MAX {
            ff += 1;
        }
    }
    // Control tables are deliberately irregular.  This only rejects obvious
    // BSS/zero/padding/string areas; archive decryption remains authoritative.
    unique.len() >= 512 && zero <= 64 && ff <= 64
}

fn find_control_block_file_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < CONTROL_BLOCK_SIZE {
        return None;
    }
    let last = bytes.len() - CONTROL_BLOCK_SIZE;
    (0..=last)
        .step_by(4)
        .find(|&offset| bytes[offset..].starts_with(CONTROL_BLOCK_SIGNATURE))
}

fn collect_candidate_files(path: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if is_candidate_module(path) {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() || depth > MAX_SCAN_DEPTH || out.len() >= MAX_SCAN_FILES {
        return Ok(());
    }
    let entries = match fs::read_dir(path) {
        Ok(value) => value,
        Err(_err) if depth != 0 => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        if out.len() >= MAX_SCAN_FILES {
            break;
        }
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        let child = entry.path();
        if child.is_dir() {
            collect_candidate_files(&child, depth + 1, out)?;
        } else if is_candidate_module(&child) {
            out.push(child);
        }
    }
    Ok(())
}

fn is_candidate_module(path: &Path) -> bool {
    crate::magic_sniff::path_looks_like_pe(path)
}


#[derive(Clone, Copy, Debug)]
struct ClassicDynamicXcodeEvidence {
    manager_rva: u32,
    builder_rva: u32,
    control_block_rva: u32,
}

#[derive(Clone, Copy, Debug)]
struct BoundaryParamsEvidence {
    rva: u32,
    mask: u32,
    offset: u32,
}

/// Recognize the classic 128-lane runtime xcode manager from executable
/// semantics rather than a title, module filename, or XP3 tag.
///
/// The manager splits the per-file key into `lane = key & 0x7f` and
/// `seed = key >> 7`, asks a bounded builder for at most 0x80 bytes of code,
/// executes the resulting lane for both `seed` and `!seed`, and obtains the
/// 4096-byte control table through a tiny pointer-return helper.  Every field
/// recovered here is subsequently validated as a file-backed PE address.
fn find_classic_dynamic_xcode(
    bytes: &[u8],
    pe: &PeImage,
) -> Option<ClassicDynamicXcodeEvidence> {
    if pe.machine != 0x014c
        || !contains_u32(bytes, XCODE_LCG_MUL)
        || !contains_u32(bytes, XCODE_LCG_ADD)
    {
        return None;
    }

    let mut found: Option<ClassicDynamicXcodeEvidence> = None;
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start.saturating_add(section.raw_size as usize).min(bytes.len());
        if end <= start + 32 {
            continue;
        }

        for and_off in start..end.saturating_sub(3) {
            // AND r32,0x7f using the compact 83 /4 ib form.
            if bytes[and_off] != 0x83
                || bytes[and_off + 2] != 0x7f
                || (bytes[and_off + 1] & 0xf8) != 0xe0
            {
                continue;
            }
            let lane_reg = bytes[and_off + 1] & 7;

            // The same source key is retained in another register and shifted
            // by seven bits to form the generated-program parameter.
            let split_end = and_off.saturating_add(24).min(end);
            let seed_reg = (and_off + 3..split_end.saturating_sub(2)).find_map(|off| {
                if bytes[off] == 0xc1
                    && (bytes[off + 1] & 0xf8) == 0xe8
                    && bytes[off + 2] == 7
                {
                    Some(bytes[off + 1] & 7)
                } else {
                    None
                }
            });
            let Some(seed_reg) = seed_reg else {
                continue;
            };

            // The builder call is associated with a 0x80-byte generated-code
            // budget and receives the lane selector. Search a modest local
            // window and require a direct call target in executable memory.
            let window_start = and_off.saturating_sub(32).max(start);
            let window_end = and_off.saturating_add(0x120).min(end);
            let mut push80 = window_start;
            while push80 + 5 <= window_end {
                if bytes[push80..push80 + 5] != [0x68, 0x80, 0, 0, 0] {
                    push80 += 1;
                    continue;
                }
                let call_end = push80.saturating_add(24).min(window_end);
                for call_off in push80 + 5..call_end.saturating_sub(4) {
                    if bytes[call_off] != 0xe8 {
                        continue;
                    }
                    let push_lane = 0x50u8.wrapping_add(lane_reg);
                    if !bytes[push80 + 5..call_off]
                        .iter()
                        .any(|byte| *byte == push_lane)
                    {
                        continue;
                    }
                    let Some(builder_rva) = rel32_call_target_rva(bytes, pe, call_off) else {
                        continue;
                    };
                    if !pe.is_executable_rva(builder_rva) {
                        continue;
                    }

                    // After generation/cache lookup, the exact same generated
                    // lane is invoked for `seed` and `!seed`. This relationship
                    // is much stronger than the individual constants alone.
                    if !has_seed_and_complement_lane_calls(bytes, call_off + 5, window_end, seed_reg)
                    {
                        continue;
                    }

                    // The control table is passed by a nearby helper which is
                    // commonly just `mov eax, imm32; ret`. This is materially
                    // stronger than scanning every 4096-byte-looking data run.
                    let search_back = push80.saturating_sub(48).max(window_start);
                    for getter_call in (search_back..push80).rev() {
                        if bytes[getter_call] != 0xe8 {
                            continue;
                        }
                        let Some(getter_rva) = rel32_call_target_rva(bytes, pe, getter_call) else {
                            continue;
                        };
                        let Some(getter_off) = pe.rva_to_file_offset(getter_rva).map(|v| v as usize)
                        else {
                            continue;
                        };
                        let Some(control_va) = tiny_pointer_return(bytes, getter_off) else {
                            continue;
                        };
                        let Some(control_rva) = control_va.checked_sub(pe.image_base) else {
                            continue;
                        };
                        let Ok(block) = pe.slice_rva(bytes, control_rva, CONTROL_BLOCK_SIZE) else {
                            continue;
                        };
                        if !looks_like_control_block(block) {
                            continue;
                        }
                        let manager_rva = pe.file_offset_to_rva(and_off as u32)?;
                        let candidate = ClassicDynamicXcodeEvidence {
                            manager_rva,
                            builder_rva,
                            control_block_rva: control_rva,
                        };
                        match found {
                            None => found = Some(candidate),
                            Some(previous)
                                if previous.builder_rva == candidate.builder_rva
                                    && previous.control_block_rva == candidate.control_block_rva =>
                            {
                                // Multiple equivalent references inside the
                                // same manager do not make the family ambiguous.
                            }
                            Some(_) => return None,
                        }
                    }
                }
                push80 += 1;
            }
        }
    }
    found
}

fn has_seed_and_complement_lane_calls(
    bytes: &[u8],
    start: usize,
    end: usize,
    seed_reg: u8,
) -> bool {
    let end = end.min(bytes.len());
    if start >= end {
        return false;
    }
    let push_seed = 0x50u8.wrapping_add(seed_reg);
    let not_seed = 0xd0u8.wrapping_add(seed_reg);
    let mut first_call = None;
    let mut off = start;
    while off + 1 < end {
        if bytes[off] == push_seed {
            let local_end = off.saturating_add(8).min(end);
            if (off + 1..local_end).any(|p| is_indirect_call(bytes, p, end)) {
                first_call = Some(off);
                break;
            }
        }
        off += 1;
    }
    let Some(first_call) = first_call else {
        return false;
    };

    let mut off = first_call + 1;
    while off + 2 < end {
        if bytes[off] == 0xf7 && bytes[off + 1] == not_seed {
            let after_not = off + 2;
            let push_end = after_not.saturating_add(12).min(end);
            for push_off in after_not..push_end {
                if bytes[push_off] != push_seed {
                    continue;
                }
                let call_end = push_off.saturating_add(8).min(end);
                if (push_off + 1..call_end).any(|p| is_indirect_call(bytes, p, end)) {
                    return true;
                }
            }
        }
        off += 1;
    }
    false
}

fn is_indirect_call(bytes: &[u8], off: usize, end: usize) -> bool {
    if off + 1 >= end || off + 1 >= bytes.len() || bytes[off] != 0xff {
        return false;
    }
    ((bytes[off + 1] >> 3) & 7) == 2
}

fn rel32_call_target_rva(bytes: &[u8], pe: &PeImage, call_off: usize) -> Option<u32> {
    if call_off.checked_add(5)? > bytes.len() || bytes[call_off] != 0xe8 {
        return None;
    }
    let call_rva = pe.file_offset_to_rva(call_off as u32)?;
    let rel = i32::from_le_bytes(bytes[call_off + 1..call_off + 5].try_into().ok()?);
    let target = i64::from(call_rva) + 5 + i64::from(rel);
    u32::try_from(target).ok()
}

fn tiny_pointer_return(bytes: &[u8], off: usize) -> Option<u32> {
    // mov eax, imm32 ; ret
    if off.checked_add(6)? <= bytes.len() && bytes[off] == 0xb8 && bytes[off + 5] == 0xc3 {
        return Some(u32::from_le_bytes(bytes[off + 1..off + 5].try_into().ok()?));
    }
    None
}

/// Recover the split boundary parameters from the filter-core constructor.
/// The recognizer requires the same register to be stored at object+4, masked,
/// incremented by the offset, and stored at object+8. This avoids accepting
/// unrelated `AND reg,imm; ADD reg,imm` arithmetic elsewhere in the module.

/// Recover the boundary expression from an extraction filter that computes it
/// in-place rather than storing precomputed fields in a helper object.
///
/// This deliberately has a narrow contract: callers only use it after the same
/// PE already proves the classic generator and a file-backed 4096-byte control
/// table.  Within executable code we then require `AND reg, imm32` followed by
/// `ADD` of another bounded immediate to the *same* register.  Distinct pairs
/// are treated as ambiguous instead of guessed.
fn find_classic_direct_boundary_params(
    bytes: &[u8],
    pe: &PeImage,
) -> Option<BoundaryParamsEvidence> {
    let mut found: Option<BoundaryParamsEvidence> = None;
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        if end <= start + 12 {
            continue;
        }

        for and_off in start..end.saturating_sub(12) {
            if bytes[and_off] != 0x81 {
                continue;
            }
            let modrm = bytes[and_off + 1];
            // 81 /4, register-direct: AND r32, imm32.
            if (modrm & 0xf8) != 0xe0 {
                continue;
            }
            let reg = modrm & 7;
            let mask = u32::from_le_bytes(bytes[and_off + 2..and_off + 6].try_into().ok()?);
            if mask == 0 || mask > 0x00ff_ffff {
                continue;
            }

            let search_end = and_off.saturating_add(40).min(end);
            for add_off in and_off + 6..search_end.saturating_sub(5) {
                // 81 /0 on the same register: ADD r32, imm32.
                if bytes[add_off] != 0x81 || bytes[add_off + 1] != (0xc0 | reg) {
                    continue;
                }
                let offset =
                    u32::from_le_bytes(bytes[add_off + 2..add_off + 6].try_into().ok()?);
                if offset == 0 || offset > 0x00ff_ffff {
                    continue;
                }
                let rva = pe.file_offset_to_rva(and_off as u32)?;
                let candidate = BoundaryParamsEvidence { rva, mask, offset };
                match found {
                    None => found = Some(candidate),
                    Some(previous)
                        if previous.mask == candidate.mask
                            && previous.offset == candidate.offset =>
                    {
                        if candidate.rva < previous.rva {
                            found = Some(candidate);
                        }
                    }
                    Some(_) => return None,
                }
            }
        }
    }
    found
}

fn find_classic_boundary_params(bytes: &[u8], pe: &PeImage) -> Option<BoundaryParamsEvidence> {
    let mut found: Option<BoundaryParamsEvidence> = None;
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start.saturating_add(section.raw_size as usize).min(bytes.len());
        if end <= start + 16 {
            continue;
        }
        for and_off in start..end.saturating_sub(12) {
            if bytes[and_off] != 0x81 {
                continue;
            }
            let and_modrm = bytes[and_off + 1];
            if (and_modrm & 0xf8) != 0xe0 {
                continue;
            }
            let reg = and_modrm & 7;
            let mask = u32::from_le_bytes(bytes[and_off + 2..and_off + 6].try_into().ok()?);
            if mask == 0 || mask > 0x00ff_ffff {
                continue;
            }

            let search_end = and_off.saturating_add(24).min(end);
            for add_off in and_off + 6..search_end.saturating_sub(5) {
                if bytes[add_off] != 0x81 || bytes[add_off + 1] != (0xc0 | reg) {
                    continue;
                }
                let offset = u32::from_le_bytes(bytes[add_off + 2..add_off + 6].try_into().ok()?);
                if offset == 0 || offset > 0x00ff_ffff {
                    continue;
                }
                let before = and_off.saturating_sub(16).max(start);
                let Some(base) = find_mov_store_reg_disp(bytes, before, and_off, reg, 4) else {
                    continue;
                };
                let after_end = add_off.saturating_add(18).min(end);
                if find_mov_store_reg_disp(bytes, add_off + 6, after_end, reg, 8) != Some(base) {
                    continue;
                }
                let rva = pe.file_offset_to_rva(and_off as u32)?;
                let candidate = BoundaryParamsEvidence { rva, mask, offset };
                match found {
                    None => found = Some(candidate),
                    Some(previous)
                        if previous.mask == candidate.mask && previous.offset == candidate.offset =>
                    {
                        if candidate.rva < previous.rva {
                            found = Some(candidate);
                        }
                    }
                    Some(_) => return None,
                }
            }
        }
    }
    found
}

fn find_mov_store_reg_disp(
    bytes: &[u8],
    start: usize,
    end: usize,
    reg: u8,
    disp: u8,
) -> Option<u8> {
    let end = end.min(bytes.len());
    if end <= start + 2 {
        return None;
    }
    for off in start..end.saturating_sub(2) {
        if bytes[off] != 0x89 {
            continue;
        }
        let modrm = bytes[off + 1];
        if (modrm >> 6) != 1 || ((modrm >> 3) & 7) != reg || (modrm & 7) == 4 {
            continue;
        }
        if bytes[off + 2] == disp {
            return Some(modrm & 7);
        }
    }
    None
}

fn probe_bytes(path: &Path, bytes: &[u8], pe: &PeImage) -> LegacyCxdecProbe {
    let mut score = 0u16;
    let mut reasons = Vec::new();

    if pe.machine == 0x014c {
        score += 5;
        reasons.push("PE32/i386".to_string());
    }

    let decc = pe
        .sections
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(".decc"));
    if let Some(section) = decc {
        score += 20;
        reasons.push(format!(
            ".decc section rva=0x{:x} size=0x{:x}",
            section.virtual_address,
            section.virtual_size.max(section.raw_size)
        ));
    }

    if contains_bytes(bytes, b"V2Link\0") {
        score += 8;
        reasons.push("V2Link export/name present".to_string());
    }
    if contains_bytes(bytes, b"V2Unlink\0") {
        score += 4;
        reasons.push("V2Unlink export/name present".to_string());
    }

    let has_lcg_mul = contains_u32(bytes, XCODE_LCG_MUL);
    let has_lcg_add = contains_u32(bytes, XCODE_LCG_ADD);
    if has_lcg_mul && has_lcg_add {
        score += 20;
        reasons.push("CXDEC xcode LCG constants 0x41c64e6d/0x3039".to_string());
    }

    // This is a separate semantic recognizer for the generation that keeps a
    // 128-lane executable-code cache.  It does not depend on the Special tag,
    // product string, module filename, or a title-specific marker.
    let dynamic_xcode = find_classic_dynamic_xcode(bytes, pe);
    if let Some(evidence) = dynamic_xcode {
        score += 36;
        reasons.push(format!(
            "classic 128-lane dynamic xcode manager rva=0x{:x} builder=0x{:x} control=0x{:x}",
            evidence.manager_rva, evidence.builder_rva, evidence.control_block_rva
        ));
    }

    let control_file = find_control_block_file_offset(bytes);
    let signature_control_rva = control_file.and_then(|off| pe.file_offset_to_rva(off as u32));
    let control_block_rva = signature_control_rva
        .or_else(|| dynamic_xcode.map(|value| value.control_block_rva));
    if let Some(rva) = control_block_rva {
        if pe.slice_rva(bytes, rva, CONTROL_BLOCK_SIZE).is_ok() {
            score += 30;
            reasons.push(format!("4096-byte CXDEC control table rva=0x{rva:x}"));
        }
    }

    let cabbage_prng_rva = find_cabbage_prng_window(bytes, pe);
    if let Some(rva) = cabbage_prng_rva {
        score += 24;
        reasons.push(format!(
            "Cabbage/CxProgramNana two-state xorshift semantics rva=0x{rva:x}"
        ));
    }
    let riddle_prefix8_rva = find_riddle_prefix8_window(bytes, pe);
    if let Some(rva) = riddle_prefix8_rva {
        score += 18;
        reasons.push(format!(
            "Riddle hash-derived Prefix8 semantic window rva=0x{rva:x}"
        ));
    }
    let has_table_mask = contains_u32(bytes, 0x3ff);
    let has_adjacent_masks = contains_u32(bytes, 0xaaaa_aaaa) && contains_u32(bytes, 0x5555_5555);
    if has_table_mask {
        score += 5;
        reasons.push("1024-word table mask 0x3ff".to_string());
    }
    if has_adjacent_masks {
        score += 10;
        reasons.push("stage0 adjacent-bit masks aaaaaaaa/55555555".to_string());
    }

    let callback = find_callback_config(bytes, pe);
    if let Some(config) = callback.as_ref() {
        score += 20;
        reasons.push(format!(
            "dec_callback rva=0x{:x} key0=0x{:x} key1=0x{:x} builder=0x{:x} xrefs={}",
            config.rva, config.key0, config.key1, config.builder_rva, config.xrefs
        ));
        if config.key0 == REFERENCE_KEY0 && config.key1 == REFERENCE_KEY1 {
            score += 3;
            reasons.push("reference callback keys 0x161/0x5c9 (bonus only)".to_string());
        }
    }

    let boundary = find_classic_boundary_params(bytes, pe).or_else(|| {
        if has_lcg_mul && has_lcg_add && control_block_rva.is_some() {
            find_classic_direct_boundary_params(bytes, pe)
        } else {
            None
        }
    });
    if let Some(value) = boundary {
        score += 24;
        reasons.push(format!(
            "content boundary expression rva=0x{:x} mask=0x{:x} offset=0x{:x}",
            value.rva, value.mask, value.offset
        ));
    }

    let builder_rva = callback
        .as_ref()
        .map(|value| value.builder_rva)
        .or_else(|| dynamic_xcode.map(|value| value.builder_rva));
    let dispatches = builder_rva
        .map(|builder| find_static_dispatch_candidates(bytes, pe, builder))
        .unwrap_or_default();
    let static_dispatch = if dispatches.len() == 1 {
        dispatches.first().cloned()
    } else {
        None
    };
    if let Some(dispatch) = static_dispatch.as_ref() {
        score += 20;
        reasons.push(format!(
            "static generator dispatch prolog={:?} even={:?} odd={:?}",
            dispatch.prolog, dispatch.even, dispatch.odd
        ));
    } else if dispatches.len() > 1 {
        reasons.push(format!(
            "generator dispatch remains ambiguous: {} structurally valid permutations",
            dispatches.len()
        ));
    }

    // This fingerprints the separate `.decc` self-decoder, not the content
    // cipher.  These arithmetic constants survive marker changes.
    let decc_state_constants = contains_u16(bytes, 0x3245) && contains_u16(bytes, 0x1b03);
    if decc_state_constants {
        score += 12;
        reasons.push(".decc state recurrence constants 0x3245/0x1b03".to_string());
    }
    let known_marker_hits = count_bytes(bytes, KNOWN_DECC_MARKER);
    if known_marker_hits >= 2 {
        score += 4;
        reasons.push(format!(
            "known sample .decc marker hits={known_marker_hits} (bonus only)"
        ));
    }

    if pe.image_base == 0x1e00_0000 {
        score += 4;
        reasons.push("historical image base 0x1e000000".to_string());
    }

    // Two independently recognized layouts share the same parameterized Rust
    // evaluator: the older callback/.decc form and the later object-based
    // 128-lane manager. The latter does not need the callback descriptor or the
    // adjacent-mask immediates to be materialized in one function.
    let classic_prng = has_lcg_mul && has_lcg_add;
    let cabbage_prng = cabbage_prng_rva.is_some();
    let callback_family_core = pe.machine == 0x014c
        && (classic_prng || cabbage_prng)
        && has_table_mask
        && has_adjacent_masks
        && callback.is_some();
    let dynamic_family_core = pe.machine == 0x014c
        && classic_prng
        && dynamic_xcode.is_some()
        && boundary.is_some()
        && control_block_rva.is_some();
    let family_core = callback_family_core || dynamic_family_core;

    // The oldest `.decc` fingerprint is useful evidence when the embedded
    // control block is already file-backed. Newer profiles remain incomplete
    // until every owned parameter is recovered statically.
    let legacy_decc = callback_family_core
        && classic_prng
        && control_block_rva.is_some()
        && decc.is_some()
        && decc_state_constants
        && callback
            .as_ref()
            .map(|value| value.builder_in_decc)
            .unwrap_or(false);
    if family_core && !legacy_decc {
        score += 10;
        reasons.push(
            "CXDEC generator recognized structurally; production use still requires a complete owned parameter set"
                .to_string(),
        );
    }
    let confidence = score.min(100) as u8;
    let recognized = family_core && confidence >= 60;
    let profile_name = if recognized && legacy_decc {
        "cxdec-legacy-decc-v1"
    } else if recognized && cabbage_prng && riddle_prefix8_rva.is_some() {
        "cxdec-riddle-generator-v3"
    } else if recognized && cabbage_prng {
        "cxdec-cabbage-generator-v2"
    } else if recognized && dynamic_family_core {
        "cxdec-early-dynamic-xcode-v1"
    } else if recognized {
        "cxdec-generator-v2"
    } else {
        "unknown"
    };

    let key0 = callback
        .as_ref()
        .map(|value| value.key0)
        .or_else(|| boundary.map(|value| value.mask));
    let key1 = callback
        .as_ref()
        .map(|value| value.key1)
        .or_else(|| boundary.map(|value| value.offset));

    LegacyCxdecProbe {
        path: path.to_path_buf(),
        profile_name,
        recognized,
        confidence,
        image_base: pe.image_base,
        decc_rva: decc.map(|s| s.virtual_address),
        decc_size: decc.map(|s| s.virtual_size.max(s.raw_size)),
        control_block_rva,
        callback_config_rva: callback.as_ref().map(|value| value.rva),
        xcode_builder_rva: builder_rva,
        xcode_builder_in_decc: callback
            .as_ref()
            .map(|value| value.builder_in_decc)
            .unwrap_or(false),
        cabbage_prng_rva,
        riddle_prefix8_rva,
        random_seed: None,
        key0,
        key1,
        prolog_order: static_dispatch.as_ref().map(|value| value.prolog),
        even_branch_order: static_dispatch.as_ref().map(|value| value.even),
        odd_branch_order: static_dispatch.as_ref().map(|value| value.odd),
        known_marker_hits,
        reasons,
    }
}

/// Locate the exact pair of state transitions used by `CxProgramNana` in one
/// compact executable window. Immediate shifts are decoded by ModRM semantics
/// rather than byte strings tied to a particular register allocation.
fn find_cabbage_prng_window(bytes: &[u8], pe: &PeImage) -> Option<u32> {
    const WINDOW: usize = 512;
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        if start >= end {
            continue;
        }
        for base in (start..end).step_by(128) {
            let stop = base.saturating_add(WINDOW).min(end);
            let window = &bytes[base..stop];
            if has_imm_shift(window, true, 17)
                && has_imm_shift(window, true, 18)
                && has_imm_shift(window, false, 15)
                && has_imm_shift(window, true, 13)
                && has_imm_shift(window, false, 17)
                && has_imm_shift(window, true, 5)
                && count_x86_xor(window) >= 5
                && has_x86_not(window)
            {
                return pe.file_offset_to_rva(base as u32);
            }
        }
    }
    None
}

fn find_riddle_prefix8_window(bytes: &[u8], pe: &PeImage) -> Option<u32> {
    const WINDOW: usize = 256;
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        for base in (start..end).step_by(32) {
            let window = &bytes[base..base.saturating_add(WINDOW).min(end)];
            // Older builds keep the hash-derived key expansion close to the
            // first-eight-byte application loop.
            let old_shape = contains_u32(window, 0x5555_5555)
                && contains_u32(window, 0xaaaa_aaaa)
                && has_imm_shift(window, true, 13)
                && has_imm_shift(window, false, 17)
                && has_imm_shift(window, true, 5)
                && has_cmp_imm8(window, 8)
                && count_x86_xor(window) >= 4;

            // Object-based Riddle-era modules precompute the eight prefix-key
            // bytes in the filter object.  The apply method then checks for
            // overlap with logical offsets 0..8 and XORs bytes from
            // object+0x10+offset before entering the shared content core.
            // Recognize that data-flow shape rather than requiring the key
            // expansion and apply loop to be in one 256-byte window.
            let object_apply_shape = has_cmp_imm8(window, 8)
                && has_lea_indexed_disp8(window, 0x10)
                && count_x86_byte_xor(window) >= 1;
            if old_shape || object_apply_shape {
                return pe.file_offset_to_rva(base as u32);
            }
        }
    }
    None
}

fn has_lea_indexed_disp8(bytes: &[u8], displacement: u8) -> bool {
    bytes.windows(4).any(|instruction| {
        // LEA r32, [base + index*scale + disp8]
        instruction[0] == 0x8d
            && instruction[1] & 0xc7 == 0x44
            && instruction[3] == displacement
    })
}

fn count_x86_byte_xor(bytes: &[u8]) -> usize {
    bytes
        .windows(2)
        .filter(|instruction| matches!(instruction[0], 0x30 | 0x32))
        .count()
}

fn has_cmp_imm8(bytes: &[u8], value: u8) -> bool {
    bytes.windows(3).any(|instruction| {
        instruction[0] == 0x83
            && instruction[1] & 0xc0 == 0xc0
            && (instruction[1] >> 3) & 7 == 7
            && instruction[2] == value
    })
}

fn has_imm_shift(bytes: &[u8], left: bool, count: u8) -> bool {
    let group = if left { 4u8 } else { 5u8 };
    bytes.windows(3).any(|instruction| {
        instruction[0] == 0xc1
            && instruction[1] & 0xc0 == 0xc0
            && (instruction[1] >> 3) & 7 == group
            && instruction[2] == count
    })
}

fn count_x86_xor(bytes: &[u8]) -> usize {
    bytes
        .windows(2)
        .filter(|instruction| {
            matches!(instruction[0], 0x31 | 0x33) && instruction[1] & 0xc0 == 0xc0
        })
        .count()
}

fn has_x86_not(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|instruction| {
        instruction[0] == 0xf7 && instruction[1] & 0xc0 == 0xc0 && (instruction[1] >> 3) & 7 == 2
    })
}

#[derive(Clone, Debug)]
struct CallbackConfig {
    rva: u32,
    key0: u32,
    key1: u32,
    builder_rva: u32,
    builder_in_decc: bool,
    xrefs: usize,
    score: u32,
}

/// Historical source layout (32-bit, naturally aligned):
///
/// ```text
/// const char *name;
/// uint32_t key[2];
/// xcode_builder_t builder;
/// ```
///
/// Keys are title parameters, not family constants.  We find the structure by
/// requiring the builder pointer to land in an executable section and the
/// structure VA to be referenced by executable code.  The reference source's
/// 0x161/0x5c9 pair is only a tie-breaker.
fn find_callback_config(bytes: &[u8], pe: &PeImage) -> Option<CallbackConfig> {
    let mut best: Option<CallbackConfig> = None;
    for section in &pe.sections {
        if section.raw_size < 16 || section.raw_offset as usize >= bytes.len() {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(bytes.len());
        let mut off = start;
        while off + 16 <= end {
            let name_va = read_u32_opt(bytes, off)?;
            let key0 = read_u32_opt(bytes, off + 4)?;
            let key1 = read_u32_opt(bytes, off + 8)?;
            let builder_va = read_u32_opt(bytes, off + 12)?;
            let Some(builder_rva) = builder_va.checked_sub(pe.image_base) else {
                off += 4;
                continue;
            };
            if !pe.is_executable_rva(builder_rva) {
                off += 4;
                continue;
            }
            // Boundary = (hash & key0) + key1.  The early family uses small
            // masks/offsets; reject obvious pointers/garbage without assuming
            // one exact game's values.
            if key0 == 0 || key1 == 0 || key0 > 0x00ff_ffff || key1 > 0x00ff_ffff {
                off += 4;
                continue;
            }
            let Some(rva) = pe.file_offset_to_rva(off as u32) else {
                off += 4;
                continue;
            };
            let struct_va = pe.image_base.wrapping_add(rva);
            let xrefs = count_u32_in_executable(bytes, pe, struct_va);
            let builder_in_decc = pe
                .section_for_rva(builder_rva)
                .map(|section| section.name.eq_ignore_ascii_case(".decc"))
                .unwrap_or(false);
            if xrefs == 0 && !builder_in_decc {
                off += 4;
                continue;
            }
            let name_score = if name_va == 0 {
                1
            } else if pe
                .va_to_file_offset(name_va)
                .and_then(|name_off| bounded_c_string(bytes, name_off as usize, 96))
                .is_some()
            {
                3
            } else {
                off += 4;
                continue;
            };
            let mut score = 20 + (xrefs.min(8) as u32 * 4) + name_score;
            if builder_in_decc {
                score += 12;
            }
            if key0 == REFERENCE_KEY0 && key1 == REFERENCE_KEY1 {
                score += 8;
            }
            let candidate = CallbackConfig {
                rva,
                key0,
                key1,
                builder_rva,
                builder_in_decc,
                xrefs,
                score,
            };
            if best
                .as_ref()
                .map_or(true, |current| candidate.score > current.score)
            {
                best = Some(candidate);
            }
            off += 4;
        }
    }
    best
}

#[derive(Clone, Debug)]
struct PeSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

#[derive(Clone, Debug)]
struct PeImage {
    machine: u16,
    image_base: u32,
    size_of_headers: u32,
    sections: Vec<PeSection>,
}

impl PeImage {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 0x100 || &bytes[..2] != b"MZ" {
            return Err(Error::format("not a PE image"));
        }
        let pe_off = read_u32(bytes, 0x3c)? as usize;
        if pe_off.checked_add(24).is_none()
            || pe_off + 24 > bytes.len()
            || &bytes[pe_off..pe_off + 4] != b"PE\0\0"
        {
            return Err(Error::format("invalid PE header"));
        }
        let coff = pe_off + 4;
        let machine = read_u16(bytes, coff)?;
        let section_count = read_u16(bytes, coff + 2)? as usize;
        let optional_size = read_u16(bytes, coff + 16)? as usize;
        let opt = coff + 20;
        if opt.checked_add(optional_size).is_none()
            || opt + optional_size > bytes.len()
            || optional_size < 64
        {
            return Err(Error::format("truncated PE optional header"));
        }
        if read_u16(bytes, opt)? != 0x10b {
            return Err(Error::unsupported("legacy CXDEC recognizer requires PE32"));
        }
        let image_base = read_u32(bytes, opt + 28)?;
        let size_of_headers = read_u32(bytes, opt + 60)?;
        let section_table = opt + optional_size;
        if section_table
            .checked_add(section_count.saturating_mul(40))
            .is_none()
            || section_table + section_count * 40 > bytes.len()
        {
            return Err(Error::format("truncated PE section table"));
        }
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let p = section_table + i * 40;
            let raw_name = &bytes[p..p + 8];
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..end]).to_string();
            sections.push(PeSection {
                name,
                virtual_size: read_u32(bytes, p + 8)?,
                virtual_address: read_u32(bytes, p + 12)?,
                raw_size: read_u32(bytes, p + 16)?,
                raw_offset: read_u32(bytes, p + 20)?,
                characteristics: read_u32(bytes, p + 36)?,
            });
        }
        Ok(Self {
            machine,
            image_base,
            size_of_headers,
            sections,
        })
    }

    fn file_offset_to_rva(&self, file_offset: u32) -> Option<u32> {
        if file_offset < self.size_of_headers {
            return Some(file_offset);
        }
        self.sections.iter().find_map(|s| {
            let end = s.raw_offset.checked_add(s.raw_size)?;
            (file_offset >= s.raw_offset && file_offset < end)
                .then(|| s.virtual_address + (file_offset - s.raw_offset))
        })
    }

    fn rva_to_file_offset(&self, rva: u32) -> Option<u32> {
        if rva < self.size_of_headers {
            return Some(rva);
        }
        self.sections.iter().find_map(|s| {
            let span = s.virtual_size.max(s.raw_size);
            let end = s.virtual_address.checked_add(span)?;
            if rva < s.virtual_address || rva >= end {
                return None;
            }
            let delta = rva - s.virtual_address;
            (delta < s.raw_size).then(|| s.raw_offset + delta)
        })
    }

    fn va_to_file_offset(&self, va: u32) -> Option<u32> {
        let rva = va.checked_sub(self.image_base)?;
        self.rva_to_file_offset(rva)
    }

    fn is_executable_rva(&self, rva: u32) -> bool {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        self.sections.iter().any(|section| {
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                return false;
            }
            let span = section.virtual_size.max(section.raw_size);
            rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span)
        })
    }

    fn section_for_rva(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|section| {
            let span = section.virtual_size.max(section.raw_size);
            rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span)
        })
    }

    fn slice_rva<'a>(&self, bytes: &'a [u8], rva: u32, len: usize) -> Result<&'a [u8]> {
        if rva < self.size_of_headers {
            let off = rva as usize;
            let end = off
                .checked_add(len)
                .ok_or_else(|| Error::format("PE slice overflow"))?;
            if end > self.size_of_headers as usize || end > bytes.len() {
                return Err(Error::format("truncated PE header RVA slice"));
            }
            return Ok(&bytes[off..end]);
        }
        let section = self
            .sections
            .iter()
            .find(|section| {
                let span = section.virtual_size.max(section.raw_size);
                rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span)
            })
            .ok_or_else(|| Error::format(format!("RVA 0x{rva:x} is outside PE sections")))?;
        let delta = rva - section.virtual_address;
        let len_u32 =
            u32::try_from(len).map_err(|_| Error::format("PE slice length does not fit u32"))?;
        if delta
            .checked_add(len_u32)
            .map_or(true, |end| end > section.raw_size)
        {
            return Err(Error::format(format!(
                "RVA slice 0x{rva:x}+0x{len:x} is not fully file-backed in section {}",
                section.name
            )));
        }
        let off = section
            .raw_offset
            .checked_add(delta)
            .ok_or_else(|| Error::format("PE section file offset overflow"))?
            as usize;
        let end = off
            .checked_add(len)
            .ok_or_else(|| Error::format("PE slice overflow"))?;
        if end > bytes.len() {
            return Err(Error::format("truncated PE RVA slice"));
        }
        Ok(&bytes[off..end])
    }
}

fn count_u32_in_executable(bytes: &[u8], pe: &PeImage, value: u32) -> usize {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    let needle = value.to_le_bytes();
    pe.sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .map(|section| {
            let start = section.raw_offset as usize;
            let end = start
                .saturating_add(section.raw_size as usize)
                .min(bytes.len());
            if start >= end {
                0
            } else {
                count_bytes(&bytes[start..end], &needle)
            }
        })
        .sum()
}

fn bounded_c_string(bytes: &[u8], off: usize, max_len: usize) -> Option<&str> {
    let tail = bytes.get(off..off.saturating_add(max_len).min(bytes.len()))?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    let raw = &tail[..end];
    if raw
        .iter()
        .any(|&byte| !(byte == b'\t' || (0x20..=0x7e).contains(&byte)))
    {
        return None;
    }
    std::str::from_utf8(raw).ok()
}

fn read_u32_opt(bytes: &[u8], off: usize) -> Option<u32> {
    let raw = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

fn read_u16(bytes: &[u8], off: usize) -> Result<u16> {
    let end = off
        .checked_add(2)
        .ok_or_else(|| Error::format("PE read overflow"))?;
    let s = bytes
        .get(off..end)
        .ok_or_else(|| Error::format("truncated PE field"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| Error::format("PE read overflow"))?;
    let s = bytes
        .get(off..end)
        .ok_or_else(|| Error::format("truncated PE field"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes(haystack, needle).is_some()
}
fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}
fn contains_u16(bytes: &[u8], value: u16) -> bool {
    contains_bytes(bytes, &value.to_le_bytes())
}
fn contains_u32(bytes: &[u8], value: u32) -> bool {
    contains_bytes(bytes, &value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_block_signature_matches_garbro_and_requires_dword_alignment() {
        let mut bytes = vec![0u8; CONTROL_BLOCK_SIZE + 64];
        let aligned = 8usize;
        bytes[aligned..aligned + CONTROL_BLOCK_SIGNATURE.len()]
            .copy_from_slice(CONTROL_BLOCK_SIGNATURE);
        assert_eq!(find_control_block_file_offset(&bytes), Some(aligned));

        let mut unaligned = vec![0u8; CONTROL_BLOCK_SIZE + 64];
        let off = 3usize;
        unaligned[off..off + CONTROL_BLOCK_SIGNATURE.len()]
            .copy_from_slice(CONTROL_BLOCK_SIGNATURE);
        assert_eq!(find_control_block_file_offset(&unaligned), None);
    }

    #[test]
    fn control_block_signature_does_not_require_legacy_dash_suffix() {
        let mut bytes = vec![0u8; CONTROL_BLOCK_SIZE + 64];
        bytes[..CONTROL_BLOCK_SIGNATURE.len()].copy_from_slice(CONTROL_BLOCK_SIGNATURE);
        // The byte immediately after the exact GARbro marker is arbitrary
        // control-table data, not a required ASCII `" -- "` suffix.
        bytes[CONTROL_BLOCK_SIGNATURE.len()] = 0xa5;
        assert_eq!(find_control_block_file_offset(&bytes), Some(0));
    }

    #[test]
    fn xcode_rng_matches_historical_formula() {
        let mut rng = XcodeRng::new(0);
        assert_eq!(rng.next_u32(), 0x0000_3039);
        let old = 0x0000_3039u32;
        let new = XCODE_LCG_MUL.wrapping_mul(old).wrapping_add(XCODE_LCG_ADD);
        assert_eq!(
            rng.next_u32(),
            new ^ old.wrapping_shl(16) ^ old.wrapping_shr(16)
        );
    }

    fn emit_test_prolog(code: &mut Vec<u8>, rng: &mut XcodeRng, order: [u8; 3]) {
        match order[(rng.next_u32() % 3) as usize] {
            0 => {
                code.push(0xb8);
                code.extend_from_slice(&rng.next_u32().to_le_bytes());
            }
            1 => code.extend_from_slice(&[0x8b, 0xc7]),
            2 => {
                code.push(0xbe);
                code.extend_from_slice(&0x1234_5000u32.to_le_bytes());
                code.extend_from_slice(&[0x8b, 0x86]);
                code.extend_from_slice(&((rng.next_u32() & 0x3ff) * 4).to_le_bytes());
            }
            _ => unreachable!(),
        }
    }

    fn emit_test_binary(code: &mut Vec<u8>, semantic: u8) {
        match semantic {
            0 => code.extend_from_slice(&[0x51, 0x89, 0xd9, 0x83, 0xe1, 0x0f, 0xd3, 0xe8, 0x59]),
            1 => code.extend_from_slice(&[0x51, 0x89, 0xd9, 0x83, 0xe1, 0x0f, 0xd3, 0xe0, 0x59]),
            2 => code.extend_from_slice(&[0x01, 0xd8]),
            3 => code.extend_from_slice(&[0x29, 0xc3, 0x89, 0xd8]),
            4 => code.extend_from_slice(&[0x0f, 0xaf, 0xc3]),
            5 => code.extend_from_slice(&[0x29, 0xd8]),
            _ => unreachable!(),
        }
    }

    fn emit_test_unary(code: &mut Vec<u8>, rng: &mut XcodeRng, semantic: u8) {
        match semantic {
            0 => code.extend_from_slice(&[0xf7, 0xd0]),
            1 => code.push(0x48),
            2 => code.extend_from_slice(&[0xf7, 0xd8]),
            3 => code.push(0x40),
            4 => code.extend_from_slice(&[
                0xbe, 0x00, 0x50, 0x34, 0x12, 0x25, 0xff, 0x03, 0x00, 0x00, 0x8b, 0x04, 0x86,
            ]),
            5 => code.extend_from_slice(&[
                0x53, 0x89, 0xc3, 0x81, 0xe3, 0xaa, 0xaa, 0xaa, 0xaa, 0x25, 0x55, 0x55, 0x55, 0x55,
                0xd1, 0xeb, 0xd1, 0xe0, 0x09, 0xd8, 0x5b,
            ]),
            6 => {
                code.push(0x35);
                code.extend_from_slice(&rng.next_u32().to_le_bytes());
            }
            7 => {
                code.push(if rng.next_u32() & 1 != 0 { 0x05 } else { 0x2d });
                code.extend_from_slice(&rng.next_u32().to_le_bytes());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn recovers_previously_unseen_classic_dispatch_permutation_from_builder_semantics() {
        let prolog = [2, 0, 1];
        let even = [6, 2, 7, 0, 5, 3, 1, 4];
        let odd = [5, 1, 3, 0, 4, 2];
        let mut odd_stage2 = Vec::new();
        let mut even_stage2 = Vec::new();
        for seed in 0..256u32 {
            let mut rng = XcodeRng::new(seed);
            let mut code = vec![0x53];
            let _first_branch = rng.next_u32();
            emit_test_prolog(&mut code, &mut rng, prolog);
            code.extend_from_slice(&[0x89, 0xc3]);
            let _second_branch = rng.next_u32();
            emit_test_prolog(&mut code, &mut rng, prolog);
            emit_test_binary(&mut code, odd[(rng.next_u32() % 6) as usize]);
            code.push(0x5b);
            odd_stage2.push((seed, code));

            let mut rng = XcodeRng::new(seed);
            let mut code = Vec::new();
            let _child_branch = rng.next_u32();
            emit_test_prolog(&mut code, &mut rng, prolog);
            let semantic = even[(rng.next_u32() & 7) as usize];
            emit_test_unary(&mut code, &mut rng, semantic);
            even_stage2.push((seed, code));
        }
        let capture = crate::x86_filter::CxdecDispatchCapture {
            odd_stage2,
            even_stage2_candidates: vec![
                (0x401000, vec![(0, vec![0xcc])]),
                (0x402000, even_stage2),
            ],
        };
        let recovered = recover_classic_dispatch_orders(&capture).unwrap();
        assert_eq!(recovered.prolog, prolog);
        assert_eq!(recovered.even, even);
        assert_eq!(recovered.odd, odd);
        assert_eq!(recovered.stage0_va, 0x402000);
    }

    #[test]
    fn static_dispatch_classifier_recovers_all_3_8_6_semantics() {
        fn pushed(values: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            for &value in values {
                out.extend_from_slice(&[0x6a, value]);
            }
            out.push(0xc3);
            out
        }

        assert_eq!(classify_dispatch_block(&pushed(&[0xb8]), DispatchKind::Prolog), Some(0));
        assert_eq!(classify_dispatch_block(&pushed(&[0x8b, 0xc7]), DispatchKind::Prolog), Some(1));
        let mut table = pushed(&[0xbe, 0x86]);
        table.splice(table.len() - 1..table.len() - 1, [0x68, 0xff, 0x03, 0x00, 0x00]);
        assert_eq!(classify_dispatch_block(&table, DispatchKind::Prolog), Some(2));

        let even = [
            (pushed(&[0xf7, 0xd0]), 0u8),
            (pushed(&[0x48]), 1),
            (pushed(&[0xf7, 0xd8]), 2),
            (pushed(&[0x40]), 3),
            ({
                let mut value = pushed(&[0xbe, 0x86]);
                value.splice(value.len() - 1..value.len() - 1, [0x68, 0xff, 0x03, 0x00, 0x00]);
                value
            }, 4),
            ({
                let mut value = Vec::new();
                value.extend_from_slice(&[0x68, 0xaa, 0xaa, 0xaa, 0xaa]);
                value.extend_from_slice(&[0x68, 0x55, 0x55, 0x55, 0x55, 0xc3]);
                value
            }, 5),
            (pushed(&[0x35]), 6),
            (pushed(&[0x05]), 7),
        ];
        for (bytes, semantic) in even {
            assert_eq!(classify_dispatch_block(&bytes, DispatchKind::Even), Some(semantic));
        }

        let odd = [
            (pushed(&[0xd3, 0xe8]), 0u8),
            (pushed(&[0xd3, 0xe0]), 1),
            (pushed(&[0x01, 0xd8]), 2),
            (pushed(&[0xf7, 0xd8, 0x01]), 3),
            (pushed(&[0x0f, 0xaf, 0xc3]), 4),
            (pushed(&[0x29, 0xd8]), 5),
        ];
        for (bytes, semantic) in odd {
            assert_eq!(classify_dispatch_block(&bytes, DispatchKind::Odd), Some(semantic));
        }
    }

    #[test]
    fn cabbage_seed_scanner_recovers_static_state_initialization() {
        let seed = 0x92d6_8ca2u32;
        let state = 0x0050_1000u32;
        let mut code = Vec::new();
        for (left, count) in [
            (true, 17u8),
            (true, 18),
            (false, 15),
            (true, 13),
            (false, 17),
            (true, 5),
        ] {
            code.extend_from_slice(&[0xc1, if left { 0xe0 } else { 0xe8 }, count]);
            code.extend_from_slice(&[0x33, 0xc1]);
        }
        code.extend_from_slice(&[0xf7, 0xd0]);
        code.extend_from_slice(&[0xa1]);
        code.extend_from_slice(&state.to_le_bytes());
        code.extend_from_slice(&[0xc7, 0x05]);
        code.extend_from_slice(&state.to_le_bytes());
        code.extend_from_slice(&seed.to_le_bytes());
        code.resize(1024, 0x90);
        let pe = PeImage {
            machine: 0x14c,
            image_base: 0x400000,
            size_of_headers: 0,
            sections: vec![PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: code.len() as u32,
                raw_offset: 0,
                raw_size: code.len() as u32,
                characteristics: 0x6000_0020,
            }],
        };
        let prng = find_cabbage_prng_window(&code, &pe).unwrap();
        let seeds = find_static_cabbage_seed_candidates(&code, &pe, prng, None);
        assert!(seeds.contains(&seed));
    }

    #[test]
    fn cabbage_prng_recognizer_requires_both_exact_state_transitions() {
        let mut code = Vec::new();
        for (left, count) in [
            (true, 17u8),
            (true, 18),
            (false, 15),
            (true, 13),
            (false, 17),
            (true, 5),
        ] {
            code.extend_from_slice(&[0xc1, if left { 0xe0 } else { 0xe8 }, count]);
            code.extend_from_slice(&[0x33, 0xc1]);
        }
        code.extend_from_slice(&[0xf7, 0xd0]);
        code.resize(600, 0x90);
        let pe = PeImage {
            machine: 0x14c,
            image_base: 0x400000,
            size_of_headers: 0,
            sections: vec![PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: code.len() as u32,
                raw_offset: 0,
                raw_size: code.len() as u32,
                characteristics: 0x6000_0020,
            }],
        };
        assert_eq!(find_cabbage_prng_window(&code, &pe), Some(0x1000));
        code[2] = 16;
        assert_eq!(find_cabbage_prng_window(&code, &pe), None);
    }

    #[test]
    fn riddle_recognizer_requires_prefix_constants_shifts_and_eight_byte_bound() {
        let mut code = Vec::new();
        code.extend_from_slice(&0x5555_5555u32.to_le_bytes());
        code.extend_from_slice(&0xaaaa_aaaau32.to_le_bytes());
        for (left, count) in [(true, 13u8), (false, 17), (true, 5)] {
            code.extend_from_slice(&[0xc1, if left { 0xe0 } else { 0xe8 }, count]);
            code.extend_from_slice(&[0x33, 0xc1, 0x33, 0xd0]);
        }
        code.extend_from_slice(&[0x83, 0xf8, 8]);
        code.resize(320, 0x90);
        let pe = PeImage {
            machine: 0x14c,
            image_base: 0x400000,
            size_of_headers: 0,
            sections: vec![PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: code.len() as u32,
                raw_offset: 0,
                raw_size: code.len() as u32,
                characteristics: 0x6000_0020,
            }],
        };
        assert_eq!(find_riddle_prefix8_window(&code, &pe), Some(0x1000));
        let bound = code.iter().position(|value| *value == 8).unwrap();
        code[bound] = 7;
        assert_eq!(find_riddle_prefix8_window(&code, &pe), None);
    }

    #[test]
    fn riddle_recognizer_accepts_object_based_prefix8_apply_shape() {
        // Newer Riddle builds precompute the eight hash-derived bytes in the
        // filter object.  The application routine only needs an overlap check
        // against eight bytes, indexed object+0x10 addressing and a byte XOR.
        let mut code = vec![0x90; 320];
        code[24..27].copy_from_slice(&[0x83, 0xf8, 0x08]); // cmp eax,8
        code[48..52].copy_from_slice(&[0x8d, 0x44, 0x0b, 0x10]); // lea eax,[ebx+ecx+0x10]
        code[72..74].copy_from_slice(&[0x32, 0x08]); // xor cl,[eax]
        let pe = PeImage {
            machine: 0x14c,
            image_base: 0x400000,
            size_of_headers: 0,
            sections: vec![PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: code.len() as u32,
                raw_offset: 0,
                raw_size: code.len() as u32,
                characteristics: 0x6000_0020,
            }],
        };
        assert_eq!(find_riddle_prefix8_window(&code, &pe), Some(0x1000));
    }

    #[test]
    fn all_128_native_lanes_build_without_machine_code() {
        for lane in 0..128u32 {
            assert!(build_lane(lane).is_some(), "lane {lane}");
        }
    }

    #[test]
    fn native_ast_matches_reference_x86_vectors() {
        // These vectors were produced independently by emitting the historical
        // 32-bit xcode byte stream and interpreting its documented opcodes.
        // They therefore catch PRNG-consumption/budget bugs that a mere
        // encrypt-decrypt symmetry test cannot detect.
        let table = Box::new(std::array::from_fn(|i| {
            (i as u32).wrapping_mul(0x9e37_79b9)
        }));
        let lanes: Vec<_> = (0..128u32)
            .map(|i| LaneProgram::LegacyAst(build_lane(i).unwrap()))
            .collect();
        let probe = LegacyCxdecProbe {
            path: PathBuf::new(),
            profile_name: "cxdec-legacy-decc-v1",
            recognized: true,
            confidence: 100,
            image_base: 0,
            decc_rva: None,
            decc_size: None,
            control_block_rva: None,
            callback_config_rva: None,
            xcode_builder_rva: None,
            xcode_builder_in_decc: false,
            cabbage_prng_rva: None,
            riddle_prefix8_rva: None,
            random_seed: None,
            key0: Some(REFERENCE_KEY0),
            key1: Some(REFERENCE_KEY1),
            prolog_order: None,
            even_branch_order: None,
            odd_branch_order: None,
            known_marker_hits: 0,
            reasons: Vec::new(),
        };
        let filter = LegacyCxdecFilter {
            module_path: PathBuf::new(),
            table,
            lanes,
            key0: REFERENCE_KEY0,
            key1: REFERENCE_KEY1,
            outer_xor: None,
            classic: None,
            probe,
        };
        for (lane, seed, expected) in [
            (0usize, 0x0000_0000, 0x0053_0bca),
            (1, 0x0012_3456, 0x0ced_4000),
            (17, 0x89ab_cdef, 0x0001_012b),
            (63, 0x0102_0304, 0x8d13_9397),
            (127, 0xffff_ffff, 0xdf29_9869),
        ] {
            assert_eq!(
                filter.eval_lane(&filter.lanes[lane], seed),
                expected,
                "lane={lane}"
            );
        }
    }

    #[test]
    fn generated_lane_parser_recovers_table_and_microops() {
        let table_va = 0x1234_5000u32;
        let mut code = Vec::new();
        // PUSH EBX; MOV EAX,EDI; MOV EBX,EAX;
        // MOV ESI,table; MOV EAX,[ESI+4*7]; NEG EAX; ADD EAX,EBX; POP EBX.
        code.extend_from_slice(&[0x53, 0x8b, 0xc7, 0x89, 0xc3, 0xbe]);
        code.extend_from_slice(&table_va.to_le_bytes());
        code.extend_from_slice(&[0x8b, 0x86]);
        code.extend_from_slice(&(7u32 * 4).to_le_bytes());
        code.extend_from_slice(&[0xf7, 0xd8, 0x01, 0xd8, 0x5b]);
        let (ops, recovered) = parse_generated_lane(&code, None).unwrap();
        assert_eq!(recovered, Some(table_va));

        let table = Box::new(std::array::from_fn(|i| i as u32));
        let probe = LegacyCxdecProbe {
            path: PathBuf::new(),
            profile_name: "cxdec-generator-v2",
            recognized: true,
            confidence: 100,
            image_base: 0,
            decc_rva: None,
            decc_size: None,
            control_block_rva: None,
            callback_config_rva: None,
            xcode_builder_rva: None,
            xcode_builder_in_decc: false,
            cabbage_prng_rva: None,
            riddle_prefix8_rva: None,
            random_seed: None,
            key0: Some(1),
            key1: Some(1),
            prolog_order: None,
            even_branch_order: None,
            odd_branch_order: None,
            known_marker_hits: 0,
            reasons: Vec::new(),
        };
        let filter = LegacyCxdecFilter {
            module_path: PathBuf::new(),
            table,
            lanes: vec![LaneProgram::Generated(ops)],
            key0: 1,
            key1: 1,
            outer_xor: None,
            classic: None,
            probe,
        };
        // seed + (-table[7]) under wrapping arithmetic.
        assert_eq!(
            filter.eval_lane(&filter.lanes[0], 0x100),
            0x100u32.wrapping_sub(7)
        );
    }

    #[test]
    fn recovers_transition_offset_xor_period() {
        let table: Vec<u8> = (0..512usize)
            .map(|i| ((i.wrapping_mul(73) ^ (i >> 8).wrapping_mul(0xa7) ^ 0x5d) & 0xff) as u8)
            .collect();
        let samples: Vec<(u64, Vec<u8>)> = [0u64, 137, 4099]
            .into_iter()
            .map(|offset| {
                let residual = (0..8192usize)
                    .map(|i| table[((offset as usize) + i) % table.len()])
                    .collect();
                (offset, residual)
            })
            .collect();
        let recovered = recover_offset_xor_table(&samples, 4096).unwrap().unwrap();
        assert_eq!(recovered, table);
    }

    #[test]
    fn body_and_sparse_xor_are_symmetric() {
        let table = Box::new(std::array::from_fn(|i| {
            (i as u32).wrapping_mul(0x9e37_79b9)
        }));
        let lanes = (0..128u32)
            .map(|i| LaneProgram::LegacyAst(build_lane(i).unwrap()))
            .collect();
        let probe = LegacyCxdecProbe {
            path: PathBuf::new(),
            profile_name: "cxdec-legacy-decc-v1",
            recognized: true,
            confidence: 100,
            image_base: 0,
            decc_rva: None,
            decc_size: None,
            control_block_rva: None,
            callback_config_rva: None,
            xcode_builder_rva: None,
            xcode_builder_in_decc: false,
            cabbage_prng_rva: None,
            riddle_prefix8_rva: None,
            random_seed: None,
            key0: Some(REFERENCE_KEY0),
            key1: Some(REFERENCE_KEY1),
            prolog_order: None,
            even_branch_order: None,
            odd_branch_order: None,
            known_marker_hits: 0,
            reasons: Vec::new(),
        };
        let filter = LegacyCxdecFilter {
            module_path: PathBuf::new(),
            table,
            lanes,
            key0: REFERENCE_KEY0,
            key1: REFERENCE_KEY1,
            outer_xor: None,
            classic: None,
            probe,
        };
        let original: Vec<u8> = (0..=255).cycle().take(8192).collect();
        let mut data = original.clone();
        filter.apply(0, 0xc302_15d1, &mut data).unwrap();
        assert_ne!(data, original);
        filter.apply(0, 0xc302_15d1, &mut data).unwrap();
        assert_eq!(data, original);
    }
}
