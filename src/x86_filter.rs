//! Generic x86 XP3 extraction-filter discovery and emulation.
//!
//! This module deliberately does not attempt to recover a title-specific
//! algorithm.  It loads a 32-bit PE module, locates or captures the callback
//! registered through `TVPSetXP3ArchiveExtractionFilter`, and executes that
//! callback against the ordinary 24-byte Kirikiri extraction-filter info
//! structure in Unicorn.
//!
//! The authoritative path is static registration provenance: locate the exact
//! `TVPSetXP3ArchiveExtractionFilter` import-stub name, follow its local
//! resolver slot, and prove that an executable callback address is passed to
//! the resolved registration function. ABI shape is retained only as an
//! unproven discovery hint and never selects a production callback.
//!
//! Static detection itself never executes module initialization. The unpack
//! pipeline may subsequently emulate DllMain/V2Link for a proven ordinary-filter
//! candidate, but it accepts that runtime only after real XP3 entries validate
//! against original `adlr` and/or strong plaintext-format evidence.

use crate::error::{Error, Result};
use crate::win32_host::{
    decode_ansi, encode_ansi_with_default, LocaleInfoValue, Win32Api, Win32HostState,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MOD_NOT_FOUND,
    ERROR_NO_UNICODE_TRANSLATION, ERROR_PROC_NOT_FOUND,
};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use unicorn_engine::{
    unicorn_const::{Arch, Mode, Prot},
    RegisterX86, UcHookId, Unicorn,
};

const PAGE: u64 = 0x1000;
const STACK_BASE: u64 = 0x0f00_0000;
const STACK_SIZE: u64 = 0x0020_0000;
const HOST_BASE: u64 = 0x0e00_0000;
const HOST_SIZE: u64 = 0x0010_0000;
const RETURN_SENTINEL: u64 = HOST_BASE + 0x100;
const QUERY_STUB: u64 = HOST_BASE + 0x200;
const SET_FILTER_STUB: u64 = HOST_BASE + 0x300;
const THROW_STUB: u64 = HOST_BASE + 0x400;
const GENERIC_TVP_STUB: u64 = HOST_BASE + 0x500;
const EXPORTER_OBJ: u64 = HOST_BASE + 0x1000;
const EXPORTER_VTBL: u64 = HOST_BASE + 0x1100;
const INFO_ADDR: u64 = HOST_BASE + 0x2000;
const DYN_BASE: u64 = 0x6000_0000;
const DYN_SIZE: u64 = 0x0100_0000;
const INPUT_BASE: u64 = 0x5000_0000;
const INPUT_RESERVE: u64 = 0x0080_0000;
const API_STUB_BASE: u64 = HOST_BASE + 0x10000;
const CXDEC_STATUS_ADDR: u64 = HOST_BASE + 0x40000;
const CXDEC_CODE_ADDR: u64 = HOST_BASE + 0x41000;
const CXDEC_CODE_BUDGET: usize = 128;
const CXDEC_PROLOGUE_BYTES: u32 = 9;
const CXDEC_EPILOGUE_BYTES: u32 = 6;
const MAX_STEPS: usize = 20_000_000;
const TIMEOUT_US: u64 = 5_000_000;
// Archive callbacks are linear in the entry size. A wall-clock timeout makes
// otherwise deterministic emulation fail under parallel CPU contention, and
// Unicorn reports timeout/count exhaustion as a normal stop. Bound callbacks
// by instructions and verify that they actually reached RETURN_SENTINEL.
const CALLBACK_MAX_STEPS: usize = 512_000_000;
// Once a callback has passed archive-level validation, using Unicorn's
// instruction-count limit is counterproductive: a non-zero `count` makes
// Unicorn install an internal per-instruction code hook. Keep a generous
// wall-clock watchdog in validated production mode instead, while relying on
// RETURN_SENTINEL for the normal callback return path.
const CALLBACK_VALIDATED_TIMEOUT_US: u64 = 120_000_000;
// Production diagnostics use a basic-block hook only on the final validated
// runtime. Sampling every few thousand blocks keeps the observer cheap and,
// unlike stop/resume instruction slicing, does not perturb callback execution.
const CALLBACK_DIAG_HEARTBEAT_SECS: u64 = 2;
const CALLBACK_DIAG_SAMPLE_BLOCKS: u64 = 4096;
const CALLBACK_DIAG_SLOW_CALL_MS: u128 = 500;


#[derive(Clone, Debug)]
pub struct FilterCandidate {
    pub callback_va: u32,
    /// Ranking is diagnostic-only. It must never turn an ABI-shaped address
    /// into a confirmed extraction-filter callback.
    pub score: u32,
    pub source: String,
    pub abi_score: u32,
    pub reasons: Vec<String>,
    /// Present only when static dataflow proves that `callback_va` is passed
    /// to the function resolved from the exact
    /// `TVPSetXP3ArchiveExtractionFilter` import-stub name.
    pub registration: Option<StaticRegistrationProvenance>,
}

#[derive(Clone, Debug)]
pub struct StaticRegistrationProvenance {
    pub v2link_va: u32,
    /// When the generated TVPSetXP3ArchiveExtractionFilter wrapper is not
    /// inlined into V2Link, this is the statically reached wrapper entry.
    pub wrapper_va: Option<u32>,
    /// Direct V2Link callsite for `wrapper_va`. None for the inlined form.
    pub wrapper_call_va: Option<u32>,
    pub api_name_va: u32,
    pub api_name_xref_va: u32,
    pub resolver_call_va: u32,
    pub function_slot_va: Option<u32>,
    /// Callsite-side instruction that materializes the executable callback
    /// argument. For the inlined form this is inside V2Link; for the wrapper
    /// form it is immediately before the direct V2Link -> wrapper call.
    pub callback_push_va: u32,
    pub registration_call_va: u32,
}

#[derive(Clone, Debug)]
pub struct ModuleProbe {
    pub path: PathBuf,
    pub image_base: u32,
    pub machine: u16,
    pub v2link_va: Option<u32>,
    pub candidates: Vec<FilterCandidate>,
    pub captured_callback: Option<u32>,
    pub requested_exports: Vec<String>,
    pub initialization_notes: Vec<String>,
    pub dynamic_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilterProbeOptions {
    pub dynamic_v2link: bool,
    pub trace_code: bool,
}

#[derive(Clone, Debug)]
pub struct InitializedMemoryRegion {
    pub address: u32,
    pub bytes: Vec<u8>,
}

/// Deterministic result of the loader, DLL attach, V2Link registration, and
/// one-time plugin initialization sequence.  Normal archive extraction never
/// executes code from these buffers; native recognizers consume this snapshot
/// and generic fallback retains the live emulator separately.
#[derive(Clone, Debug)]
pub struct FilterInitialization {
    pub path: PathBuf,
    pub image_base: u32,
    pub callback_va: u32,
    pub initialized_image: Vec<u8>,
    pub initialized_file: Vec<u8>,
    pub allocated_regions: Vec<InitializedMemoryRegion>,
    pub requested_exports: Vec<String>,
    pub notes: Vec<String>,
}

/// Snapshot of a PE module after one initialization stage.  This is narrower
/// than [`FilterInitialization`]: no extraction-filter callback is required.
/// It exists so native recognizers can inspect self-decoded/self-modified code
/// without treating the original x86 callback as the production decryptor.
#[derive(Clone, Debug)]
pub(crate) struct X86ModuleInitializationSnapshot {
    pub stage: &'static str,
    pub initialized_file: Vec<u8>,
    pub changed_executable_bytes: usize,
}

impl Default for FilterProbeOptions {
    fn default() -> Self {
        Self {
            // Static-only by default. Module initialization is never executed
            // merely to decide which callback/address should be trusted.
            dynamic_v2link: false,
            trace_code: false,
        }
    }
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

impl PeSection {
    fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    fn writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    fn contains_rva(&self, rva: u32) -> bool {
        let span = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && rva < self.virtual_address.saturating_add(span)
    }
}

#[derive(Clone, Debug)]
struct PeImport {
    name: String,
    iat_rva: u32,
}

#[derive(Clone, Debug)]
struct Pe32 {
    bytes: Vec<u8>,
    machine: u16,
    image_base: u32,
    entry_point_rva: u32,
    size_of_image: u32,
    size_of_headers: u32,
    sections: Vec<PeSection>,
    exports: BTreeMap<String, u32>,
    imports: Vec<PeImport>,
}

impl Pe32 {
    fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 0x100 || &bytes[0..2] != b"MZ" {
            return Err(Error::format("not a PE image (missing MZ)"));
        }
        let pe_off = read_u32_slice(&bytes, 0x3c)? as usize;
        if pe_off.checked_add(24).is_none()
            || pe_off + 24 > bytes.len()
            || &bytes[pe_off..pe_off + 4] != b"PE\0\0"
        {
            return Err(Error::format("invalid PE header"));
        }
        let coff = pe_off + 4;
        let machine = read_u16_slice(&bytes, coff)?;
        if machine != 0x014c {
            return Err(Error::unsupported(format!(
                "x86 filter emulation requires PE32/i386, machine=0x{machine:04x}"
            )));
        }
        let section_count = read_u16_slice(&bytes, coff + 2)? as usize;
        let optional_size = read_u16_slice(&bytes, coff + 16)? as usize;
        let opt = coff + 20;
        if opt.checked_add(optional_size).is_none()
            || opt + optional_size > bytes.len()
            || optional_size < 0x60
        {
            return Err(Error::format("truncated PE optional header"));
        }
        if read_u16_slice(&bytes, opt)? != 0x010b {
            return Err(Error::unsupported(
                "PE32+ is not supported by the x86 filter emulator",
            ));
        }
        let image_base = read_u32_slice(&bytes, opt + 28)?;
        let entry_point_rva = read_u32_slice(&bytes, opt + 16)?;
        let size_of_image = read_u32_slice(&bytes, opt + 56)?;
        let size_of_headers = read_u32_slice(&bytes, opt + 60)?;
        if size_of_image == 0 || size_of_image as u64 > 0x4000_0000 {
            return Err(Error::format(format!(
                "unreasonable PE image size 0x{size_of_image:x}"
            )));
        }

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
            let end = raw_name
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(raw_name.len());
            let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
            sections.push(PeSection {
                name,
                virtual_size: read_u32_slice(&bytes, p + 8)?,
                virtual_address: read_u32_slice(&bytes, p + 12)?,
                raw_size: read_u32_slice(&bytes, p + 16)?,
                raw_offset: read_u32_slice(&bytes, p + 20)?,
                characteristics: read_u32_slice(&bytes, p + 36)?,
            });
        }

        let mut pe = Self {
            bytes,
            machine,
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            sections,
            exports: BTreeMap::new(),
            imports: Vec::new(),
        };

        let num_dirs = if optional_size >= 96 {
            read_u32_slice(&pe.bytes, opt + 92).unwrap_or(0)
        } else {
            0
        };
        if num_dirs > 0 && optional_size >= 104 {
            let export_rva = read_u32_slice(&pe.bytes, opt + 96).unwrap_or(0);
            if export_rva != 0 {
                pe.exports = pe.parse_exports(export_rva)?;
            }
        }
        if num_dirs > 1 && optional_size >= 112 {
            let import_rva = read_u32_slice(&pe.bytes, opt + 104).unwrap_or(0);
            if import_rva != 0 {
                pe.imports = pe.parse_imports(import_rva)?;
            }
        }
        Ok(pe)
    }

    fn from_path(path: &Path) -> Result<Self> {
        let normalized = crate::pe_normalize::normalize_pe_file(path)?;
        Self::parse(normalized.bytes)
    }

    fn offset_to_rva(&self, offset: usize) -> Option<u32> {
        if offset < self.size_of_headers as usize {
            return Some(offset as u32);
        }
        self.sections.iter().find_map(|section| {
            let start = section.raw_offset as usize;
            let end = start.saturating_add(section.raw_size as usize);
            (offset >= start && offset < end).then(|| {
                section
                    .virtual_address
                    .saturating_add((offset - start) as u32)
            })
        })
    }

    fn offset_to_va(&self, offset: usize) -> Option<u32> {
        self.offset_to_rva(offset)
            .map(|rva| self.image_base.wrapping_add(rva))
    }

    fn is_writable_va(&self, va: u32) -> bool {
        let Some(rva) = va.checked_sub(self.image_base) else {
            return false;
        };
        self.sections
            .iter()
            .any(|s| s.writable() && s.contains_rva(rva))
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            let off = rva as usize;
            return (off < self.bytes.len()).then_some(off);
        }
        for section in &self.sections {
            if !section.contains_rva(rva) {
                continue;
            }
            let delta = rva.checked_sub(section.virtual_address)?;
            if delta >= section.raw_size {
                return None;
            }
            let off = section.raw_offset.checked_add(delta)? as usize;
            if off < self.bytes.len() {
                return Some(off);
            }
        }
        None
    }

    fn read_rva_u32(&self, rva: u32) -> Option<u32> {
        self.rva_to_offset(rva)
            .and_then(|o| read_u32_slice(&self.bytes, o).ok())
    }

    fn read_rva_u16(&self, rva: u32) -> Option<u16> {
        self.rva_to_offset(rva)
            .and_then(|o| read_u16_slice(&self.bytes, o).ok())
    }

    fn read_rva_c_string(&self, rva: u32, max: usize) -> Option<String> {
        let off = self.rva_to_offset(rva)?;
        let end = self.bytes[off..].iter().take(max).position(|b| *b == 0)?;
        Some(String::from_utf8_lossy(&self.bytes[off..off + end]).into_owned())
    }

    fn parse_exports(&self, export_rva: u32) -> Result<BTreeMap<String, u32>> {
        let off = self
            .rva_to_offset(export_rva)
            .ok_or_else(|| Error::format("export directory RVA is outside PE"))?;
        if off + 40 > self.bytes.len() {
            return Err(Error::format("truncated PE export directory"));
        }
        let number_of_functions = read_u32_slice(&self.bytes, off + 20)?;
        let number_of_names = read_u32_slice(&self.bytes, off + 24)?;
        let functions_rva = read_u32_slice(&self.bytes, off + 28)?;
        let names_rva = read_u32_slice(&self.bytes, off + 32)?;
        let ordinals_rva = read_u32_slice(&self.bytes, off + 36)?;
        let count = number_of_names.min(1_000_000);
        let mut out = BTreeMap::new();
        for i in 0..count {
            let Some(name_rva) = self.read_rva_u32(names_rva.saturating_add(i * 4)) else {
                break;
            };
            let Some(ord) = self.read_rva_u16(ordinals_rva.saturating_add(i * 2)) else {
                break;
            };
            if ord as u32 >= number_of_functions {
                continue;
            }
            let Some(func_rva) = self.read_rva_u32(functions_rva.saturating_add(ord as u32 * 4))
            else {
                continue;
            };
            let Some(name) = self.read_rva_c_string(name_rva, 1024) else {
                continue;
            };
            out.insert(name, func_rva);
        }
        Ok(out)
    }

    fn parse_imports(&self, import_rva: u32) -> Result<Vec<PeImport>> {
        let mut out = Vec::new();
        for descriptor_index in 0..4096u32 {
            let desc_rva = import_rva.saturating_add(descriptor_index * 20);
            let Some(desc_off) = self.rva_to_offset(desc_rva) else {
                break;
            };
            if desc_off + 20 > self.bytes.len() {
                break;
            }
            let original_first_thunk = read_u32_slice(&self.bytes, desc_off)?;
            let name_rva = read_u32_slice(&self.bytes, desc_off + 12)?;
            let first_thunk = read_u32_slice(&self.bytes, desc_off + 16)?;
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let names_thunk = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            for thunk_index in 0..65536u32 {
                let Some(thunk) = self.read_rva_u32(names_thunk.saturating_add(thunk_index * 4))
                else {
                    break;
                };
                if thunk == 0 {
                    break;
                }
                let name = if thunk & 0x8000_0000 != 0 {
                    format!("#{}", thunk & 0xffff)
                } else {
                    self.read_rva_c_string(thunk.saturating_add(2), 512)
                        .unwrap_or_else(|| "?".to_string())
                };
                out.push(PeImport {
                    name,
                    iat_rva: first_thunk.saturating_add(thunk_index * 4),
                });
            }
        }
        Ok(out)
    }

    fn export_rva(&self, wanted: &str) -> Option<u32> {
        self.exports.get(wanted).copied().or_else(|| {
            self.exports.iter().find_map(|(name, rva)| {
                let undecorated = name.trim_start_matches('_');
                let undecorated = undecorated.split('@').next().unwrap_or(undecorated);
                undecorated.eq_ignore_ascii_case(wanted).then_some(*rva)
            })
        })
    }

    fn virtual_image(&self) -> Result<Vec<u8>> {
        let mut image = vec![0u8; self.size_of_image as usize];
        let header_len = (self.size_of_headers as usize)
            .min(self.bytes.len())
            .min(image.len());
        image[..header_len].copy_from_slice(&self.bytes[..header_len]);
        for section in &self.sections {
            let src = section.raw_offset as usize;
            let raw = section.raw_size as usize;
            let dst = section.virtual_address as usize;
            if src >= self.bytes.len() || dst >= image.len() {
                continue;
            }
            let copy = raw.min(self.bytes.len() - src).min(image.len() - dst);
            image[dst..dst + copy].copy_from_slice(&self.bytes[src..src + copy]);
        }
        Ok(image)
    }

    fn materialize_file_from_virtual(&self, image: &[u8]) -> Vec<u8> {
        let mut file = self.bytes.clone();
        for section in &self.sections {
            let src = section.virtual_address as usize;
            let dst = section.raw_offset as usize;
            let len = section.raw_size as usize;
            if src >= image.len() || dst >= file.len() {
                continue;
            }
            let copy = len.min(image.len() - src).min(file.len() - dst);
            file[dst..dst + copy].copy_from_slice(&image[src..src + copy]);
        }
        file
    }

    fn is_exec_va(&self, va: u32) -> bool {
        let Some(rva) = va.checked_sub(self.image_base) else {
            return false;
        };
        self.sections
            .iter()
            .any(|s| s.executable() && s.contains_rva(rva))
    }

    fn exec_slice_at_va(&self, va: u32, max_len: usize) -> Option<&[u8]> {
        let rva = va.checked_sub(self.image_base)?;
        let section = self
            .sections
            .iter()
            .find(|s| s.executable() && s.contains_rva(rva))?;
        let off = self.rva_to_offset(rva)?;
        let section_raw_end = section.raw_offset.saturating_add(section.raw_size) as usize;
        let end = off
            .saturating_add(max_len)
            .min(section_raw_end)
            .min(self.bytes.len());
        (off < end).then_some(&self.bytes[off..end])
    }
}

fn read_u16_slice(bytes: &[u8], off: usize) -> Result<u16> {
    let s = bytes
        .get(off..off + 2)
        .ok_or_else(|| Error::format("truncated u16"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_slice(bytes: &[u8], off: usize) -> Result<u32> {
    let s = bytes
        .get(off..off + 4)
        .ok_or_else(|| Error::format("truncated u32"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u32_uc<D>(
    uc: &Unicorn<'_, D>,
    address: u64,
) -> std::result::Result<u32, unicorn_engine::uc_error> {
    let mut b = [0u8; 4];
    uc.mem_read(address, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_u32_uc<D>(
    uc: &mut Unicorn<'_, D>,
    address: u64,
    value: u32,
) -> std::result::Result<(), unicorn_engine::uc_error> {
    uc.mem_write(address, &value.to_le_bytes())
}

fn write_u64_uc<D>(
    uc: &mut Unicorn<'_, D>,
    address: u64,
    value: u64,
) -> std::result::Result<(), unicorn_engine::uc_error> {
    uc.mem_write(address, &value.to_le_bytes())
}

fn read_c_string_uc<D>(uc: &Unicorn<'_, D>, address: u64, max: usize) -> Option<String> {
    read_c_bytes_uc(uc, address, max).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn read_c_bytes_uc<D>(uc: &Unicorn<'_, D>, address: u64, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..max {
        let mut b = [0u8; 1];
        if uc.mem_read(address + i as u64, &mut b).is_err() {
            return None;
        }
        if b[0] == 0 {
            return Some(out);
        }
        out.push(b[0]);
    }
    None
}

const SET_XP3_FILTER_IMPORT_FRAGMENT: &[u8] = b"TVPSetXP3ArchiveExtractionFilter";

fn heuristic_function_prefix<'a>(pe: &'a Pe32, va: u32, max_len: usize) -> Option<&'a [u8]> {
    let code = pe.exec_slice_at_va(va, max_len)?;
    let mut end = code.len();
    let mut i = 0usize;
    while i < code.len() {
        match code[i] {
            0xc3 | 0xcb => {
                end = i + 1;
                break;
            }
            0xc2 | 0xca if i + 2 < code.len() => {
                end = i + 3;
                break;
            }
            _ => i += 1,
        }
    }
    Some(&code[..end])
}

fn mov_arg0_register(code: &[u8], at: usize) -> Option<(u8, usize)> {
    // mov r32, [esp+4]
    if at + 4 <= code.len()
        && code[at] == 0x8b
        && code[at + 1] & 0xc7 == 0x44
        && code[at + 2] == 0x24
        && code[at + 3] == 0x04
    {
        return Some(((code[at + 1] >> 3) & 7, 4));
    }
    // Canonical MSVC frame: mov r32, [ebp+8].
    if at + 3 <= code.len()
        && code[at] == 0x8b
        && code[at + 1] & 0xc7 == 0x45
        && code[at + 2] == 0x08
    {
        return Some(((code[at + 1] >> 3) & 7, 3));
    }
    None
}

fn memory_base_register(code: &[u8], modrm_at: usize) -> Option<(u8, usize)> {
    let modrm = *code.get(modrm_at)?;
    let mode = modrm >> 6;
    if mode == 3 {
        return None;
    }
    let rm = modrm & 7;
    if rm != 4 {
        // mod=00,rm=5 is absolute disp32, not [ebp].
        if mode == 0 && rm == 5 {
            return None;
        }
        return Some((rm, 1));
    }
    let sib = *code.get(modrm_at + 1)?;
    let base = sib & 7;
    if mode == 0 && base == 5 {
        return None;
    }
    Some((base, 2))
}

fn mov_reg_from_base_disp(code: &[u8], at: usize, base: u8) -> Option<(u8, i32, usize)> {
    if *code.get(at)? != 0x8b {
        return None;
    }
    let modrm = *code.get(at + 1)?;
    let mode = modrm >> 6;
    if mode == 3 {
        return None;
    }
    let dst = (modrm >> 3) & 7;
    let (actual_base, modrm_len) = memory_base_register(code, at + 1)?;
    if actual_base != base {
        return None;
    }
    let disp_at = at + 1 + modrm_len;
    match mode {
        0 => Some((dst, 0, 1 + modrm_len)),
        1 => Some((dst, *code.get(disp_at)? as i8 as i32, 2 + modrm_len)),
        2 => {
            let bytes = code.get(disp_at..disp_at + 4)?;
            Some((
                dst,
                i32::from_le_bytes(bytes.try_into().ok()?),
                5 + modrm_len,
            ))
        }
        _ => None,
    }
}

fn memory_write_uses_base(code: &[u8], at: usize, base: u8) -> bool {
    let Some(&opcode) = code.get(at) else {
        return false;
    };
    let Some(&modrm) = code.get(at + 1) else {
        return false;
    };
    if modrm >> 6 == 3 {
        return false;
    }
    let writes_memory = match opcode {
        // xor/mov r -> r/m
        0x30 | 0x31 | 0x88 | 0x89 | 0xc6 | 0xc7 => true,
        // Group-1 immediate: /6 is XOR.  Other arithmetic forms are not used
        // as positive extraction-filter evidence here because they are noisy.
        0x80 | 0x81 | 0x83 => ((modrm >> 3) & 7) == 6,
        _ => false,
    };
    if !writes_memory {
        return false;
    }
    memory_base_register(code, at + 1)
        .is_some_and(|(actual_base, _)| actual_base == base)
}

fn cmp_info_size_uses_base(code: &[u8], at: usize, base: u8) -> bool {
    if at + 3 > code.len() || code[at] != 0x83 {
        return false;
    }
    let modrm = code[at + 1];
    if ((modrm >> 3) & 7) != 7 || modrm >> 6 == 3 {
        return false;
    }
    let Some((actual_base, modrm_len)) = memory_base_register(code, at + 1) else {
        return false;
    };
    if actual_base != base {
        return false;
    }
    let mode = modrm >> 6;
    let imm_at = match mode {
        0 => at + 1 + modrm_len,
        1 => at + 2 + modrm_len,
        2 => at + 5 + modrm_len,
        _ => return false,
    };
    matches!(code.get(imm_at), Some(0x18) | Some(0x1c))
}

fn abi_score(pe: &Pe32, va: u32) -> (u32, Vec<String>) {
    // Keep the broad legacy ABI score for recall, then add a much larger
    // semantic bonus when the candidate demonstrably follows one info-pointer
    // dataflow into Buffer/BufferSize/FileHash/Offset.  This preserves obscure
    // compiler shapes as sandbox hypotheses while pushing real extraction
    // callbacks ahead of thousands of incidental C++ member accesses.
    let Some(code) = heuristic_function_prefix(pe, va, 0x280) else {
        return (0, Vec::new());
    };

    let mut score = 0u32;
    let mut reasons = Vec::new();
    if code.windows(3).any(|w| w[0] == 0x83 && w[2] == 0x18) {
        score += 12;
        reasons.push("contains 0x18-sized structure check".into());
    }
    let mut weak_fields = Vec::new();
    for disp in [0x04u8, 0x08, 0x0c, 0x10, 0x14] {
        let seen = code.windows(3).any(|w| w[0] == 0x8b && w[2] == disp)
            || code.windows(4).any(|w| w[0] == 0x8b && w[3] == disp)
            || code.windows(3).any(|w| w[0] == 0x03 && w[2] == disp)
            || code.windows(4).any(|w| w[0] == 0x03 && w[3] == disp);
        if seen {
            weak_fields.push(disp);
        }
    }
    if weak_fields.contains(&0x0c) {
        score += 8;
        reasons.push("contains possible buffer-field access +0x0c".into());
    }
    if weak_fields.contains(&0x10) {
        score += 8;
        reasons.push("contains possible size-field access +0x10".into());
    }
    if weak_fields.contains(&0x14) {
        score += 8;
        reasons.push("contains possible hash-field access +0x14".into());
    }
    if weak_fields.contains(&0x04) || weak_fields.contains(&0x08) {
        score += 5;
        reasons.push("contains possible file-offset access".into());
    }
    if code.windows(3).any(|w| w == [0xc2, 0x04, 0x00]) {
        score += 10;
        reasons.push("returns with ret 4".into());
    }
    if code
        .iter()
        .take(0x100)
        .filter(|b| **b == 0x30 || **b == 0x32)
        .count()
        >= 1
    {
        score += 3;
        reasons.push("contains byte XOR operation".into());
    }

    let weak_score = score;
    let mut arg_alias = [false; 8];
    let mut buffer_alias = [false; 8];
    let mut fields = [false; 6]; // size, off-lo, off-hi, buffer, length, hash
    let mut size_guard = false;
    let mut buffer_mutation = false;
    let mut ret4 = false;
    let mut calls_helper = false;
    let mut saw_arg0 = false;

    let mut i = 0usize;
    while i < code.len() {
        if let Some((reg, len)) = mov_arg0_register(code, i) {
            arg_alias[reg as usize] = true;
            saw_arg0 = true;
            i += len;
            continue;
        }

        if i + 2 <= code.len() && code[i] == 0x8b && code[i + 1] >> 6 == 3 {
            let modrm = code[i + 1];
            let dst = ((modrm >> 3) & 7) as usize;
            let src = (modrm & 7) as usize;
            arg_alias[dst] = arg_alias[src];
            buffer_alias[dst] = buffer_alias[src];
            i += 2;
            continue;
        }

        for base in 0u8..8 {
            if !arg_alias[base as usize] {
                continue;
            }
            if cmp_info_size_uses_base(code, i, base) {
                size_guard = true;
            }
            if let Some((dst, disp, _len)) = mov_reg_from_base_disp(code, i, base) {
                let field = match disp {
                    0x00 => Some(0),
                    0x04 => Some(1),
                    0x08 => Some(2),
                    0x0c => Some(3),
                    0x10 => Some(4),
                    0x14 => Some(5),
                    _ => None,
                };
                if let Some(field) = field {
                    fields[field] = true;
                    arg_alias[dst as usize] = false;
                    buffer_alias[dst as usize] = field == 3;
                }
            }
        }

        for base in 0u8..8 {
            if buffer_alias[base as usize] && memory_write_uses_base(code, i, base) {
                buffer_mutation = true;
            }
        }

        if matches!(
            code.get(i..i.saturating_add(3)),
            Some(bytes) if bytes == [0xc2, 0x04, 0x00]
        ) {
            ret4 = true;
        }
        if code[i] == 0xe8
            || (i + 1 < code.len() && code[i] == 0xff && code[i + 1] & 0x38 == 0x10)
        {
            calls_helper = true;
        }
        i += 1;
    }

    if saw_arg0 {
        let direct_shape = fields[3] && (fields[4] || fields[5] || fields[1] || fields[2]);
        let forwarding_shape = calls_helper && ret4;
        if direct_shape || forwarding_shape {
            score += 32;
            reasons.push("semantic: follows callback arg0 as one info object".into());
            if fields[3] {
                score += 24;
                reasons.push("semantic: reads Buffer from info +0x0c".into());
            }
            if fields[4] {
                score += 16;
                reasons.push("semantic: reads BufferSize from info +0x10".into());
            }
            if fields[5] {
                score += 16;
                reasons.push("semantic: reads FileHash from info +0x14".into());
            }
            if fields[1] || fields[2] {
                score += 10;
                reasons.push("semantic: reads Offset from info +0x04/+0x08".into());
            }
            if size_guard {
                score += 16;
                reasons.push("semantic: checks SizeOfSelf against 0x18/0x1c".into());
            }
            if buffer_mutation {
                score += 32;
                reasons.push("semantic: mutates memory reached from Buffer".into());
            }
            if forwarding_shape && !direct_shape {
                score += 12;
                reasons.push("semantic: thin stdcall wrapper forwards to helper".into());
            }
        }
    }

    if score == weak_score && weak_score == 0 {
        reasons.clear();
    }
    (score, reasons)
}

fn has_call_soon(code: &[u8]) -> bool {
    let limit = code.len().min(20);
    let mut i = 0;
    while i < limit {
        if code[i] == 0xe8 {
            return true;
        }
        if i + 1 < limit && code[i] == 0xff && code[i + 1] & 0x38 == 0x10 {
            return true;
        }
        i += 1;
    }
    false
}

fn read_imm32(code: &[u8], at: usize) -> Option<u32> {
    let b = code.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rel32_target(instruction_va: u32, instruction_len: u32, rel: u32) -> u32 {
    instruction_va
        .wrapping_add(instruction_len)
        .wrapping_add(rel as i32 as u32)
}

fn find_api_name_vas(pe: &Pe32) -> Vec<u32> {
    let mut out = Vec::new();
    for (offset, window) in pe.bytes.windows(SET_XP3_FILTER_IMPORT_FRAGMENT.len()).enumerate() {
        if window != SET_XP3_FILTER_IMPORT_FRAGMENT {
            continue;
        }
        // The fragment may sit inside the full generated signature
        // "void ::TVPSetXP3...(...)". Referencing the fragment itself is
        // sufficient because push/mov immediates must point at the first byte
        // of the actual C string, so also walk backward to its start.
        let mut start = offset;
        while start > 0
            && pe.bytes[start - 1] != 0
            && offset.saturating_sub(start) < 96
        {
            start -= 1;
        }
        if let Some(va) = pe.offset_to_va(start) {
            out.push(va);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn find_push_imm_xrefs(pe: &Pe32, target_va: u32) -> Vec<(u32, usize, &[u8])> {
    let needle = target_va.to_le_bytes();
    let mut out = Vec::new();
    for section in pe.sections.iter().filter(|s| s.executable()) {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(pe.bytes.len());
        if start >= end {
            continue;
        }
        let code = &pe.bytes[start..end];
        for i in 0..code.len().saturating_sub(4) {
            if code[i] == 0x68 && code.get(i + 1..i + 5) == Some(needle.as_slice()) {
                let rva = section.virtual_address.saturating_add(i as u32);
                out.push((pe.image_base.wrapping_add(rva), i, code));
            }
        }
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct SlotStore {
    slot_va: u32,
    end: usize,
}

fn find_resolver_call_and_slot(
    pe: &Pe32,
    xref_va: u32,
    xref_index: usize,
    section_code: &[u8],
) -> Option<(u32, Option<SlotStore>)> {
    let search_end = (xref_index + 96).min(section_code.len());
    let mut i = xref_index + 5;
    let mut resolver_call = None;
    let mut slot = None;
    while i < search_end {
        if section_code[i] == 0xe8 && i + 4 < search_end {
            if resolver_call.is_none() {
                let rel = read_imm32(section_code, i + 1)?;
                let call_va = xref_va.wrapping_add((i - xref_index) as u32);
                let target = rel32_target(call_va, 5, rel);
                if pe.is_exec_va(target) {
                    resolver_call = Some(call_va);
                }
            }
            i += 5;
            continue;
        }
        // mov [abs32], eax
        if section_code[i] == 0xa3 && i + 4 < search_end {
            let slot_va = read_imm32(section_code, i + 1)?;
            if pe.is_writable_va(slot_va) {
                slot = Some(SlotStore {
                    slot_va,
                    end: i + 5,
                });
            }
            i += 5;
            continue;
        }
        // mov [abs32], eax (89 05 imm32)
        if i + 5 < search_end && section_code[i..i + 2] == [0x89, 0x05] {
            let slot_va = read_imm32(section_code, i + 2)?;
            if pe.is_writable_va(slot_va) {
                slot = Some(SlotStore {
                    slot_va,
                    end: i + 6,
                });
            }
            i += 6;
            continue;
        }
        i += 1;
    }
    resolver_call.map(|call| (call, slot))
}

fn find_registration_call_through_slot(
    pe: &Pe32,
    xref_va: u32,
    xref_index: usize,
    section_code: &[u8],
    after: usize,
    slot_va: Option<u32>,
) -> Option<(u32, u32, u32)> {
    let search_end = (xref_index + 192).min(section_code.len());
    let mut i = after.max(xref_index + 5);
    let mut last_exec_push: Option<(u32, u32)> = None;
    let mut loaded_reg_from_slot: [Option<u32>; 8] = [None; 8];
    // A canonical lazy import stub stores EAX into the function slot and may
    // immediately call EAX on the fall-through path. The store does not
    // change EAX, so that value is still proven to be the resolved slot.
    if let Some(slot) = slot_va {
        loaded_reg_from_slot[0] = Some(slot);
    }
    while i < search_end {
        // Keep this deliberately conservative: a return terminates the local
        // provenance region. We do not borrow evidence from the next function.
        if section_code[i] == 0xc3 || section_code[i] == 0xcb {
            break;
        }
        if (section_code[i] == 0xc2 || section_code[i] == 0xca) && i + 2 < search_end {
            break;
        }
        if section_code[i] == 0x68 && i + 4 < search_end {
            let imm = read_imm32(section_code, i + 1)?;
            if pe.is_exec_va(imm) {
                let push_va = xref_va.wrapping_add((i - xref_index) as u32);
                last_exec_push = Some((push_va, imm));
            }
            i += 5;
            continue;
        }
        // mov r32, imm32; push r32 -- another common compiler spelling
        // for passing an address constant. Requiring adjacency avoids treating
        // a stale register value as provenance.
        if (0xb8..=0xbf).contains(&section_code[i]) && i + 5 < search_end {
            let reg = (section_code[i] - 0xb8) as usize;
            let imm = read_imm32(section_code, i + 1)?;
            if pe.is_exec_va(imm)
                && section_code.get(i + 5).copied() == Some(0x50 + reg as u8)
            {
                let push_va = xref_va.wrapping_add((i + 5 - xref_index) as u32);
                last_exec_push = Some((push_va, imm));
                i += 6;
                continue;
            }
        }
        // call dword ptr [abs32]
        if i + 5 < search_end && section_code[i..i + 2] == [0xff, 0x15] {
            let call_slot = read_imm32(section_code, i + 2)?;
            if slot_va == Some(call_slot) {
                if let Some((push_va, callback)) = last_exec_push {
                    let call_va = xref_va.wrapping_add((i - xref_index) as u32);
                    return Some((push_va, callback, call_va));
                }
            }
            i += 6;
            continue;
        }
        // mov r32, [abs32] : 8B /r with mod=00 r/m=101
        if i + 5 < search_end && section_code[i] == 0x8b && section_code[i + 1] & 0xc7 == 0x05 {
            let reg = ((section_code[i + 1] >> 3) & 7) as usize;
            let loaded_slot = read_imm32(section_code, i + 2)?;
            loaded_reg_from_slot[reg] = Some(loaded_slot);
            i += 6;
            continue;
        }
        // call r32 : FF D0..D7
        if i + 1 < search_end && section_code[i] == 0xff && section_code[i + 1] & 0xf8 == 0xd0 {
            let reg = (section_code[i + 1] & 7) as usize;
            if slot_va.is_some() && loaded_reg_from_slot[reg] == slot_va {
                if let Some((push_va, callback)) = last_exec_push {
                    let call_va = xref_va.wrapping_add((i - xref_index) as u32);
                    return Some((push_va, callback, call_va));
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

fn v2link_static_range(pe: &Pe32) -> Option<(u32, u32)> {
    let v2link_va = pe.image_base.wrapping_add(pe.export_rva("V2Link")?);
    let prefix = heuristic_function_prefix(pe, v2link_va, 0x600)?;
    let end = v2link_va.checked_add(prefix.len() as u32)?;
    Some((v2link_va, end))
}

/// Recover the one executable argument passed immediately to a direct call.
/// This is deliberately instruction-shape based rather than score based: the
/// returned value is accepted only when the call target is independently
/// proven to be the TVPSetXP3ArchiveExtractionFilter wrapper.
fn direct_call_exec_argument(code: &[u8], call_index: usize, pe: &Pe32) -> Option<(usize, u32)> {
    // push imm32 ; call rel32
    if call_index >= 5 && code[call_index - 5] == 0x68 {
        let imm = read_imm32(code, call_index - 4)?;
        if pe.is_exec_va(imm) {
            return Some((call_index - 5, imm));
        }
    }
    // mov r32, imm32 ; push r32 ; call rel32
    if call_index >= 6 && (0xb8..=0xbf).contains(&code[call_index - 6]) {
        let reg = code[call_index - 6] - 0xb8;
        if code[call_index - 1] == 0x50 + reg {
            let imm = read_imm32(code, call_index - 5)?;
            if pe.is_exec_va(imm) {
                return Some((call_index - 1, imm));
            }
        }
    }
    // lea r32, [abs32] ; push r32 ; call rel32
    if call_index >= 7 && code[call_index - 7] == 0x8d {
        let modrm = code[call_index - 6];
        if modrm & 0xc7 == 0x05 {
            let reg = (modrm >> 3) & 7;
            if code[call_index - 1] == 0x50 + reg {
                let imm = read_imm32(code, call_index - 5)?;
                if pe.is_exec_va(imm) {
                    return Some((call_index - 1, imm));
                }
            }
        }
    }
    None
}

/// Prove the non-inlined generated wrapper form. The exact API-name lookup and
/// writable function slot prove what the wrapper resolves; forwarding the
/// wrapper's first argument into a call through that slot proves the wrapper's
/// semantics without executing it.
fn find_registration_wrapper_forwarding_first_arg(
    pe: &Pe32,
    xref_va: u32,
    xref_index: usize,
    section_code: &[u8],
    after: usize,
    slot_va: u32,
) -> Option<(u32, u32)> {
    let search_end = (xref_index + 256).min(section_code.len());
    let mut i = after.max(xref_index + 5);
    let mut first_arg_pushed: Option<u32> = None;
    let mut reg_from_first_arg = [false; 8];
    let mut loaded_reg_from_slot: [Option<u32>; 8] = [None; 8];
    // The lazy resolver normally returns the function pointer in EAX and then
    // stores EAX into the slot. The store leaves EAX unchanged.
    loaded_reg_from_slot[0] = Some(slot_va);

    while i < search_end {
        if section_code[i] == 0xc3 || section_code[i] == 0xcb {
            break;
        }
        if (section_code[i] == 0xc2 || section_code[i] == 0xca) && i + 2 < search_end {
            break;
        }

        // push dword ptr [ebp+8] -- canonical first argument with frame pointer.
        if i + 2 < search_end && section_code[i..i + 3] == [0xff, 0x75, 0x08] {
            first_arg_pushed = Some(xref_va.wrapping_add((i - xref_index) as u32));
            i += 3;
            continue;
        }
        // push dword ptr [esp+4]. This is the canonical frameless one-argument
        // wrapper after resolver temporaries have been cleaned up.
        if i + 3 < search_end && section_code[i..i + 4] == [0xff, 0x74, 0x24, 0x04] {
            first_arg_pushed = Some(xref_va.wrapping_add((i - xref_index) as u32));
            i += 4;
            continue;
        }
        // mov r32, [ebp+8]
        if i + 2 < search_end
            && section_code[i] == 0x8b
            && section_code[i + 1] & 0xc7 == 0x45
            && section_code[i + 2] == 0x08
        {
            let reg = ((section_code[i + 1] >> 3) & 7) as usize;
            reg_from_first_arg[reg] = true;
            i += 3;
            continue;
        }
        // mov r32, [esp+4]
        if i + 3 < search_end
            && section_code[i] == 0x8b
            && section_code[i + 1] & 0xc7 == 0x44
            && section_code[i + 2] == 0x24
            && section_code[i + 3] == 0x04
        {
            let reg = ((section_code[i + 1] >> 3) & 7) as usize;
            reg_from_first_arg[reg] = true;
            i += 4;
            continue;
        }
        // push r32 after the register was proven to come from wrapper arg0.
        if (0x50..=0x57).contains(&section_code[i]) {
            let reg = (section_code[i] - 0x50) as usize;
            if reg_from_first_arg[reg] {
                first_arg_pushed = Some(xref_va.wrapping_add((i - xref_index) as u32));
            }
            i += 1;
            continue;
        }
        // mov r32, [abs32]
        if i + 5 < search_end && section_code[i] == 0x8b && section_code[i + 1] & 0xc7 == 0x05 {
            let reg = ((section_code[i + 1] >> 3) & 7) as usize;
            let loaded_slot = read_imm32(section_code, i + 2)?;
            loaded_reg_from_slot[reg] = Some(loaded_slot);
            i += 6;
            continue;
        }
        // call dword ptr [abs32]
        if i + 5 < search_end && section_code[i..i + 2] == [0xff, 0x15] {
            let call_slot = read_imm32(section_code, i + 2)?;
            if call_slot == slot_va && first_arg_pushed.is_some() {
                let call_va = xref_va.wrapping_add((i - xref_index) as u32);
                return Some((first_arg_pushed.unwrap(), call_va));
            }
            i += 6;
            continue;
        }
        // call r32
        if i + 1 < search_end && section_code[i] == 0xff && section_code[i + 1] & 0xf8 == 0xd0 {
            let reg = (section_code[i + 1] & 7) as usize;
            if loaded_reg_from_slot[reg] == Some(slot_va) && first_arg_pushed.is_some() {
                let call_va = xref_va.wrapping_add((i - xref_index) as u32);
                return Some((first_arg_pushed.unwrap(), call_va));
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

/// Find a direct V2Link -> wrapper call whose target body contains the exact
/// TVPSetXP3ArchiveExtractionFilter API-name xref, and recover the executable
/// callback argument at that callsite.
fn find_v2link_call_to_wrapper(
    pe: &Pe32,
    v2link_va: u32,
    api_name_xref_va: u32,
) -> Option<(u32, u32, u32, u32)> {
    let code = heuristic_function_prefix(pe, v2link_va, 0x600)?;
    let mut i = 0usize;
    while i + 4 < code.len() {
        if code[i] != 0xe8 {
            i += 1;
            continue;
        }
        let rel = read_imm32(code, i + 1)?;
        let call_va = v2link_va.wrapping_add(i as u32);
        let target = rel32_target(call_va, 5, rel);
        if !pe.is_exec_va(target) {
            i += 5;
            continue;
        }
        let Some(wrapper) = heuristic_function_prefix(pe, target, 0x600) else {
            i += 5;
            continue;
        };
        let wrapper_end = target.wrapping_add(wrapper.len() as u32);
        if api_name_xref_va < target || api_name_xref_va >= wrapper_end {
            i += 5;
            continue;
        }
        if let Some((arg_index, callback_va)) = direct_call_exec_argument(code, i, pe) {
            let callback_push_va = v2link_va.wrapping_add(arg_index as u32);
            return Some((target, call_va, callback_push_va, callback_va));
        }
        i += 5;
    }
    None
}

fn collect_registration_provenance_candidates(pe: &Pe32) -> Vec<FilterCandidate> {
    let mut out = Vec::new();
    let Some((v2link_va, v2link_end)) = v2link_static_range(pe) else {
        return out;
    };
    for api_name_va in find_api_name_vas(pe) {
        for (xref_va, xref_index, section_code) in find_push_imm_xrefs(pe, api_name_va) {
            let Some((resolver_call_va, slot_store)) =
                find_resolver_call_and_slot(pe, xref_va, xref_index, section_code)
            else {
                continue;
            };
            let Some(slot_store) = slot_store else {
                continue;
            };
            let slot_va = Some(slot_store.slot_va);

            // Form A: generated wrapper was inlined into V2Link. This keeps the
            // strongest existing proof and requires the callback constant and
            // resolved registration call in the same V2Link body.
            if xref_va >= v2link_va && xref_va < v2link_end {
                if let Some((callback_push_va, callback_va, registration_call_va)) =
                    find_registration_call_through_slot(
                        pe,
                        xref_va,
                        xref_index,
                        section_code,
                        slot_store.end,
                        slot_va,
                    )
                {
                    let registration = StaticRegistrationProvenance {
                        v2link_va,
                        wrapper_va: None,
                        wrapper_call_va: None,
                        api_name_va,
                        api_name_xref_va: xref_va,
                        resolver_call_va,
                        function_slot_va: slot_va,
                        callback_push_va,
                        registration_call_va,
                    };
                    out.push(FilterCandidate {
                        callback_va,
                        score: 1000,
                        source: "static-registration-provenance".into(),
                        abi_score: 0,
                        reasons: vec![
                            format!("inlined registration chain is inside exported V2Link at 0x{v2link_va:08x}"),
                            format!("exact TVPSetXP3ArchiveExtractionFilter import name at 0x{api_name_va:08x} referenced at 0x{xref_va:08x}"),
                            format!("resolver result stored in writable function slot 0x{:08x}", slot_store.slot_va),
                            format!("executable callback 0x{callback_va:08x} materialized at 0x{callback_push_va:08x} and passed to registration call at 0x{registration_call_va:08x}"),
                        ],
                        registration: Some(registration),
                    });
                    continue;
                }
            }

            // Form B: V2Link calls a non-inlined generated wrapper. First prove
            // that the wrapper resolves the exact API and forwards its arg0 to
            // the resolved function slot, then recover the executable arg0 at
            // the direct V2Link -> wrapper callsite.
            let Some((_forward_push_va, registration_call_va)) =
                find_registration_wrapper_forwarding_first_arg(
                    pe,
                    xref_va,
                    xref_index,
                    section_code,
                    slot_store.end,
                    slot_store.slot_va,
                )
            else {
                continue;
            };
            let Some((wrapper_va, wrapper_call_va, callback_push_va, callback_va)) =
                find_v2link_call_to_wrapper(pe, v2link_va, xref_va)
            else {
                continue;
            };
            let registration = StaticRegistrationProvenance {
                v2link_va,
                wrapper_va: Some(wrapper_va),
                wrapper_call_va: Some(wrapper_call_va),
                api_name_va,
                api_name_xref_va: xref_va,
                resolver_call_va,
                function_slot_va: slot_va,
                callback_push_va,
                registration_call_va,
            };
            out.push(FilterCandidate {
                callback_va,
                score: 1000,
                source: "static-registration-provenance".into(),
                abi_score: 0,
                reasons: vec![
                    format!("exported V2Link at 0x{v2link_va:08x} directly reaches proven TVPSetXP3ArchiveExtractionFilter wrapper 0x{wrapper_va:08x} at callsite 0x{wrapper_call_va:08x}"),
                    format!("exact TVPSetXP3ArchiveExtractionFilter import name at 0x{api_name_va:08x} referenced inside wrapper at 0x{xref_va:08x}"),
                    format!("wrapper resolver result stored in writable function slot 0x{:08x} and wrapper arg0 is forwarded to registration call at 0x{registration_call_va:08x}", slot_store.slot_va),
                    format!("V2Link materializes executable callback 0x{callback_va:08x} at 0x{callback_push_va:08x} before the proven wrapper call"),
                ],
                registration: Some(registration),
            });
        }
    }
    out.sort_by_key(|c| c.callback_va);
    out.dedup_by_key(|c| c.callback_va);
    out
}

fn collect_abi_hint_candidates(pe: &Pe32) -> Vec<FilterCandidate> {
    let mut found: HashMap<u32, FilterCandidate> = HashMap::new();
    if let Some(v2_rva) = pe.export_rva("V2Link") {
        let v2_va = pe.image_base.wrapping_add(v2_rva);
        if let Some(code) = pe.exec_slice_at_va(v2_va, 0x300) {
            for i in 0..code.len().saturating_sub(5) {
                if code[i] != 0x68 {
                    continue;
                }
                let imm = u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
                if !pe.is_exec_va(imm) || !has_call_soon(&code[i + 5..]) {
                    continue;
                }
                let (abi, mut reasons) = abi_score(pe, imm);
                if abi == 0 {
                    continue;
                }
                reasons.insert(0, "unproven V2Link executable-address/call proximity".into());
                let score = abi;
                found.entry(imm).or_insert(FilterCandidate {
                    callback_va: imm,
                    score,
                    source: "abi-v2link-hypothesis".into(),
                    abi_score: abi,
                    reasons,
                    registration: None,
                });
            }
        }
    }

    for section in pe.sections.iter().filter(|s| s.executable()) {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(pe.bytes.len());
        if start >= end {
            continue;
        }
        let code = &pe.bytes[start..end];
        for i in 0..code.len().saturating_sub(5) {
            if code[i] != 0x68 {
                continue;
            }
            let imm = u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            if !pe.is_exec_va(imm) || !has_call_soon(&code[i + 5..]) {
                continue;
            }
            let (abi, mut reasons) = abi_score(pe, imm);
            if abi < 18 {
                continue;
            }
            reasons.insert(
                0,
                format!("unproven {} executable-address/call proximity", section.name),
            );
            found.entry(imm).or_insert(FilterCandidate {
                callback_va: imm,
                score: abi,
                source: "abi-callsite-hypothesis".into(),
                abi_score: abi,
                reasons,
                registration: None,
            });
        }
    }

    // Registration provenance can disappear entirely in statically linked or
    // heavily inlined builds. Discover high-confidence ABI-shaped function
    // bodies directly as sandbox-only hypotheses. Common MSVC frame prologues
    // give us a bounded set of plausible entries; the ABI score then requires
    // accesses compatible with tTVPXP3ExtractionFilterInfo before the candidate
    // is ever executed.
    for section in pe.sections.iter().filter(|s| s.executable()) {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(pe.bytes.len());
        if start >= end {
            continue;
        }
        let code = &pe.bytes[start..end];
        for i in 0..code.len().saturating_sub(4) {
            let framed = code[i..].starts_with(&[0x55, 0x8b, 0xec]);
            let frameless_arg0 = code[i..].starts_with(&[0x8b, 0x44, 0x24, 0x04])
                && (i == 0
                    || matches!(code[i - 1], 0xcc | 0xc3 | 0x90)
                    || i % 16 == 0);
            if !framed && !frameless_arg0 {
                continue;
            }
            let rva = section.virtual_address.saturating_add(i as u32);
            let va = pe.image_base.wrapping_add(rva);
            let (abi, mut reasons) = abi_score(pe, va);
            if abi < 24 {
                continue;
            }
            reasons.insert(
                0,
                format!("unproven extraction-filter ABI body in {}", section.name),
            );
            found.entry(va).or_insert(FilterCandidate {
                callback_va: va,
                score: abi,
                source: "abi-body-scan-hypothesis".into(),
                abi_score: abi,
                reasons,
                registration: None,
            });
        }
    }

    // Some titles compile the XP3 filter into the main executable or assign
    // the callback through a private wrapper instead of tp_stub's exported
    // TVPSetXP3ArchiveExtractionFilter resolver.  Preserve these as *unproven
    // hypotheses* only: a direct executable pointer written into writable PE
    // storage is not authoritative by itself, but it is safe to try inside the
    // emulator and accept only after real archive entries match their original
    // adlr values.
    for section in pe.sections.iter().filter(|s| s.executable()) {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(pe.bytes.len());
        if start >= end {
            continue;
        }
        let code = &pe.bytes[start..end];
        for i in 0..code.len().saturating_sub(10) {
            // mov dword ptr [abs32], imm32
            if code[i] == 0xc7 && code[i + 1] == 0x05 {
                let slot = u32::from_le_bytes([
                    code[i + 2], code[i + 3], code[i + 4], code[i + 5],
                ]);
                let imm = u32::from_le_bytes([
                    code[i + 6], code[i + 7], code[i + 8], code[i + 9],
                ]);
                if pe.is_writable_va(slot) && pe.is_exec_va(imm) {
                    let (abi, mut reasons) = abi_score(pe, imm);
                    if abi >= 18 {
                        reasons.insert(
                            0,
                            format!(
                                "unproven executable callback stored to writable global 0x{slot:08x} from {}",
                                section.name
                            ),
                        );
                        found.entry(imm).or_insert(FilterCandidate {
                            callback_va: imm,
                            score: abi,
                            source: "abi-global-store-hypothesis".into(),
                            abi_score: abi,
                            reasons,
                            registration: None,
                        });
                    }
                }
            }
            // mov r32, imm32 ; ... ; mov [abs32], r32
            if (0xb8..=0xbf).contains(&code[i]) {
                let reg = code[i] - 0xb8;
                let imm = u32::from_le_bytes([
                    code[i + 1], code[i + 2], code[i + 3], code[i + 4],
                ]);
                if pe.is_exec_va(imm) {
                    let search_end = (i + 20).min(code.len().saturating_sub(6));
                    for j in i + 5..=search_end {
                        if code[j] != 0x89 || code[j + 1] != ((reg << 3) | 0x05) {
                            continue;
                        }
                        let slot = u32::from_le_bytes([
                            code[j + 2], code[j + 3], code[j + 4], code[j + 5],
                        ]);
                        if !pe.is_writable_va(slot) {
                            continue;
                        }
                        let (abi, mut reasons) = abi_score(pe, imm);
                        if abi >= 18 {
                            reasons.insert(
                                0,
                                format!(
                                    "unproven executable callback moved through r{reg} into writable global 0x{slot:08x} from {}",
                                    section.name
                                ),
                            );
                            found.entry(imm).or_insert(FilterCandidate {
                                callback_va: imm,
                                score: abi,
                                source: "abi-global-store-hypothesis".into(),
                                abi_score: abi,
                                reasons,
                                registration: None,
                            });
                        }
                        break;
                    }
                }
            }
        }
    }

    let mut out: Vec<_> = found.into_values().collect();
    out.sort_by_key(|c| (std::cmp::Reverse(c.abi_score), c.callback_va));
    out
}

fn collect_static_candidates(pe: &Pe32) -> Vec<FilterCandidate> {
    let mut proven = collect_registration_provenance_candidates(pe);
    let proven_vas: std::collections::BTreeSet<u32> =
        proven.iter().map(|c| c.callback_va).collect();
    proven.extend(
        collect_abi_hint_candidates(pe)
            .into_iter()
            .filter(|c| !proven_vas.contains(&c.callback_va)),
    );
    proven
}

#[derive(Clone, Debug, Default)]
struct RuntimeExecutionProfile {
    active: bool,
    call_id: u64,
    context: String,
    chunk_index: usize,
    chunk_count: usize,
    chunk_bytes: usize,
    started: Option<Instant>,
    last_heartbeat: Option<Instant>,
    basic_blocks: u64,
    executed_block_bytes: u64,
    sampled_blocks: BTreeMap<u32, u64>,
}

#[derive(Clone, Debug)]
struct EmuState {
    captured_callback: Option<u32>,
    requested_exports: Vec<String>,
    trace_code: bool,
    last_api: Option<String>,
    unsupported_api: Option<String>,
    win32: Win32HostState,
    module_image_base: u32,
    module_image_size: u32,
    runtime_profile: RuntimeExecutionProfile,
    module_file: Vec<u8>,
    host_file: Vec<u8>,
    opened_file: Vec<u8>,
    file_cursor: usize,
    file_open: bool,
    file_trace: Vec<String>,
    initialization_notes: Vec<String>,
}

impl EmuState {
    fn new(
        trace_code: bool,
        module_image_base: u32,
        module_image_size: u32,
        module_file: Vec<u8>,
    ) -> Self {
        // Some protected plugins authenticate the engine executable by
        // following the exporter object's allocation base.  The recoverable
        // payload is the plugin image appended at the conventional 0x80000
        // boundary; model that host layout without executing or trusting a
        // real game executable.
        let mut host_file = vec![0u8; 0x80000];
        host_file.extend_from_slice(&module_file);
        let mut win32 = Win32HostState::default();
        for module in ["kernel32.dll", "kernelbase.dll", "ntdll.dll", "msvcrt.dll"] {
            win32.load_module(module);
        }
        win32.configure_allocator(DYN_BASE, DYN_BASE + DYN_SIZE);
        Self {
            captured_callback: None,
            requested_exports: Vec::new(),
            trace_code,
            last_api: None,
            unsupported_api: None,
            win32,
            module_image_base,
            module_image_size,
            runtime_profile: RuntimeExecutionProfile::default(),
            module_file,
            host_file,
            opened_file: Vec::new(),
            file_cursor: 0,
            file_open: false,
            file_trace: Vec::new(),
            initialization_notes: Vec::new(),
        }
    }

    fn allocate(&mut self, requested: usize) -> Option<u64> {
        self.win32.allocate(requested)
    }

    fn free_allocation(&mut self, pointer: u64) -> bool {
        self.win32.free_allocation(pointer)
    }
}

#[derive(Clone, Debug, Default)]
struct X86FilterInitProfile {
    pe_parse: Duration,
    emulator_build: Duration,
    dll_attach: Duration,
    v2link: Duration,
    info_probe: Duration,
    total: Duration,
}

#[derive(Clone, Debug, Default)]
struct X86FilterChunkProfile {
    upload: Duration,
    setup: Duration,
    emulate: Duration,
    download: Duration,
    basic_blocks: u64,
    executed_block_bytes: u64,
    sampled_pcs: BTreeMap<u32, u64>,
}

impl X86FilterChunkProfile {
    fn merge(&mut self, other: X86FilterChunkProfile) {
        self.upload += other.upload;
        self.setup += other.setup;
        self.emulate += other.emulate;
        self.download += other.download;
        self.basic_blocks = self.basic_blocks.saturating_add(other.basic_blocks);
        self.executed_block_bytes = self
            .executed_block_bytes
            .saturating_add(other.executed_block_bytes);
        for (pc, count) in other.sampled_pcs {
            *self.sampled_pcs.entry(pc).or_default() += count;
        }
    }
}

pub struct X86Xp3FilterRuntime {
    module: PathBuf,
    pe: Pe32,
    uc: Unicorn<'static, EmuState>,
    callback_va: u32,
    callback_source: String,
    info_size: u32,
    init_profile: X86FilterInitProfile,
    execution_diagnostics: bool,
    execution_context: Option<String>,
    execution_calls: u64,
    profile_hook_ids: Vec<UcHookId>,
    detailed_profile_complete: bool,
    validated_production_execution: bool,
}

impl X86Xp3FilterRuntime {
    pub fn open(path: impl AsRef<Path>, trace_code: bool) -> Result<Self> {
        let path = path.as_ref();
        let pe = Pe32::from_path(path)?;
        Self::open_pe(path.to_path_buf(), pe, trace_code)
    }

    /// Open a filter from bytes retained in `xp3-meta.yaml`. This avoids a
    /// hidden dependency on the original game directory during repacking.
    pub fn from_bytes(
        module_name: impl Into<PathBuf>,
        bytes: Vec<u8>,
        trace_code: bool,
    ) -> Result<Self> {
        let module = module_name.into();
        let normalized = crate::pe_normalize::normalize_pe_bytes(&bytes)?;
        let pe = Pe32::parse(normalized.bytes)?;
        Self::open_pe(module, pe, trace_code)
    }

    /// Build a sandboxed runtime around an explicitly discovered callback
    /// hypothesis.  This is intentionally separate from `open()`: callers may
    /// use it for ABI/dataflow candidates whose registration path could not be
    /// proven, but production acceptance must still be gated by archive-level
    /// adlr/format validation.
    pub fn open_with_callback(
        path: impl AsRef<Path>,
        callback_va: u32,
        callback_source: impl Into<String>,
        trace_code: bool,
    ) -> Result<Self> {
        let total_start = Instant::now();
        let path = path.as_ref();
        let parse_start = Instant::now();
        let pe = Pe32::from_path(path)?;
        let pe_parse = parse_start.elapsed();
        if !pe.is_exec_va(callback_va) {
            return Err(Error::format(format!(
                "explicit XP3 filter callback 0x{callback_va:08x} is outside executable PE sections in {}",
                path.display()
            )));
        }

        let build_start = Instant::now();
        let mut uc = build_emulator(&pe, trace_code)?;
        let emulator_build = build_start.elapsed();

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        // Plugin callbacks frequently rely on normal DLL_PROCESS_ATTACH state.
        // Do not call an EXE entry point with DLL arguments merely because the
        // callback lives in the main image.
        let mut dll_attach = Duration::default();
        if matches!(ext.as_str(), "dll" | "tpm") || pe.export_rva("V2Link").is_some() {
            let phase_start = Instant::now();
            run_dll_process_attach(&mut uc, &pe)?;
            dll_attach = phase_start.elapsed();
        }

        let mut v2link = Duration::default();
        if let Some(v2_rva) = pe.export_rva("V2Link") {
            let v2_va = pe.image_base.wrapping_add(v2_rva);
            // Even when the registration path itself is private/unrecognized,
            // V2Link may initialize tables/state consumed by the callback.
            // Keep those side effects when emulation succeeds; callback
            // selection remains the explicit archive-validated hypothesis.
            let phase_start = Instant::now();
            let _ = run_initialized_v2link_capture(&mut uc, &pe, v2_va);
            v2link = phase_start.elapsed();
        }

        let info_start = Instant::now();
        let info_size = detect_filter_info_size(&uc, callback_va).unwrap_or(24);
        let info_probe = info_start.elapsed();
        let total = total_start.elapsed();
        Ok(Self {
            module: path.to_path_buf(),
            pe,
            uc,
            callback_va,
            callback_source: callback_source.into(),
            info_size,
            init_profile: X86FilterInitProfile {
                pe_parse,
                emulator_build,
                dll_attach,
                v2link,
                info_probe,
                total,
            },
            execution_diagnostics: false,
            execution_context: None,
            execution_calls: 0,
            profile_hook_ids: Vec::new(),
            detailed_profile_complete: false,
            validated_production_execution: false,
        })
    }

    fn open_pe(module: PathBuf, pe: Pe32, trace_code: bool) -> Result<Self> {
        let total_start = Instant::now();
        let static_candidates = collect_static_candidates(&pe);

        let build_start = Instant::now();
        let mut uc = build_emulator(&pe, trace_code)?;
        let emulator_build = build_start.elapsed();

        let attach_start = Instant::now();
        run_dll_process_attach(&mut uc, &pe)?;
        let dll_attach = attach_start.elapsed();

        let mut callback = None;
        let mut callback_source = None;
        let mut v2link = Duration::default();
        if let Some(v2_rva) = pe.export_rva("V2Link") {
            let v2_va = pe.image_base.wrapping_add(v2_rva);
            let phase_start = Instant::now();
            if run_initialized_v2link_capture(&mut uc, &pe, v2_va).is_ok() {
                callback = uc.get_data().captured_callback;
                if callback.is_some() {
                    callback_source = Some("v2link-emulated-registration".to_string());
                }
            }
            v2link = phase_start.elapsed();
        }
        if callback.is_none() {
            if let Some(best) = static_candidates
                .iter()
                .find(|candidate| candidate.registration.is_some())
            {
                callback = Some(best.callback_va);
                callback_source = Some(best.source.clone());
            }
        }
        let callback_va = callback.ok_or_else(|| {
            let extra = uc
                .get_data()
                .unsupported_api
                .as_deref()
                .map(|s| format!("; unsupported API {s}"))
                .unwrap_or_default();
            Error::format(format!(
                "no XP3 extraction filter callback found in {}{extra}",
                module.display()
            ))
        })?;
        let source = callback_source.unwrap_or_else(|| "unknown".to_string());
        let info_start = Instant::now();
        let info_size = detect_filter_info_size(&uc, callback_va).unwrap_or(24);
        let info_probe = info_start.elapsed();
        let total = total_start.elapsed();
        Ok(Self {
            module,
            pe,
            uc,
            callback_va,
            callback_source: source,
            info_size,
            init_profile: X86FilterInitProfile {
                pe_parse: Duration::default(),
                emulator_build,
                dll_attach,
                v2link,
                info_probe,
                total,
            },
            execution_diagnostics: false,
            execution_context: None,
            execution_calls: 0,
            profile_hook_ids: Vec::new(),
            detailed_profile_complete: false,
            validated_production_execution: false,
        })
    }

    /// Mark this runtime as the final archive-validated production executor.
    /// Candidate/hypothesis validation deliberately keeps the instruction
    /// budget enabled so bad callbacks cannot run forever. Production uses
    /// `count=0` because Unicorn implements a non-zero count with an internal
    /// per-instruction hook, which destroys throughput for byte-wise filters.
    pub fn enable_validated_production_execution(&mut self) {
        self.validated_production_execution = true;
    }

    pub fn callback_va(&self) -> u32 {
        self.callback_va
    }

    pub fn callback_source(&self) -> &str {
        &self.callback_source
    }

    pub fn requested_exports(&self) -> &[String] {
        &self.uc.get_data().requested_exports
    }

    pub fn module_path(&self) -> &Path {
        &self.module
    }

    /// Enable low-overhead diagnostics for the final production runtime.
    /// Candidate validation keeps this disabled so thousands of rejected
    /// hypotheses do not flood stderr or pay the profiling cost.
    pub fn enable_execution_diagnostics(&mut self, enabled: bool) -> Result<()> {
        if enabled && !self.detailed_profile_complete && self.profile_hook_ids.is_empty() {
            let image_begin = self.pe.image_base as u64;
            let image_end = image_begin + align_page(self.pe.size_of_image as u64) - 1;
            let image_hook = self
                .uc
                .add_block_hook(image_begin, image_end, runtime_profile_block_hook)
                .map_err(uc_error)?;
            let dynamic_hook = self
                .uc
                .add_block_hook(DYN_BASE, DYN_BASE + DYN_SIZE - 1, runtime_profile_block_hook)
                .map_err(uc_error)?;
            self.profile_hook_ids.push(image_hook);
            self.profile_hook_ids.push(dynamic_hook);
            eprintln!(
                "[x86-filter-prof] detailed_sampling=basic-block heartbeat_s={} sample_every_blocks={} scope=validated-production-runtime temporary=true",
                CALLBACK_DIAG_HEARTBEAT_SECS,
                CALLBACK_DIAG_SAMPLE_BLOCKS
            );
        }
        self.execution_diagnostics = enabled;
        Ok(())
    }

    fn finish_detailed_profile(&mut self) -> Result<()> {
        let hooks = std::mem::take(&mut self.profile_hook_ids);
        for hook in hooks {
            self.uc.remove_hook(hook).map_err(uc_error)?;
        }
        self.detailed_profile_complete = true;
        Ok(())
    }

    /// Attach a human-readable archive entry to the next `apply()` call.  The
    /// context is consumed by that call so stale names cannot leak into later
    /// diagnostics.
    pub fn set_execution_context(&mut self, entry_index: usize, name: &str) {
        let mut clean = name.replace('\r', " ").replace('\n', " ").replace('\t', " ");
        if clean.chars().count() > 120 {
            clean = clean.chars().take(117).collect::<String>() + "...";
        }
        self.execution_context = Some(format!("entry={entry_index} name={clean:?}"));
    }

    pub fn print_initialization_diagnostics(&self) {
        let p = &self.init_profile;
        eprintln!(
            "[x86-filter-prof] init module={} callback=0x{:08x} info_size={} total_ms={:.3} pe_parse_ms={:.3} emulator_build_ms={:.3} dll_attach_ms={:.3} v2link_ms={:.3} info_probe_ms={:.3}",
            self.module.display(),
            self.callback_va,
            self.info_size,
            duration_ms(p.total),
            duration_ms(p.pe_parse),
            duration_ms(p.emulator_build),
            duration_ms(p.dll_attach),
            duration_ms(p.v2link),
            duration_ms(p.info_probe),
        );
    }

    pub fn apply(&mut self, file_offset: u64, file_hash: u32, buffer: &mut [u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        self.execution_calls = self.execution_calls.saturating_add(1);
        let call_id = self.execution_calls;
        let context = self
            .execution_context
            .take()
            .unwrap_or_else(|| "entry=<unknown>".to_string());
        let call_start = Instant::now();
        let total_bytes = buffer.len();
        let chunk_size = INPUT_RESERVE.min(u32::MAX as u64) as usize;
        let chunk_count = (buffer.len() - 1) / chunk_size + 1;
        let mut profile = X86FilterChunkProfile::default();

        if self.execution_diagnostics && (call_id <= 8 || call_id % 64 == 0) {
            eprintln!(
                "[x86-filter-prof] call={} {} phase=start bytes={} chunks={} file_offset={} file_hash=0x{:08x} callback=0x{:08x}",
                call_id,
                context,
                total_bytes,
                chunk_count,
                file_offset,
                file_hash,
                self.callback_va,
            );
        }

        for (chunk_index, chunk) in buffer.chunks_mut(chunk_size).enumerate() {
            let delta = (chunk_index as u64)
                .checked_mul(chunk_size as u64)
                .ok_or_else(|| Error::invalid("filter file offset overflow"))?;
            let offset = file_offset
                .checked_add(delta)
                .ok_or_else(|| Error::invalid("filter file offset overflow"))?;
            let chunk_profile = self.apply_chunk(
                offset,
                file_hash,
                chunk,
                call_id,
                &context,
                chunk_index,
                chunk_count,
            )?;
            profile.merge(chunk_profile);
        }

        let total = call_start.elapsed();
        if self.execution_diagnostics
            && (call_id <= 8
                || call_id % 64 == 0
                || total.as_millis() >= CALLBACK_DIAG_SLOW_CALL_MS)
        {
            let mib = total_bytes as f64 / (1024.0 * 1024.0);
            let total_s = total.as_secs_f64().max(f64::EPSILON);
            let emu_s = profile.emulate.as_secs_f64().max(f64::EPSILON);
            eprintln!(
                "[x86-filter-prof] call={} {} phase=done bytes={} total_ms={:.3} upload_ms={:.3} setup_ms={:.3} emulate_ms={:.3} download_ms={:.3} total_mib_s={:.2} emulate_mib_s={:.2} basic_blocks={} executed_block_bytes={} sampled_hot_blocks={}",
                call_id,
                context,
                total_bytes,
                duration_ms(total),
                duration_ms(profile.upload),
                duration_ms(profile.setup),
                duration_ms(profile.emulate),
                duration_ms(profile.download),
                mib / total_s,
                mib / emu_s,
                profile.basic_blocks,
                profile.executed_block_bytes,
                format_sampled_pcs(&profile.sampled_pcs, self.pe.image_base),
            );
        }
        // The block hook is deliberately temporary: capture one genuinely
        // slow production call (or at most the first eight calls), then remove
        // it so the diagnostic observer cannot become the long-run bottleneck.
        if self.execution_diagnostics
            && !self.detailed_profile_complete
            && (total.as_millis() >= CALLBACK_DIAG_SLOW_CALL_MS || call_id >= 8)
        {
            self.finish_detailed_profile()?;
            eprintln!(
                "[x86-filter-prof] detailed basic-block sampling complete after call={}; hooks=removed; phase timing remains enabled",
                call_id
            );
        }
        Ok(())
    }

    fn apply_chunk(
        &mut self,
        file_offset: u64,
        file_hash: u32,
        buffer: &mut [u8],
        call_id: u64,
        context: &str,
        chunk_index: usize,
        chunk_count: usize,
    ) -> Result<X86FilterChunkProfile> {
        debug_assert!(!buffer.is_empty());
        debug_assert!(buffer.len() as u64 <= INPUT_RESERVE);
        let mut profile = X86FilterChunkProfile::default();

        let phase_start = Instant::now();
        self.uc.mem_write(INPUT_BASE, buffer).map_err(uc_error)?;
        profile.upload = phase_start.elapsed();

        let phase_start = Instant::now();
        let mut info = vec![0u8; self.info_size as usize];
        info[0..4].copy_from_slice(&self.info_size.to_le_bytes());
        info[4..8].copy_from_slice(&(file_offset as u32).to_le_bytes());
        info[8..12].copy_from_slice(&((file_offset >> 32) as u32).to_le_bytes());
        info[12..16].copy_from_slice(&(INPUT_BASE as u32).to_le_bytes());
        info[16..20].copy_from_slice(&(buffer.len() as u32).to_le_bytes());
        info[20..24].copy_from_slice(&file_hash.to_le_bytes());
        self.uc.mem_write(INFO_ADDR, &info).map_err(uc_error)?;

        {
            let state = self.uc.get_data_mut();
            state.last_api = None;
            state.unsupported_api = None;
        }
        reset_stack_for_call(&mut self.uc, &[INFO_ADDR as u32])?;
        for reg in [
            RegisterX86::EAX,
            RegisterX86::EBX,
            RegisterX86::ECX,
            RegisterX86::EDX,
            RegisterX86::ESI,
            RegisterX86::EDI,
        ] {
            self.uc.reg_write(reg, 0).map_err(uc_error)?;
        }
        profile.setup = phase_start.elapsed();

        if self.execution_diagnostics {
            let now = Instant::now();
            let runtime_profile = &mut self.uc.get_data_mut().runtime_profile;
            runtime_profile.active = true;
            runtime_profile.call_id = call_id;
            runtime_profile.context.clear();
            runtime_profile.context.push_str(context);
            runtime_profile.chunk_index = chunk_index;
            runtime_profile.chunk_count = chunk_count;
            runtime_profile.chunk_bytes = buffer.len();
            runtime_profile.started = Some(now);
            runtime_profile.last_heartbeat = Some(now);
            runtime_profile.basic_blocks = 0;
            runtime_profile.executed_block_bytes = 0;
            runtime_profile.sampled_blocks.clear();
        }

        let emulate_start = Instant::now();
        let (timeout_us, instruction_limit) = if self.validated_production_execution {
            (CALLBACK_VALIDATED_TIMEOUT_US, 0)
        } else {
            (0, CALLBACK_MAX_STEPS)
        };
        self.uc.emu_start(
            self.callback_va as u64,
            RETURN_SENTINEL,
            timeout_us,
            instruction_limit,
        )
            .map_err(|e| Error::format(format!(
                "x86 filter execution failed in {} callback=0x{:08x}: {e:?}; last_api={:?}; unsupported_api={:?}",
                self.module.display(), self.callback_va, self.uc.get_data().last_api, self.uc.get_data().unsupported_api
            )))?;

        if self.execution_diagnostics {
            let runtime_profile = &mut self.uc.get_data_mut().runtime_profile;
            runtime_profile.active = false;
            profile.basic_blocks = runtime_profile.basic_blocks;
            profile.executed_block_bytes = runtime_profile.executed_block_bytes;
            profile.sampled_pcs = runtime_profile.sampled_blocks.clone();
        }
        profile.emulate = emulate_start.elapsed();

        let eip = self.uc.reg_read(RegisterX86::EIP).map_err(uc_error)?;
        if eip != RETURN_SENTINEL {
            return Err(Error::format(format!(
                "x86 filter callback 0x{:08x} stopped before return sentinel: eip=0x{eip:08x}; execution_mode={} instruction_budget={} timeout_us={}",
                self.callback_va,
                if self.validated_production_execution { "validated-production" } else { "candidate-validation" },
                instruction_limit,
                timeout_us,
            )));
        }
        if let Some(unsupported) = self.uc.get_data().unsupported_api.as_deref() {
            return Err(Error::unsupported(format!(
                "x86 filter callback 0x{:08x} requires unsupported host behavior: {unsupported}",
                self.callback_va
            )));
        }

        let phase_start = Instant::now();
        self.uc.mem_read(INPUT_BASE, buffer).map_err(uc_error)?;
        profile.download = phase_start.elapsed();
        Ok(profile)
    }

    pub fn apply_owned(
        &mut self,
        file_offset: u64,
        file_hash: u32,
        mut buffer: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.apply(file_offset, file_hash, &mut buffer)?;
        Ok(buffer)
    }

    pub fn image_base(&self) -> u32 {
        self.pe.image_base
    }
}

fn runtime_profile_block_hook(uc: &mut Unicorn<'_, EmuState>, address: u64, size: u32) {
    let report = {
        let state = uc.get_data_mut();
        let image_base = state.module_image_base;
        let image_size = state.module_image_size;
        let profile = &mut state.runtime_profile;
        if !profile.active {
            return;
        }
        profile.basic_blocks = profile.basic_blocks.saturating_add(1);
        profile.executed_block_bytes = profile
            .executed_block_bytes
            .saturating_add(size as u64);
        if profile.basic_blocks % CALLBACK_DIAG_SAMPLE_BLOCKS != 0 {
            return;
        }
        *profile.sampled_blocks.entry(address as u32).or_default() += 1;

        let now = Instant::now();
        let last = profile.last_heartbeat.unwrap_or(now);
        if now.duration_since(last) < Duration::from_secs(CALLBACK_DIAG_HEARTBEAT_SECS) {
            return;
        }
        profile.last_heartbeat = Some(now);
        let elapsed = profile
            .started
            .map(|started| now.duration_since(started))
            .unwrap_or_default();
        Some((
            profile.call_id,
            profile.context.clone(),
            profile.chunk_index,
            profile.chunk_count,
            profile.chunk_bytes,
            elapsed,
            profile.basic_blocks,
            profile.executed_block_bytes,
            profile.sampled_blocks.clone(),
            image_base,
            image_size,
        ))
    };

    let Some((
        call_id,
        context,
        chunk_index,
        chunk_count,
        chunk_bytes,
        elapsed,
        basic_blocks,
        executed_block_bytes,
        sampled_blocks,
        image_base,
        image_size,
    )) = report
    else {
        return;
    };

    let eax = uc.reg_read(RegisterX86::EAX).unwrap_or(0);
    let ecx = uc.reg_read(RegisterX86::ECX).unwrap_or(0);
    let edx = uc.reg_read(RegisterX86::EDX).unwrap_or(0);
    let esi = uc.reg_read(RegisterX86::ESI).unwrap_or(0);
    let edi = uc.reg_read(RegisterX86::EDI).unwrap_or(0);
    let esp = uc.reg_read(RegisterX86::ESP).unwrap_or(0);
    let ret = read_u32_uc(uc, esp).unwrap_or(0);
    let code = uc.mem_read_as_vec(address, 8).unwrap_or_default();
    let blocks_per_second = basic_blocks as f64
        / elapsed.as_secs_f64().max(f64::EPSILON);
    eprintln!(
        "[x86-filter-prof] call={} {} phase=callback chunk={}/{} chunk_bytes={} elapsed_s={:.2} basic_blocks={} block_million_s={:.2} executed_block_bytes={} eip=0x{:08x} eip_rva={} ret=0x{:08x} eax=0x{:08x} ecx=0x{:08x} edx=0x{:08x} esi=0x{:08x} edi=0x{:08x} code={} hot_blocks={}",
        call_id,
        context,
        chunk_index + 1,
        chunk_count,
        chunk_bytes,
        elapsed.as_secs_f64(),
        basic_blocks,
        blocks_per_second / 1_000_000.0,
        executed_block_bytes,
        address as u32,
        format_rva(address as u32, image_base, image_size),
        ret,
        eax as u32,
        ecx as u32,
        edx as u32,
        esi as u32,
        edi as u32,
        hex_preview(&code),
        format_sampled_pcs(&sampled_blocks, image_base),
    );
}

fn duration_ms(value: Duration) -> f64 {
    value.as_secs_f64() * 1000.0
}

fn format_rva(address: u32, image_base: u32, size_of_image: u32) -> String {
    let end = image_base.saturating_add(size_of_image);
    if address >= image_base && address < end {
        format!("0x{:x}", address - image_base)
    } else {
        "outside-module".to_string()
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<unreadable>".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn format_sampled_pcs(samples: &BTreeMap<u32, u64>, image_base: u32) -> String {
    if samples.is_empty() {
        return "-".to_string();
    }
    let mut ranked = samples
        .iter()
        .map(|(&pc, &count)| (pc, count))
        .collect::<Vec<_>>();
    ranked.sort_by(|(pc_a, count_a), (pc_b, count_b)| {
        count_b.cmp(count_a).then_with(|| pc_a.cmp(pc_b))
    });
    ranked
        .into_iter()
        .take(6)
        .map(|(pc, count)| {
            if pc >= image_base {
                format!("0x{pc:08x}/rva+0x{:x}:{count}", pc - image_base)
            } else {
                format!("0x{pc:08x}:{count}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn detect_filter_info_size(uc: &Unicorn<'static, EmuState>, callback_va: u32) -> Option<u32> {
    let mut pending = vec![callback_va];
    let mut visited = std::collections::BTreeSet::new();
    while let Some(address) = pending.pop() {
        if !visited.insert(address) || visited.len() > 8 {
            continue;
        }
        let Ok(code) = uc.mem_read_as_vec(address as u64, 0x100) else {
            continue;
        };
        for index in 0..code.len().saturating_sub(2) {
            // cmp dword ptr [r32(+disp)], imm8.  Both the old 0x1c and newer
            // 0x18 TVP structures use this compact guard near the callback
            // entry after any compiler-generated thunk.
            if code[index] == 0x83
                && code[index + 1] & 0x38 == 0x38
                && matches!(code[index + 2], 0x18 | 0x1c)
            {
                return Some(code[index + 2] as u32);
            }
            if code[index] == 0xe9 && index + 5 <= code.len() {
                let displacement = i32::from_le_bytes(code[index + 1..index + 5].try_into().ok()?);
                pending.push(
                    address
                        .wrapping_add(index as u32 + 5)
                        .wrapping_add(displacement as u32),
                );
            }
        }
    }
    None
}

fn snapshot_initialized_module(
    uc: &Unicorn<'static, EmuState>,
    pe: &Pe32,
    stage: &'static str,
) -> Result<X86ModuleInitializationSnapshot> {
    let original_image = pe.virtual_image()?;
    let mut initialized_image = vec![0u8; pe.size_of_image as usize];
    uc.mem_read(pe.image_base as u64, &mut initialized_image)
        .map_err(uc_error)?;

    let changed_executable_bytes = pe
        .sections
        .iter()
        .filter(|section| section.executable())
        .map(|section| {
            let start = section.virtual_address as usize;
            let len = section.raw_size as usize;
            let end = start
                .saturating_add(len)
                .min(original_image.len())
                .min(initialized_image.len());
            if start >= end {
                return 0;
            }
            original_image[start..end]
                .iter()
                .zip(&initialized_image[start..end])
                .filter(|(before, after)| before != after)
                .count()
        })
        .sum();

    Ok(X86ModuleInitializationSnapshot {
        stage,
        initialized_file: pe.materialize_file_from_virtual(&initialized_image),
        changed_executable_bytes,
    })
}

/// Execute only the bounded initialization path needed to expose code that a
/// plugin decodes or materializes at runtime.  Callers must already have
/// structural evidence that the module is relevant; this function does not
/// classify arbitrary DLLs as CXDEC.
///
/// Two snapshots can be returned.  The first is always immediately after
/// `DLL_PROCESS_ATTACH`.  When the module exports `V2Link`, a second snapshot
/// is taken after attempting V2Link with the existing minimal KiriKiri host.
/// V2Link callback capture is deliberately *not* required here: the purpose is
/// to recover native semantics from the initialized image, and later archive
/// validation remains authoritative.
fn initialize_x86_pe_for_static_analysis(
    pe: Pe32,
) -> Result<Vec<X86ModuleInitializationSnapshot>> {
    if pe.export_rva("V2Link").is_none() {
        return Err(Error::format(
            "runtime static-analysis initialization requires an exported V2Link",
        ));
    }
    let mut uc = build_emulator(&pe, false)?;
    run_dll_process_attach(&mut uc, &pe)?;

    let mut snapshots = vec![snapshot_initialized_module(
        &uc,
        &pe,
        "dll-process-attach",
    )?];

    if let Some(v2_rva) = pe.export_rva("V2Link") {
        let v2link_va = pe.image_base.wrapping_add(v2_rva);
        match run_initialized_v2link_capture(&mut uc, &pe, v2link_va) {
            Ok(callback) => uc.get_data_mut().initialization_notes.push(format!(
                "V2Link registered XP3 extraction callback 0x{callback:08x}"
            )),
            Err(error) => uc.get_data_mut().initialization_notes.push(format!(
                "V2Link side-effect probe stopped before proven callback registration: {error}"
            )),
        }
        snapshots.push(snapshot_initialized_module(&uc, &pe, "v2link")?);
    }

    Ok(snapshots)
}

pub(crate) fn initialize_x86_module_for_static_analysis(
    path: impl AsRef<Path>,
) -> Result<Vec<X86ModuleInitializationSnapshot>> {
    initialize_x86_pe_for_static_analysis(Pe32::from_path(path.as_ref())?)
}

pub(crate) fn initialize_x86_module_bytes_for_static_analysis(
    raw_bytes: &[u8],
) -> Result<Vec<X86ModuleInitializationSnapshot>> {
    let normalized = crate::pe_normalize::normalize_pe_bytes(raw_bytes)?;
    initialize_x86_pe_for_static_analysis(Pe32::parse(normalized.bytes)?)
}

pub fn initialize_x86_filter_module(
    path: impl AsRef<Path>,
    trace_code: bool,
) -> Result<FilterInitialization> {
    let path = path.as_ref();
    let pe = Pe32::from_path(path)?;
    let v2link_va = pe
        .export_rva("V2Link")
        .map(|rva| pe.image_base.wrapping_add(rva))
        .ok_or_else(|| Error::format("PE module has no V2Link export"))?;
    let mut uc = build_emulator(&pe, trace_code)?;
    run_dll_process_attach(&mut uc, &pe)?;
    let callback_va = run_initialized_v2link_capture(&mut uc, &pe, v2link_va)?;

    let mut initialized_image = vec![0u8; pe.size_of_image as usize];
    uc.mem_read(pe.image_base as u64, &mut initialized_image)
        .map_err(uc_error)?;
    let initialized_file = pe.materialize_file_from_virtual(&initialized_image);
    let allocations = uc.get_data().win32.allocation_snapshot();
    let mut allocated_regions = Vec::new();
    for (address, size) in allocations {
        if size == 0 || size > DYN_SIZE as usize {
            continue;
        }
        if let Ok(bytes) = uc.mem_read_as_vec(address, size) {
            allocated_regions.push(InitializedMemoryRegion {
                address: address as u32,
                bytes,
            });
        }
    }
    Ok(FilterInitialization {
        path: path.to_path_buf(),
        image_base: pe.image_base,
        callback_va,
        initialized_image,
        initialized_file,
        allocated_regions,
        requested_exports: uc.get_data().requested_exports.clone(),
        notes: uc.get_data().initialization_notes.clone(),
    })
}

fn uc_error(e: unicorn_engine::uc_error) -> Error {
    Error::format(format!("Unicorn error: {e:?}"))
}

/// Run only a CXDEC generator callback to initialize its 128 generated lanes.
///
/// Intermediate CXDEC builds keep the outer archive-filter algorithm stable
/// but shuffle the generator's three dispatch tables.  Instead of identifying
/// compiler-specific switch layouts, we execute the title's own
/// `xcode_building_stage1(cxdec_xcode_status*, stage)` function during
/// initialization and capture the bytes it emits.  The generated functions
/// themselves are *not* executed here; callers translate them to native
/// semantics and use those for every archive read.
///
/// This reproduces the historical retry rule exactly: stage 5 is tried first,
/// `curr` is reset between failures, while the PRNG seed in the status object
/// is deliberately preserved across retries.
pub(crate) fn capture_cxdec_generated_lanes(
    path: impl AsRef<Path>,
    builder_va: u32,
) -> Result<Vec<Vec<u8>>> {
    let path = path.as_ref();
    let pe = Pe32::from_path(path)?;
    if !pe.is_exec_va(builder_va) {
        return Err(Error::format(format!(
            "CXDEC builder 0x{builder_va:08x} is not executable in {}",
            path.display()
        )));
    }
    let mut uc = build_emulator(&pe, false)?;
    run_dll_process_attach(&mut uc, &pe)?;
    if let Some(v2_rva) = pe.export_rva("V2Link") {
        let v2link_va = pe.image_base.wrapping_add(v2_rva);
        run_initialized_v2link_capture(&mut uc, &pe, v2link_va)?;
    }
    let mut lanes = Vec::with_capacity(128);

    for lane in 0..128u32 {
        uc.mem_write(CXDEC_CODE_ADDR, &[0u8; CXDEC_CODE_BUDGET])
            .map_err(uc_error)?;

        // struct cxdec_xcode_status (PE32):
        //   +00 BYTE *start
        //   +04 BYTE *curr
        //   +08 DWORD space_size
        //   +0c DWORD seed
        //   +10 int (*xcode_building)(status*, int)
        write_u32_uc(&mut uc, CXDEC_STATUS_ADDR + 0x00, CXDEC_CODE_ADDR as u32)
            .map_err(uc_error)?;
        write_u32_uc(
            &mut uc,
            CXDEC_STATUS_ADDR + 0x04,
            (CXDEC_CODE_ADDR + CXDEC_PROLOGUE_BYTES as u64) as u32,
        )
        .map_err(uc_error)?;
        write_u32_uc(&mut uc, CXDEC_STATUS_ADDR + 0x08, CXDEC_CODE_BUDGET as u32)
            .map_err(uc_error)?;
        write_u32_uc(&mut uc, CXDEC_STATUS_ADDR + 0x0c, lane).map_err(uc_error)?;
        write_u32_uc(&mut uc, CXDEC_STATUS_ADDR + 0x10, builder_va).map_err(uc_error)?;

        let mut generated = None;
        for stage in (1u32..=5).rev() {
            // xcode_building_start() would emit a 9-byte prologue before
            // calling the builder.  We skip those known bytes but keep `curr`
            // at start+9 so the builder's 128-byte budget decisions are exact.
            write_u32_uc(
                &mut uc,
                CXDEC_STATUS_ADDR + 0x04,
                (CXDEC_CODE_ADDR + CXDEC_PROLOGUE_BYTES as u64) as u32,
            )
            .map_err(uc_error)?;
            {
                let state = uc.get_data_mut();
                state.last_api = None;
                state.unsupported_api = None;
            }
            reset_stack_for_call(&mut uc, &[CXDEC_STATUS_ADDR as u32, stage])?;
            for reg in [
                RegisterX86::EAX,
                RegisterX86::EBX,
                RegisterX86::ECX,
                RegisterX86::EDX,
                RegisterX86::ESI,
                RegisterX86::EDI,
            ] {
                uc.reg_write(reg, 0).map_err(uc_error)?;
            }
            uc.emu_start(builder_va as u64, RETURN_SENTINEL, TIMEOUT_US, MAX_STEPS)
                .map_err(|e| Error::format(format!(
                    "CXDEC builder execution failed in {} builder=0x{builder_va:08x} lane={lane} stage={stage}: {e:?}; last_api={:?}; unsupported_api={:?}",
                    path.display(), uc.get_data().last_api, uc.get_data().unsupported_api
                )))?;
            if let Some(unsupported) = uc.get_data().unsupported_api.as_deref() {
                return Err(Error::unsupported(format!(
                    "CXDEC builder 0x{builder_va:08x} requires unsupported host behavior: {unsupported}"
                )));
            }
            let ok = uc.reg_read(RegisterX86::EAX).map_err(uc_error)? as u32 != 0;
            let curr = read_u32_uc(&uc, CXDEC_STATUS_ADDR + 0x04).map_err(uc_error)?;
            let start = CXDEC_CODE_ADDR as u32;
            if curr < start + CXDEC_PROLOGUE_BYTES || curr > start + CXDEC_CODE_BUDGET as u32 {
                return Err(Error::format(format!(
                    "CXDEC builder produced invalid curr=0x{curr:08x} for lane {lane}"
                )));
            }
            // A successful builder can still fail in xcode_building_start()
            // if the fixed 6-byte epilogue would overflow the 128-byte budget.
            let total_with_epilogue = curr
                .saturating_sub(start)
                .saturating_add(CXDEC_EPILOGUE_BYTES);
            if ok && total_with_epilogue <= CXDEC_CODE_BUDGET as u32 {
                let body_len = (curr - start - CXDEC_PROLOGUE_BYTES) as usize;
                let mut body = vec![0u8; body_len];
                if body_len != 0 {
                    uc.mem_read(CXDEC_CODE_ADDR + CXDEC_PROLOGUE_BYTES as u64, &mut body)
                        .map_err(uc_error)?;
                }
                generated = Some(body);
                break;
            }
            // Do not reset +0x0c seed.  That is the subtle historical CXDEC
            // behavior required for the next lower stage to match the game.
        }

        lanes.push(generated.ok_or_else(|| {
            Error::format(format!(
                "CXDEC builder 0x{builder_va:08x} could not generate lane {lane} within 128 bytes"
            ))
        })?);
    }
    Ok(lanes)
}

/// Controlled builder outputs used to recover Classic's dispatch tables.
/// `odd_stage2` comes from the configured stage1 builder.  Each
/// `even_stage2_candidates` entry comes from one executable direct-call
/// target observed in that builder; the semantic recognizer accepts only the
/// unique target whose outputs all have the stage0(prolog + unary) grammar.
#[derive(Clone, Debug)]
pub(crate) struct CxdecDispatchCapture {
    pub odd_stage2: Vec<(u32, Vec<u8>)>,
    pub even_stage2_candidates: Vec<(u32, Vec<(u32, Vec<u8>)>)>,
}

pub(crate) fn capture_cxdec_dispatch_samples(
    path: impl AsRef<Path>,
    builder_va: u32,
) -> Result<CxdecDispatchCapture> {
    const SAMPLE_COUNT: u32 = 256;

    let path = path.as_ref();
    let pe = Pe32::from_path(path)?;
    if !pe.is_exec_va(builder_va) {
        return Err(Error::format(format!(
            "CXDEC builder 0x{builder_va:08x} is not executable in {}",
            path.display()
        )));
    }

    let mut builder_uc = initialized_builder_emulator(&pe)?;
    let odd_stage2 = capture_builder_stage_samples(
        &mut builder_uc,
        path,
        builder_va,
        builder_va,
        2,
        SAMPLE_COUNT,
    )?;
    let call_targets = executable_direct_call_targets(&builder_uc, &pe, builder_va, 0x300)?;

    let mut even_stage2_candidates = Vec::new();
    for target_va in call_targets {
        if target_va == builder_va {
            continue;
        }
        let Ok(mut uc) = initialized_builder_emulator(&pe) else {
            continue;
        };
        let Ok(samples) =
            capture_builder_stage_samples(&mut uc, path, target_va, builder_va, 2, SAMPLE_COUNT)
        else {
            continue;
        };
        even_stage2_candidates.push((target_va, samples));
    }

    Ok(CxdecDispatchCapture {
        odd_stage2,
        even_stage2_candidates,
    })
}

fn initialized_builder_emulator(pe: &Pe32) -> Result<Unicorn<'static, EmuState>> {
    let mut uc = build_emulator(pe, false)?;
    run_dll_process_attach(&mut uc, pe)?;
    if let Some(v2_rva) = pe.export_rva("V2Link") {
        run_initialized_v2link_capture(&mut uc, pe, pe.image_base.wrapping_add(v2_rva))?;
    }
    Ok(uc)
}

fn capture_builder_stage_samples(
    uc: &mut Unicorn<'static, EmuState>,
    path: &Path,
    function_va: u32,
    configured_builder_va: u32,
    stage: u32,
    sample_count: u32,
) -> Result<Vec<(u32, Vec<u8>)>> {
    let mut samples = Vec::with_capacity(sample_count as usize);
    for seed in 0..sample_count {
        uc.mem_write(CXDEC_CODE_ADDR, &[0u8; CXDEC_CODE_BUDGET])
            .map_err(uc_error)?;
        write_u32_uc(uc, CXDEC_STATUS_ADDR + 0x00, CXDEC_CODE_ADDR as u32).map_err(uc_error)?;
        write_u32_uc(
            uc,
            CXDEC_STATUS_ADDR + 0x04,
            (CXDEC_CODE_ADDR + CXDEC_PROLOGUE_BYTES as u64) as u32,
        )
        .map_err(uc_error)?;
        write_u32_uc(uc, CXDEC_STATUS_ADDR + 0x08, CXDEC_CODE_BUDGET as u32).map_err(uc_error)?;
        write_u32_uc(uc, CXDEC_STATUS_ADDR + 0x0c, seed).map_err(uc_error)?;
        write_u32_uc(uc, CXDEC_STATUS_ADDR + 0x10, configured_builder_va).map_err(uc_error)?;
        {
            let state = uc.get_data_mut();
            state.last_api = None;
            state.unsupported_api = None;
        }
        reset_stack_for_call(uc, &[CXDEC_STATUS_ADDR as u32, stage])?;
        for reg in [
            RegisterX86::EAX,
            RegisterX86::EBX,
            RegisterX86::ECX,
            RegisterX86::EDX,
            RegisterX86::ESI,
            RegisterX86::EDI,
        ] {
            uc.reg_write(reg, 0).map_err(uc_error)?;
        }
        uc.emu_start(function_va as u64, RETURN_SENTINEL, TIMEOUT_US, MAX_STEPS)
            .map_err(|error| {
                Error::format(format!(
                    "CXDEC dispatch sampling failed in {} function=0x{function_va:08x} seed={seed} stage={stage}: {error:?}",
                    path.display()
                ))
            })?;
        if uc.reg_read(RegisterX86::EAX).map_err(uc_error)? as u32 == 0 {
            return Err(Error::format(format!(
                "CXDEC dispatch sampling function 0x{function_va:08x} rejected seed {seed} stage {stage}"
            )));
        }
        let curr = read_u32_uc(uc, CXDEC_STATUS_ADDR + 0x04).map_err(uc_error)?;
        let body_start = CXDEC_CODE_ADDR as u32 + CXDEC_PROLOGUE_BYTES;
        if curr < body_start || curr > CXDEC_CODE_ADDR as u32 + CXDEC_CODE_BUDGET as u32 {
            return Err(Error::format(format!(
                "CXDEC dispatch sampling produced invalid curr=0x{curr:08x}"
            )));
        }
        let mut body = vec![0u8; (curr - body_start) as usize];
        if !body.is_empty() {
            uc.mem_read(body_start as u64, &mut body)
                .map_err(uc_error)?;
        }
        samples.push((seed, body));
    }
    Ok(samples)
}

fn executable_direct_call_targets(
    uc: &Unicorn<'static, EmuState>,
    pe: &Pe32,
    function_va: u32,
    scan_len: usize,
) -> Result<Vec<u32>> {
    let available = pe
        .image_base
        .wrapping_add(pe.size_of_image)
        .saturating_sub(function_va) as usize;
    let mut code = vec![0u8; scan_len.min(available)];
    uc.mem_read(function_va as u64, &mut code)
        .map_err(uc_error)?;
    let mut targets = std::collections::BTreeSet::new();
    for index in 0..code.len().saturating_sub(4) {
        if code[index] != 0xe8 {
            continue;
        }
        let displacement = i32::from_le_bytes(code[index + 1..index + 5].try_into().unwrap());
        let target = function_va
            .wrapping_add(index as u32 + 5)
            .wrapping_add(displacement as u32);
        if pe.is_exec_va(target) {
            targets.insert(target);
        }
    }
    Ok(targets.into_iter().collect())
}

fn build_emulator(pe: &Pe32, trace_code: bool) -> Result<Unicorn<'static, EmuState>> {
    let mut uc = Unicorn::new_with_data(
        Arch::X86,
        Mode::MODE_32,
        EmuState::new(
            trace_code,
            pe.image_base,
            pe.size_of_image,
            pe.bytes.clone(),
        ),
    )
    .map_err(uc_error)?;
    let image = pe.virtual_image()?;
    let image_map_size = align_page(pe.size_of_image as u64);
    if ranges_overlap(pe.image_base as u64, image_map_size, HOST_BASE, HOST_SIZE)
        || ranges_overlap(pe.image_base as u64, image_map_size, STACK_BASE, STACK_SIZE)
        || ranges_overlap(
            pe.image_base as u64,
            image_map_size,
            INPUT_BASE,
            INPUT_RESERVE,
        )
        || ranges_overlap(pe.image_base as u64, image_map_size, DYN_BASE, DYN_SIZE)
    {
        return Err(Error::unsupported(format!(
            "PE preferred image base 0x{:08x} overlaps emulator reserved memory",
            pe.image_base
        )));
    }
    uc.mem_map(pe.image_base as u64, image_map_size, Prot::ALL)
        .map_err(uc_error)?;
    uc.mem_write(pe.image_base as u64, &image)
        .map_err(uc_error)?;
    uc.mem_map(STACK_BASE, STACK_SIZE, Prot::ALL)
        .map_err(uc_error)?;
    uc.mem_map(HOST_BASE, HOST_SIZE, Prot::ALL)
        .map_err(uc_error)?;
    uc.mem_map(DYN_BASE, DYN_SIZE, Prot::ALL)
        .map_err(uc_error)?;
    uc.mem_map(INPUT_BASE, INPUT_RESERVE, Prot::ALL)
        .map_err(uc_error)?;
    // PE32 MSVC exception prologues access the head of the SEH chain through
    // `fs:[0]`. Unicorn starts with a zero FS base, so provide the single low
    // page used by those deterministic setup/teardown instructions.
    uc.mem_map(0, PAGE, Prot::ALL).map_err(uc_error)?;

    // iTVPFunctionExporter is a COM-style interface: QueryFunctions receives
    // `this,names,functions,count` and removes all four arguments. SetFilter
    // is likewise stdcall with one argument.
    uc.mem_write(RETURN_SENTINEL, &[0xcc]).map_err(uc_error)?;
    uc.mem_write(QUERY_STUB, &[0xc2, 0x10, 0x00])
        .map_err(uc_error)?;
    uc.mem_write(SET_FILTER_STUB, &[0xc2, 0x04, 0x00])
        .map_err(uc_error)?;
    uc.mem_write(THROW_STUB, &[0xc2, 0x04, 0x00])
        .map_err(uc_error)?;
    uc.mem_write(GENERIC_TVP_STUB, &[0xc3]).map_err(uc_error)?;
    write_u32_uc(&mut uc, EXPORTER_OBJ, EXPORTER_VTBL as u32).map_err(uc_error)?;
    for i in 0..32u64 {
        // iTVPFunctionExporter::QueryFunctions is slot 1.  Other methods are
        // deliberately fail-fast: treating them as QueryFunctions corrupts
        // the stack/arguments and can create a false callback capture.
        let target = if i == 1 {
            QUERY_STUB as u32
        } else {
            GENERIC_TVP_STUB as u32
        };
        write_u32_uc(&mut uc, EXPORTER_VTBL + i * 4, target).map_err(uc_error)?;
    }

    uc.add_code_hook(QUERY_STUB, QUERY_STUB, |uc, _, _| {
        let Ok(esp) = uc.reg_read(RegisterX86::ESP) else {
            return;
        };
        let Ok(names) = read_u32_uc(uc, esp + 8) else {
            return;
        };
        let Ok(funcs) = read_u32_uc(uc, esp + 12) else {
            return;
        };
        let Ok(count) = read_u32_uc(uc, esp + 16) else {
            return;
        };
        let mut ok = true;
        for i in 0..count.min(256) {
            let name_ptr = read_u32_uc(uc, names as u64 + i as u64 * 4).unwrap_or(0);
            let name = read_c_string_uc(uc, name_ptr as u64, 1024)
                .unwrap_or_else(|| "<invalid>".to_string());
            let target = if name.contains("TVPSetXP3ArchiveExtractionFilter") {
                SET_FILTER_STUB as u32
            } else if name.contains("TVPThrowExceptionMessage") {
                THROW_STUB as u32
            } else {
                // Many plugins resolve engine functions during V2Link but do
                // not use them while registering the XP3 filter.  Give those
                // requests a sentinel function so QueryFunctions succeeds;
                // if one is actually called, the hook below stops cleanly.
                GENERIC_TVP_STUB as u32
            };
            uc.get_data_mut().requested_exports.push(name.clone());
            if write_u32_uc(uc, funcs as u64 + i as u64 * 4, target).is_err() {
                ok = false;
            }
        }
        let _ = uc.reg_write(RegisterX86::EAX, if ok { 1 } else { 0 });
    })
    .map_err(uc_error)?;

    uc.add_code_hook(SET_FILTER_STUB, SET_FILTER_STUB, |uc, _, _| {
        let Ok(esp) = uc.reg_read(RegisterX86::ESP) else {
            return;
        };
        if let Ok(callback) = read_u32_uc(uc, esp + 4) {
            uc.get_data_mut().captured_callback = Some(callback);
        }
    })
    .map_err(uc_error)?;

    uc.add_code_hook(THROW_STUB, THROW_STUB, |uc, _, _| {
        let Ok(esp) = uc.reg_read(RegisterX86::ESP) else {
            return;
        };
        let message_ptr = read_u32_uc(uc, esp + 4).unwrap_or(0);
        let message = read_utf16_string_uc(uc, message_ptr as u64, 2048)
            .unwrap_or_else(|| "<TVP exception>".into());
        uc.get_data_mut().unsupported_api = Some(format!("TVPThrowExceptionMessage: {message}"));
        let _ = uc.emu_stop();
    })
    .map_err(uc_error)?;

    uc.add_code_hook(GENERIC_TVP_STUB, GENERIC_TVP_STUB, |uc, _, _| {
        let name = uc
            .get_data()
            .requested_exports
            .last()
            .cloned()
            .unwrap_or_else(|| "<unknown>".into());
        uc.get_data_mut().unsupported_api = Some(format!(
            "unimplemented iTVPFunctionExporter/TVP function was called: {name}"
        ));
        let _ = uc.emu_stop();
    })
    .map_err(uc_error)?;

    install_import_stubs(&mut uc, pe)?;

    if trace_code {
        let image_begin = pe.image_base as u64;
        let image_end = image_begin + image_map_size - 1;
        uc.add_code_hook(image_begin, image_end, |uc, address, size| {
            if uc.get_data().trace_code {
                eprintln!("[x86-filter] code 0x{address:08x} size={size}");
            }
        })
        .map_err(uc_error)?;
        uc.add_code_hook(DYN_BASE, DYN_BASE + DYN_SIZE - 1, |uc, address, size| {
            if uc.get_data().trace_code {
                eprintln!("[x86-filter] generated-code 0x{address:08x} size={size}");
            }
        })
        .map_err(uc_error)?;
    }
    Ok(uc)
}

fn read_utf16_string_uc<D>(uc: &Unicorn<'_, D>, address: u64, max_units: usize) -> Option<String> {
    if address == 0 {
        return None;
    }
    let mut units = Vec::new();
    for i in 0..max_units {
        let mut b = [0u8; 2];
        uc.mem_read(address + i as u64 * 2, &mut b).ok()?;
        let u = u16::from_le_bytes(b);
        if u == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(u);
    }
    Some(String::from_utf16_lossy(&units))
}

fn run_v2link_capture(uc: &mut Unicorn<'static, EmuState>, v2link_va: u32) -> Result<u32> {
    {
        let state = uc.get_data_mut();
        state.captured_callback = None;
        state.requested_exports.clear();
        state.last_api = None;
        state.unsupported_api = None;
        state.file_trace.clear();
    }
    reset_stack_for_call(uc, &[EXPORTER_OBJ as u32])?;
    // KiriKiri TPMs exist in both MSVC/stdcall and Borland register-call
    // builds. Supplying the exporter in EAX as well as on the stack is benign
    // for the former and required by the latter (including the Fate sample).
    uc.reg_write(RegisterX86::EAX, EXPORTER_OBJ)
        .map_err(uc_error)?;
    uc.emu_start(v2link_va as u64, RETURN_SENTINEL, TIMEOUT_US, MAX_STEPS)
        .map_err(|e| {
            let eip = uc.reg_read(RegisterX86::EIP).unwrap_or(0);
            let esp = uc.reg_read(RegisterX86::ESP).unwrap_or(0);
            let ebp = uc.reg_read(RegisterX86::EBP).unwrap_or(0);
            let stack = uc
                .mem_read_as_vec(esp, 32)
                .map(|bytes| {
                    bytes
                        .chunks_exact(4)
                        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Error::format(format!(
                "V2Link emulation failed at 0x{v2link_va:08x}: {e:?}; eip=0x{eip:08x}; esp=0x{esp:08x}; ebp=0x{ebp:08x}; stack={stack:08x?}; last_api={:?}; unsupported_api={:?}",
                uc.get_data().last_api, uc.get_data().unsupported_api
            ))
        })?;
    if let Some(unsupported) = uc.get_data().unsupported_api.as_deref() {
        return Err(Error::unsupported(format!(
            "V2Link requires unsupported host behavior: {unsupported}; file_trace={:?}",
            uc.get_data().file_trace
        )));
    }
    uc.get_data().captured_callback.ok_or_else(|| {
        Error::format("V2Link returned without registering an XP3 extraction filter")
    })
}

fn run_initialized_v2link_capture(
    uc: &mut Unicorn<'static, EmuState>,
    pe: &Pe32,
    v2link_va: u32,
) -> Result<u32> {
    let has_external_host_auth_markers = pe
        .bytes
        .windows(b"OPT_EMBED_AREA_".len())
        .any(|window| window == b"OPT_EMBED_AREA_")
        && pe
            .bytes
            .windows(b"RELEASE_SIG____".len())
            .any(|window| window == b"RELEASE_SIG____");
    if has_external_host_auth_markers {
        let (auth_helper_va, branch_va, success_va) =
            find_external_host_auth_success_branch(pe, v2link_va)
            .ok_or_else(|| {
                Error::unsupported(
                    "external host authentication markers were found but the V2Link success guard could not be identified",
                )
            })?;
        let verifier_va = find_external_host_verifier(pe, auth_helper_va).ok_or_else(|| {
            Error::unsupported(
                "external host authentication helper was found but its terminal verifier could not be identified",
            )
        })?;
        // Preserve the helper's module-range/config side effects and replace
        // only the terminal signature verifier whose host executable is not
        // part of a standalone plugin sample.
        uc.mem_write(verifier_va as u64, &[0xb0, 0x01, 0xc3])
            .map_err(uc_error)?;
        uc.get_data_mut().initialization_notes.push(format!(
            "external host executable was unavailable; preserved host-auth helper 0x{auth_helper_va:08x} side effects and substituted terminal verifier 0x{verifier_va:08x}, preserving V2Link guard 0x{branch_va:08x} -> 0x{success_va:08x}"
        ));
    }
    run_v2link_capture(uc, v2link_va)
}

fn find_external_host_verifier(pe: &Pe32, auth_helper_va: u32) -> Option<u32> {
    let helper_rva = auth_helper_va.checked_sub(pe.image_base)?;
    let offset = pe.rva_to_offset(helper_rva)?;
    let bytes = pe
        .bytes
        .get(offset..offset.saturating_add(0x100).min(pe.bytes.len()))?;
    let function_end = bytes
        .windows(8)
        .position(|window| window.iter().all(|byte| matches!(byte, 0x90 | 0xcc)))?;
    let call_index = (0..function_end.saturating_sub(4))
        .rev()
        .find(|index| bytes[*index] == 0xe8)?;
    let displacement = i32::from_le_bytes(bytes[call_index + 1..call_index + 5].try_into().ok()?);
    let verifier_rva = helper_rva
        .checked_add(call_index as u32 + 5)?
        .wrapping_add(displacement as u32);
    pe.sections
        .iter()
        .any(|section| section.executable() && section.contains_rva(verifier_rva))
        .then_some(pe.image_base.wrapping_add(verifier_rva))
}

fn find_external_host_auth_success_branch(pe: &Pe32, v2link_va: u32) -> Option<(u32, u32, u32)> {
    let mut entry_rva = v2link_va.checked_sub(pe.image_base)?;
    for _ in 0..3 {
        let offset = pe.rva_to_offset(entry_rva)?;
        let bytes = pe
            .bytes
            .get(offset..offset.saturating_add(0x100).min(pe.bytes.len()))?;

        if let Some((index, jump)) = bytes
            .windows(5)
            .enumerate()
            .find(|(index, window)| *index < 0x20 && window[0] == 0xe9)
        {
            let displacement = i32::from_le_bytes(jump[1..5].try_into().ok()?);
            entry_rva = entry_rva
                .checked_add(index as u32 + 5)?
                .wrapping_add(displacement as u32);
            continue;
        }

        for index in 2..bytes.len().saturating_sub(2) {
            if bytes[index - 2..=index] != [0x84, 0xc0, 0x75] {
                continue;
            }
            let branch_rva = entry_rva.checked_add(index as u32)?;
            let success_rva = branch_rva
                .checked_add(2)?
                .wrapping_add(bytes[index + 1] as i8 as i32 as u32);
            if success_rva <= branch_rva || success_rva >= entry_rva.saturating_add(0x100) {
                continue;
            }
            let failure_start = index + 2;
            let failure_end = (success_rva - entry_rva) as usize;
            if failure_end <= failure_start
                || !bytes[failure_start..failure_end]
                    .windows(2)
                    .any(|window| window == [0xff, 0xd0])
            {
                continue;
            }
            let call_index = (0..index.saturating_sub(2)).rev().find(|candidate| {
                *candidate + 5 <= index.saturating_sub(2) && bytes[*candidate] == 0xe8
            })?;
            let displacement =
                i32::from_le_bytes(bytes[call_index + 1..call_index + 5].try_into().ok()?);
            let helper_rva = entry_rva
                .checked_add(call_index as u32 + 5)?
                .wrapping_add(displacement as u32);
            if !pe
                .sections
                .iter()
                .any(|section| section.executable() && section.contains_rva(helper_rva))
            {
                continue;
            }
            return Some((
                pe.image_base.wrapping_add(helper_rva),
                pe.image_base.wrapping_add(branch_rva),
                pe.image_base.wrapping_add(success_rva),
            ));
        }
        return None;
    }
    None
}

fn run_dll_process_attach(uc: &mut Unicorn<'static, EmuState>, pe: &Pe32) -> Result<()> {
    if pe.entry_point_rva == 0 {
        return Ok(());
    }
    let entry = pe.image_base.wrapping_add(pe.entry_point_rva);
    reset_stack_for_call(uc, &[pe.image_base, 1, 0])?;
    for reg in [
        RegisterX86::EAX,
        RegisterX86::EBX,
        RegisterX86::ECX,
        RegisterX86::EDX,
        RegisterX86::ESI,
        RegisterX86::EDI,
    ] {
        uc.reg_write(reg, 0).map_err(uc_error)?;
    }
    uc.emu_start(entry as u64, RETURN_SENTINEL, TIMEOUT_US, MAX_STEPS)
        .map_err(|error| {
            let eip = uc.reg_read(RegisterX86::EIP).unwrap_or(0);
            Error::format(format!(
                "DLL_PROCESS_ATTACH failed at 0x{entry:08x}: {error:?}; eip=0x{eip:08x}; last_api={:?}; unsupported_api={:?}",
                uc.get_data().last_api,
                uc.get_data().unsupported_api
            ))
        })?;
    if let Some(unsupported) = uc.get_data().unsupported_api.as_deref() {
        return Err(Error::unsupported(format!(
            "DLL_PROCESS_ATTACH requires unsupported host behavior: {unsupported}"
        )));
    }
    Ok(())
}

fn reset_stack_for_call(uc: &mut Unicorn<'static, EmuState>, args: &[u32]) -> Result<()> {
    let sp = STACK_BASE + STACK_SIZE - 0x1000;
    write_u32_uc(uc, sp, RETURN_SENTINEL as u32).map_err(uc_error)?;
    for (i, arg) in args.iter().enumerate() {
        write_u32_uc(uc, sp + 4 + i as u64 * 4, *arg).map_err(uc_error)?;
    }
    uc.reg_write(RegisterX86::ESP, sp).map_err(uc_error)?;
    uc.reg_write(RegisterX86::EBP, sp + 0x800)
        .map_err(uc_error)?;
    Ok(())
}

fn install_import_stubs(uc: &mut Unicorn<'static, EmuState>, pe: &Pe32) -> Result<()> {
    // Install a stable set first so dynamically-resolved imports such as
    // GetProcAddress("VirtualAlloc") work even when the symbol is absent from
    // the PE's static import table.
    let builtin_names = [
        "VirtualAlloc",
        "VirtualQuery",
        "VirtualFree",
        "VirtualProtect",
        "HeapAlloc",
        "HeapReAlloc",
        "HeapFree",
        "HeapSize",
        "HeapCreate",
        "HeapDestroy",
        "GetProcessHeap",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "FreeLibrary",
        "GetProcAddress",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetModuleFileNameA",
        "GetModuleFileNameW",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetTickCount",
        "QueryPerformanceCounter",
        "GetSystemTimeAsFileTime",
        "IsProcessorFeaturePresent",
        "EncodePointer",
        "DecodePointer",
        "IsDebuggerPresent",
        "Sleep",
        "TlsAlloc",
        "TlsGetValue",
        "TlsSetValue",
        "TlsFree",
        "FlsAlloc",
        "FlsGetValue",
        "FlsSetValue",
        "FlsFree",
        "GetLastError",
        "SetLastError",
        "GetACP",
        "GetOEMCP",
        "GetConsoleCP",
        "GetConsoleOutputCP",
        "GetUserDefaultLCID",
        "GetSystemDefaultLCID",
        "GetThreadLocale",
        "GetLocaleInfoA",
        "GetLocaleInfoW",
        "GetCPInfo",
        "IsValidCodePage",
        "IsDBCSLeadByte",
        "IsDBCSLeadByteEx",
        "MultiByteToWideChar",
        "WideCharToMultiByte",
        "InitializeCriticalSection",
        "DeleteCriticalSection",
        "EnterCriticalSection",
        "LeaveCriticalSection",
        "TryEnterCriticalSection",
        "InitializeCriticalSectionAndSpinCount",
        "InitializeCriticalSectionEx",
        "memcpy",
        "memmove",
        "memset",
        "malloc",
        "calloc",
        "realloc",
        "free",
    ];
    let mut next_stub = API_STUB_BASE;
    for name in builtin_names {
        install_one_api_stub(uc, name, Win32Api::from_name(name), &mut next_stub)?;
    }

    for import in &pe.imports {
        let address = if let Some(address) = uc.get_data().win32.resolve_export(&import.name) {
            address
        } else {
            install_one_api_stub(
                uc,
                &import.name,
                Win32Api::from_name(&import.name),
                &mut next_stub,
            )?
        };
        write_u32_uc(uc, pe.image_base as u64 + import.iat_rva as u64, address)
            .map_err(uc_error)?;
    }
    Ok(())
}

fn install_one_api_stub(
    uc: &mut Unicorn<'static, EmuState>,
    name: &str,
    api: Win32Api,
    next_stub: &mut u64,
) -> Result<u32> {
    if let Some(address) = uc.get_data().win32.resolve_export(name) {
        return Ok(address);
    }
    let stub = *next_stub;
    *next_stub = stub.saturating_add(0x10);
    if stub + 0x10 >= HOST_BASE + HOST_SIZE {
        return Err(Error::format("too many PE imports for emulator stub area"));
    }
    let stack = api.stack_bytes();
    let ret = if stack == 0 {
        vec![0xc3]
    } else {
        vec![0xc2, (stack & 0xff) as u8, (stack >> 8) as u8]
    };
    uc.mem_write(stub, &ret).map_err(uc_error)?;
    let hook_api = api.clone();
    let hook_name = name.to_string();
    uc.add_code_hook(stub, stub, move |uc, _, _| {
        emulate_kernel_api(uc, &hook_api, &hook_name);
    })
    .map_err(uc_error)?;
    uc.get_data_mut()
        .win32
        .register_export(name.to_string(), stub as u32);
    Ok(stub as u32)
}

fn emulate_kernel_api(uc: &mut Unicorn<'_, EmuState>, api: &Win32Api, name: &str) {
    uc.get_data_mut().last_api = Some(name.to_string());
    let esp = match uc.reg_read(RegisterX86::ESP) {
        Ok(v) => v,
        Err(_) => return,
    };
    let arg = |uc: &Unicorn<'_, EmuState>, n: u64| -> u32 {
        read_u32_uc(uc, esp + 4 + n * 4).unwrap_or(0)
    };
    match api {
        Win32Api::VirtualAlloc => {
            let requested_addr = arg(uc, 0) as u64;
            let size = arg(uc, 1) as usize;
            let ptr = if (DYN_BASE..DYN_BASE + DYN_SIZE).contains(&requested_addr) {
                if uc.get_data_mut().win32.reserve(requested_addr, size) {
                    requested_addr
                } else {
                    0
                }
            } else {
                uc.get_data_mut().allocate(size).unwrap_or(0)
            };
            let _ = uc.reg_write(RegisterX86::EAX, ptr);
        }
        Win32Api::VirtualQuery => {
            let address = arg(uc, 0);
            let output = arg(uc, 1) as u64;
            let output_size = arg(uc, 2) as usize;
            // Win32 MEMORY_BASIC_INFORMATION is 28 bytes. The self-decoding
            // TPMs use it only to establish the queried page and protection;
            // report a deterministic committed executable/read/write page.
            let mut info = [0u8; 28];
            let page = address & !0xfff;
            for (offset, value) in [
                (0usize, page), // BaseAddress
                (4, page),      // AllocationBase
                (8, 0x40),      // AllocationProtect: PAGE_EXECUTE_READWRITE
                (12, 0x1000),   // RegionSize
                (16, 0x1000),   // State: MEM_COMMIT
                (20, 0x40),     // Protect
                (24, 0x20_000), // Type: MEM_PRIVATE
            ] {
                info[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            let returned = output_size.min(info.len());
            if output == 0 || uc.mem_write(output, &info[..returned]).is_err() {
                let _ = uc.reg_write(RegisterX86::EAX, 0);
            } else {
                let _ = uc.reg_write(RegisterX86::EAX, returned as u64);
            }
        }
        Win32Api::VirtualFree => {
            let pointer = arg(uc, 0) as u64;
            let ok = uc.get_data_mut().free_allocation(pointer);
            if !ok {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
            }
            let _ = uc.reg_write(RegisterX86::EAX, u64::from(ok));
        }
        Win32Api::VirtualProtect => {
            let old_ptr = arg(uc, 3) as u64;
            if old_ptr != 0 {
                let _ = write_u32_uc(uc, old_ptr, 0x40);
            }
            let _ = uc.reg_write(RegisterX86::EAX, 1);
        }
        Win32Api::HeapAlloc => {
            let flags = arg(uc, 1);
            let size = arg(uc, 2) as usize;
            let ptr = uc.get_data_mut().allocate(size).unwrap_or(0);
            if ptr != 0 && flags & 0x0000_0008 != 0 {
                let _ = uc.mem_write(ptr, &vec![0u8; size]);
            }
            let _ = uc.reg_write(RegisterX86::EAX, ptr);
        }
        Win32Api::HeapReAlloc => {
            let old_ptr = arg(uc, 2) as u64;
            let size = arg(uc, 3) as usize;
            let old_size = uc.get_data().win32.allocation_size(old_ptr).unwrap_or(0);
            let ptr = uc.get_data_mut().allocate(size).unwrap_or(0);
            if ptr != 0 && old_ptr != 0 && old_size != 0 {
                let copy_len = old_size.min(size);
                if let Ok(data) = uc.mem_read_as_vec(old_ptr, copy_len) {
                    let _ = uc.mem_write(ptr, &data);
                }
                uc.get_data_mut().free_allocation(old_ptr);
            }
            let _ = uc.reg_write(RegisterX86::EAX, ptr);
        }
        Win32Api::HeapFree => {
            let pointer = arg(uc, 2) as u64;
            let ok = uc.get_data_mut().free_allocation(pointer);
            if !ok {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
            }
            let _ = uc.reg_write(RegisterX86::EAX, u64::from(ok));
        }
        Win32Api::HeapSize => {
            let pointer = arg(uc, 2) as u64;
            let size = uc.get_data().win32.allocation_size(pointer);
            if size.is_none() {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
            }
            let _ = uc.reg_write(
                RegisterX86::EAX,
                size.map(|size| size as u64).unwrap_or(u32::MAX as u64),
            );
        }
        Win32Api::HeapDestroy
        | Win32Api::FreeLibrary
        | Win32Api::CriticalSection
        | Win32Api::CriticalSectionSpin
        | Win32Api::CriticalSectionEx => {
            let _ = uc.reg_write(RegisterX86::EAX, 1);
        }
        Win32Api::HeapCreate | Win32Api::GetProcessHeap => {
            let _ = uc.reg_write(RegisterX86::EAX, 0x1337_0000);
        }
        Win32Api::LoadLibrary | Win32Api::LoadLibraryEx => {
            let path_ptr = arg(uc, 0) as u64;
            let module = if name.ends_with('W') {
                read_utf16_string_uc(uc, path_ptr, 1024)
            } else {
                read_c_string_uc(uc, path_ptr, 1024)
            };
            let handle = if let Some(module) = module {
                uc.get_data_mut().win32.load_module(&module)
            } else {
                uc.get_data_mut().win32.set_last_error(ERROR_MOD_NOT_FOUND);
                0
            };
            let _ = uc.reg_write(RegisterX86::EAX, handle as u64);
        }
        Win32Api::GetModuleHandle => {
            let path_ptr = arg(uc, 0) as u64;
            let handle = if path_ptr == 0 {
                uc.get_data().module_image_base
            } else {
                let module = if name.ends_with('W') {
                    read_utf16_string_uc(uc, path_ptr, 1024)
                } else {
                    read_c_string_uc(uc, path_ptr, 1024)
                };
                module
                    .as_deref()
                    .and_then(|module| uc.get_data().win32.module_handle(module))
                    .unwrap_or(0)
            };
            if handle == 0 {
                uc.get_data_mut().win32.set_last_error(ERROR_MOD_NOT_FOUND);
            }
            let _ = uc.reg_write(RegisterX86::EAX, handle as u64);
        }
        Win32Api::GetModuleFileNameA | Win32Api::GetModuleFileNameW => {
            let module = arg(uc, 0) as u64;
            let output = arg(uc, 1) as u64;
            let capacity = arg(uc, 2) as usize;
            let wide = matches!(api, Win32Api::GetModuleFileNameW);
            let path = if (HOST_BASE..HOST_BASE + HOST_SIZE).contains(&module) {
                "C:\\game\\game.exe\0"
            } else {
                "C:\\game\\module.tpm\0"
            };
            let bytes = if wide {
                path.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            } else {
                path.as_bytes().to_vec()
            };
            let unit = if wide { 2 } else { 1 };
            let writable = capacity.saturating_mul(unit).min(bytes.len());
            if output == 0 || uc.mem_write(output, &bytes[..writable]).is_err() {
                let _ = uc.reg_write(RegisterX86::EAX, 0);
            } else {
                let chars = bytes.len().saturating_sub(unit) / unit;
                let _ = uc.reg_write(RegisterX86::EAX, chars.min(capacity) as u64);
            }
        }
        Win32Api::GetProcAddress => {
            let name_ptr = arg(uc, 1) as u64;
            let sym = if name_ptr < 0x10000 {
                format!("#{name_ptr}")
            } else {
                read_c_string_uc(uc, name_ptr, 512).unwrap_or_else(|| "<invalid>".into())
            };
            let address = uc.get_data().win32.resolve_export(&sym).unwrap_or(0);
            if address == 0 {
                uc.get_data_mut().win32.set_last_error(ERROR_PROC_NOT_FOUND);
            }
            let _ = uc.reg_write(RegisterX86::EAX, address as u64);
        }
        Win32Api::GetCurrentProcess => {
            let _ = uc.reg_write(RegisterX86::EAX, 0xffff_ffff);
        }
        Win32Api::GetCurrentProcessId => {
            let _ = uc.reg_write(RegisterX86::EAX, 0x1234);
        }
        Win32Api::GetCurrentThreadId => {
            let _ = uc.reg_write(RegisterX86::EAX, 1);
        }
        Win32Api::GetTickCount => {
            let _ = uc.reg_write(RegisterX86::EAX, 0x1234_5678);
        }
        Win32Api::QueryPerformanceCounter => {
            let ptr = arg(uc, 0) as u64;
            if ptr != 0 {
                let _ = write_u64_uc(uc, ptr, 0x0123_4567_89ab_cdef);
            }
            let _ = uc.reg_write(RegisterX86::EAX, 1);
        }
        Win32Api::IsDebuggerPresent => {
            let _ = uc.reg_write(RegisterX86::EAX, 0);
        }
        Win32Api::Sleep => {}
        Win32Api::TlsAlloc | Win32Api::FlsAlloc => {
            let index = uc.get_data_mut().win32.tls_alloc();
            let _ = uc.reg_write(RegisterX86::EAX, index as u64);
        }
        Win32Api::TlsGetValue => {
            let idx = arg(uc, 0);
            let value = uc.get_data_mut().win32.tls_get(idx).unwrap_or(0);
            let _ = uc.reg_write(RegisterX86::EAX, value as u64);
        }
        Win32Api::TlsSetValue => {
            let idx = arg(uc, 0);
            let value = arg(uc, 1);
            let ok = uc.get_data_mut().win32.tls_set(idx, value);
            let _ = uc.reg_write(RegisterX86::EAX, u64::from(ok));
        }
        Win32Api::TlsFree => {
            let index = arg(uc, 0);
            let ok = uc.get_data_mut().win32.tls_free(index);
            let _ = uc.reg_write(RegisterX86::EAX, u64::from(ok));
        }
        Win32Api::Memcpy | Win32Api::Memmove => {
            let dst = arg(uc, 0) as u64;
            let src = arg(uc, 1) as u64;
            let len = arg(uc, 2) as usize;
            let copied = uc
                .mem_read_as_vec(src, len)
                .and_then(|data| uc.mem_write(dst, &data));
            if copied.is_err() {
                uc.get_data_mut().unsupported_api = Some(format!("{name} touched unmapped memory"));
                let _ = uc.emu_stop();
            }
            let _ = uc.reg_write(RegisterX86::EAX, dst);
        }
        Win32Api::Memset => {
            let dst = arg(uc, 0) as u64;
            let value = arg(uc, 1) as u8;
            let len = arg(uc, 2) as usize;
            let data = vec![value; len];
            if uc.mem_write(dst, &data).is_err() {
                uc.get_data_mut().unsupported_api = Some(format!("{name} touched unmapped memory"));
                let _ = uc.emu_stop();
            }
            let _ = uc.reg_write(RegisterX86::EAX, dst);
        }
        Win32Api::Malloc => {
            let size = arg(uc, 0) as usize;
            let ptr = uc.get_data_mut().allocate(size).unwrap_or(0);
            let _ = uc.reg_write(RegisterX86::EAX, ptr);
        }
        Win32Api::Calloc => {
            let count = arg(uc, 0) as usize;
            let size = arg(uc, 1) as usize;
            let total = count.checked_mul(size).unwrap_or(usize::MAX);
            let ptr = uc.get_data_mut().allocate(total).unwrap_or(0);
            if ptr != 0 && total != 0 {
                let zeros = vec![0u8; total];
                let _ = uc.mem_write(ptr, &zeros);
            }
            let _ = uc.reg_write(RegisterX86::EAX, ptr);
        }
        Win32Api::Realloc => {
            let old_ptr = arg(uc, 0) as u64;
            let size = arg(uc, 1) as usize;
            let old_size = uc.get_data().win32.allocation_size(old_ptr).unwrap_or(0);
            let ptr = uc.get_data_mut().allocate(size).unwrap_or(0);
            if ptr != 0 && old_ptr != 0 && old_size != 0 {
                let copy_len = old_size.min(size);
                if let Ok(data) = uc.mem_read_as_vec(old_ptr, copy_len) {
                    let _ = uc.mem_write(ptr, &data);
                }
                uc.get_data_mut().free_allocation(old_ptr);
            }
            let _ = uc.reg_write(RegisterX86::EAX, ptr);
        }
        Win32Api::Free => {
            let pointer = arg(uc, 0) as u64;
            if pointer != 0 {
                uc.get_data_mut().free_allocation(pointer);
            }
            let _ = uc.reg_write(RegisterX86::EAX, 0);
        }
        Win32Api::Unknown(sym) => {
            if !emulate_win32_compat_api(uc, sym, esp) {
                uc.get_data_mut().unsupported_api =
                    Some(format!("unimplemented import {name} ({sym})"));
                let _ = uc.reg_write(RegisterX86::EAX, 0);
                let _ = uc.emu_stop();
            }
        }
    }
}

fn emulate_win32_compat_api(uc: &mut Unicorn<'_, EmuState>, name: &str, esp: u64) -> bool {
    let arg = |uc: &Unicorn<'_, EmuState>, n: u64| -> u32 {
        read_u32_uc(uc, esp + 4 + n * 4).unwrap_or(0)
    };
    let set_eax = |uc: &mut Unicorn<'_, EmuState>, value: u64| {
        let _ = uc.reg_write(RegisterX86::EAX, value);
    };
    match name {
        "GetVersion" => set_eax(uc, 0x0000_0005),
        "GetLastError" => set_eax(uc, uc.get_data().win32.last_error() as u64),
        "SetLastError" => {
            let error = arg(uc, 0);
            uc.get_data_mut().win32.set_last_error(error);
            set_eax(uc, 0);
        }
        "GetACP" => set_eax(uc, uc.get_data().win32.profile.ansi_code_page as u64),
        "GetOEMCP" => set_eax(uc, uc.get_data().win32.profile.oem_code_page as u64),
        "GetConsoleCP" | "GetConsoleOutputCP" => {
            set_eax(uc, uc.get_data().win32.profile.ansi_code_page as u64)
        }
        "GetUserDefaultLCID" | "GetThreadLocale" => {
            set_eax(uc, uc.get_data().win32.profile.user_lcid as u64)
        }
        "GetSystemDefaultLCID" => set_eax(uc, uc.get_data().win32.profile.system_lcid as u64),
        "GetLocaleInfoA" | "GetLocaleInfoW" => {
            let locale = arg(uc, 0);
            let locale_type = arg(uc, 1);
            let output = arg(uc, 2) as u64;
            let capacity = arg(uc, 3) as i32;
            let wide = name.ends_with('W');
            let value = uc.get_data_mut().win32.locale_info_a(locale, locale_type);
            uc.get_data_mut().initialization_notes.push(format!(
                "{name}(locale=0x{locale:08x}, type=0x{locale_type:08x}, capacity={capacity})"
            ));
            if uc.get_data().trace_code {
                eprintln!(
                    "[x86-filter] {name} locale=0x{locale:08x} type=0x{locale_type:08x} capacity={capacity}"
                );
            }
            let Some(value) = value else {
                set_eax(uc, 0);
                return true;
            };
            let bytes = match (wide, value) {
                (_, LocaleInfoValue::Number(number)) => number.to_le_bytes().to_vec(),
                (false, LocaleInfoValue::Ansi(bytes)) => bytes,
                (true, LocaleInfoValue::Ansi(bytes)) => {
                    let text = &bytes[..bytes.len().saturating_sub(1)];
                    let mut units = decode_ansi(932, text, false).unwrap_or_default();
                    units.push(0);
                    units.into_iter().flat_map(u16::to_le_bytes).collect()
                }
            };
            let unit = if wide { 2 } else { 1 };
            let required = bytes.len() / unit;
            if capacity == 0 {
                set_eax(uc, required as u64);
            } else if capacity < 0
                || output == 0
                || (capacity as usize).saturating_mul(unit) < bytes.len()
            {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INSUFFICIENT_BUFFER);
                set_eax(uc, 0);
            } else if uc.mem_write(output, &bytes).is_ok() {
                set_eax(uc, required as u64);
            } else {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
                set_eax(uc, 0);
            }
        }
        "GetSystemTimeAsFileTime" => {
            let ptr = arg(uc, 0) as u64;
            if ptr != 0 {
                let _ = write_u64_uc(uc, ptr, 0x01d9_0000_1234_5678);
            }
            set_eax(uc, 0);
        }
        "IsProcessorFeaturePresent" => set_eax(uc, 0),
        "EncodePointer" | "DecodePointer" => set_eax(uc, arg(uc, 0) as u64),
        "GetCommandLineA" => {
            let bytes = b"C:\\game\\game.exe\0";
            let ptr = uc.get_data_mut().allocate(bytes.len()).unwrap_or(0);
            if ptr != 0 {
                let _ = uc.mem_write(ptr, bytes);
            }
            set_eax(uc, ptr);
        }
        "GetEnvironmentStrings" | "GetEnvironmentStringsA" => {
            let bytes = b"PATH=C:\\Windows\0\0";
            let ptr = uc.get_data_mut().allocate(bytes.len()).unwrap_or(0);
            if ptr != 0 {
                let _ = uc.mem_write(ptr, bytes);
            }
            set_eax(uc, ptr);
        }
        "GetEnvironmentStringsW" => {
            let bytes = "PATH=C:\\Windows\0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            let ptr = uc.get_data_mut().allocate(bytes.len()).unwrap_or(0);
            if ptr != 0 {
                let _ = uc.mem_write(ptr, &bytes);
            }
            set_eax(uc, ptr);
        }
        "FreeEnvironmentStringsA"
        | "FreeEnvironmentStringsW"
        | "FlushFileBuffers"
        | "FlushInstructionCache"
        | "SetEndOfFile"
        | "SetStdHandle"
        | "SetHandleCount" => set_eax(uc, 1),
        "GetEnvironmentVariableA" => set_eax(uc, 0),
        "GetSystemDirectoryA" => {
            let output = arg(uc, 0) as u64;
            let capacity = arg(uc, 1) as usize;
            let path = b"C:\\Windows\\System32\0";
            if output != 0 && capacity >= path.len() && uc.mem_write(output, path).is_ok() {
                set_eax(uc, (path.len() - 1) as u64);
            } else {
                set_eax(uc, path.len() as u64);
            }
        }
        "lstrcmpiA" => {
            let left = read_c_string_uc(uc, arg(uc, 0) as u64, 4096).unwrap_or_default();
            let right = read_c_string_uc(uc, arg(uc, 1) as u64, 4096).unwrap_or_default();
            let ordering = left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase());
            let value = match ordering {
                std::cmp::Ordering::Less => -1i32,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            set_eax(uc, value as u32 as u64);
        }
        "FindFirstFileW" => {
            uc.get_data_mut().win32.set_last_error(2);
            set_eax(uc, 0xffff_ffff);
        }
        "FindNextFileW" => {
            uc.get_data_mut().win32.set_last_error(18);
            set_eax(uc, 0);
        }
        "FindClose" => set_eax(uc, 1),
        "GetStdHandle" => set_eax(uc, 0xffff_ffff),
        "GetFileType" => set_eax(uc, 1),
        "SetUnhandledExceptionFilter" => set_eax(uc, 0),
        "IsBadWritePtr" | "IsBadReadPtr" | "IsBadCodePtr" => set_eax(uc, 0),
        "InterlockedIncrement" | "InterlockedDecrement" => {
            let ptr = arg(uc, 0) as u64;
            let old = read_u32_uc(uc, ptr).unwrap_or(0);
            let value = if name == "InterlockedIncrement" {
                old.wrapping_add(1)
            } else {
                old.wrapping_sub(1)
            };
            let _ = write_u32_uc(uc, ptr, value);
            set_eax(uc, value as u64);
        }
        "GetStartupInfoA" | "GetStartupInfoW" => {
            let ptr = arg(uc, 0) as u64;
            let mut info = [0u8; 68];
            info[..4].copy_from_slice(&68u32.to_le_bytes());
            let ok = ptr != 0 && uc.mem_write(ptr, &info).is_ok();
            set_eax(uc, u64::from(ok));
        }
        "GetVersionExA" => {
            let ptr = arg(uc, 0) as u64;
            let size = read_u32_uc(uc, ptr).unwrap_or(0).min(148) as usize;
            let mut info = [0u8; 148];
            info[..4].copy_from_slice(&(size as u32).to_le_bytes());
            info[4..8].copy_from_slice(&5u32.to_le_bytes());
            info[8..12].copy_from_slice(&1u32.to_le_bytes());
            info[12..16].copy_from_slice(&2600u32.to_le_bytes());
            let ok = ptr != 0 && size >= 20 && uc.mem_write(ptr, &info[..size]).is_ok();
            set_eax(uc, u64::from(ok));
        }
        "GetCPInfo" => {
            let code_page = uc.get_data().win32.profile.resolve_code_page(arg(uc, 0));
            let ptr = arg(uc, 1) as u64;
            let mut info = [0u8; 20];
            info[..4].copy_from_slice(&2u32.to_le_bytes());
            info[4] = b'?';
            info[6..10].copy_from_slice(&[0x81, 0x9f, 0xe0, 0xfc]);
            let ok = code_page == Some(932) && ptr != 0 && uc.mem_write(ptr, &info).is_ok();
            if !ok {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
            }
            set_eax(uc, u64::from(ok));
        }
        "IsValidCodePage" => {
            let valid = uc
                .get_data()
                .win32
                .profile
                .resolve_code_page(arg(uc, 0))
                .is_some();
            set_eax(uc, u64::from(valid));
        }
        "IsDBCSLeadByte" | "IsDBCSLeadByteEx" => {
            let byte = if name == "IsDBCSLeadByte" {
                arg(uc, 0) as u8
            } else {
                arg(uc, 1) as u8
            };
            let code_page = if name == "IsDBCSLeadByte" {
                Some(uc.get_data().win32.profile.ansi_code_page)
            } else {
                uc.get_data().win32.profile.resolve_code_page(arg(uc, 0))
            };
            let lead = code_page == Some(932)
                && ((0x81..=0x9f).contains(&byte) || (0xe0..=0xfc).contains(&byte));
            set_eax(uc, u64::from(lead));
        }
        "CreateFileA" => {
            let path =
                read_c_string_uc(uc, arg(uc, 0) as u64, 4096).unwrap_or_else(|| "<invalid>".into());
            let caller = read_u32_uc(uc, esp).unwrap_or(0);
            let access = arg(uc, 1);
            let creation = arg(uc, 4);
            let state = uc.get_data_mut();
            state.file_cursor = 0;
            state.file_open = true;
            state.opened_file = if path.to_ascii_lowercase().ends_with("game.exe") {
                state.host_file.clone()
            } else {
                state.module_file.clone()
            };
            state.file_trace.push(format!(
                "CreateFileA(caller=0x{caller:08x}, path={path:?}, access=0x{access:08x}, creation={creation})"
            ));
            set_eax(uc, 0x4444);
        }
        "CloseHandle" => {
            let handle = arg(uc, 0);
            if handle == 0x4444 {
                let state = uc.get_data_mut();
                state.file_open = false;
                state.file_trace.push("CloseHandle(module)".into());
            }
            set_eax(uc, 1);
        }
        "ReadFile" => {
            let handle = arg(uc, 0);
            let output = arg(uc, 1) as u64;
            let requested = arg(uc, 2) as usize;
            let transferred = arg(uc, 3) as u64;
            let caller = read_u32_uc(uc, esp).unwrap_or(0);
            let (data, next) = {
                let state = uc.get_data();
                if handle != 0x4444 || !state.file_open {
                    (Vec::new(), state.file_cursor)
                } else {
                    let end = state
                        .file_cursor
                        .saturating_add(requested)
                        .min(state.opened_file.len());
                    (state.opened_file[state.file_cursor..end].to_vec(), end)
                }
            };
            let ok = handle == 0x4444 && uc.mem_write(output, &data).is_ok();
            if ok {
                uc.get_data_mut().file_cursor = next;
            }
            if transferred != 0 {
                let _ = write_u32_uc(uc, transferred, data.len() as u32);
            }
            uc.get_data_mut().file_trace.push(format!(
                "ReadFile(caller=0x{caller:08x}, handle=0x{handle:08x}, requested={requested}, read={}, next={next}, ok={ok})",
                data.len()
            ));
            set_eax(uc, u64::from(ok));
        }
        "WriteFile" => {
            let transferred = arg(uc, 3) as u64;
            if transferred != 0 {
                let _ = write_u32_uc(uc, transferred, 0);
            }
            set_eax(uc, 0);
        }
        "SetFilePointer" => {
            let handle = arg(uc, 0);
            let distance = arg(uc, 1) as i32 as i64;
            let high_ptr = arg(uc, 2);
            let method = arg(uc, 3);
            let caller = read_u32_uc(uc, esp).unwrap_or(0);
            let current = uc.get_data().file_cursor as i64;
            let end = uc.get_data().opened_file.len() as i64;
            let base = match method {
                0 => 0,
                1 => current,
                2 => end,
                _ => -1,
            };
            let next = base.saturating_add(distance);
            if handle == 0x4444 && next >= 0 && next <= end {
                uc.get_data_mut().file_cursor = next as usize;
                set_eax(uc, next as u64);
            } else {
                set_eax(uc, 0xffff_ffff);
            }
            uc.get_data_mut().file_trace.push(format!(
                "SetFilePointer(caller=0x{caller:08x}, handle=0x{handle:08x}, distance={distance}, high_ptr=0x{high_ptr:08x}, method={method}, current={current}, next={next})"
            ));
        }
        "MultiByteToWideChar" => {
            let requested_code_page = arg(uc, 0);
            let flags = arg(uc, 1);
            let src = arg(uc, 2) as u64;
            let requested = arg(uc, 3) as i32;
            let dst = arg(uc, 4) as u64;
            let capacity = arg(uc, 5) as usize;
            let code_page = uc
                .get_data()
                .win32
                .profile
                .resolve_code_page(requested_code_page);
            if src == 0 || requested == 0 || requested < -1 || code_page.is_none() {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
                set_eax(uc, 0);
                return true;
            }
            let nul_terminated = requested == -1;
            let bytes = if nul_terminated {
                let Some(bytes) = read_c_bytes_uc(uc, src, 1 << 20) else {
                    uc.get_data_mut()
                        .win32
                        .set_last_error(ERROR_INVALID_PARAMETER);
                    set_eax(uc, 0);
                    return true;
                };
                bytes
            } else {
                match uc.mem_read_as_vec(src, requested as usize) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        uc.get_data_mut()
                            .win32
                            .set_last_error(ERROR_INVALID_PARAMETER);
                        set_eax(uc, 0);
                        return true;
                    }
                }
            };
            let strict = flags & 0x0000_0008 != 0; // MB_ERR_INVALID_CHARS
            let mut wide = match decode_ansi(code_page.unwrap(), &bytes, strict) {
                Ok(wide) => wide,
                Err(error) => {
                    uc.get_data_mut().win32.set_last_error(error);
                    set_eax(uc, 0);
                    return true;
                }
            };
            if nul_terminated {
                wide.push(0);
            }
            if dst == 0 || capacity == 0 {
                set_eax(uc, wide.len() as u64);
            } else if capacity < wide.len() {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INSUFFICIENT_BUFFER);
                set_eax(uc, 0);
            } else {
                let encoded = wide
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>();
                if uc.mem_write(dst, &encoded).is_err() {
                    uc.get_data_mut()
                        .win32
                        .set_last_error(ERROR_INVALID_PARAMETER);
                    set_eax(uc, 0);
                    return true;
                }
                set_eax(uc, wide.len() as u64);
            }
        }
        "WideCharToMultiByte" => {
            let requested_code_page = arg(uc, 0);
            let flags = arg(uc, 1);
            let src = arg(uc, 2) as u64;
            let requested = arg(uc, 3) as i32;
            let dst = arg(uc, 4) as u64;
            let capacity = arg(uc, 5) as usize;
            let used_default_ptr = arg(uc, 7) as u64;
            let code_page = uc
                .get_data()
                .win32
                .profile
                .resolve_code_page(requested_code_page);
            if src == 0 || requested == 0 || requested < -1 || code_page.is_none() {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
                set_eax(uc, 0);
                return true;
            }
            let nul_terminated = requested == -1;
            let units = if nul_terminated {
                let mut values = Vec::new();
                for index in 0..(1 << 20) {
                    let mut raw = [0u8; 2];
                    if uc.mem_read(src + index * 2, &mut raw).is_err() {
                        break;
                    }
                    let value = u16::from_le_bytes(raw);
                    values.push(value);
                    if value == 0 {
                        break;
                    }
                }
                values
            } else {
                let raw = uc
                    .mem_read_as_vec(src, requested.max(0) as usize * 2)
                    .unwrap_or_default();
                raw.chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect()
            };
            let (text, invalid_utf16) = match String::from_utf16(&units) {
                Ok(text) => (text, false),
                Err(_) => (String::from_utf16_lossy(&units), true),
            };
            if invalid_utf16 && flags & 0x0000_0080 != 0 {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                set_eax(uc, 0);
                return true;
            }
            let (bytes, used_default) = match encode_ansi_with_default(code_page.unwrap(), &text) {
                Ok(result) => result,
                Err(error) => {
                    uc.get_data_mut().win32.set_last_error(error);
                    set_eax(uc, 0);
                    return true;
                }
            };
            if used_default_ptr != 0 {
                let _ = uc.mem_write(used_default_ptr, &[u8::from(used_default)]);
            }
            if dst == 0 || capacity == 0 {
                set_eax(uc, bytes.len() as u64);
            } else if capacity < bytes.len() {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INSUFFICIENT_BUFFER);
                set_eax(uc, 0);
            } else if uc.mem_write(dst, &bytes).is_ok() {
                set_eax(uc, bytes.len() as u64);
            } else {
                uc.get_data_mut()
                    .win32
                    .set_last_error(ERROR_INVALID_PARAMETER);
                set_eax(uc, 0);
            }
        }
        "GetStringTypeA" | "GetStringTypeW" => {
            let (count, output) = if name == "GetStringTypeA" {
                (arg(uc, 3), arg(uc, 4) as u64)
            } else {
                (arg(uc, 2), arg(uc, 3) as u64)
            };
            let zeros = vec![0u8; count.max(0) as usize * 2];
            let ok = output != 0 && uc.mem_write(output, &zeros).is_ok();
            set_eax(uc, u64::from(ok));
        }
        "LCMapStringA" | "LCMapStringW" => set_eax(uc, 0),
        "RtlUnwind" | "RaiseException" | "ExitProcess" | "TerminateProcess" => {
            uc.get_data_mut().unsupported_api = Some(format!(
                "{name} was reached during deterministic module initialization"
            ));
            set_eax(uc, 0);
            let _ = uc.emu_stop();
        }
        _ => return false,
    }
    true
}

fn align_page(value: u64) -> u64 {
    value.saturating_add(PAGE - 1) & !(PAGE - 1)
}

fn ranges_overlap(a: u64, a_size: u64, b: u64, b_size: u64) -> bool {
    a < b.saturating_add(b_size) && b < a.saturating_add(a_size)
}

pub fn probe_x86_filter_module(
    path: impl AsRef<Path>,
    options: FilterProbeOptions,
) -> Result<ModuleProbe> {
    let path = path.as_ref();
    let pe = Pe32::from_path(path)?;
    let candidates = collect_static_candidates(&pe);
    let v2link_va = pe
        .export_rva("V2Link")
        .map(|rva| pe.image_base.wrapping_add(rva));
    let mut captured_callback = None;
    let mut requested_exports = Vec::new();
    let mut initialization_notes = Vec::new();
    let mut dynamic_error = None;
    if options.dynamic_v2link {
        if let Some(v2) = v2link_va {
            match build_emulator(&pe, options.trace_code).and_then(|mut uc| {
                run_dll_process_attach(&mut uc, &pe)?;
                let callback = run_initialized_v2link_capture(&mut uc, &pe, v2)?;
                let requested = uc.get_data().requested_exports.clone();
                let notes = uc.get_data().initialization_notes.clone();
                Ok((callback, requested, notes))
            }) {
                Ok((callback, requested, notes)) => {
                    captured_callback = Some(callback);
                    requested_exports = requested;
                    initialization_notes = notes;
                }
                Err(e) => dynamic_error = Some(e.to_string()),
            }
        }
    }
    Ok(ModuleProbe {
        path: path.to_path_buf(),
        image_base: pe.image_base,
        machine: pe.machine,
        v2link_va,
        candidates,
        captured_callback,
        requested_exports,
        initialization_notes,
        dynamic_error,
    })
}

pub fn probe_x86_filter_path(
    path: impl AsRef<Path>,
    options: FilterProbeOptions,
) -> Result<Vec<ModuleProbe>> {
    let path = path.as_ref();
    if path.is_file() {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let known_plugin = matches!(ext.as_str(), "dll" | "tpm");
        let game_root_hint = ext == "exe"
            || (!known_plugin && crate::magic_sniff::path_looks_like_pe(path));
        if !game_root_hint {
            return Ok(vec![probe_x86_filter_module(path, options)?]);
        }

        // A game executable is treated as the game root: inspect the EXE first,
        // then sibling DLL/TPM modules.  This mirrors how Kirikiri titles ship
        // extraction filters outside the main executable.
        let mut files = vec![path.to_path_buf()];
        if let Some(parent) = path.parent() {
            let mut siblings = Vec::new();
            collect_pe_like_files(parent, 0, &mut siblings)?;
            siblings.retain(|p| p != path);
            files.extend(siblings);
        }
        let mut reports = Vec::new();
        for file in files {
            match probe_x86_filter_module(&file, options.clone()) {
                Ok(report)
                    if report.v2link_va.is_some()
                        || !report.candidates.is_empty()
                        || report.captured_callback.is_some() =>
                {
                    reports.push(report)
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        reports.sort_by_key(|r| {
            let captured = if r.captured_callback.is_some() {
                0u8
            } else {
                1u8
            };
            let score = r.candidates.first().map(|c| c.score).unwrap_or(0);
            (captured, std::cmp::Reverse(score), r.path.clone())
        });
        return Ok(reports);
    }
    if !path.is_dir() {
        return Err(Error::invalid(format!(
            "{} is not a file or directory",
            path.display()
        )));
    }
    let mut files = Vec::new();
    collect_pe_like_files(path, 0, &mut files)?;
    let mut reports = Vec::new();
    for file in files {
        match probe_x86_filter_module(&file, options.clone()) {
            Ok(report)
                if report.v2link_va.is_some()
                    || !report.candidates.is_empty()
                    || report.captured_callback.is_some() =>
            {
                reports.push(report)
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    reports.sort_by_key(|r| {
        let captured = if r.captured_callback.is_some() {
            0u8
        } else {
            1u8
        };
        let score = r.candidates.first().map(|c| c.score).unwrap_or(0);
        (captured, std::cmp::Reverse(score), r.path.clone())
    });
    Ok(reports)
}

fn collect_pe_like_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 4 || out.len() >= 4096 {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_pe_like_files(&path, depth + 1, out)?;
            continue;
        }
        if !ty.is_file() {
            continue;
        }
        if crate::magic_sniff::path_looks_like_pe(&path) {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_alignment() {
        assert_eq!(align_page(1), 0x1000);
        assert_eq!(align_page(0x1000), 0x1000);
        assert_eq!(align_page(0x1001), 0x2000);
    }

    #[test]
    fn overlap() {
        assert!(ranges_overlap(0x1000, 0x1000, 0x1800, 0x1000));
        assert!(!ranges_overlap(0x1000, 0x1000, 0x2000, 0x1000));
    }


    fn synthetic_registration_pe() -> Pe32 {
        let image_base = 0x1000_0000u32;
        let text_rva = 0x1000u32;
        let rdata_rva = 0x2000u32;
        let data_rva = 0x3000u32;
        let text_raw = 0x200usize;
        let rdata_raw = 0x400usize;
        let data_raw = 0x600usize;
        let mut bytes = vec![0u8; 0x800];

        let api = b"void ::TVPSetXP3ArchiveExtractionFilter(tTVPXP3ArchiveExtractionFilter)\0";
        bytes[rdata_raw..rdata_raw + api.len()].copy_from_slice(api);
        let api_va = image_base + rdata_rva;
        let slot_va = image_base + data_rva;
        let callback_va = image_base + text_rva + 0x80;
        let resolver_va = image_base + text_rva + 0x50;

        let mut code = Vec::new();
        code.push(0x68); // push api-name
        code.extend_from_slice(&api_va.to_le_bytes());
        code.push(0xe8); // call resolver
        let call_va = image_base + text_rva + code.len() as u32 - 1;
        let rel = resolver_va.wrapping_sub(call_va.wrapping_add(5));
        code.extend_from_slice(&rel.to_le_bytes());
        code.extend_from_slice(&[0x83, 0xc4, 0x04]); // add esp,4
        code.push(0xa3); // mov [slot],eax
        code.extend_from_slice(&slot_va.to_le_bytes());
        code.push(0x68); // push callback
        code.extend_from_slice(&callback_va.to_le_bytes());
        code.extend_from_slice(&[0xff, 0x15]); // call [slot]
        code.extend_from_slice(&slot_va.to_le_bytes());
        code.push(0xc3);
        bytes[text_raw..text_raw + code.len()].copy_from_slice(&code);
        bytes[text_raw + 0x50] = 0xc3; // resolver target only needs to be executable
        bytes[text_raw + 0x80] = 0xc2; // callback ret 4
        bytes[text_raw + 0x81] = 0x04;
        bytes[text_raw + 0x82] = 0x00;

        Pe32 {
            bytes,
            machine: 0x14c,
            image_base,
            entry_point_rva: text_rva,
            size_of_image: 0x4000,
            size_of_headers: 0x200,
            sections: vec![
                PeSection {
                    name: ".text".into(),
                    virtual_address: text_rva,
                    virtual_size: 0x200,
                    raw_offset: text_raw as u32,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                },
                PeSection {
                    name: ".rdata".into(),
                    virtual_address: rdata_rva,
                    virtual_size: 0x200,
                    raw_offset: rdata_raw as u32,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
                PeSection {
                    name: ".data".into(),
                    virtual_address: data_rva,
                    virtual_size: 0x200,
                    raw_offset: data_raw as u32,
                    raw_size: 0x200,
                    characteristics: 0xc000_0040,
                },
            ],
            exports: BTreeMap::from([("V2Link".to_string(), text_rva)]),
            imports: Vec::new(),
        }
    }


    fn synthetic_registration_wrapper_pe() -> Pe32 {
        let image_base = 0x1000_0000u32;
        let text_rva = 0x1000u32;
        let rdata_rva = 0x2000u32;
        let data_rva = 0x3000u32;
        let text_raw = 0x200usize;
        let rdata_raw = 0x400usize;
        let data_raw = 0x600usize;
        let mut bytes = vec![0u8; 0x800];

        let api = b"void ::TVPSetXP3ArchiveExtractionFilter(tTVPXP3ArchiveExtractionFilter)\0";
        bytes[rdata_raw..rdata_raw + api.len()].copy_from_slice(api);
        let api_va = image_base + rdata_rva;
        let slot_va = image_base + data_rva;
        let v2link_va = image_base + text_rva;
        let wrapper_va = image_base + text_rva + 0x40;
        let resolver_va = image_base + text_rva + 0x90;
        let callback_va = image_base + text_rva + 0xc0;

        // V2Link: push callback ; call wrapper ; ret
        let mut v2 = Vec::new();
        v2.push(0x68);
        v2.extend_from_slice(&callback_va.to_le_bytes());
        v2.push(0xe8);
        let wrapper_call_va = v2link_va + 5;
        v2.extend_from_slice(&wrapper_va.wrapping_sub(wrapper_call_va + 5).to_le_bytes());
        v2.push(0xc3);
        bytes[text_raw..text_raw + v2.len()].copy_from_slice(&v2);

        // Non-inlined generated wrapper. It resolves the exact Kirikiri API,
        // stores the result, forwards arg0, and calls through the slot.
        let wrapper_raw = text_raw + 0x40;
        let mut wrapper = vec![0x55, 0x8b, 0xec]; // push ebp; mov ebp,esp
        wrapper.push(0x68);
        wrapper.extend_from_slice(&api_va.to_le_bytes());
        wrapper.push(0xe8);
        let resolver_call_va = wrapper_va + wrapper.len() as u32 - 1;
        wrapper.extend_from_slice(&resolver_va.wrapping_sub(resolver_call_va + 5).to_le_bytes());
        wrapper.extend_from_slice(&[0x83, 0xc4, 0x04]);
        wrapper.push(0xa3);
        wrapper.extend_from_slice(&slot_va.to_le_bytes());
        wrapper.extend_from_slice(&[0xff, 0x75, 0x08]); // push [ebp+8]
        wrapper.extend_from_slice(&[0xff, 0x15]);
        wrapper.extend_from_slice(&slot_va.to_le_bytes());
        wrapper.extend_from_slice(&[0x5d, 0xc2, 0x04, 0x00]);
        bytes[wrapper_raw..wrapper_raw + wrapper.len()].copy_from_slice(&wrapper);
        bytes[text_raw + 0x90] = 0xc3;
        bytes[text_raw + 0xc0..text_raw + 0xc3].copy_from_slice(&[0xc2, 0x04, 0x00]);

        Pe32 {
            bytes,
            machine: 0x14c,
            image_base,
            entry_point_rva: text_rva,
            size_of_image: 0x4000,
            size_of_headers: 0x200,
            sections: vec![
                PeSection {
                    name: ".text".into(),
                    virtual_address: text_rva,
                    virtual_size: 0x200,
                    raw_offset: text_raw as u32,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                },
                PeSection {
                    name: ".rdata".into(),
                    virtual_address: rdata_rva,
                    virtual_size: 0x200,
                    raw_offset: rdata_raw as u32,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
                PeSection {
                    name: ".data".into(),
                    virtual_address: data_rva,
                    virtual_size: 0x200,
                    raw_offset: data_raw as u32,
                    raw_size: 0x200,
                    characteristics: 0xc000_0040,
                },
            ],
            exports: BTreeMap::from([("V2Link".to_string(), text_rva)]),
            imports: Vec::new(),
        }
    }

    #[test]
    fn static_registration_provenance_follows_non_inlined_wrapper() {
        let pe = synthetic_registration_wrapper_pe();
        let candidates = collect_registration_provenance_candidates(&pe);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.callback_va, 0x1000_10c0);
        let provenance = candidate.registration.as_ref().unwrap();
        assert_eq!(provenance.v2link_va, 0x1000_1000);
        assert_eq!(provenance.wrapper_va, Some(0x1000_1040));
        assert_eq!(provenance.wrapper_call_va, Some(0x1000_1005));
        assert_eq!(provenance.function_slot_va, Some(0x1000_3000));
        assert_eq!(provenance.callback_push_va, 0x1000_1000);
    }

    #[test]
    fn static_registration_provenance_requires_exact_import_dataflow() {
        let pe = synthetic_registration_pe();
        let candidates = collect_registration_provenance_candidates(&pe);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.callback_va, 0x1000_1080);
        assert_eq!(candidate.source, "static-registration-provenance");
        let provenance = candidate.registration.as_ref().unwrap();
        assert_eq!(provenance.v2link_va, 0x1000_1000);
        assert_eq!(provenance.api_name_va, 0x1000_2000);
        assert_eq!(provenance.function_slot_va, Some(0x1000_3000));
        assert_eq!(provenance.callback_push_va, 0x1000_1012);
        assert_eq!(provenance.registration_call_va, 0x1000_1017);
    }

    #[test]
    fn abi_hint_requires_info_pointer_dataflow_and_buffer_use() {
        let mut pe = synthetic_registration_pe();
        let raw = 0x200usize + 0x100;
        // push ebp; mov ebp,esp; mov esi,[ebp+8]
        // cmp dword ptr [esi],0x18
        // mov eax,[esi+0x0c]   ; Buffer
        // mov ecx,[esi+0x10]   ; BufferSize
        // mov edx,[esi+0x14]   ; FileHash
        // xor byte ptr [eax],dl
        // ret 4
        let bytes = [
            0x55, 0x8b, 0xec, 0x8b, 0x75, 0x08,
            0x83, 0x3e, 0x18,
            0x8b, 0x46, 0x0c,
            0x8b, 0x4e, 0x10,
            0x8b, 0x56, 0x14,
            0x30, 0x10,
            0xc2, 0x04, 0x00,
        ];
        pe.bytes[raw..raw + bytes.len()].copy_from_slice(&bytes);
        let (score, reasons) = abi_score(&pe, 0x1000_1100);
        assert!(score >= 40, "score={score} reasons={reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("Buffer from info")));
        assert!(reasons.iter().any(|r| r.contains("BufferSize")));
        assert!(reasons.iter().any(|r| r.contains("FileHash")));
        assert!(reasons.iter().any(|r| r.contains("mutates memory")));
    }

    #[test]
    fn abi_hint_rejects_unrelated_struct_member_access() {
        let mut pe = synthetic_registration_pe();
        let raw = 0x200usize + 0x100;
        // One pointer argument and one +0x0c member read is not enough.  This
        // shape occurs constantly in ordinary C++ methods and was responsible
        // for the thousands of false hypotheses in large game executables.
        let bytes = [
            0x55, 0x8b, 0xec, 0x8b, 0x75, 0x08,
            0x8b, 0x46, 0x0c,
            0xc2, 0x04, 0x00,
        ];
        pe.bytes[raw..raw + bytes.len()].copy_from_slice(&bytes);
        let (score, reasons) = abi_score(&pe, 0x1000_1100);
        assert!(score < 24, "score={score} reasons={reasons:?}");
    }

    #[test]
    fn abi_hint_stops_at_first_return_and_does_not_borrow_next_function() {
        let mut pe = synthetic_registration_pe();
        let raw = 0x200usize + 0x100;
        // A short epilogue/continuation exactly like the RiddleJoker false
        // positive, followed by bytes that would score highly if scanning
        // crossed the return into another function.
        let bytes = [
            0x5d, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3,
            0x83, 0x38, 0x18, 0x8b, 0x40, 0x0c, 0x8b, 0x48, 0x10,
            0x8b, 0x50, 0x14, 0xc2, 0x04, 0x00,
        ];
        pe.bytes[raw..raw + bytes.len()].copy_from_slice(&bytes);
        let (score, reasons) = abi_score(&pe, 0x1000_1100);
        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn initialized_virtual_sections_are_materialized_back_to_file_layout() {
        let pe = Pe32 {
            bytes: vec![0xa5; 0x300],
            machine: 0x14c,
            image_base: 0x400000,
            entry_point_rva: 0x1000,
            size_of_image: 0x2000,
            size_of_headers: 0x100,
            sections: vec![PeSection {
                name: ".decc".into(),
                virtual_address: 0x1000,
                virtual_size: 0x40,
                raw_offset: 0x100,
                raw_size: 0x20,
                characteristics: 0x6000_0020,
            }],
            exports: BTreeMap::new(),
            imports: Vec::new(),
        };
        let mut initialized = vec![0u8; 0x2000];
        for (index, byte) in initialized[0x1000..0x1020].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let file = pe.materialize_file_from_virtual(&initialized);
        assert_eq!(&file[0x100..0x120], &initialized[0x1000..0x1020]);
        assert!(file[0x120..0x140].iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn callback_thunk_recovers_old_28_byte_filter_info_abi() {
        let mut uc = Unicorn::new_with_data(
            Arch::X86,
            Mode::MODE_32,
            EmuState::new(false, 0x400000, 0x1000, Vec::new()),
        )
        .unwrap();
        uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
        // Entry thunk jumps to a body that checks cmp dword ptr [esi], 0x1c.
        uc.mem_write(0x1000, &[0xe9, 0xfb, 0x00, 0x00, 0x00])
            .unwrap();
        uc.mem_write(0x1100, &[0x83, 0x3e, 0x1c, 0x74, 0x01, 0xc3])
            .unwrap();
        assert_eq!(detect_filter_info_size(&uc, 0x1000), Some(0x1c));
    }

    #[test]
    fn retained_module_bytes_match_path_runtime() {
        let path = Path::new("../games/game-normal/plugin/kinglove.tpm");
        if !path.is_file() {
            return;
        }
        let bytes = fs::read(path).unwrap();
        let mut path_runtime = X86Xp3FilterRuntime::open(path, false).unwrap();
        let mut retained_runtime =
            X86Xp3FilterRuntime::from_bytes("embedded/kinglove.tpm", bytes, false).unwrap();
        let mut from_path = (0..4096).map(|value| value as u8).collect::<Vec<_>>();
        let mut retained = from_path.clone();
        path_runtime.apply(0, 0x1861_e764, &mut from_path).unwrap();
        retained_runtime
            .apply(0, 0x1861_e764, &mut retained)
            .unwrap();
        assert_eq!(retained, from_path);
    }
}
