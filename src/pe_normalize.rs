//! PE normalization for executable-analysis backends.
//!
//! This layer removes supported outer executable wrappers before KiriKiri/
//! XP3 filter-family detection.  Wrapper recognition is structural: no title,
//! AppID, filename, fixed RVA, or file hash is used as an identity oracle.

use crate::error::{Error, Result};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use std::fs;
use std::path::Path;

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const PE32_MAGIC: u16 = 0x010b;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const STEAMSTUB31_HEADER_SIZE: usize = 0xF0;
const STEAMSTUB31_SIGNATURE: u32 = 0xC0DE_C0DF;

// SteamStub v3.x x86 entry signature.  This is only a coarse gate; a candidate
// is accepted only after the encoded 0xF0-byte header and its PE invariants
// validate completely.
const STEAMSTUB_V3_ENTRY: &[u8] = &[
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x8B, 0x44, 0x24,
    0x1C, 0x2D, 0x05, 0x00, 0x00, 0x00, 0x8B, 0xCC, 0x83, 0xE4, 0xF0, 0x51, 0x51, 0x51, 0x50,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeNormalizationKind {
    SteamStub31X86,
}

impl PeNormalizationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::SteamStub31X86 => "steamstub-3.1-x86",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeNormalizationReport {
    pub kind: PeNormalizationKind,
    pub source_entry_rva: u32,
    pub original_entry_rva: u32,
    pub code_section_rva: u32,
    pub code_section_raw_size: u32,
    pub steam_app_id: u32,
    pub header_size: u32,
    pub bind_section_rva: u32,
    pub bind_section_raw_offset: u32,
    pub bind_section_raw_size: u32,
    pub bind_kept: bool,
}

#[derive(Clone, Debug)]
pub struct NormalizedPe {
    pub bytes: Vec<u8>,
    pub report: Option<PeNormalizationReport>,
}

#[derive(Clone, Debug)]
struct PeLayout {
    pe_offset: usize,
    optional_offset: usize,
    image_base: u32,
    entry_rva: u32,
    sections: Vec<PeSection>,
}

#[derive(Clone, Debug)]
struct PeSection {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
}

impl PeSection {
    fn contains_rva(&self, rva: u32) -> bool {
        let span = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && rva < self.virtual_address.saturating_add(span)
    }

    fn executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

#[derive(Clone, Debug)]
struct SteamStub31Header {
    image_base: u64,
    address_of_entry_point: u64,
    bind_section_offset: u32,
    original_entry_point: u64,
    steam_app_id: u32,
    flags: u32,
    bind_section_virtual_size: u32,
    code_section_virtual_address: u64,
    code_section_raw_size: u64,
    aes_key: [u8; 32],
    aes_iv: [u8; 16],
    stolen_data: [u8; 16],
}

/// Normalize any supported outer PE wrapper.  Ordinary/unsupported PE files
/// are returned byte-for-byte unchanged so downstream analyzers retain their
/// previous behavior.
pub fn normalize_pe_bytes(bytes: &[u8]) -> Result<NormalizedPe> {
    if let Some(normalized) = unpack_steamstub31_x86_bytes(bytes)? {
        return Ok(normalized);
    }
    Ok(NormalizedPe {
        bytes: bytes.to_vec(),
        report: None,
    })
}

pub fn normalize_pe_file(path: impl AsRef<Path>) -> Result<NormalizedPe> {
    normalize_pe_bytes(&fs::read(path)?)
}

/// Statically restore the code section of a structurally validated SteamStub
/// Variant 3.1.x x86 wrapper.  The `.bind` section is intentionally retained:
/// analysis needs the original RVA/file layout, while removing the outer
/// section is unnecessary and increases PE-rewrite risk.
pub fn unpack_steamstub31_x86_bytes(bytes: &[u8]) -> Result<Option<NormalizedPe>> {
    let Some(pe) = parse_pe32_layout(bytes) else {
        return Ok(None);
    };
    if read_u16(bytes, pe.pe_offset + 4) != Some(IMAGE_FILE_MACHINE_I386) {
        return Ok(None);
    }
    let Some(bind) = pe
        .sections
        .iter()
        .find(|section| section.name.eq_ignore_ascii_case(".bind"))
    else {
        return Ok(None);
    };

    let bind_start = bind.raw_offset as usize;
    let bind_len = bind.raw_size as usize;
    let Some(bind_end) = bind_start.checked_add(bind_len) else {
        return Ok(None);
    };
    if bind_end > bytes.len() || bind_len < STEAMSTUB31_HEADER_SIZE {
        return Ok(None);
    }
    let bind_bytes = &bytes[bind_start..bind_end];
    if !contains_bytes(bind_bytes, STEAMSTUB_V3_ENTRY)
        || steamstub31_header_size_from_bind(bind_bytes) != Some(STEAMSTUB31_HEADER_SIZE as u32)
    {
        return Ok(None);
    }

    // For Variant 3.1 x86 the encoded DRM header is immediately before the
    // wrapped entry point.  We do not trust that relation by itself: every
    // decoded field below is cross-checked against the containing PE.
    let Some(entry_file_offset) = rva_to_file_offset(&pe, pe.entry_rva, bytes.len()) else {
        return Ok(None);
    };
    if entry_file_offset < STEAMSTUB31_HEADER_SIZE {
        return Ok(None);
    }
    let header_offset = entry_file_offset - STEAMSTUB31_HEADER_SIZE;
    if header_offset < bind_start || header_offset + STEAMSTUB31_HEADER_SIZE > bind_end {
        return Ok(None);
    }

    let mut decoded = bytes[header_offset..header_offset + STEAMSTUB31_HEADER_SIZE].to_vec();
    steam_xor_decode(&mut decoded)?;
    if read_u32(&decoded, 4) != Some(STEAMSTUB31_SIGNATURE) {
        return Ok(None);
    }
    let header = parse_steamstub31_header(&decoded)?;
    validate_steamstub31_header(&pe, bind, &header, bytes.len())?;

    // Flags are preserved in the report indirectly via structural validation,
    // but this first implementation intentionally supports the encrypted form
    // used by the real Senren＊Banka sample.  A non-zero flag word can encode
    // additional SteamStub behavior; fail closed rather than guessing whether
    // the code section is plaintext.
    if header.flags != 0 {
        return Err(Error::unsupported(format!(
            "SteamStub 3.1 x86 flags=0x{:08x} are not supported by the static normalizer",
            header.flags
        )));
    }

    let code_rva = u32::try_from(header.code_section_virtual_address)
        .map_err(|_| Error::format("SteamStub code-section RVA exceeds PE32"))?;
    let code_size = usize::try_from(header.code_section_raw_size)
        .map_err(|_| Error::format("SteamStub code-section size does not fit host usize"))?;
    let code_section = pe
        .sections
        .iter()
        .find(|section| section.contains_rva(code_rva))
        .ok_or_else(|| Error::format("SteamStub code-section RVA has no owning PE section"))?;
    let delta = code_rva
        .checked_sub(code_section.virtual_address)
        .ok_or_else(|| Error::format("invalid SteamStub code-section RVA"))? as usize;
    let code_offset = (code_section.raw_offset as usize)
        .checked_add(delta)
        .ok_or_else(|| Error::format("SteamStub code-section file offset overflow"))?;
    let code_end = code_offset
        .checked_add(code_size)
        .ok_or_else(|| Error::format("SteamStub code-section size overflow"))?;
    if code_end > bytes.len() {
        return Err(Error::format("SteamStub encrypted code section is truncated"));
    }

    let cipher_len = code_size
        .checked_add(header.stolen_data.len())
        .ok_or_else(|| Error::format("SteamStub ciphertext length overflow"))?;
    if cipher_len % 16 != 0 {
        return Err(Error::format(format!(
            "SteamStub ciphertext length 0x{cipher_len:x} is not AES-block aligned"
        )));
    }
    let mut ciphertext = Vec::with_capacity(cipher_len);
    ciphertext.extend_from_slice(&header.stolen_data);
    ciphertext.extend_from_slice(&bytes[code_offset..code_end]);
    aes256_cbc_decrypt_in_place(&mut ciphertext, &header.aes_key, &header.aes_iv)?;

    let mut output = bytes.to_vec();
    output[code_offset..code_end].copy_from_slice(&ciphertext[..code_size]);

    let original_entry = u32::try_from(header.original_entry_point)
        .map_err(|_| Error::format("SteamStub original entry point exceeds PE32"))?;
    write_u32(&mut output, pe.optional_offset + 16, original_entry)?;
    // PE checksum is optional for user-mode loading.  Clear the stale checksum
    // rather than keeping the wrapped binary's value after modifying `.text`.
    write_u32(&mut output, pe.optional_offset + 64, 0)?;

    Ok(Some(NormalizedPe {
        bytes: output,
        report: Some(PeNormalizationReport {
            kind: PeNormalizationKind::SteamStub31X86,
            source_entry_rva: pe.entry_rva,
            original_entry_rva: original_entry,
            code_section_rva: code_rva,
            code_section_raw_size: u32::try_from(header.code_section_raw_size)
                .map_err(|_| Error::format("SteamStub code-section size exceeds u32"))?,
            steam_app_id: header.steam_app_id,
            header_size: STEAMSTUB31_HEADER_SIZE as u32,
            bind_section_rva: bind.virtual_address,
            bind_section_raw_offset: bind.raw_offset,
            bind_section_raw_size: bind.raw_size,
            bind_kept: true,
        }),
    }))
}

fn parse_steamstub31_header(decoded: &[u8]) -> Result<SteamStub31Header> {
    if decoded.len() != STEAMSTUB31_HEADER_SIZE {
        return Err(Error::format("invalid SteamStub 3.1 header size"));
    }
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&decoded[0x58..0x78]);
    let mut aes_iv = [0u8; 16];
    aes_iv.copy_from_slice(&decoded[0x78..0x88]);
    let mut stolen_data = [0u8; 16];
    stolen_data.copy_from_slice(&decoded[0x88..0x98]);
    Ok(SteamStub31Header {
        image_base: read_u64_req(decoded, 0x08, "ImageBase")?,
        address_of_entry_point: read_u64_req(decoded, 0x10, "AddressOfEntryPoint")?,
        bind_section_offset: read_u32_req(decoded, 0x18, "BindSectionOffset")?,
        original_entry_point: read_u64_req(decoded, 0x20, "OriginalEntryPoint")?,
        steam_app_id: read_u32_req(decoded, 0x38, "SteamAppId")?,
        flags: read_u32_req(decoded, 0x3c, "Flags")?,
        bind_section_virtual_size: read_u32_req(decoded, 0x40, "BindSectionVirtualSize")?,
        code_section_virtual_address: read_u64_req(decoded, 0x48, "CodeSectionVirtualAddress")?,
        code_section_raw_size: read_u64_req(decoded, 0x50, "CodeSectionRawSize")?,
        aes_key,
        aes_iv,
        stolen_data,
    })
}

fn validate_steamstub31_header(
    pe: &PeLayout,
    bind: &PeSection,
    header: &SteamStub31Header,
    file_len: usize,
) -> Result<()> {
    if header.image_base != pe.image_base as u64 {
        return Err(Error::format(format!(
            "SteamStub ImageBase mismatch: header=0x{:x} PE=0x{:x}",
            header.image_base, pe.image_base
        )));
    }
    if header.address_of_entry_point != pe.entry_rva as u64 {
        return Err(Error::format(format!(
            "SteamStub entry-point mismatch: header=0x{:x} PE=0x{:x}",
            header.address_of_entry_point, pe.entry_rva
        )));
    }
    if pe.entry_rva != bind.virtual_address.saturating_add(header.bind_section_offset) {
        return Err(Error::format("SteamStub bind-section offset does not resolve to PE entry point"));
    }
    if header.bind_section_virtual_size == 0
        || header.bind_section_virtual_size > bind.virtual_size.max(bind.raw_size).saturating_add(0x1000)
    {
        return Err(Error::format("SteamStub bind-section virtual size is implausible"));
    }

    let original_entry = u32::try_from(header.original_entry_point)
        .map_err(|_| Error::format("SteamStub original entry point exceeds PE32"))?;
    if !pe
        .sections
        .iter()
        .any(|section| section.executable() && section.contains_rva(original_entry))
    {
        return Err(Error::format(
            "SteamStub original entry point is not inside an executable PE section",
        ));
    }

    let code_rva = u32::try_from(header.code_section_virtual_address)
        .map_err(|_| Error::format("SteamStub code-section RVA exceeds PE32"))?;
    let code_size = u32::try_from(header.code_section_raw_size)
        .map_err(|_| Error::format("SteamStub code-section size exceeds PE32"))?;
    if code_size == 0 {
        return Err(Error::format("SteamStub code section is empty"));
    }
    let code_section = pe
        .sections
        .iter()
        .find(|section| section.contains_rva(code_rva))
        .ok_or_else(|| Error::format("SteamStub code-section RVA has no owner"))?;
    if !code_section.executable() {
        return Err(Error::format("SteamStub code section is not executable"));
    }
    let delta = code_rva
        .checked_sub(code_section.virtual_address)
        .ok_or_else(|| Error::format("invalid SteamStub code-section RVA"))?;
    if delta.saturating_add(code_size) > code_section.raw_size {
        return Err(Error::format(format!(
            "SteamStub code size 0x{code_size:x} exceeds owning section raw range"
        )));
    }
    let file_end = (code_section.raw_offset as usize)
        .checked_add(delta as usize)
        .and_then(|offset| offset.checked_add(code_size as usize))
        .ok_or_else(|| Error::format("SteamStub code range overflow"))?;
    if file_end > file_len {
        return Err(Error::format("SteamStub code range is outside file"));
    }
    Ok(())
}

fn parse_pe32_layout(bytes: &[u8]) -> Option<PeLayout> {
    if bytes.len() < 0x100 || bytes.get(0..2)? != b"MZ" {
        return None;
    }
    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if pe_offset.checked_add(24)? > bytes.len() || bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_offset + 4;
    let section_count = read_u16(bytes, coff + 2)? as usize;
    let optional_size = read_u16(bytes, coff + 16)? as usize;
    let optional_offset = coff + 20;
    if optional_offset.checked_add(optional_size)? > bytes.len()
        || optional_size < 0x60
        || read_u16(bytes, optional_offset)? != PE32_MAGIC
    {
        return None;
    }
    let image_base = read_u32(bytes, optional_offset + 28)?;
    let entry_rva = read_u32(bytes, optional_offset + 16)?;
    let section_table = optional_offset + optional_size;
    if section_table.checked_add(section_count.checked_mul(40)?)? > bytes.len() {
        return None;
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let at = section_table + index * 40;
        let raw_name = bytes.get(at..at + 8)?;
        let end = raw_name.iter().position(|b| *b == 0).unwrap_or(raw_name.len());
        sections.push(PeSection {
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            virtual_size: read_u32(bytes, at + 8)?,
            virtual_address: read_u32(bytes, at + 12)?,
            raw_size: read_u32(bytes, at + 16)?,
            raw_offset: read_u32(bytes, at + 20)?,
            characteristics: read_u32(bytes, at + 36)?,
        });
    }
    Some(PeLayout {
        pe_offset,
        optional_offset,
        image_base,
        entry_rva,
        sections,
    })
}

fn rva_to_file_offset(pe: &PeLayout, rva: u32, file_len: usize) -> Option<usize> {
    for section in &pe.sections {
        if !section.contains_rva(rva) {
            continue;
        }
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.raw_size {
            return None;
        }
        let offset = section.raw_offset.checked_add(delta)? as usize;
        return (offset < file_len).then_some(offset);
    }
    None
}

fn aes256_cbc_decrypt_in_place(bytes: &mut [u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<()> {
    if bytes.len() % 16 != 0 {
        return Err(Error::format("AES-CBC input is not block aligned"));
    }
    let cipher = Aes256::new_from_slice(key)
        .map_err(|_| Error::format("invalid AES-256 key length"))?;
    let mut previous = *iv;
    for chunk in bytes.chunks_exact_mut(16) {
        let mut encrypted = [0u8; 16];
        encrypted.copy_from_slice(chunk);
        let block = aes::cipher::Block::<Aes256>::from_mut_slice(chunk);
        cipher.decrypt_block(block);
        for (plain, chain) in chunk.iter_mut().zip(previous.iter()) {
            *plain ^= *chain;
        }
        previous = encrypted;
    }
    Ok(())
}

fn steam_xor_decode(bytes: &mut [u8]) -> Result<u32> {
    if bytes.len() < 8 || bytes.len() % 4 != 0 {
        return Err(Error::format("SteamStub header is not DWORD aligned"));
    }
    let mut key = read_u32_req(bytes, 0, "XorKey")?;
    for offset in (4..bytes.len()).step_by(4) {
        let encoded = read_u32_req(bytes, offset, "encoded header DWORD")?;
        write_u32(bytes, offset, encoded ^ key)?;
        key = encoded;
    }
    Ok(key)
}

fn steamstub31_header_size_from_bind(bind: &[u8]) -> Option<u32> {
    const P1: &[u8] = &[
        0x55, 0x8b, 0xec, 0x81, 0xec, 0, 0, 0, 0, 0x53, 0, 0, 0, 0, 0, 0x68,
    ];
    const M1: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0xff,
    ];
    const P2: &[u8] = &[
        0x55, 0x8b, 0xec, 0x81, 0xec, 0, 0, 0, 0, 0x53, 0, 0, 0, 0, 0, 0x8d, 0x83,
    ];
    const M2: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0xff, 0xff,
    ];
    const P3: &[u8] = &[
        0x55, 0x8b, 0xec, 0x81, 0xec, 0, 0, 0, 0, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8d,
    ];
    const M3: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff,
    ];
    for (pattern, mask, size_offset) in [(P1, M1, 0x10usize), (P2, M2, 0x16), (P3, M3, 0x10)] {
        let Some(at) = find_masked_pattern(bind, pattern, mask) else {
            continue;
        };
        let size = read_u32(bind, at.checked_add(size_offset)?)?;
        if size != 0 {
            return Some(size);
        }
    }
    None
}

fn find_masked_pattern(haystack: &[u8], pattern: &[u8], mask: &[u8]) -> Option<usize> {
    if pattern.len() != mask.len() || pattern.is_empty() || pattern.len() > haystack.len() {
        return None;
    }
    haystack.windows(pattern.len()).position(|window| {
        window
            .iter()
            .zip(pattern.iter().zip(mask.iter()))
            .all(|(actual, (expected, mask))| (*actual & *mask) == (*expected & *mask))
    })
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let s = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let s = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let s = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn read_u32_req(bytes: &[u8], offset: usize, name: &str) -> Result<u32> {
    read_u32(bytes, offset).ok_or_else(|| Error::format(format!("truncated SteamStub {name}")))
}

fn read_u64_req(bytes: &[u8], offset: usize, name: &str) -> Result<u64> {
    read_u64(bytes, offset).ok_or_else(|| Error::format(format!("truncated SteamStub {name}")))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::format("PE write offset overflow"))?;
    let target = bytes
        .get_mut(offset..end)
        .ok_or_else(|| Error::format("PE write is outside file"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steam_xor_decodes_chained_dwords() {
        let decoded = [
            0x78u32,
            STEAMSTUB31_SIGNATURE,
            0x1122_3344,
            0x5566_7788,
        ];
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&decoded[0].to_le_bytes());
        let mut previous = decoded[0];
        for value in decoded.iter().skip(1) {
            let raw = *value ^ previous;
            encoded.extend_from_slice(&raw.to_le_bytes());
            previous = raw;
        }
        steam_xor_decode(&mut encoded).unwrap();
        assert_eq!(read_u32(&encoded, 4), Some(STEAMSTUB31_SIGNATURE));
        assert_eq!(read_u32(&encoded, 8), Some(0x1122_3344));
        assert_eq!(read_u32(&encoded, 12), Some(0x5566_7788));
    }

    #[test]
    fn aes256_cbc_matches_nist_vector_first_block() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
            0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
            0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f,
        ];
        let mut ciphertext = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
            0x7b, 0xfb, 0xd6,
        ];
        aes256_cbc_decrypt_in_place(&mut ciphertext, &key, &iv).unwrap();
        assert_eq!(
            ciphertext,
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                0x93, 0x17, 0x2a,
            ]
        );
    }
}
