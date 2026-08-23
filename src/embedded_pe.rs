//! Recovery of PE images embedded inside another executable.
//!
//! Some Kirikiri executables keep protection modules as zlib-compressed
//! `internal module` records and map them manually at runtime.  Disk-only PE
//! enumeration misses those modules completely, so static analysis must expose
//! them as ordinary byte-backed PE images without executing the loader.

use crate::{Error, Result};
use flate2::read::ZlibDecoder;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const INTERNAL_MODULE_MARKER: &[u8] = b"internal module\0";
const MAX_MARKER_TO_ZLIB: usize = 0x100;
const MAX_EMBEDDED_PE_SIZE: usize = 64 * 1024 * 1024;
const MAX_EMBEDDED_MODULES: usize = 32;

#[derive(Clone, Debug)]
pub struct EmbeddedPeModule {
    pub container: PathBuf,
    pub marker_offset: usize,
    pub compressed_offset: usize,
    pub compressed_size: usize,
    pub uncompressed_size: usize,
    pub bytes: Vec<u8>,
}

impl EmbeddedPeModule {
    pub fn label(&self) -> String {
        format!(
            "{}::internal@0x{:x}",
            self.container.display(),
            self.marker_offset
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupStorageRedirect {
    /// Virtual storage path exposed by the embedded storage media.
    pub virtual_startup: String,
    /// Physical XP3 archive name opened by the native storage callback.
    pub archive_name: String,
    /// Member name inside the physical XP3 archive.
    pub member_name: String,
}

/// Recover the native redirect used to provide Kirikiri's startup script.
///
/// The Yuzu/CXDEC storage module does not necessarily expose the ordinary XP3
/// member named `startup.tjs`.  Instead, its storage media special-cases the
/// virtual path `./startup.tjs` and opens a physical `archive.xp3>member`
/// stream.  This helper recognizes that mapping from the embedded PE's UTF-16
/// constants.  It is intentionally conservative: exactly one physical XP3
/// member reference must coexist with a startup.tjs virtual-path literal.
pub fn detect_startup_storage_redirect(module: &[u8]) -> Option<StartupStorageRedirect> {
    let strings = utf16le_ascii_strings(module);
    let virtual_startup = strings
        .iter()
        .find(|value| {
            let normalized = value.replace('\\', "/").to_ascii_lowercase();
            normalized == "./startup.tjs" || normalized == "startup.tjs"
        })?
        .clone();

    let mut redirects = strings
        .iter()
        .filter_map(|value| parse_xp3_member_reference(value))
        .collect::<Vec<_>>();
    redirects.sort();
    redirects.dedup();
    if redirects.len() != 1 {
        return None;
    }
    let (archive_name, member_name) = redirects.pop()?;
    Some(StartupStorageRedirect {
        virtual_startup,
        archive_name,
        member_name,
    })
}

fn parse_xp3_member_reference(value: &str) -> Option<(String, String)> {
    let (archive, member) = value.rsplit_once('>')?;
    let archive = archive.trim();
    let member = member.trim();
    if archive.is_empty() || member.is_empty() {
        return None;
    }
    let archive_name = archive
        .replace('\\', "/")
        .rsplit('/')
        .next()?
        .to_string();
    if !archive_name.to_ascii_lowercase().ends_with(".xp3") {
        return None;
    }
    Some((archive_name, member.to_string()))
}

fn utf16le_ascii_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 1 < bytes.len() {
        if !(0x20..=0x7e).contains(&bytes[offset]) || bytes[offset + 1] != 0 {
            offset += 1;
            continue;
        }
        let start = offset;
        let mut value = String::new();
        while offset + 1 < bytes.len()
            && (0x20..=0x7e).contains(&bytes[offset])
            && bytes[offset + 1] == 0
        {
            value.push(bytes[offset] as char);
            offset += 2;
        }
        if value.len() >= 4 {
            out.push(value);
        }
        if offset == start {
            offset += 1;
        }
    }
    out
}

pub fn extract_embedded_pe_modules(path: impl AsRef<Path>) -> Result<Vec<EmbeddedPeModule>> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    Ok(extract_embedded_pe_modules_from_bytes(path, &bytes))
}

pub fn extract_embedded_pe_modules_from_bytes(
    container: impl AsRef<Path>,
    bytes: &[u8],
) -> Vec<EmbeddedPeModule> {
    let container = container.as_ref();
    let mut out = Vec::new();
    let mut search = 0usize;

    while search + INTERNAL_MODULE_MARKER.len() <= bytes.len()
        && out.len() < MAX_EMBEDDED_MODULES
    {
        let Some(rel) = bytes[search..]
            .windows(INTERNAL_MODULE_MARKER.len())
            .position(|window| window == INTERNAL_MODULE_MARKER)
        else {
            break;
        };
        let marker_offset = search + rel;
        let after_marker = marker_offset + INTERNAL_MODULE_MARKER.len();
        let scan_end = after_marker
            .saturating_add(MAX_MARKER_TO_ZLIB)
            .min(bytes.len());

        let mut accepted = false;
        let mut zlib_offset = after_marker.saturating_add(8);
        while zlib_offset + 2 <= scan_end {
            if !looks_like_zlib_header(&bytes[zlib_offset..]) || zlib_offset < 8 {
                zlib_offset += 1;
                continue;
            }
            let size_offset = zlib_offset - 8;
            let uncompressed_size = match read_u32(bytes, size_offset) {
                Some(value) => value as usize,
                None => {
                    zlib_offset += 1;
                    continue;
                }
            };
            let compressed_size = match read_u32(bytes, size_offset + 4) {
                Some(value) => value as usize,
                None => {
                    zlib_offset += 1;
                    continue;
                }
            };
            if uncompressed_size == 0
                || uncompressed_size > MAX_EMBEDDED_PE_SIZE
                || compressed_size < 2
                || compressed_size > MAX_EMBEDDED_PE_SIZE
                || zlib_offset
                    .checked_add(compressed_size)
                    .is_none_or(|end| end > bytes.len())
            {
                zlib_offset += 1;
                continue;
            }

            let compressed = &bytes[zlib_offset..zlib_offset + compressed_size];
            let mut decoder = ZlibDecoder::new(compressed);
            let mut decoded = Vec::with_capacity(uncompressed_size);
            if decoder.read_to_end(&mut decoded).is_err()
                || decoded.len() != uncompressed_size
                || !crate::magic_sniff::looks_like_pe_bytes(&decoded)
            {
                zlib_offset += 1;
                continue;
            }

            out.push(EmbeddedPeModule {
                container: container.to_path_buf(),
                marker_offset,
                compressed_offset: zlib_offset,
                compressed_size,
                uncompressed_size,
                bytes: decoded,
            });
            accepted = true;
            break;
        }

        search = marker_offset + INTERNAL_MODULE_MARKER.len();
        if !accepted && search <= marker_offset {
            break;
        }
    }

    out
}

fn looks_like_zlib_header(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let cmf = bytes[0];
    let flg = bytes[1];
    cmf & 0x0f == 8 && (u16::from(cmf) * 256 + u16::from(flg)) % 31 == 0
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

pub fn require_single_embedded_pe(path: impl AsRef<Path>) -> Result<EmbeddedPeModule> {
    let modules = extract_embedded_pe_modules(path)?;
    match modules.as_slice() {
        [module] => Ok(module.clone()),
        [] => Err(Error::invalid("no embedded PE internal module found")),
        _ => Err(Error::invalid(format!(
            "expected one embedded PE internal module, found {}",
            modules.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    fn tiny_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 0x100];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe
    }

    #[test]
    fn extracts_internal_module_record() {
        let pe = tiny_pe();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&pe).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut container = b"prefix-internal module\0".to_vec();
        container.extend_from_slice(&[0u8; 8]);
        container.extend_from_slice(&(pe.len() as u32).to_le_bytes());
        container.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        container.extend_from_slice(&compressed);

        let found = extract_embedded_pe_modules_from_bytes("game.exe", &container);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bytes, pe);
    }

    fn utf16(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0, 0])
            .collect()
    }

    #[test]
    fn detects_native_startup_storage_redirect() {
        let mut module = vec![0x90; 32];
        module.extend_from_slice(&utf16("./startup.tjs"));
        module.extend_from_slice(&[0x90; 13]);
        module.extend_from_slice(&utf16("data.xp3>$"));

        let redirect = detect_startup_storage_redirect(&module).unwrap();
        assert_eq!(redirect.virtual_startup, "./startup.tjs");
        assert_eq!(redirect.archive_name, "data.xp3");
        assert_eq!(redirect.member_name, "$");
    }

    #[test]
    fn startup_redirect_is_conservative_when_multiple_xp3_members_exist() {
        let mut module = utf16("./startup.tjs");
        module.extend_from_slice(&utf16("data.xp3>$"));
        module.extend_from_slice(&utf16("patch.xp3>boot.tjs"));
        assert!(detect_startup_storage_redirect(&module).is_none());
    }

}
