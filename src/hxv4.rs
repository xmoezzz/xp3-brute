//! Hxv4 special-index and data-side recovery support.
//!
//! Hxv4 has two independent problems:
//! 1. the out-of-line special index is encrypted with title-specific ChaCha
//!    key/nonce material, then zlib-compressed and serialized;
//! 2. file contents use a per-entry symmetric XOR filter derived from the
//!    authenticated Special record's 64-bit `entry_key` by the title's
//!    FilterManager/DripValue programs.
//!
//! The native FilterManager is reproduced in [`crate::hxv4_native`].  The older
//! known-format effective-filter solver in this module remains only as a
//! compatibility fallback when the title's native manager cannot be recovered.

use crate::compute::{
    gpu_adler_search, gpu_slot_scores, AdlerGpuChoice, AdlerGpuProblem, AdlerGpuSlot, ComputeMode,
};
use crate::error::{Error, Result};
use crate::format::{
    builtin_hypotheses, hard_plaintext_constraints, length_derived_cribs,
    specific_hypotheses_for_name, FormatHypothesis,
};
use crate::repeating_xor::Crib;
use crate::simd::xor_const_in_place;
use crate::validate::validate_hypothesis;
use crate::xp3::{adler32, Entry};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use flate2::read::ZlibDecoder;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

const HXV4_SALT: &str = "xp3hnp";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hxv4IndexKeys {
    /// XChaCha20-Poly1305 key protecting the out-of-line Hxv4 table.
    pub key: [u8; 32],
    /// Selected 24-byte XChaCha20 nonce for this archive descriptor.
    /// The caller is responsible for selecting nonce0/nonce1 from the
    /// descriptor flag when both are known.
    pub nonce: [u8; 24],
}

impl Hxv4IndexKeys {
    pub fn from_hex(key: &str, nonce: &str) -> Result<Self> {
        Ok(Self {
            key: parse_hex_array::<32>(key)?,
            nonce: parse_hex_array::<24>(nonce)?,
        })
    }
}

/// HXV4 selects one of two 24-byte XChaCha nonces with descriptor bit 0.
/// Callers that already recovered both nonce slots should use this selector
/// rather than guessing from archive position or filename.
pub fn hxv4_special_nonce_slot(flags: u16) -> usize {
    (flags & 1) as usize
}

/// Return the authenticated 16-byte tag stored at the front of an HXV4
/// Special payload.  The remaining bytes are XChaCha20 ciphertext.
pub fn hxv4_special_tag(blob: &[u8]) -> Option<[u8; 16]> {
    let raw = blob.get(..16)?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(raw);
    Some(tag)
}

/// Return an explicit HXV4 `startup.tjs` entry when this archive actually
/// contains one.  `startup.tjs` is a bootstrap anchor of the main/data archive,
/// not a family-wide invariant: voice/image/etc. XP3 files must never have an
/// arbitrary unique non-fake entry relabeled as `startup.tjs`.
pub fn hxv4_startup_entry_index(entries: &[Entry]) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .find(|(_, entry)| {
            entry.hxv4_id.is_none() && entry.name.eq_ignore_ascii_case("startup.tjs")
        })
        .map(|(index, _)| index)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hxv4StartupHints {
    pub entry_index: usize,
    pub bootstrap_prefix: Option<String>,
    pub media_name: String,
}

/// Mine the TJS-level bootstrap prefix from a recovered `startup.tjs`.  This
/// deliberately reports script-visible inputs only; it does not pretend that
/// the script itself contains the FilterManager XChaCha key/nonce.
pub fn inspect_hxv4_startup_plaintext(entry_index: usize, bytes: &[u8]) -> Hxv4StartupHints {
    let utf8 = String::from_utf8_lossy(bytes).into_owned();
    let utf16 = decode_utf16le_lossy(bytes);
    let bootstrap_prefix =
        extract_bootstrap_prefix(&utf8).or_else(|| extract_bootstrap_prefix(&utf16));
    let media_name = bootstrap_prefix
        .as_deref()
        .and_then(|prefix| {
            prefix
                .split_once(':')
                .map(|(media, _)| media.trim())
                .filter(|media| !media.is_empty())
        })
        .map(str::to_string)
        .or_else(|| extract_media_name(&utf8))
        .or_else(|| extract_media_name(&utf16))
        .unwrap_or_else(|| "xp3hnp".to_string());
    Hxv4StartupHints {
        entry_index,
        bootstrap_prefix,
        media_name,
    }
}

fn extract_bootstrap_prefix(text: &str) -> Option<String> {
    for marker in ["_bootStrap(", "bootStrap(", "System.bootStrap("] {
        let Some(pos) = text.find(marker) else {
            continue;
        };
        let tail = &text[pos + marker.len()..];
        let mut chars = tail.char_indices().skip_while(|(_, c)| c.is_whitespace());
        let (quote_pos, quote) = chars.next()?;
        if quote != '\'' && quote != '"' {
            continue;
        }
        let start = quote_pos + quote.len_utf8();
        let body = &tail[start..];
        if let Some(end) = body.find(quote) {
            let value = body[..end].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_media_name(text: &str) -> Option<String> {
    if text.contains("xp3hnp") {
        return Some("xp3hnp".to_string());
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hxv4IndexEntry {
    /// Zero-based record number in the decoded Special table.
    pub record_index: usize,
    /// Raw first 64-bit integer from the authenticated Special record.
    ///
    /// Native `sub_10005850` consumes this integer as two independent dwords:
    /// the low dword is the synthetic XP3 lookup id, while the high dword is a
    /// packed locator/control value.
    pub packed: u64,
    /// High 16 bits of `packed >> 32`; selects the archive slot.
    pub archive_slot: u16,
    /// Low 16 bits of `packed >> 32`. `sub_10005850` writes this value to the
    /// fourth output parameter and `sub_10013CF0` uses bit 0 as `open_flag`.
    /// The historical field name is retained for API compatibility.
    pub filter_flag: u16,
    /// Low 32 bits of `packed`. This is passed to `sub_100179A0` and encoded as
    /// the synthetic Unicode XP3 `info` name.
    pub id: u64,
    pub entry_key: u64,
    pub path_hash: [u8; 8],
    pub name_hash: [u8; 32],
    pub path: Option<String>,
    pub name: Option<String>,
}

impl Hxv4IndexEntry {
    pub fn path_hash_hex(&self) -> String {
        hex_upper(&self.path_hash)
    }
    pub fn name_hash_hex(&self) -> String {
        hex_upper(&self.name_hash)
    }
    pub fn display_path(&self) -> String {
        let path = self.path.clone().unwrap_or_else(|| self.path_hash_hex());
        let name = self.name.clone().unwrap_or_else(|| self.name_hash_hex());
        if path == "/" || path.is_empty() {
            name
        } else {
            format!("{}/{}", path.trim_end_matches('/'), name)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Hxv4Index {
    pub entries: Vec<Hxv4IndexEntry>,
    pub decompressed_size: usize,
}

impl Hxv4Index {
    pub fn by_id(&self) -> HashMap<u64, &Hxv4IndexEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.archive_slot == 0)
            .map(|entry| (entry.id, entry))
            .collect()
    }

    pub fn apply_names(&mut self, names: &Hxv4NameMap) {
        for entry in &mut self.entries {
            if let Some(path) = names.paths.get(&entry.path_hash_hex()) {
                entry.path = Some(path.clone());
            }
            if let Some(name) = names.names.get(&entry.name_hash_hex()) {
                entry.name = Some(name.clone());
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Hxv4NameMap {
    pub paths: HashMap<String, String>,
    pub names: HashMap<String, String>,
}

impl Hxv4NameMap {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let mut map = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((hash, value)) = line.split_once(':') else {
                continue;
            };
            let hash = hash.trim().to_ascii_uppercase();
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match hash.len() {
                16 if hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    map.paths.insert(hash, value.to_string());
                }
                64 if hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    map.names.insert(hash, value.to_string());
                }
                _ => {}
            }
        }
        Ok(map)
    }

    /// Extend an HxNames-compatible map from a candidate path or filename.
    ///
    /// Hxv4 hashes the directory path and basename independently.  A dictionary
    /// line such as `scenario/chapter01/start.ks` therefore contributes the
    /// basename plus every useful directory prefix instead of incorrectly
    /// hashing the complete file path as one filename.
    pub fn add_candidate(&mut self, candidate: &str) {
        let canonical = candidate.trim().replace('\\', "/");
        if canonical.is_empty() {
            return;
        }
        if canonical == "/" {
            let hash = hex_upper(&hxv4_path_hash("/"));
            self.paths.entry(hash).or_insert_with(|| "/".to_string());
            return;
        }

        let parts: Vec<&str> = canonical
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        if parts.is_empty() {
            return;
        }

        // Always treat the last path component as a possible filename.  This is
        // harmless for directory-only dictionary lines and substantially raises
        // recall for mined script/resource references.
        let basename = parts[parts.len() - 1];
        let name_hash = hex_upper(&hxv4_filename_hash(basename));
        self.names
            .entry(name_hash)
            .or_insert_with(|| basename.to_string());

        if parts.len() > 1 || canonical.starts_with('/') {
            // Root and cumulative directory prefixes are all plausible Hx path
            // dictionary entries.  Keep both slash spellings used by public
            // HxNames lists without fabricating file-to-directory associations.
            let root_hash = hex_upper(&hxv4_path_hash("/"));
            self.paths
                .entry(root_hash)
                .or_insert_with(|| "/".to_string());
            let dir_count = parts.len().saturating_sub(1);
            let mut prefix = String::new();
            for (idx, part) in parts.iter().take(dir_count).enumerate() {
                if idx != 0 {
                    prefix.push('/');
                }
                prefix.push_str(part);
                let hash = hex_upper(&hxv4_path_hash(&prefix));
                self.paths.entry(hash).or_insert_with(|| prefix.clone());
                let rooted = format!("/{prefix}");
                let rooted_hash = hex_upper(&hxv4_path_hash(&rooted));
                self.paths.entry(rooted_hash).or_insert(rooted);
            }
        }
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut lines = Vec::with_capacity(self.paths.len() + self.names.len());
        let mut paths: Vec<_> = self.paths.iter().collect();
        paths.sort_by(|a, b| a.0.cmp(b.0));
        let mut names: Vec<_> = self.names.iter().collect();
        names.sort_by(|a, b| a.0.cmp(b.0));
        for (hash, value) in paths {
            lines.push(format!("{hash}:{value}"));
        }
        for (hash, value) in names {
            lines.push(format!("{hash}:{value}"));
        }
        fs::write(path, lines.join("\n") + "\n")?;
        Ok(())
    }
}

/// Authenticate and decrypt the Hxv4 Special payload without decompressing it.
///
/// Stored layout: `tag[16] || XChaCha20 ciphertext`. RustCrypto's AEAD API
/// expects `ciphertext || tag`, so the input is reordered before verification.
/// The returned bytes are the exact authenticated plaintext: a 4-byte little-
/// endian uncompressed-size field followed by the zlib stream.
pub fn decrypt_hxv4_special_plaintext(blob: &[u8], keys: &Hxv4IndexKeys) -> Result<Vec<u8>> {
    if blob.len() < 21 {
        return Err(Error::format("Hxv4 special index is too short"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.key)
        .map_err(|_| Error::invalid("invalid Hxv4 XChaCha20 key length"))?;
    let mut sealed = Vec::with_capacity(blob.len());
    sealed.extend_from_slice(&blob[16..]);
    sealed.extend_from_slice(&blob[..16]);
    cipher
        .decrypt(XNonce::from_slice(&keys.nonce), sealed.as_ref())
        .map_err(|_| Error::format("Hxv4 XChaCha20-Poly1305 authentication failed"))
}

/// Authenticate, decrypt, and zlib-decompress the Hxv4 Special index.
pub fn decrypt_hxv4_special_payload(blob: &[u8], keys: &Hxv4IndexKeys) -> Result<Vec<u8>> {
    let decrypted = decrypt_hxv4_special_plaintext(blob, keys)?;
    if decrypted.len() <= 4 {
        return Err(Error::format("Hxv4 special-index plaintext is truncated"));
    }

    let expected = u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
    if expected == 0 || expected > 256 * 1024 * 1024 {
        return Err(Error::format(format!(
            "Hxv4 special-index uncompressed size is unreasonable: {expected}"
        )));
    }
    let mut decoder = ZlibDecoder::new(&decrypted[4..]);
    let mut inflated = Vec::with_capacity(expected.min(16 * 1024 * 1024));
    decoder
        .read_to_end(&mut inflated)
        .map_err(|e| Error::format(format!("Hxv4 special-index zlib failed: {e}")))?;
    if inflated.len() != expected {
        return Err(Error::format(format!(
            "Hxv4 special-index size mismatch: got {}, expected {}",
            inflated.len(),
            expected
        )));
    }
    Ok(inflated)
}

pub fn decrypt_hxv4_special_index(blob: &[u8], keys: &Hxv4IndexKeys) -> Result<Hxv4Index> {
    let inflated = decrypt_hxv4_special_payload(blob, keys)?;
    let mut cursor = Cursor::new(&inflated);
    let root = read_hx_object(&mut cursor, 0)?;
    if cursor.pos != inflated.len() {
        return Err(Error::format(format!(
            "Hxv4 index deserializer left {} trailing bytes",
            inflated.len() - cursor.pos
        )));
    }
    let entries = extract_hx_index_entries(&root)?;
    Ok(Hxv4Index {
        entries,
        decompressed_size: inflated.len(),
    })
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum HxObject {
    Null,
    String(String),
    Bytes(Vec<u8>),
    Int(i64),
    Float(f64),
    Array(Vec<HxObject>),
    Dict(BTreeMap<String, HxObject>),
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.data.len().saturating_sub(self.pos) {
            return Err(Error::format("truncated Hxv4 index object"));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn be_i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn be_i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn read_hx_object(cursor: &mut Cursor<'_>, depth: usize) -> Result<HxObject> {
    if depth > 128 {
        return Err(Error::format("Hxv4 index nesting limit exceeded"));
    }
    match cursor.u8()? {
        0x00 | 0x01 => Ok(HxObject::Null),
        0x02 => Ok(HxObject::String(read_hx_string(cursor)?)),
        0x03 => {
            let count = checked_count(cursor.be_i32()?, "Hxv4 byte array")?;
            Ok(HxObject::Bytes(cursor.take(count)?.to_vec()))
        }
        0x04 => Ok(HxObject::Int(cursor.be_i64()?)),
        0x05 => Ok(HxObject::Float(f64::from_bits(cursor.be_i64()? as u64))),
        0x81 => {
            let count = checked_count(cursor.be_i32()?, "Hxv4 array")?;
            if count > 2_000_000 {
                return Err(Error::format("Hxv4 array count is unreasonable"));
            }
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                out.push(read_hx_object(cursor, depth + 1)?);
            }
            Ok(HxObject::Array(out))
        }
        0xC1 => {
            let count = checked_count(cursor.be_i32()?, "Hxv4 dictionary")?;
            if count > 1_000_000 {
                return Err(Error::format("Hxv4 dictionary count is unreasonable"));
            }
            let mut out = BTreeMap::new();
            for _ in 0..count {
                let name = read_hx_string(cursor)?;
                let value = read_hx_object(cursor, depth + 1)?;
                out.insert(name, value);
            }
            Ok(HxObject::Dict(out))
        }
        other => Err(Error::format(format!(
            "unknown Hxv4 index object type 0x{other:02x}"
        ))),
    }
}

fn read_hx_string(cursor: &mut Cursor<'_>) -> Result<String> {
    let chars = checked_count(cursor.be_i32()?, "Hxv4 string")?;
    let bytes = chars
        .checked_mul(2)
        .ok_or_else(|| Error::format("Hxv4 string length overflow"))?;
    let raw = cursor.take(bytes)?;
    let words: Vec<u16> = raw
        .chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&words))
}

fn checked_count(value: i32, what: &str) -> Result<usize> {
    if value < 0 {
        return Err(Error::format(format!("negative {what} length")));
    }
    Ok(value as usize)
}

fn extract_hx_index_entries(root: &HxObject) -> Result<Vec<Hxv4IndexEntry>> {
    let HxObject::Array(root) = root else {
        return Err(Error::format("Hxv4 root object is not an array"));
    };
    if root.len() % 2 != 0 {
        return Err(Error::format("Hxv4 root array has odd pair count"));
    }

    let mut out = Vec::new();
    for pair in root.chunks_exact(2) {
        let HxObject::Bytes(path_hash) = &pair[0] else {
            return Err(Error::format("Hxv4 path hash is not an octet value"));
        };
        if path_hash.len() != 8 {
            return Err(Error::format(format!(
                "Hxv4 path hash has {} bytes, expected 8",
                path_hash.len()
            )));
        }
        let HxObject::Array(dir) = &pair[1] else {
            return Err(Error::format("Hxv4 path group is not an array"));
        };
        if dir.len() % 2 != 0 {
            return Err(Error::format("Hxv4 path group has odd pair count"));
        }

        let mut path = [0u8; 8];
        path.copy_from_slice(path_hash);
        for entry_pair in dir.chunks_exact(2) {
            let HxObject::Bytes(name_hash) = &entry_pair[0] else {
                return Err(Error::format("Hxv4 filename hash is not an octet value"));
            };
            if name_hash.len() != 32 {
                return Err(Error::format(format!(
                    "Hxv4 filename hash has {} bytes, expected 32",
                    name_hash.len()
                )));
            }
            let HxObject::Array(info) = &entry_pair[1] else {
                return Err(Error::format("Hxv4 record metadata is not an array"));
            };
            if info.len() != 2 {
                return Err(Error::format(format!(
                    "Hxv4 record metadata has {} values, expected 2",
                    info.len()
                )));
            }
            let HxObject::Int(packed) = &info[0] else {
                return Err(Error::format("Hxv4 packed locator is not an integer"));
            };
            let HxObject::Int(entry_key) = &info[1] else {
                return Err(Error::format("Hxv4 entry key is not an integer"));
            };
            if *packed < 0 {
                return Err(Error::format("Hxv4 packed locator is negative"));
            }

            let packed = *packed as u64;
            // `sub_10005850` proves the 64-bit layout: EAX (low32) is fed to
            // `sub_100179A0` to construct the fake XP3 name; EDX (high32) is
            // split into archive_slot=high16 and the per-entry local value=low16.
            let id = packed & 0xffff_ffff;
            let native_locator = (packed >> 32) as u32;
            let archive_slot = (native_locator >> 16) as u16;
            let filter_flag = native_locator as u16;
            let mut name = [0u8; 32];
            name.copy_from_slice(name_hash);
            out.push(Hxv4IndexEntry {
                record_index: out.len(),
                packed,
                archive_slot,
                filter_flag,
                id,
                entry_key: *entry_key as u64,
                path_hash: path,
                name_hash: name,
                path: None,
                name: None,
            });
        }
    }

    if out.is_empty() {
        return Err(Error::format("Hxv4 index contains no records"));
    }
    out.sort_by_key(|entry| (entry.archive_slot, entry.id, entry.record_index));
    Ok(out)
}

/// Hash a candidate Hxv4 directory/path name exactly as the known engine-side
/// implementation does: SipHash-2-4 with a zero key over UTF-16LE plus the
/// `xp3hnp` salt, followed by byte reversal.  `/` is a special root spelling.
pub fn hxv4_path_hash(path: &str) -> [u8; 8] {
    let mut text = if path == "/" {
        String::new()
    } else {
        path.to_string()
    };
    text.push_str(HXV4_SALT);
    let bytes = utf16le_bytes(&text);
    let value = siphash24_zero(&bytes);
    value.to_be_bytes()
}

/// Hash a candidate Hxv4 filename using the engine's BLAKE2s-like state with
/// UTF-16LE `xp3hnp` salt.  This is intentionally implemented locally rather
/// than depending on a C DLL so name dictionary recovery is cross-platform.
pub fn hxv4_filename_hash(name: &str) -> [u8; 32] {
    let mut text = name.to_string();
    text.push_str(HXV4_SALT);
    let data = utf16le_bytes(&text);
    let mut state = [
        0x6B08E647u32,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
        0,
        0,
        0,
        0,
    ];
    let mut total = 0u32;
    let mut offset = 0usize;
    while offset < data.len() {
        let take = (data.len() - offset).min(64);
        total = total.wrapping_add(take as u32);
        state[8] = total;
        state[10] = if offset + take == data.len() {
            u32::MAX
        } else {
            0
        };
        let mut block = [0u8; 64];
        block[..take].copy_from_slice(&data[offset..offset + take]);
        blake2s_compress_custom(&mut state, &block);
        offset += take;
    }
    let mut out = [0u8; 32];
    for (i, word) in state[..8].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn utf16le_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for word in text.encode_utf16() {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn blake2s_compress_custom(state: &mut [u32; 12], block: &[u8; 64]) {
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&state[..8]);
    v[8..].copy_from_slice(&IV);
    v[12] ^= state[8];
    v[13] ^= state[9];
    v[14] ^= state[10];
    v[15] ^= state[11];
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for s in SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        state[i] ^= v[i] ^ v[i + 8];
    }
}
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn siphash24_zero(data: &[u8]) -> u64 {
    let mut v0 = 0x736f6d6570736575u64;
    let mut v1 = 0x646f72616e646f6du64;
    let mut v2 = 0x6c7967656e657261u64;
    let mut v3 = 0x7465646279746573u64;
    let full = data.len() / 8 * 8;
    for chunk in data[..full].chunks_exact(8) {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
    let tail = &data[full..];
    let mut b = (data.len() as u64) << 56;
    for (i, &x) in tail.iter().enumerate() {
        b |= (x as u64) << (8 * i);
    }
    v3 ^= b;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;
    v2 ^= 0xff;
    for _ in 0..4 {
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13) ^ *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16) ^ *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21) ^ *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17) ^ *v2;
    *v2 = v2.rotate_left(32);
}

#[derive(Clone, Debug)]
pub struct Hxv4EffectiveFilter {
    pub split_position: usize,
    pub left_xor: u8,
    pub right_xor: u8,
    /// Composite XOR for the first 16 bytes.  It includes the span XOR and any
    /// sparse correction at those offsets, so applying this array alone yields
    /// the recovered header bytes.
    pub header_xor: [u8; 16],
    pub sparse_outliers: Vec<usize>,
    /// Effective one-byte corrections after the span XOR.  Hxv4 has at most
    /// two such absolute positions per span.  Values are the additional XOR.
    pub corrections: Vec<(usize, u8)>,
}

#[derive(Clone, Debug)]
pub struct Hxv4Recovery {
    pub format: String,
    pub filter: Hxv4EffectiveFilter,
    pub plaintext: Vec<u8>,
    pub adler_match: Option<bool>,
    pub gpu_used: bool,
}

/// Data-side recovery of the effective Hxv4 content filter.  This intentionally
/// does not claim to recover the original title-specific entry key/Cx program.
/// It exploits the effective piecewise-constant XOR shape visible at the file
/// boundary and validates candidates with a complete format grammar + adlr.
pub fn recover_hxv4_effective(
    ciphertext: &[u8],
    expected_adler: Option<u32>,
    compute_mode: ComputeMode,
) -> Result<Option<Hxv4Recovery>> {
    recover_hxv4_effective_with_hypotheses(
        ciphertext,
        expected_adler,
        compute_mode,
        builtin_hypotheses(),
        true,
    )
}

/// Strict HXV4 recovery for an entry whose real filename is already known.
///
/// This is the only content-recovery primitive used by the filename bootstrap:
/// it never broad-sniffs an unresolved hash-only entry.  The extension must map
/// to an explicit format model, and the resulting plaintext must pass that
/// model (plus adlr when present) before it can contribute more filename
/// candidates.
pub fn recover_hxv4_effective_for_name(
    ciphertext: &[u8],
    expected_adler: Option<u32>,
    compute_mode: ComputeMode,
    name: &str,
) -> Result<Option<Hxv4Recovery>> {
    let hypotheses = specific_hypotheses_for_name(name);
    if hypotheses.is_empty() {
        return Ok(None);
    }
    recover_hxv4_effective_with_hypotheses(
        ciphertext,
        expected_adler,
        compute_mode,
        hypotheses,
        false,
    )
}

fn recover_hxv4_effective_with_hypotheses(
    ciphertext: &[u8],
    expected_adler: Option<u32>,
    compute_mode: ComputeMode,
    hypotheses: Vec<FormatHypothesis>,
    allow_unknown_text_probe: bool,
) -> Result<Option<Hxv4Recovery>> {
    if ciphertext.len() < 8 {
        return Ok(None);
    }
    let mut best: Option<(i64, Hxv4Recovery)> = None;
    for hypothesis in hypotheses {
        let mut cribs = hypothesis.cribs.clone();
        cribs.extend(length_derived_cribs(&hypothesis, ciphertext.len()));
        let observations = exact_delta_observations(ciphertext, &hypothesis, &cribs);
        if observations.len() < 4 {
            continue;
        }
        let candidates = infer_piecewise_filters(ciphertext.len(), &observations, 4);
        for (rank, mut filter) in candidates.into_iter().take(32).enumerate() {
            // Hxv4 applies an independent 16-byte header XOR before the two
            // body spans.  Exact format facts fill deterministic bytes first;
            // any remaining *bounded* header ambiguity is solved with Adler
            // equations (GPU when profitable) and then the complete grammar.
            let Some((plaintext, header_xor, header_gpu)) = recover_hx_header(
                ciphertext,
                &filter,
                &hypothesis,
                &cribs,
                expected_adler,
                compute_mode,
            )?
            else {
                continue;
            };
            filter.header_xor = header_xor;
            let validation = validate_hypothesis(hypothesis.name, &plaintext);
            if !validation.is_strong() {
                continue;
            }
            let adler_match = expected_adler.map(|want| adler32(&plaintext) == want);
            if adler_match == Some(false) {
                continue;
            }
            let score =
                10_000i64 - (rank as i64) * 10 - (filter.sparse_outliers.len() as i64) * 100;
            let recovery = Hxv4Recovery {
                format: hypothesis.name.to_string(),
                filter,
                plaintext,
                adler_match,
                gpu_used: header_gpu,
            };
            if best.as_ref().map_or(true, |(s, _)| score > *s) {
                best = Some((score, recovery));
            }
        }
    }

    // Broad text probing is intentionally disabled for the name-bootstrap path:
    // an unresolved filename must never be "solved" merely to obtain more name
    // candidates.  The legacy full-unpack path may still use this conservative
    // candidate generator after the filename gate has opened.
    if allow_unknown_text_probe && best.is_none() && ciphertext.len() >= 128 {
        if let Some(recovery) = recover_textlike_hxv4(ciphertext, expected_adler, compute_mode)? {
            best = Some((100, recovery));
        }
    }
    Ok(best.map(|(_, r)| r))
}

const ADLER_MOD: u32 = 65_521;
const HXV4_HEADER_BRUTE_LIMIT: u128 = 1u128 << 24;
const HXV4_GPU_HEADER_MIN: u128 = 1u128 << 16;

fn mod_sub(a: u32, b: u32) -> u32 {
    ((a as u64 + ADLER_MOD as u64 - b as u64) % ADLER_MOD as u64) as u32
}

fn header_candidate_sets(
    hypothesis: &FormatHypothesis,
    cribs: &[Crib],
    len: usize,
) -> Option<Vec<Vec<u8>>> {
    let used = len.min(16);
    let mut allowed = vec![[true; 256]; used];
    for crib in cribs {
        for (delta, &plain) in crib.plaintext.iter().enumerate() {
            let Ok(base) = usize::try_from(crib.offset) else {
                continue;
            };
            let Some(off) = base.checked_add(delta) else {
                continue;
            };
            if off >= used {
                continue;
            }
            allowed[off].fill(false);
            allowed[off][plain as usize] = true;
        }
    }
    for constraint in hard_plaintext_constraints(hypothesis, len) {
        let Ok(off) = usize::try_from(constraint.offset) else {
            continue;
        };
        if off >= used || constraint.allowed.is_empty() {
            continue;
        }
        let mut permitted = [false; 256];
        for &value in &constraint.allowed {
            permitted[value as usize] = true;
        }
        for value in 0..256 {
            allowed[off][value] &= permitted[value];
        }
    }
    allowed
        .into_iter()
        .map(|bits| {
            let values: Vec<u8> = bits
                .iter()
                .enumerate()
                .filter_map(|(v, &yes)| yes.then_some(v as u8))
                .collect();
            (!values.is_empty()).then_some(values)
        })
        .collect()
}

fn adler_target(expected: u32, len: usize) -> (u32, u32) {
    let final_a = expected & 0xffff;
    let final_b = expected >> 16;
    (
        mod_sub(final_a, 1),
        mod_sub(final_b, (len as u64 % ADLER_MOD as u64) as u32),
    )
}

fn contribution_add(a: &mut u32, b: &mut u32, offset: usize, value: u8, len: usize) {
    *a = (*a + value as u32) % ADLER_MOD;
    let weight = ((len - offset) as u64 % ADLER_MOD as u64) as u32;
    *b = (*b + ((weight as u64 * value as u64) % ADLER_MOD as u64) as u32) % ADLER_MOD;
}

/// Solve the independent first-16-byte Hx header filter after a body-span
/// candidate has been recovered.  Adler is used as a search constraint, not as
/// a success oracle: every hit is still parsed by the caller's strong grammar.
fn recover_hx_header(
    ciphertext: &[u8],
    filter: &Hxv4EffectiveFilter,
    hypothesis: &FormatHypothesis,
    cribs: &[Crib],
    expected_adler: Option<u32>,
    compute_mode: ComputeMode,
) -> Result<Option<(Vec<u8>, [u8; 16], bool)>> {
    let sets = match header_candidate_sets(hypothesis, cribs, ciphertext.len()) {
        Some(v) => v,
        None => return Ok(None),
    };
    let used = sets.len();
    let mut total = 1u128;
    for set in &sets {
        total = match total.checked_mul(set.len() as u128) {
            Some(v) => v,
            None => return Ok(None),
        };
        if total > HXV4_HEADER_BRUTE_LIMIT {
            return Ok(None);
        }
    }

    let base = apply_effective_filter(ciphertext, filter);
    let accept = |header: &[u8], mut plain: Vec<u8>| -> Option<(Vec<u8>, [u8; 16])> {
        let mut hx = [0u8; 16];
        for i in 0..used {
            plain[i] = header[i];
            hx[i] = ciphertext[i] ^ header[i];
        }
        let validation = validate_hypothesis(hypothesis.name, &plain);
        if !validation.is_strong() {
            return None;
        }
        if expected_adler.is_some_and(|want| adler32(&plain) != want) {
            return None;
        }
        Some((plain, hx))
    };

    if total == 1 {
        let header: Vec<u8> = sets.iter().map(|s| s[0]).collect();
        return Ok(accept(&header, base).map(|(p, h)| (p, h, false)));
    }

    if let Some(expected) = expected_adler {
        let mut fixed_a = 0u32;
        let mut fixed_b = 0u32;
        for (offset, &value) in base.iter().enumerate().skip(used) {
            contribution_add(&mut fixed_a, &mut fixed_b, offset, value, base.len());
        }
        let mut ambiguous = Vec::<(usize, Vec<u8>)>::new();
        for (offset, set) in sets.iter().enumerate() {
            if set.len() == 1 {
                contribution_add(&mut fixed_a, &mut fixed_b, offset, set[0], base.len());
            } else {
                ambiguous.push((offset, set.clone()));
            }
        }
        let (target_a, target_b) = adler_target(expected, base.len());
        let need_a = mod_sub(target_a, fixed_a);
        let need_b = mod_sub(target_b, fixed_b);
        if total <= u32::MAX as u128 {
            let problem = AdlerGpuProblem {
                total_combinations: total as u32,
                need_a,
                need_b,
                slots: ambiguous
                    .iter()
                    .map(|(offset, set)| AdlerGpuSlot {
                        key_slot: *offset,
                        choices: set
                            .iter()
                            .map(|&value| {
                                let mut a = 0u32;
                                let mut b = 0u32;
                                contribution_add(&mut a, &mut b, *offset, value, base.len());
                                AdlerGpuChoice { value, a, b }
                            })
                            .collect(),
                    })
                    .collect(),
            };
            if total >= HXV4_GPU_HEADER_MIN {
                if let Some(result) = gpu_adler_search(compute_mode, &problem, HXV4_GPU_HEADER_MIN)
                    .map_err(|e| Error::invalid(format!("Hxv4 GPU header search failed: {e}")))?
                {
                    for hit in result.hit_indices {
                        let mut mixed = hit as usize;
                        let mut header: Vec<u8> = sets.iter().map(|s| s[0]).collect();
                        for (offset, set) in &ambiguous {
                            let digit = mixed % set.len();
                            mixed /= set.len();
                            header[*offset] = set[digit];
                        }
                        if let Some((p, h)) = accept(&header, base.clone()) {
                            return Ok(Some((p, h, true)));
                        }
                    }
                    return Ok(None);
                }
            }
        }

        // Lossless CPU fallback for the same bounded space.  Check the two
        // Adler sums before invoking the expensive grammar validator.
        fn walk(
            idx: usize,
            ambiguous: &[(usize, Vec<u8>)],
            header: &mut [u8],
            a: u32,
            b: u32,
            need_a: u32,
            need_b: u32,
            len: usize,
            base: &[u8],
            hypothesis: &FormatHypothesis,
            expected: u32,
            ciphertext: &[u8],
        ) -> Option<(Vec<u8>, [u8; 16])> {
            if idx == ambiguous.len() {
                if a != need_a || b != need_b {
                    return None;
                }
                let mut plain = base.to_vec();
                let mut hx = [0u8; 16];
                for i in 0..header.len() {
                    plain[i] = header[i];
                    hx[i] = ciphertext[i] ^ header[i];
                }
                if adler32(&plain) != expected
                    || !validate_hypothesis(hypothesis.name, &plain).is_strong()
                {
                    return None;
                }
                return Some((plain, hx));
            }
            let (offset, set) = &ambiguous[idx];
            for &value in set {
                header[*offset] = value;
                let mut na = a;
                let mut nb = b;
                contribution_add(&mut na, &mut nb, *offset, value, len);
                if let Some(v) = walk(
                    idx + 1,
                    ambiguous,
                    header,
                    na,
                    nb,
                    need_a,
                    need_b,
                    len,
                    base,
                    hypothesis,
                    expected,
                    ciphertext,
                ) {
                    return Some(v);
                }
            }
            None
        }
        let mut header: Vec<u8> = sets.iter().map(|s| s[0]).collect();
        if let Some((p, h)) = walk(
            0,
            &ambiguous,
            &mut header,
            0,
            0,
            need_a,
            need_b,
            base.len(),
            &base,
            hypothesis,
            expected,
            ciphertext,
        ) {
            return Ok(Some((p, h, false)));
        }
        return Ok(None);
    }

    // Without an Adler checksum, only enumerate genuinely tiny header spaces.
    if total > (1u128 << 16) {
        return Ok(None);
    }
    fn walk_plain(
        idx: usize,
        sets: &[Vec<u8>],
        header: &mut [u8],
        base: &[u8],
        hypothesis: &FormatHypothesis,
        ciphertext: &[u8],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        if idx == sets.len() {
            let mut plain = base.to_vec();
            let mut hx = [0u8; 16];
            for i in 0..header.len() {
                plain[i] = header[i];
                hx[i] = ciphertext[i] ^ header[i];
            }
            return validate_hypothesis(hypothesis.name, &plain)
                .is_strong()
                .then_some((plain, hx));
        }
        for &v in &sets[idx] {
            header[idx] = v;
            if let Some(x) = walk_plain(idx + 1, sets, header, base, hypothesis, ciphertext) {
                return Some(x);
            }
        }
        None
    }
    let mut header = vec![0u8; used];
    Ok(
        walk_plain(0, &sets, &mut header, &base, hypothesis, ciphertext)
            .map(|(p, h)| (p, h, false)),
    )
}

fn exact_delta_observations(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    cribs: &[Crib],
) -> Vec<(usize, u8)> {
    let mut out = Vec::new();
    for crib in cribs {
        for (delta, &p) in crib.plaintext.iter().enumerate() {
            let off = crib.offset as usize + delta;
            if off >= 16 && off < ciphertext.len() {
                out.push((off, ciphertext[off] ^ p));
            }
        }
    }
    for constraint in hard_plaintext_constraints(hypothesis, ciphertext.len()) {
        let Ok(offset) = usize::try_from(constraint.offset) else {
            continue;
        };
        if offset >= 16 && offset < ciphertext.len() && constraint.allowed.len() == 1 {
            out.push((offset, ciphertext[offset] ^ constraint.allowed[0]));
        }
    }
    out.sort_by_key(|x| x.0);
    out.dedup();
    out
}

fn infer_piecewise_filters(
    len: usize,
    obs: &[(usize, u8)],
    max_outliers: usize,
) -> Vec<Hxv4EffectiveFilter> {
    let mut boundaries = vec![16usize, len];
    for &(off, _) in obs {
        boundaries.push(off);
        boundaries.push(off.saturating_add(1).min(len));
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    let mut scored = Vec::new();
    for split in boundaries {
        let (lk, ls, lo) = mode_for(obs.iter().copied().filter(|(o, _)| *o < split));
        let (rk, rs, ro) = mode_for(obs.iter().copied().filter(|(o, _)| *o >= split));
        let left = lk.unwrap_or_else(|| rk.unwrap_or(0));
        let right = rk.unwrap_or(left);
        let outliers = lo + ro;
        if outliers > max_outliers || ls + rs < 2 {
            continue;
        }
        let mut sparse = Vec::new();
        let mut corrections = Vec::new();
        for &(o, d) in obs {
            let k = if o < split { left } else { right };
            if d != k {
                sparse.push(o);
                corrections.push((o, d ^ k));
            }
        }
        // The concrete Hx filter has no more than two corrections per span.
        if corrections.iter().filter(|(o, _)| *o < split).count() > 2
            || corrections.iter().filter(|(o, _)| *o >= split).count() > 2
        {
            continue;
        }
        scored.push((
            ls + rs,
            outliers,
            Hxv4EffectiveFilter {
                split_position: split,
                left_xor: left,
                right_xor: right,
                header_xor: [0; 16],
                sparse_outliers: sparse,
                corrections,
            },
        ));
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.into_iter().map(|x| x.2).collect()
}
fn mode_for<I: Iterator<Item = (usize, u8)>>(iter: I) -> (Option<u8>, usize, usize) {
    let mut counts = [0usize; 256];
    let mut total = 0;
    for (_, v) in iter {
        counts[v as usize] += 1;
        total += 1;
    }
    let (best, count) = counts
        .iter()
        .enumerate()
        .max_by_key(|(_, c)| **c)
        .map(|(i, c)| (i as u8, *c))
        .unwrap_or((0, 0));
    (count > 0)
        .then_some(best)
        .map_or((None, 0, total), |v| (Some(v), count, total - count))
}

pub fn apply_effective_filter(ciphertext: &[u8], filter: &Hxv4EffectiveFilter) -> Vec<u8> {
    let mut out = ciphertext.to_vec();
    let body_start = 16usize.min(out.len());
    let split = filter.split_position.clamp(body_start, out.len());
    xor_const_in_place(&mut out[body_start..split], filter.left_xor);
    xor_const_in_place(&mut out[split..], filter.right_xor);
    for &(offset, extra) in &filter.corrections {
        if offset >= body_start && offset < out.len() {
            out[offset] ^= extra;
        }
    }
    for i in 0..body_start {
        out[i] = ciphertext[i] ^ filter.header_xor[i];
    }
    out
}

fn recover_textlike_hxv4(
    ciphertext: &[u8],
    expected_adler: Option<u32>,
    compute_mode: ComputeMode,
) -> Result<Option<Hxv4Recovery>> {
    // Evaluate a modest set of split candidates.  Prefix/suffix histograms are
    // scored under a byte-language model by the existing 256-way wgpu kernel.
    let splits: Vec<usize> = (64..ciphertext.len())
        .step_by((ciphertext.len() / 64).max(32))
        .take(64)
        .collect();
    if splits.is_empty() {
        return Ok(None);
    }
    // O(N + splits*256), not O(N*splits): advance one prefix histogram and
    // derive the suffix from the total histogram.  This matters for multi-MiB
    // Hx archives where the GPU must not be starved by CPU histogram building.
    let mut total = [0u32; 256];
    for &b in &ciphertext[16..] {
        total[b as usize] += 1;
    }
    let mut left = [0u32; 256];
    let mut cursor = 16usize;
    let mut histograms = Vec::<[u32; 256]>::with_capacity(splits.len() * 2);
    for &split in &splits {
        for &b in &ciphertext[cursor..split] {
            left[b as usize] += 1;
        }
        cursor = split;
        let mut right = total;
        for i in 0..256 {
            right[i] = right[i].saturating_sub(left[i]);
        }
        histograms.push(left);
        histograms.push(right);
    }
    let logp = text_log_probabilities();
    let gpu = gpu_slot_scores(compute_mode, &histograms, &logp, 4096)
        .map_err(|e| Error::invalid(format!("Hxv4 GPU span scoring failed: {e}")))?;
    let gpu_used = gpu.is_some();
    let rows = if let Some(gpu) = gpu {
        gpu.scores
    } else {
        histograms
            .iter()
            .map(|h| cpu_hist_scores(h, &logp))
            .collect()
    };
    let mut ranked = Vec::new();
    for (i, &split) in splits.iter().enumerate() {
        let (lk, ls) = best_score(&rows[i * 2]);
        let (rk, rs) = best_score(&rows[i * 2 + 1]);
        ranked.push((ls + rs, split, lk, rk));
    }
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    for (_, split, left, right) in ranked.into_iter().take(16) {
        let filter = Hxv4EffectiveFilter {
            split_position: split,
            left_xor: left,
            right_xor: right,
            header_xor: [0; 16],
            sparse_outliers: Vec::new(),
            corrections: Vec::new(),
        };
        let mut plain = apply_effective_filter(ciphertext, &filter); // header intentionally remains unusable
                                                                     // Statistical mode cannot recover the independent 16-byte header key,
                                                                     // so only accept files whose meaningful payload begins after it and for
                                                                     // which adlr can still be satisfied.  At present this acts as a GPU
                                                                     // candidate generator and deliberately returns unresolved.
        let _ = &mut plain;
        let _ = expected_adler;
        let _ = gpu_used;
    }
    Ok(None)
}
fn text_log_probabilities() -> [f64; 256] {
    let mut p = [-7.0f64; 256];
    for b in 0x20u8..=0x7e {
        p[b as usize] = -2.5;
    }
    for &b in b" \t\r\n{}[](),.;:=+-*/_\\\"'" {
        p[b as usize] = -1.0;
    }
    p[0] = -1.5;
    for b in 0x80..=0xff {
        p[b] = -4.0;
    }
    p
}
fn cpu_hist_scores(hist: &[u32; 256], logp: &[f64; 256]) -> [f64; 256] {
    let mut out = [0.0; 256];
    for key in 0..256 {
        let mut s = 0.0;
        for c in 0..256 {
            s += hist[c] as f64 * logp[c ^ key];
        }
        out[key] = s;
    }
    out
}
fn best_score(row: &[f64; 256]) -> (u8, f64) {
    let mut best = (0u8, f64::NEG_INFINITY);
    for (i, &s) in row.iter().enumerate() {
        if s > best.1 {
            best = (i as u8, s);
        }
    }
    best
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let clean = value
        .trim()
        .trim_start_matches("0x")
        .replace(' ', "")
        .replace(':', "")
        .replace('-', "");
    if clean.len() != N * 2 {
        return Err(Error::invalid(format!("expected {} hex bytes", N)));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::invalid("invalid hex key"))?;
    }
    Ok(out)
}
fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02X}");
    }
    s
}

/// Mine filename/path candidates from recovered plaintext and TJS2 bytecode.
///
/// TJS2 bytecode keeps many useful constants as individually aligned UTF-16LE
/// strings, so decoding the *whole* byte stream as UTF-16 misses them when a
/// preceding binary field changes alignment or when NUL/control delimiters are
/// present.  Scan printable ASCII and UTF-16LE runs independently (both byte
/// alignments), then tokenize each run.  False candidates are harmless because
/// HXV4 accepts a name only after its native hash exactly matches the Special
/// table.
/// Visit filename/path candidates without materializing whole-file UTF-8/UTF-16
/// copies or a `Vec<String>` of every printable run.
///
/// Hash-only HXV4 recovery frequently feeds multi-megabyte binary resources into
/// the name miner.  The old implementation simultaneously kept a lossy UTF-8
/// copy, a UTF-16 copy, and three vectors of printable runs; on random/binary
/// data that could transiently require many times the entry size.  This scanner
/// keeps at most one 240-character token per encoding lane.
pub fn visit_name_candidates(bytes: &[u8], mut visit: impl FnMut(&str)) {
    fn is_separator(c: char) -> bool {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | ',' | ';' | '=')
    }

    fn emit(token: &mut String, overflowed: &mut bool, visit: &mut impl FnMut(&str)) {
        if *overflowed {
            token.clear();
            *overflowed = false;
            return;
        }
        if token.is_empty() {
            return;
        }
        let trimmed = token
            .trim_matches(|c: char| matches!(c, '[' | ']' | '{' | '}' | '`'))
            .trim_matches(|c: char| matches!(c, '!' | '?' | '>' | '<'));
        if !(3..=240).contains(&trimmed.chars().count()) {
            token.clear();
            return;
        }
        if trimmed.chars().any(|c| c.is_control() || c == '\u{fffd}') {
            token.clear();
            return;
        }
        let pathlike = trimmed.contains('.') || trimmed.contains('/') || trimmed.contains('\\');
        let stemlike = !pathlike
            && trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '+' | '@' | '~'));
        if pathlike || stemlike {
            if trimmed.contains('\\') {
                let normalized = trimmed.replace('\\', "/");
                visit(&normalized);
            } else {
                visit(trimmed);
            }
        }
        // On the wrong UTF-16 alignment, preceding binary bytes can form a
        // short run of valid non-ASCII code points immediately before a real
        // ASCII constant. Emit the all-ASCII suffix as an additional candidate
        // (the HXV4 hash table remains the acceptance oracle).
        if let Some((suffix_start, _)) = trimmed.char_indices().find(|(_, c)| c.is_ascii()) {
            if suffix_start != 0 {
                let suffix = &trimmed[suffix_start..];
                let suffix_pathlike =
                    suffix.contains('.') || suffix.contains('/') || suffix.contains('\\');
                if suffix_pathlike
                    && suffix.chars().all(|c| c.is_ascii() && !c.is_control())
                    && (3..=240).contains(&suffix.chars().count())
                {
                    if suffix.contains('\\') {
                        let normalized = suffix.replace('\\', "/");
                        visit(&normalized);
                    } else {
                        visit(suffix);
                    }
                }
            }
        }
        token.clear();
    }

    // ASCII/ASCII-compatible strings.  This is deliberately token-streaming:
    // a binary file with millions of short runs never produces a giant
    // intermediate `HashSet<String>`.
    let mut token = String::with_capacity(240);
    let mut overflowed = false;
    for &byte in bytes {
        let printable = byte == b'\t' || byte == b' ' || (0x21..=0x7e).contains(&byte);
        if !printable {
            emit(&mut token, &mut overflowed, &mut visit);
            continue;
        }
        let c = byte as char;
        if is_separator(c) {
            emit(&mut token, &mut overflowed, &mut visit);
            continue;
        }
        if !overflowed {
            if token.len() < 240 {
                token.push(c);
            } else {
                token.clear();
                overflowed = true;
            }
        }
    }
    emit(&mut token, &mut overflowed, &mut visit);

    // TJS/PSB-family binaries commonly keep useful constants as UTF-16LE and
    // may start them at either byte alignment.  Each lane is still O(1) extra
    // memory with respect to the input size.
    for alignment in 0..=1usize {
        let mut token = String::with_capacity(240);
        let mut token_chars = 0usize;
        let mut overflowed = false;
        let mut i = alignment;
        while i + 1 < bytes.len() {
            let word = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            i += 2;
            let Some(c) = char::from_u32(word as u32) else {
                emit(&mut token, &mut overflowed, &mut visit);
                token_chars = 0;
                continue;
            };
            if word == 0 || c.is_control() || c == '\u{fffd}' || matches!(word, 0xd800..=0xdfff) {
                emit(&mut token, &mut overflowed, &mut visit);
                token_chars = 0;
                continue;
            }
            if is_separator(c) {
                emit(&mut token, &mut overflowed, &mut visit);
                token_chars = 0;
                continue;
            }
            if !overflowed {
                if token_chars < 240 {
                    token.push(c);
                    token_chars += 1;
                } else {
                    token.clear();
                    token_chars = 0;
                    overflowed = true;
                }
            }
        }
        emit(&mut token, &mut overflowed, &mut visit);
    }
}

pub fn mine_name_candidates(bytes: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    visit_name_candidates(bytes, |candidate| {
        out.insert(candidate.to_string());
    });
    out
}
fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16_lossy(&words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hxv4_hash_vectors_match_reference_algorithm() {
        assert_eq!(hex_upper(&hxv4_path_hash("/")), "218649617CA9D494");
        assert_eq!(hex_upper(&hxv4_path_hash("scenario")), "4EFCD0B6AF3787F6");
        assert_eq!(
            hex_upper(&hxv4_filename_hash("macro_1.ks")),
            "8977D1C51B104017B9E9B8917878C781B6334A679973F290C60C6B674EC54243"
        );
        assert_eq!(
            hex_upper(&hxv4_filename_hash("startup.tjs")),
            "D9FB4859A254D7B9EDA6621CFBE7DFD9D428082090CA08E32A9314E7116548E9"
        );
    }

    #[test]
    fn effective_piecewise_inference() {
        let plain = b"0123456789abcdefPNG-body-known-structure-and-more";
        let mut c = plain.to_vec();
        for i in 16..c.len() {
            c[i] ^= if i < 32 { 0x5a } else { 0xa5 };
        }
        let obs: Vec<_> = (16..c.len()).map(|i| (i, c[i] ^ plain[i])).collect();
        let got = infer_piecewise_filters(c.len(), &obs, 4);
        assert!(got
            .iter()
            .any(|f| f.left_xor == 0x5a && f.right_xor == 0xa5));
    }

    #[test]
    fn tjs_bytecode_miner_recovers_individually_aligned_utf16_strings() {
        let mut bytes = vec![0x54, 0x4a, 0x53, 0x32, 0x31, 0x30, 0x30, 0x00, 0x7f];
        for word in "scenario/chapter01.ks".encode_utf16() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 0xff]);
        let names = mine_name_candidates(&bytes);
        assert!(
            names.contains("scenario/chapter01.ks"),
            "mined candidates: {names:?}"
        );
    }

    #[test]
    fn startup_anchor_requires_an_explicit_startup_name() {
        let entries = vec![
            Entry {
                name: "anything.bin".into(),
                hxv4_id: Some(7),
                ..Entry::default()
            },
            Entry {
                name: "opaque-anchor".into(),
                hxv4_id: None,
                ..Entry::default()
            },
        ];
        assert_eq!(hxv4_startup_entry_index(&entries), None);
    }

    #[test]
    fn startup_anchor_finds_explicit_startup_entry() {
        let entries = vec![
            Entry {
                name: "anything.bin".into(),
                hxv4_id: Some(7),
                ..Entry::default()
            },
            Entry {
                name: "STARTUP.TJS".into(),
                hxv4_id: None,
                ..Entry::default()
            },
            Entry {
                name: "other.bin".into(),
                hxv4_id: Some(8),
                ..Entry::default()
            },
        ];
        assert_eq!(hxv4_startup_entry_index(&entries), Some(1));
    }

    #[test]
    fn startup_hints_extract_bootstrap_prefix_and_media() {
        let script = br#"var x = System.bootStrap(  "prefix:value", cb); var media = "xp3hnp";"#;
        let hints = inspect_hxv4_startup_plaintext(3, script);
        assert_eq!(hints.entry_index, 3);
        assert_eq!(hints.bootstrap_prefix.as_deref(), Some("prefix:value"));
        assert_eq!(hints.media_name, "prefix");
    }

    #[test]
    fn hxv4_string_reader_is_utf16be() {
        let mut data = Vec::new();
        data.extend_from_slice(&3i32.to_be_bytes());
        for word in "abc".encode_utf16() {
            data.extend_from_slice(&word.to_be_bytes());
        }
        let mut cursor = Cursor::new(&data);
        assert_eq!(read_hx_string(&mut cursor).unwrap(), "abc");
    }

    #[test]
    fn hxv4_descriptor_bit_selects_nonce_slot_and_tag_is_prefix() {
        assert_eq!(hxv4_special_nonce_slot(0), 0);
        assert_eq!(hxv4_special_nonce_slot(1), 1);
        assert_eq!(hxv4_special_nonce_slot(2), 0);
        assert_eq!(hxv4_special_nonce_slot(3), 1);
        let blob: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            hxv4_special_tag(&blob),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
    }

    #[test]
    fn xchacha_poly1305_tag_prefix_round_trip() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;

        let mut table = Vec::new();
        table.push(0x81);
        table.extend_from_slice(&2i32.to_be_bytes());
        table.push(0x03);
        table.extend_from_slice(&8i32.to_be_bytes());
        table.extend_from_slice(&[0x11; 8]);
        table.push(0x81);
        table.extend_from_slice(&2i32.to_be_bytes());
        table.push(0x03);
        table.extend_from_slice(&32i32.to_be_bytes());
        table.extend_from_slice(&[0x22; 32]);
        table.push(0x81);
        table.extend_from_slice(&2i32.to_be_bytes());
        table.push(0x04);
        table.extend_from_slice(&7i64.to_be_bytes());
        table.push(0x04);
        table.extend_from_slice(&0x1122334455667788i64.to_be_bytes());

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&table).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&(table.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(&compressed);

        let keys = Hxv4IndexKeys {
            key: [0x33; 32],
            nonce: [0x44; 24],
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&keys.key).unwrap();
        let sealed = cipher
            .encrypt(XNonce::from_slice(&keys.nonce), plaintext.as_ref())
            .unwrap();
        let split = sealed.len() - 16;
        let mut stored = Vec::new();
        stored.extend_from_slice(&sealed[split..]);
        stored.extend_from_slice(&sealed[..split]);

        let decrypted = decrypt_hxv4_special_plaintext(&stored, &keys).unwrap();
        assert_eq!(decrypted, plaintext);
        let decoded = decrypt_hxv4_special_payload(&stored, &keys).unwrap();
        assert_eq!(decoded, table);
        let index = decrypt_hxv4_special_index(&stored, &keys).unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].record_index, 0);
        assert_eq!(index.entries[0].packed, 7);
        assert_eq!(index.entries[0].archive_slot, 0);
        assert_eq!(index.entries[0].filter_flag, 0);
        assert_eq!(index.entries[0].id, 7);
        assert_eq!(index.entries[0].entry_key, 0x1122334455667788);
    }
    #[test]
    fn hxv4_first_integer_splits_id_and_native_locator() {
        let root = HxObject::Array(vec![
            HxObject::Bytes(vec![0x11; 8]),
            HxObject::Array(vec![
                HxObject::Bytes(vec![0x22; 32]),
                HxObject::Array(vec![
                    HxObject::Int(0x0003_0042_1234_5678),
                    HxObject::Int(0x1234),
                ]),
            ]),
        ]);
        let index = extract_hx_index_entries(&root).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].packed, 0x0003_0042_1234_5678);
        assert_eq!(index[0].archive_slot, 3);
        assert_eq!(index[0].filter_flag, 0x42);
        assert_eq!(index[0].id, 0x1234_5678);
        let wrapped = Hxv4Index {
            entries: index,
            decompressed_size: 0,
        };
        assert!(
            wrapped.by_id().is_empty(),
            "non-local archive slots must not map to current XP3 ids"
        );
    }
}
