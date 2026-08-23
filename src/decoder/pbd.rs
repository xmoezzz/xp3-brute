//! KiriKiri TJS `ns0` / `4s0` binary encoded script (commonly `.pbd`).
//!
//! The implementation is intentionally independent from the XP3 layer.  It
//! preserves the container variant, seed, crypt field, IV and the otherwise
//! opaque 4s0 trailer so an exported JSON document can be encoded back to the
//! same PBD family instead of silently downgrading the file to `ns0`.

use blake2::{
    digest::{KeyInit, Mac},
    Blake2sMac256,
};
use lz4_flex::block::{compress, compress_with_dict, decompress_with_dict};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use xxhash_rust::xxh32::xxh32;

pub const PBD_NS0_MAGIC: &[u8; 8] = b"TJS/ns0\0";
pub const PBD_4S0_MAGIC: &[u8; 8] = b"TJS/4s0\0";
pub const PBD_JSON_SCHEMA: &str = "krkr-xp3-brute/pbd-v1";

const HEADER_SIZE: usize = 16;
const LZ4_BLOCK_SIZE: usize = 4096;
const LZ4_DICT_SIZE: usize = 64 * 1024;
const MAX_DEPTH: usize = 256;
const MAX_CONTAINER_ITEMS: usize = 1_000_000;
const MAX_STRING_UNITS: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PbdError {
    message: String,
}

impl PbdError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PbdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PbdError {}

impl From<std::io::Error> for PbdError {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbdVariant {
    Ns0,
    FourS0,
}

impl PbdVariant {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ns0 => "ns0",
            Self::FourS0 => "4s0",
        }
    }

    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Ns0 => PBD_NS0_MAGIC,
            Self::FourS0 => PBD_4S0_MAGIC,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PbdHeader {
    pub variant: PbdVariant,
    pub seed: u32,
    pub crypt: u16,
    pub iv: Vec<u8>,
    /// `4s0` carries a trailing u32 after the value stream.  Existing files
    /// preserve it verbatim because its engine-side semantic purpose is not
    /// required for decoding and must not be guessed during round-trip.
    pub trailer: Option<u32>,
    /// Whether the original TJS/4s0 framed LZ4 stream ended with an explicit
    /// zero-length block. This is preserved for variant-faithful repacking.
    pub lz4_terminated: bool,
}

#[derive(Debug, Clone)]
pub struct PbdDocument {
    pub header: PbdHeader,
    pub root: PbdValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "$type", rename_all = "kebab-case")]
pub enum PbdValue {
    Void,
    String {
        value: String,
    },
    Integer {
        value: i64,
    },
    /// IEEE-754 bits are authoritative so NaNs and signed zero round-trip
    /// exactly. `display` is only for humans/editors.
    Double {
        bits_hex: String,
        display: String,
    },
    Array {
        items: Vec<PbdValue>,
    },
    /// Keep entry order and duplicate keys. A JSON object/BTreeMap would lose
    /// both properties and is therefore unsuitable for a repack manifest.
    Dictionary {
        entries: Vec<PbdDictEntry>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PbdDictEntry {
    pub key: String,
    pub value: PbdValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PbdJsonDocument {
    pub schema: String,
    pub format: PbdJsonFormat,
    pub root: PbdValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PbdJsonFormat {
    pub variant: String,
    pub seed_hex: String,
    pub crypt: u16,
    pub iv_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailer_hex: Option<String>,
    pub string_encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lz4_block_size: Option<usize>,
    /// Preserve the optional explicit zero-sized LZ4 terminator used by some
    /// TJS/4s0 writers. Absent for ns0 and older exported JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lz4_terminated: Option<bool>,
}

impl PbdDocument {
    pub fn to_json_document(&self) -> PbdJsonDocument {
        PbdJsonDocument {
            schema: PBD_JSON_SCHEMA.to_string(),
            format: PbdJsonFormat {
                variant: self.header.variant.label().to_string(),
                seed_hex: format!("0x{:08x}", self.header.seed),
                crypt: self.header.crypt,
                iv_hex: hex_encode(&self.header.iv),
                trailer_hex: self.header.trailer.map(|value| format!("0x{value:08x}")),
                string_encoding: "utf-16le".to_string(),
                lz4_block_size: matches!(self.header.variant, PbdVariant::FourS0)
                    .then_some(LZ4_BLOCK_SIZE),
                lz4_terminated: matches!(self.header.variant, PbdVariant::FourS0)
                    .then_some(self.header.lz4_terminated),
            },
            root: self.root.clone(),
        }
    }
}

pub fn is_pbd_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(PBD_NS0_MAGIC) || bytes.starts_with(PBD_4S0_MAGIC)
}

pub fn decode_pbd(bytes: &[u8]) -> Result<PbdDocument, PbdError> {
    if bytes.len() < HEADER_SIZE {
        return Err(PbdError::new("PBD header is truncated"));
    }
    let variant = if bytes.starts_with(PBD_NS0_MAGIC) {
        PbdVariant::Ns0
    } else if bytes.starts_with(PBD_4S0_MAGIC) {
        PbdVariant::FourS0
    } else {
        return Err(PbdError::new("PBD magic is neither TJS/ns0 nor TJS/4s0"));
    };
    let seed = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let crypt = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
    let iv_len = u16::from_le_bytes(bytes[14..16].try_into().unwrap()) as usize;

    match variant {
        PbdVariant::Ns0 => {
            if crypt != 0 || iv_len != 0 {
                return Err(PbdError::new("TJS/ns0 must have crypt=0 and iv_len=0"));
            }
            let mut checker = ByteChecker::new(seed);
            let mut cursor = Cursor::new(&bytes[HEADER_SIZE..]);
            let root = parse_value(&mut cursor, &mut checker, 0)?;
            let checksum = cursor.read_u32_le()?;
            if checksum != checker.final_check() {
                return Err(PbdError::new(format!(
                    "TJS/ns0 checksum mismatch: stored=0x{checksum:08x} expected=0x{:08x}",
                    checker.final_check()
                )));
            }
            if !cursor.is_eof() {
                return Err(PbdError::new("TJS/ns0 has trailing bytes after checksum"));
            }
            Ok(PbdDocument {
                header: PbdHeader {
                    variant,
                    seed,
                    crypt,
                    iv: Vec::new(),
                    trailer: None,
                    lz4_terminated: false,
                },
                root,
            })
        }
        PbdVariant::FourS0 => {
            let iv_end = HEADER_SIZE
                .checked_add(iv_len)
                .ok_or_else(|| PbdError::new("PBD IV length overflow"))?;
            if iv_end > bytes.len() {
                return Err(PbdError::new("TJS/4s0 IV is truncated"));
            }
            validate_crypt_field(crypt)?;
            let iv = bytes[HEADER_SIZE..iv_end].to_vec();
            let mut framed = bytes[iv_end..].to_vec();
            if crypt != 0 {
                crypt_4s0_in_place(&mut framed, seed, crypt, &iv)?;
            }
            let (plain, lz4_terminated) = decompress_4s0_frames(&framed)?;
            let mut cursor = Cursor::new(&plain);
            let mut checker = FourS0Checker::new(seed);
            let root = parse_value(&mut cursor, &mut checker, 0)?;
            let trailer = cursor.read_u32_le()?;
            if !cursor.is_eof() {
                return Err(PbdError::new("TJS/4s0 has trailing bytes after trailer"));
            }
            Ok(PbdDocument {
                header: PbdHeader {
                    variant,
                    seed,
                    crypt,
                    iv,
                    trailer: Some(trailer),
                    lz4_terminated,
                },
                root,
            })
        }
    }
}

pub fn decode_pbd_file(path: impl AsRef<Path>) -> Result<PbdDocument, PbdError> {
    decode_pbd(&fs::read(path)?)
}

pub fn pbd_json_output_path(source: &Path) -> PathBuf {
    let file_name = source
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("script.pbd");
    source.with_file_name(format!("{file_name}.json"))
}

pub fn export_pbd_json(bytes: &[u8], source: &Path) -> Result<PathBuf, PbdError> {
    let document = decode_pbd(bytes)?;
    let output = pbd_json_output_path(source);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&document.to_json_document())
        .map_err(|e| PbdError::new(format!("serialize PBD JSON: {e}")))?;
    fs::write(&output, json)?;
    Ok(output)
}

pub fn encode_pbd_json(document: &PbdJsonDocument) -> Result<Vec<u8>, PbdError> {
    if document.schema != PBD_JSON_SCHEMA {
        return Err(PbdError::new(format!(
            "unsupported PBD JSON schema {:?}; expected {:?}",
            document.schema, PBD_JSON_SCHEMA
        )));
    }
    let variant = match document.format.variant.to_ascii_lowercase().as_str() {
        "ns0" => PbdVariant::Ns0,
        "4s0" => PbdVariant::FourS0,
        other => return Err(PbdError::new(format!("unsupported PBD variant {other:?}"))),
    };
    let seed = parse_hex_u32(&document.format.seed_hex, "seed_hex")?;
    let iv = hex_decode(&document.format.iv_hex)?;
    let trailer = match &document.format.trailer_hex {
        Some(value) => Some(parse_hex_u32(value, "trailer_hex")?),
        None => None,
    };
    encode_pbd(&PbdDocument {
        header: PbdHeader {
            variant,
            seed,
            crypt: document.format.crypt,
            iv,
            trailer,
            lz4_terminated: document.format.lz4_terminated.unwrap_or(false),
        },
        root: document.root.clone(),
    })
}

pub fn encode_pbd(document: &PbdDocument) -> Result<Vec<u8>, PbdError> {
    let mut out = Vec::new();
    out.extend_from_slice(document.header.variant.magic());
    out.extend_from_slice(&document.header.seed.to_le_bytes());

    match document.header.variant {
        PbdVariant::Ns0 => {
            if document.header.crypt != 0 || !document.header.iv.is_empty() {
                return Err(PbdError::new(
                    "TJS/ns0 encoder requires crypt=0 and an empty IV",
                ));
            }
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            let mut checker = ByteChecker::new(document.header.seed);
            write_value(&mut out, &document.root, &mut checker, 0)?;
            out.extend_from_slice(&checker.final_check().to_le_bytes());
        }
        PbdVariant::FourS0 => {
            validate_crypt_field(document.header.crypt)?;
            if document.header.iv.len() > u16::MAX as usize {
                return Err(PbdError::new("TJS/4s0 IV exceeds u16 length"));
            }
            let trailer = document.header.trailer.ok_or_else(|| {
                PbdError::new("TJS/4s0 round-trip requires trailer_hex from the source PBD")
            })?;
            out.extend_from_slice(&document.header.crypt.to_le_bytes());
            out.extend_from_slice(&(document.header.iv.len() as u16).to_le_bytes());
            out.extend_from_slice(&document.header.iv);

            let mut plain = Vec::new();
            let mut checker = FourS0Checker::new(document.header.seed);
            write_value(&mut plain, &document.root, &mut checker, 0)?;
            plain.extend_from_slice(&trailer.to_le_bytes());
            let mut framed = compress_4s0_frames(&plain, document.header.lz4_terminated)?;
            if document.header.crypt != 0 {
                crypt_4s0_in_place(
                    &mut framed,
                    document.header.seed,
                    document.header.crypt,
                    &document.header.iv,
                )?;
            }
            out.extend_from_slice(&framed);
        }
    }
    Ok(out)
}

pub fn encode_pbd_json_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<(), PbdError> {
    let json = fs::read(input)?;
    let document: PbdJsonDocument =
        serde_json::from_slice(&json).map_err(|e| PbdError::new(format!("parse PBD JSON: {e}")))?;
    let bytes = encode_pbd_json(&document)?;
    let output = output.as_ref();
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, bytes)?;
    Ok(())
}

trait TypeChecker {
    fn byte_for_type(&mut self, type_code: u8) -> u8;
}

#[derive(Clone, Copy)]
struct ByteChecker {
    seed: u32,
}

impl ByteChecker {
    fn new(seed: u32) -> Self {
        Self { seed }
    }

    fn round(bytes: &mut [u8; 4]) {
        let a = bytes[0] ^ bytes[0].wrapping_mul(2);
        let mut b = a;
        b >>= 2;
        b ^= bytes[2];
        b >>= 3;
        b ^= bytes[2];
        b ^= a;
        bytes[0] = bytes[1];
        bytes[1] = bytes[2];
        bytes[2] = b;
    }

    fn final_check(&self) -> u32 {
        let mut bytes = self.seed.to_le_bytes();
        Self::round(&mut bytes);
        Self::round(&mut bytes);
        Self::round(&mut bytes);
        bytes.swap(0, 2);
        u32::from_le_bytes(bytes)
    }
}

impl TypeChecker for ByteChecker {
    fn byte_for_type(&mut self, type_code: u8) -> u8 {
        let mut bytes = self.seed.to_le_bytes();
        if type_code == 0 {
            return bytes[2];
        }
        Self::round(&mut bytes);
        self.seed = u32::from_le_bytes(bytes);
        bytes[2]
    }
}

#[derive(Clone, Copy)]
struct FourS0Checker {
    b0: u8,
    b1: u8,
    b2: u8,
}

impl FourS0Checker {
    fn new(seed: u32) -> Self {
        Self {
            b0: ((seed >> 24) as u8) ^ seed as u8,
            b1: (seed >> 8) as u8,
            b2: (seed >> 16) as u8,
        }
    }
}

impl TypeChecker for FourS0Checker {
    fn byte_for_type(&mut self, type_code: u8) -> u8 {
        if type_code == 0 {
            return self.b2;
        }
        let t = self.b0 ^ self.b0.wrapping_shl(1);
        self.b0 = self.b1;
        self.b1 = self.b2;
        self.b2 = self.b2 ^ (self.b2 >> 3) ^ t ^ (t >> 5);
        self.b2
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }
    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PbdError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| PbdError::new("PBD cursor overflow"))?;
        if end > self.bytes.len() {
            return Err(PbdError::new("PBD value stream is truncated"));
        }
        let value = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(value)
    }
    fn read_u8(&mut self) -> Result<u8, PbdError> {
        Ok(self.read_exact(1)?[0])
    }
    fn read_u32_le(&mut self) -> Result<u32, PbdError> {
        Ok(u32::from_le_bytes(self.read_exact(4)?.try_into().unwrap()))
    }
    fn read_i64_le(&mut self) -> Result<i64, PbdError> {
        Ok(i64::from_le_bytes(self.read_exact(8)?.try_into().unwrap()))
    }
    fn read_u64_le(&mut self) -> Result<u64, PbdError> {
        Ok(u64::from_le_bytes(self.read_exact(8)?.try_into().unwrap()))
    }
}

fn parse_value<C: TypeChecker>(
    cursor: &mut Cursor<'_>,
    checker: &mut C,
    depth: usize,
) -> Result<PbdValue, PbdError> {
    if depth > MAX_DEPTH {
        return Err(PbdError::new("PBD value nesting exceeds safety limit"));
    }
    let type_code = cursor.read_u8()?;
    let check = cursor.read_u8()?;
    let expected = checker.byte_for_type(type_code);
    if check != expected {
        return Err(PbdError::new(format!(
            "PBD type check mismatch at byte {}: type=0x{type_code:02x} stored=0x{check:02x} expected=0x{expected:02x}",
            cursor.pos.saturating_sub(1)
        )));
    }
    match type_code {
        0 => Ok(PbdValue::Void),
        2 => Ok(PbdValue::String {
            value: read_utf16_string(cursor)?,
        }),
        4 => Ok(PbdValue::Integer {
            value: cursor.read_i64_le()?,
        }),
        5 => {
            let bits = cursor.read_u64_le()?;
            let value = f64::from_bits(bits);
            Ok(PbdValue::Double {
                bits_hex: format!("0x{bits:016x}"),
                display: format!("{value:?}"),
            })
        }
        0x81 => {
            let count = cursor.read_u32_le()? as usize;
            if count > MAX_CONTAINER_ITEMS || count > cursor.remaining().saturating_div(2) + 1 {
                return Err(PbdError::new(
                    "PBD array count exceeds safety/remaining-data limit",
                ));
            }
            let mut items = Vec::with_capacity(count.min(65536));
            for _ in 0..count {
                items.push(parse_value(cursor, checker, depth + 1)?);
            }
            Ok(PbdValue::Array { items })
        }
        0xc1 => {
            let count = cursor.read_u32_le()? as usize;
            if count > MAX_CONTAINER_ITEMS {
                return Err(PbdError::new("PBD dictionary count exceeds safety limit"));
            }
            let mut entries = Vec::with_capacity(count.min(65536));
            for _ in 0..count {
                let key = read_utf16_string(cursor)?;
                let value = parse_value(cursor, checker, depth + 1)?;
                entries.push(PbdDictEntry { key, value });
            }
            Ok(PbdValue::Dictionary { entries })
        }
        other => Err(PbdError::new(format!(
            "unsupported PBD value type 0x{other:02x}"
        ))),
    }
}

fn read_utf16_string(cursor: &mut Cursor<'_>) -> Result<String, PbdError> {
    let units = cursor.read_u32_le()? as usize;
    if units > MAX_STRING_UNITS {
        return Err(PbdError::new("PBD UTF-16 string exceeds safety limit"));
    }
    let byte_len = units
        .checked_mul(2)
        .ok_or_else(|| PbdError::new("PBD UTF-16 length overflow"))?;
    let bytes = cursor.read_exact(byte_len)?;
    let mut values = Vec::with_capacity(units.min(65536));
    for pair in bytes.chunks_exact(2) {
        values.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    String::from_utf16(&values).map_err(|_| PbdError::new("PBD string contains invalid UTF-16"))
}

fn write_value<C: TypeChecker>(
    out: &mut Vec<u8>,
    value: &PbdValue,
    checker: &mut C,
    depth: usize,
) -> Result<(), PbdError> {
    if depth > MAX_DEPTH {
        return Err(PbdError::new("PBD value nesting exceeds safety limit"));
    }
    let type_code = match value {
        PbdValue::Void => 0,
        PbdValue::String { .. } => 2,
        PbdValue::Integer { .. } => 4,
        PbdValue::Double { .. } => 5,
        PbdValue::Array { .. } => 0x81,
        PbdValue::Dictionary { .. } => 0xc1,
    };
    out.push(type_code);
    out.push(checker.byte_for_type(type_code));
    match value {
        PbdValue::Void => {}
        PbdValue::String { value } => write_utf16_string(out, value)?,
        PbdValue::Integer { value } => out.extend_from_slice(&value.to_le_bytes()),
        PbdValue::Double { bits_hex, .. } => {
            let bits = parse_hex_u64(bits_hex, "double bits_hex")?;
            out.extend_from_slice(&bits.to_le_bytes());
        }
        PbdValue::Array { items } => {
            if items.len() > u32::MAX as usize {
                return Err(PbdError::new("PBD array is too large"));
            }
            out.extend_from_slice(&(items.len() as u32).to_le_bytes());
            for item in items {
                write_value(out, item, checker, depth + 1)?;
            }
        }
        PbdValue::Dictionary { entries } => {
            if entries.len() > u32::MAX as usize {
                return Err(PbdError::new("PBD dictionary is too large"));
            }
            out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            for entry in entries {
                write_utf16_string(out, &entry.key)?;
                write_value(out, &entry.value, checker, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn write_utf16_string(out: &mut Vec<u8>, value: &str) -> Result<(), PbdError> {
    let utf16 = value.encode_utf16().collect::<Vec<_>>();
    if utf16.len() > u32::MAX as usize {
        return Err(PbdError::new("PBD UTF-16 string is too large"));
    }
    out.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    for unit in utf16 {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

fn validate_crypt_field(crypt: u16) -> Result<(), PbdError> {
    if crypt <= 6 {
        Ok(())
    } else {
        Err(PbdError::new(format!(
            "unsupported TJS/4s0 crypt field {crypt}"
        )))
    }
}

fn crypt_parameters(crypt: u16) -> Result<Option<(usize, usize)>, PbdError> {
    let value = match crypt {
        0 => None,
        1 => Some((8, 0x10)),
        2 => Some((12, 8)),
        3 => Some((20, 4)),
        4 => Some((8, 1)),
        5 => Some((12, 1)),
        6 => Some((20, 1)),
        _ => {
            return Err(PbdError::new(format!(
                "unsupported TJS/4s0 crypt field {crypt}"
            )))
        }
    };
    Ok(value)
}

fn derive_4s0_key(seed: u32, iv: &[u8]) -> Result<[u8; 32], PbdError> {
    let seed_bytes = seed.to_le_bytes();
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(&seed_bytes)
        .map_err(|_| PbdError::new("failed to initialize BLAKE2s PBD key derivation"))?;
    Mac::update(&mut mac, iv);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

fn crypt_4s0_in_place(data: &mut [u8], seed: u32, crypt: u16, iv: &[u8]) -> Result<(), PbdError> {
    let Some((rounds, expand_blocks)) = crypt_parameters(crypt)? else {
        return Ok(());
    };
    let key = derive_4s0_key(seed, iv)?;
    let nonce_lo = xxh32(iv, seed);
    let nonce_hi = seed;
    let mut fallback = nonce_hi ^ nonce_lo;
    if fallback == 0 {
        fallback = seed;
    }
    if fallback == 0 {
        fallback = 0xffff_ffff;
    }

    let mut offset = 0usize;
    let mut counter = 0u64;
    while offset < data.len() {
        let base = chacha_block(&key, counter, nonce_lo, nonce_hi, rounds);
        counter = counter.wrapping_add(1);
        let stream = expand_stream_block(&base, expand_blocks, fallback);
        let take = stream.len().min(data.len() - offset);
        for (dst, key_byte) in data[offset..offset + take].iter_mut().zip(&stream[..take]) {
            *dst ^= *key_byte;
        }
        offset += take;
    }
    Ok(())
}

fn chacha_block(
    key: &[u8; 32],
    counter: u64,
    nonce_lo: u32,
    nonce_hi: u32,
    rounds: usize,
) -> [u8; 64] {
    debug_assert!(matches!(rounds, 8 | 12 | 20));
    let constants = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    for i in 0..4 {
        state[i] = u32::from_le_bytes(constants[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = nonce_lo;
    state[15] = nonce_hi;

    let original = state;
    for _ in 0..(rounds / 2) {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(original[i]);
    }
    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

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

fn xorshift32(mut x: u32, fallback: u32) -> u32 {
    x ^= x.wrapping_shl(13);
    x ^= x >> 17;
    x ^= x.wrapping_shl(5);
    if x == 0 {
        fallback
    } else {
        x
    }
}

fn expand_stream_block(base: &[u8; 64], blocks: usize, fallback: u32) -> Vec<u8> {
    if blocks <= 1 {
        return base.to_vec();
    }
    let mut words = Vec::with_capacity(blocks * 16);
    for chunk in base.chunks_exact(4) {
        words.push(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    // PackinOne expands from a moving source index over the already-created
    // word stream.  It is not a single xorshift chain from the final word.
    let mut src_i = 0usize;
    let extra_groups = blocks * 4 - 4;
    for _ in 0..extra_groups {
        for _ in 0..4 {
            let source = words[src_i];
            src_i += 1;
            words.push(xorshift32(source, fallback));
        }
    }
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn decompress_4s0_frames(bytes: &[u8]) -> Result<(Vec<u8>, bool), PbdError> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < bytes.len() {
        if bytes.len() - pos < 2 {
            return Err(PbdError::new(
                "TJS/4s0 LZ4 frame has truncated u16 block size",
            ));
        }
        let size = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if size == 0 {
            if bytes[pos..].iter().any(|&b| b != 0) {
                return Err(PbdError::new(
                    "TJS/4s0 has non-zero data after LZ4 terminator",
                ));
            }
            return Ok((out, true));
        }
        let end = pos
            .checked_add(size)
            .ok_or_else(|| PbdError::new("TJS/4s0 LZ4 block size overflow"))?;
        if end > bytes.len() {
            return Err(PbdError::new("TJS/4s0 LZ4 block is truncated"));
        }
        let dict_start = out.len().saturating_sub(LZ4_DICT_SIZE);
        let dict = &out[dict_start..];
        // The common page size is 4096 bytes, but known 4s0 readers allow a
        // larger destination when a producer emits an unusual final/block
        // page. lz4_flex requires only an upper bound here, so 64 KiB covers
        // the exact dictionary window without guessing the decoded size.
        let block = match decompress_with_dict(&bytes[pos..end], LZ4_DICT_SIZE, dict) {
            Ok(block) => block,
            Err(first) if !dict.is_empty() => {
                decompress_with_dict(&bytes[pos..end], LZ4_DICT_SIZE, &[])
                    .map_err(|second| PbdError::new(format!(
                        "TJS/4s0 LZ4 decode failed with dictionary ({first}) and without dictionary ({second})"
                    )))?
            }
            Err(err) => return Err(PbdError::new(format!("TJS/4s0 LZ4 decode failed: {err}"))),
        };
        if block.len() > LZ4_DICT_SIZE {
            return Err(PbdError::new("TJS/4s0 LZ4 block expands past 64 KiB"));
        }
        if block.is_empty() {
            return Err(PbdError::new("TJS/4s0 LZ4 block decoded to zero bytes"));
        }
        out.extend_from_slice(&block);
        pos = end;
    }
    Ok((out, false))
}

fn compress_4s0_frames(bytes: &[u8], terminated: bool) -> Result<Vec<u8>, PbdError> {
    let mut out = Vec::new();
    let mut history = Vec::<u8>::new();
    for chunk in bytes.chunks(LZ4_BLOCK_SIZE) {
        let dict_start = history.len().saturating_sub(LZ4_DICT_SIZE);
        let dict = &history[dict_start..];
        let encoded = if dict.is_empty() {
            compress(chunk)
        } else {
            compress_with_dict(chunk, dict)
        };
        if encoded.len() > u16::MAX as usize {
            return Err(PbdError::new(
                "TJS/4s0 compressed LZ4 block exceeds u16 length",
            ));
        }
        out.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        out.extend_from_slice(&encoded);
        history.extend_from_slice(chunk);
        if history.len() > LZ4_DICT_SIZE * 2 {
            let keep_from = history.len() - LZ4_DICT_SIZE;
            history.drain(..keep_from);
        }
    }
    if terminated {
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    Ok(out)
}

fn parse_hex_u32(text: &str, field: &str) -> Result<u32, PbdError> {
    let text = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))
        .unwrap_or(text.trim());
    u32::from_str_radix(text, 16)
        .map_err(|_| PbdError::new(format!("invalid {field}: expected hexadecimal u32")))
}

fn parse_hex_u64(text: &str, field: &str) -> Result<u64, PbdError> {
    let text = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))
        .unwrap_or(text.trim());
    u64::from_str_radix(text, 16)
        .map_err(|_| PbdError::new(format!("invalid {field}: expected hexadecimal u64")))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, PbdError> {
    let text = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))
        .unwrap_or(text.trim());
    if text.len() % 2 != 0 {
        return Err(PbdError::new("hex string has odd length"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for i in (0..text.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| PbdError::new("invalid hexadecimal byte string"))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_root() -> PbdValue {
        PbdValue::Dictionary {
            entries: vec![
                PbdDictEntry {
                    key: "name".into(),
                    value: PbdValue::String {
                        value: "日本語".into(),
                    },
                },
                PbdDictEntry {
                    key: "count".into(),
                    value: PbdValue::Integer { value: -42 },
                },
                PbdDictEntry {
                    key: "values".into(),
                    value: PbdValue::Array {
                        items: vec![
                            PbdValue::Void,
                            PbdValue::Double {
                                bits_hex: format!("0x{:016x}", 1.5f64.to_bits()),
                                display: "1.5".into(),
                            },
                        ],
                    },
                },
            ],
        }
    }

    #[test]
    fn ns0_roundtrip() {
        let doc = PbdDocument {
            header: PbdHeader {
                variant: PbdVariant::Ns0,
                seed: 0x1435_3cc6,
                crypt: 0,
                iv: vec![],
                trailer: None,
                lz4_terminated: false,
            },
            root: sample_root(),
        };
        let encoded = encode_pbd(&doc).unwrap();
        assert!(encoded.starts_with(PBD_NS0_MAGIC));
        let decoded = decode_pbd(&encoded).unwrap();
        assert_eq!(decoded.root, doc.root);
        assert_eq!(decoded.header.seed, doc.header.seed);
    }

    #[test]
    fn four_s0_roundtrip_crypt1() {
        let doc = PbdDocument {
            header: PbdHeader {
                variant: PbdVariant::FourS0,
                seed: 0x1435_3cc6,
                crypt: 1,
                iv: b"pbd-test-iv".to_vec(),
                trailer: Some(0x1122_3344),
                lz4_terminated: true,
            },
            root: sample_root(),
        };
        let encoded = encode_pbd(&doc).unwrap();
        assert!(encoded.starts_with(PBD_4S0_MAGIC));
        let decoded = decode_pbd(&encoded).unwrap();
        assert_eq!(decoded.root, doc.root);
        assert_eq!(decoded.header.crypt, 1);
        assert_eq!(decoded.header.iv, doc.header.iv);
        assert_eq!(decoded.header.trailer, Some(0x1122_3344));
        assert!(decoded.header.lz4_terminated);
    }

    #[test]
    fn four_s0_known_key_schedule_matches_packinone_vector() {
        let seed = 0x1435_3cc6u32;
        let key = derive_4s0_key(seed, b"").unwrap();
        assert_eq!(
            hex_encode(&key),
            "2fca145d50b8cb030395f0868c49ed85aa0280c6d0b844c09673351e64408aed"
        );
        let nonce_lo = xxh32(b"", seed);
        assert_eq!(nonce_lo, 0x9848_23d3);
        let base = chacha_block(&key, 0, nonce_lo, seed, 8);
        let stream = expand_stream_block(&base, 0x10, seed ^ nonce_lo);
        assert_eq!(
            &stream[..16],
            &hex_decode("2e9d7adaabc57ee65d0d4f2b440895d5").unwrap()[..]
        );
    }

    #[test]
    fn four_s0_keystream_expansion_uses_moving_source_words() {
        let mut base = [0u8; 64];
        for i in 0..16u32 {
            base[(i as usize) * 4..(i as usize + 1) * 4].copy_from_slice(&(i + 1).to_le_bytes());
        }
        let fallback = 0x1357_9bdf;
        let expanded = expand_stream_block(&base, 2, fallback);
        assert_eq!(expanded.len(), 128);
        for i in 0..16usize {
            let got = u32::from_le_bytes(expanded[(16 + i) * 4..(17 + i) * 4].try_into().unwrap());
            assert_eq!(got, xorshift32((i as u32) + 1, fallback));
        }
    }

    #[test]
    fn json_roundtrip_preserves_variant_metadata() {
        let source = PbdDocument {
            header: PbdHeader {
                variant: PbdVariant::FourS0,
                seed: 0x0102_0304,
                crypt: 4,
                iv: vec![1, 2, 3, 4],
                trailer: Some(0xaabb_ccdd),
                lz4_terminated: false,
            },
            root: sample_root(),
        };
        let json = source.to_json_document();
        let encoded = encode_pbd_json(&json).unwrap();
        let decoded = decode_pbd(&encoded).unwrap();
        assert_eq!(decoded.root, source.root);
        assert_eq!(decoded.header.variant, PbdVariant::FourS0);
        assert_eq!(decoded.header.seed, 0x0102_0304);
        assert_eq!(decoded.header.crypt, 4);
        assert_eq!(decoded.header.iv, vec![1, 2, 3, 4]);
        assert_eq!(decoded.header.trailer, Some(0xaabb_ccdd));
    }

    #[test]
    fn modified_json_field_is_present_after_reparse() {
        let source = PbdDocument {
            header: PbdHeader {
                variant: PbdVariant::Ns0,
                seed: 0x7654_3210,
                crypt: 0,
                iv: Vec::new(),
                trailer: None,
                lz4_terminated: false,
            },
            root: sample_root(),
        };
        let mut json = source.to_json_document();
        let PbdValue::Dictionary { entries } = &mut json.root else {
            panic!("sample root must be a dictionary");
        };
        entries[1].value = PbdValue::Integer { value: 2026 };
        let encoded = encode_pbd_json(&json).unwrap();
        let decoded = decode_pbd(&encoded).unwrap();
        let PbdValue::Dictionary { entries } = decoded.root else {
            panic!("rebuilt root must be a dictionary");
        };
        assert_eq!(entries[1].value, PbdValue::Integer { value: 2026 });
        assert_eq!(decoded.header.seed, source.header.seed);
    }
}
