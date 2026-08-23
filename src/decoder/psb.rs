//! PSB / Emote decoding and run-wide Emote key reuse.
//!
//! `eluna_rs` is the canonical PSB parser/decryptor.  This wrapper adds two
//! extraction-oriented policies:
//! - a process-wide cache for Emote private-key DWORDs, serialized brute-force
//!   discovery, and cached-key reuse for later PSBs;
//! - KrkrExtract-compatible structural PSB bitmap discovery (`width` +
//!   `height` + `pixel`, optional `pal` / `compress = RL`) plus the dedicated
//!   Emote `source/*/texture` layout;
//! - generic traversal of PSB resource/extra-resource blobs as a fallback,
//!   preserving unknown resources byte-for-byte when requested;
//! - an explicit, round-trip-oriented JSON representation of the generic PSB
//!   root for PSB/SCN/MTN/PIMG-family assets.  The JSON representation keeps
//!   PSB value kinds, object-entry order, resource references, and compiler
//!   tags instead of flattening them into lossy ordinary JSON.

use crate::decoder::tlg::{decode_tlg, TLG0_MAGIC, TLG5_MAGIC, TLG6_MAGIC};
use eluna::emote::{EmoteModelSchema, EmoteTextureSource};
use eluna::psb::{
    bruteforce_emote_key, PsbBruteforceOptions, PsbCompilerTag, PsbDecryptionKey, PsbError,
    PsbFile, PsbHeader, PsbNormalizeOptions, PsbValue,
};
use emote_psb::psb::read::PsbFile as EmotePsbReader;
use image::{ColorType, ImageFormat, RgbaImage};
use std::error::Error as StdError;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const PSB_SIGNATURE: &[u8; 4] = b"PSB\0";
const MDF_SIGNATURE: &[u8; 3] = b"mdf";
const LZ4_FRAME_SIGNATURE: [u8; 4] = 0x184D_2204u32.to_le_bytes();

static EMOTE_KEYS: OnceLock<Mutex<Vec<u32>>> = OnceLock::new();
static EMOTE_BRUTE_LOCK: Mutex<()> = Mutex::new(());

fn global_keys() -> &'static Mutex<Vec<u32>> {
    EMOTE_KEYS.get_or_init(|| Mutex::new(Vec::new()))
}

fn lock_keys() -> std::sync::MutexGuard<'static, Vec<u32>> {
    global_keys()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbKeySource {
    None,
    Cached(u32),
    Bruteforced { key: u32, tested_keys: u64 },
}

impl PsbKeySource {
    pub fn key(self) -> Option<u32> {
        match self {
            Self::None => None,
            Self::Cached(key) | Self::Bruteforced { key, .. } => Some(key),
        }
    }
}

#[derive(Debug)]
pub struct DecodedPsb {
    /// Plain PSB bytes after MDF/LZ4 unwrapping and, when necessary, PSB
    /// header/body decryption.  Resource offsets in `psb` refer to this
    /// buffer, not necessarily to the original wrapper bytes.
    pub normalized: Vec<u8>,
    pub psb: PsbFile,
    /// PSB v4 extra-resource payloads. `eluna_rs 0.1.0` exposes an
    /// `extra_resources` field but does not currently populate it, so keep
    /// the v4 table here after parsing it with `emote-psb`.
    pub extra_resource_blobs: Vec<Vec<u8>>,
    pub key_source: PsbKeySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmoteTextureExportFormat {
    Png,
    Jpeg,
    Bmp,
}

impl EmoteTextureExportFormat {
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Bmp => "bmp",
        }
    }

    fn image_format(self) -> Option<ImageFormat> {
        match self {
            Self::Png => Some(ImageFormat::Png),
            Self::Jpeg => None,
            Self::Bmp => Some(ImageFormat::Bmp),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecodedEmoteTexture {
    pub name: String,
    pub resource_index: u32,
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EmoteTextureExportRecord {
    pub path: PathBuf,
    pub name: String,
    pub resource_index: u32,
    pub width: u32,
    pub height: u32,
    pub source_format: Option<String>,
    pub compress: Option<String>,
    pub bit_count: Option<u32>,
    pub spec: Option<String>,
    pub exported_format: EmoteTextureExportFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PsbResourceTable {
    Resource,
    ExtraResource,
}

impl PsbResourceTable {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::ExtraResource => "extra-resource",
        }
    }

    const fn file_prefix(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::ExtraResource => "extra",
        }
    }
}

/// One user-visible file derived from a PSB resource blob. Image records have
/// `exported_format`, `width`, and `height`; unknown blobs emitted by
/// `--psb all` have `raw_blob=true` and are written byte-for-byte as `.bin`.
#[derive(Debug, Clone)]
pub struct PsbResourceExportRecord {
    pub path: PathBuf,
    pub table: PsbResourceTable,
    pub resource_index: u32,
    pub name: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub source_format: Option<String>,
    pub compress: Option<String>,
    pub bit_count: Option<u32>,
    pub spec: Option<String>,
    /// How the PSB object tree identified this image.  Structural records use
    /// `generic-bitmap` or `emote-texture`; fallback decoders use `embedded-image`.
    pub semantic: Option<String>,
    /// Slash-separated location of the object that supplied the structural
    /// image metadata.  This is retained for future PSB rewriting.
    pub object_path: Option<String>,
    /// Full source surface dimensions.  Emote textures can store a larger
    /// stride surface than the truncated user-visible image.
    pub full_width: Option<u32>,
    pub full_height: Option<u32>,
    /// Generic indexed PSB bitmaps keep their palette in a separate resource.
    pub palette_table: Option<PsbResourceTable>,
    pub palette_index: Option<u32>,
    /// If structural metadata identified this blob as an image but the pixel
    /// decoder rejected it, retain the reason on the raw fallback record.
    pub decode_error: Option<String>,
    pub exported_format: Option<EmoteTextureExportFormat>,
    pub raw_blob: bool,
    pub source_blob_size: usize,
    pub source_blob_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PsbResourceRef {
    table: PsbResourceTable,
    index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsbBitmapSemantic {
    GenericBitmap,
    EmoteTexture,
}

impl PsbBitmapSemantic {
    const fn label(self) -> &'static str {
        match self {
            Self::GenericBitmap => "generic-bitmap",
            Self::EmoteTexture => "emote-texture",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::GenericBitmap => 1,
            Self::EmoteTexture => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct PsbBitmapCandidate {
    semantic: PsbBitmapSemantic,
    object_path: String,
    name: String,
    pixel: PsbResourceRef,
    palette: Option<PsbResourceRef>,
    full_width: u32,
    full_height: u32,
    width: u32,
    height: u32,
    format: Option<String>,
    compress: Option<String>,
    bit_count: Option<u32>,
}

#[derive(Debug)]
pub enum PsbDecoderError {
    Psb(PsbError),
    Texture(String),
    Image(image::ImageError),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl fmt::Display for PsbDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Psb(err) => write!(f, "PSB error: {err}"),
            Self::Texture(err) => write!(f, "Emote texture error: {err}"),
            Self::Image(err) => write!(f, "image error: {err}"),
            Self::Json(err) => write!(f, "JSON error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl StdError for PsbDecoderError {}

impl From<PsbError> for PsbDecoderError {
    fn from(value: PsbError) -> Self {
        Self::Psb(value)
    }
}
impl From<image::ImageError> for PsbDecoderError {
    fn from(value: image::ImageError) -> Self {
        Self::Image(value)
    }
}
impl From<serde_json::Error> for PsbDecoderError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<std::io::Error> for PsbDecoderError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Cheap, conservative PSB-family gate used before invoking Eluna.
///
/// Encrypted PSBs retain the `PSB\0` outer header.  Eluna also knows how to
/// unwrap MDF/zlib and LZ4-frame containers, so those two signatures are
/// accepted here as candidates.  Merely having a `.psb` filename is not
/// enough to trigger a 32-bit key search.
pub fn is_psb_family_bytes(data: &[u8]) -> bool {
    data.starts_with(PSB_SIGNATURE)
        || (data.len() >= 8 && data.starts_with(MDF_SIGNATURE))
        || data.starts_with(&LZ4_FRAME_SIGNATURE)
}

pub fn cached_emote_keys() -> Vec<u32> {
    lock_keys().clone()
}

fn remember_key(key: u32) {
    let mut keys = lock_keys();
    if !keys.contains(&key) {
        keys.push(key);
    }
}

fn should_bruteforce(data: &[u8], plain_error: &PsbError) -> bool {
    if matches!(plain_error, PsbError::EncryptedPsbRequiresKey) {
        return true;
    }
    // Avoid turning an ordinary malformed PSB into a 2^32 search.  Raw PSBs
    // expose enough header state to distinguish explicit encryption.  Legacy
    // v2 can omit the body flag, in which case Eluna treats a non-object root
    // code as the implicit-encryption signal.
    if data.starts_with(PSB_SIGNATURE) {
        if let Ok(header) = PsbHeader::read(data) {
            if (header.flags & 0x0003) != 0 {
                return true;
            }
            if header.version <= 2 {
                return data.get(header.root_offset as usize).copied() != Some(0x21);
            }
        }
    }
    false
}

fn extract_v4_extra_resource_blobs(
    normalized: &[u8],
    version: u16,
) -> Result<Vec<Vec<u8>>, PsbDecoderError> {
    if version < 4 {
        return Ok(Vec::new());
    }

    let stream = BufReader::new(Cursor::new(normalized));
    let mut psb = EmotePsbReader::open(stream).map_err(|err| {
        PsbDecoderError::Texture(format!("cannot parse PSB v4 extra-resource table: {err}"))
    })?;
    let mut out = Vec::with_capacity(psb.extra_resources());
    for index in 0..psb.extra_resources() {
        let mut resource = psb
            .open_extra_resource(index)
            .map_err(PsbDecoderError::Io)?
            .ok_or_else(|| {
                PsbDecoderError::Texture(format!("missing PSB v4 extra resource {index}"))
            })?;
        let mut bytes = Vec::new();
        resource
            .read_to_end(&mut bytes)
            .map_err(PsbDecoderError::Io)?;
        out.push(bytes);
    }
    Ok(out)
}

fn normalize_with_key(data: &[u8], key: u32) -> Result<DecodedPsb, PsbDecoderError> {
    let options = PsbNormalizeOptions {
        decrypt_key: Some(PsbDecryptionKey::emote_key(key)),
        decode_mdf: true,
        decode_lz4: true,
    };
    let (normalized, psb) = PsbFile::parse_normalized(data, &options)?;
    let extra_resource_blobs = extract_v4_extra_resource_blobs(&normalized, psb.version)?;
    Ok(DecodedPsb {
        normalized,
        psb,
        extra_resource_blobs,
        key_source: PsbKeySource::Cached(key),
    })
}

/// Parse a PSB-family asset with an explicitly supplied Emote key.
///
/// Unlike [`decode_psb_with_global_key`], this never performs brute force. It
/// is intended for deterministic rebuilds driven by `xp3-meta.yaml`, where the
/// original key has already been recorded.
pub fn decode_psb_with_key(
    data: &[u8],
    key: Option<u32>,
) -> Result<Option<DecodedPsb>, PsbDecoderError> {
    if !is_psb_family_bytes(data) {
        return Ok(None);
    }

    let options = PsbNormalizeOptions {
        decrypt_key: key.map(PsbDecryptionKey::emote_key),
        decode_mdf: true,
        decode_lz4: true,
    };
    let (normalized, psb) = PsbFile::parse_normalized(data, &options)?;
    let extra_resource_blobs = extract_v4_extra_resource_blobs(&normalized, psb.version)?;
    Ok(Some(DecodedPsb {
        normalized,
        psb,
        extra_resource_blobs,
        key_source: key.map(PsbKeySource::Cached).unwrap_or(PsbKeySource::None),
    }))
}

/// Parse a PSB using Eluna, reusing any previously recovered Emote key and
/// brute-forcing the single varying DWORD only when necessary.
///
/// The brute-force section is serialized process-wide.  This prevents Rayon
/// workers from launching several full 32-bit key searches at once.  Once a
/// key is found it is cached globally and tried first for every later PSB.
pub fn decode_psb_with_global_key(data: &[u8]) -> Result<Option<DecodedPsb>, PsbDecoderError> {
    if !is_psb_family_bytes(data) {
        return Ok(None);
    }

    let plain_options = PsbNormalizeOptions::default();
    let plain_error = match PsbFile::parse_normalized(data, &plain_options) {
        Ok((normalized, psb)) => {
            let extra_resource_blobs = extract_v4_extra_resource_blobs(&normalized, psb.version)?;
            return Ok(Some(DecodedPsb {
                normalized,
                psb,
                extra_resource_blobs,
                key_source: PsbKeySource::None,
            }));
        }
        Err(err) => err,
    };

    // A game normally has one Emote key, but keeping a small ordered cache
    // makes the decoder robust when several independent PSB families are
    // encountered in the same process.
    for key in cached_emote_keys() {
        if let Ok(decoded) = normalize_with_key(data, key) {
            return Ok(Some(decoded));
        }
    }

    let _brute_guard = EMOTE_BRUTE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Another file may have recovered the key while this caller was waiting.
    for key in cached_emote_keys() {
        if let Ok(decoded) = normalize_with_key(data, key) {
            return Ok(Some(decoded));
        }
    }

    if !should_bruteforce(data, &plain_error) {
        return Err(PsbDecoderError::Psb(plain_error));
    }

    // For a PSB-family blob that did not parse plainly and has an encryption
    // signal, use Eluna's own complete key search.  It unwraps MDF/LZ4 itself,
    // applies the fast v3 Adler/header reject, and fully parses survivors.
    let result = bruteforce_emote_key(data, PsbBruteforceOptions::default());
    let found = match result {
        Ok(Some(found)) => found,
        Ok(None) => return Err(PsbDecoderError::Psb(plain_error)),
        Err(err) => return Err(PsbDecoderError::Psb(err)),
    };
    remember_key(found.key);

    let mut decoded = normalize_with_key(data, found.key)?;
    decoded.key_source = PsbKeySource::Bruteforced {
        key: found.key,
        tested_keys: found.tested_keys,
    };
    Ok(Some(decoded))
}

/// Stable JSON schema name used for generic PSB root exports.
///
/// This is intentionally *not* a naïve `serde_json::Value` conversion of the
/// PSB object.  PSB distinguishes Int/Float/Double and Resource/ExtraResource,
/// and objects are represented by Eluna as ordered `Vec<(String, PsbValue)>`.
/// A plain JSON object would erase some of those distinctions and make a
/// future packer ambiguous.
pub const PSB_ROOT_JSON_SCHEMA: &str = "krkr-xp3-brute/psb-root-v1";

/// Convert a parsed PSB value into a JSON value that preserves enough type
/// information for a future PSB writer to reconstruct the semantic tree.
///
/// Objects are encoded as ordered `entries`, rather than JSON maps, so key
/// order and duplicate keys (if a title uses them) are not discarded.
pub fn psb_value_to_roundtrip_json(value: &PsbValue) -> serde_json::Value {
    use serde_json::{json, Value};

    match value {
        PsbValue::Null => json!({"$type": "null"}),
        PsbValue::Bool(value) => json!({"$type": "bool", "value": value}),
        PsbValue::Int(value) => json!({"$type": "int", "value": value}),
        // Preserve IEEE bits rather than forcing all PSB floating-point values
        // through JSON's single Number representation.  This retains f32/f64,
        // -0, NaN payloads and infinities for a later packer.
        PsbValue::Float(value) => json!({
            "$type": "float",
            "bits": format!("0x{:08X}", value.to_bits()),
            "display": value.to_string(),
        }),
        PsbValue::Double(value) => json!({
            "$type": "double",
            "bits": format!("0x{:016X}", value.to_bits()),
            "display": value.to_string(),
        }),
        PsbValue::String(value) => json!({"$type": "string", "value": value}),
        PsbValue::Resource(index) => json!({"$type": "resource", "index": index}),
        PsbValue::ExtraResource(index) => json!({"$type": "extra_resource", "index": index}),
        PsbValue::List(items) => Value::Object({
            let mut object = serde_json::Map::new();
            object.insert("$type".to_string(), Value::String("list".to_string()));
            object.insert(
                "items".to_string(),
                Value::Array(items.iter().map(psb_value_to_roundtrip_json).collect()),
            );
            object
        }),
        PsbValue::Object(entries) => Value::Object({
            let mut object = serde_json::Map::new();
            object.insert("$type".to_string(), Value::String("object".to_string()));
            object.insert(
                "entries".to_string(),
                Value::Array(
                    entries
                        .iter()
                        .map(|(key, value)| {
                            json!({
                                "key": key,
                                "value": psb_value_to_roundtrip_json(value),
                            })
                        })
                        .collect(),
                ),
            );
            object
        }),
        PsbValue::Compiler(tag) => json!({
            "$type": "compiler",
            "tag": compiler_tag_name(tag),
        }),
    }
}

fn compiler_tag_name(tag: &PsbCompilerTag) -> &'static str {
    match tag {
        PsbCompilerTag::Integer => "integer",
        PsbCompilerTag::String => "string",
        PsbCompilerTag::Resource => "resource",
        PsbCompilerTag::Decimal => "decimal",
        PsbCompilerTag::Array => "array",
        PsbCompilerTag::Bool => "bool",
        PsbCompilerTag::BinaryTree => "binary_tree",
    }
}

fn resource_ranges_json(ranges: &[eluna::psb::PsbResourceRange]) -> serde_json::Value {
    use serde_json::{json, Value};
    Value::Array(
        ranges
            .iter()
            .enumerate()
            .map(|(index, range)| {
                json!({
                    "index": index,
                    "offset": range.offset,
                    "length": range.length,
                })
            })
            .collect(),
    )
}

fn extra_resource_blobs_json(blobs: &[Vec<u8>]) -> serde_json::Value {
    use serde_json::{json, Value};
    Value::Array(
        blobs
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                json!({
                    "index": index,
                    "length": bytes.len(),
                    "sha256": crate::xp3_meta::sha256_hex(bytes),
                })
            })
            .collect(),
    )
}

fn key_source_json(source: PsbKeySource) -> serde_json::Value {
    use serde_json::json;
    match source {
        PsbKeySource::None => json!({
            "kind": "none",
            "emote_key": serde_json::Value::Null,
        }),
        PsbKeySource::Cached(key) => json!({
            "kind": "cached",
            "emote_key": format!("0x{key:08X}"),
        }),
        PsbKeySource::Bruteforced { key, tested_keys } => json!({
            "kind": "bruteforced",
            "emote_key": format!("0x{key:08X}"),
            "tested_keys": tested_keys,
        }),
    }
}

/// Build the generic PSB manifest used by `--psb json`.
///
/// The manifest carries the original parsed name/string tables, resource range
/// tables, header metadata, and a typed root tree.  Raw resource bytes remain
/// in the original PSB/SCN/MTN/PIMG file for now; a future packer can pair this
/// manifest with that source file while edited roots are being supported.
pub fn psb_roundtrip_json(decoded: &DecodedPsb, source_path: Option<&Path>) -> serde_json::Value {
    use serde_json::json;

    let header = decoded.psb.header;
    let source_name = source_path
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    let source_extension = source_path
        .and_then(Path::extension)
        .and_then(|extension| extension.to_str());

    json!({
        "$schema": PSB_ROOT_JSON_SCHEMA,
        "source": {
            "file_name": source_name,
            "extension": source_extension,
        },
        "psb": {
            "version": decoded.psb.version,
            "encrypted_input": decoded.psb.encrypted,
            "checksum": decoded.psb.checksum,
            "decryption": key_source_json(decoded.key_source),
            "header": {
                "signature": header.signature,
                "version": header.version,
                "flags": header.flags,
                "header_offset": header.header_offset,
                "name_offset": header.name_offset,
                "string_offset": header.string_offset,
                "string_data_offset": header.string_data_offset,
                "resource_offset": header.resource_offset,
                "resource_length_offset": header.resource_length_offset,
                "resource_data_offset": header.resource_data_offset,
                "root_offset": header.root_offset,
                "extra": header.extra,
            },
            "names": &decoded.psb.names,
            "strings": &decoded.psb.strings,
            "resources": resource_ranges_json(&decoded.psb.resources),
            "extra_resources": extra_resource_blobs_json(&decoded.extra_resource_blobs),
            "root": psb_value_to_roundtrip_json(&decoded.psb.root),
        },
    })
}

/// Sidecar path used by a generic PSB-family JSON export.
///
/// `foo.psb` -> `foo.psb.json`, `scene.scn` -> `scene.scn.json`, etc.  Keeping
/// the original suffix makes the family identity explicit and avoids clashes
/// between same-stem PSB/SCN/MTN/PIMG files.
pub fn psb_json_output_path(psb_output_path: &Path) -> PathBuf {
    let file_name = psb_output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("asset.psb");
    psb_output_path.with_file_name(format!("{file_name}.json"))
}

/// Export the generic PSB root/metadata manifest as pretty JSON.
pub fn export_psb_root_json(
    decoded: &DecodedPsb,
    psb_output_path: &Path,
) -> Result<PathBuf, PsbDecoderError> {
    let output = psb_json_output_path(psb_output_path);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let document = psb_roundtrip_json(decoded, Some(psb_output_path));
    let bytes = serde_json::to_vec_pretty(&document)?;
    fs::write(&output, bytes)?;
    Ok(output)
}

fn object_field<'a>(entries: &'a [(String, PsbValue)], key: &str) -> Option<&'a PsbValue> {
    // KrkrExtract materialized a dictionary into std::map before examining
    // bitmap fields, so a duplicate name effectively kept the last value.
    entries
        .iter()
        .rev()
        .find_map(|(name, value)| (name == key).then_some(value))
}

fn positive_u32(value: &PsbValue) -> Option<u32> {
    match value {
        PsbValue::Int(value) => u32::try_from(*value).ok().filter(|value| *value != 0),
        // The historical PSB node accessor converted floating numeric values
        // through AsInt(), so retain that permissive numeric behavior while
        // rejecting non-finite/out-of-range dimensions.
        PsbValue::Float(value)
            if value.is_finite() && *value >= 1.0 && *value <= u32::MAX as f32 =>
        {
            Some(*value as u32)
        }
        PsbValue::Double(value)
            if value.is_finite() && *value >= 1.0 && *value <= u32::MAX as f64 =>
        {
            Some(*value as u32)
        }
        _ => None,
    }
}

fn optional_u32_field(entries: &[(String, PsbValue)], key: &str) -> Option<u32> {
    object_field(entries, key).and_then(positive_u32)
}

fn optional_string_field(entries: &[(String, PsbValue)], key: &str) -> Option<String> {
    match object_field(entries, key) {
        Some(PsbValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn psb_resource_ref(value: &PsbValue) -> Option<PsbResourceRef> {
    match value {
        PsbValue::Resource(index) => Some(PsbResourceRef {
            table: PsbResourceTable::Resource,
            index: *index,
        }),
        PsbValue::ExtraResource(index) => Some(PsbResourceRef {
            table: PsbResourceTable::ExtraResource,
            index: *index,
        }),
        _ => None,
    }
}

fn psb_resource_bytes<'a>(decoded: &'a DecodedPsb, resource: PsbResourceRef) -> Option<&'a [u8]> {
    match resource.table {
        PsbResourceTable::Resource => decoded
            .psb
            .resource_bytes(&decoded.normalized, resource.index as usize),
        PsbResourceTable::ExtraResource => decoded
            .extra_resource_blobs
            .get(resource.index as usize)
            .map(Vec::as_slice),
    }
}

fn json_pointer_component(component: &str) -> String {
    component.replace('~', "~0").replace('/', "~1")
}

fn object_path(path: &[String]) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path.join("/"))
    }
}

fn generic_bitmap_candidate(
    entries: &[(String, PsbValue)],
    path: &[String],
    display_name: Option<&str>,
) -> Option<PsbBitmapCandidate> {
    // This is the defining KrkrExtract heuristic: width + height + pixel in
    // one dictionary.  Do not infer image-ness from the resource blob itself.
    let full_width = positive_u32(object_field(entries, "width")?)?;
    let full_height = positive_u32(object_field(entries, "height")?)?;
    let pixel = psb_resource_ref(object_field(entries, "pixel")?)?;
    let palette = object_field(entries, "pal").and_then(psb_resource_ref);
    // KrkrExtract's generic bitmap path chooses the pixel size solely from
    // whether a palette exists: indexed8 with `pal`, otherwise four bytes per
    // pixel.  Preserve that exact semantic instead of trusting unrelated
    // bit-count fields that may coexist in a larger object.
    let bit_count = Some(if palette.is_some() { 8 } else { 32 });

    Some(PsbBitmapCandidate {
        semantic: PsbBitmapSemantic::GenericBitmap,
        object_path: object_path(path),
        name: display_name
            .filter(|name| !name.is_empty())
            .unwrap_or("bitmap")
            .to_string(),
        pixel,
        palette,
        full_width,
        full_height,
        // dumpBitmapInternal(), the image path used by KrkrExtract, used the
        // full generic bitmap dimensions.  Truncated dimensions belong to the
        // dedicated Emote texture path below.
        width: full_width,
        height: full_height,
        format: optional_string_field(entries, "type")
            .or_else(|| optional_string_field(entries, "format")),
        compress: optional_string_field(entries, "compress"),
        bit_count,
    })
}

fn collect_generic_bitmap_candidates(
    value: &PsbValue,
    path: &mut Vec<String>,
    display_name: Option<&str>,
    out: &mut Vec<PsbBitmapCandidate>,
) {
    match value {
        PsbValue::Object(entries) => {
            if let Some(candidate) = generic_bitmap_candidate(entries, path, display_name) {
                out.push(candidate);
            }
            for (name, child) in entries {
                path.push(json_pointer_component(name));
                collect_generic_bitmap_candidates(child, path, Some(name), out);
                path.pop();
            }
        }
        PsbValue::List(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(index.to_string());
                collect_generic_bitmap_candidates(child, path, display_name, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn collect_emote_texture_candidates(root: &PsbValue, out: &mut Vec<PsbBitmapCandidate>) {
    let PsbValue::Object(root_entries) = root else {
        return;
    };
    let Some(PsbValue::Object(source_entries)) = object_field(root_entries, "source") else {
        return;
    };

    // Mirror KrkrExtract's dedicated root["source"][name]["texture"] walk.
    // Unlike the old implementation, malformed/non-texture source entries are
    // skipped individually instead of aborting extraction of every texture.
    for (source_name, source_value) in source_entries {
        let PsbValue::Object(source_object) = source_value else {
            continue;
        };
        let Some(PsbValue::Object(texture)) = object_field(source_object, "texture") else {
            continue;
        };
        let Some(full_width) = object_field(texture, "width").and_then(positive_u32) else {
            continue;
        };
        let Some(full_height) = object_field(texture, "height").and_then(positive_u32) else {
            continue;
        };
        let Some(pixel) = object_field(texture, "pixel").and_then(psb_resource_ref) else {
            continue;
        };
        let width = optional_u32_field(texture, "truncated_width").unwrap_or(full_width);
        let height = optional_u32_field(texture, "truncated_height").unwrap_or(full_height);
        if width > full_width || height > full_height {
            continue;
        }

        out.push(PsbBitmapCandidate {
            semantic: PsbBitmapSemantic::EmoteTexture,
            object_path: format!("/source/{}/texture", json_pointer_component(source_name)),
            name: source_name.clone(),
            pixel,
            palette: None,
            full_width,
            full_height,
            width,
            height,
            format: optional_string_field(texture, "type")
                .or_else(|| optional_string_field(texture, "format")),
            compress: optional_string_field(texture, "compress"),
            bit_count: optional_u32_field(texture, "bitCount")
                .or_else(|| optional_u32_field(texture, "bit_count")),
        });
    }
}

fn collect_psb_bitmap_candidates(root: &PsbValue) -> Vec<PsbBitmapCandidate> {
    let mut out = Vec::new();
    collect_emote_texture_candidates(root, &mut out);
    let mut path = Vec::new();
    collect_generic_bitmap_candidates(root, &mut path, None, &mut out);
    out.sort_by(|left, right| {
        right
            .semantic
            .priority()
            .cmp(&left.semantic.priority())
            .then_with(|| left.object_path.cmp(&right.object_path))
    });
    out
}

fn checked_surface_len(
    width: u32,
    height: u32,
    bytes_per_pixel: usize,
) -> Result<usize, PsbDecoderError> {
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(bytes_per_pixel))
        .ok_or_else(|| {
            PsbDecoderError::Texture(format!(
                "PSB bitmap dimensions overflow: {width}x{height}x{bytes_per_pixel}"
            ))
        })
}

fn uncompressed_or_rl_payload(
    bytes: &[u8],
    compress: Option<&str>,
    bytes_per_pixel: usize,
    expected_len: usize,
) -> Result<Vec<u8>, PsbDecoderError> {
    if compress.is_some_and(|value| value.eq_ignore_ascii_case("RL")) {
        decompress_rl(bytes, bytes_per_pixel, expected_len)
    } else if bytes.len() >= expected_len {
        Ok(bytes[..expected_len].to_vec())
    } else {
        Err(PsbDecoderError::Texture(format!(
            "PSB bitmap resource is too short: got {}, expected at least {expected_len}",
            bytes.len()
        )))
    }
}

fn decode_indexed8_bitmap(
    pixels: &[u8],
    palette: &[u8],
    full_width: u32,
    full_height: u32,
    width: u32,
    height: u32,
    compress: Option<&str>,
) -> Result<Vec<u8>, PsbDecoderError> {
    if palette.len() < 256 * 4 {
        return Err(PsbDecoderError::Texture(format!(
            "PSB indexed bitmap palette is too short: got {}, expected at least 1024",
            palette.len()
        )));
    }
    if width > full_width || height > full_height {
        return Err(PsbDecoderError::Texture(
            "PSB indexed bitmap crop exceeds full surface".to_string(),
        ));
    }
    let expected_len = checked_surface_len(full_width, full_height, 1)?;
    let payload = uncompressed_or_rl_payload(pixels, compress, 1, expected_len)?;
    let output_len = checked_surface_len(width, height, 4)?;
    let mut rgba = Vec::with_capacity(output_len);
    let full_width = full_width as usize;
    let width = width as usize;
    for y in 0..height as usize {
        let row = y.checked_mul(full_width).ok_or_else(|| {
            PsbDecoderError::Texture("PSB indexed bitmap row overflow".to_string())
        })?;
        for &index in &payload[row..row + width] {
            let palette_offset = index as usize * 4;
            let entry = &palette[palette_offset..palette_offset + 4];
            // KrkrExtract writes the four-byte PSB palette directly as a BMP
            // RGBQUAD.  Its fourth byte is reserved, not alpha.
            rgba.extend_from_slice(&[entry[2], entry[1], entry[0], 0xff]);
        }
    }
    Ok(rgba)
}

fn format_is_rgba4444(format: Option<&str>, bit_count: Option<u32>) -> bool {
    let Some(format) = format else {
        return bit_count == Some(16);
    };
    let normalized: String = format
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    matches!(
        normalized.as_str(),
        "RGBA4444" | "A4R4G4B4" | "D3DFMTA4R4G4B4"
    )
}

fn decode_rgba4444_bitmap(
    bytes: &[u8],
    full_width: u32,
    full_height: u32,
    width: u32,
    height: u32,
    compress: Option<&str>,
) -> Result<Vec<u8>, PsbDecoderError> {
    if width > full_width || height > full_height {
        return Err(PsbDecoderError::Texture(
            "RGBA4444 crop exceeds full surface".to_string(),
        ));
    }
    let expected_len = checked_surface_len(full_width, full_height, 2)?;
    let payload = uncompressed_or_rl_payload(bytes, compress, 2, expected_len)?;
    let output_len = checked_surface_len(width, height, 4)?;
    let mut rgba = Vec::with_capacity(output_len);
    let source_stride = full_width as usize * 2;
    for y in 0..height as usize {
        let row_start = y
            .checked_mul(source_stride)
            .ok_or_else(|| PsbDecoderError::Texture("RGBA4444 row overflow".to_string()))?;
        for x in 0..width as usize {
            let offset = row_start + x * 2;
            let value = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
            let b = ((value & 0x000f) as u8) * 17;
            let g = (((value >> 4) & 0x000f) as u8) * 17;
            let r = (((value >> 8) & 0x000f) as u8) * 17;
            let a = (((value >> 12) & 0x000f) as u8) * 17;
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    Ok(rgba)
}

fn decode_raw32_bitmap(
    bytes: &[u8],
    full_width: u32,
    full_height: u32,
    width: u32,
    height: u32,
    format: Option<&str>,
    compress: Option<&str>,
    spec: Option<&str>,
) -> Result<Vec<u8>, PsbDecoderError> {
    if width > full_width || height > full_height {
        return Err(PsbDecoderError::Texture(
            "32-bit PSB bitmap crop exceeds full surface".to_string(),
        ));
    }
    let expected_len = checked_surface_len(full_width, full_height, 4)?;
    let payload = uncompressed_or_rl_payload(bytes, compress, 4, expected_len)?;
    let source_stride = full_width as usize * 4;
    let output_stride = width as usize * 4;
    let mut cropped = Vec::with_capacity(checked_surface_len(width, height, 4)?);
    for y in 0..height as usize {
        let row_start = y.checked_mul(source_stride).ok_or_else(|| {
            PsbDecoderError::Texture("32-bit PSB bitmap row overflow".to_string())
        })?;
        cropped.extend_from_slice(&payload[row_start..row_start + output_stride]);
    }
    Ok(convert_raw_32bpp_texture_to_rgba(&cropped, format, spec))
}

fn decode_structural_bitmap(
    decoded: &DecodedPsb,
    candidate: &PsbBitmapCandidate,
    spec: Option<&str>,
) -> Result<Vec<u8>, PsbDecoderError> {
    let pixels = psb_resource_bytes(decoded, candidate.pixel).ok_or_else(|| {
        PsbDecoderError::Texture(format!(
            "{} {} references missing {} resource {}",
            candidate.semantic.label(),
            candidate.object_path,
            candidate.pixel.table.label(),
            candidate.pixel.index
        ))
    })?;

    if let Some(palette_ref) = candidate.palette {
        let palette = psb_resource_bytes(decoded, palette_ref).ok_or_else(|| {
            PsbDecoderError::Texture(format!(
                "{} {} references missing palette {} resource {}",
                candidate.semantic.label(),
                candidate.object_path,
                palette_ref.table.label(),
                palette_ref.index
            ))
        })?;
        return decode_indexed8_bitmap(
            pixels,
            palette,
            candidate.full_width,
            candidate.full_height,
            candidate.width,
            candidate.height,
            candidate.compress.as_deref(),
        );
    }

    if candidate.semantic == PsbBitmapSemantic::EmoteTexture
        && format_is_rgba4444(candidate.format.as_deref(), candidate.bit_count)
    {
        return decode_rgba4444_bitmap(
            pixels,
            candidate.full_width,
            candidate.full_height,
            candidate.width,
            candidate.height,
            candidate.compress.as_deref(),
        );
    }

    // Generic KrkrExtract bitmaps are four-byte pixels written directly to a
    // top-down 32-bit BMP, i.e. BGRA byte order.  Emote RGBA8 varies by PSB
    // spec, so retain the existing spec-aware channel mapping there.
    let (format, spec) = if candidate.semantic == PsbBitmapSemantic::GenericBitmap {
        (Some("BGRA8"), None)
    } else {
        (candidate.format.as_deref(), spec)
    };
    decode_raw32_bitmap(
        pixels,
        candidate.full_width,
        candidate.full_height,
        candidate.width,
        candidate.height,
        format,
        candidate.compress.as_deref(),
        spec,
    )
}

/// Parse the Emote schema and decode each unique source texture into RGBA8.
/// General PSBs that are not Emote models simply return an empty list.
pub fn decode_emote_textures(
    decoded: &DecodedPsb,
) -> Result<Vec<DecodedEmoteTexture>, PsbDecoderError> {
    let schema = match EmoteModelSchema::from_psb(&decoded.psb) {
        Ok(schema) => schema,
        Err(_) => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::<u32>::new();
    for texture in schema.textures.values() {
        if !seen.insert(texture.resource_index) {
            continue;
        }
        out.push(decode_texture_source(
            &decoded.normalized,
            &decoded.psb,
            texture,
            schema.spec.as_deref(),
        )?);
    }
    Ok(out)
}

fn decode_texture_source(
    data: &[u8],
    psb: &PsbFile,
    texture: &EmoteTextureSource,
    spec: Option<&str>,
) -> Result<DecodedEmoteTexture, PsbDecoderError> {
    let bytes = psb
        .resource_bytes(data, texture.resource_index as usize)
        .ok_or_else(|| {
            PsbDecoderError::Texture(format!(
                "texture {} resource index {} is outside the PSB resource table",
                texture.name, texture.resource_index
            ))
        })?;
    let (rgba, width, height) = decode_texture_rgba(
        bytes,
        texture.width,
        texture.height,
        texture.format.as_deref(),
        texture.compress.as_deref(),
        texture.bit_count,
        spec,
    )?;
    Ok(DecodedEmoteTexture {
        name: texture.name.clone(),
        resource_index: texture.resource_index,
        width,
        height,
        rgba,
    })
}

fn decode_texture_rgba(
    bytes: &[u8],
    expected_width: u32,
    expected_height: u32,
    format: Option<&str>,
    compress: Option<&str>,
    bit_count: Option<u32>,
    spec: Option<&str>,
) -> Result<(Vec<u8>, u32, u32), PsbDecoderError> {
    // The Emote texture type is authoritative here.  KrkrExtract's Emote
    // path uses two-byte source pixels for RGBA4444 even though its metadata
    // helper initializes a generic 32-bit BPP field.
    let bpp = if format_is_rgba4444(format, None) {
        16
    } else {
        bit_count.unwrap_or(32)
    };
    let bytes_per_pixel = (bpp as usize / 8).max(1);
    let expected_len = (expected_width as usize)
        .checked_mul(expected_height as usize)
        .and_then(|v| v.checked_mul(bytes_per_pixel))
        .ok_or_else(|| PsbDecoderError::Texture("texture dimensions overflow".to_string()))?;

    let rl = compress.is_some_and(|value| value.eq_ignore_ascii_case("RL"));
    let payload = if rl {
        decompress_rl(bytes, bytes_per_pixel, expected_len)?
    } else {
        bytes.to_vec()
    };

    if bpp == 32
        && payload.len()
            == (expected_width as usize)
                .saturating_mul(expected_height as usize)
                .saturating_mul(4)
    {
        return Ok((
            convert_raw_32bpp_texture_to_rgba(&payload, format, spec),
            expected_width,
            expected_height,
        ));
    }

    if format_is_rgba4444(format, bit_count) && payload.len() == expected_len {
        return Ok((
            decode_rgba4444_bitmap(
                &payload,
                expected_width,
                expected_height,
                expected_width,
                expected_height,
                None,
            )?,
            expected_width,
            expected_height,
        ));
    }

    // Some Emote PSBs embed a normal image bitstream as the resource.  Match
    // eluna_player: this path is only valid when the resource is not RL.
    if !rl {
        if let Ok(image) = image::load_from_memory(bytes) {
            let width = image.width();
            let height = image.height();
            return Ok((image.to_rgba8().into_raw(), width, height));
        }
    }

    Err(PsbDecoderError::Texture(format!(
        "unsupported texture payload: format={format:?} compress={compress:?} bit_count={bit_count:?} spec={spec:?} bytes={} expected={expected_len}",
        bytes.len()
    )))
}

fn decompress_rl(
    bytes: &[u8],
    align: usize,
    expected_len: usize,
) -> Result<Vec<u8>, PsbDecoderError> {
    if align == 0 {
        return Err(PsbDecoderError::Texture("invalid RL alignment".to_string()));
    }
    let mut out = Vec::with_capacity(expected_len);
    let mut pos = 0usize;
    while pos < bytes.len() {
        let cmd = bytes[pos];
        pos += 1;
        if (cmd & 0x80) != 0 {
            let count = ((cmd ^ 0x80) as usize) + 3;
            let end = pos
                .checked_add(align)
                .ok_or_else(|| PsbDecoderError::Texture("RL offset overflow".to_string()))?;
            let pattern = bytes
                .get(pos..end)
                .ok_or_else(|| PsbDecoderError::Texture("truncated RL repeat block".to_string()))?;
            let add = count
                .checked_mul(pattern.len())
                .ok_or_else(|| PsbDecoderError::Texture("RL output overflow".to_string()))?;
            if out.len().saturating_add(add) > expected_len {
                return Err(PsbDecoderError::Texture(
                    "RL output exceeds expected length".to_string(),
                ));
            }
            for _ in 0..count {
                out.extend_from_slice(pattern);
            }
            pos = end;
        } else {
            let count = ((cmd as usize) + 1)
                .checked_mul(align)
                .ok_or_else(|| PsbDecoderError::Texture("RL literal size overflow".to_string()))?;
            let end = pos
                .checked_add(count)
                .ok_or_else(|| PsbDecoderError::Texture("RL offset overflow".to_string()))?;
            let block = bytes.get(pos..end).ok_or_else(|| {
                PsbDecoderError::Texture("truncated RL literal block".to_string())
            })?;
            if out.len().saturating_add(block.len()) > expected_len {
                return Err(PsbDecoderError::Texture(
                    "RL output exceeds expected length".to_string(),
                ));
            }
            out.extend_from_slice(block);
            pos = end;
        }
    }
    if out.len() != expected_len {
        return Err(PsbDecoderError::Texture(format!(
            "RL output length mismatch: got {}, expected {expected_len}",
            out.len()
        )));
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum Raw32ChannelOrder {
    Bgra,
    Rgba,
    Bgrx,
    Rgbx,
}

fn convert_raw_32bpp_texture_to_rgba(
    bytes: &[u8],
    format: Option<&str>,
    spec: Option<&str>,
) -> Vec<u8> {
    let order = raw_32bpp_channel_order(format, spec);
    let mut rgba = Vec::with_capacity(bytes.len());
    for px in bytes.chunks_exact(4) {
        match order {
            Raw32ChannelOrder::Bgra => rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]),
            Raw32ChannelOrder::Rgba => rgba.extend_from_slice(px),
            Raw32ChannelOrder::Bgrx => rgba.extend_from_slice(&[px[2], px[1], px[0], 0xff]),
            Raw32ChannelOrder::Rgbx => rgba.extend_from_slice(&[px[0], px[1], px[2], 0xff]),
        }
    }
    rgba
}

fn raw_32bpp_channel_order(format: Option<&str>, spec: Option<&str>) -> Raw32ChannelOrder {
    let Some(format) = format else {
        return if spec_uses_big_endian_rgba(spec) {
            Raw32ChannelOrder::Rgba
        } else {
            Raw32ChannelOrder::Bgra
        };
    };
    let normalized: String = format
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    match normalized.as_str() {
        "RGBA" | "RGBA8" => {
            if spec_uses_big_endian_rgba(spec) {
                Raw32ChannelOrder::Rgba
            } else {
                Raw32ChannelOrder::Bgra
            }
        }
        "BERGBA8" => Raw32ChannelOrder::Rgba,
        "LERGBA8" | "BGRA8" | "ARGB8" | "A8R8G8B8" | "D3DFMTA8R8G8B8" => Raw32ChannelOrder::Bgra,
        "BGRX8" | "X8R8G8B8" | "D3DFMTX8R8G8B8" => Raw32ChannelOrder::Bgrx,
        "RGBX8" | "RGBX" => Raw32ChannelOrder::Rgbx,
        _ => {
            if spec_uses_big_endian_rgba(spec) {
                Raw32ChannelOrder::Rgba
            } else {
                Raw32ChannelOrder::Bgra
            }
        }
    }
}

fn spec_uses_big_endian_rgba(spec: Option<&str>) -> bool {
    spec.is_some_and(|spec| {
        matches!(
            spec.to_ascii_lowercase().as_str(),
            "common" | "ems" | "vita" | "psp" | "ps3"
        )
    })
}

/// Export PSB resource blobs next to the extracted PSB.
///
/// Every entry in both the normal resource table and the extra-resource table
/// is visited.  Images are decoded to `format` in this order: structural PSB
/// bitmap semantics recovered from the object tree, Eluna's Emote schema as a
/// compatibility fallback, then self-describing image bitstreams.  The blob
/// itself is therefore not required to carry an image magic/header.
/// When `include_unknown_raw` is true, blobs that are not decodable as images
/// are preserved byte-for-byte as `.bin` files instead of being silently lost.
pub fn export_psb_resources_detailed(
    decoded: &DecodedPsb,
    psb_output_path: &Path,
    format: EmoteTextureExportFormat,
    include_unknown_raw: bool,
) -> Result<Vec<PsbResourceExportRecord>, PsbDecoderError> {
    let file_name = psb_output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("asset.psb");
    let asset_dir = psb_output_path.with_file_name(format!("{file_name}.resources"));
    if asset_dir.exists() {
        fs::remove_dir_all(&asset_dir)?;
    }

    if decoded.psb.resources.is_empty() && decoded.extra_resource_blobs.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(&asset_dir)?;

    let structural_candidates = collect_psb_bitmap_candidates(&decoded.psb.root);
    let mut candidates_by_resource =
        std::collections::BTreeMap::<PsbResourceRef, Vec<&PsbBitmapCandidate>>::new();
    for candidate in &structural_candidates {
        candidates_by_resource
            .entry(candidate.pixel)
            .or_default()
            .push(candidate);
    }

    let schema = EmoteModelSchema::from_psb(&decoded.psb).ok();
    let mut emote_sources = std::collections::BTreeMap::<u32, &EmoteTextureSource>::new();
    if let Some(schema) = schema.as_ref() {
        for source in schema.textures.values() {
            emote_sources.entry(source.resource_index).or_insert(source);
        }
    }
    let spec = schema.as_ref().and_then(|schema| schema.spec.as_deref());

    let mut written = Vec::new();
    for index in 0..decoded.psb.resources.len() {
        let Some(bytes) = decoded.psb.resource_bytes(&decoded.normalized, index) else {
            continue;
        };
        let source = emote_sources.get(&(index as u32)).copied();
        let resource_ref = PsbResourceRef {
            table: PsbResourceTable::Resource,
            index: index as u32,
        };
        let candidates = candidates_by_resource
            .get(&resource_ref)
            .map_or(&[][..], |candidates| candidates.as_slice());
        if let Some(record) = export_one_psb_blob(
            decoded,
            &asset_dir,
            PsbResourceTable::Resource,
            index as u32,
            bytes,
            candidates,
            source,
            spec,
            format,
            include_unknown_raw,
        )? {
            written.push(record);
        }
    }

    for (index, bytes) in decoded.extra_resource_blobs.iter().enumerate() {
        let resource_ref = PsbResourceRef {
            table: PsbResourceTable::ExtraResource,
            index: index as u32,
        };
        let candidates = candidates_by_resource
            .get(&resource_ref)
            .map_or(&[][..], |candidates| candidates.as_slice());
        if let Some(record) = export_one_psb_blob(
            decoded,
            &asset_dir,
            PsbResourceTable::ExtraResource,
            index as u32,
            bytes,
            candidates,
            None,
            spec,
            format,
            include_unknown_raw,
        )? {
            written.push(record);
        }
    }

    if written.is_empty() && asset_dir.is_dir() {
        fs::remove_dir_all(&asset_dir)?;
    }
    Ok(written)
}

fn export_one_psb_blob(
    decoded: &DecodedPsb,
    asset_dir: &Path,
    table: PsbResourceTable,
    resource_index: u32,
    bytes: &[u8],
    structural_candidates: &[&PsbBitmapCandidate],
    emote_source: Option<&EmoteTextureSource>,
    spec: Option<&str>,
    format: EmoteTextureExportFormat,
    include_unknown_raw: bool,
) -> Result<Option<PsbResourceExportRecord>, PsbDecoderError> {
    let mut structural_decode_error = None;
    for candidate in structural_candidates {
        match decode_structural_bitmap(decoded, candidate, spec) {
            Ok(rgba) => {
                let name = sanitize_component(&candidate.name, resource_index);
                let path = asset_dir.join(format!(
                    "{}_{resource_index:04}_{name}.{}",
                    table.file_prefix(),
                    format.extension()
                ));
                save_rgba_image(&path, &rgba, candidate.width, candidate.height, format)?;
                let source_format = if candidate.palette.is_some() {
                    Some("psb-indexed8".to_string())
                } else if candidate.semantic == PsbBitmapSemantic::GenericBitmap {
                    Some("psb-bgra8".to_string())
                } else {
                    candidate
                        .format
                        .clone()
                        .or_else(|| Some("RGBA8".to_string()))
                };
                return Ok(Some(PsbResourceExportRecord {
                    path,
                    table,
                    resource_index,
                    name: candidate.name.clone(),
                    width: Some(candidate.width),
                    height: Some(candidate.height),
                    source_format,
                    compress: candidate.compress.clone(),
                    bit_count: candidate.bit_count.or_else(|| {
                        if candidate.palette.is_some() {
                            Some(8)
                        } else if format_is_rgba4444(
                            candidate.format.as_deref(),
                            candidate.bit_count,
                        ) {
                            Some(16)
                        } else {
                            Some(32)
                        }
                    }),
                    spec: spec.map(str::to_owned),
                    semantic: Some(candidate.semantic.label().to_string()),
                    object_path: Some(candidate.object_path.clone()),
                    full_width: Some(candidate.full_width),
                    full_height: Some(candidate.full_height),
                    palette_table: candidate.palette.map(|palette| palette.table),
                    palette_index: candidate.palette.map(|palette| palette.index),
                    decode_error: None,
                    exported_format: Some(format),
                    raw_blob: false,
                    source_blob_size: bytes.len(),
                    source_blob_sha256: crate::xp3_meta::sha256_hex(bytes),
                }));
            }
            Err(err) => {
                if structural_decode_error.is_none() {
                    structural_decode_error = Some(format!(
                        "{} {}: {err}",
                        candidate.semantic.label(),
                        candidate.object_path
                    ));
                }
            }
        }
    }

    if let Some(source) = emote_source {
        if let Ok((rgba, width, height)) = decode_texture_rgba(
            bytes,
            source.width,
            source.height,
            source.format.as_deref(),
            source.compress.as_deref(),
            source.bit_count,
            spec,
        ) {
            let name = sanitize_component(&source.name, resource_index);
            let path = asset_dir.join(format!(
                "{}_{resource_index:04}_{name}.{}",
                table.file_prefix(),
                format.extension()
            ));
            save_rgba_image(&path, &rgba, width, height, format)?;
            return Ok(Some(PsbResourceExportRecord {
                path,
                table,
                resource_index,
                name: source.name.clone(),
                width: Some(width),
                height: Some(height),
                source_format: source
                    .format
                    .clone()
                    .or_else(|| Some("emote-resource".to_string())),
                compress: source.compress.clone(),
                bit_count: source.bit_count,
                spec: spec.map(str::to_owned),
                semantic: Some("emote-schema-fallback".to_string()),
                object_path: None,
                full_width: Some(source.width),
                full_height: Some(source.height),
                palette_table: None,
                palette_index: None,
                decode_error: None,
                exported_format: Some(format),
                raw_blob: false,
                source_blob_size: bytes.len(),
                source_blob_sha256: crate::xp3_meta::sha256_hex(bytes),
            }));
        }
    }

    if bytes.starts_with(TLG0_MAGIC)
        || bytes.starts_with(TLG5_MAGIC)
        || bytes.starts_with(TLG6_MAGIC)
    {
        if let Ok(tlg) = decode_tlg(bytes) {
            let width = tlg.info.width;
            let height = tlg.info.height;
            let path = asset_dir.join(format!(
                "{}_{resource_index:04}.{}",
                table.file_prefix(),
                format.extension()
            ));
            save_rgba_image(&path, &tlg.rgba, width, height, format)?;
            return Ok(Some(PsbResourceExportRecord {
                path,
                table,
                resource_index,
                name: format!("{}_{resource_index:04}", table.file_prefix()),
                width: Some(width),
                height: Some(height),
                source_format: Some(tlg.info.version.as_str().to_ascii_lowercase()),
                compress: None,
                bit_count: None,
                spec: None,
                semantic: Some("embedded-image".to_string()),
                object_path: None,
                full_width: Some(width),
                full_height: Some(height),
                palette_table: None,
                palette_index: None,
                decode_error: None,
                exported_format: Some(format),
                raw_blob: false,
                source_blob_size: bytes.len(),
                source_blob_sha256: crate::xp3_meta::sha256_hex(bytes),
            }));
        }
    }

    if let Ok(image) = image::load_from_memory(bytes) {
        let width = image.width();
        let height = image.height();
        let rgba = image.to_rgba8().into_raw();
        let path = asset_dir.join(format!(
            "{}_{resource_index:04}.{}",
            table.file_prefix(),
            format.extension()
        ));
        save_rgba_image(&path, &rgba, width, height, format)?;
        return Ok(Some(PsbResourceExportRecord {
            path,
            table,
            resource_index,
            name: format!("{}_{resource_index:04}", table.file_prefix()),
            width: Some(width),
            height: Some(height),
            source_format: image::guess_format(bytes).ok().map(image_format_label),
            compress: None,
            bit_count: None,
            spec: None,
            semantic: Some("embedded-image".to_string()),
            object_path: None,
            full_width: Some(width),
            full_height: Some(height),
            palette_table: None,
            palette_index: None,
            decode_error: None,
            exported_format: Some(format),
            raw_blob: false,
            source_blob_size: bytes.len(),
            source_blob_sha256: crate::xp3_meta::sha256_hex(bytes),
        }));
    }

    if !include_unknown_raw {
        return Ok(None);
    }

    let structural_candidate = structural_candidates.first().copied();
    let path = asset_dir.join(format!("{}_{resource_index:04}.bin", table.file_prefix()));
    fs::write(&path, bytes)?;
    Ok(Some(PsbResourceExportRecord {
        path,
        table,
        resource_index,
        name: format!("{}_{resource_index:04}", table.file_prefix()),
        width: None,
        height: None,
        source_format: structural_candidate.and_then(|candidate| candidate.format.clone()),
        compress: structural_candidate.and_then(|candidate| candidate.compress.clone()),
        bit_count: structural_candidate.and_then(|candidate| candidate.bit_count),
        spec: spec.map(str::to_owned),
        semantic: structural_candidate.map(|candidate| candidate.semantic.label().to_string()),
        object_path: structural_candidate.map(|candidate| candidate.object_path.clone()),
        full_width: structural_candidate.map(|candidate| candidate.full_width),
        full_height: structural_candidate.map(|candidate| candidate.full_height),
        palette_table: structural_candidate
            .and_then(|candidate| candidate.palette.map(|palette| palette.table)),
        palette_index: structural_candidate
            .and_then(|candidate| candidate.palette.map(|palette| palette.index)),
        decode_error: structural_decode_error,
        exported_format: None,
        raw_blob: true,
        source_blob_size: bytes.len(),
        source_blob_sha256: crate::xp3_meta::sha256_hex(bytes),
    }))
}

fn image_format_label(format: ImageFormat) -> String {
    match format {
        ImageFormat::Png => "png",
        ImageFormat::Jpeg => "jpeg",
        ImageFormat::Bmp => "bmp",
        _ => "image",
    }
    .to_string()
}

fn save_rgba_image(
    path: &Path,
    rgba: &[u8],
    width: u32,
    height: u32,
    format: EmoteTextureExportFormat,
) -> Result<(), PsbDecoderError> {
    let image = RgbaImage::from_raw(width, height, rgba.to_vec()).ok_or_else(|| {
        PsbDecoderError::Texture(format!("RGBA size does not match {width}x{height}"))
    })?;
    match format.image_format() {
        Some(image_format) => image.save_with_format(path, image_format)?,
        None => {
            let mut rgb = Vec::with_capacity((width as usize) * (height as usize) * 3);
            for pixel in image.as_raw().chunks_exact(4) {
                rgb.extend_from_slice(&pixel[..3]);
            }
            let file = File::create(path)?;
            let mut writer = BufWriter::new(file);
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut writer, 95);
            encoder.encode(&rgb, width, height, ColorType::Rgb8.into())?;
            drop(encoder);
            writer.flush()?;
        }
    }
    Ok(())
}

/// Export decoded Emote source textures next to the extracted PSB.
///
/// For `foo.psb`, assets are placed under `foo.psb.textures/`. Only actual
/// image assets are written; no raw PSB resources or schema/debug files are
/// produced. PNG/BMP preserve alpha. JPEG deliberately drops alpha because
/// the format has no alpha channel.
pub fn export_emote_textures_detailed(
    decoded: &DecodedPsb,
    psb_output_path: &Path,
    formats: &[EmoteTextureExportFormat],
) -> Result<Vec<EmoteTextureExportRecord>, PsbDecoderError> {
    if formats.is_empty() {
        return Ok(Vec::new());
    }
    let schema = match EmoteModelSchema::from_psb(&decoded.psb) {
        Ok(schema) => schema,
        Err(_) => return Ok(Vec::new()),
    };
    if schema.textures.is_empty() {
        return Ok(Vec::new());
    }

    let file_name = psb_output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("model.psb");
    let asset_dir = psb_output_path.with_file_name(format!("{file_name}.textures"));
    if asset_dir.exists() {
        fs::remove_dir_all(&asset_dir)?;
    }
    fs::create_dir_all(&asset_dir)?;

    let mut written = Vec::new();
    let mut seen = std::collections::BTreeSet::<u32>::new();
    for source in schema.textures.values() {
        if !seen.insert(source.resource_index) {
            continue;
        }
        // Decode/save/drop one source texture at a time.  Do not materialize
        // every Emote atlas simultaneously; large models must not reintroduce
        // the archive-wide memory behaviour removed from the XP3 pipeline.
        let texture = decode_texture_source(
            &decoded.normalized,
            &decoded.psb,
            source,
            schema.spec.as_deref(),
        )?;
        let stem = sanitize_component(&texture.name, texture.resource_index);
        let image =
            RgbaImage::from_raw(texture.width, texture.height, texture.rgba).ok_or_else(|| {
                PsbDecoderError::Texture(format!(
                    "texture {} RGBA size does not match {}x{}",
                    texture.name, texture.width, texture.height
                ))
            })?;
        for &format in formats {
            let path = asset_dir.join(format!(
                "{:04}_{}.{}",
                texture.resource_index,
                stem,
                format.extension()
            ));
            match format.image_format() {
                Some(image_format) => image.save_with_format(&path, image_format)?,
                None => {
                    let mut rgb = Vec::with_capacity(
                        (texture.width as usize) * (texture.height as usize) * 3,
                    );
                    for pixel in image.as_raw().chunks_exact(4) {
                        rgb.extend_from_slice(&pixel[..3]);
                    }
                    let file = File::create(&path)?;
                    let mut writer = BufWriter::new(file);
                    let mut encoder =
                        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut writer, 95);
                    encoder.encode(&rgb, texture.width, texture.height, ColorType::Rgb8.into())?;
                    drop(encoder);
                    writer.flush()?;
                }
            }
            written.push(EmoteTextureExportRecord {
                path,
                name: source.name.clone(),
                resource_index: source.resource_index,
                width: texture.width,
                height: texture.height,
                source_format: source.format.clone(),
                compress: source.compress.clone(),
                bit_count: source.bit_count,
                spec: schema.spec.clone(),
                exported_format: format,
            });
        }
    }
    Ok(written)
}

/// Compatibility wrapper returning only output paths. New repack-aware callers
/// should use [`export_emote_textures_detailed`] so resource linkage and source
/// codec fields can be persisted in `xp3-meta.yaml`.
pub fn export_emote_textures(
    decoded: &DecodedPsb,
    psb_output_path: &Path,
    formats: &[EmoteTextureExportFormat],
) -> Result<Vec<PathBuf>, PsbDecoderError> {
    Ok(
        export_emote_textures_detailed(decoded, psb_output_path, formats)?
            .into_iter()
            .map(|record| record.path)
            .collect(),
    )
}

fn sanitize_component(name: &str, resource_index: u32) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let out = out.trim_matches(|c: char| c == '.' || c.is_whitespace());
    if out.is_empty() {
        format!("texture_{resource_index:04}")
    } else {
        out.chars().take(160).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psb_family_gate_is_signature_based() {
        assert!(is_psb_family_bytes(b"PSB\0rest"));
        assert!(is_psb_family_bytes(b"mdf\0\x10\x00\x00\x00rest"));
        assert!(is_psb_family_bytes(&[0x04, 0x22, 0x4d, 0x18, 1, 2, 3, 4]));
        assert!(!is_psb_family_bytes(b"not a psb.psb"));
    }

    #[test]
    fn brute_gate_requires_an_encryption_signal() {
        let mut v3 = vec![0u8; 48];
        v3[0..4].copy_from_slice(b"PSB\0");
        v3[4..6].copy_from_slice(&3u16.to_le_bytes());
        v3[6..8].copy_from_slice(&0u16.to_le_bytes());
        v3[36..40].copy_from_slice(&40u32.to_le_bytes());
        assert!(!should_bruteforce(&v3, &PsbError::UnexpectedEof));

        v3[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert!(should_bruteforce(&v3, &PsbError::UnexpectedEof));

        let mut v2 = v3.clone();
        v2[4..6].copy_from_slice(&2u16.to_le_bytes());
        v2[6..8].copy_from_slice(&0u16.to_le_bytes());
        v2[40] = 0x00;
        assert!(should_bruteforce(&v2, &PsbError::UnexpectedEof));
        v2[40] = 0x21;
        assert!(!should_bruteforce(&v2, &PsbError::UnexpectedEof));
    }

    #[test]
    fn rl_literal_and_repeat_blocks_decode() {
        // 0x00 => one literal 4-byte pixel; 0x80 => repeat next pixel 3 times.
        let input = [0x00, 1, 2, 3, 4, 0x80, 5, 6, 7, 8];
        let decoded = decompress_rl(&input, 4, 16).unwrap();
        assert_eq!(
            decoded,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]
        );
    }

    #[test]
    fn win_rgba8_uses_bgra_bytes_like_eluna_player() {
        let rgba = convert_raw_32bpp_texture_to_rgba(&[10, 20, 30, 40], Some("RGBA8"), Some("win"));
        assert_eq!(rgba, vec![30, 20, 10, 40]);
        let rgba =
            convert_raw_32bpp_texture_to_rgba(&[10, 20, 30, 40], Some("RGBA8"), Some("common"));
        assert_eq!(rgba, vec![10, 20, 30, 40]);
    }

    #[test]
    fn generic_bitmap_discovery_follows_psb_object_context() {
        let root = PsbValue::Object(vec![(
            "sprites".to_string(),
            PsbValue::Object(vec![(
                "face".to_string(),
                PsbValue::Object(vec![
                    ("width".to_string(), PsbValue::Int(320)),
                    ("height".to_string(), PsbValue::Int(180)),
                    ("pixel".to_string(), PsbValue::Resource(7)),
                    ("pal".to_string(), PsbValue::ExtraResource(2)),
                    ("compress".to_string(), PsbValue::String("RL".to_string())),
                ]),
            )]),
        )]);

        let candidates = collect_psb_bitmap_candidates(&root);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.semantic == PsbBitmapSemantic::GenericBitmap)
            .unwrap();
        assert_eq!(candidate.object_path, "/sprites/face");
        assert_eq!(candidate.name, "face");
        assert_eq!(candidate.full_width, 320);
        assert_eq!(candidate.full_height, 180);
        assert_eq!(candidate.pixel.table, PsbResourceTable::Resource);
        assert_eq!(candidate.pixel.index, 7);
        assert_eq!(
            candidate.palette.unwrap().table,
            PsbResourceTable::ExtraResource
        );
        assert_eq!(candidate.palette.unwrap().index, 2);
        assert_eq!(candidate.compress.as_deref(), Some("RL"));
    }

    #[test]
    fn emote_texture_discovery_keeps_full_and_truncated_dimensions() {
        let root = PsbValue::Object(vec![(
            "source".to_string(),
            PsbValue::Object(vec![(
                "face".to_string(),
                PsbValue::Object(vec![(
                    "texture".to_string(),
                    PsbValue::Object(vec![
                        ("width".to_string(), PsbValue::Int(1024)),
                        ("height".to_string(), PsbValue::Int(512)),
                        ("truncated_width".to_string(), PsbValue::Int(777)),
                        ("truncated_height".to_string(), PsbValue::Int(400)),
                        ("type".to_string(), PsbValue::String("RGBA4444".to_string())),
                        ("pixel".to_string(), PsbValue::ExtraResource(9)),
                    ]),
                )]),
            )]),
        )]);

        let candidates = collect_psb_bitmap_candidates(&root);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.semantic == PsbBitmapSemantic::EmoteTexture)
            .unwrap();
        assert_eq!(candidate.object_path, "/source/face/texture");
        assert_eq!(candidate.name, "face");
        assert_eq!((candidate.full_width, candidate.full_height), (1024, 512));
        assert_eq!((candidate.width, candidate.height), (777, 400));
        assert_eq!(candidate.pixel.table, PsbResourceTable::ExtraResource);
        assert_eq!(candidate.pixel.index, 9);
        assert_eq!(candidate.format.as_deref(), Some("RGBA4444"));
    }

    #[test]
    fn rgba4444_decode_matches_krkrextract_nibble_layout() {
        // A4R4G4B4 little-endian: A=F, R=1, G=2, B=3.
        let rgba = decode_rgba4444_bitmap(&[0x23, 0xF1], 1, 1, 1, 1, None).unwrap();
        assert_eq!(rgba, vec![0x11, 0x22, 0x33, 0xFF]);
    }

    #[test]
    fn indexed_psb_palette_is_bgrx_not_rgba() {
        let pixels = [1u8];
        let mut palette = vec![0u8; 1024];
        palette[4..8].copy_from_slice(&[0x33, 0x22, 0x11, 0x00]);
        let rgba = decode_indexed8_bitmap(&pixels, &palette, 1, 1, 1, 1, None).unwrap();
        assert_eq!(rgba, vec![0x11, 0x22, 0x33, 0xFF]);
    }

    #[test]
    fn roundtrip_json_preserves_object_order_and_psb_types() {
        let value = PsbValue::Object(vec![
            ("x".to_string(), PsbValue::Int(7)),
            ("x".to_string(), PsbValue::Resource(3)),
            ("f".to_string(), PsbValue::Float(-0.0)),
            (
                "compiler".to_string(),
                PsbValue::Compiler(PsbCompilerTag::BinaryTree),
            ),
        ]);
        let json = psb_value_to_roundtrip_json(&value);
        let entries = json["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0]["key"], "x");
        assert_eq!(entries[0]["value"]["$type"], "int");
        assert_eq!(entries[1]["key"], "x");
        assert_eq!(entries[1]["value"]["$type"], "resource");
        assert_eq!(entries[2]["value"]["bits"], "0x80000000");
        assert_eq!(entries[3]["value"]["tag"], "binary_tree");
    }

    #[test]
    fn json_sidecar_keeps_original_psb_family_suffix() {
        assert_eq!(
            psb_json_output_path(Path::new("foo.scn")),
            PathBuf::from("foo.scn.json")
        );
        assert_eq!(
            psb_json_output_path(Path::new("foo.pimg")),
            PathBuf::from("foo.pimg.json")
        );
    }
}
