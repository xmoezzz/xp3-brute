//! End-to-end XP3 and embedded-format round-trip verification.
//!
//! Archive checks and file-format checks are deliberately reported as two
//! independent groups. A structurally valid XP3 is not evidence that an
//! expanded TLG/PSB/AMV/PBD/text asset was reconstructed correctly.

use crate::decoder::amv::decode_amv;
use crate::decoder::pbd::decode_pbd;
use crate::decoder::psb::{decode_psb_with_key, psb_value_to_roundtrip_json, DecodedPsb};
use crate::decoder::tlg::decode_tlg;
use crate::encoder::{
    pack_xp3_from_manifest, reconstruct_plaintext_entry_from_manifest, Xp3PackOptions,
};
use crate::validate::decode_kirikiri_text;
use crate::xp3::Archive;
use crate::xp3_meta::{
    read_manifest, sha256_hex, EntryMeta, PsbSourceMeta, TransformMeta, Xp3Meta,
};
use crate::{Error, Result};
use base64::Engine;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

const TAG_INFO: u32 = u32::from_le_bytes(*b"info");
const TAG_SEGM: u32 = u32::from_le_bytes(*b"segm");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoundtripClass {
    ByteExact,
    SemanticExact,
    Lossy,
    Unsupported,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Unsupported,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoundtripCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileFormatRoundtripReport {
    pub detected: String,
    pub expanded: bool,
    pub modified: Option<bool>,
    pub classification: RoundtripClass,
    pub checks: Vec<RoundtripCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryRoundtripReport {
    pub entry_index: usize,
    pub path: String,
    pub pack_mode: String,
    pub xp3: Vec<RoundtripCheck>,
    pub file_format: FileFormatRoundtripReport,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoundtripReport {
    pub source_archive: Option<String>,
    pub output_archive: String,
    pub archive_reopened: bool,
    pub archive_byte_exact: Option<bool>,
    pub entries: Vec<EntryRoundtripReport>,
    pub passed: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyRoundtripOptions {
    pub output_archive: PathBuf,
    pub rebuilt_root: Option<PathBuf>,
    pub source_archive: Option<PathBuf>,
    pub allow_lossy: bool,
    pub preserve_physical_anchors: bool,
}

fn pass(name: &str, detail: impl Into<String>) -> RoundtripCheck {
    RoundtripCheck {
        name: name.to_string(),
        status: CheckStatus::Pass,
        detail: detail.into(),
    }
}

fn fail(name: &str, detail: impl Into<String>) -> RoundtripCheck {
    RoundtripCheck {
        name: name.to_string(),
        status: CheckStatus::Fail,
        detail: detail.into(),
    }
}

fn unsupported(name: &str, detail: impl Into<String>) -> RoundtripCheck {
    RoundtripCheck {
        name: name.to_string(),
        status: CheckStatus::Unsupported,
        detail: detail.into(),
    }
}

fn na(name: &str, detail: impl Into<String>) -> RoundtripCheck {
    RoundtripCheck {
        name: name.to_string(),
        status: CheckStatus::NotApplicable,
        detail: detail.into(),
    }
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(Error::invalid(format!(
            "manifest path must be relative: {value:?}"
        )));
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::invalid(format!("unsafe manifest path: {value:?}")));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::invalid("empty manifest path"));
    }
    Ok(out)
}

fn entry_storage_path(entry: &EntryMeta) -> Result<Option<String>> {
    let mut paths = BTreeSet::new();
    for transform in &entry.transforms {
        let path = match transform {
            TransformMeta::KirikiriText(_) => entry.identity.logical_path.as_deref(),
            TransformMeta::TlgImage(meta) => Some(meta.source_asset_path.as_str()),
            TransformMeta::PsbRootJson(meta) => Some(meta.source.source_binary_path.as_str()),
            TransformMeta::PsbTexture(meta) => Some(meta.source.source_binary_path.as_str()),
            TransformMeta::PsbResourceBlob(meta) => Some(meta.source.source_binary_path.as_str()),
            TransformMeta::PbdJson(meta) => Some(meta.source_binary_path.as_str()),
            TransformMeta::AmvFrame(meta) => Some(meta.source_container_path.as_str()),
        };
        if let Some(path) = path {
            paths.insert(path.to_string());
        }
    }
    if paths.len() > 1 {
        return Err(Error::format(format!(
            "entry[{}] transform families disagree on storage path: {paths:?}",
            entry.index
        )));
    }
    Ok(paths
        .into_iter()
        .next()
        .or_else(|| entry.identity.output_path.clone()))
}

fn expected_hash(transform: &TransformMeta) -> Option<(&str, &str)> {
    match transform {
        TransformMeta::KirikiriText(meta) => meta.output_sha256.as_deref().map(|hash| ("", hash)),
        TransformMeta::TlgImage(meta) => meta
            .output_sha256
            .as_deref()
            .map(|hash| (meta.output_path.as_str(), hash)),
        TransformMeta::PsbRootJson(meta) => meta
            .output_sha256
            .as_deref()
            .map(|hash| (meta.output_path.as_str(), hash)),
        TransformMeta::PsbTexture(meta) => meta
            .output_sha256
            .as_deref()
            .map(|hash| (meta.output_path.as_str(), hash)),
        TransformMeta::PsbResourceBlob(meta) => {
            Some((meta.output_path.as_str(), meta.blob_sha256.as_str()))
        }
        TransformMeta::PbdJson(meta) => {
            Some((meta.output_path.as_str(), meta.output_sha256.as_str()))
        }
        TransformMeta::AmvFrame(meta) => meta
            .output_sha256
            .as_deref()
            .map(|hash| (meta.output_path.as_str(), hash)),
    }
}

fn sidecars_modified(unpack_root: &Path, entry: &EntryMeta) -> Result<Option<bool>> {
    if entry.transforms.is_empty() {
        return Ok(None);
    }
    for transform in &entry.transforms {
        let Some((mut path, hash)) = expected_hash(transform) else {
            return Ok(None);
        };
        if path.is_empty() {
            path = entry.identity.output_path.as_deref().ok_or_else(|| {
                Error::format(format!(
                    "entry[{}] text transform has no output path",
                    entry.index
                ))
            })?;
        }
        let bytes = match fs::read(unpack_root.join(safe_relative(path)?)) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Some(true)),
            Err(err) => return Err(err.into()),
        };
        if !sha256_hex(&bytes).eq_ignore_ascii_case(hash) {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

fn format_label(entry: &EntryMeta) -> String {
    let extension = entry_storage_path(entry).ok().flatten().and_then(|path| {
        Path::new(&path)
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_uppercase)
    });
    if let Some(transform) = entry.transforms.first() {
        return match transform {
            TransformMeta::KirikiriText(_) => "KiriKiri text".to_string(),
            TransformMeta::TlgImage(_) => "TLG".to_string(),
            TransformMeta::PsbRootJson(_)
            | TransformMeta::PsbTexture(_)
            | TransformMeta::PsbResourceBlob(_) => extension.unwrap_or_else(|| "PSB".to_string()),
            TransformMeta::PbdJson(_) => "PBD".to_string(),
            TransformMeta::AmvFrame(_) => "AMV".to_string(),
        };
    }
    entry
        .recovery
        .format
        .clone()
        .or(extension)
        .unwrap_or_else(|| "raw/unknown".to_string())
}

fn psb_source(entry: &EntryMeta) -> Option<&PsbSourceMeta> {
    entry
        .transforms
        .iter()
        .find_map(|transform| match transform {
            TransformMeta::PsbRootJson(meta) => Some(&meta.source),
            TransformMeta::PsbTexture(meta) => Some(&meta.source),
            TransformMeta::PsbResourceBlob(meta) => Some(&meta.source),
            _ => None,
        })
}

fn parse_u32_hex(value: &str) -> Result<u32> {
    u32::from_str_radix(
        value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .map_err(|_| Error::format(format!("invalid PSB key {value:?}")))
}

fn psb_key(manifest: &Xp3Meta, entry: &EntryMeta) -> Result<Option<u32>> {
    if let Some(value) = psb_source(entry).and_then(|source| source.emote_key_hex.as_deref()) {
        return parse_u32_hex(value).map(Some);
    }
    for transform in &entry.transforms {
        if let TransformMeta::PsbTexture(meta) = transform {
            if let Some(value) = meta.emote_key_hex.as_deref() {
                return parse_u32_hex(value).map(Some);
            }
        }
    }
    for key in &manifest.keys {
        if matches!(key.kind.as_str(), "emote-psb-key" | "emote-psb-key-global") {
            if let Some(value) = key.u32_hex.as_deref() {
                return parse_u32_hex(value).map(Some);
            }
        }
    }
    Ok(None)
}

fn psb_resources(decoded: &DecodedPsb) -> Result<Vec<Vec<u8>>> {
    (0..decoded.psb.resources.len())
        .map(|index| {
            decoded
                .psb
                .resource_bytes(&decoded.normalized, index)
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::format(format!("cannot read PSB resource {index}")))
        })
        .collect()
}

fn compare_file_format(
    manifest: &Xp3Meta,
    entry: &EntryMeta,
    expected: &[u8],
    actual: &[u8],
) -> Vec<RoundtripCheck> {
    let Some(first) = entry.transforms.first() else {
        return vec![if expected == actual {
            pass(
                "source bytes",
                "unexpanded source-format bytes are byte-identical",
            )
        } else {
            fail("source bytes", "unexpanded source-format bytes changed")
        }];
    };
    match first {
        TransformMeta::TlgImage(expected_meta) => {
            let left = decode_tlg(expected);
            let right = decode_tlg(actual);
            match (left, right) {
                (Ok(left), Ok(right)) => vec![
                    pass("parse rebuilt", "rebuilt TLG decoded successfully"),
                    if (left.info.width, left.info.height) == (right.info.width, right.info.height)
                    {
                        pass(
                            "dimensions",
                            format!("{}x{}", right.info.width, right.info.height),
                        )
                    } else {
                        fail("dimensions", "rebuilt TLG dimensions differ")
                    },
                    if left
                        .rgba
                        .chunks_exact(4)
                        .map(|p| p[3])
                        .eq(right.rgba.chunks_exact(4).map(|p| p[3]))
                    {
                        pass("alpha", "canonical alpha plane matches")
                    } else {
                        fail("alpha", "canonical alpha plane differs")
                    },
                    if left.rgba == right.rgba {
                        pass("pixels", "canonical RGBA pixels match")
                    } else if !expected_meta.lossless_pixels {
                        pass(
                            "pixels",
                            "lossy target explicitly permits pixel differences",
                        )
                    } else {
                        fail("pixels", "canonical RGBA pixels differ")
                    },
                    if left.info.container.is_some() == right.info.container.is_some() {
                        pass(
                            "container type",
                            if right.info.container.is_some() {
                                "TLG0/SDS preserved"
                            } else {
                                "raw TLG preserved"
                            },
                        )
                    } else {
                        fail("container type", "raw/TLG0 container identity differs")
                    },
                ],
                (Err(err), _) => vec![fail("reference decode", err.to_string())],
                (_, Err(err)) => vec![fail("parse rebuilt", err.to_string())],
            }
        }
        TransformMeta::PsbRootJson(_)
        | TransformMeta::PsbTexture(_)
        | TransformMeta::PsbResourceBlob(_) => {
            let key = match psb_key(manifest, entry) {
                Ok(key) => key,
                Err(err) => return vec![fail("PSB key", err.to_string())],
            };
            let left = decode_psb_with_key(expected, key);
            let right = decode_psb_with_key(actual, key);
            match (left, right) {
                (Ok(Some(left)), Ok(Some(right))) => {
                    let left_root = psb_value_to_roundtrip_json(&left.psb.root);
                    let right_root = psb_value_to_roundtrip_json(&right.psb.root);
                    let left_resources = psb_resources(&left);
                    let right_resources = psb_resources(&right);
                    vec![
                        pass(
                            "parse rebuilt",
                            format!("PSB v{} parsed", right.psb.version),
                        ),
                        if left.psb.version == right.psb.version {
                            pass(
                                "subtype/version",
                                format!("version {} preserved", right.psb.version),
                            )
                        } else {
                            fail("subtype/version", "PSB version differs")
                        },
                        if left_root == right_root {
                            pass("root structure", "ordered typed root values match")
                        } else {
                            fail("root structure", "ordered typed root values differ")
                        },
                        if left.psb.names == right.psb.names
                            && left.psb.strings == right.psb.strings
                        {
                            pass("strings", "name and string tables match")
                        } else {
                            fail("strings", "name or string table differs")
                        },
                        match (left_resources, right_resources) {
                            (Ok(a), Ok(b))
                                if a == b
                                    && left.extra_resource_blobs == right.extra_resource_blobs =>
                            {
                                pass("resource identity", "resource indices and payloads match")
                            }
                            (Ok(_), Ok(_)) => {
                                fail("resource identity", "resource index payloads differ")
                            }
                            (Err(err), _) | (_, Err(err)) => {
                                fail("resource identity", err.to_string())
                            }
                        },
                        if left.psb.encrypted == right.psb.encrypted {
                            pass(
                                "PSB protection state",
                                format!("encrypted={}", right.psb.encrypted),
                            )
                        } else {
                            fail("PSB protection state", "encrypted-input state differs")
                        },
                    ]
                }
                (Ok(None), _) | (_, Ok(None)) => vec![fail(
                    "parse rebuilt",
                    "bytes were not recognized as PSB family",
                )],
                (Err(err), _) => vec![fail("reference decode", err.to_string())],
                (_, Err(err)) => vec![fail("parse rebuilt", err.to_string())],
            }
        }
        TransformMeta::PbdJson(_) => match (decode_pbd(expected), decode_pbd(actual)) {
            (Ok(left), Ok(right)) => vec![
                pass(
                    "parse rebuilt",
                    format!("{} parsed", right.header.variant.label()),
                ),
                if left.header.variant == right.header.variant {
                    pass("variant", right.header.variant.label())
                } else {
                    fail("variant", "PBD variant differs")
                },
                if left.header.seed == right.header.seed
                    && left.header.crypt == right.header.crypt
                    && left.header.iv == right.header.iv
                    && left.header.trailer == right.header.trailer
                    && left.header.lz4_terminated == right.header.lz4_terminated
                {
                    pass(
                        "framing metadata",
                        "seed/crypt/IV/trailer/LZ4 terminator match",
                    )
                } else {
                    fail("framing metadata", "PBD framing metadata differs")
                },
                if left.root == right.root {
                    pass("semantic structure", "ordered typed PBD value tree matches")
                } else {
                    fail("semantic structure", "PBD value tree differs")
                },
            ],
            (Err(err), _) => vec![fail("reference decode", err.to_string())],
            (_, Err(err)) => vec![fail("parse rebuilt", err.to_string())],
        },
        TransformMeta::AmvFrame(_) => match (decode_amv(expected), decode_amv(actual)) {
            (Ok(left), Ok(right)) => vec![
                pass(
                    "re-encode",
                    format!("{} decoded", right.info.variant.label()),
                ),
                if left.info.frame_count == right.info.frame_count
                    && left.frames.len() == right.frames.len()
                {
                    pass("frames", format!("{} frames", right.frames.len()))
                } else {
                    fail("frames", "frame count differs")
                },
                if (left.info.width, left.info.height) == (right.info.width, right.info.height) {
                    pass(
                        "dimensions",
                        format!("{}x{}", right.info.width, right.info.height),
                    )
                } else {
                    fail("dimensions", "canvas dimensions differ")
                },
                if (left.info.fps_num, left.info.fps_den)
                    == (right.info.fps_num, right.info.fps_den)
                {
                    pass(
                        "timing",
                        format!(
                            "duration={}/{} seconds",
                            right.info.fps_num, right.info.fps_den
                        ),
                    )
                } else {
                    fail("timing", "frame duration rational differs")
                },
                if left
                    .frames
                    .iter()
                    .map(|frame| frame.index)
                    .eq(right.frames.iter().map(|frame| frame.index))
                {
                    pass("frame order", "frame indices and order match")
                } else {
                    fail("frame order", "frame order differs")
                },
                if left
                    .frames
                    .iter()
                    .map(|frame| &frame.rgba)
                    .eq(right.frames.iter().map(|frame| &frame.rgba))
                {
                    pass("pixels/alpha", "decoded RGBA frames match")
                } else {
                    fail("pixels/alpha", "decoded RGBA frames differ")
                },
            ],
            (Err(err), _) => vec![fail("reference decode", err.to_string())],
            (_, Err(err)) => vec![fail("parse rebuilt", err.to_string())],
        },
        TransformMeta::KirikiriText(meta) => {
            match (decode_kirikiri_text(expected), decode_kirikiri_text(actual)) {
                (Some(left), Some(right)) => vec![
                    pass(
                        "parse rebuilt",
                        format!("wrapper={}", meta.source_encoding_or_wrapper),
                    ),
                    if left == right {
                        pass(
                            "text",
                            "decoded UTF-16LE content, BOM, and line endings match",
                        )
                    } else {
                        fail("text", "decoded text differs")
                    },
                    if expected.get(..3) == actual.get(..3) {
                        pass(
                            "wrapper/BOM",
                            "source wrapper signature and BOM state match",
                        )
                    } else {
                        fail(
                            "wrapper/BOM",
                            "source wrapper signature or BOM state differs",
                        )
                    },
                ],
                (None, _) => vec![fail(
                    "reference decode",
                    "reference text wrapper did not decode",
                )],
                (_, None) => vec![fail("parse rebuilt", "rebuilt text wrapper did not decode")],
            }
        }
    }
}

fn file_class(entry: &EntryMeta, modified: Option<bool>, bytes_equal: bool) -> RoundtripClass {
    if entry.transforms.is_empty() {
        return if bytes_equal {
            RoundtripClass::ByteExact
        } else {
            RoundtripClass::Unsupported
        };
    }
    if modified == Some(false) && bytes_equal {
        return RoundtripClass::ByteExact;
    }
    let lossy = entry.transforms.iter().any(|transform| match transform {
        TransformMeta::TlgImage(meta) => !meta.lossless_pixels,
        TransformMeta::PsbTexture(meta) => !meta.lossless_pixels,
        TransformMeta::AmvFrame(_) => true,
        _ => false,
    });
    if lossy {
        RoundtripClass::Lossy
    } else {
        RoundtripClass::SemanticExact
    }
}

fn checks_pass(checks: &[RoundtripCheck]) -> bool {
    checks
        .iter()
        .all(|check| !matches!(check.status, CheckStatus::Fail | CheckStatus::Unsupported))
}

fn read_le_u32(bytes: &[u8], at: usize, what: &str) -> Result<u32> {
    let value = bytes
        .get(at..at + 4)
        .ok_or_else(|| Error::format(format!("truncated {what}")))?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn read_le_u64(bytes: &[u8], at: usize, what: &str) -> Result<u64> {
    let value = bytes
        .get(at..at + 8)
        .ok_or_else(|| Error::format(format!("truncated {what}")))?;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}

/// Produce the immutable portion of a `File` root body.
///
/// The only fields an edited entry is allowed to change are the two `info`
/// sizes and each `segm` descriptor's offset/original/stored sizes. Everything
/// else remains byte-for-byte significant: flags, physical name and its raw
/// length, `adlr`, `time`, unknown/private chunks, chunk order and vendor tails.
fn immutable_file_body(mut body: Vec<u8>) -> Result<Vec<u8>> {
    let mut position = 0usize;
    while position + 12 <= body.len() {
        let tag = read_le_u32(&body, position, "File child tag")?;
        let len = usize::try_from(read_le_u64(&body, position + 4, "File child size")?)
            .map_err(|_| Error::format("File child size exceeds usize"))?;
        let data_start = position + 12;
        let data_end = data_start
            .checked_add(len)
            .ok_or_else(|| Error::format("File child range overflow"))?;
        if data_end > body.len() {
            return Err(Error::format("File child extends beyond root body"));
        }
        match tag {
            TAG_INFO if len >= 20 => body[data_start + 4..data_start + 20].fill(0),
            TAG_SEGM if len.is_multiple_of(28) => {
                for at in (data_start..data_end).step_by(28) {
                    body[at + 4..at + 28].fill(0);
                }
            }
            _ => {}
        }
        position = data_end;
    }
    if position != body.len() {
        return Err(Error::format("File root has trailing partial child header"));
    }
    Ok(body)
}

fn immutable_file_metadata_hash(
    decoded: &[u8],
    root_offset: usize,
    root_size: u64,
) -> Result<String> {
    if read_le_u64(decoded, root_offset + 4, "File root size")? != root_size {
        return Err(Error::format(
            "File root size differs from manifest template",
        ));
    }
    let len =
        usize::try_from(root_size).map_err(|_| Error::format("File root size exceeds usize"))?;
    let start = root_offset
        .checked_add(12)
        .ok_or_else(|| Error::format("File root offset overflow"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::format("File root range overflow"))?;
    let body = decoded
        .get(start..end)
        .ok_or_else(|| Error::format("File root is outside decoded index"))?;
    Ok(sha256_hex(&immutable_file_body(body.to_vec())?))
}

fn manifest_metadata_hash(manifest: &Xp3Meta, entry: &EntryMeta) -> Result<String> {
    let root_index = entry.original.root_chunk_index.ok_or_else(|| {
        Error::format(format!(
            "entry[{}] manifest lacks exact File root identity",
            entry.index
        ))
    })?;
    let root = manifest
        .root_chunks
        .get(root_index)
        .ok_or_else(|| Error::format(format!("entry[{}] File root is missing", entry.index)))?;
    let block = manifest.index_blocks.get(root.index_block).ok_or_else(|| {
        Error::format(format!(
            "entry[{}] File root index block is missing",
            entry.index
        ))
    })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&block.decoded_base64)
        .map_err(|err| Error::format(format!("invalid manifest index base64: {err}")))?;
    immutable_file_metadata_hash(&decoded, root.index_offset, root.size)
}

fn archive_metadata_hash(
    archive: &Archive,
    manifest: &Xp3Meta,
    entry: &EntryMeta,
) -> Result<String> {
    let root_index = entry.original.root_chunk_index.ok_or_else(|| {
        Error::format(format!(
            "entry[{}] manifest lacks exact File root identity",
            entry.index
        ))
    })?;
    let root = manifest
        .root_chunks
        .get(root_index)
        .ok_or_else(|| Error::format(format!("entry[{}] File root is missing", entry.index)))?;
    let block = archive.index_blocks.get(root.index_block).ok_or_else(|| {
        Error::format(format!(
            "entry[{}] rebuilt index block is missing",
            entry.index
        ))
    })?;
    immutable_file_metadata_hash(&block.decoded, root.index_offset, root.size)
}

fn parse_optional_hex_u32(value: Option<&str>) -> Result<Option<u32>> {
    value.map(parse_u32_hex).transpose()
}

fn special_blobs_match(manifest: &Xp3Meta, rebuilt: &Archive) -> Result<Option<bool>> {
    if manifest.special.is_empty() {
        return Ok(None);
    }
    for special in &manifest.special {
        let expected = base64::engine::general_purpose::STANDARD
            .decode(&special.stored_blob_base64)
            .map_err(|err| Error::format(format!("invalid Special blob base64: {err}")))?;
        if sha256_hex(&expected) != special.stored_blob_sha256 {
            return Err(Error::format(format!(
                "Special root {} manifest hash is inconsistent",
                special.root_index
            )));
        }
        if rebuilt.special_index_bytes_for_root(special.root_index) != Some(expected.as_slice()) {
            return Ok(Some(false));
        }
    }
    Ok(Some(true))
}

pub fn verify_roundtrip(
    unpack_root: &Path,
    options: &VerifyRoundtripOptions,
) -> Result<RoundtripReport> {
    let manifest = read_manifest(unpack_root)
        .map_err(|err| Error::format(format!("cannot read xp3-meta.yaml: {err}")))?;
    let rebuilt_root = options
        .rebuilt_root
        .clone()
        .unwrap_or_else(|| unpack_root.join(".xp3-roundtrip-rebuilt"));
    let pack = pack_xp3_from_manifest(
        unpack_root,
        &options.output_archive,
        &Xp3PackOptions {
            source_archive: options.source_archive.clone(),
            rebuild_assets: true,
            rebuilt_root: Some(rebuilt_root.clone()),
            allow_lossy: options.allow_lossy,
            preserve_physical_anchors: options.preserve_physical_anchors,
        },
    )?;
    let reopened = Archive::open(&options.output_archive)?;
    let source_path = options
        .source_archive
        .clone()
        .or_else(|| manifest.archive.source_path.as_deref().map(PathBuf::from));
    let source_archive = match source_path.as_deref() {
        Some(path) if path.is_file() => Some(Archive::open(path)?),
        _ => None,
    };
    let special_identity = special_blobs_match(&manifest, &reopened)?;
    let reports = manifest
        .entries
        .par_iter()
        .map(|entry| -> Result<_> {
        let path = entry_storage_path(entry)?
            .or_else(|| entry.identity.logical_path.clone())
            .unwrap_or_else(|| entry.original.info_name.clone());
        let pack_entry = pack
            .entries
            .iter()
            .find(|record| record.entry_index == entry.index)
            .ok_or_else(|| Error::format(format!("pack report missing entry[{}]", entry.index)))?;
        let modified = sidecars_modified(unpack_root, entry)?;
        let expected_path = if pack_entry.mode == "reencoded" && !entry.transforms.is_empty() {
            rebuilt_root.join(safe_relative(&path)?)
        } else {
            unpack_root.join(safe_relative(&path)?)
        };
        let mut expected = fs::read(&expected_path).ok();
        let actual = reconstruct_plaintext_entry_from_manifest(
            &reopened,
            &manifest,
            entry.index,
        );
        let retained_stored_exact = pack_entry.mode == "stored-byte-reuse"
            && source_archive.as_ref().is_some_and(|source| {
                source.stored_entry_bytes(entry.index).ok()
                    == reopened.stored_entry_bytes(entry.index).ok()
            });
        let manifest_plaintext_matches = |bytes: &[u8]| {
            entry
                .recovery
                .storage_plaintext_sha256
                .as_deref()
                .is_some_and(|expected| sha256_hex(bytes).eq_ignore_ascii_case(expected))
        };
        let mut retained_ciphertext_proof = false;
        if retained_stored_exact {
            match (&expected, &actual) {
                (None, Ok(reopened_plaintext)) if manifest_plaintext_matches(reopened_plaintext) => {
                    expected = Some(reopened_plaintext.clone());
                    retained_ciphertext_proof = true;
                }
                (None, Ok(_)) => {
                    retained_ciphertext_proof = true;
                }
                (_, Err(_)) => {
                    retained_ciphertext_proof = true;
                }
                _ => {}
            }
        }
        let reopened_entry = reopened.entries.get(entry.index);
        let mut xp3 = vec![pass("reopen", "entry parsed from rebuilt XP3")];
        xp3.push(match reopened_entry {
            Some(value)
                if value.name == entry.original.info_name
                    && value.info_name_length == entry.original.info_name_length
                    && value.alternate_name == entry.original.alternate_name =>
            {
                pass(
                    "physical name",
                    "info name bytes/length and alternate identity preserved",
                )
            }
            Some(_) => fail("physical name", "info/alternate name identity differs"),
            None => fail("physical name", "rebuilt archive entry is missing"),
        });
        xp3.push(match reopened_entry {
            Some(value) => {
                let expected_adler = parse_optional_hex_u32(entry.original.adler32_hex.as_deref())?;
                let expected_filter =
                    parse_optional_hex_u32(entry.original.original_filter_hash_hex.as_deref())?;
                if value.adler == expected_adler
                    && expected_filter.is_none_or(|hash| value.adler == Some(hash))
                    && value.alternate_hash == entry.original.alternate_hash
                    && value.hxv4_id == entry.original.hxv4_id
                {
                    pass(
                        "XP3 hash identity",
                        "original adlr/filter seed, alternate hash and HXV4 id preserved",
                    )
                } else {
                    fail(
                        "XP3 hash identity",
                        "adlr/filter seed, alternate hash or HXV4 id changed",
                    )
                }
            }
            None => fail("XP3 hash identity", "rebuilt archive entry is missing"),
        });
        xp3.push(match (
            manifest_metadata_hash(&manifest, entry),
            archive_metadata_hash(&reopened, &manifest, entry),
        ) {
            (Ok(expected), Ok(actual)) if expected == actual => pass(
                "timestamp/metadata",
                format!(
                    "immutable File metadata SHA-256 {actual}; adlr/time/flags/names/unknown chunks preserved"
                ),
            ),
            (Ok(expected), Ok(actual)) => fail(
                "timestamp/metadata",
                format!("immutable File metadata changed: expected {expected}, got {actual}"),
            ),
            (Err(err), _) | (_, Err(err)) => fail("timestamp/metadata", err.to_string()),
        });
        xp3.push(if entry.identity.hxv4_special_record_index.is_some() {
            if reopened_entry.and_then(|value| value.hxv4_id) == entry.original.hxv4_id {
                pass(
                    "Special mapping",
                    "HXV4 physical id and manifest linkage preserved",
                )
            } else {
                fail("Special mapping", "HXV4 physical id/linkage differs")
            }
        } else {
            na("Special mapping", "entry has no Special name mapping")
        });
        xp3.push(match special_identity {
            Some(true) => pass(
                "Special bytes/hash",
                "stored Special/HXV4 blob and authenticated name hashes are byte-identical",
            ),
            Some(false) => fail(
                "Special bytes/hash",
                "stored Special/HXV4 blob or name/hash identity changed",
            ),
            None => na("Special bytes/hash", "archive has no Special blob"),
        });
        xp3.push(match reopened_entry {
            Some(value)
                if value.segments.len() == entry.original.segments.len()
                    && value
                        .segments
                        .iter()
                        .zip(&entry.original.segments)
                        .all(|(actual, expected)| actual.flags == expected.flags) =>
            {
                pass(
                    "segment structure",
                    "segment count/order/storage flags preserved",
                )
            }
            Some(_) => fail("segment structure", "segment count or storage flags differ"),
            None => fail("segment structure", "rebuilt archive entry is missing"),
        });

        let (actual, encryption_equal, opaque_preserved) =
            match (expected.as_deref(), actual) {
            (Some(expected), Ok(actual)) => {
                let equal = expected == actual;
                let expected_hash = sha256_hex(expected);
                let actual_hash = sha256_hex(&actual);
                xp3.push(if expected_hash == actual_hash {
                    pass(
                        "source hash",
                        format!("source-format SHA-256 {actual_hash}"),
                    )
                } else {
                    fail(
                        "source hash",
                        format!(
                            "source-format SHA-256 differs: expected {expected_hash}, got {actual_hash}"
                        ),
                    )
                });
                xp3.push(if equal {
                    pass(
                        "encryption",
                        if retained_ciphertext_proof {
                            "stored ciphertext is byte-identical and post-pack decrypt matches the retained plaintext hash"
                        } else {
                            "post-pack reconstruct+decrypt equals rebuilt source-format bytes"
                        },
                    )
                } else {
                    fail(
                        "encryption",
                        "post-pack reconstruct+decrypt differs from rebuilt source-format bytes",
                    )
                });
                xp3.push(
                    if modified == Some(true) && pack_entry.mode != "reencoded" {
                        fail(
                            "edited asset consumption",
                            "modified sidecar used stored-byte reuse",
                        )
                    } else if modified == Some(true) {
                        pass(
                            "edited asset consumption",
                            "modified sidecar forced source-format rebuild",
                        )
                    } else {
                        na(
                            "edited asset consumption",
                            "sidecars are unchanged or asset was not expanded",
                        )
                    },
                );
                (Some(actual), equal, false)
            }
            (None, result) if retained_ciphertext_proof => {
                xp3.push(pass(
                    "source hash",
                    "entry has no retained plaintext reference; exact stored segment bytes were preserved",
                ));
                xp3.push(pass(
                    "encryption",
                    "source and rebuilt encrypted segment bytes are byte-identical",
                ));
                xp3.push(na(
                    "edited asset consumption",
                    "opaque entry was not edited and used exact stored-byte reuse",
                ));
                let _ = result;
                (None, true, true)
            }
            (_, Err(err)) if retained_ciphertext_proof => {
                xp3.push(pass(
                    "source hash",
                    "entry is opaque to the reversible filter set; exact stored segment bytes were retained",
                ));
                xp3.push(pass(
                    "encryption",
                    "source and rebuilt encrypted segment bytes are byte-identical",
                ));
                xp3.push(na(
                    "edited asset consumption",
                    "opaque entry was not edited and used exact stored-byte reuse",
                ));
                let _ = err;
                (None, true, true)
            }
            (_, Err(err)) => {
                xp3.push(unsupported(
                    "source hash",
                    "post-pack source-format bytes could not be reconstructed",
                ));
                xp3.push(unsupported("encryption", err.to_string()));
                (None, false, false)
            }
            (None, _) => {
                xp3.push(unsupported(
                    "source hash",
                    format!(
                        "expected source-format bytes are unavailable at {}",
                        expected_path.display()
                    ),
                ));
                xp3.push(unsupported(
                    "encryption",
                    format!(
                        "expected source-format bytes are unavailable at {}",
                        expected_path.display()
                    ),
                ));
                (None, false, false)
            }
        };

        let format_checks = if opaque_preserved {
            vec![na(
                "format verification",
                "opaque unchanged entry is preserved as exact encrypted stored bytes",
            )]
        } else {
            match (expected.as_deref(), actual.as_deref()) {
            (Some(expected), Some(actual)) => {
                compare_file_format(&manifest, entry, expected, actual)
            }
            _ => vec![unsupported(
                "format verification",
                "source-format bytes were unavailable after XP3 verification",
            )],
            }
        };
        let classification = if opaque_preserved {
            RoundtripClass::NotApplicable
        } else {
            file_class(entry, modified, encryption_equal)
        };
        let passed = checks_pass(&xp3) && checks_pass(&format_checks);
        Ok(EntryRoundtripReport {
            entry_index: entry.index,
            path,
            pack_mode: pack_entry.mode.clone(),
            xp3,
            file_format: FileFormatRoundtripReport {
                detected: format_label(entry),
                expanded: !entry.transforms.is_empty(),
                modified,
                classification,
                checks: format_checks,
            },
            passed,
        })
        })
        .collect::<Result<Vec<_>>>()?;

    let passed = reports.iter().all(|entry| entry.passed);
    Ok(RoundtripReport {
        source_archive: manifest.archive.source_path.clone(),
        output_archive: options.output_archive.display().to_string(),
        archive_reopened: true,
        archive_byte_exact: pack.byte_identical_to_source,
        entries: reports,
        passed,
    })
}

pub fn roundtrip_report_json(report: &RoundtripReport) -> Result<String> {
    serde_json::to_string_pretty(report)
        .map_err(|err| Error::format(format!("cannot serialize round-trip report: {err}")))
}

pub fn roundtrip_report_summary(report: &RoundtripReport) -> serde_json::Value {
    let mut byte_exact = 0usize;
    let mut semantic_exact = 0usize;
    let mut lossy = 0usize;
    for entry in &report.entries {
        match entry.file_format.classification {
            RoundtripClass::ByteExact => byte_exact += 1,
            RoundtripClass::SemanticExact => semantic_exact += 1,
            RoundtripClass::Lossy => lossy += 1,
            RoundtripClass::Unsupported | RoundtripClass::NotApplicable => {}
        }
    }
    json!({
        "passed": report.passed,
        "entries": report.entries.len(),
        "byte_exact": byte_exact,
        "semantic_exact": semantic_exact,
        "lossy": lossy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::psb::test_psb_resource_fixture;
    use crate::encoder::reconstruct_plaintext_entry_from_manifest;
    use crate::encoder::tlg::{encode_tlg_image, TlgEncodeOptions};
    use crate::xp3::XP3_MAGIC;
    use crate::xp3_meta::{
        write_manifest, ArchiveMeta, EntryIdentityMeta, EntryOriginalMeta, EntryRecoveryMeta,
        IndexBlockMeta, KeyMeta, PsbResourceBlobTransformMeta, PsbSourceMeta, RepackPolicies,
        RepeatingXorKeyMeta, RootChunkMeta, SegmentMeta, TlgCodecMeta, TlgTransformMeta,
        UnpackMeta, XP3_META_SCHEMA,
    };
    use image::{Rgba, RgbaImage};

    fn child(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag);
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn sample_file_body() -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        info.extend_from_slice(&100u64.to_le_bytes());
        info.extend_from_slice(&80u64.to_le_bytes());
        info.extend_from_slice(&1u16.to_le_bytes());
        info.extend_from_slice(&('a' as u16).to_le_bytes());
        info.extend_from_slice(b"vendor-tail");

        let mut segment = Vec::new();
        segment.extend_from_slice(&0x81u32.to_le_bytes());
        segment.extend_from_slice(&0x1000u64.to_le_bytes());
        segment.extend_from_slice(&100u64.to_le_bytes());
        segment.extend_from_slice(&80u64.to_le_bytes());

        let mut body = child(b"info", &info);
        body.extend_from_slice(&child(b"segm", &segment));
        body.extend_from_slice(&child(b"adlr", &0xdead_beefu32.to_le_bytes()));
        body.extend_from_slice(&child(b"time", &0x0123_4567_89ab_cdefu64.to_le_bytes()));
        body.extend_from_slice(&child(b"vend", b"opaque-metadata"));
        body
    }

    fn make_single_entry_xp3(payload: &[u8], name: &str, adlr: u32) -> Vec<u8> {
        let words = name.encode_utf16().collect::<Vec<_>>();
        let mut info = Vec::new();
        info.extend_from_slice(&0x0000_0042u32.to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(words.len() as u16).to_le_bytes());
        for word in words {
            info.extend_from_slice(&word.to_le_bytes());
        }
        info.extend_from_slice(b"info-vendor-tail");

        let data_offset = (XP3_MAGIC.len() + 8) as u64;
        let mut segment = Vec::new();
        segment.extend_from_slice(&0u32.to_le_bytes());
        segment.extend_from_slice(&data_offset.to_le_bytes());
        segment.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        segment.extend_from_slice(&(payload.len() as u64).to_le_bytes());

        let mut body = child(b"info", &info);
        body.extend_from_slice(&child(b"segm", &segment));
        body.extend_from_slice(&child(b"adlr", &adlr.to_le_bytes()));
        body.extend_from_slice(&child(b"time", &0x0123_4567_89ab_cdefu64.to_le_bytes()));
        body.extend_from_slice(&child(b"vend", b"immutable-vendor-metadata"));
        let index = child(b"File", &body);
        let index_offset = data_offset + payload.len() as u64;

        let mut archive = Vec::new();
        archive.extend_from_slice(&XP3_MAGIC);
        archive.extend_from_slice(&index_offset.to_le_bytes());
        archive.extend_from_slice(payload);
        archive.push(0);
        archive.extend_from_slice(&(index.len() as u64).to_le_bytes());
        archive.extend_from_slice(&index);
        archive
    }

    fn xor(data: &mut [u8], key: &[u8]) {
        for (index, byte) in data.iter_mut().enumerate() {
            *byte ^= key[index % key.len()];
        }
    }

    fn single_entry_manifest(
        output_root: &Path,
        source_path: &Path,
        source_archive: &Archive,
        logical_path: &str,
        format: &str,
        storage_plaintext: &[u8],
        transform: TransformMeta,
    ) -> Xp3Meta {
        let entry = &source_archive.entries[0];
        let block = &source_archive.index_blocks[0];
        let parsed_root = &source_archive.root_chunks[entry.root_chunk_index.unwrap()];
        let adlr = entry.adler.unwrap();
        Xp3Meta {
            schema: XP3_META_SCHEMA.to_string(),
            producer: "xp3-brute-test".to_string(),
            producer_version: env!("CARGO_PKG_VERSION").to_string(),
            archive: ArchiveMeta {
                source_file: "source.xp3".to_string(),
                source_path: Some(source_path.display().to_string()),
                family: "xp3".to_string(),
                xp3_offset: source_archive.xp3_offset,
                physical_size: source_archive.physical_size(),
                entry_count: 1,
            },
            unpack: UnpackMeta {
                tlg: if format.starts_with("TLG") {
                    "png".to_string()
                } else {
                    "none".to_string()
                },
                psb: if format == "PSB" {
                    "all".to_string()
                } else {
                    "none".to_string()
                },
                pbd: "none".to_string(),
                amv: Some("none".to_string()),
                output_root: output_root.display().to_string(),
            },
            policies: RepackPolicies::default(),
            index_blocks: vec![IndexBlockMeta {
                index: 0,
                physical_offset: block.physical_offset,
                flags: block.flags,
                stored_size: block.stored_size,
                original_size: block.original_size,
                decoded_base64: crate::xp3_meta::b64(&block.decoded),
                decoded_sha256: sha256_hex(&block.decoded),
                encoded_base64: None,
                encoded_sha256: None,
            }],
            root_chunks: vec![RootChunkMeta {
                index: 0,
                magic_hex: format!("0x{:08x}", parsed_root.magic),
                size: parsed_root.size,
                index_block: parsed_root.index_block,
                index_offset: parsed_root.index_offset,
                kind: "File".to_string(),
                inferred_name: None,
                inferred_hash: None,
                inferred_offset: None,
                inferred_original_size: None,
                inferred_archive_size: None,
                inferred_hxv4_kind: None,
                inferred_hxv4_id: None,
            }],
            special: Vec::new(),
            preserved_files: Vec::new(),
            hxv4: None,
            keys: vec![KeyMeta {
                kind: "archive-global-repeating-xor".to_string(),
                source: "test-vector".to_string(),
                entry_index: None,
                logical_path: None,
                repeating_xor: Some(RepeatingXorKeyMeta {
                    period: 3,
                    slots: vec!["42".to_string(), "a7".to_string(), "19".to_string()],
                    complete_key_hex: Some("42a719".to_string()),
                }),
                u32_hex: None,
                bytes_hex: None,
            }],
            x86_filter_modules: Vec::new(),
            entries: vec![EntryMeta {
                index: 0,
                original: EntryOriginalMeta {
                    root_chunk_index: entry.root_chunk_index,
                    flags: entry.flags,
                    original_size: entry.original_size,
                    archive_size: entry.archive_size,
                    info_name_length: entry.info_name_length,
                    info_name: entry.name.clone(),
                    alternate_name: None,
                    alternate_hash: None,
                    hxv4_id: None,
                    adler32_hex: Some(format!("{adlr:08x}")),
                    original_filter_hash_hex: Some(format!("{adlr:08x}")),
                    segments: entry
                        .segments
                        .iter()
                        .map(|segment| SegmentMeta {
                            flags: segment.flags,
                            archive_offset: segment.archive_offset,
                            original_size: segment.original_size,
                            archive_size: segment.archive_size,
                        })
                        .collect(),
                },
                identity: EntryIdentityMeta {
                    logical_path: Some(logical_path.to_string()),
                    output_path: Some(logical_path.to_string()),
                    hxv4_special_record_index: None,
                    path_hash_hex: None,
                    name_hash_hex: None,
                },
                recovery: EntryRecoveryMeta {
                    status: "global-repeating-xor".to_string(),
                    format: Some(format.to_string()),
                    storage_plaintext_sha256: Some(sha256_hex(storage_plaintext)),
                    repeating_xor: None,
                    hxv4_native: None,
                    x86_filter: None,
                    detail: Some("test reversible filter".to_string()),
                },
                transforms: vec![transform],
            }],
        }
    }

    #[test]
    fn immutable_xp3_metadata_ignores_only_sizes_and_offsets() {
        let original = sample_file_body();
        let expected = immutable_file_body(original.clone()).unwrap();

        let mut layout_changed = original.clone();
        // info original/archive sizes
        layout_changed[16..32].copy_from_slice(&[0x55; 16]);
        let segm = 12 + (22 + 2 + b"vendor-tail".len()) + 12;
        // segm offset/original/archive sizes
        layout_changed[segm + 4..segm + 28].copy_from_slice(&[0x66; 24]);
        assert_eq!(immutable_file_body(layout_changed).unwrap(), expected);

        for needle in [b"adlr", b"time", b"vend"] {
            let at = original
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap();
            let mut changed = original.clone();
            changed[at + 12] ^= 0x80;
            assert_ne!(immutable_file_body(changed).unwrap(), expected);
        }

        let mut name_or_flags_changed = original;
        name_or_flags_changed[12] ^= 1;
        assert_ne!(
            immutable_file_body(name_or_flags_changed).unwrap(),
            expected
        );
    }

    #[test]
    fn encrypted_xp3_modified_tlg_full_chain_preserves_identity_metadata() {
        let root =
            std::env::temp_dir().join(format!("xp3-full-roundtrip-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let original_image = RgbaImage::from_fn(8, 8, |x, y| {
            Rgba([(x * 17) as u8, (y * 19) as u8, 31, 255 - (x + y) as u8])
        });
        let source_tlg = encode_tlg_image(&original_image, TlgEncodeOptions::default()).unwrap();
        let adlr = crate::xp3::adler32(&source_tlg);
        let key = [0x42, 0xa7, 0x19];
        let mut encrypted = source_tlg.clone();
        xor(&mut encrypted, &key);
        let source_bytes = make_single_entry_xp3(&encrypted, "image.tlg", adlr);
        let source_path = root.join("source.xp3");
        fs::write(&source_path, &source_bytes).unwrap();
        let source_archive = Archive::open(&source_path).unwrap();
        let entry = &source_archive.entries[0];
        let block = &source_archive.index_blocks[0];
        let parsed_root = &source_archive.root_chunks[entry.root_chunk_index.unwrap()];

        let png_path = root.join("image.png");
        original_image.save(&png_path).unwrap();
        let original_png_hash = sha256_hex(&fs::read(&png_path).unwrap());
        let decoded = decode_tlg(&source_tlg).unwrap();
        let manifest = Xp3Meta {
            schema: XP3_META_SCHEMA.to_string(),
            producer: "xp3-brute-test".to_string(),
            producer_version: env!("CARGO_PKG_VERSION").to_string(),
            archive: ArchiveMeta {
                source_file: "source.xp3".to_string(),
                source_path: Some(source_path.display().to_string()),
                family: "xp3".to_string(),
                xp3_offset: source_archive.xp3_offset,
                physical_size: source_archive.physical_size(),
                entry_count: 1,
            },
            unpack: UnpackMeta {
                tlg: "png".to_string(),
                psb: "none".to_string(),
                pbd: "none".to_string(),
                amv: Some("none".to_string()),
                output_root: root.display().to_string(),
            },
            policies: RepackPolicies::default(),
            index_blocks: vec![IndexBlockMeta {
                index: 0,
                physical_offset: block.physical_offset,
                flags: block.flags,
                stored_size: block.stored_size,
                original_size: block.original_size,
                decoded_base64: crate::xp3_meta::b64(&block.decoded),
                decoded_sha256: sha256_hex(&block.decoded),
                encoded_base64: None,
                encoded_sha256: None,
            }],
            root_chunks: vec![RootChunkMeta {
                index: 0,
                magic_hex: format!("0x{:08x}", parsed_root.magic),
                size: parsed_root.size,
                index_block: parsed_root.index_block,
                index_offset: parsed_root.index_offset,
                kind: "File".to_string(),
                inferred_name: None,
                inferred_hash: None,
                inferred_offset: None,
                inferred_original_size: None,
                inferred_archive_size: None,
                inferred_hxv4_kind: None,
                inferred_hxv4_id: None,
            }],
            special: Vec::new(),
            preserved_files: Vec::new(),
            hxv4: None,
            keys: vec![KeyMeta {
                kind: "archive-global-repeating-xor".to_string(),
                source: "test-vector".to_string(),
                entry_index: None,
                logical_path: None,
                repeating_xor: Some(RepeatingXorKeyMeta {
                    period: key.len(),
                    slots: key.iter().map(|value| format!("{value:02x}")).collect(),
                    complete_key_hex: Some("42a719".to_string()),
                }),
                u32_hex: None,
                bytes_hex: None,
            }],
            x86_filter_modules: Vec::new(),
            entries: vec![EntryMeta {
                index: 0,
                original: EntryOriginalMeta {
                    root_chunk_index: entry.root_chunk_index,
                    flags: entry.flags,
                    original_size: entry.original_size,
                    archive_size: entry.archive_size,
                    info_name_length: entry.info_name_length,
                    info_name: entry.name.clone(),
                    alternate_name: None,
                    alternate_hash: None,
                    hxv4_id: None,
                    adler32_hex: Some(format!("{adlr:08x}")),
                    original_filter_hash_hex: Some(format!("{adlr:08x}")),
                    segments: entry
                        .segments
                        .iter()
                        .map(|segment| SegmentMeta {
                            flags: segment.flags,
                            archive_offset: segment.archive_offset,
                            original_size: segment.original_size,
                            archive_size: segment.archive_size,
                        })
                        .collect(),
                },
                identity: EntryIdentityMeta {
                    logical_path: Some("image.tlg".to_string()),
                    output_path: Some("image.tlg".to_string()),
                    hxv4_special_record_index: None,
                    path_hash_hex: None,
                    name_hash_hex: None,
                },
                recovery: EntryRecoveryMeta {
                    status: "global-repeating-xor".to_string(),
                    format: Some("TLG5".to_string()),
                    storage_plaintext_sha256: Some(sha256_hex(&source_tlg)),
                    repeating_xor: None,
                    hxv4_native: None,
                    x86_filter: None,
                    detail: Some("test reversible filter".to_string()),
                },
                transforms: vec![TransformMeta::TlgImage(TlgTransformMeta {
                    source_asset_path: "image.tlg".to_string(),
                    source_size: source_tlg.len(),
                    source_sha256: sha256_hex(&source_tlg),
                    output_path: "image.png".to_string(),
                    output_format: "png".to_string(),
                    output_sha256: Some(original_png_hash),
                    lossless_pixels: true,
                    version: "TLG5".to_string(),
                    width: 8,
                    height: 8,
                    components: 4,
                    decoded_rgba_sha256: sha256_hex(&decoded.rgba),
                    codec: TlgCodecMeta::Tlg5 { block_height: 4 },
                    container: None,
                })],
            }],
        };
        write_manifest(&root, &manifest).unwrap();

        let mut modified_image = original_image;
        modified_image.put_pixel(0, 0, Rgba([250, 1, 200, 77]));
        modified_image.save(&png_path).unwrap();
        let output = root.join("rebuilt.xp3");
        let report = verify_roundtrip(
            &root,
            &VerifyRoundtripOptions {
                output_archive: output.clone(),
                source_archive: Some(source_path),
                rebuilt_root: Some(root.join("rebuilt-assets")),
                allow_lossy: false,
                preserve_physical_anchors: true,
            },
        )
        .unwrap();
        assert!(report.passed, "{:#?}", report.entries[0]);
        assert_eq!(report.entries[0].pack_mode, "reencoded");
        assert_eq!(report.entries[0].file_format.modified, Some(true));
        for name in [
            "XP3 hash identity",
            "timestamp/metadata",
            "source hash",
            "encryption",
            "edited asset consumption",
        ] {
            assert!(report.entries[0]
                .xp3
                .iter()
                .any(|check| check.name == name && check.status == CheckStatus::Pass));
        }

        let rebuilt_archive = Archive::open(output).unwrap();
        let rebuilt_plain =
            reconstruct_plaintext_entry_from_manifest(&rebuilt_archive, &manifest, 0).unwrap();
        let rebuilt_tlg = decode_tlg(&rebuilt_plain).unwrap();
        assert_eq!(rebuilt_tlg.rgba, modified_image.into_raw());
        assert_eq!(rebuilt_archive.entries[0].adler, Some(adlr));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn encrypted_xp3_modified_psb_full_chain_preserves_identity_metadata() {
        let root =
            std::env::temp_dir().join(format!("xp3-psb-full-chain-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let original_resource = b"original-psb-resource".to_vec();
        let source_psb = test_psb_resource_fixture(&original_resource);
        let decoded_source = decode_psb_with_key(&source_psb, None).unwrap().unwrap();
        let adlr = crate::xp3::adler32(&source_psb);
        let key = [0x42, 0xa7, 0x19];
        let mut encrypted = source_psb.clone();
        xor(&mut encrypted, &key);
        let source_bytes = make_single_entry_xp3(&encrypted, "scene.scn", adlr);
        let source_path = root.join("source.xp3");
        fs::write(&source_path, &source_bytes).unwrap();
        let source_archive = Archive::open(&source_path).unwrap();

        fs::write(root.join("scene.scn"), &source_psb).unwrap();
        let resource_path = root.join("resource-0.bin");
        fs::write(&resource_path, &original_resource).unwrap();
        let source = PsbSourceMeta {
            source_binary_path: "scene.scn".to_string(),
            source_size: source_psb.len(),
            source_sha256: sha256_hex(&source_psb),
            normalized_size: decoded_source.normalized.len(),
            normalized_sha256: sha256_hex(&decoded_source.normalized),
            wrapper: "raw-psb".to_string(),
            psb_version: 4,
            encrypted_input: false,
            emote_key_hex: None,
        };
        let transform = TransformMeta::PsbResourceBlob(PsbResourceBlobTransformMeta {
            source,
            output_path: "resource-0.bin".to_string(),
            source_binary_retained: true,
            resource_table: "resource".to_string(),
            resource_index: 0,
            blob_size: original_resource.len(),
            blob_sha256: sha256_hex(&original_resource),
            semantic_candidate: None,
            object_path: Some("/payload".to_string()),
            full_width: None,
            full_height: None,
            palette_resource_table: None,
            palette_resource_index: None,
            decode_error: None,
        });
        let manifest = single_entry_manifest(
            &root,
            &source_path,
            &source_archive,
            "scene.scn",
            "PSB",
            &source_psb,
            transform,
        );
        write_manifest(&root, &manifest).unwrap();

        let modified_resource = b"modified-psb-resource-2026".to_vec();
        fs::write(&resource_path, &modified_resource).unwrap();
        let output = root.join("rebuilt.xp3");
        let report = verify_roundtrip(
            &root,
            &VerifyRoundtripOptions {
                output_archive: output.clone(),
                source_archive: Some(source_path),
                rebuilt_root: Some(root.join("rebuilt-assets")),
                allow_lossy: false,
                preserve_physical_anchors: true,
            },
        )
        .unwrap();
        assert!(report.passed, "{:#?}", report.entries[0]);
        assert_eq!(report.entries[0].pack_mode, "reencoded");
        assert_eq!(report.entries[0].file_format.modified, Some(true));
        for name in [
            "XP3 hash identity",
            "timestamp/metadata",
            "source hash",
            "encryption",
            "edited asset consumption",
        ] {
            assert!(report.entries[0]
                .xp3
                .iter()
                .any(|check| check.name == name && check.status == CheckStatus::Pass));
        }
        for name in [
            "parse rebuilt",
            "subtype/version",
            "root structure",
            "strings",
            "resource identity",
            "PSB protection state",
        ] {
            assert!(report.entries[0]
                .file_format
                .checks
                .iter()
                .any(|check| check.name == name && check.status == CheckStatus::Pass));
        }

        let rebuilt_archive = Archive::open(output).unwrap();
        let rebuilt_plain =
            reconstruct_plaintext_entry_from_manifest(&rebuilt_archive, &manifest, 0).unwrap();
        let decoded_rebuilt = decode_psb_with_key(&rebuilt_plain, None).unwrap().unwrap();
        assert_eq!(
            psb_value_to_roundtrip_json(&decoded_rebuilt.psb.root),
            psb_value_to_roundtrip_json(&decoded_source.psb.root)
        );
        assert_eq!(
            decoded_rebuilt
                .psb
                .resource_bytes(&decoded_rebuilt.normalized, 0),
            Some(modified_resource.as_slice())
        );
        assert_eq!(rebuilt_archive.entries[0].adler, Some(adlr));

        fs::remove_dir_all(root).unwrap();
    }
}
