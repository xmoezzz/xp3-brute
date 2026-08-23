//! Manifest-driven reconstruction of expanded assets.
//!
//! This produces an overlay tree containing the original archive paths.  It is
//! deliberately separate from XP3 container writing: a future/adjacent XP3
//! packer only has to consume these rebuilt plaintext assets and the archive
//! identity/layout metadata.

use crate::encoder::amv::rebuild_amv_from_transforms;
use crate::encoder::pbd::rebuild_pbd_from_json;
use crate::encoder::psb::{rebuild_psb_from_transforms, PsbRebuildInput};
use crate::encoder::text::rebuild_kirikiri_text;
use crate::encoder::tlg::rebuild_tlg_from_transform;
use crate::xp3_meta::{
    read_manifest, AmvFrameTransformMeta, KirikiriTextTransformMeta, PbdJsonTransformMeta,
    PsbResourceBlobTransformMeta, PsbRootJsonTransformMeta, PsbSourceMeta, PsbTextureTransformMeta,
    TlgTransformMeta, TransformMeta, Xp3Meta, XP3_META_SCHEMA,
};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RebuildOptions {
    pub output_root: PathBuf,
    pub allow_lossy: bool,
    /// When a validated source XP3 is available, unchanged sidecars can reuse
    /// their exact stored entry bytes and must not be needlessly re-encoded.
    pub changed_only: bool,
}

#[derive(Debug, Clone)]
pub struct RebuildRecord {
    pub kind: String,
    pub source_path: String,
    pub output_path: PathBuf,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct RebuildReport {
    pub records: Vec<RebuildRecord>,
}

#[derive(Debug, Clone)]
struct PsbGroup {
    source: PsbSourceMeta,
    root_json: Option<PsbRootJsonTransformMeta>,
    textures: Vec<PsbTextureTransformMeta>,
    raw_blobs: Vec<PsbResourceBlobTransformMeta>,
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

fn write_overlay(output_root: &Path, source_path: &str, bytes: &[u8]) -> Result<PathBuf> {
    let relative = safe_relative(source_path)?;
    let output = output_root.join(relative);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, bytes)?;
    Ok(output)
}

fn sidecar_unchanged(
    unpack_root: &Path,
    path: &str,
    expected_sha256: Option<&str>,
) -> Result<bool> {
    let Some(expected) = expected_sha256 else {
        return Ok(false);
    };
    let bytes = fs::read(unpack_root.join(safe_relative(path)?))?;
    Ok(crate::xp3_meta::sha256_hex(&bytes).eq_ignore_ascii_case(expected))
}

fn parse_u32_hex(value: &str) -> Result<u32> {
    u32::from_str_radix(
        value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .map_err(|_| Error::format(format!("invalid u32 key {value:?} in xp3-meta.yaml")))
}

fn global_emote_key(manifest: &Xp3Meta) -> Result<Option<u32>> {
    for key in &manifest.keys {
        if matches!(key.kind.as_str(), "emote-psb-key" | "emote-psb-key-global") {
            if let Some(value) = &key.u32_hex {
                return Ok(Some(parse_u32_hex(value)?));
            }
        }
    }
    Ok(None)
}

fn merge_psb_group(groups: &mut BTreeMap<String, PsbGroup>, source: &PsbSourceMeta) -> Result<()> {
    match groups.get(&source.source_binary_path) {
        Some(group) => {
            if group.source.source_sha256 != source.source_sha256
                || group.source.normalized_sha256 != source.normalized_sha256
            {
                return Err(Error::format(format!(
                    "conflicting PSB source metadata for {}",
                    source.source_binary_path
                )));
            }
        }
        None => {
            groups.insert(
                source.source_binary_path.clone(),
                PsbGroup {
                    source: source.clone(),
                    root_json: None,
                    textures: Vec::new(),
                    raw_blobs: Vec::new(),
                },
            );
        }
    }
    Ok(())
}

/// Rebuild every asset that has an encoder-backed transform in `xp3-meta.yaml`.
///
/// `unpack_root` contains the manifest and editable sidecars. `output_root`
/// receives an overlay using the *original archive asset paths*.  This means an
/// XP3 writer can resolve `output_root/path` first and fall back to
/// `unpack_root/path` for entries that were never expanded.
pub fn rebuild_assets_from_manifest(
    unpack_root: &Path,
    options: &RebuildOptions,
) -> Result<RebuildReport> {
    let manifest = read_manifest(unpack_root)
        .map_err(|err| Error::format(format!("cannot read xp3-meta.yaml: {err}")))?;
    if manifest.schema != XP3_META_SCHEMA {
        return Err(Error::unsupported(format!(
            "unsupported xp3-meta.yaml schema {:?}; expected {:?}",
            manifest.schema, XP3_META_SCHEMA
        )));
    }
    let global_key = global_emote_key(&manifest)?;
    fs::create_dir_all(&options.output_root)?;

    let mut text = BTreeMap::<String, (String, KirikiriTextTransformMeta)>::new();
    let mut tlg = BTreeMap::<String, TlgTransformMeta>::new();
    let mut pbd = BTreeMap::<String, PbdJsonTransformMeta>::new();
    let mut psb = BTreeMap::<String, PsbGroup>::new();
    let mut amv = BTreeMap::<String, Vec<AmvFrameTransformMeta>>::new();

    for entry in &manifest.entries {
        for transform in &entry.transforms {
            match transform {
                TransformMeta::TlgImage(meta) => {
                    tlg.insert(meta.source_asset_path.clone(), meta.clone());
                }
                TransformMeta::PbdJson(meta) => {
                    pbd.insert(meta.source_binary_path.clone(), meta.clone());
                }
                TransformMeta::PsbRootJson(meta) => {
                    merge_psb_group(&mut psb, &meta.source)?;
                    psb.get_mut(&meta.source.source_binary_path)
                        .unwrap()
                        .root_json = Some(meta.clone());
                }
                TransformMeta::PsbTexture(meta) => {
                    merge_psb_group(&mut psb, &meta.source)?;
                    psb.get_mut(&meta.source.source_binary_path)
                        .unwrap()
                        .textures
                        .push(meta.clone());
                }
                TransformMeta::PsbResourceBlob(meta) => {
                    merge_psb_group(&mut psb, &meta.source)?;
                    psb.get_mut(&meta.source.source_binary_path)
                        .unwrap()
                        .raw_blobs
                        .push(meta.clone());
                }
                TransformMeta::AmvFrame(meta) => {
                    amv.entry(meta.source_container_path.clone())
                        .or_default()
                        .push(meta.clone());
                }
                TransformMeta::KirikiriText(meta) => {
                    let source_path = entry
                        .identity
                        .logical_path
                        .as_ref()
                        .ok_or_else(|| {
                            Error::format(format!(
                                "entry[{}] has a reversible text transform but no logical_path",
                                entry.index
                            ))
                        })?
                        .clone();
                    let sidecar_path = entry
                        .identity
                        .output_path
                        .as_ref()
                        .ok_or_else(|| {
                            Error::format(format!(
                                "entry[{}] has a reversible text transform but no output_path",
                                entry.index
                            ))
                        })?
                        .clone();
                    if text
                        .insert(source_path.clone(), (sidecar_path, meta.clone()))
                        .is_some()
                    {
                        return Err(Error::format(format!(
                            "multiple text transforms claim manifest source path {source_path:?}"
                        )));
                    }
                }
            }
        }
    }

    // Prevent two transform families from claiming the same source path. This
    // would otherwise make overlay precedence depend on map iteration order.
    let mut claimed = BTreeSet::new();
    for path in text
        .keys()
        .chain(tlg.keys())
        .chain(pbd.keys())
        .chain(psb.keys())
        .chain(amv.keys())
    {
        if !claimed.insert(path.clone()) {
            return Err(Error::format(format!(
                "multiple encoder families claim manifest source path {path:?}"
            )));
        }
    }

    let mut report = RebuildReport::default();
    for (source_path, (sidecar_path, meta)) in text {
        if options.changed_only
            && sidecar_unchanged(unpack_root, &sidecar_path, meta.output_sha256.as_deref())?
        {
            continue;
        }
        let sidecar = unpack_root.join(safe_relative(&sidecar_path)?);
        let bytes = fs::read(&sidecar)?;
        let rebuilt = rebuild_kirikiri_text(&bytes, &meta)?;
        let output = write_overlay(&options.output_root, &source_path, &rebuilt)?;
        report.records.push(RebuildRecord {
            kind: "kirikiri-text".to_string(),
            source_path,
            output_path: output,
            detail: format!(
                "restored {} storage representation",
                meta.source_encoding_or_wrapper
            ),
        });
    }

    for (source_path, meta) in tlg {
        if options.changed_only
            && sidecar_unchanged(
                unpack_root,
                &meta.output_path,
                meta.output_sha256.as_deref(),
            )?
        {
            continue;
        }
        let bytes = rebuild_tlg_from_transform(unpack_root, &meta, options.allow_lossy)?;
        let output = write_overlay(&options.output_root, &source_path, &bytes)?;
        let detail = if meta.version.eq_ignore_ascii_case("TLG6") {
            "edited TLG6 pixels canonicalized to TLG5; TLG0 chunks restored from manifest"
        } else if meta.container.is_some() {
            "TLG5 re-encoded; TLG0 chunks restored from manifest"
        } else {
            "TLG5 re-encoded"
        };
        report.records.push(RebuildRecord {
            kind: "tlg".to_string(),
            source_path,
            output_path: output,
            detail: detail.to_string(),
        });
    }

    for (source_path, meta) in pbd {
        if options.changed_only
            && sidecar_unchanged(unpack_root, &meta.output_path, Some(&meta.output_sha256))?
        {
            continue;
        }
        let sidecar = unpack_root.join(safe_relative(&meta.output_path)?);
        let relative = safe_relative(&source_path)?;
        let output = options.output_root.join(relative);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        rebuild_pbd_from_json(&sidecar, &output)?;
        report.records.push(RebuildRecord {
            kind: "pbd".to_string(),
            source_path,
            output_path: output,
            detail: "PBD rebuilt from typed JSON with recorded variant/crypto framing".to_string(),
        });
    }

    for (source_path, group) in psb {
        let local_key = if let Some(value) = group.source.emote_key_hex.as_deref() {
            Some(parse_u32_hex(value)?)
        } else if let Some(value) = group
            .textures
            .iter()
            .find_map(|meta| meta.emote_key_hex.as_deref())
        {
            Some(parse_u32_hex(value)?)
        } else {
            global_key
        };
        let bytes = rebuild_psb_from_transforms(
            unpack_root,
            PsbRebuildInput {
                source: &group.source,
                root_json: group.root_json.as_ref(),
                textures: group.textures.iter().collect(),
                raw_blobs: group.raw_blobs.iter().collect(),
                emote_key: local_key,
                allow_lossy: options.allow_lossy,
            },
        )?;
        let output = write_overlay(&options.output_root, &source_path, &bytes)?;
        report.records.push(RebuildRecord {
            kind: "psb".to_string(),
            source_path,
            output_path: output,
            detail:
                "PSB semantic tree/resources rebuilt; original wrapper/encryption policy restored"
                    .to_string(),
        });
    }

    for (source_path, frames) in amv {
        let bytes =
            rebuild_amv_from_transforms(unpack_root, &source_path, &frames, options.allow_lossy)?;
        let output = write_overlay(&options.output_root, &source_path, &bytes)?;
        report.records.push(RebuildRecord {
            kind: "amv".to_string(),
            source_path,
            output_path: output,
            detail: format!(
                "re-encoded {} Mode B frame(s); untouched AMV packets preserved byte-for-byte",
                frames.len()
            ),
        });
    }

    Ok(report)
}
