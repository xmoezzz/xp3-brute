//! XP3 container round-trip writer.
//!
//! The writer is template-driven: `xp3-meta.yaml` retains exact decoded index
//! blocks and root-chunk locations, while this module patches only fields that
//! must change when payload bytes change (segment offsets/sizes and special
//! out-of-line offsets). Unknown/private chunks and child-chunk ordering are
//! never normalized.

use crate::encoder::{rebuild_assets_from_manifest, RebuildOptions};
use crate::hxv4_native::{Hxv4NativeBoundary, Hxv4NativeFilterState};
use crate::repeating_xor::parse_hex;
use crate::xp3::{Archive, XP3_MAGIC};
use crate::xp3_meta::{
    read_manifest, EntryMeta, Hxv4BoundaryMeta, Hxv4FilterStateMeta, IndexBlockMeta,
    RepeatingXorKeyMeta, RootChunkMeta, TransformMeta, Xp3Meta, XP3_META_SCHEMA,
};
use crate::X86Xp3FilterRuntime;
use crate::{Error, Result};
use base64::Engine as _;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const TAG_INFO: u32 = 0x6f66_6e69;
const TAG_SEGM: u32 = 0x6d67_6573;
const INDEX_METHOD_MASK: u8 = 0x07;
const INDEX_RAW: u8 = 0;
const INDEX_ZLIB: u8 = 1;
const INDEX_CONTINUE: u8 = 0x80;
const SEGM_METHOD_MASK: u32 = 0x07;
const SEGM_RAW: u32 = 0;
const SEGM_ZLIB: u32 = 1;

#[derive(Debug, Clone)]
pub struct Xp3PackOptions {
    /// Optional original XP3. When available, unchanged ordinary entries reuse
    /// their exact stored segment bytes (including the original zlib stream).
    pub source_archive: Option<PathBuf>,
    /// Rebuild TLG/PSB/PBD/text sidecars into an overlay before writing XP3.
    pub rebuild_assets: bool,
    /// Output directory used for rebuilt storage plaintext assets.
    pub rebuilt_root: Option<PathBuf>,
    /// Permit lossy sidecars such as JPEG to feed a reversible encoder.
    pub allow_lossy: bool,
    /// Keep every physical object at its old absolute offset while it still
    /// fits; growth only shifts the objects that can no longer fit there.
    pub preserve_physical_anchors: bool,
}

impl Default for Xp3PackOptions {
    fn default() -> Self {
        Self {
            source_archive: None,
            rebuild_assets: true,
            rebuilt_root: None,
            allow_lossy: false,
            preserve_physical_anchors: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Xp3PackEntryReport {
    pub entry_index: usize,
    pub source_path: Option<String>,
    pub mode: String,
    pub original_size: u64,
    pub archive_size: u64,
    pub segments: usize,
}

#[derive(Debug, Clone)]
pub struct Xp3PackReport {
    pub output: PathBuf,
    pub bytes_written: u64,
    pub reused_stored_entries: usize,
    pub reencoded_entries: usize,
    pub index_blocks: usize,
    pub root_chunks: usize,
    pub special_blobs: usize,
    /// `Some(true)` is returned only when the writer proved that a no-edit
    /// source-template round trip is byte-for-byte identical.
    pub byte_identical_to_source: Option<bool>,
    pub entries: Vec<Xp3PackEntryReport>,
}

/// Reconstruct and decrypt one entry from an archive written from `manifest`.
///
/// XP3 reconstruction first yields the storage stream after segment
/// decompression. Supported content filters are symmetric, so applying the
/// persisted filter state a second time returns source-format plaintext. This
/// is intentionally public for post-pack verification and never substitutes a
/// recomputed `adlr` for the manifest's original filter seed/state.
pub fn reconstruct_plaintext_entry_from_manifest(
    archive: &Archive,
    manifest: &Xp3Meta,
    entry_index: usize,
) -> Result<Vec<u8>> {
    let mut cache = ManifestFilterCache::default();
    reconstruct_plaintext_entry_with_cache(archive, manifest, entry_index, &mut cache)
}

#[derive(Default)]
pub(crate) struct ManifestFilterCache {
    x86: HashMap<String, X86Xp3FilterRuntime>,
}

pub(crate) fn reconstruct_plaintext_entry_with_cache(
    archive: &Archive,
    manifest: &Xp3Meta,
    entry_index: usize,
    cache: &mut ManifestFilterCache,
) -> Result<Vec<u8>> {
    let entry = manifest.entries.get(entry_index).ok_or_else(|| {
        Error::invalid(format!(
            "manifest entry index {entry_index} is out of range"
        ))
    })?;
    if entry.index != entry_index {
        return Err(Error::format(format!(
            "manifest entry order mismatch: slot={entry_index} entry.index={}",
            entry.index
        )));
    }
    let mut bytes = archive.reconstruct_entry(entry_index)?;
    apply_entry_filter_with_cache(manifest, entry, &mut bytes, cache)?;
    Ok(bytes)
}

#[derive(Debug, Clone)]
struct PackedSegment {
    flags: u32,
    original_size: u64,
    stored: Vec<u8>,
    original_offset: u64,
}

#[derive(Debug, Clone)]
struct PackedEntry {
    entry_index: usize,
    root_chunk_index: usize,
    source_path: Option<String>,
    info_original_size: u64,
    info_archive_size: u64,
    segments: Vec<PackedSegment>,
    reused: bool,
}

#[derive(Debug, Clone)]
struct PreservedPackedFile {
    root_chunk_index: usize,
    segments: Vec<PackedSegment>,
}

#[derive(Debug, Clone)]
struct SpecialBlob {
    root_chunk_index: usize,
    original_offset: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ObjectKey {
    EntrySegment(usize, usize),
    PreservedSegment(usize, usize),
    Special(usize),
    Index(usize),
}

#[derive(Debug, Clone)]
struct LayoutObject {
    key: ObjectKey,
    original_offset: u64,
    footprint: u64,
    /// Identical source segments can be referenced by several File roots at
    /// the same physical offset. Preserve that alias only while bytes remain
    /// identical; an edited alias receives independent storage.
    content_sha256: String,
    assigned_offset: u64,
}

#[derive(Debug)]
struct SourceTemplate {
    path: PathBuf,
    archive: Archive,
}

pub fn pack_xp3_from_manifest(
    unpack_root: &Path,
    output: &Path,
    options: &Xp3PackOptions,
) -> Result<Xp3PackReport> {
    let manifest = read_manifest(unpack_root)
        .map_err(|err| Error::format(format!("cannot read xp3-meta.yaml: {err}")))?;
    if manifest.schema != XP3_META_SCHEMA {
        return Err(Error::unsupported(format!(
            "unsupported xp3-meta.yaml schema {:?}; expected {:?}",
            manifest.schema, XP3_META_SCHEMA
        )));
    }
    validate_manifest_templates(&manifest)?;

    let rebuilt_root = options
        .rebuilt_root
        .clone()
        .unwrap_or_else(|| unpack_root.join(".xp3-rebuilt"));

    let source = open_source_template(&manifest, unpack_root, output, options)?;
    validate_source_template(source.as_ref(), &manifest)?;
    validate_retained_source_assets(unpack_root, &manifest)?;
    if options.preserve_physical_anchors && source.is_none() {
        return Err(Error::unsupported(
            "strict source-template XP3 packing requires the original archive so opaque physical bytes can be preserved and verified; provide --source-archive (or keep the manifest source_path valid), or explicitly use --compact-layout for a manifest-known semantic rebuild",
        ));
    }

    // A true no-edit round trip must not depend on codec determinism. If every
    // editable sidecar is byte-identical to what unpack emitted and the source
    // XP3 is present, there is nothing to rebuild: later stages reuse the exact
    // stored segment streams and the exact encoded index objects.
    let mut all_transforms_proven_unchanged = source.is_some();
    let mut has_transforms = false;
    for entry in &manifest.entries {
        if entry.transforms.is_empty() {
            continue;
        }
        has_transforms = true;
        if entry_sidecars_unchanged(unpack_root, entry)? != Some(true) {
            all_transforms_proven_unchanged = false;
            break;
        }
    }
    if options.rebuild_assets && has_transforms && !all_transforms_proven_unchanged {
        if rebuilt_root != unpack_root && rebuilt_root.is_dir() {
            fs::remove_dir_all(&rebuilt_root)?;
        }
        rebuild_assets_from_manifest(
            unpack_root,
            &RebuildOptions {
                output_root: rebuilt_root.clone(),
                allow_lossy: options.allow_lossy,
                changed_only: source.is_some(),
            },
        )?;
    }

    let root_binding = resolve_entry_root_bindings(&manifest)?;
    let mut packed_entries = Vec::with_capacity(manifest.entries.len());
    let mut reused_stored_entries = 0usize;
    let mut reencoded_entries = 0usize;

    for entry in &manifest.entries {
        let root_chunk_index = *root_binding.get(&entry.index).ok_or_else(|| {
            Error::format(format!("entry[{}] has no File root binding", entry.index))
        })?;
        let storage_path = entry_storage_path(entry)?;
        let sidecars_unchanged = entry_sidecars_unchanged(unpack_root, entry)?;
        let plaintext = read_entry_storage_plaintext(
            unpack_root,
            &rebuilt_root,
            entry,
            storage_path.as_deref(),
        )?;

        let plaintext_sha = plaintext.as_deref().map(crate::xp3_meta::sha256_hex);
        let unchanged = plaintext_sha
            .as_deref()
            .zip(entry.recovery.storage_plaintext_sha256.as_deref())
            .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(expected));

        let packed = if sidecars_unchanged == Some(true) && source.is_some() {
            // Nothing in the editable representation changed. Reuse the exact
            // source segment streams even if a codec rebuild would produce a
            // semantically equivalent but byte-different PSB/TLG/PBD stream.
            packed_entry_from_source(
                source.as_ref().unwrap(),
                entry,
                root_chunk_index,
                storage_path.clone(),
            )?
        } else if unchanged {
            if let Some(source) = source.as_ref() {
                packed_entry_from_source(source, entry, root_chunk_index, storage_path.clone())?
            } else {
                encode_entry_from_plaintext(
                    &manifest,
                    entry,
                    root_chunk_index,
                    storage_path.clone(),
                    plaintext.ok_or_else(|| {
                        Error::format(format!(
                            "entry[{}] has no extracted storage plaintext and no source archive",
                            entry.index
                        ))
                    })?,
                )?
            }
        } else if let Some(plaintext) = plaintext {
            encode_entry_from_plaintext(
                &manifest,
                entry,
                root_chunk_index,
                storage_path.clone(),
                plaintext,
            )?
        } else if !entry.transforms.is_empty() {
            return Err(Error::format(format!(
                "entry[{}] has editable transform sidecars but no rebuilt storage asset; refusing to reuse the old archive and silently discard edits (remove --no-rebuild-assets or provide --rebuilt-dir)",
                entry.index
            )));
        } else if let Some(source) = source.as_ref() {
            // Unresolved/reconstruction-failed files that never had editable
            // transforms can safely keep their original stored bytes.
            packed_entry_from_source(source, entry, root_chunk_index, storage_path.clone())?
        } else {
            return Err(Error::format(format!(
                "entry[{}] has no storage plaintext and cannot be preserved because the original archive is unavailable",
                entry.index
            )));
        };

        if packed.reused {
            reused_stored_entries += 1;
        } else {
            reencoded_entries += 1;
        }
        packed_entries.push(packed);
    }

    let index_templates = decode_index_templates(&manifest)?;
    let preserved_files = load_preserved_files(&manifest, &index_templates, source.as_ref())?;
    let specials = load_special_blobs(&manifest, source.as_ref())?;

    let mut objects =
        build_layout_objects(&manifest, &packed_entries, &preserved_files, &specials)?;

    // Index compression size can change when physical offsets change. Keep an
    // index object's old footprint as reserved slack and grow it monotonically
    // only when the new encoded block no longer fits. This preserves original
    // anchors whenever possible and guarantees convergence without normalizing
    // the archive into a new physical ordering.
    let header_end = manifest
        .archive
        .xp3_offset
        .checked_add(XP3_MAGIC.len() as u64 + 8)
        .ok_or_else(|| Error::format("XP3 header offset overflow"))?;

    for _ in 0..32 {
        assign_layout(&mut objects, header_end, options.preserve_physical_anchors)?;
        let offsets = object_offsets(&objects);
        let decoded = patch_index_templates(
            &manifest,
            &index_templates,
            &packed_entries,
            &preserved_files,
            &specials,
            &offsets,
        )?;
        let index_payloads = encode_index_payloads(&manifest, &decoded)?;

        let mut changed = false;
        for (index, payload) in index_payloads.iter().enumerate() {
            let key = ObjectKey::Index(index);
            let object = objects
                .iter_mut()
                .find(|object| object.key == key)
                .ok_or_else(|| {
                    Error::format(format!("missing layout object for index block {index}"))
                })?;
            let total = index_object_actual_len(&manifest.index_blocks[index], payload.len())?;
            let wanted = if options.preserve_physical_anchors {
                object.footprint.max(total)
            } else {
                total
            };
            if wanted != object.footprint {
                object.footprint = wanted;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    assign_layout(&mut objects, header_end, options.preserve_physical_anchors)?;
    let offsets = object_offsets(&objects);
    let final_decoded = patch_index_templates(
        &manifest,
        &index_templates,
        &packed_entries,
        &preserved_files,
        &specials,
        &offsets,
    )?;
    let final_index_payloads = encode_index_payloads(&manifest, &final_decoded)?;

    let index_blocks = build_index_objects(
        &manifest,
        &final_index_payloads,
        &final_decoded,
        &index_templates,
        &offsets,
        source.as_ref(),
    )?;
    validate_opaque_source_safety(
        &manifest,
        source.as_ref(),
        &objects,
        &packed_entries,
        &preserved_files,
        &specials,
        &index_blocks,
    )?;
    write_container(
        &manifest,
        output,
        source.as_ref(),
        &objects,
        &packed_entries,
        &preserved_files,
        &specials,
        &index_blocks,
        options.preserve_physical_anchors,
    )?;

    // Parse what we wrote. This catches incorrect first/continuation pointers,
    // malformed patched index chunks and segment range errors immediately.
    let check = Archive::open(output)?;
    if check.entries.len() != manifest.entries.len() {
        return Err(Error::format(format!(
            "writer self-check entry count mismatch: expected {}, got {}",
            manifest.entries.len(),
            check.entries.len()
        )));
    }
    if check.index_blocks.len() != manifest.index_blocks.len() {
        return Err(Error::format(format!(
            "writer self-check index block count mismatch: expected {}, got {}",
            manifest.index_blocks.len(),
            check.index_blocks.len()
        )));
    }

    let byte_identical_to_source = if reencoded_entries == 0 && options.preserve_physical_anchors {
        if let Some(source) = source.as_ref() {
            let identical = files_equal(&source.path, output)?;
            if !identical {
                return Err(Error::format(
                    "no-edit/source-reuse pack was expected to be byte-for-byte identical, but output differs from the validated source archive",
                ));
            }
            Some(true)
        } else {
            None
        }
    } else {
        None
    };

    let bytes_written = fs::metadata(output)?.len();
    let entries = packed_entries
        .iter()
        .map(|entry| Xp3PackEntryReport {
            entry_index: entry.entry_index,
            source_path: entry.source_path.clone(),
            mode: if entry.reused {
                "stored-byte-reuse".to_string()
            } else {
                "reencoded".to_string()
            },
            original_size: entry.info_original_size,
            archive_size: entry.info_archive_size,
            segments: entry.segments.len(),
        })
        .collect();

    Ok(Xp3PackReport {
        output: output.to_path_buf(),
        bytes_written,
        reused_stored_entries,
        reencoded_entries,
        index_blocks: manifest.index_blocks.len(),
        root_chunks: manifest.root_chunks.len(),
        special_blobs: specials.len(),
        byte_identical_to_source,
        entries,
    })
}

fn validate_manifest_templates(manifest: &Xp3Meta) -> Result<()> {
    if manifest.index_blocks.is_empty() {
        return Err(Error::format("xp3-meta.yaml has no index block templates"));
    }
    if manifest.entries.len() != manifest.archive.entry_count {
        return Err(Error::format(format!(
            "manifest entry count mismatch: archive.entry_count={} entries={}",
            manifest.archive.entry_count,
            manifest.entries.len()
        )));
    }
    for (expected, block) in manifest.index_blocks.iter().enumerate() {
        if block.index != expected {
            return Err(Error::format(format!(
                "index block order mismatch: slot={expected} meta.index={}",
                block.index
            )));
        }
    }

    Ok(())
}

fn open_source_template(
    manifest: &Xp3Meta,
    unpack_root: &Path,
    output: &Path,
    options: &Xp3PackOptions,
) -> Result<Option<SourceTemplate>> {
    let mut candidates = Vec::<PathBuf>::new();
    if let Some(path) = options.source_archive.as_ref() {
        candidates.push(path.clone());
    }
    if let Some(path) = manifest.archive.source_path.as_ref() {
        candidates.push(PathBuf::from(path));
    }
    if let Some(parent) = unpack_root.parent() {
        candidates.push(parent.join(&manifest.archive.source_file));
    }
    for path in candidates {
        let same_as_output = path == output
            || (path.is_file()
                && output.is_file()
                && fs::canonicalize(&path).ok() == fs::canonicalize(output).ok());
        if same_as_output || !path.is_file() {
            continue;
        }
        let archive = Archive::open(&path)?;
        return Ok(Some(SourceTemplate { path, archive }));
    }
    Ok(None)
}

fn validate_source_template(source: Option<&SourceTemplate>, manifest: &Xp3Meta) -> Result<()> {
    let Some(source) = source else {
        if manifest.archive.xp3_offset != 0 {
            return Err(Error::format(format!(
                "archive is embedded at xp3_offset=0x{:x}; --source-archive is required to preserve the executable/prefix bytes",
                manifest.archive.xp3_offset
            )));
        }
        return Ok(());
    };
    if source.archive.xp3_offset != manifest.archive.xp3_offset {
        return Err(Error::format(format!(
            "source archive XP3 offset mismatch: manifest=0x{:x} source=0x{:x}",
            manifest.archive.xp3_offset, source.archive.xp3_offset
        )));
    }
    if source.archive.physical_size() != manifest.archive.physical_size {
        return Err(Error::format(format!(
            "source archive physical size mismatch: manifest={} source={}",
            manifest.archive.physical_size,
            source.archive.physical_size()
        )));
    }
    if source.archive.index_blocks.len() != manifest.index_blocks.len() {
        return Err(Error::format(format!(
            "source archive index block count mismatch: manifest={} source={}",
            manifest.index_blocks.len(),
            source.archive.index_blocks.len()
        )));
    }
    for (index, (source_block, meta_block)) in source
        .archive
        .index_blocks
        .iter()
        .zip(manifest.index_blocks.iter())
        .enumerate()
    {
        if source_block.flags != meta_block.flags
            || source_block.physical_offset != meta_block.physical_offset
            || source_block.stored_size != meta_block.stored_size
            || source_block.original_size != meta_block.original_size
            || !crate::xp3_meta::sha256_hex(&source_block.decoded)
                .eq_ignore_ascii_case(&meta_block.decoded_sha256)
        {
            return Err(Error::format(format!(
                "source archive index[{index}] does not match xp3-meta.yaml template"
            )));
        }
    }
    if source.archive.root_chunks.len() != manifest.root_chunks.len() {
        return Err(Error::format(format!(
            "source archive root chunk count mismatch: manifest={} source={}",
            manifest.root_chunks.len(),
            source.archive.root_chunks.len()
        )));
    }
    if source.archive.entries.len() != manifest.entries.len() {
        return Err(Error::format(format!(
            "source archive entry count mismatch: manifest={} source={}",
            manifest.entries.len(),
            source.archive.entries.len()
        )));
    }
    for entry in &manifest.entries {
        let source_entry = source.archive.entries.get(entry.index).ok_or_else(|| {
            Error::format(format!("source archive is missing entry[{}]", entry.index))
        })?;
        if source_entry.name != entry.original.info_name
            || source_entry.info_name_length != entry.original.info_name_length
            || source_entry.segments.len() != entry.original.segments.len()
        {
            return Err(Error::format(format!(
                "source archive entry[{}] does not match manifest identity/layout",
                entry.index
            )));
        }
    }
    Ok(())
}

fn validate_retained_source_assets(unpack_root: &Path, manifest: &Xp3Meta) -> Result<()> {
    let mut expected = BTreeMap::<PathBuf, (usize, String)>::new();
    let mut register = |path: &str, size: usize, sha256: &str| -> Result<()> {
        let relative = safe_relative(path)?;
        match expected.get(&relative) {
            Some((old_size, old_sha))
                if *old_size != size || !old_sha.eq_ignore_ascii_case(sha256) =>
            {
                return Err(Error::format(format!(
                    "manifest transforms disagree on retained source asset {:?}",
                    relative
                )));
            }
            Some(_) => return Ok(()),
            None => {}
        }
        expected.insert(relative, (size, sha256.to_string()));
        Ok(())
    };

    for entry in &manifest.entries {
        for transform in &entry.transforms {
            match transform {
                TransformMeta::TlgImage(meta) => {
                    // TLG conversion historically replaces the source path, so
                    // absence is expected. If a raw TLG is present, however, it
                    // must still be the recorded source rather than an ambiguous
                    // second edit that would otherwise be silently ignored.
                    register(
                        &meta.source_asset_path,
                        meta.source_size,
                        &meta.source_sha256,
                    )?;
                }
                TransformMeta::PsbRootJson(meta) if meta.source_binary_retained => {
                    register(
                        &meta.source.source_binary_path,
                        meta.source.source_size,
                        &meta.source.source_sha256,
                    )?;
                }
                TransformMeta::PsbTexture(meta) if meta.source_binary_retained => {
                    register(
                        &meta.source.source_binary_path,
                        meta.source.source_size,
                        &meta.source.source_sha256,
                    )?;
                }
                TransformMeta::PsbResourceBlob(meta) if meta.source_binary_retained => {
                    register(
                        &meta.source.source_binary_path,
                        meta.source.source_size,
                        &meta.source.source_sha256,
                    )?;
                }
                TransformMeta::PbdJson(meta) => {
                    register(
                        &meta.source_binary_path,
                        meta.source_size,
                        &meta.source_sha256,
                    )?;
                }
                TransformMeta::AmvFrame(meta) if meta.source_container_retained => {
                    register(
                        &meta.source_container_path,
                        meta.source_size,
                        &meta.source_sha256,
                    )?;
                }
                _ => {}
            }
        }
    }

    for (relative, (expected_size, expected_sha)) in expected {
        let path = unpack_root.join(&relative);
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path)?;
        if bytes.len() != expected_size
            || !crate::xp3_meta::sha256_hex(&bytes).eq_ignore_ascii_case(&expected_sha)
        {
            return Err(Error::unsupported(format!(
                "retained source asset {} was modified while editable transform sidecars also exist; refusing to guess which representation is authoritative (edit the recorded sidecars, or re-unpack/rebuild the transform set)",
                path.display()
            )));
        }
    }
    Ok(())
}

fn decode_index_templates(manifest: &Xp3Meta) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(manifest.index_blocks.len());
    for block in &manifest.index_blocks {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(block.decoded_base64.as_bytes())
            .map_err(|err| {
                Error::format(format!(
                    "index[{}] base64 decode failed: {err}",
                    block.index
                ))
            })?;
        if crate::xp3_meta::sha256_hex(&decoded) != block.decoded_sha256 {
            return Err(Error::format(format!(
                "index[{}] decoded template SHA-256 mismatch",
                block.index
            )));
        }
        let expected = usize::try_from(block.original_size).map_err(|_| {
            Error::format(format!(
                "index[{}] original_size does not fit usize",
                block.index
            ))
        })?;
        if decoded.len() != expected {
            return Err(Error::format(format!(
                "index[{}] decoded template size mismatch: meta={} actual={}",
                block.index,
                block.original_size,
                decoded.len()
            )));
        }
        out.push(decoded);
    }
    Ok(out)
}

fn resolve_entry_root_bindings(manifest: &Xp3Meta) -> Result<HashMap<usize, usize>> {
    let mut result = HashMap::new();
    let ordinary_file_roots = manifest
        .root_chunks
        .iter()
        .filter(|root| root.kind == "File")
        .map(|root| root.index)
        .collect::<Vec<_>>();
    for entry in &manifest.entries {
        let root = match entry.original.root_chunk_index {
            Some(index) => index,
            None => *ordinary_file_roots.get(entry.index).ok_or_else(|| {
                Error::format(format!(
                    "old manifest cannot map entry[{}] to a File root; re-run unpack with the current version",
                    entry.index
                ))
            })?,
        };
        let root_meta = manifest.root_chunks.get(root).ok_or_else(|| {
            Error::format(format!(
                "entry[{}] root_chunk_index={} is out of range",
                entry.index, root
            ))
        })?;
        if root_meta.kind != "File" {
            return Err(Error::format(format!(
                "entry[{}] root_chunk_index={} points to {:?}, not File",
                entry.index, root, root_meta.kind
            )));
        }
        if result.insert(entry.index, root).is_some() {
            return Err(Error::format(format!(
                "duplicate entry root binding for entry[{}]",
                entry.index
            )));
        }
    }
    Ok(result)
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
    let mut source: Option<String> = None;
    let mut claim = |candidate: &str| -> Result<()> {
        match source.as_deref() {
            Some(existing) if existing != candidate => Err(Error::format(format!(
                "entry[{}] transforms disagree on source storage path: {:?} vs {:?}",
                entry.index, existing, candidate
            ))),
            Some(_) => Ok(()),
            None => {
                source = Some(candidate.to_string());
                Ok(())
            }
        }
    };
    for transform in &entry.transforms {
        match transform {
            TransformMeta::KirikiriText(_) => {
                if let Some(path) = entry.identity.logical_path.as_deref() {
                    claim(path)?;
                }
            }
            TransformMeta::TlgImage(meta) => claim(&meta.source_asset_path)?,
            TransformMeta::PsbRootJson(meta) => claim(&meta.source.source_binary_path)?,
            TransformMeta::PsbTexture(meta) => claim(&meta.source.source_binary_path)?,
            TransformMeta::PsbResourceBlob(meta) => claim(&meta.source.source_binary_path)?,
            TransformMeta::PbdJson(meta) => claim(&meta.source_binary_path)?,
            TransformMeta::AmvFrame(meta) => claim(&meta.source_container_path)?,
        }
    }
    if source.is_none() {
        source = entry.identity.output_path.clone();
    }
    Ok(source)
}

fn entry_sidecars_unchanged(unpack_root: &Path, entry: &EntryMeta) -> Result<Option<bool>> {
    if entry.transforms.is_empty() {
        return Ok(None);
    }

    let check_file = |path: &str, expected: Option<&str>| -> Result<Option<bool>> {
        let Some(expected) = expected else {
            return Ok(None);
        };
        let path = unpack_root.join(safe_relative(path)?);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Some(false)),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(
            crate::xp3_meta::sha256_hex(&bytes).eq_ignore_ascii_case(expected),
        ))
    };

    let mut saw = false;
    for transform in &entry.transforms {
        let result = match transform {
            TransformMeta::KirikiriText(meta) => {
                let Some(path) = entry.identity.output_path.as_deref() else {
                    return Ok(Some(false));
                };
                check_file(path, meta.output_sha256.as_deref())?
            }
            TransformMeta::TlgImage(meta) => {
                check_file(&meta.output_path, meta.output_sha256.as_deref())?
            }
            TransformMeta::PsbRootJson(meta) => {
                check_file(&meta.output_path, meta.output_sha256.as_deref())?
            }
            TransformMeta::PsbTexture(meta) => {
                check_file(&meta.output_path, meta.output_sha256.as_deref())?
            }
            TransformMeta::PsbResourceBlob(meta) => {
                check_file(&meta.output_path, Some(meta.blob_sha256.as_str()))?
            }
            TransformMeta::PbdJson(meta) => {
                check_file(&meta.output_path, Some(meta.output_sha256.as_str()))?
            }
            TransformMeta::AmvFrame(meta) => {
                check_file(&meta.output_path, meta.output_sha256.as_deref())?
            }
        };
        match result {
            Some(true) => saw = true,
            Some(false) => return Ok(Some(false)),
            None => return Ok(None),
        }
    }
    Ok(saw.then_some(true))
}

fn read_entry_storage_plaintext(
    unpack_root: &Path,
    rebuilt_root: &Path,
    entry: &EntryMeta,
    storage_path: Option<&str>,
) -> Result<Option<Vec<u8>>> {
    let Some(storage_path) = storage_path else {
        return Ok(None);
    };
    let relative = safe_relative(storage_path)?;
    let overlay = rebuilt_root.join(&relative);
    if overlay.is_file() {
        return Ok(Some(fs::read(overlay)?));
    }

    // A transform claims an original storage path that may no longer physically
    // exist in the extraction tree (TLG->PNG is intentionally replacement-style).
    // In that case do not accidentally feed the PNG as if it were TLG bytes.
    if !entry.transforms.is_empty() {
        return Ok(None);
    }

    if let Some(path) = entry.identity.output_path.as_deref() {
        let output = unpack_root.join(safe_relative(path)?);
        if output.is_file() {
            return Ok(Some(fs::read(output)?));
        }
    }
    Ok(None)
}

fn packed_entry_from_source(
    source: &SourceTemplate,
    entry: &EntryMeta,
    root_chunk_index: usize,
    source_path: Option<String>,
) -> Result<PackedEntry> {
    let source_entry =
        source.archive.entries.get(entry.index).ok_or_else(|| {
            Error::format(format!("source archive missing entry[{}]", entry.index))
        })?;
    let concatenated = source.archive.stored_entry_bytes(entry.index)?;
    let mut at = 0usize;
    let mut segments = Vec::with_capacity(source_entry.segments.len());
    for (segment_index, segment) in source_entry.segments.iter().enumerate() {
        let size = usize::try_from(segment.archive_size).map_err(|_| {
            Error::format(format!(
                "entry[{}] segment[{segment_index}] stored size overflow",
                entry.index
            ))
        })?;
        let end = at
            .checked_add(size)
            .ok_or_else(|| Error::format("stored segment split overflow"))?;
        let stored = concatenated
            .get(at..end)
            .ok_or_else(|| {
                Error::format(format!(
                    "source entry[{}] stored segment table is inconsistent",
                    entry.index
                ))
            })?
            .to_vec();
        segments.push(PackedSegment {
            flags: segment.flags,
            original_size: segment.original_size,
            stored,
            original_offset: segment.archive_offset,
        });
        at = end;
    }
    if at != concatenated.len() {
        return Err(Error::format(format!(
            "source entry[{}] stored bytes contain an unassigned tail",
            entry.index
        )));
    }
    Ok(PackedEntry {
        entry_index: entry.index,
        root_chunk_index,
        source_path,
        info_original_size: source_entry.original_size,
        info_archive_size: source_entry.archive_size,
        segments,
        reused: true,
    })
}

fn encode_entry_from_plaintext(
    manifest: &Xp3Meta,
    entry: &EntryMeta,
    root_chunk_index: usize,
    source_path: Option<String>,
    mut plaintext: Vec<u8>,
) -> Result<PackedEntry> {
    // The uncommon historical entry-level-zlib fallback has different `info`
    // and `segm` logical sizes. Preserve it exactly from a source archive, but
    // do not fabricate a new interpretation when edited.
    let segment_logical_total = entry
        .original
        .segments
        .iter()
        .try_fold(0u64, |sum, segment| sum.checked_add(segment.original_size))
        .ok_or_else(|| Error::format("segment logical-size sum overflow"))?;
    if segment_logical_total != entry.original.original_size {
        return Err(Error::unsupported(format!(
            "entry[{}] uses non-standard entry-level storage sizing (info.original={} segm.original.sum={}); edited rebuild requires the original archive for byte reuse",
            entry.index, entry.original.original_size, segment_logical_total
        )));
    }

    apply_entry_filter(manifest, entry, &mut plaintext)?;
    let logical_sizes = repartition_logical_sizes(&entry.original.segments, plaintext.len())?;

    let mut segments = Vec::with_capacity(entry.original.segments.len());
    let mut at = 0usize;
    for (segment_index, (original, logical_size)) in entry
        .original
        .segments
        .iter()
        .zip(logical_sizes.into_iter())
        .enumerate()
    {
        let end = at
            .checked_add(logical_size)
            .ok_or_else(|| Error::format("segment plaintext range overflow"))?;
        let chunk = plaintext.get(at..end).ok_or_else(|| {
            Error::format(format!(
                "entry[{}] segment[{segment_index}] plaintext range invalid",
                entry.index
            ))
        })?;
        let stored = match original.flags & SEGM_METHOD_MASK {
            SEGM_RAW => chunk.to_vec(),
            SEGM_ZLIB => zlib_encode(chunk)?,
            method => {
                return Err(Error::unsupported(format!(
                    "entry[{}] segment[{segment_index}] encoding method {method} is not writable",
                    entry.index
                )))
            }
        };
        segments.push(PackedSegment {
            flags: original.flags,
            original_size: chunk.len() as u64,
            stored,
            original_offset: original.archive_offset,
        });
        at = end;
    }
    if at != plaintext.len() {
        return Err(Error::format(format!(
            "entry[{}] repartition left {} bytes unassigned",
            entry.index,
            plaintext.len() - at
        )));
    }
    let info_archive_size = segments
        .iter()
        .try_fold(0u64, |sum, segment| {
            sum.checked_add(segment.stored.len() as u64)
        })
        .ok_or_else(|| Error::format("entry archive-size sum overflow"))?;

    Ok(PackedEntry {
        entry_index: entry.index,
        root_chunk_index,
        source_path,
        info_original_size: plaintext.len() as u64,
        info_archive_size,
        segments,
        reused: false,
    })
}

fn repartition_logical_sizes(
    original: &[crate::xp3_meta::SegmentMeta],
    new_len: usize,
) -> Result<Vec<usize>> {
    if original.is_empty() {
        return Err(Error::format("entry has no XP3 segments"));
    }
    if original.len() == 1 {
        return Ok(vec![new_len]);
    }
    let old_total = original
        .iter()
        .try_fold(0u64, |sum, segment| sum.checked_add(segment.original_size))
        .ok_or_else(|| Error::format("original segment-size sum overflow"))?;
    if old_total == new_len as u64 {
        return original
            .iter()
            .map(|segment| {
                usize::try_from(segment.original_size)
                    .map_err(|_| Error::format("segment original_size does not fit usize"))
            })
            .collect();
    }

    // Keep the original logical boundaries for as long as the edited stream
    // permits. Growth is absorbed by the last segment; shrinkage only collapses
    // boundaries after the new EOF. This changes fewer segm fields than a
    // proportional repartition and therefore follows the source template more
    // closely while preserving descriptor count/order/flags.
    let mut remaining = new_len;
    let mut out = Vec::with_capacity(original.len());
    for (index, segment) in original.iter().enumerate() {
        if index + 1 == original.len() {
            out.push(remaining);
            break;
        }
        let old = usize::try_from(segment.original_size)
            .map_err(|_| Error::format("segment original_size does not fit usize"))?;
        let take = old.min(remaining);
        out.push(take);
        remaining -= take;
    }
    Ok(out)
}

fn complete_key(meta: &RepeatingXorKeyMeta) -> Result<Vec<u8>> {
    let text = meta.complete_key_hex.as_ref().ok_or_else(|| {
        Error::unsupported(format!(
            "repeating-XOR period {} is incomplete in xp3-meta.yaml",
            meta.period
        ))
    })?;
    let key = parse_hex(text)?;
    if key.len() != meta.period || key.is_empty() {
        return Err(Error::format(format!(
            "repeating-XOR key length mismatch: period={} key_bytes={}",
            meta.period,
            key.len()
        )));
    }
    Ok(key)
}

fn apply_xor(data: &mut [u8], key: &[u8]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn global_repeating_key(manifest: &Xp3Meta) -> Result<Option<Vec<u8>>> {
    for key in &manifest.keys {
        if key.kind == "archive-global-repeating-xor" {
            if let Some(meta) = key.repeating_xor.as_ref() {
                return Ok(Some(complete_key(meta)?));
            }
        }
    }
    Ok(None)
}

fn per_entry_repeating_key(manifest: &Xp3Meta, entry: &EntryMeta) -> Result<Option<Vec<u8>>> {
    if let Some(recovery) = entry.recovery.repeating_xor.as_ref() {
        return Ok(Some(complete_key(&recovery.key)?));
    }
    for key in &manifest.keys {
        if key.kind == "per-entry-repeating-xor" && key.entry_index == Some(entry.index) {
            if let Some(meta) = key.repeating_xor.as_ref() {
                return Ok(Some(complete_key(meta)?));
            }
        }
    }
    Ok(None)
}

fn apply_entry_filter(manifest: &Xp3Meta, entry: &EntryMeta, data: &mut [u8]) -> Result<()> {
    let mut cache = ManifestFilterCache::default();
    apply_entry_filter_with_cache(manifest, entry, data, &mut cache)
}

fn apply_entry_filter_with_cache(
    manifest: &Xp3Meta,
    entry: &EntryMeta,
    data: &mut [u8],
    cache: &mut ManifestFilterCache,
) -> Result<()> {
    // A no-name-bootstrap HXV4 inventory deliberately leaves recovery.status
    // as `pending`: no logical file was emitted, so there was no ordinary
    // recovery attempt to label.  The authenticated Special record still
    // carries a complete native filter state bound to the physical entry.
    // That physical binding is sufficient (and required) for post-pack
    // decrypt verification and for a future rebuild addressed by identity.
    if entry.recovery.status == "pending" && hxv4_filter_state_exists(manifest, entry.index) {
        let state = hxv4_filter_state_for_entry(manifest, entry.index)?;
        state.apply(0, data);
        return Ok(());
    }
    match entry.recovery.status.as_str() {
        "plain" => Ok(()),
        "global-repeating-xor" => {
            let key = global_repeating_key(manifest)?.ok_or_else(|| {
                Error::unsupported("archive-global repeating-XOR key is missing from xp3-meta.yaml")
            })?;
            apply_xor(data, &key);
            Ok(())
        }
        "per-file-repeating-xor" | "recovered" => {
            let key = per_entry_repeating_key(manifest, entry)?.ok_or_else(|| {
                Error::unsupported(format!(
                    "entry[{}] was recovered with a per-file filter but no complete persisted key is available; unchanged data can only be packed with --source-archive",
                    entry.index
                ))
            })?;
            apply_xor(data, &key);
            Ok(())
        }
        "hxv4-native" => {
            let state = hxv4_filter_state_for_entry(manifest, entry.index)?;
            state.apply(0, data);
            Ok(())
        }
        "x86-emulated-filter" => apply_x86_filter(manifest, entry, data, cache),
        "hxv4-effective-fallback" => Err(Error::unsupported(format!(
            "entry[{}] used heuristic HXV4 effective-filter recovery without a complete native state; edited data cannot be re-encrypted safely",
            entry.index
        ))),
        "unresolved" | "reconstruct-failed" | "hxv4-native-mismatch" => Err(Error::unsupported(format!(
            "entry[{}] recovery status {:?} has no reversible content filter; use the original archive to preserve it byte-for-byte",
            entry.index, entry.recovery.status
        ))),
        other => {
            if let Some(key) = per_entry_repeating_key(manifest, entry)? {
                apply_xor(data, &key);
                Ok(())
            } else {
                Err(Error::unsupported(format!(
                    "entry[{}] recovery status {:?} has no known encoder/filter inverse",
                    entry.index, other
                )))
            }
        }
    }
}

fn apply_x86_filter(
    manifest: &Xp3Meta,
    entry: &EntryMeta,
    data: &mut [u8],
    cache: &mut ManifestFilterCache,
) -> Result<()> {
    let recovery = entry.recovery.x86_filter.as_ref().ok_or_else(|| {
        Error::unsupported(format!(
            "entry[{}] used an emulated PE32 filter but xp3-meta.yaml has no reversible filter state",
            entry.index
        ))
    })?;
    let module = manifest
        .x86_filter_modules
        .iter()
        .find(|module| module.sha256.eq_ignore_ascii_case(&recovery.module_sha256))
        .ok_or_else(|| {
            Error::unsupported(format!(
                "entry[{}] references missing PE32 filter module {}",
                entry.index, recovery.module_sha256
            ))
        })?;
    if module.guest_profile != "ja-JP-windows"
        || !module.lcid_hex.eq_ignore_ascii_case("0x0411")
        || module.ansi_code_page != 932
    {
        return Err(Error::unsupported(format!(
            "entry[{}] PE32 filter guest profile is not the supported ja-JP Windows profile",
            entry.index
        )));
    }
    let callback = parse_hex_u32(&recovery.callback_va_hex)?;
    let file_hash = parse_hex_u32(&recovery.file_hash_hex)?;
    if let Some(original) = entry.original.original_filter_hash_hex.as_deref() {
        let original = parse_hex_u32(original)?;
        if original != file_hash {
            return Err(Error::format(format!(
                "entry[{}] PE32 filter seed changed: original=0x{original:08x} retained=0x{file_hash:08x}",
                entry.index
            )));
        }
    }

    if !cache.x86.contains_key(&module.sha256) {
        let module_bytes = base64::engine::general_purpose::STANDARD
            .decode(&module.pe32_base64)
            .map_err(|err| Error::format(format!("invalid embedded PE32 filter base64: {err}")))?;
        let actual_sha = crate::xp3_meta::sha256_hex(&module_bytes);
        if !actual_sha.eq_ignore_ascii_case(&module.sha256) {
            return Err(Error::format(format!(
                "embedded PE32 filter integrity mismatch: manifest={} actual={actual_sha}",
                module.sha256
            )));
        }
        cache.x86.insert(
            module.sha256.clone(),
            X86Xp3FilterRuntime::from_bytes(
                format!("embedded/{}", module.file_name),
                module_bytes,
                false,
            )?,
        );
    }
    let runtime = cache
        .x86
        .get_mut(&module.sha256)
        .ok_or_else(|| Error::format("embedded PE32 filter cache lost initialized module"))?;
    if runtime.callback_va() != callback {
        return Err(Error::format(format!(
            "entry[{}] PE32 filter callback changed: manifest=0x{callback:08x} loaded=0x{:08x}",
            entry.index,
            runtime.callback_va()
        )));
    }
    runtime.apply(0, file_hash, data)
}

fn hxv4_filter_state_exists(manifest: &Xp3Meta, entry_index: usize) -> bool {
    manifest.hxv4.as_ref().is_some_and(|hx| {
        hx.records.iter().any(|record| {
            record.physical_entry_index == Some(entry_index) && record.filter_state.is_some()
        })
    })
}

fn hxv4_filter_state_for_entry(
    manifest: &Xp3Meta,
    entry_index: usize,
) -> Result<Hxv4NativeFilterState> {
    let hx = manifest.hxv4.as_ref().ok_or_else(|| {
        Error::format(format!(
            "entry[{entry_index}] is hxv4-native but manifest.hxv4 is missing"
        ))
    })?;
    let record = hx
        .records
        .iter()
        .find(|record| record.physical_entry_index == Some(entry_index))
        .ok_or_else(|| {
            Error::format(format!(
                "entry[{entry_index}] has no HXV4 Special record linkage"
            ))
        })?;
    let state = record.filter_state.as_ref().ok_or_else(|| {
        Error::format(format!(
            "entry[{entry_index}] has no persisted HXV4 filter state"
        ))
    })?;
    hx_state_from_meta(
        record.entry_key_hex.as_str(),
        record.local_flag_hex.as_str(),
        state,
    )
}

fn hx_state_from_meta(
    entry_key: &str,
    local_flag: &str,
    meta: &Hxv4FilterStateMeta,
) -> Result<Hxv4NativeFilterState> {
    let prefix = parse_hex(&meta.prefix_xor_hex)?;
    let prefix_xor: [u8; 16] = prefix.try_into().map_err(|value: Vec<u8>| {
        Error::format(format!(
            "HXV4 prefix_xor has {} bytes, expected 16",
            value.len()
        ))
    })?;
    Ok(Hxv4NativeFilterState {
        entry_key: parse_hex_u64(entry_key)?,
        local_flag: parse_hex_u16(local_flag)?,
        open_flag: meta.open_flag,
        split: meta.split,
        prefix_xor,
        left_drip: parse_hex_u64(&meta.left_drip_hex)?,
        right_drip: parse_hex_u64(&meta.right_drip_hex)?,
        left: hx_boundary_from_meta(&meta.left)?,
        right: hx_boundary_from_meta(&meta.right)?,
    })
}

fn hx_boundary_from_meta(meta: &Hxv4BoundaryMeta) -> Result<Hxv4NativeBoundary> {
    Ok(Hxv4NativeBoundary {
        position0: meta.position0,
        position1: meta.position1,
        xor_byte: parse_hex_u8(&meta.xor_byte_hex)?,
        correction0: parse_hex_u8(&meta.correction0_hex)?,
        correction1: parse_hex_u8(&meta.correction1_hex)?,
    })
}

fn trim_hex(value: &str) -> &str {
    value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim())
}

fn parse_hex_u8(value: &str) -> Result<u8> {
    u8::from_str_radix(trim_hex(value), 16)
        .map_err(|_| Error::format(format!("invalid hex u8 {value:?}")))
}
fn parse_hex_u16(value: &str) -> Result<u16> {
    u16::from_str_radix(trim_hex(value), 16)
        .map_err(|_| Error::format(format!("invalid hex u16 {value:?}")))
}
fn parse_hex_u32(value: &str) -> Result<u32> {
    u32::from_str_radix(trim_hex(value), 16)
        .map_err(|_| Error::format(format!("invalid hex u32 {value:?}")))
}
fn parse_hex_u64(value: &str) -> Result<u64> {
    u64::from_str_radix(trim_hex(value), 16)
        .map_err(|_| Error::format(format!("invalid hex u64 {value:?}")))
}

fn zlib_encode(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder
        .finish()
        .map_err(|err| Error::format(format!("zlib encoding failed: {err}")))
}

fn load_preserved_files(
    manifest: &Xp3Meta,
    templates: &[Vec<u8>],
    source: Option<&SourceTemplate>,
) -> Result<Vec<PreservedPackedFile>> {
    let mut by_root = BTreeMap::<usize, PreservedPackedFile>::new();
    for file in &manifest.preserved_files {
        let mut segments = Vec::with_capacity(file.segments.len());
        for (index, segment) in file.segments.iter().enumerate() {
            let stored = base64::engine::general_purpose::STANDARD
                .decode(segment.stored_base64.as_bytes())
                .map_err(|err| {
                    Error::format(format!(
                        "preserved File root={} segment[{index}] base64 decode failed: {err}",
                        file.root_chunk_index
                    ))
                })?;
            if stored.len() as u64 != segment.archive_size
                || crate::xp3_meta::sha256_hex(&stored) != segment.stored_sha256
            {
                return Err(Error::format(format!(
                    "preserved File root={} segment[{index}] payload does not match manifest size/hash",
                    file.root_chunk_index
                )));
            }
            segments.push(PackedSegment {
                flags: segment.flags,
                original_size: segment.original_size,
                stored,
                original_offset: segment.archive_offset,
            });
        }
        by_root.insert(
            file.root_chunk_index,
            PreservedPackedFile {
                root_chunk_index: file.root_chunk_index,
                segments,
            },
        );
    }

    // Compatibility for older manifests: if a protected File root has a segm
    // table but no retained payload record, recover those exact bytes from the
    // validated source archive. An info-only protected node needs no payload.
    for root in &manifest.root_chunks {
        if root.kind != "protected-dummy/File" || by_root.contains_key(&root.index) {
            continue;
        }
        let block = templates.get(root.index_block).ok_or_else(|| {
            Error::format(format!(
                "protected root {} index block is out of range",
                root.index
            ))
        })?;
        let range = root_body_range(block, root)?;
        let body = &block[range];
        let mut position = 0usize;
        let mut found_segm = false;
        let mut segments = Vec::new();
        while position + 12 <= body.len() {
            let tag = read_u32(body, position)?;
            let len = usize::try_from(read_u64(body, position + 4)?)
                .map_err(|_| Error::format("protected File child chunk size overflow"))?;
            let data_start = position + 12;
            let data_end = data_start
                .checked_add(len)
                .ok_or_else(|| Error::format("protected File child chunk overflow"))?;
            if data_end > body.len() {
                return Err(Error::format(format!(
                    "protected root {} has malformed child chunk",
                    root.index
                )));
            }
            if tag == TAG_SEGM {
                found_segm = true;
                if len % 28 != 0 {
                    return Err(Error::format(format!(
                        "protected root {} segm size is not a multiple of 28",
                        root.index
                    )));
                }
                for (segment_index, raw) in body[data_start..data_end].chunks_exact(28).enumerate()
                {
                    let flags = read_u32(raw, 0)?;
                    let archive_offset = read_u64(raw, 4)?;
                    let original_size = read_u64(raw, 12)?;
                    let archive_size = read_u64(raw, 20)?;
                    let source = source.ok_or_else(|| Error::format(format!(
                        "protected File root {} segment[{segment_index}] was not retained by this old manifest; provide --source-archive or re-run unpack",
                        root.index
                    )))?;
                    let size = usize::try_from(archive_size)
                        .map_err(|_| Error::format("protected stored segment size overflow"))?;
                    let stored = source.archive.physical_range(archive_offset, size)?;
                    segments.push(PackedSegment {
                        flags,
                        original_size,
                        stored,
                        original_offset: archive_offset,
                    });
                }
            }
            position = data_end;
        }
        if found_segm {
            by_root.insert(
                root.index,
                PreservedPackedFile {
                    root_chunk_index: root.index,
                    segments,
                },
            );
        }
    }

    Ok(by_root.into_values().collect())
}

fn load_special_blobs(
    manifest: &Xp3Meta,
    source: Option<&SourceTemplate>,
) -> Result<Vec<SpecialBlob>> {
    let mut by_root = BTreeMap::<usize, SpecialBlob>::new();
    for special in &manifest.special {
        let root = manifest
            .root_chunks
            .get(special.root_index)
            .ok_or_else(|| {
                Error::format(format!(
                    "special root {} is out of range",
                    special.root_index
                ))
            })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(special.stored_blob_base64.as_bytes())
            .map_err(|err| {
                Error::format(format!(
                    "special root {} base64 decode failed: {err}",
                    special.root_index
                ))
            })?;
        if crate::xp3_meta::sha256_hex(&bytes) != special.stored_blob_sha256 {
            return Err(Error::format(format!(
                "special root {} stored blob SHA-256 mismatch",
                special.root_index
            )));
        }
        let original_offset = root.inferred_offset.ok_or_else(|| {
            Error::format(format!(
                "special root {} has no original physical offset",
                special.root_index
            ))
        })?;
        by_root.insert(
            special.root_index,
            SpecialBlob {
                root_chunk_index: special.root_index,
                original_offset,
                bytes,
            },
        );
    }

    // Old/partial manifests may omit `special[]` even though a descriptor root
    // exists. If the original archive is available, preserve the opaque blob.
    for root in &manifest.root_chunks {
        if !is_special_root(root) || by_root.contains_key(&root.index) {
            continue;
        }
        let (Some(offset), Some(size), Some(source)) =
            (root.inferred_offset, root.inferred_archive_size, source)
        else {
            return Err(Error::format(format!(
                "special root {} has no retained stored blob; re-run unpack or provide --source-archive",
                root.index
            )));
        };
        let size =
            usize::try_from(size).map_err(|_| Error::format("special blob size overflow"))?;
        let bytes = source.archive.physical_range(offset, size)?;
        by_root.insert(
            root.index,
            SpecialBlob {
                root_chunk_index: root.index,
                original_offset: offset,
                bytes,
            },
        );
    }
    Ok(by_root.into_values().collect())
}

fn is_special_root(root: &RootChunkMeta) -> bool {
    matches!(
        root.kind.as_str(),
        "special-index-v1-shaped"
            | "special-index-v2-shaped"
            | "special-index-v3-shaped"
            | "special-index-generic-shaped"
            | "Hxv4-special-index"
    )
}

fn index_original_total_len(block: &IndexBlockMeta) -> Result<u64> {
    let header = match block.flags & INDEX_METHOD_MASK {
        INDEX_RAW => 1u64 + 8,
        INDEX_ZLIB => 1u64 + 16,
        method => {
            return Err(Error::unsupported(format!(
                "index[{}] encoding method {method} is not writable",
                block.index
            )))
        }
    };
    Ok(header
        + block.stored_size
        + if block.flags & INDEX_CONTINUE != 0 {
            8
        } else {
            0
        })
}

fn build_layout_objects(
    manifest: &Xp3Meta,
    entries: &[PackedEntry],
    preserved: &[PreservedPackedFile],
    specials: &[SpecialBlob],
) -> Result<Vec<LayoutObject>> {
    let mut out = Vec::new();
    for entry in entries {
        for (segment_index, segment) in entry.segments.iter().enumerate() {
            out.push(LayoutObject {
                key: ObjectKey::EntrySegment(entry.entry_index, segment_index),
                original_offset: segment.original_offset,
                footprint: segment.stored.len() as u64,
                content_sha256: crate::xp3_meta::sha256_hex(&segment.stored),
                assigned_offset: 0,
            });
        }
    }
    for file in preserved {
        for (segment_index, segment) in file.segments.iter().enumerate() {
            out.push(LayoutObject {
                key: ObjectKey::PreservedSegment(file.root_chunk_index, segment_index),
                original_offset: segment.original_offset,
                footprint: segment.stored.len() as u64,
                content_sha256: crate::xp3_meta::sha256_hex(&segment.stored),
                assigned_offset: 0,
            });
        }
    }
    for special in specials {
        out.push(LayoutObject {
            key: ObjectKey::Special(special.root_chunk_index),
            original_offset: special.original_offset,
            footprint: special.bytes.len() as u64,
            content_sha256: crate::xp3_meta::sha256_hex(&special.bytes),
            assigned_offset: 0,
        });
    }
    for block in &manifest.index_blocks {
        out.push(LayoutObject {
            key: ObjectKey::Index(block.index),
            original_offset: block.physical_offset,
            footprint: index_original_total_len(block)?,
            content_sha256: block
                .encoded_sha256
                .clone()
                .unwrap_or_else(|| format!("index-template-{}", block.index)),
            assigned_offset: 0,
        });
    }
    out.sort_by_key(|object| (object.original_offset, object.key));
    Ok(out)
}

fn assign_layout(
    objects: &mut [LayoutObject],
    header_end: u64,
    preserve_anchors: bool,
) -> Result<()> {
    objects.sort_by_key(|object| (object.original_offset, object.key));
    let mut cursor = header_end;
    let mut previous: Option<(u64, u64, String, u64)> = None;
    for object in objects {
        if preserve_anchors {
            if let Some((offset, footprint, hash, assigned)) = previous.as_ref() {
                if object.original_offset == *offset
                    && object.footprint == *footprint
                    && object.content_sha256 == *hash
                {
                    object.assigned_offset = *assigned;
                    continue;
                }
            }
        }
        let offset = if preserve_anchors {
            cursor.max(object.original_offset)
        } else {
            cursor
        };
        object.assigned_offset = offset;
        cursor = offset
            .checked_add(object.footprint)
            .ok_or_else(|| Error::format("XP3 physical layout overflow"))?;
        previous = Some((
            object.original_offset,
            object.footprint,
            object.content_sha256.clone(),
            object.assigned_offset,
        ));
    }
    Ok(())
}

fn object_offsets(objects: &[LayoutObject]) -> HashMap<ObjectKey, u64> {
    objects
        .iter()
        .map(|object| (object.key, object.assigned_offset))
        .collect()
}

fn patch_index_templates(
    manifest: &Xp3Meta,
    templates: &[Vec<u8>],
    entries: &[PackedEntry],
    preserved: &[PreservedPackedFile],
    specials: &[SpecialBlob],
    offsets: &HashMap<ObjectKey, u64>,
) -> Result<Vec<Vec<u8>>> {
    let mut decoded = templates.to_vec();
    for entry in entries {
        let root = manifest
            .root_chunks
            .get(entry.root_chunk_index)
            .ok_or_else(|| {
                Error::format(format!(
                    "entry[{}] File root is out of range",
                    entry.entry_index
                ))
            })?;
        let block = decoded
            .get_mut(root.index_block)
            .ok_or_else(|| Error::format("root index block out of range"))?;
        patch_file_root(block, root, entry, offsets)?;
    }
    for file in preserved {
        let root = manifest
            .root_chunks
            .get(file.root_chunk_index)
            .ok_or_else(|| {
                Error::format(format!(
                    "preserved File root {} is out of range",
                    file.root_chunk_index
                ))
            })?;
        let block = decoded
            .get_mut(root.index_block)
            .ok_or_else(|| Error::format("preserved root index block out of range"))?;
        patch_preserved_file_root(block, root, file, offsets)?;
    }
    for special in specials {
        let root = manifest
            .root_chunks
            .get(special.root_chunk_index)
            .ok_or_else(|| {
                Error::format(format!(
                    "special root {} is out of range",
                    special.root_chunk_index
                ))
            })?;
        let new_offset = *offsets
            .get(&ObjectKey::Special(special.root_chunk_index))
            .ok_or_else(|| {
                Error::format(format!(
                    "special root {} has no physical layout",
                    special.root_chunk_index
                ))
            })?;
        let block = decoded
            .get_mut(root.index_block)
            .ok_or_else(|| Error::format("special root index block out of range"))?;
        patch_special_root(block, root, new_offset, special.bytes.len() as u64)?;
    }
    Ok(decoded)
}

fn root_body_range(block: &[u8], root: &RootChunkMeta) -> Result<std::ops::Range<usize>> {
    let start = root.index_offset;
    if start + 12 > block.len() {
        return Err(Error::format(format!(
            "root[{}] header outside decoded index",
            root.index
        )));
    }
    let encoded_size = read_u64(block, start + 4)?;
    if encoded_size != root.size {
        return Err(Error::format(format!(
            "root[{}] template size mismatch: meta={} template={encoded_size}",
            root.index, root.size
        )));
    }
    let len = usize::try_from(root.size).map_err(|_| Error::format("root chunk size overflow"))?;
    let body_start = start + 12;
    let body_end = body_start
        .checked_add(len)
        .ok_or_else(|| Error::format("root body overflow"))?;
    if body_end > block.len() {
        return Err(Error::format(format!(
            "root[{}] body outside decoded index",
            root.index
        )));
    }
    Ok(body_start..body_end)
}

fn patch_file_root(
    block: &mut [u8],
    root: &RootChunkMeta,
    entry: &PackedEntry,
    offsets: &HashMap<ObjectKey, u64>,
) -> Result<()> {
    let range = root_body_range(block, root)?;
    let body = &mut block[range];
    let mut position = 0usize;
    let mut saw_info = false;
    let mut segment_cursor = 0usize;
    while position + 12 <= body.len() {
        let tag = read_u32(body, position)?;
        let len = usize::try_from(read_u64(body, position + 4)?)
            .map_err(|_| Error::format("File child chunk size overflow"))?;
        let data_start = position + 12;
        let data_end = data_start
            .checked_add(len)
            .ok_or_else(|| Error::format("File child chunk overflow"))?;
        if data_end > body.len() {
            return Err(Error::format(format!(
                "root[{}] malformed File child chunk",
                root.index
            )));
        }
        match tag {
            TAG_INFO => {
                if len < 22 {
                    return Err(Error::format(format!(
                        "root[{}] info chunk too short",
                        root.index
                    )));
                }
                // Preserve flags, filename-length/name bytes and any vendor tail.
                // Only the two size fields depend on edited storage content.
                write_u64(body, data_start + 4, entry.info_original_size)?;
                write_u64(body, data_start + 12, entry.info_archive_size)?;
                saw_info = true;
            }
            TAG_SEGM => {
                if len == 0 || len % 28 != 0 {
                    return Err(Error::format(format!(
                        "root[{}] segm chunk size {} is not a non-zero multiple of 28",
                        root.index, len
                    )));
                }
                let descriptor_count = len / 28;
                let segment_end = segment_cursor
                    .checked_add(descriptor_count)
                    .ok_or_else(|| Error::format("File segm descriptor count overflow"))?;
                let slice = entry
                    .segments
                    .get(segment_cursor..segment_end)
                    .ok_or_else(|| {
                        Error::format(format!(
                            "root[{}] has more segm descriptors than retained entry segments",
                            root.index
                        ))
                    })?;
                for (local_index, segment) in slice.iter().enumerate() {
                    let segment_index = segment_cursor + local_index;
                    let at = data_start + local_index * 28;
                    let offset = *offsets
                        .get(&ObjectKey::EntrySegment(entry.entry_index, segment_index))
                        .ok_or_else(|| Error::format("missing entry segment physical offset"))?;
                    // Full descriptor flags are copied from the source manifest;
                    // keep every vendor/reserved bit, changing only the fields
                    // that are physically content/layout dependent.
                    write_u32(body, at, segment.flags)?;
                    write_u64(body, at + 4, offset)?;
                    write_u64(body, at + 12, segment.original_size)?;
                    write_u64(body, at + 20, segment.stored.len() as u64)?;
                }
                segment_cursor = segment_end;
            }
            _ => {}
        }
        position = data_end;
    }
    if !saw_info || segment_cursor != entry.segments.len() {
        return Err(Error::format(format!(
            "root[{}] File template mismatch: info={} segm_descriptors={} expected_segments={}",
            root.index,
            saw_info,
            segment_cursor,
            entry.segments.len()
        )));
    }
    Ok(())
}

fn patch_preserved_file_root(
    block: &mut [u8],
    root: &RootChunkMeta,
    file: &PreservedPackedFile,
    offsets: &HashMap<ObjectKey, u64>,
) -> Result<()> {
    let range = root_body_range(block, root)?;
    let body = &mut block[range];
    let mut position = 0usize;
    let mut segment_cursor = 0usize;
    let mut saw_segm = false;
    while position + 12 <= body.len() {
        let tag = read_u32(body, position)?;
        let len = usize::try_from(read_u64(body, position + 4)?)
            .map_err(|_| Error::format("protected File child chunk size overflow"))?;
        let data_start = position + 12;
        let data_end = data_start
            .checked_add(len)
            .ok_or_else(|| Error::format("protected File child chunk overflow"))?;
        if data_end > body.len() {
            return Err(Error::format(format!(
                "root[{}] malformed protected File child chunk",
                root.index
            )));
        }
        if tag == TAG_SEGM {
            if len % 28 != 0 {
                return Err(Error::format(format!(
                    "root[{}] protected segm size is not a multiple of 28",
                    root.index
                )));
            }
            saw_segm = true;
            let descriptor_count = len / 28;
            let segment_end = segment_cursor
                .checked_add(descriptor_count)
                .ok_or_else(|| Error::format("protected segm descriptor count overflow"))?;
            let slice = file
                .segments
                .get(segment_cursor..segment_end)
                .ok_or_else(|| {
                    Error::format(format!(
                        "root[{}] has more protected segm descriptors than retained segments",
                        root.index
                    ))
                })?;
            for (local_index, segment) in slice.iter().enumerate() {
                let segment_index = segment_cursor + local_index;
                let at = data_start + local_index * 28;
                let offset = *offsets
                    .get(&ObjectKey::PreservedSegment(
                        file.root_chunk_index,
                        segment_index,
                    ))
                    .ok_or_else(|| Error::format("missing protected segment physical offset"))?;
                write_u32(body, at, segment.flags)?;
                write_u64(body, at + 4, offset)?;
                write_u64(body, at + 12, segment.original_size)?;
                write_u64(body, at + 20, segment.stored.len() as u64)?;
            }
            segment_cursor = segment_end;
        }
        position = data_end;
    }
    if !saw_segm || segment_cursor != file.segments.len() {
        return Err(Error::format(format!(
            "root[{}] protected File segm mismatch: found={} descriptors={} retained_segments={}",
            root.index,
            saw_segm,
            segment_cursor,
            file.segments.len()
        )));
    }
    Ok(())
}

fn patch_special_root(
    block: &mut [u8],
    root: &RootChunkMeta,
    new_offset: u64,
    new_stored_size: u64,
) -> Result<()> {
    if new_stored_size > u32::MAX as u64 {
        return Err(Error::unsupported(format!(
            "special root {} stored blob exceeds u32 descriptor size",
            root.index
        )));
    }
    let range = root_body_range(block, root)?;
    let body = &mut block[range];
    match root.kind.as_str() {
        "Hxv4-special-index" | "special-index-v3-shaped" => {
            if body.len() < 12 {
                return Err(Error::format("special v3/HXV4 body too short"));
            }
            write_u64(body, 0, new_offset)?;
            write_u32(body, 8, new_stored_size as u32)?;
        }
        "special-index-v1-shaped" | "special-index-v2-shaped" => {
            if body.len() < 16 {
                return Err(Error::format("special v1/v2 body too short"));
            }
            write_u64(body, 0, new_offset)?;
            write_u32(body, 12, new_stored_size as u32)?;
        }
        "special-index-generic-shaped" => {
            let old_offset = root
                .inferred_offset
                .ok_or_else(|| Error::format("generic special root has no old offset"))?;
            let old_size = root
                .inferred_archive_size
                .ok_or_else(|| Error::format("generic special root has no old size"))?;
            if old_size > u32::MAX as u64 {
                return Err(Error::format("generic special old size exceeds u32"));
            }
            let mut match_at = None;
            for at in 0..=body.len().saturating_sub(12) {
                if read_u64(body, at)? == old_offset && read_u32(body, at + 8)? == old_size as u32 {
                    if match_at.is_some() {
                        return Err(Error::format(format!(
                            "generic special root {} contains more than one matching offset/size tuple",
                            root.index
                        )));
                    }
                    match_at = Some(at);
                }
            }
            let at = match_at.ok_or_else(|| {
                Error::format(format!(
                    "generic special root {} no longer contains its original offset/size tuple",
                    root.index
                ))
            })?;
            write_u64(body, at, new_offset)?;
            write_u32(body, at + 8, new_stored_size as u32)?;
        }
        other => {
            return Err(Error::unsupported(format!(
                "cannot patch special root kind {other:?}"
            )))
        }
    }
    Ok(())
}

fn encode_index_payloads(manifest: &Xp3Meta, decoded: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    manifest
        .index_blocks
        .iter()
        .zip(decoded.iter())
        .map(|(block, bytes)| match block.flags & INDEX_METHOD_MASK {
            INDEX_RAW => Ok(bytes.clone()),
            INDEX_ZLIB => zlib_encode(bytes),
            method => Err(Error::unsupported(format!(
                "index[{}] encoding method {method} is not writable",
                block.index
            ))),
        })
        .collect()
}

fn index_object_actual_len(block: &IndexBlockMeta, payload_len: usize) -> Result<u64> {
    let header = match block.flags & INDEX_METHOD_MASK {
        INDEX_RAW => 1u64 + 8,
        INDEX_ZLIB => 1u64 + 16,
        method => {
            return Err(Error::unsupported(format!(
                "index encoding method {method}"
            )))
        }
    };
    header
        .checked_add(payload_len as u64)
        .and_then(|value| {
            value.checked_add(if block.flags & INDEX_CONTINUE != 0 {
                8
            } else {
                0
            })
        })
        .ok_or_else(|| Error::format("index block total size overflow"))
}

fn retained_index_object(
    block: &IndexBlockMeta,
    source: Option<&SourceTemplate>,
) -> Result<Option<Vec<u8>>> {
    let expected_len = index_original_total_len(block)?;
    let expected_len_usize = usize::try_from(expected_len).map_err(|_| {
        Error::format(format!(
            "index[{}] physical object size overflow",
            block.index
        ))
    })?;

    if let Some(source) = source {
        return Ok(Some(
            source
                .archive
                .physical_range(block.physical_offset, expected_len_usize)?,
        ));
    }

    let Some(encoded) = block.encoded_base64.as_deref() else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|err| {
            Error::format(format!(
                "index[{}] encoded template base64 decode failed: {err}",
                block.index
            ))
        })?;
    if bytes.len() != expected_len_usize {
        return Err(Error::format(format!(
            "index[{}] encoded template size mismatch: expected={} actual={}",
            block.index,
            expected_len_usize,
            bytes.len()
        )));
    }
    if let Some(expected_sha) = block.encoded_sha256.as_deref() {
        if !crate::xp3_meta::sha256_hex(&bytes).eq_ignore_ascii_case(expected_sha) {
            return Err(Error::format(format!(
                "index[{}] encoded template SHA-256 mismatch",
                block.index
            )));
        }
    }
    Ok(Some(bytes))
}

fn build_index_objects(
    manifest: &Xp3Meta,
    payloads: &[Vec<u8>],
    decoded: &[Vec<u8>],
    original_decoded: &[Vec<u8>],
    offsets: &HashMap<ObjectKey, u64>,
    source: Option<&SourceTemplate>,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(manifest.index_blocks.len());
    for (index, (block, payload)) in manifest
        .index_blocks
        .iter()
        .zip(payloads.iter())
        .enumerate()
    {
        let same_decoded = decoded.get(index) == original_decoded.get(index);
        let same_next = if block.flags & INDEX_CONTINUE != 0 {
            let original_next = manifest
                .index_blocks
                .get(index + 1)
                .map(|next| next.physical_offset);
            offsets.get(&ObjectKey::Index(index + 1)).copied() == original_next
        } else {
            true
        };

        // An index object's own physical address is stored by the XP3 header or
        // the previous block, not inside this object. Therefore movement of the
        // block itself does not require re-encoding it. Reuse the exact original
        // bytes whenever its decoded payload and its own continuation pointer are
        // unchanged, including the original zlib bitstream/header bytes.
        if same_decoded && same_next {
            if let Some(bytes) = retained_index_object(block, source)? {
                out.push(bytes);
                continue;
            }
        }

        let mut bytes = Vec::new();
        bytes.push(block.flags);
        match block.flags & INDEX_METHOD_MASK {
            INDEX_RAW => {
                bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                bytes.extend_from_slice(payload);
            }
            INDEX_ZLIB => {
                // Compressed-index header: stored size, then decoded/original size.
                bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                bytes.extend_from_slice(&block.original_size.to_le_bytes());
                bytes.extend_from_slice(payload);
            }
            method => {
                return Err(Error::unsupported(format!(
                    "index[{}] encoding method {method}",
                    block.index
                )))
            }
        }
        if block.flags & INDEX_CONTINUE != 0 {
            let next = offsets.get(&ObjectKey::Index(index + 1)).ok_or_else(|| {
                Error::format(format!(
                    "index[{index}] CONTINUE flag has no following index block"
                ))
            })?;
            let relative = next
                .checked_sub(manifest.archive.xp3_offset)
                .ok_or_else(|| {
                    Error::format(format!("index[{index}] next pointer precedes XP3 base"))
                })?;
            bytes.extend_from_slice(&relative.to_le_bytes());
        } else if index + 1 != manifest.index_blocks.len() {
            return Err(Error::format(format!(
                "index[{index}] clears CONTINUE but manifest contains later index blocks"
            )));
        }
        out.push(bytes);
    }
    Ok(out)
}

fn validate_opaque_source_safety(
    manifest: &Xp3Meta,
    source: Option<&SourceTemplate>,
    objects: &[LayoutObject],
    entries: &[PackedEntry],
    preserved: &[PreservedPackedFile],
    specials: &[SpecialBlob],
    index_objects: &[Vec<u8>],
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };

    // Build the union of every physical range whose semantics are known to the
    // writer in the *source* file. Growth may overwrite/move another known XP3
    // object because all of its pointers are patched below. Bytes outside this
    // union are opaque. Non-zero opaque bytes are never sacrificed implicitly;
    // zero-filled gaps are treated as padding and may absorb growth.
    let mut known = Vec::<(u64, u64)>::new();
    let header_end = manifest
        .archive
        .xp3_offset
        .checked_add(XP3_MAGIC.len() as u64 + 8)
        .ok_or_else(|| Error::format("XP3 header range overflow"))?;
    known.push((manifest.archive.xp3_offset, header_end));

    for entry in &manifest.entries {
        for segment in &entry.original.segments {
            push_range(&mut known, segment.archive_offset, segment.archive_size)?;
        }
    }
    for file in preserved {
        for segment in &file.segments {
            push_range(
                &mut known,
                segment.original_offset,
                segment.stored.len() as u64,
            )?;
        }
    }
    for special in specials {
        push_range(
            &mut known,
            special.original_offset,
            special.bytes.len() as u64,
        )?;
    }
    for block in &manifest.index_blocks {
        push_range(
            &mut known,
            block.physical_offset,
            index_original_total_len(block)?,
        )?;
    }
    let known = merge_ranges(known);

    let entry_map = entries
        .iter()
        .map(|entry| (entry.entry_index, entry))
        .collect::<HashMap<_, _>>();
    let preserved_map = preserved
        .iter()
        .map(|file| (file.root_chunk_index, file))
        .collect::<HashMap<_, _>>();
    let special_map = specials
        .iter()
        .map(|blob| (blob.root_chunk_index, blob))
        .collect::<HashMap<_, _>>();

    for object in objects {
        let written_len = match object.key {
            ObjectKey::EntrySegment(entry_index, segment_index) => entry_map
                .get(&entry_index)
                .and_then(|entry| entry.segments.get(segment_index))
                .map(|segment| segment.stored.len() as u64)
                .ok_or_else(|| {
                    Error::format("missing entry segment while validating opaque physical ranges")
                })?,
            ObjectKey::PreservedSegment(root_index, segment_index) => preserved_map
                .get(&root_index)
                .and_then(|file| file.segments.get(segment_index))
                .map(|segment| segment.stored.len() as u64)
                .ok_or_else(|| {
                    Error::format(
                        "missing preserved segment while validating opaque physical ranges",
                    )
                })?,
            ObjectKey::Special(root_index) => special_map
                .get(&root_index)
                .map(|blob| blob.bytes.len() as u64)
                .ok_or_else(|| {
                    Error::format("missing special blob while validating opaque physical ranges")
                })?,
            ObjectKey::Index(index) => index_objects
                .get(index)
                .map(|bytes| bytes.len() as u64)
                .ok_or_else(|| {
                    Error::format("missing index object while validating opaque physical ranges")
                })?,
        };
        if written_len == 0 {
            continue;
        }
        let end = object
            .assigned_offset
            .checked_add(written_len)
            .ok_or_else(|| Error::format("new XP3 object range overflow"))?;
        let source_end = end.min(manifest.archive.physical_size);
        if object.assigned_offset >= source_end {
            continue;
        }
        for (gap_start, gap_end) in uncovered_ranges(object.assigned_offset, source_end, &known) {
            if source_range_has_nonzero(source, gap_start, gap_end)? {
                return Err(Error::unsupported(format!(
                    "strict physical-layout preservation would overwrite opaque non-zero source bytes at 0x{gap_start:x}..0x{gap_end:x} while placing {:?}; use a layout that preserves this region or extend the parser/meta model before packing",
                    object.key
                )));
            }
        }
    }
    Ok(())
}

fn push_range(ranges: &mut Vec<(u64, u64)>, start: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::format("physical range overflow"))?;
    ranges.push((start, end));
    Ok(())
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged = Vec::<(u64, u64)>::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn uncovered_ranges(start: u64, end: u64, known: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut cursor = start;
    for &(known_start, known_end) in known {
        if known_end <= cursor {
            continue;
        }
        if known_start >= end {
            break;
        }
        if known_start > cursor {
            out.push((cursor, known_start.min(end)));
        }
        cursor = cursor.max(known_end);
        if cursor >= end {
            break;
        }
    }
    if cursor < end {
        out.push((cursor, end));
    }
    out
}

fn source_range_has_nonzero(source: &SourceTemplate, start: u64, end: u64) -> Result<bool> {
    const CHUNK: usize = 1024 * 1024;
    let mut at = start;
    while at < end {
        let remaining = end - at;
        let size = usize::try_from(remaining.min(CHUNK as u64))
            .map_err(|_| Error::format("opaque-range chunk size overflow"))?;
        let bytes = source.archive.physical_range(at, size)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(true);
        }
        at = at
            .checked_add(size as u64)
            .ok_or_else(|| Error::format("opaque-range cursor overflow"))?;
    }
    Ok(false)
}

fn write_container(
    manifest: &Xp3Meta,
    output: &Path,
    source: Option<&SourceTemplate>,
    objects: &[LayoutObject],
    entries: &[PackedEntry],
    preserved: &[PreservedPackedFile],
    specials: &[SpecialBlob],
    index_objects: &[Vec<u8>],
    preserve_anchors: bool,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }

    // When the original archive is available and physical anchors are being
    // preserved, clone the entire file first and then patch the known XP3
    // objects in place. This retains bytes that are intentionally opaque to
    // the parser: padding, trailers and unknown out-of-line/private payloads.
    // The output path is rejected as a source earlier, so this cannot truncate
    // the template before it is copied.
    let copied_physical_template = preserve_anchors && source.is_some();
    if copied_physical_template {
        let source = source.ok_or_else(|| {
            Error::format("physical-template copy requested without source archive")
        })?;
        fs::copy(&source.path, output)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(!copied_physical_template)
        .open(output)?;

    if manifest.archive.xp3_offset != 0 && !copied_physical_template {
        let source =
            source.ok_or_else(|| Error::format("embedded XP3 requires source archive prefix"))?;
        let mut source_file = File::open(&source.path)?;
        let prefix_len = usize::try_from(manifest.archive.xp3_offset)
            .map_err(|_| Error::format("embedded XP3 prefix length does not fit usize"))?;
        let mut prefix = vec![0u8; prefix_len];
        source_file.read_exact(&mut prefix)?;
        file.write_all(&prefix)?;
    }

    file.seek(SeekFrom::Start(manifest.archive.xp3_offset))?;
    file.write_all(&XP3_MAGIC)?;
    let first_index = objects
        .iter()
        .find(|object| object.key == ObjectKey::Index(0))
        .ok_or_else(|| Error::format("missing first index layout object"))?;
    let first_relative = first_index
        .assigned_offset
        .checked_sub(manifest.archive.xp3_offset)
        .ok_or_else(|| Error::format("first index precedes XP3 base"))?;
    file.write_all(&first_relative.to_le_bytes())?;

    let entry_map = entries
        .iter()
        .map(|entry| (entry.entry_index, entry))
        .collect::<HashMap<_, _>>();
    let preserved_map = preserved
        .iter()
        .map(|entry| (entry.root_chunk_index, entry))
        .collect::<HashMap<_, _>>();
    let special_map = specials
        .iter()
        .map(|blob| (blob.root_chunk_index, blob))
        .collect::<HashMap<_, _>>();

    let mut logical_end = manifest.archive.xp3_offset + XP3_MAGIC.len() as u64 + 8;
    for object in objects {
        file.seek(SeekFrom::Start(object.assigned_offset))?;
        match object.key {
            ObjectKey::EntrySegment(entry_index, segment_index) => {
                let entry = entry_map
                    .get(&entry_index)
                    .ok_or_else(|| Error::format("missing packed entry object"))?;
                let segment = entry
                    .segments
                    .get(segment_index)
                    .ok_or_else(|| Error::format("missing packed entry segment"))?;
                file.write_all(&segment.stored)?;
                logical_end = logical_end.max(object.assigned_offset + segment.stored.len() as u64);
            }
            ObjectKey::PreservedSegment(root_index, segment_index) => {
                let entry = preserved_map
                    .get(&root_index)
                    .ok_or_else(|| Error::format("missing preserved File object"))?;
                let segment = entry
                    .segments
                    .get(segment_index)
                    .ok_or_else(|| Error::format("missing preserved File segment"))?;
                file.write_all(&segment.stored)?;
                logical_end = logical_end.max(object.assigned_offset + segment.stored.len() as u64);
            }
            ObjectKey::Special(root_index) => {
                let special = special_map
                    .get(&root_index)
                    .ok_or_else(|| Error::format("missing special object"))?;
                file.write_all(&special.bytes)?;
                logical_end = logical_end.max(object.assigned_offset + special.bytes.len() as u64);
            }
            ObjectKey::Index(index) => {
                let bytes = index_objects
                    .get(index)
                    .ok_or_else(|| Error::format("missing encoded index object"))?;
                file.write_all(bytes)?;
                logical_end = logical_end.max(object.assigned_offset + bytes.len() as u64);
            }
        }
    }

    // Preserve the original physical length as a floor when using source-layout
    // anchors. Sparse/trailing padding is not semantically interpreted by XP3,
    // but keeping the footprint avoids needlessly shrinking template archives.
    let final_len = if preserve_anchors {
        logical_end.max(manifest.archive.physical_size)
    } else {
        logical_end
    };
    file.set_len(final_len)?;
    file.flush()?;
    Ok(())
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    let left_meta = fs::metadata(left)?;
    let right_meta = fs::metadata(right)?;
    if left_meta.len() != right_meta.len() {
        return Ok(false);
    }
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let mut a = vec![0u8; 1024 * 1024];
    let mut b = vec![0u8; 1024 * 1024];
    loop {
        let an = left.read(&mut a)?;
        let bn = right.read(&mut b)?;
        if an != bn || a[..an] != b[..bn] {
            return Ok(false);
        }
        if an == 0 {
            return Ok(true);
        }
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| Error::format("u32 offset overflow"))?;
    let raw = bytes
        .get(at..end)
        .ok_or_else(|| Error::format("u32 outside buffer"))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}
fn read_u64(bytes: &[u8], at: usize) -> Result<u64> {
    let end = at
        .checked_add(8)
        .ok_or_else(|| Error::format("u64 offset overflow"))?;
    let raw = bytes
        .get(at..end)
        .ok_or_else(|| Error::format("u64 outside buffer"))?;
    Ok(u64::from_le_bytes(raw.try_into().unwrap()))
}
fn write_u32(bytes: &mut [u8], at: usize, value: u32) -> Result<()> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| Error::format("u32 offset overflow"))?;
    let target = bytes
        .get_mut(at..end)
        .ok_or_else(|| Error::format("u32 outside buffer"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write_u64(bytes: &mut [u8], at: usize, value: u64) -> Result<()> {
    let end = at
        .checked_add(8)
        .ok_or_else(|| Error::format("u64 offset overflow"))?;
    let target = bytes
        .get_mut(at..end)
        .ok_or_else(|| Error::format("u64 outside buffer"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xp3_meta::SegmentMeta;

    #[test]
    fn repartition_keeps_exact_original_boundaries_when_size_matches() {
        let original = vec![
            SegmentMeta {
                flags: 0,
                archive_offset: 0,
                original_size: 10,
                archive_size: 10,
            },
            SegmentMeta {
                flags: 1,
                archive_offset: 10,
                original_size: 20,
                archive_size: 8,
            },
        ];
        assert_eq!(
            repartition_logical_sizes(&original, 30).unwrap(),
            vec![10, 20]
        );
    }

    #[test]
    fn repartition_preserves_segment_count_when_size_changes() {
        let original = vec![
            SegmentMeta {
                flags: 0,
                archive_offset: 0,
                original_size: 10,
                archive_size: 10,
            },
            SegmentMeta {
                flags: 1,
                archive_offset: 10,
                original_size: 20,
                archive_size: 8,
            },
        ];
        let sizes = repartition_logical_sizes(&original, 60).unwrap();
        assert_eq!(sizes, vec![10, 50]);
        assert_eq!(sizes.iter().sum::<usize>(), 60);
    }

    #[test]
    fn uncovered_ranges_only_returns_opaque_gaps() {
        let known = merge_ranges(vec![(10, 20), (18, 30), (40, 50)]);
        assert_eq!(known, vec![(10, 30), (40, 50)]);
        assert_eq!(
            uncovered_ranges(5, 55, &known),
            vec![(5, 10), (30, 40), (50, 55)]
        );
        assert!(uncovered_ranges(12, 28, &known).is_empty());
    }

    #[test]
    fn xor_is_symmetric() {
        let key = [0x12, 0x34, 0x56];
        let mut data = b"hello world".to_vec();
        let original = data.clone();
        apply_xor(&mut data, &key);
        assert_ne!(data, original);
        apply_xor(&mut data, &key);
        assert_eq!(data, original);
    }
}
