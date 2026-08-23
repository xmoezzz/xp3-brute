use crate::error::{Error, Result};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

pub const XP3_MAGIC: [u8; 11] = [
    0x58, 0x50, 0x33, 0x0d, 0x0a, 0x20, 0x0a, 0x1a, 0x8b, 0x67, 0x01,
];

const TAG_FILE: u32 = 0x656c_6946; // "File" little-endian
const TAG_INFO: u32 = 0x6f66_6e69; // "info"
const TAG_SEGM: u32 = 0x6d67_6573; // "segm"
const TAG_ADLR: u32 = 0x726c_6461; // "adlr"
const TAG_TIME: u32 = 0x656d_6974; // "time"
const TAG_HXV4: u32 = 0x3476_7848; // "Hxv4" little-endian

/// Stable ASCII prefix stored in the Hxv4 protected-warning pseudo entry.
/// The localized suffix varies, so detection deliberately stops at this prefix.
pub const HXV4_PROTECTED_WARNING_PREFIX: &[u8] =
    b"Warning: Extracting this archive may infringe on author's rights.";

/// Prefix used by the standard Kirikiri protected-archive dummy entry.
///
/// Historical KrkrExtract explicitly filtered this synthetic `File` node out of
/// the archive item list.  The full filename intentionally contains a very long
/// warning message and can exceed host filesystem filename limits.
pub const PROTECTED_DUMMY_PREFIX: &str = "$$$ This is a protected archive. $$$";
/// Typo emitted by older commercial KiriKiri builds (including the real Fate
/// sample). It is part of the on-disk compatibility surface, not a spelling
/// correction we can ignore.
pub const PROTECTED_DUMMY_PREFIX_LEGACY_TYPO: &str = "$$$ This is a protectet archive. $$$";

const INDEX_METHOD_MASK: u8 = 0x07;
const INDEX_RAW: u8 = 0;
const INDEX_ZLIB: u8 = 1;
const INDEX_CONTINUE: u8 = 0x80;

const SEGM_METHOD_MASK: u32 = 0x07;
const SEGM_RAW: u32 = 0;
const SEGM_ZLIB: u32 = 1;

#[derive(Clone, Copy, Debug)]
pub struct ArchiveOptions {
    pub tolerant: bool,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self { tolerant: true }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub flags: u32,
    /// Absolute offset in the physical archive file.
    pub archive_offset: u64,
    pub original_size: u64,
    pub archive_size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    /// Root chunk index of the ordinary XP3 `File` node that produced this entry.
    /// This is retained for container round-trip writing so unknown sibling/root chunks
    /// never need to be reordered or guessed.
    pub root_chunk_index: Option<usize>,
    pub flags: u32,
    pub original_size: u64,
    pub archive_size: u64,
    /// Raw UTF-16 code-unit count stored in the ordinary XP3 `info` chunk.
    /// Historical KrkrZ/SenrenBanka deliberately preserves the *real* filename
    /// length here even when `name` itself is replaced by a hash/synthetic token.
    /// Do not recompute this value from `name`.
    pub info_name_length: u16,
    pub name: String,
    pub alternate_name: Option<String>,
    pub alternate_hash: Option<u32>,
    /// Hxv4 synthetic entry id encoded in the normal XP3 `info` name.
    /// When present, `name` is not a real path/filename.
    pub hxv4_id: Option<u64>,
    pub adler: Option<u32>,
    pub segments: Vec<Segment>,
}

impl Entry {
    pub fn preferred_name(&self) -> &str {
        self.alternate_name.as_deref().unwrap_or(&self.name)
    }

    /// Hxv4 stores synthetic Unicode ids in ordinary XP3 `info` names.
    /// Such a name is an archive lookup token, not the original filename.
    pub fn has_hxv4_fakename(&self) -> bool {
        self.hxv4_id.is_some()
    }

    /// Return true for the synthetic protected-archive warning entry emitted by
    /// Kirikiri-compatible protected XP3 archives.  This node is metadata/noise,
    /// not an extractable game resource.
    pub fn is_protected_dummy(&self) -> bool {
        is_protected_dummy_name(self.preferred_name())
    }
}

/// Recognize the historical XP3 protected-archive dummy filename.
///
/// We deliberately key on the stable ASCII prefix rather than embedding the
/// entire localized warning string used by different Kirikiri builds.
pub fn is_protected_dummy_name(name: &str) -> bool {
    name.starts_with(PROTECTED_DUMMY_PREFIX) || name.starts_with(PROTECTED_DUMMY_PREFIX_LEGACY_TYPO)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootKind {
    File,
    ProtectedFile,
    AlternateName,
    SpecialIndexV1,
    SpecialIndexV2,
    SpecialIndexV3,
    /// Structurally inferred out-of-line special-index descriptor whose exact
    /// vendor magic/layout is not yet named.  It is diagnostic only.
    SpecialIndexGeneric,
    Hxv4SpecialIndex,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct RootChunk {
    pub magic: u32,
    pub size: u64,
    pub index_block: usize,
    pub index_offset: usize,
    pub kind: RootKind,
    pub inferred_name: Option<String>,
    pub inferred_hash: Option<u32>,
    pub inferred_offset: Option<u64>,
    pub inferred_original_size: Option<u64>,
    pub inferred_archive_size: Option<u64>,
    pub inferred_hxv4_kind: Option<u16>,
    pub inferred_hxv4_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hxv4Descriptor {
    /// Physical offset of the opaque/encrypted Hxv4 special-index blob.
    pub offset: u64,
    /// Stored size of the special-index blob.
    pub stored_size: u64,
    /// Hxv4 descriptor kind/flags field.
    pub kind: u16,
    /// Root chunk index in [`Archive::root_chunks`].
    pub root_chunk_index: usize,
}

#[derive(Clone, Debug)]
pub struct IndexBlock {
    pub physical_offset: u64,
    pub flags: u8,
    pub stored_size: u64,
    pub original_size: u64,
    pub decoded: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Archive {
    pub path: Option<PathBuf>,
    pub xp3_offset: u64,
    pub index_blocks: Vec<IndexBlock>,
    pub root_chunks: Vec<RootChunk>,
    /// Present when the normal XP3 index contains a literal `Hxv4` special-index descriptor.
    pub hxv4: Option<Hxv4Descriptor>,
    pub entries: Vec<Entry>,
    storage: PhysicalStorage,
    physical_cache: OnceLock<Vec<u8>>,
    special_index_blobs: HashMap<usize, OnceLock<Option<Vec<u8>>>>,
}

#[derive(Clone, Debug)]
enum PhysicalStorage {
    Memory(Vec<u8>),
    File {
        file: Arc<Mutex<fs::File>>,
        len: u64,
    },
}

impl PhysicalStorage {
    fn len(&self) -> u64 {
        match self {
            Self::Memory(bytes) => bytes.len() as u64,
            Self::File { len, .. } => *len,
        }
    }

    fn memory_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Memory(bytes) => Some(bytes),
            Self::File { .. } => None,
        }
    }

    fn read_vec(&self, offset: u64, size: usize, what: &str) -> Result<Vec<u8>> {
        let size64 = u64::try_from(size)
            .map_err(|_| Error::format(format!("{what} size does not fit u64")))?;
        let end = offset
            .checked_add(size64)
            .ok_or_else(|| Error::format(format!("{what} range overflow")))?;
        if end > self.len() {
            return Err(Error::format(format!(
                "{what} range outside archive: offset={offset} size={size} physical_size={}",
                self.len()
            )));
        }

        match self {
            Self::Memory(bytes) => {
                let start = to_usize(offset, what)?;
                let end = start
                    .checked_add(size)
                    .ok_or_else(|| Error::format(format!("{what} range overflow")))?;
                Ok(bytes[start..end].to_vec())
            }
            Self::File { file, .. } => {
                let mut guard = file
                    .lock()
                    .map_err(|_| Error::invalid("XP3 backing file lock poisoned"))?;
                guard.seek(SeekFrom::Start(offset))?;
                let mut out = vec![0u8; size];
                guard.read_exact(&mut out)?;
                Ok(out)
            }
        }
    }

    fn append_range(&self, offset: u64, size: usize, out: &mut Vec<u8>, what: &str) -> Result<()> {
        let size64 = u64::try_from(size)
            .map_err(|_| Error::format(format!("{what} size does not fit u64")))?;
        let end = offset
            .checked_add(size64)
            .ok_or_else(|| Error::format(format!("{what} range overflow")))?;
        if end > self.len() {
            return Err(Error::format(format!(
                "{what} range outside archive: offset={offset} size={size} physical_size={}",
                self.len()
            )));
        }

        match self {
            Self::Memory(bytes) => {
                let start = to_usize(offset, what)?;
                let end = start
                    .checked_add(size)
                    .ok_or_else(|| Error::format(format!("{what} range overflow")))?;
                out.extend_from_slice(&bytes[start..end]);
            }
            Self::File { file, .. } => {
                let old_len = out.len();
                let new_len = old_len
                    .checked_add(size)
                    .ok_or_else(|| Error::format(format!("{what} output size overflow")))?;
                out.resize(new_len, 0);
                let read_result = (|| -> std::io::Result<()> {
                    let mut guard = file
                        .lock()
                        .map_err(|_| std::io::Error::other("XP3 backing file lock poisoned"))?;
                    guard.seek(SeekFrom::Start(offset))?;
                    guard.read_exact(&mut out[old_len..new_len])
                })();
                if let Err(err) = read_result {
                    out.truncate(old_len);
                    return Err(err.into());
                }
            }
        }
        Ok(())
    }
}

impl Archive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(path, ArchiveOptions::default())
    }

    pub fn open_with_options(path: impl AsRef<Path>, options: ArchiveOptions) -> Result<Self> {
        let path = path.as_ref();
        let file = fs::File::open(path)?;
        let len = file.metadata()?.len();
        let storage = PhysicalStorage::File {
            file: Arc::new(Mutex::new(file)),
            len,
        };
        let mut archive = Self::from_storage(storage, options)?;
        archive.path = Some(path.to_path_buf());
        archive.normalize_hxv4_data_startup_anchor();
        Ok(archive)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes_with_options(bytes, ArchiveOptions::default())
    }

    pub fn from_bytes_with_options(bytes: Vec<u8>, options: ArchiveOptions) -> Result<Self> {
        Self::from_storage(PhysicalStorage::Memory(bytes), options)
    }

    fn from_storage(storage: PhysicalStorage, options: ArchiveOptions) -> Result<Self> {
        let xp3_offset = find_xp3_storage(&storage)?;
        let first_pointer = xp3_offset
            .checked_add(XP3_MAGIC.len() as u64)
            .ok_or_else(|| Error::format("first XP3 index pointer overflow"))?;

        let mut archive = Archive {
            path: None,
            xp3_offset,
            index_blocks: Vec::new(),
            root_chunks: Vec::new(),
            hxv4: None,
            entries: Vec::new(),
            storage,
            physical_cache: OnceLock::new(),
            special_index_blobs: HashMap::new(),
        };

        let mut pointer_pos = first_pointer;
        let mut pending_alt_name: Option<String> = None;
        let mut pending_alt_hash: Option<u32> = None;
        let mut completed = false;

        for block_no in 0..=1_000_000usize {
            let pointer = archive.read_physical_vec(pointer_pos, 8, "XP3 index pointer")?;
            let relative = read_u64(&pointer, 0)?;
            let absolute = archive
                .xp3_offset
                .checked_add(relative)
                .ok_or_else(|| Error::format("XP3 index offset overflow"))?;
            let flags_buf = archive.read_physical_vec(absolute, 1, "XP3 index flag")?;
            let flags = flags_buf[0];
            let method = flags & INDEX_METHOD_MASK;
            let mut position = absolute
                .checked_add(1)
                .ok_or_else(|| Error::format("XP3 index position overflow"))?;

            let (stored_size, original_size, decoded) = match method {
                INDEX_RAW => {
                    let size_buf = archive.read_physical_vec(position, 8, "raw XP3 index size")?;
                    let size = read_u64(&size_buf, 0)?;
                    position = position
                        .checked_add(8)
                        .ok_or_else(|| Error::format("raw XP3 index position overflow"))?;
                    let size_usize = to_usize(size, "raw XP3 index size")?;
                    let decoded =
                        archive.read_physical_vec(position, size_usize, "raw XP3 index")?;
                    position = position
                        .checked_add(size)
                        .ok_or_else(|| Error::format("raw XP3 index end overflow"))?;
                    (size, size, decoded)
                }
                INDEX_ZLIB => {
                    let sizes =
                        archive.read_physical_vec(position, 16, "compressed XP3 index sizes")?;
                    let stored = read_u64(&sizes, 0)?;
                    let original = read_u64(&sizes, 8)?;
                    position = position
                        .checked_add(16)
                        .ok_or_else(|| Error::format("compressed XP3 index position overflow"))?;
                    let stored_usize = to_usize(stored, "compressed XP3 index size")?;
                    let original_usize = to_usize(original, "decoded XP3 index size")?;
                    let compressed = archive.read_physical_vec(
                        position,
                        stored_usize,
                        "compressed XP3 index",
                    )?;
                    let decoded = zlib_decode_exact(&compressed, original_usize)?;
                    position = position
                        .checked_add(stored)
                        .ok_or_else(|| Error::format("compressed XP3 index end overflow"))?;
                    (stored, original, decoded)
                }
                _ => {
                    return Err(Error::unsupported(format!(
                        "XP3 index encoding method {method}"
                    )))
                }
            };

            let block_index = archive.index_blocks.len();
            walk_root_chunks(
                &decoded,
                block_index,
                archive.storage.len(),
                options.tolerant,
                &mut archive.root_chunks,
                &mut archive.hxv4,
                &mut archive.entries,
                &mut pending_alt_name,
                &mut pending_alt_hash,
            )?;

            archive.index_blocks.push(IndexBlock {
                physical_offset: absolute,
                flags,
                stored_size,
                original_size,
                decoded,
            });

            if flags & INDEX_CONTINUE == 0 {
                completed = true;
                break;
            }
            pointer_pos = position;

            if block_no == 1_000_000 {
                return Err(Error::format("unreasonable XP3 index chain"));
            }
        }

        if !completed {
            return Err(Error::format("unreachable XP3 index parser state"));
        }

        archive.prune_hxv4_protected_warning_entry()?;
        archive.initialize_special_index_blobs();
        Ok(archive)
    }

    fn read_physical_vec(&self, offset: u64, size: usize, what: &str) -> Result<Vec<u8>> {
        self.storage.read_vec(offset, size, what)
    }

    fn append_physical_range(
        &self,
        offset: u64,
        size: usize,
        out: &mut Vec<u8>,
        what: &str,
    ) -> Result<()> {
        self.storage.append_range(offset, size, out, what)
    }

    fn prune_hxv4_protected_warning_entry(&mut self) -> Result<()> {
        if self.hxv4.is_none() {
            return Ok(());
        }
        let Some(entry_index) = self.entries.iter().position(|entry| {
            entry.hxv4_id == Some(0)
                && entry.segments.len() == 1
                && entry.segments[0].flags & SEGM_METHOD_MASK == SEGM_RAW
        }) else {
            return Ok(());
        };

        let segment = &self.entries[entry_index].segments[0];
        let prefix_len = usize::try_from(segment.archive_size)
            .unwrap_or(usize::MAX)
            .min(HXV4_PROTECTED_WARNING_PREFIX.len());
        if prefix_len != HXV4_PROTECTED_WARNING_PREFIX.len() {
            return Ok(());
        }
        let prefix = self.read_physical_vec(
            segment.archive_offset,
            prefix_len,
            "Hxv4 protected-warning prefix",
        )?;
        if prefix != HXV4_PROTECTED_WARNING_PREFIX {
            return Ok(());
        }

        let removed = self.entries.remove(entry_index);
        if let Some(root) = self
            .root_chunks
            .iter_mut()
            .find(|root| root.kind == RootKind::File && root.inferred_hxv4_id == Some(0))
        {
            root.kind = RootKind::ProtectedFile;
            root.inferred_name = Some(removed.name);
        }
        Ok(())
    }

    fn initialize_special_index_blobs(&mut self) {
        for (root_index, root) in self.root_chunks.iter().enumerate() {
            if matches!(
                root.kind,
                RootKind::SpecialIndexV1
                    | RootKind::SpecialIndexV2
                    | RootKind::SpecialIndexV3
                    | RootKind::SpecialIndexGeneric
                    | RootKind::Hxv4SpecialIndex
            ) && root.inferred_offset.is_some()
                && root.inferred_archive_size.is_some()
            {
                self.special_index_blobs.entry(root_index).or_default();
            }
        }
    }

    /// Return the complete physical archive bytes.
    ///
    /// `Archive::open` stays file-backed unless this legacy accessor is actually
    /// called. For compatibility with the original API, an explicit call lazily
    /// materializes and caches the whole file. Normal extraction and Special
    /// accessors never call this method.
    pub fn physical_bytes(&self) -> &[u8] {
        if let Some(bytes) = self.storage.memory_bytes() {
            return bytes;
        }
        self.physical_cache
            .get_or_init(|| {
                let size = to_usize(self.storage.len(), "physical archive size")
                    .expect("physical archive size does not fit usize");
                self.storage
                    .read_vec(0, size, "physical archive")
                    .expect("failed to materialize physical archive")
            })
            .as_slice()
    }

    pub fn physical_size(&self) -> u64 {
        self.storage.len()
    }

    /// Read an exact physical range from the archive. This is primarily used by
    /// the round-trip manifest builder to retain small out-of-line payloads
    /// (for example protected-dummy storage) without materializing the whole XP3.
    pub fn physical_range(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        self.read_physical_vec(offset, size, "XP3 physical range")
    }

    pub fn is_file_backed(&self) -> bool {
        matches!(&self.storage, PhysicalStorage::File { .. })
    }

    pub fn is_hxv4(&self) -> bool {
        self.hxv4.is_some()
    }

    /// Return every structurally recognized out-of-line Special/name root.
    /// The four-byte root magic is intentionally ignored: vendors can rename
    /// it without changing the protection algorithm.
    pub fn indirect_special_roots(&self) -> Vec<usize> {
        self.root_chunks
            .iter()
            .enumerate()
            .filter_map(|(index, root)| {
                matches!(
                    root.kind,
                    RootKind::SpecialIndexV1
                        | RootKind::SpecialIndexV2
                        | RootKind::SpecialIndexV3
                        | RootKind::SpecialIndexGeneric
                )
                .then_some(index)
            })
            .collect()
    }

    /// Historical four-byte tag hints retained only for diagnostics and
    /// compatibility. Never use this to choose a CXDEC generation.
    pub fn known_cxdec_name_tag_hints(
        &self,
    ) -> Vec<(usize, crate::cxdec_names::CxdecNameSectionKind)> {
        self.root_chunks
            .iter()
            .enumerate()
            .filter_map(|(index, root)| {
                crate::cxdec_names::CxdecNameSectionKind::from_known_tag_hint(
                    root.magic.to_le_bytes(),
                )
                .map(|kind| (index, kind))
            })
            .collect()
    }

    /// Decode one structurally selected Special/name payload with an already
    /// recovered native profile. The root tag is not consulted.
    pub fn decode_cxdec_names_at(
        &self,
        root_index: usize,
        profile: crate::cxdec_names::CxdecNameProfile,
    ) -> Result<crate::cxdec_names::CxdecNameMap> {
        let root = self
            .root_chunks
            .get(root_index)
            .ok_or_else(|| Error::format("CXDEC filename root index is out of range"))?;
        if !matches!(
            root.kind,
            RootKind::SpecialIndexV1
                | RootKind::SpecialIndexV2
                | RootKind::SpecialIndexV3
                | RootKind::SpecialIndexGeneric
        ) {
            return Err(Error::format(
                "selected root is not a structurally recognized indirect Special index",
            ));
        }
        let stored = self
            .special_index_bytes_for_root(root_index)
            .ok_or_else(|| Error::format("CXDEC filename section payload is unavailable"))?;
        let token_suffix = match (profile, root.kind) {
            (crate::cxdec_names::CxdecNameProfile::Senren, RootKind::SpecialIndexV1) => {
                root.inferred_name.as_deref()
            }
            _ => None,
        };
        profile.decode_with_token_suffix(stored, token_suffix)
    }

    /// Compatibility helper for callers that explicitly chose a historical
    /// tag profile. Automatic recovery must use `decode_cxdec_names_at`.
    pub fn decode_cxdec_names(
        &self,
        profile: crate::cxdec_names::CxdecNameProfile,
    ) -> Result<(usize, crate::cxdec_names::CxdecNameMap)> {
        let expected = profile.section_id();
        let root_index = self
            .known_cxdec_name_tag_hints()
            .into_iter()
            .find(|(_, kind)| kind.section_id() == expected)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                Error::format(format!(
                    "XP3 index has no compatibility tag {}",
                    String::from_utf8_lossy(&expected)
                ))
            })?;
        Ok((root_index, self.decode_cxdec_names_at(root_index, profile)?))
    }

    /// Decode a structurally selected metadata root and populate
    /// `alternate_name` by the exact GARbro lookup policy (visible shortcut/MD5
    /// token, then `adlr` hash). The root tag is never consulted.
    pub fn apply_cxdec_names_at(
        &mut self,
        root_index: usize,
        profile: crate::cxdec_names::CxdecNameProfile,
    ) -> Result<crate::cxdec_names::CxdecNameApplyReport> {
        let kind = profile.kind();
        let names = self.decode_cxdec_names_at(root_index, profile)?;
        let mut mapped_entries = 0usize;
        for entry in &mut self.entries {
            let resolved = names.resolve(entry.adler, &entry.name);
            if resolved != entry.name {
                entry.alternate_name = Some(resolved.to_string());
                mapped_entries += 1;
            }
        }
        Ok(crate::cxdec_names::CxdecNameApplyReport {
            section_root_index: root_index,
            kind,
            mapped_entries,
            unresolved_entries: self.entries.len().saturating_sub(mapped_entries),
        })
    }

    /// Compatibility helper for explicit historical-tag callers. Automatic
    /// recovery must use `apply_cxdec_names_at`.
    pub fn apply_cxdec_names(
        &mut self,
        profile: crate::cxdec_names::CxdecNameProfile,
    ) -> Result<crate::cxdec_names::CxdecNameApplyReport> {
        let expected = profile.section_id();
        let root_index = self
            .known_cxdec_name_tag_hints()
            .into_iter()
            .find(|(_, kind)| kind.section_id() == expected)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                Error::format(format!(
                    "XP3 index has no compatibility tag {}",
                    String::from_utf8_lossy(&expected)
                ))
            })?;
        self.apply_cxdec_names_at(root_index, profile)
    }

    /// `startup.tjs` is a bootstrap anchor of the main `data.xp3`, not an
    /// invariant of every HXV4 archive.  Only the filesystem-backed data archive
    /// may canonicalize its sole ordinary entry; sibling voice/image/etc. XP3s
    /// retain their original names and are never relabeled as startup.
    fn normalize_hxv4_data_startup_anchor(&mut self) {
        if self.hxv4.is_none() {
            return;
        }
        let is_data_xp3 = self
            .path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("data.xp3"));
        if !is_data_xp3 {
            return;
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.name.eq_ignore_ascii_case("startup.tjs"))
        {
            return;
        }
        let ordinary: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.hxv4_id.is_none().then_some(index))
            .collect();
        if ordinary.len() == 1 {
            self.entries[ordinary[0]].name = "startup.tjs".to_string();
        }
    }

    /// Return the opaque Hxv4 special-index blob exactly as stored in the archive.
    /// Decryption requires title-specific Hxv4 index keys and is intentionally
    /// separate from standard XP3 index reconstruction.
    pub fn hxv4_special_index_bytes(&self) -> Option<&[u8]> {
        let descriptor = self.hxv4.as_ref()?;
        self.special_index_bytes_for_root(descriptor.root_chunk_index)
    }

    /// Return an out-of-line blob referenced by any recognized/structurally
    /// inferred special-index root.  This is used by the binwalk-style scanner
    /// and never changes the normal XP3 extraction path.
    pub fn special_index_bytes_for_root(&self, root_index: usize) -> Option<&[u8]> {
        let root = self.root_chunks.get(root_index)?;
        if !matches!(
            root.kind,
            RootKind::SpecialIndexV1
                | RootKind::SpecialIndexV2
                | RootKind::SpecialIndexV3
                | RootKind::SpecialIndexGeneric
                | RootKind::Hxv4SpecialIndex
        ) {
            return None;
        }
        let offset = root.inferred_offset?;
        let stored_size = root.inferred_archive_size?;
        let cell = self.special_index_blobs.get(&root_index)?;
        let blob = cell.get_or_init(|| {
            let size = to_usize(stored_size, "special-index stored size").ok()?;
            self.read_physical_vec(offset, size, "special-index blob")
                .ok()
        });
        blob.as_deref()
    }

    /// Reconstruct an entry strictly from its raw/zlib `segm` records, without using
    /// the `info` original/archive size fields as a final consistency check.
    ///
    /// Protected CXDEC archives can deliberately falsify `info` sizes while
    /// leaving the segment descriptors usable.  Callers must opt into this
    /// method only after independently identifying such an index.  The parsed
    /// `info` metadata remains untouched, so repacking can preserve it exactly.
    pub fn reconstruct_entry_segments(&self, index: usize) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| Error::invalid("entry index out of range"))?;
        let segment_capacity = entry.segments.iter().try_fold(0usize, |total, segment| {
            let size = to_usize(segment.original_size, "segment original size")?;
            total
                .checked_add(size)
                .ok_or_else(|| Error::invalid("segment original-size sum overflow"))
        })?;
        let mut out = Vec::with_capacity(segment_capacity);

        for (segment_index, segment) in entry.segments.iter().enumerate() {
            let stored = to_usize(segment.archive_size, "segment archive size")?;
            let original = to_usize(segment.original_size, "segment original size")?;

            match segment.flags & SEGM_METHOD_MASK {
                SEGM_RAW => {
                    if stored != original {
                        return Err(Error::format(format!(
                            "raw XP3 segment size mismatch: entry[{index}] name={:?} segment={} flags=0x{:08x} offset={} original={} archive={}",
                            entry.preferred_name(),
                            segment_index,
                            segment.flags,
                            segment.archive_offset,
                            segment.original_size,
                            segment.archive_size
                        )));
                    }
                    self.append_physical_range(
                        segment.archive_offset,
                        stored,
                        &mut out,
                        "XP3 raw segment",
                    )?;
                }
                SEGM_ZLIB => {
                    let source = self.read_physical_vec(
                        segment.archive_offset,
                        stored,
                        "XP3 compressed segment",
                    )?;
                    zlib_decode_append_exact(&source, original, &mut out)?;
                }
                method => {
                    return Err(Error::unsupported(format!(
                        "XP3 segment encoding method {method}: entry[{index}] name={:?} segment={} flags=0x{:08x}",
                        entry.preferred_name(),
                        segment_index,
                        segment.flags
                    )))
                }
            }
        }
        Ok(out)
    }

    pub fn reconstruct_entry(&self, index: usize) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| Error::invalid("entry index out of range"))?;
        let capacity = to_usize(entry.original_size, "entry original size")?;
        let out = self.reconstruct_entry_segments(index)?;

        if out.len() == capacity {
            return Ok(out);
        }

        // Some historical/protected XP3 variants describe the stored stream in
        // `segm` while `info` carries the post-zlib size.  Old KrkrExtract also
        // had an entry-level decompression path.  If the normally reconstructed
        // bytes equal info.archive_size, try one exact zlib layer before
        // declaring the entry malformed.  Exact decode + exact expected length
        // makes this a conservative compatibility fallback rather than a guess.
        let entry_archive_size = to_usize(entry.archive_size, "entry archive size")?;
        if out.len() == entry_archive_size && entry_archive_size != capacity {
            if let Ok(decoded) = zlib_decode_exact(&out, capacity) {
                return Ok(decoded);
            }
        }

        let segments = entry
            .segments
            .iter()
            .enumerate()
            .map(|(i, s)| {
                format!(
                    "#{i}:flags=0x{:08x},off={},orig={},arc={}",
                    s.flags, s.archive_offset, s.original_size, s.archive_size
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(Error::format(format!(
            "reconstructed entry size mismatch: entry[{index}] name={:?} info_flags=0x{:08x} expected_original={} info_archive={} got={} segments=[{}]",
            entry.preferred_name(),
            entry.flags,
            entry.original_size,
            entry.archive_size,
            out.len(),
            segments
        )))
    }

    /// Return the concatenated stored bytes referenced by an entry's segments
    /// without applying XP3 segment decompression.  This is intended for
    /// diagnostics when reconstruction fails, so the CLI can preserve evidence
    /// instead of aborting an entire archive.
    pub fn stored_entry_bytes(&self, index: usize) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| Error::invalid("entry index out of range"))?;
        let capacity = to_usize(entry.archive_size, "entry archive size").unwrap_or(0);
        let mut out = Vec::with_capacity(capacity);
        for segment in &entry.segments {
            let stored = to_usize(segment.archive_size, "segment archive size")?;
            self.append_physical_range(
                segment.archive_offset,
                stored,
                &mut out,
                "XP3 stored segment",
            )?;
        }
        Ok(out)
    }

    /// Validate the standard XP3 `adlr` checksum against provided plaintext.
    pub fn adler_matches(&self, index: usize, plaintext: &[u8]) -> Result<Option<bool>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| Error::invalid("entry index out of range"))?;
        Ok(entry.adler.map(|expected| adler32(plaintext) == expected))
    }
}

fn walk_root_chunks(
    decoded: &[u8],
    block_index: usize,
    physical_size: u64,
    tolerant: bool,
    root_chunks: &mut Vec<RootChunk>,
    hxv4: &mut Option<Hxv4Descriptor>,
    entries: &mut Vec<Entry>,
    pending_alt_name: &mut Option<String>,
    pending_alt_hash: &mut Option<u32>,
) -> Result<()> {
    let mut position = 0usize;
    while position + 12 <= decoded.len() {
        let tag = read_u32(decoded, position)?;
        let length64 = read_u64(decoded, position + 4)?;
        let Ok(length) = usize::try_from(length64) else {
            if tolerant {
                position += 1;
                continue;
            }
            return Err(Error::format("root chunk length does not fit usize"));
        };
        let Some(body_start) = position.checked_add(12) else {
            return Err(Error::format("root chunk offset overflow"));
        };
        if body_start > decoded.len() || length > decoded.len() - body_start {
            if tolerant {
                position += 1;
                continue;
            }
            return Err(Error::format("malformed XP3 root chunk length"));
        }
        let body = &decoded[body_start..body_start + length];
        let mut root = classify_root(tag, length64, body, block_index, position, physical_size);

        match root.kind {
            RootKind::Hxv4SpecialIndex => {
                if hxv4.is_none() {
                    if let (Some(offset), Some(stored_size), Some(kind)) = (
                        root.inferred_offset,
                        root.inferred_archive_size,
                        root.inferred_hxv4_kind,
                    ) {
                        *hxv4 = Some(Hxv4Descriptor {
                            offset,
                            stored_size,
                            kind,
                            root_chunk_index: root_chunks.len(),
                        });
                    }
                }
                // Hxv4 does not use an M2 alternate-name record for its synthetic
                // lookup ids. Do not let a stale heuristic name bleed across it.
                *pending_alt_name = None;
                *pending_alt_hash = None;
            }
            RootKind::AlternateName => {
                *pending_alt_name = root.inferred_name.clone();
                *pending_alt_hash = root.inferred_hash;
            }
            RootKind::File => {
                // An M2-style alternate-name chunk belongs to exactly the next
                // `File` chunk, so consume it even if the file body is malformed.
                let alternate_name = pending_alt_name.take();
                let alternate_hash = pending_alt_hash.take();

                // Historical KrkrExtract has a dedicated protected-node validator.
                // For M2-shaped entries it checks the alternate name; otherwise it
                // checks the normal `info` name.  Do this before requiring `segm`,
                // because the synthetic warning node is not a real resource.
                let protected_name = if let Some(name) = alternate_name.as_deref() {
                    is_protected_dummy_name(name).then(|| name.to_string())
                } else {
                    protected_dummy_name_from_file_chunk(body)?
                };

                if let Some(name) = protected_name {
                    root.kind = RootKind::ProtectedFile;
                    root.inferred_name = Some(name);
                    root.inferred_hash = alternate_hash;
                } else if let Some(mut entry) = parse_file_chunk(body)? {
                    entry.root_chunk_index = Some(root_chunks.len());
                    entry.alternate_name = alternate_name;
                    entry.alternate_hash = alternate_hash;

                    // In Hxv4 archives the normal XP3 `info` name is deliberately
                    // a synthetic Unicode encoding of entry_id, not the original
                    // filename.  Decode it only after seeing a literal Hxv4 root so
                    // ordinary Japanese filenames in non-Hx archives are untouched.
                    if hxv4.is_some() {
                        entry.hxv4_id = hxv4_fake_id(&entry.name);
                        root.inferred_hxv4_id = entry.hxv4_id;
                    }

                    // Modern Hxv4 hides the protected warning behind fake id 0.
                    // File-backed parsing cannot inspect its segment bytes while
                    // walking the decoded index, so keep the entry for now and
                    // prune it in `Archive::prune_hxv4_protected_warning_entry`.
                    entries.push(entry);
                }
            }
            _ => {}
        }

        root_chunks.push(root);
        position = body_start + length;
    }
    Ok(())
}

fn protected_dummy_name_from_file_chunk(body: &[u8]) -> Result<Option<String>> {
    let mut position = 0usize;

    while position + 12 <= body.len() {
        let tag = read_u32(body, position)?;
        let length64 = read_u64(body, position + 4)?;
        let Ok(length) = usize::try_from(length64) else {
            return Ok(None);
        };
        let body_start = position + 12;
        if body_start > body.len() || length > body.len() - body_start {
            return Ok(None);
        }

        if tag == TAG_INFO {
            let chunk = &body[body_start..body_start + length];
            if chunk.len() >= 22 {
                let chars = read_u16(chunk, 20)? as usize;
                let Some(byte_len) = chars.checked_mul(2) else {
                    return Ok(None);
                };
                if 22 + byte_len <= chunk.len() {
                    let name = decode_utf16le_lossy(&chunk[22..22 + byte_len]);
                    if is_protected_dummy_name(&name) {
                        return Ok(Some(name));
                    }
                }
            }
        }

        position = body_start + length;
    }

    Ok(None)
}

fn parse_file_chunk(body: &[u8]) -> Result<Option<Entry>> {
    let mut entry = Entry::default();
    let mut have_info = false;
    let mut have_segments = false;
    let mut position = 0usize;

    while position + 12 <= body.len() {
        let tag = read_u32(body, position)?;
        let length64 = read_u64(body, position + 4)?;
        let Ok(length) = usize::try_from(length64) else {
            return Ok(None);
        };
        let body_start = position + 12;
        if body_start > body.len() || length > body.len() - body_start {
            return Ok(None);
        }
        let chunk = &body[body_start..body_start + length];

        match tag {
            TAG_INFO if chunk.len() >= 22 => {
                entry.flags = read_u32(chunk, 0)?;
                entry.original_size = read_u64(chunk, 4)?;
                entry.archive_size = read_u64(chunk, 12)?;
                let raw_chars = read_u16(chunk, 20)?;
                entry.info_name_length = raw_chars;
                let chars = raw_chars as usize;
                let byte_len = chars
                    .checked_mul(2)
                    .ok_or_else(|| Error::format("XP3 filename length overflow"))?;
                if 22 + byte_len <= chunk.len() {
                    entry.name = decode_utf16le_lossy(&chunk[22..22 + byte_len]);
                    have_info = true;
                }
            }
            TAG_SEGM if !chunk.is_empty() && chunk.len() % 28 == 0 => {
                for segment in chunk.chunks_exact(28) {
                    let flags = read_u32(segment, 0)?;
                    // XP3 `segm` offsets are physical archive-file offsets.
                    // They are not relative to an embedded XP3 signature.  This
                    // also matches historical KrkrExtract, which seeks the
                    // stored offset from FILE_BEGIN.
                    let archive_offset = read_u64(segment, 4)?;
                    entry.segments.push(Segment {
                        flags,
                        archive_offset,
                        original_size: read_u64(segment, 12)?,
                        archive_size: read_u64(segment, 20)?,
                    });
                }
                have_segments = !entry.segments.is_empty();
            }
            TAG_ADLR if chunk.len() >= 4 => {
                entry.adler = Some(read_u32(chunk, 0)?);
            }
            TAG_TIME => {}
            _ => {}
        }

        position = body_start + length;
    }

    Ok((have_info && have_segments).then_some(entry))
}

fn classify_root(
    magic: u32,
    size: u64,
    body: &[u8],
    block_index: usize,
    block_offset: usize,
    physical_size: u64,
) -> RootChunk {
    let mut root = RootChunk {
        magic,
        size,
        index_block: block_index,
        index_offset: block_offset,
        kind: RootKind::Unknown,
        inferred_name: None,
        inferred_hash: None,
        inferred_offset: None,
        inferred_original_size: None,
        inferred_archive_size: None,
        inferred_hxv4_kind: None,
        inferred_hxv4_id: None,
    };

    if magic == TAG_HXV4 && body.len() == 14 {
        let offset = le_u64_unchecked(&body[0..8]);
        let stored = le_u32_unchecked(&body[8..12]) as u64;
        let kind = u16::from_le_bytes([body[12], body[13]]);
        if offset < physical_size
            && stored > 0
            && offset
                .checked_add(stored)
                .is_some_and(|end| end <= physical_size)
        {
            root.kind = RootKind::Hxv4SpecialIndex;
            root.inferred_offset = Some(offset);
            root.inferred_archive_size = Some(stored);
            root.inferred_hxv4_kind = Some(kind);
            return root;
        }
    }

    if magic == TAG_FILE {
        root.kind = RootKind::File;
        return root;
    }

    // Historical M2/KrkrZ alternate-name shape:
    // hash:u32, filename_length:u16, UTF-16LE filename. The 4-byte root magic is
    // intentionally not used as the classifier.
    if body.len() >= 6 {
        let chars = u16::from_le_bytes([body[4], body[5]]) as usize;
        if chars <= 4096 {
            if let Some(name_end) = chars.checked_mul(2).and_then(|n| 6usize.checked_add(n)) {
                // Historical variants are either exact-length or carry one
                // trailing UTF-16 NUL. Requiring that shape avoids treating an
                // arbitrary long unknown chunk as an alternate-name record.
                let exact = name_end == body.len();
                let nul_terminated =
                    name_end + 2 == body.len() && body[name_end] == 0 && body[name_end + 1] == 0;
                if exact || nul_terminated {
                    let name = decode_utf16le_lossy(&body[6..name_end]);
                    if plausible_name(&name) {
                        root.kind = RootKind::AlternateName;
                        root.inferred_hash =
                            Some(u32::from_le_bytes([body[0], body[1], body[2], body[3]]));
                        root.inferred_name = Some(name);
                        return root;
                    }
                }
            }
        }
    }

    // Historical indirect-index descriptor V1 shape:
    // offset:u64, original_size:u32, archive_size:u32, product_len:u16, UTF-16LE product.
    if body.len() >= 18 {
        let offset = le_u64_unchecked(&body[0..8]);
        let original = le_u32_unchecked(&body[8..12]) as u64;
        let stored = le_u32_unchecked(&body[12..16]) as u64;
        let chars = u16::from_le_bytes([body[16], body[17]]) as usize;
        let target_ok = offset < physical_size
            && stored > 0
            && offset
                .checked_add(stored)
                .is_some_and(|end| end <= physical_size)
            && original > 0;
        if target_ok && chars <= 4096 {
            if let Some(end) = chars.checked_mul(2).and_then(|n| 18usize.checked_add(n)) {
                if end <= body.len() {
                    root.kind = RootKind::SpecialIndexV1;
                    root.inferred_offset = Some(offset);
                    root.inferred_original_size = Some(original);
                    root.inferred_archive_size = Some(stored);
                    if chars != 0 {
                        root.inferred_name = Some(decode_utf16le_lossy(&body[18..end]));
                    }
                    return root;
                }
            }
        }
    }

    // Historical V2 shape: offset:u64, original_size:u32, archive_size:u32.
    if body.len() == 16 {
        let offset = le_u64_unchecked(&body[0..8]);
        let original = le_u32_unchecked(&body[8..12]) as u64;
        let stored = le_u32_unchecked(&body[12..16]) as u64;
        if offset < physical_size
            && stored > 0
            && offset
                .checked_add(stored)
                .is_some_and(|end| end <= physical_size)
            && original > 0
        {
            root.kind = RootKind::SpecialIndexV2;
            root.inferred_offset = Some(offset);
            root.inferred_original_size = Some(original);
            root.inferred_archive_size = Some(stored);
            return root;
        }
    }

    // Historical V3 shape: offset:u64, archive_size:u32, kind:u16.
    if body.len() == 14 {
        let offset = le_u64_unchecked(&body[0..8]);
        let stored = le_u32_unchecked(&body[8..12]) as u64;
        let kind = u16::from_le_bytes([body[12], body[13]]);
        if matches!(kind, 0 | 1)
            && offset < physical_size
            && stored > 0
            && offset
                .checked_add(stored)
                .is_some_and(|end| end <= physical_size)
        {
            root.kind = RootKind::SpecialIndexV3;
            root.inferred_offset = Some(offset);
            root.inferred_archive_size = Some(stored);
            return root;
        }
    }

    // Future/unknown special-index descriptors often keep an absolute u64
    // offset + u32 stored-size tuple while changing the root FourCC or adding
    // small flag/version fields.  Probe a short unknown body for a *unique*
    // plausible tuple.  This classification is diagnostic only: no decoder is
    // selected from it, so false positives cannot corrupt known extraction paths.
    if body.len() >= 12 && body.len() <= 64 {
        let mut candidate = None;
        for at in 0..=body.len() - 12 {
            let offset = le_u64_unchecked(&body[at..at + 8]);
            let stored = le_u32_unchecked(&body[at + 8..at + 12]) as u64;
            let valid = stored >= 16
                && offset < physical_size
                && offset
                    .checked_add(stored)
                    .is_some_and(|end| end <= physical_size);
            if valid {
                if candidate.is_some() {
                    candidate = None;
                    break;
                }
                candidate = Some((offset, stored));
            }
        }
        if let Some((offset, stored)) = candidate {
            root.kind = RootKind::SpecialIndexGeneric;
            root.inferred_offset = Some(offset);
            root.inferred_archive_size = Some(stored);
            return root;
        }
    }

    root
}

/// Encode an Hxv4 entry id into the synthetic Unicode name stored in XP3 `info`.
pub fn hxv4_fake_name(mut id: u64) -> String {
    let mut words = Vec::new();
    loop {
        words.push(0x5000u16 + (id as u16 & 0x3fff));
        id >>= 14;
        if id == 0 {
            break;
        }
    }
    String::from_utf16_lossy(&words)
}

/// Decode the canonical Hxv4 synthetic Unicode `info` name back to its entry id.
///
/// The function intentionally rejects non-canonical encodings and is only used
/// automatically after a literal `Hxv4` root has identified the archive family.
pub fn hxv4_fake_id(name: &str) -> Option<u64> {
    let words: Vec<u16> = name.encode_utf16().collect();
    if words.is_empty() || words.len() > 5 {
        return None;
    }
    let mut id = 0u64;
    for (i, word) in words.iter().copied().enumerate() {
        if !(0x5000..=0x8fff).contains(&word) {
            return None;
        }
        let part = (word - 0x5000) as u64;
        let shift = i * 14;
        if shift >= 64 {
            return None;
        }
        if shift > 50 && part >= (1u64 << (64 - shift)) {
            return None;
        }
        id |= part << shift;
    }
    (hxv4_fake_name(id) == name).then_some(id)
}

fn find_xp3_storage(storage: &PhysicalStorage) -> Result<u64> {
    if let Some(bytes) = storage.memory_bytes() {
        return find_xp3(bytes);
    }

    let len = storage.len();
    if len < XP3_MAGIC.len() as u64 {
        return Err(Error::format("XP3 signature not found"));
    }
    let prefix_len = XP3_MAGIC.len().max(2);
    let prefix = storage.read_vec(0, prefix_len, "XP3 signature prefix")?;
    if prefix.starts_with(&XP3_MAGIC) {
        return Ok(0);
    }

    // Historical self-extracting/embedded XP3 archives are searched only when
    // the physical file itself is an MZ image, matching the in-memory parser.
    if !prefix.starts_with(b"MZ") {
        return Err(Error::format("XP3 signature not found"));
    }

    const SCAN_CHUNK: usize = 1024 * 1024;
    let overlap = XP3_MAGIC.len() - 1;
    let mut base = 0u64;
    while base < len {
        let remaining = len - base;
        let want = remaining.min((SCAN_CHUNK + overlap) as u64) as usize;
        let chunk = storage.read_vec(base, want, "embedded XP3 scan window")?;

        let first_global = base.max(0x10);
        let aligned = (first_global + 0x0f) & !0x0f;
        let mut position = aligned;
        let chunk_end = base + chunk.len() as u64;
        while position
            .checked_add(XP3_MAGIC.len() as u64)
            .is_some_and(|end| end <= chunk_end && end <= len)
        {
            let local = (position - base) as usize;
            if chunk[local..].starts_with(&XP3_MAGIC) {
                return Ok(position);
            }
            position += 0x10;
        }

        if remaining <= SCAN_CHUNK as u64 {
            break;
        }
        base += SCAN_CHUNK as u64;
    }

    Err(Error::format("XP3 signature not found"))
}

fn find_xp3(bytes: &[u8]) -> Result<u64> {
    if bytes.starts_with(&XP3_MAGIC) {
        return Ok(0);
    }

    // For an XP3 embedded in an MZ image, search paragraph-aligned positions.
    if bytes.starts_with(b"MZ") {
        let mut position = 0x10usize;
        while position + XP3_MAGIC.len() <= bytes.len() {
            if bytes[position..].starts_with(&XP3_MAGIC) {
                return Ok(position as u64);
            }
            position += 0x10;
        }
    }

    Err(Error::format("XP3 signature not found"))
}

fn zlib_decode_exact(source: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(source);
    let mut out = Vec::with_capacity(expected_size);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::format(format!("zlib decompression failed: {e}")))?;
    if out.len() != expected_size {
        return Err(Error::format(format!(
            "zlib size mismatch: expected {expected_size}, got {}",
            out.len()
        )));
    }
    Ok(out)
}

fn zlib_decode_append_exact(source: &[u8], expected_size: usize, out: &mut Vec<u8>) -> Result<()> {
    let start = out.len();
    let mut decoder = ZlibDecoder::new(source);
    if let Err(err) = decoder.read_to_end(out) {
        out.truncate(start);
        return Err(Error::format(format!("zlib decompression failed: {err}")));
    }
    let decoded = out.len() - start;
    if decoded != expected_size {
        out.truncate(start);
        return Err(Error::format(format!(
            "zlib size mismatch: expected {expected_size}, got {decoded}"
        )));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], position: usize) -> Result<u16> {
    require_range(bytes, position, 2, "u16")?;
    Ok(u16::from_le_bytes([bytes[position], bytes[position + 1]]))
}

fn read_u32(bytes: &[u8], position: usize) -> Result<u32> {
    require_range(bytes, position, 4, "u32")?;
    Ok(u32::from_le_bytes([
        bytes[position],
        bytes[position + 1],
        bytes[position + 2],
        bytes[position + 3],
    ]))
}

fn read_u64(bytes: &[u8], position: usize) -> Result<u64> {
    require_range(bytes, position, 8, "u64")?;
    Ok(le_u64_unchecked(&bytes[position..position + 8]))
}

fn le_u32_unchecked(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le_u64_unchecked(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::format(format!("{what} does not fit usize")))
}

fn require_range(bytes: &[u8], position: usize, length: usize, what: &str) -> Result<()> {
    if position > bytes.len() || length > bytes.len() - position {
        return Err(Error::format(format!("out of bounds while reading {what}")));
    }
    Ok(())
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16_lossy(&words)
}

fn plausible_name(name: &str) -> bool {
    if name.is_empty() || name.chars().count() > 4096 || name.contains('\0') {
        return false;
    }
    let total = name.chars().count();
    let printable = name.chars().filter(|c| !c.is_control()).count();
    let pathish = name
        .chars()
        .filter(|c| matches!(*c, '/' | '\\' | '.' | '_' | '-'))
        .count();
    printable * 10 >= total * 9 && (pathish > 0 || total >= 3)
}

pub fn tag_to_string(tag: u32) -> String {
    tag.to_le_bytes()
        .into_iter()
        .map(|b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

pub fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    // Chunking keeps additions bounded while avoiding a modulo per byte.
    for chunk in bytes.chunks(5_552) {
        for &value in chunk {
            a += value as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag);
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn make_xp3(payload: &[u8], compressed_index: bool) -> Vec<u8> {
        make_xp3_named(payload, compressed_index, "test.bin")
    }

    fn make_xp3_named(payload: &[u8], compressed_index: bool, name: &str) -> Vec<u8> {
        let name: Vec<u16> = name.encode_utf16().collect();

        let mut info = Vec::new();
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for word in &name {
            info.extend_from_slice(&word.to_le_bytes());
        }

        let data_offset = 19u64;
        let mut segm = Vec::new();
        segm.extend_from_slice(&0u32.to_le_bytes());
        segm.extend_from_slice(&data_offset.to_le_bytes());
        segm.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        segm.extend_from_slice(&(payload.len() as u64).to_le_bytes());

        let mut file_body = Vec::new();
        file_body.extend_from_slice(&chunk(b"info", &info));
        file_body.extend_from_slice(&chunk(b"segm", &segm));
        file_body.extend_from_slice(&chunk(b"adlr", &adler32(payload).to_le_bytes()));
        let index = chunk(b"File", &file_body);

        let index_offset = data_offset + payload.len() as u64;
        let mut archive = Vec::new();
        archive.extend_from_slice(&XP3_MAGIC);
        archive.extend_from_slice(&index_offset.to_le_bytes());
        archive.extend_from_slice(payload);

        if compressed_index {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&index).unwrap();
            let encoded = encoder.finish().unwrap();
            archive.push(INDEX_ZLIB);
            archive.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
            archive.extend_from_slice(&(index.len() as u64).to_le_bytes());
            archive.extend_from_slice(&encoded);
        } else {
            archive.push(INDEX_RAW);
            archive.extend_from_slice(&(index.len() as u64).to_le_bytes());
            archive.extend_from_slice(&index);
        }
        archive
    }

    fn make_senren_names_xp3(payload: &[u8], real_name: &str) -> Vec<u8> {
        let hash = adler32(payload);
        let units = real_name.encode_utf16().collect::<Vec<_>>();
        let mut names_plain = Vec::new();
        names_plain.extend_from_slice(b"name");
        names_plain.extend_from_slice(&(6i64 + units.len() as i64 * 2).to_le_bytes());
        names_plain.extend_from_slice(&hash.to_le_bytes());
        names_plain.extend_from_slice(&(units.len() as i16).to_le_bytes());
        for unit in units {
            names_plain.extend_from_slice(&unit.to_le_bytes());
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&names_plain).unwrap();
        let names_blob = encoder.finish().unwrap();

        let visible = "opaque".encode_utf16().collect::<Vec<_>>();
        let mut info = Vec::new();
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(visible.len() as u16).to_le_bytes());
        for word in visible {
            info.extend_from_slice(&word.to_le_bytes());
        }
        let data_offset = 19u64;
        let mut segm = Vec::new();
        segm.extend_from_slice(&0u32.to_le_bytes());
        segm.extend_from_slice(&data_offset.to_le_bytes());
        segm.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        segm.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        let mut file_body = Vec::new();
        file_body.extend_from_slice(&chunk(b"info", &info));
        file_body.extend_from_slice(&chunk(b"segm", &segm));
        file_body.extend_from_slice(&chunk(b"adlr", &hash.to_le_bytes()));

        let names_offset = data_offset + payload.len() as u64;
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&names_offset.to_le_bytes());
        descriptor.extend_from_slice(&(names_plain.len() as u32).to_le_bytes());
        descriptor.extend_from_slice(&(names_blob.len() as u32).to_le_bytes());
        let mut index = chunk(b"sen:", &descriptor);
        index.extend_from_slice(&chunk(b"File", &file_body));
        let index_offset = names_offset + names_blob.len() as u64;

        let mut archive = Vec::new();
        archive.extend_from_slice(&XP3_MAGIC);
        archive.extend_from_slice(&index_offset.to_le_bytes());
        archive.extend_from_slice(payload);
        archive.extend_from_slice(&names_blob);
        archive.push(INDEX_RAW);
        archive.extend_from_slice(&(index.len() as u64).to_le_bytes());
        archive.extend_from_slice(&index);
        archive
    }

    #[test]
    fn parses_and_reconstructs_raw_index() {
        let payload = b"hello xp3";
        let archive = Archive::from_bytes(make_xp3(payload, false)).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "test.bin");
        assert_eq!(archive.reconstruct_entry(0).unwrap().as_slice(), payload);
        assert_eq!(archive.adler_matches(0, payload).unwrap(), Some(true));
    }

    #[test]
    fn segment_only_reconstruction_ignores_obfuscated_info_sizes() {
        let payload = b"protected-index-segment-data";
        let mut archive = Archive::from_bytes(make_xp3(payload, false)).unwrap();
        let original_info = archive.entries[0].original_size;
        archive.entries[0].original_size = original_info + 753;
        archive.entries[0].archive_size = original_info + 753;

        assert_eq!(
            archive.reconstruct_entry_segments(0).unwrap().as_slice(),
            payload
        );
        assert!(archive.reconstruct_entry(0).is_err());
        assert_eq!(archive.entries[0].original_size, original_info + 753);
        assert_eq!(archive.entries[0].segments[0].original_size, original_info);
    }

    #[test]
    fn senren_section_is_detected_and_populates_real_entry_name() {
        let mut archive = Archive::from_bytes(make_senren_names_xp3(
            b"senren payload",
            "scenario/startup.ks",
        ))
        .unwrap();
        assert_eq!(
            archive.known_cxdec_name_tag_hints(),
            vec![(0, crate::cxdec_names::CxdecNameSectionKind::Senren)]
        );
        let detected = crate::filter_detection::detect_special_name_sections(&archive);
        assert_eq!(detected.len(), 1);
        assert_eq!(
            detected[0].profile,
            crate::filter_detection::SpecialNameProfile::OrderedEncrypted {
                section: "sen:".to_string(),
                encrypted_prefix: 0x100,
            }
        );
        assert_eq!(
            detected[0].confidence,
            crate::filter_detection::DetectionConfidence::Low
        );
        let report = archive
            .apply_cxdec_names(crate::cxdec_names::CxdecNameProfile::Senren)
            .unwrap();
        assert_eq!(report.mapped_entries, 1);
        assert_eq!(archive.entries[0].preferred_name(), "scenario/startup.ks");
    }

    #[test]
    fn renamed_special_tag_does_not_define_a_cxdec_family() {
        let mut bytes = make_senren_names_xp3(b"payload", "scenario/a.ks");
        // Replace only the root magic in the uncompressed index. The descriptor
        // structure and out-of-line payload remain unchanged.
        if let Some(pos) = bytes.windows(4).rposition(|w| w == b"sen:") {
            bytes[pos..pos + 4].copy_from_slice(b"vnd1");
        } else {
            panic!("fixture has no sen: root");
        }
        let archive = Archive::from_bytes(bytes).unwrap();
        assert!(archive.known_cxdec_name_tag_hints().is_empty());
        assert_eq!(archive.indirect_special_roots(), vec![0]);
        let detected = crate::filter_detection::detect_special_name_sections(&archive);
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].confidence, crate::filter_detection::DetectionConfidence::None);
    }

    #[test]
    fn open_keeps_archive_file_backed() {
        let payload = b"file-backed XP3 payload";
        let bytes = make_xp3(payload, false);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "krkr-xp3-brute-file-backed-{}-{unique}.xp3",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::open(&path).unwrap();
        assert!(archive.is_file_backed());
        assert_eq!(archive.physical_size(), bytes.len() as u64);
        assert!(archive.physical_cache.get().is_none());
        assert_eq!(archive.reconstruct_entry(0).unwrap().as_slice(), payload);
        assert!(archive.physical_cache.get().is_none());

        drop(archive);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reconstructs_entry_level_zlib_compatibility_stream() {
        let payload = vec![b'A'; 910];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&payload).unwrap();
        let stored = encoder.finish().unwrap();

        let name: Vec<u16> = "compressed.bin".encode_utf16().collect();
        let mut info = Vec::new();
        info.extend_from_slice(&1u32.to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(stored.len() as u64).to_le_bytes());
        info.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for word in &name {
            info.extend_from_slice(&word.to_le_bytes());
        }

        let data_offset = 19u64;
        let mut segm = Vec::new();
        segm.extend_from_slice(&SEGM_RAW.to_le_bytes());
        segm.extend_from_slice(&data_offset.to_le_bytes());
        // Historical/protected shape: segm describes the stored stream; info
        // describes the post-zlib stream.
        segm.extend_from_slice(&(stored.len() as u64).to_le_bytes());
        segm.extend_from_slice(&(stored.len() as u64).to_le_bytes());

        let mut file_body = Vec::new();
        file_body.extend_from_slice(&chunk(b"info", &info));
        file_body.extend_from_slice(&chunk(b"segm", &segm));
        file_body.extend_from_slice(&chunk(b"adlr", &adler32(&payload).to_le_bytes()));
        let index = chunk(b"File", &file_body);
        let index_offset = data_offset + stored.len() as u64;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&XP3_MAGIC);
        bytes.extend_from_slice(&index_offset.to_le_bytes());
        bytes.extend_from_slice(&stored);
        bytes.push(INDEX_RAW);
        bytes.extend_from_slice(&(index.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&index);

        let archive = Archive::from_bytes(bytes).unwrap();
        assert_eq!(archive.reconstruct_entry(0).unwrap(), payload);
    }

    #[test]
    fn embedded_xp3_segment_offsets_are_file_absolute() {
        let payload = b"embedded xp3 payload";
        let mut prefix = vec![0x90u8; 64];
        prefix[..2].copy_from_slice(b"MZ");
        let name: Vec<u16> = "embedded.bin".encode_utf16().collect();
        let mut info = Vec::new();
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        info.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for word in &name {
            info.extend_from_slice(&word.to_le_bytes());
        }

        let relative_data_offset = 19u64;
        let absolute_data_offset = prefix.len() as u64 + relative_data_offset;
        let mut segm = Vec::new();
        segm.extend_from_slice(&SEGM_RAW.to_le_bytes());
        segm.extend_from_slice(&absolute_data_offset.to_le_bytes());
        segm.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        segm.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        let mut file_body = Vec::new();
        file_body.extend_from_slice(&chunk(b"info", &info));
        file_body.extend_from_slice(&chunk(b"segm", &segm));
        let index = chunk(b"File", &file_body);
        let relative_index_offset = relative_data_offset + payload.len() as u64;

        let mut bytes = prefix;
        bytes.extend_from_slice(&XP3_MAGIC);
        bytes.extend_from_slice(&relative_index_offset.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.push(INDEX_RAW);
        bytes.extend_from_slice(&(index.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&index);

        let archive = Archive::from_bytes(bytes).unwrap();
        assert_eq!(archive.xp3_offset, 64);
        assert_eq!(archive.reconstruct_entry(0).unwrap().as_slice(), payload);
    }

    fn make_info_only_xp3(name: &str) -> Vec<u8> {
        let name: Vec<u16> = name.encode_utf16().collect();
        let mut info = Vec::new();
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&0u64.to_le_bytes());
        info.extend_from_slice(&0u64.to_le_bytes());
        info.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for word in &name {
            info.extend_from_slice(&word.to_le_bytes());
        }

        let index = chunk(b"File", &chunk(b"info", &info));
        let index_offset = 19u64;
        let mut archive = Vec::new();
        archive.extend_from_slice(&XP3_MAGIC);
        archive.extend_from_slice(&index_offset.to_le_bytes());
        archive.push(INDEX_RAW);
        archive.extend_from_slice(&(index.len() as u64).to_le_bytes());
        archive.extend_from_slice(&index);
        archive
    }

    #[test]
    fn skips_protected_archive_dummy_entry() {
        let payload = b"not a real resource";
        let protected_name = format!(
            "{} Warning! Extracting this archive may infringe on author's rights. txt",
            PROTECTED_DUMMY_PREFIX
        );
        let archive = Archive::from_bytes(make_xp3_named(payload, false, &protected_name)).unwrap();

        assert!(archive.entries.is_empty());
        assert_eq!(archive.root_chunks.len(), 1);
        assert_eq!(archive.root_chunks[0].kind, RootKind::ProtectedFile);
        assert_eq!(
            archive.root_chunks[0].inferred_name.as_deref(),
            Some(protected_name.as_str())
        );
    }

    #[test]
    fn recognizes_info_only_protected_dummy_before_segment_validation() {
        let protected_name = format!("{} synthetic warning.txt", PROTECTED_DUMMY_PREFIX);
        let archive = Archive::from_bytes(make_info_only_xp3(&protected_name)).unwrap();

        assert!(archive.entries.is_empty());
        assert_eq!(archive.root_chunks.len(), 1);
        assert_eq!(archive.root_chunks[0].kind, RootKind::ProtectedFile);
    }

    #[test]
    fn recognizes_legacy_protectet_typo_dummy() {
        let protected_name = format!(
            "{} localized warning.txt",
            PROTECTED_DUMMY_PREFIX_LEGACY_TYPO
        );
        let archive = Archive::from_bytes(make_info_only_xp3(&protected_name)).unwrap();
        assert!(archive.entries.is_empty());
        assert_eq!(archive.root_chunks[0].kind, RootKind::ProtectedFile);
    }

    #[test]
    fn hxv4_startup_canonicalization_is_data_archive_only() {
        let make = |path: &str| Archive {
            path: Some(PathBuf::from(path)),
            xp3_offset: 0,
            index_blocks: Vec::new(),
            root_chunks: Vec::new(),
            hxv4: Some(Hxv4Descriptor {
                offset: 0,
                stored_size: 64,
                kind: 0,
                root_chunk_index: 0,
            }),
            entries: vec![
                Entry {
                    name: hxv4_fake_name(1),
                    hxv4_id: Some(1),
                    ..Entry::default()
                },
                Entry {
                    name: "opaque-anchor-name".into(),
                    hxv4_id: None,
                    ..Entry::default()
                },
                Entry {
                    name: hxv4_fake_name(2),
                    hxv4_id: Some(2),
                    ..Entry::default()
                },
            ],
            storage: PhysicalStorage::Memory(Vec::new()),
            physical_cache: OnceLock::new(),
            special_index_blobs: HashMap::new(),
        };
        let mut data = make("/game/data.xp3");
        data.normalize_hxv4_data_startup_anchor();
        assert_eq!(data.entries[1].name, "startup.tjs");

        let mut voice = make("/game/voice.xp3");
        voice.normalize_hxv4_data_startup_anchor();
        assert_eq!(voice.entries[1].name, "opaque-anchor-name");
    }

    #[test]
    fn hxv4_fake_name_round_trips() {
        for id in [0u64, 1, 0x3fff, 0x4000, 0x1234567, u32::MAX as u64] {
            let name = hxv4_fake_name(id);
            assert_eq!(hxv4_fake_id(&name), Some(id));
        }
        assert_eq!(hxv4_fake_name(0), "倀");
        assert_eq!(hxv4_fake_name(1), "倁");
        assert_eq!(hxv4_fake_id("普通.tjs"), None);
    }

    #[test]
    fn hxv4_descriptor_marks_fake_names_and_skips_hidden_warning() {
        let warning =
            b"Warning: Extracting this archive may infringe on author's rights. protected";
        let payload = b"real encrypted resource bytes";

        // Physical layout: XP3 header/pointer, warning, resource, opaque Hxv4
        // special-index blob, then the ordinary XP3 index.
        let data_offset = 19u64;
        let warning_offset = data_offset;
        let resource_offset = warning_offset + warning.len() as u64;
        let special_offset = resource_offset + payload.len() as u64;
        let special_blob = vec![0xCCu8; 64];

        fn file_chunk(
            name: &str,
            info_original: u64,
            info_archive: u64,
            seg_offset: u64,
            seg_size: u64,
        ) -> Vec<u8> {
            let words: Vec<u16> = name.encode_utf16().collect();
            let mut info = Vec::new();
            info.extend_from_slice(&0u32.to_le_bytes());
            info.extend_from_slice(&info_original.to_le_bytes());
            info.extend_from_slice(&info_archive.to_le_bytes());
            info.extend_from_slice(&(words.len() as u16).to_le_bytes());
            for word in words {
                info.extend_from_slice(&word.to_le_bytes());
            }
            let mut segm = Vec::new();
            segm.extend_from_slice(&SEGM_RAW.to_le_bytes());
            segm.extend_from_slice(&seg_offset.to_le_bytes());
            segm.extend_from_slice(&seg_size.to_le_bytes());
            segm.extend_from_slice(&seg_size.to_le_bytes());
            let mut body = Vec::new();
            body.extend_from_slice(&chunk(b"info", &info));
            body.extend_from_slice(&chunk(b"segm", &segm));
            chunk(b"File", &body)
        }

        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&special_offset.to_le_bytes());
        descriptor.extend_from_slice(&(special_blob.len() as u32).to_le_bytes());
        descriptor.extend_from_slice(&0u16.to_le_bytes());

        let mut index = chunk(b"Hxv4", &descriptor);
        // This pseudo entry deliberately lies in `info` about its final size,
        // matching real Hxv4 protected archives. It must be filtered before
        // reconstruction ever sees the mismatch.
        index.extend_from_slice(&file_chunk(
            &hxv4_fake_name(0),
            910,
            910,
            warning_offset,
            warning.len() as u64,
        ));
        index.extend_from_slice(&file_chunk(
            &hxv4_fake_name(1),
            payload.len() as u64,
            payload.len() as u64,
            resource_offset,
            payload.len() as u64,
        ));

        let index_offset = special_offset + special_blob.len() as u64;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&XP3_MAGIC);
        bytes.extend_from_slice(&index_offset.to_le_bytes());
        bytes.extend_from_slice(warning);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&special_blob);
        bytes.push(INDEX_RAW);
        bytes.extend_from_slice(&(index.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&index);

        let archive = Archive::from_bytes(bytes).unwrap();
        let hx = archive.hxv4.as_ref().expect("Hxv4 descriptor");
        assert_eq!(hx.offset, special_offset);
        assert_eq!(hx.stored_size, special_blob.len() as u64);
        assert_eq!(hx.kind, 0);
        assert_eq!(
            archive.hxv4_special_index_bytes(),
            Some(special_blob.as_slice())
        );

        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].hxv4_id, Some(1));
        assert_eq!(archive.entries[0].name, hxv4_fake_name(1));
        assert_eq!(archive.reconstruct_entry(0).unwrap().as_slice(), payload);

        assert_eq!(archive.root_chunks[0].kind, RootKind::Hxv4SpecialIndex);
        assert!(archive
            .root_chunks
            .iter()
            .any(|root| root.kind == RootKind::ProtectedFile && root.inferred_hxv4_id == Some(0)));
    }

    #[test]
    fn parses_compressed_index() {
        let payload = b"compressed index test";
        let archive = Archive::from_bytes(make_xp3(payload, true)).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.reconstruct_entry(0).unwrap().as_slice(), payload);
    }
}
