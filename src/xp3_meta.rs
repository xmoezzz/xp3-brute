//! Round-trip metadata emitted next to an unpacked XP3 tree.
//!
//! `xp3-meta.yaml` is deliberately a repack manifest rather than a debug log.
//! It records information that cannot be reconstructed safely from the
//! user-visible files alone: original XP3 index/layout fields, authenticated
//! HXV4 Special hashes and record linkage, brute-force-only per-file recovery
//! keys plus archive-level keys required for repacking, and destructive/derived
//! decode operations such as TLG -> PNG, PSB resource-blob extraction, and
//! reversible PBD -> typed-JSON transforms.  A future packer should treat stored identity hashes as the
//! source of truth and only recompute content-dependent checksums when bytes
//! are changed.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

pub const XP3_META_SCHEMA: &str = "krkr-xp3-brute/xp3-meta-v1";
pub const XP3_META_FILE: &str = "xp3-meta.yaml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xp3Meta {
    pub schema: String,
    pub producer: String,
    pub producer_version: String,
    pub archive: ArchiveMeta,
    pub unpack: UnpackMeta,
    pub policies: RepackPolicies,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index_blocks: Vec<IndexBlockMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_chunks: Vec<RootChunkMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub special: Vec<SpecialChunkMeta>,
    /// `File` roots intentionally excluded from the normal entry list (for
    /// example KiriKiri/HXV4 protected-warning pseudo entries). Their stored
    /// segment bytes are retained so a container writer can preserve the root
    /// and its out-of-line payload without requiring the original archive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved_files: Vec<PreservedFileMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hxv4: Option<Hxv4Meta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<KeyMeta>,
    /// Exact PE32 filter modules needed to invert edited entries. The module
    /// is retained once per manifest so repacking does not depend on the
    /// original game installation still being present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x86_filter_modules: Vec<X86FilterModuleMeta>,
    pub entries: Vec<EntryMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86FilterModuleMeta {
    /// SHA-256 is both the stable module identifier and an integrity check for
    /// the embedded bytes.
    pub sha256: String,
    pub file_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub pe32_base64: String,
    pub guest_profile: String,
    pub lcid_hex: String,
    pub ansi_code_page: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMeta {
    pub source_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub family: String,
    pub xp3_offset: u64,
    pub physical_size: u64,
    pub entry_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tjs: Option<String>,
    pub tlg: String,
    pub psb: String,
    pub pbd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amv: Option<String>,
    pub output_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepackPolicies {
    /// Never derive an HXV4 path/name identity hash from a recovered path when
    /// the manifest already contains the authenticated original value.
    pub identity_hashes: String,
    /// Original `adlr` values may also be filter seeds. XP3 packing must
    /// preserve them exactly and is never allowed to recompute, replace, or synthesize them.
    pub content_checksums: String,
    /// Segment offsets/sizes describe the source layout. A packer may preserve
    /// them only when encoded sizes still fit that layout.
    pub physical_layout: String,
    /// JPEG conversion is intentionally marked lossy in transform records.
    pub derived_assets: String,
}

impl Default for RepackPolicies {
    fn default() -> Self {
        Self {
            identity_hashes: "preserve-manifest-values; do-not-rehash-recovered-names".to_string(),
            content_checksums: "immutable-original-adlr; never-recompute-replace-or-synthesize"
                .to_string(),
            physical_layout: "source-template; preserve-only-when-compatible".to_string(),
            derived_assets: "use-transform-records; reject-exact-roundtrip-claims-for-lossy-inputs"
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexBlockMeta {
    pub index: usize,
    pub physical_offset: u64,
    pub flags: u8,
    pub stored_size: u64,
    pub original_size: u64,
    /// Exact decoded index bytes are intentionally retained. XP3 indexes are
    /// small compared with archive payloads, and keeping this template means
    /// unknown/private root chunks do not need to be reverse engineered before
    /// a byte-faithful no-edit repack can preserve them.
    pub decoded_base64: String,
    pub decoded_sha256: String,
    /// Exact physical index object: flag + size header + stored payload and,
    /// when CONTINUE is set, the following relative-index pointer. Keeping this
    /// small object allows byte-for-byte index reuse when no patched field or
    /// physical anchor changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoded_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoded_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootChunkMeta {
    pub index: usize,
    pub magic_hex: String,
    pub size: u64,
    pub index_block: usize,
    pub index_offset: usize,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_hash: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_original_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_archive_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_hxv4_kind: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_hxv4_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialChunkMeta {
    pub root_index: usize,
    pub kind: String,
    /// Exact stored bytes are kept because unknown/private wrapper fields must
    /// not be guessed during a no-edit round trip.
    pub stored_blob_base64: String,
    pub stored_blob_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<OrdinarySpecialDecodedMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdinarySpecialDecodedMeta {
    pub decoder: String,
    pub layout: String,
    pub confidence: u8,
    pub decoded_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_blob_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xor: Option<RepeatingXorKeyMeta>,
    /// Ordered linkage recovered from the Special payload.  For verified
    /// M2/Yuzu layouts `special_record_hash_hex` is the exact u32 stored in
    /// the Special record (and is deliberately preserved instead of being
    /// regenerated from the recovered name).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<OrdinarySpecialRecordMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdinarySpecialRecordMeta {
    pub record_index: usize,
    pub physical_entry_index: usize,
    pub recovered_name: String,
    pub info_name_length: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special_record_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xp3_adler32_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservedFileMeta {
    pub root_chunk_index: usize,
    pub kind: String,
    pub segments: Vec<PreservedSegmentMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservedSegmentMeta {
    pub flags: u32,
    pub archive_offset: u64,
    pub original_size: u64,
    pub archive_size: u64,
    pub stored_base64: String,
    pub stored_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4Meta {
    pub descriptor: Hxv4DescriptorMeta,
    pub decompressed_special_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aead: Option<Hxv4AeadMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_manager: Option<Hxv4FilterManagerMeta>,
    pub records: Vec<Hxv4RecordMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4DescriptorMeta {
    pub offset: u64,
    pub stored_size: u64,
    pub kind: u16,
    pub root_chunk_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4AeadMeta {
    pub source: String,
    pub key_hex: String,
    pub nonce_hex: String,
    pub nonce_slot: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce0_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce1_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_seed_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_unique_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe_offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4FilterManagerMeta {
    pub mask: u32,
    pub offset: u32,
    pub control_mode: u8,
    pub random_type: u8,
    pub random_type_label: String,
    pub holder_low_hex: String,
    pub holder_high_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4RecordMeta {
    pub record_index: usize,
    pub packed_hex: String,
    pub archive_slot: u16,
    pub local_flag_hex: String,
    pub synthetic_id: u64,
    pub entry_key_hex: String,
    pub path_hash_hex: String,
    pub name_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_entry_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_state: Option<Hxv4FilterStateMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4FilterStateMeta {
    pub open_flag: bool,
    pub split: u64,
    pub prefix_xor_hex: String,
    pub left_drip_hex: String,
    pub right_drip_hex: String,
    pub left: Hxv4BoundaryMeta,
    pub right: Hxv4BoundaryMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4BoundaryMeta {
    pub position0: u64,
    pub position1: u64,
    pub xor_byte_hex: String,
    pub correction0_hex: String,
    pub correction1_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMeta {
    pub kind: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repeating_xor: Option<RepeatingXorKeyMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u32_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeatingXorKeyMeta {
    pub period: usize,
    /// Two hexadecimal digits per known residue and `??` for an unknown slot.
    pub slots: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete_key_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMeta {
    pub index: usize,
    pub original: EntryOriginalMeta,
    pub identity: EntryIdentityMeta,
    pub recovery: EntryRecoveryMeta,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transforms: Vec<TransformMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryOriginalMeta {
    /// Exact root `File` chunk that owns this entry. New manifests always set
    /// this; `Option` keeps older v1 manifests readable with strict fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_chunk_index: Option<usize>,
    pub flags: u32,
    pub original_size: u64,
    pub archive_size: u64,
    pub info_name_length: u16,
    pub info_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternate_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternate_hash: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hxv4_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adler32_hex: Option<String>,
    /// The original XP3 `adlr` value is also the per-entry hash handed to
    /// many historical extraction filters.  Keep this explicit alias so a
    /// future packer/filter backend never silently substitutes a checksum
    /// recomputed from edited output bytes when the original seed is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_filter_hash_hex: Option<String>,
    pub segments: Vec<SegmentMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMeta {
    pub flags: u32,
    pub archive_offset: u64,
    pub original_size: u64,
    pub archive_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryIdentityMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hxv4_special_record_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryRecoveryMeta {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// SHA-256 of the verified/plain reconstructed content *before* user-facing
    /// text normalization or TLG/PSB derived exports.  A repacker can use this
    /// to determine whether an original transform may be reused byte-for-byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_plaintext_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repeating_xor: Option<RepeatingXorRecoveryMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hxv4_native: Option<Hxv4NativeRecoveryMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x86_filter: Option<X86FilterRecoveryMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Default for EntryRecoveryMeta {
    fn default() -> Self {
        Self {
            status: "pending".to_string(),
            format: None,
            storage_plaintext_sha256: None,
            repeating_xor: None,
            hxv4_native: None,
            x86_filter: None,
            detail: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86FilterRecoveryMeta {
    pub module_sha256: String,
    pub callback_va_hex: String,
    pub callback_source: String,
    /// Immutable original XP3 filter seed, never a checksum of edited data.
    pub file_hash_hex: String,
}

/// Per-entry repeating-XOR key material is serialized only for a recovery
/// that actually used brute force. Non-bruteforced constraint/crib recovery
/// deliberately leaves `EntryRecoveryMeta::repeating_xor` absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeatingXorRecoveryMeta {
    pub key: RepeatingXorKeyMeta,
    pub brute_used: bool,
    pub mitm: bool,
    pub gpu: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_adapter: Option<String>,
    pub combinations: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hxv4NativeRecoveryMeta {
    pub entry_key_hex: String,
    pub local_flag_hex: String,
    pub split: u64,
    pub left_xor_hex: String,
    pub right_xor_hex: String,
    pub corrections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TransformMeta {
    KirikiriText(KirikiriTextTransformMeta),
    TlgImage(TlgTransformMeta),
    PsbRootJson(PsbRootJsonTransformMeta),
    PsbTexture(PsbTextureTransformMeta),
    PsbResourceBlob(PsbResourceBlobTransformMeta),
    PbdJson(PbdJsonTransformMeta),
    /// Reserved now so AMV integration can use the same manifest contract.
    AmvFrame(AmvFrameTransformMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KirikiriTextTransformMeta {
    pub source_encoding_or_wrapper: String,
    pub output_encoding: String,
    pub bom_hex: String,
    /// Hash of the editable normalized text emitted by unpack. If it still
    /// matches, a container writer with the source XP3 can reuse the original
    /// stored entry bytes exactly instead of needlessly re-encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    /// Required by a future packer to restore the exact FE FE storage mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kirikiri_wrapper_mode: Option<u8>,
    /// Whether the extracted bytes are a user-facing normalization rather than
    /// the source storage representation.
    pub reversible_with_encoder: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlgTransformMeta {
    pub source_asset_path: String,
    pub source_size: usize,
    pub source_sha256: String,
    pub output_path: String,
    pub output_format: String,
    /// Exact emitted sidecar hash for no-edit detection. Pixel hash below is
    /// separately retained for semantic image validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    pub lossless_pixels: bool,
    pub version: String,
    pub width: u32,
    pub height: u32,
    pub components: u8,
    /// Hash of canonical decoded RGBA8 pixels. Future packing can tell whether
    /// a lossless derived image still represents the original TLG pixels.
    pub decoded_rgba_sha256: String,
    pub codec: TlgCodecMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<TlgContainerMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "lowercase")]
pub enum TlgCodecMeta {
    Tlg5 {
        block_height: u32,
    },
    Tlg6 {
        data_flag: u8,
        color_type: u8,
        external_golomb_table: u8,
        max_bit_length: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlgContainerMeta {
    pub raw_offset: usize,
    pub raw_size: u32,
    pub chunks: Vec<TlgContainerChunkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlgContainerChunkMeta {
    pub name: String,
    pub order: usize,
    pub payload_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbSourceMeta {
    pub source_binary_path: String,
    pub source_size: usize,
    pub source_sha256: String,
    pub normalized_size: usize,
    pub normalized_sha256: String,
    /// `raw-psb`, `mdf`, or `lz4-frame`. This is the wrapper that a future
    /// writer must restore after applying edits to the normalized PSB.
    pub wrapper: String,
    pub psb_version: u64,
    pub encrypted_input: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emote_key_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbRootJsonTransformMeta {
    pub source: PsbSourceMeta,
    pub output_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    pub schema: String,
    /// The original PSB-family binary remains in the extraction tree and is
    /// the binary template for future rewrite/repack.
    pub source_binary_retained: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbTextureTransformMeta {
    pub source: PsbSourceMeta,
    pub output_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    pub output_format: String,
    pub lossless_pixels: bool,
    pub source_binary_retained: bool,
    /// `resource` or `extra-resource`; indices are local to that PSB table.
    pub resource_table: String,
    pub resource_index: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    /// Structural decoder that identified the resource, e.g.
    /// `generic-bitmap` or `emote-texture`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<String>,
    /// JSON-pointer-like path to the PSB object that references the pixel
    /// resource.  This is the stable rewrite anchor for a future PSB packer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
    /// Source surface dimensions.  These differ from `width`/`height` for
    /// truncated Emote textures whose rows use the full surface stride.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_height: Option<u32>,
    /// Optional palette resource for generic 8-bit PSB bitmaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub palette_resource_table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub palette_resource_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emote_key_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbResourceBlobTransformMeta {
    pub source: PsbSourceMeta,
    pub output_path: String,
    pub source_binary_retained: bool,
    /// `resource` or `extra-resource`; indices are local to that PSB table.
    pub resource_table: String,
    pub resource_index: u32,
    pub blob_size: usize,
    pub blob_sha256: String,
    /// Present when the object tree identified this blob as an image resource
    /// but the current pixel decoder could not materialize it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_candidate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub palette_resource_table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub palette_resource_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbdJsonTransformMeta {
    pub source_binary_path: String,
    pub source_size: usize,
    pub source_sha256: String,
    pub output_path: String,
    pub output_sha256: String,
    pub schema: String,
    pub variant: String,
    pub seed_hex: String,
    pub crypt: u16,
    pub iv_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailer_hex: Option<String>,
    /// TJS/4s0 uses independently framed raw LZ4 blocks; absent for ns0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lz4_block_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lz4_terminated: Option<bool>,
    /// The original .pbd remains next to the editable JSON and is the source
    /// template when the JSON was not modified.
    pub source_binary_retained: bool,
    /// Future XP3 packing should rebuild the PBD from the JSON while preserving
    /// its ns0/4s0 variant, seed, crypt field, IV and 4s0 trailer.
    pub repack_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmvFrameTransformMeta {
    pub source_container_path: String,
    pub source_size: usize,
    pub source_sha256: String,
    pub output_path: String,
    pub frame_index: usize,
    pub output_format: String,
    /// Exact emitted frame-sidecar hash for no-edit detection. This is
    /// bookkeeping provenance and is deliberately unrelated to XP3 `adlr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    pub lossless_pixels: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps_num: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps_den: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<u8>,
    /// AMV integration will retain/refer to the original container as the
    /// encoding template; this field makes that round-trip contract explicit.
    pub source_container_retained: bool,
}

pub fn repeating_xor_key(slots: &[Option<u8>]) -> RepeatingXorKeyMeta {
    let slot_strings = slots
        .iter()
        .map(|slot| {
            slot.map(|b| format!("{b:02x}"))
                .unwrap_or_else(|| "??".to_string())
        })
        .collect::<Vec<_>>();
    let complete_key_hex = slots
        .iter()
        .copied()
        .collect::<Option<Vec<_>>>()
        .map(|key| hex_lower(&key));
    RepeatingXorKeyMeta {
        period: slots.len(),
        slots: slot_strings,
        complete_key_hex,
    }
}

pub fn complete_repeating_xor_key(key: &[u8]) -> RepeatingXorKeyMeta {
    RepeatingXorKeyMeta {
        period: key.len(),
        slots: key.iter().map(|b| format!("{b:02x}")).collect(),
        complete_key_hex: Some(hex_lower(key)),
    }
}

pub fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn read_manifest(root_or_manifest: &Path) -> Result<Xp3Meta, Box<dyn std::error::Error>> {
    let path = if root_or_manifest.is_dir() {
        root_or_manifest.join(XP3_META_FILE)
    } else {
        root_or_manifest.to_path_buf()
    };
    let file = File::open(path)?;
    Ok(serde_yaml::from_reader(file)?)
}

pub fn write_manifest(
    root: &Path,
    manifest: &Xp3Meta,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let path = root.join(XP3_META_FILE);
    let tmp = root.join(format!(".{XP3_META_FILE}.tmp"));
    let file = File::create(&tmp)?;
    let mut writer = BufWriter::new(file);
    serde_yaml::to_writer(&mut writer, manifest)?;
    writer.flush()?;
    drop(writer);
    fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

pub fn io_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeating_key_preserves_unknown_slots() {
        let key = repeating_xor_key(&[Some(0x12), None, Some(0xab)]);
        assert_eq!(key.period, 3);
        assert_eq!(key.slots, vec!["12", "??", "ab"]);
        assert!(key.complete_key_hex.is_none());
    }

    #[test]
    fn manifest_schema_and_identity_policy_serialize() {
        let manifest = Xp3Meta {
            schema: XP3_META_SCHEMA.to_string(),
            producer: "xp3-brute".to_string(),
            producer_version: env!("CARGO_PKG_VERSION").to_string(),
            archive: ArchiveMeta {
                source_file: "data.xp3".to_string(),
                source_path: None,
                family: "ordinary".to_string(),
                xp3_offset: 0,
                physical_size: 0,
                entry_count: 0,
            },
            unpack: UnpackMeta {
                tjs: None,
                tlg: "none".to_string(),
                psb: "none".to_string(),
                pbd: "none".to_string(),
                amv: None,
                output_root: "out".to_string(),
            },
            policies: RepackPolicies::default(),
            index_blocks: Vec::new(),
            root_chunks: Vec::new(),
            special: Vec::new(),
            preserved_files: Vec::new(),
            hxv4: None,
            keys: Vec::new(),
            x86_filter_modules: Vec::new(),
            entries: Vec::new(),
        };
        let yaml = serde_yaml::to_string(&manifest).unwrap();
        assert!(yaml.contains("krkr-xp3-brute/xp3-meta-v1"));
        assert!(yaml.contains("preserve-manifest-values; do-not-rehash-recovered-names"));
        let decoded: Xp3Meta = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(decoded.schema, XP3_META_SCHEMA);
        assert_eq!(decoded.archive.source_file, "data.xp3");
        assert_eq!(decoded.entries.len(), 0);
    }
}
