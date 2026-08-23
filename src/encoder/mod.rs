//! Reversible encoders for derived unpack assets.
//!
//! Decoders create editable sidecars and record their provenance in
//! `xp3-meta.yaml`; this module performs the inverse mapping.  The central
//! [`rebuild_assets_from_manifest`] API writes an overlay with the original
//! asset paths so archive packing can stay independent of individual codecs.

pub mod amv;
pub mod pbd;
pub mod psb;
pub mod rebuild;
pub mod text;
pub mod tlg;
pub mod xp3;

pub use amv::{
    encode_amv_frames, encode_amv_frames_with_context, encode_amv_image_files,
    encode_amv_image_files_with_context, rebuild_amv_from_transforms, AmvEncodeOptions,
};
pub use pbd::rebuild_pbd_from_json;
pub use psb::{rebuild_psb_from_transforms, PsbRebuildInput};
pub use rebuild::{rebuild_assets_from_manifest, RebuildOptions, RebuildRecord, RebuildReport};
pub use text::rebuild_kirikiri_text;
pub use tlg::{
    encode_tlg_image, encode_tlg_image_file, rebuild_tlg_from_transform, TlgEncodeOptions,
};
pub use xp3::{
    pack_xp3_from_manifest, reconstruct_plaintext_entry_from_manifest, Xp3PackEntryReport,
    Xp3PackOptions, Xp3PackReport,
};
