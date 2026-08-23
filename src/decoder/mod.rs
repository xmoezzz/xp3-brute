//! Decoders for KiriKiri-native payload formats.
//!
//! Decoder modules are intentionally independent from XP3 extraction so the
//! same implementation can be reused by the library, the CLI, and future
//! post-processing pipelines.

pub mod amv;
pub mod pbd;
pub mod psb;
pub mod tlg;
