//! Archive-family strategy selection.
//!
//! The solver must never let a newly recognized protection family disable the
//! known-good paths for ordinary Krkr2/KrkrZ archives.  Strategy detection is
//! therefore additive: storage parsing is shared, then mutually incompatible
//! extraction-filter models are selected explicitly.

use crate::xp3::{Archive, RootKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveFamily {
    StandardOrKrkr2,
    IndirectSpecialIndex,
    Hxv4,
}

#[derive(Clone, Debug)]
pub struct RecoveryPlan {
    pub family: ArchiveFamily,
    pub try_plain: bool,
    pub try_shared_repeating_xor: bool,
    pub try_per_file_repeating_xor: bool,
    pub try_hxv4_effective_filter: bool,
    pub probe_unknown_chunks: bool,
}

pub fn recovery_plan(archive: &Archive) -> RecoveryPlan {
    if archive.is_hxv4() {
        return RecoveryPlan {
            family: ArchiveFamily::Hxv4,
            try_plain: true,
            // Hxv4 content has a dedicated per-entry filter.  Do not pool its
            // entries into the generic archive-wide shared-key optimization
            // before that model has a chance to run.  Per-file repeating-XOR
            // remains an additive validated fallback after the Hx solver.
            try_shared_repeating_xor: false,
            try_per_file_repeating_xor: true,
            try_hxv4_effective_filter: true,
            probe_unknown_chunks: true,
        };
    }
    let indirect = archive.root_chunks.iter().any(|r| {
        matches!(
            r.kind,
            RootKind::SpecialIndexV1
                | RootKind::SpecialIndexV2
                | RootKind::SpecialIndexV3
                | RootKind::SpecialIndexGeneric
        )
    });
    RecoveryPlan {
        family: if indirect {
            ArchiveFamily::IndirectSpecialIndex
        } else {
            ArchiveFamily::StandardOrKrkr2
        },
        try_plain: true,
        // Old Krkr2/KrkrZ titles can use one shared extraction filter or
        // independent keys.  Shared probing is only an optimization: failure
        // falls through to independent per-file recovery.
        try_shared_repeating_xor: true,
        try_per_file_repeating_xor: true,
        try_hxv4_effective_filter: false,
        probe_unknown_chunks: true,
    }
}
