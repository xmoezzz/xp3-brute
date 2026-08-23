//! Library-first discovery and execution policy for XP3 content filters.
//!
//! Detection is deliberately separate from archive parsing.  An archive can
//! always be opened and recovered with [`FilterBackend::ArchiveOnly`]; an
//! executable module may add a native semantic strategy. Static x86 callback
//! provenance is diagnostic/reverse-engineering evidence only: normal
//! detection never executes V2Link or an original x86 callback. A production
//! content backend is selected only when the semantics have been recovered as
//! owned Rust data.

use crate::{
    cxdec_candidate_modules, probe_cxdec_path, probe_x86_filter_module, Archive, CxdecNativeFilter,
    Error, FilterProbeOptions, Result,
};
use std::path::{Path, PathBuf};

/// Ordered recovery backend selected for content bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterBackend {
    /// A recognized semantic family is evaluated directly in Rust.
    NativeRust,
    /// Legacy explicit x86 execution backend. Automatic detection never
    /// selects this variant; static registration provenance is evidence only.
    GenericX86,
    /// No executable module is required; archive-level recovery remains valid.
    ArchiveOnly,
}

/// Content-filter family.  This intentionally does not encode a game title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentFilterProfile {
    None,
    /// Recovered CXDEC semantics. `known_fixture` is diagnostic-only.
    Cxdec {
        generation: CxdecGeneration,
        known_fixture: Option<&'static str>,
    },
    Hxv4,
    GenericX86,
}

/// Semantic CXDEC generations. These values describe algorithm deltas, not
/// game names or module filenames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CxdecGeneration {
    Classic,
    CxEncryption,
    /// Early object-based 128-lane dynamic xcode generation. The name is
    /// semantic on purpose: automatic detection must not depend on a title.
    EarlyDynamicXcode,
    Senren,
    Cabbage,
    Nana,
    Riddle,
    /// A recovered generator retained as evidence until it can be separated
    /// into one of the named generations above.
    Recovered(String),
}

/// Name/index handling is independently selected from content decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecialNameProfile {
    None,
    OrderedPlain,
    OrderedCompressed,
    OrderedEncrypted {
        section: String,
        encrypted_prefix: usize,
    },
    Senren,
    Cabbage,
    Nana {
        encrypted_prefix: usize,
        parameters_recovered: bool,
    },
    RiddleYuz {
        encrypted_prefix: usize,
        parameters_recovered: bool,
    },
    Hxv4Authenticated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecialNameDetection {
    pub root_index: usize,
    pub profile: SpecialNameProfile,
    pub confidence: DetectionConfidence,
    pub evidence: Vec<DetectionEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionConfidence {
    None,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionEvidence {
    pub kind: String,
    pub detail: String,
}

/// Recovered classic-CXDEC fields, kept structured so frontends and future
/// bindings do not need to parse CLI diagnostics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassicCxdecDetection {
    pub mask: Option<u32>,
    pub offset: Option<u32>,
    pub control_block_rva: Option<u32>,
    pub callback_config_rva: Option<u32>,
    pub builder_rva: Option<u32>,
    pub builder_in_decc: bool,
    pub generator_semantics: Option<String>,
    pub cabbage_prng_rva: Option<u32>,
    pub riddle_prefix8_rva: Option<u32>,
    pub random_seed: Option<u32>,
    pub prolog_order: Option<[u8; 3]>,
    pub even_branch_order: Option<[u8; 8]>,
    pub odd_branch_order: Option<[u8; 6]>,
    pub native_complete: bool,
    pub missing_fields: Vec<String>,
}

/// A pure diagnostic result.  It has no emulator handles or raw process state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterDetection {
    pub source_module: Option<PathBuf>,
    pub backend: FilterBackend,
    pub content: ContentFilterProfile,
    pub special_names: SpecialNameProfile,
    pub confidence: DetectionConfidence,
    pub callback_va: Option<u32>,
    pub callback_source: Option<String>,
    pub classic_cxdec: Option<ClassicCxdecDetection>,
    pub evidence: Vec<DetectionEvidence>,
}

impl FilterDetection {
    pub fn archive_only() -> Self {
        Self {
            source_module: None,
            backend: FilterBackend::ArchiveOnly,
            content: ContentFilterProfile::None,
            special_names: SpecialNameProfile::None,
            confidence: DetectionConfidence::None,
            callback_va: None,
            callback_source: None,
            classic_cxdec: None,
            evidence: vec![DetectionEvidence {
                kind: "policy".into(),
                detail: "no executable filter selected; archive-only recovery remains available"
                    .into(),
            }],
        }
    }
}

/// Detect structurally valid indirect Special/name sections without assigning a
/// CXDEC family. Four-byte tags are mutable vendor metadata; when a historical
/// tag is recognized it is retained only as low-confidence evidence.
pub fn detect_special_name_sections(archive: &Archive) -> Vec<SpecialNameDetection> {
    archive
        .indirect_special_roots()
        .into_iter()
        .map(|root_index| {
            let root = &archive.root_chunks[root_index];
            let raw_tag = root.magic.to_le_bytes();
            let hint = crate::cxdec_names::CxdecNameSectionKind::from_known_tag_hint(raw_tag);
            let mut evidence = vec![DetectionEvidence {
                kind: "indirect-special-structure".into(),
                detail: format!(
                    "root[{root_index}] kind={:?} descriptor_size={} stored={:?} original={:?}",
                    root.kind, root.size, root.inferred_archive_size, root.inferred_original_size
                ),
            }];
            if let Some(kind) = hint {
                evidence.push(DetectionEvidence {
                    kind: "historical-tag-hint".into(),
                    detail: format!(
                        "root tag {} has historically been used by {:?}; tag is not family evidence",
                        String::from_utf8_lossy(&raw_tag),
                        kind
                    ),
                });
            }
            SpecialNameDetection {
                root_index,
                profile: SpecialNameProfile::OrderedEncrypted {
                    section: String::from_utf8_lossy(&raw_tag).into_owned(),
                    encrypted_prefix: 0x100,
                },
                confidence: if hint.is_some() {
                    DetectionConfidence::Low
                } else {
                    DetectionConfidence::None
                },
                evidence,
            }
        })
        .collect()
}

enum Runtime {
    Native(CxdecNativeFilter),
}

/// An owned, non-global filter executor.  Create one per worker when using
/// parallel extraction; this keeps Unicorn state out of public diagnostics and
/// avoids hidden thread-local caches.
pub struct FilterSession {
    detection: FilterDetection,
    runtime: Runtime,
}

impl FilterSession {
    pub fn detection(&self) -> &FilterDetection {
        &self.detection
    }

    pub fn apply(&mut self, file_offset: u64, file_hash: u32, bytes: &mut [u8]) -> Result<()> {
        match &mut self.runtime {
            Runtime::Native(filter) => filter.apply(file_offset, file_hash, bytes),
        }
    }
}

pub fn generation_from_probe(probe: &crate::CxdecProbe) -> CxdecGeneration {
    match probe.profile() {
        "cxdec-legacy-decc-v1" => CxdecGeneration::Classic,
        // Semantically identified by the 128-lane runtime xcode manager,
        // classic LCG, file-backed 4096-byte control table and split-boundary
        // constructor. The label describes the algorithm generation; no
        // archive tag, product string, title or module filename participates.
        "cxdec-early-dynamic-xcode-v1" => CxdecGeneration::EarlyDynamicXcode,
        "cxdec-cabbage-generator-v2" => CxdecGeneration::Cabbage,
        "cxdec-riddle-generator-v3" => CxdecGeneration::Riddle,
        other => CxdecGeneration::Recovered(other.to_string()),
    }
}

fn classic_detection_from_probe(probe: &crate::CxdecProbe) -> ClassicCxdecDetection {
    ClassicCxdecDetection {
        mask: probe.key0,
        offset: probe.key1,
        control_block_rva: probe.control_block_rva,
        callback_config_rva: probe.callback_config_rva,
        builder_rva: probe.xcode_builder_rva,
        builder_in_decc: probe.xcode_builder_in_decc,
        generator_semantics: Some(
            if probe.cabbage_prng_rva.is_some() {
                "cabbage-cxprogram-nana"
            } else {
                "classic-lcg"
            }
            .into(),
        ),
        cabbage_prng_rva: probe.cabbage_prng_rva,
        riddle_prefix8_rva: probe.riddle_prefix8_rva,
        random_seed: probe.random_seed,
        prolog_order: probe.prolog_order,
        even_branch_order: probe.even_branch_order,
        odd_branch_order: probe.odd_branch_order,
        native_complete: probe.native_complete(),
        missing_fields: probe
            .missing_native_fields()
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

/// Detect the best backend without opening a mutable runtime.  `None` is a
/// first-class archive-only request, not an error. Known CXDEC family identity
/// is retained when its static profile is incomplete, but that candidate is
/// never executed through GenericX86 as a production fallback.
pub fn detect_filter(target: Option<&Path>) -> Result<FilterDetection> {
    let Some(target) = target else {
        return Ok(FilterDetection::archive_only());
    };

    let native = probe_cxdec_path(target)?;
    let mut native_failures = Vec::new();
    let mut incomplete = std::collections::BTreeMap::<PathBuf, crate::CxdecProbe>::new();
    for candidate in native {
        if !candidate.native_complete() {
            native_failures.push(DetectionEvidence {
                kind: "native-profile-incomplete".into(),
                detail: format!(
                    "{}: family={:?}, missing {}",
                    candidate.path.display(),
                    generation_from_probe(&candidate),
                    candidate.missing_native_fields().join(", ")
                ),
            });
            incomplete.insert(candidate.path.clone(), candidate);
            continue;
        }
        let native_filter = match CxdecNativeFilter::open(&candidate.path) {
            Ok(filter) => filter,
            Err(error) => {
                native_failures.push(DetectionEvidence {
                    kind: "native-profile-incomplete".into(),
                    detail: format!("{}: {error}", candidate.path.display()),
                });
                incomplete.insert(candidate.path.clone(), candidate);
                continue;
            }
        };
        let probe = native_filter.probe();
        if !probe.native_complete() {
            native_failures.push(DetectionEvidence {
                kind: "native-profile-incomplete".into(),
                detail: format!(
                    "{}: missing {}",
                    probe.path.display(),
                    probe.missing_native_fields().join(", ")
                ),
            });
            continue;
        }
        return Ok(FilterDetection {
            source_module: Some(probe.path.clone()),
            backend: FilterBackend::NativeRust,
            content: ContentFilterProfile::Cxdec {
                generation: generation_from_probe(probe),
                known_fixture: None,
            },
            special_names: SpecialNameProfile::None,
            confidence: if probe.confidence >= 80 {
                DetectionConfidence::High
            } else {
                DetectionConfidence::Medium
            },
            callback_va: None,
            callback_source: Some("semantic-cxdec-static-profile".into()),
            classic_cxdec: Some(classic_detection_from_probe(probe)),
            evidence: probe
                .reasons
                .iter()
                .cloned()
                .map(|detail| DetectionEvidence {
                    kind: "cxdec-semantic".into(),
                    detail,
                })
                .collect(),
        });
    }

    // Static-only callback provenance. This does not authorize execution of
    // the original module; it only identifies a trustworthy entry point for
    // subsequent CFG/dataflow recovery into Rust semantics.
    let mut reports = Vec::new();
    for module in cxdec_candidate_modules(target)? {
        if let Ok(report) = probe_x86_filter_module(
            &module,
            FilterProbeOptions {
                dynamic_v2link: false,
                trace_code: false,
            },
        ) {
            reports.push(report);
        }
    }
    reports.sort_by_key(|report| report.path.clone());
    for report in reports {
        let Some(candidate) = report
            .candidates
            .iter()
            .find(|candidate| candidate.registration.is_some())
        else {
            continue;
        };
        let mut evidence = native_failures.clone();
        evidence.extend(candidate.reasons.iter().cloned().map(|detail| DetectionEvidence {
            kind: "x86-static-registration-provenance".into(),
            detail,
        }));
        evidence.push(DetectionEvidence {
            kind: "policy".into(),
            detail: "registered x86 callback retained as static reverse-engineering evidence; original module/callback was not executed".into(),
        });
        return Ok(FilterDetection {
            source_module: Some(report.path),
            backend: FilterBackend::ArchiveOnly,
            content: ContentFilterProfile::GenericX86,
            special_names: SpecialNameProfile::None,
            confidence: DetectionConfidence::High,
            callback_va: Some(candidate.callback_va),
            callback_source: Some("static-registration-provenance".into()),
            classic_cxdec: None,
            evidence,
        });
    }

    let mut archive = FilterDetection::archive_only();
    archive.evidence.splice(0..0, native_failures);
    Ok(archive)
}

/// Open the selected runtime.  Archive-only results deliberately return
/// `Ok(None)` so callers may continue their brute-force strategy unchanged.
pub fn open_filter_session(target: Option<&Path>) -> Result<Option<FilterSession>> {
    let detection = detect_filter(target)?;
    let Some(module) = detection.source_module.as_deref() else {
        return Ok(None);
    };
    let runtime = match detection.backend {
        FilterBackend::NativeRust => match CxdecNativeFilter::open(module) {
            Ok(runtime) => Runtime::Native(runtime),
            Err(_native_error) => {
                // Detection and opening use the same static profile contract.
                // If the native Rust engine cannot be constructed, fail closed
                // instead of executing the recognized CXDEC module.
                return Ok(None);
            }
        },
        FilterBackend::GenericX86 | FilterBackend::ArchiveOnly => return Ok(None),
    };
    Ok(Some(FilterSession { detection, runtime }))
}

/// A convenience helper for consumers that need a filter and want an error
/// instead of archive-only fallback.
pub fn require_filter_session(target: &Path) -> Result<FilterSession> {
    open_filter_session(Some(target))?.ok_or_else(|| {
        Error::unsupported(format!(
            "no executable XP3 content filter found under {}",
            target.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_only_is_a_valid_first_class_detection() {
        let detection = detect_filter(None).unwrap();
        assert_eq!(detection.backend, FilterBackend::ArchiveOnly);
        assert_eq!(detection.content, ContentFilterProfile::None);
        assert!(detection.source_module.is_none());
    }

    #[test]
    fn kinglove_static_registration_is_not_an_execution_backend() {
        let sample =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../games/game-normal/plugin/kinglove.tpm");
        assert!(
            sample.is_file(),
            "missing corpus sample {}",
            sample.display()
        );
        let detection = detect_filter(Some(&sample)).unwrap();
        // Static registration provenance may identify the callback, but
        // automatic detection must not authorize original x86 execution.
        assert_eq!(detection.backend, FilterBackend::ArchiveOnly);
        assert_eq!(detection.content, ContentFilterProfile::GenericX86);
        assert!(detection.callback_va.is_some());
        assert_eq!(
            detection.callback_source.as_deref(),
            Some("static-registration-provenance")
        );
    }
}
