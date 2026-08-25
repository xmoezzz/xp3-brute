//! Offline XP3 recovery primitives.
//!
//! The crate deliberately separates the XP3 storage layer from any extraction
//! filter. [`Archive::reconstruct_entry`] returns the stream after XP3 segment
//! reconstruction/decompression. Title-specific extraction filters, including
//! the reconstructed HXV4 per-entry symmetric filter, are applied to that reconstructed
//! stream rather than to the stored/zlib-compressed bytes.

pub mod brute;
pub mod chunk_probe;
pub mod compute;
pub mod cxdec_classic;
pub mod cxdec_names;
pub mod decoder;
pub mod encoder;
pub mod embedded_pe;
pub mod error;
pub mod filter_detection;
pub mod format;
pub mod hxv4;
pub mod hxv4_native;
pub mod krkr_exe;
pub mod legacy_cxdec;
pub mod magic_sniff;
pub mod pe_normalize;
pub mod progress;
#[cfg(feature = "python")]
mod python;
pub mod repeating_xor;
pub mod roundtrip;
pub mod script_names;
pub mod simd;
pub mod solver;
pub mod special_content;
pub mod special_cipher;
pub mod special_index;
pub mod special_params;
pub mod strategy;
pub mod text;
pub mod tjs_symexec;
pub mod validate;
mod win32_host;
pub mod x86_filter;
pub mod xp3;
pub mod xp3_meta;

pub use decoder::amv::{
    decode_amv, export_amv_frames, is_amv_bytes, AmvInfo, AmvVariant, DecodedAmv, DecodedAmvFrame,
};

pub use special_cipher::{
    complemented_chacha8_block, ComplementedChaCha8Cipher, ComplementedChaCha8Profile,
    SpecialFixedParams,
};
pub use brute::{
    build_key_space, candidate_is_complete_for_len, enumerate_key_space,
    refine_key_space_with_histogram, refine_key_space_with_histogram_compute,
    search_key_space_with_adler, search_key_space_with_adler_predicate,
    search_key_space_with_adler_predicate_compute, search_key_space_with_predicate, BruteLimits,
    BruteSearchResult, KeyByteCandidate, KeySlotCandidates, KeySpace, PlainByteConstraint,
};
pub use chunk_probe::{probe_blob, ChunkProbe, ProbeKind};
pub use compute::{
    compute_telemetry, gpu_info, reset_compute_telemetry, ComputeMode, ComputeTelemetry, GpuInfo,
};
pub use cxdec_classic::{
    apply_riddle_prefix8, known_classic_profile, ClassicCxdecEngine, ClassicCxdecFixture,
    ClassicCxdecScheme, CxdecContentWrapper, CxdecEngine, CxdecGeneratorKind, CxdecProfile,
    KnownClassicCxdecProfile, CLASSIC_CXDEC_CONTROL_BLOCK_SIZE, KNOWN_CLASSIC_CXDEC_FIXTURES,
    KNOWN_CLASSIC_CXDEC_PROFILES,
};
pub use cxdec_names::{
    cxdec_filename_md5_token, decode_plain_cxdec_name_payload, normalize_cxdec_filename,
    parse_structural_cxdec_name_record_groups, parse_structural_cxdec_name_records,
    recover_riddle_special_fixed_params_from_pe,
    recover_riddle_special_fixed_params_from_pe_bytes,
    recover_riddle_special_seed_candidates_from_pe,
    riddle_joker_builtin_profile, riddle_joker_reference_profile,
    CxdecNameApplyReport, CxdecNameMap, CxdecNameProfile, CxdecNameRecord,
    CxdecNameSectionKind, NanaDecryptor, RiddleCxdecProfile, RiddleFixedParams,
    RiddleSpecialFixedParamsCandidate, RiddleSpecialSeedCandidate,
    YuzControlKey, YuzDecryptor, YuzKey, RIDDLE_JOKER_EVEN_BRANCH_ORDER,
    RIDDLE_JOKER_MASK, RIDDLE_JOKER_ODD_BRANCH_ORDER, RIDDLE_JOKER_OFFSET,
    RIDDLE_JOKER_PROLOG_ORDER, RIDDLE_JOKER_RANDOM_SEED, RIDDLE_JOKER_SPECIAL_SEED0,
    RIDDLE_JOKER_SPECIAL_SEED1,
};
pub use decoder::pbd::{
    decode_pbd, decode_pbd_file, encode_pbd, encode_pbd_json, encode_pbd_json_file,
    export_pbd_json, is_pbd_bytes, pbd_json_output_path, PbdDictEntry, PbdDocument, PbdError,
    PbdHeader, PbdJsonDocument, PbdJsonFormat, PbdValue, PbdVariant, PBD_4S0_MAGIC,
    PBD_JSON_SCHEMA, PBD_NS0_MAGIC,
};
pub use decoder::psb::{
    cached_emote_keys, decode_emote_textures, decode_psb_with_global_key, decode_psb_with_key,
    export_emote_textures, export_emote_textures_detailed, export_psb_resources_detailed,
    export_psb_root_json, is_psb_family_bytes, psb_json_output_path, psb_roundtrip_json,
    psb_value_to_roundtrip_json, DecodedEmoteTexture, DecodedPsb, EmoteTextureExportFormat,
    EmoteTextureExportRecord, PsbDecoderError, PsbKeySource, PsbResourceExportRecord,
    PsbResourceTable, PSB_ROOT_JSON_SCHEMA,
};
pub use decoder::tlg::{
    decode_tlg, decode_tlg_file, decode_tlg_to_file, export_decoded_tlg, inspect_tlg,
    output_options_for_path, parse_tlg0_tags, with_output_extension, DecodedTlg, TlgCodecInfo,
    TlgContainerChunk, TlgContainerInfo, TlgExportFormat, TlgExportOptions, TlgInfo, TlgVersion,
};
pub use embedded_pe::{
    detect_startup_storage_redirect, extract_embedded_pe_modules,
    extract_embedded_pe_modules_from_bytes, EmbeddedPeModule, StartupStorageRedirect,
};
pub use encoder::{
    encode_amv_frames, encode_amv_frames_with_context, encode_amv_image_files,
    encode_amv_image_files_with_context, encode_tlg_image, encode_tlg_image_file,
    pack_xp3_from_manifest, rebuild_amv_from_transforms, rebuild_assets_from_manifest,
    rebuild_kirikiri_text, rebuild_pbd_from_json, rebuild_psb_from_transforms,
    rebuild_tlg_from_transform, reconstruct_plaintext_entry_from_manifest, AmvEncodeOptions,
    PsbRebuildInput, RebuildOptions, RebuildRecord, RebuildReport, TlgEncodeOptions,
    Xp3PackEntryReport, Xp3PackOptions, Xp3PackReport,
};
pub use error::{Error, Result};
pub use filter_detection::{
    detect_filter, detect_special_name_sections, generation_from_probe, open_filter_session,
    require_filter_session,
    ClassicCxdecDetection, ContentFilterProfile, CxdecGeneration, DetectionConfidence,
    DetectionEvidence, FilterBackend, FilterDetection, FilterSession, SpecialNameDetection,
    SpecialNameProfile,
};
pub use format::{
    builtin_hypotheses, discover_dynamic_cribs, hard_plaintext_constraints, hypotheses_for_name,
    length_derived_cribs, shared_cribs_for_name, specific_hypotheses_for_name, DynamicModel,
    FormatHypothesis,
};
pub use hxv4::{
    decrypt_hxv4_special_index, decrypt_hxv4_special_payload, decrypt_hxv4_special_plaintext,
    hxv4_filename_hash, hxv4_path_hash, hxv4_special_nonce_slot, hxv4_special_tag,
    hxv4_startup_entry_index, inspect_hxv4_startup_plaintext, mine_name_candidates,
    recover_hxv4_effective, recover_hxv4_effective_for_name, visit_name_candidates,
    Hxv4EffectiveFilter, Hxv4Index, Hxv4IndexEntry, Hxv4IndexKeys, Hxv4NameMap, Hxv4Recovery,
    Hxv4StartupHints,
};
pub use hxv4_native::{Hxv4NativeBoundary, Hxv4NativeFilterManager, Hxv4NativeFilterState};
pub use krkr_exe::{
    analyze_krkr_exe, discover_game_executables, recover_hxv4_keys_auto,
    recover_hxv4_keys_from_exe, scan_pe_candidates, Hxv4ExeKeyRecovery, KrkrExeAnalysis,
    KrkrExePeCandidate,
};
pub use legacy_cxdec::{
    cxdec_candidate_modules, probe_cxdec_game_modules, probe_cxdec_module, probe_cxdec_path,
    probe_legacy_cxdec_bytes, probe_legacy_cxdec_module, probe_legacy_cxdec_path,
    recover_cxdec_params_from_game,
    recover_cxdec_params_from_game_with_control_blocks,
    recover_cxdec_params_from_game_with_generated_values,
    recover_coherent_runtime_cxdec_params_from_game_with_generated_values,
    recover_static_cxdec_control_block,
    recover_static_cxdec_control_blocks, recover_static_cxdec_control_blocks_from_pe_bytes,
    recover_static_cxdec_profile, recover_static_special_param_facts,
    recover_static_special_param_facts_from_pe_bytes, CxdecNativeFilter,
    CxdecParamSources, CxdecProbe, LegacyCxdecFilter, LegacyCxdecProbe,
    RecoveredCxdecParams, RecoveredSpecialParamFacts,
};
pub use magic_sniff::{
    looks_like_pe32_executable_bytes, looks_like_pe_bytes, path_looks_like_pe,
    path_looks_like_pe32_executable, sniff_bytes, MagicGuess,
};
pub use pe_normalize::{
    normalize_pe_bytes, normalize_pe_file, unpack_steamstub31_x86_bytes, NormalizedPe,
    PeNormalizationKind, PeNormalizationReport,
};
pub use progress::{
    CancellationToken, NoopProgressSink, OperationContext, ProgressEvent, ProgressEventKind,
    ProgressLevel, ProgressOutcome, ProgressSink, ProgressTask, ProgressUnit,
};
pub use repeating_xor::{
    derive_key_observations, parse_crib, parse_hex, partial_decrypt, rank_periods,
    rank_shared_periods, Crib, KeyObservation, PeriodCandidate, SharedSample,
};
pub use roundtrip::{
    roundtrip_report_json, roundtrip_report_summary, verify_roundtrip, CheckStatus,
    EntryRoundtripReport, FileFormatRoundtripReport, RoundtripCheck, RoundtripClass,
    RoundtripReport, VerifyRoundtripOptions,
};
pub use script_names::{analyze_script_names, ScriptKind, ScriptMiningReport, ScriptReference};
pub use simd::{
    count_equal, count_equal_sampled, cpu_backend_label, xor_const_in_place, xor_repeating_in_place,
};
pub use special_content::{
    complete_period_candidate_from_key, validate_special_xor_as_content_key,
    SpecialContentValidation,
};
pub use special_params::{
    derive_special_params_from_archive_data_bytes, derive_special_params_from_archive_data_text,
    setup_archive_data_text_candidates, has_setup_archive_data_special_generator,
    DerivedSpecialParams, ARCHIVE_CONTROL_BYTES,
};
pub use special_index::{
    recover_ordered_names_from_decoded, recover_ordered_names_from_decoded_for_archive,
    recover_ordered_special_names, recover_ordered_special_names_with_xor_key,
    recover_special_index, recover_special_index_with_max_xor_period,
    recover_special_index_with_progress, recover_special_index_with_xor_key, OrderedNameRecovery,
    SpecialIndexRecovery, SpecialRecoveryProgress, SpecialXorRecovery, SpecialXorScope,
};
pub use tjs_symexec::{symbolically_execute_tjs2, TjsSymbolicCall, TjsSymbolicReport};
pub use text::{
    guess_text_keys, period_is_parity_sensitive, period_score as text_period_score,
    period_score_from_counts, period_score_with_parity, rank_statistical_periods,
    rank_statistical_periods_from_scores, recovery_model_for_hypothesis, TextRecoveryModel,
};

pub use solver::{
    recover_complete_stream, recover_stream, BruteSummary, RecoveryCandidate, RecoveryConfig,
    RecoveryReport, ValidatedRecovery,
};
pub use strategy::{recovery_plan, ArchiveFamily, RecoveryPlan};
pub use validate::{
    crc32_ieee, decode_kirikiri_text, ogg_crc32, validate_hypothesis, ValidationResult,
};
pub use xp3::{
    adler32, hxv4_fake_id, hxv4_fake_name, is_protected_dummy_name, tag_to_string, Archive,
    ArchiveOptions, Entry, Hxv4Descriptor, IndexBlock, RootChunk, RootKind, Segment,
    HXV4_PROTECTED_WARNING_PREFIX, PROTECTED_DUMMY_PREFIX, PROTECTED_DUMMY_PREFIX_LEGACY_TYPO,
    XP3_MAGIC,
};

pub use xp3_meta::{
    read_manifest as read_xp3_meta_manifest, write_manifest as write_xp3_meta_manifest, Xp3Meta,
    XP3_META_FILE, XP3_META_SCHEMA,
};

pub use x86_filter::{
    initialize_x86_filter_module, probe_x86_filter_module, probe_x86_filter_path, FilterCandidate,
    FilterInitialization, FilterProbeOptions, InitializedMemoryRegion, ModuleProbe,
    StaticRegistrationProvenance, X86Xp3FilterRuntime,
};
