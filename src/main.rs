use encoding_rs::SHIFT_JIS;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use tjs2dec::decompile::srcgen_high::dump_src_file as dump_tjs_source_high;
use tjs2dec::{emit_executable_tjs, load_tjs2_bytecode};
use std::env;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Instant;
use xp3_brute::xp3_meta::{
    self, AmvFrameTransformMeta, ArchiveMeta, EntryIdentityMeta, EntryMeta, EntryOriginalMeta,
    EntryRecoveryMeta, Hxv4AeadMeta, Hxv4BoundaryMeta, Hxv4DescriptorMeta, Hxv4FilterManagerMeta,
    Hxv4FilterStateMeta, Hxv4Meta, Hxv4NativeRecoveryMeta, Hxv4RecordMeta, IndexBlockMeta, KeyMeta,
    KirikiriTextTransformMeta, OrdinarySpecialDecodedMeta, OrdinarySpecialRecordMeta,
    PbdJsonTransformMeta, PreservedFileMeta, PreservedSegmentMeta, PsbResourceBlobTransformMeta,
    PsbRootJsonTransformMeta, PsbSourceMeta, PsbTextureTransformMeta, RepeatingXorRecoveryMeta,
    RootChunkMeta, SegmentMeta, SpecialChunkMeta, TlgCodecMeta, TlgContainerChunkMeta,
    TlgContainerMeta, TlgTransformMeta, TransformMeta, UnpackMeta, X86FilterModuleMeta,
    X86FilterRecoveryMeta, Xp3Meta, XP3_META_SCHEMA,
};
use xp3_brute::{
    analyze_krkr_exe, analyze_script_names, builtin_hypotheses, complete_period_candidate_from_key,
    compute_telemetry, cpu_backend_label, cxdec_filename_md5_token, decode_amv,
    decode_plain_cxdec_name_payload,
    decode_kirikiri_text, decode_pbd,
    decode_pbd_file, decode_psb_with_global_key, decode_tlg, decode_tlg_file,
    cxdec_candidate_modules, decrypt_hxv4_special_index, decrypt_hxv4_special_payload,
    detect_filter, discover_game_executables,
    encode_amv_image_files, encode_pbd_json_file, encode_tlg_image_file, export_amv_frames,
    export_decoded_tlg, export_pbd_json, export_psb_resources_detailed, export_psb_root_json,
    gpu_info, hxv4_filename_hash, hxv4_path_hash, hxv4_special_nonce_slot, hxv4_special_tag,
    hxv4_startup_entry_index, hypotheses_for_name, inspect_hxv4_startup_plaintext, is_amv_bytes,
    is_pbd_bytes, is_psb_family_bytes, normalize_pe_file, open_filter_session,
    pack_xp3_from_manifest, parse_crib,
    parse_hex, parse_structural_cxdec_name_record_groups, pbd_json_output_path, probe_blob,
    probe_cxdec_game_modules, probe_cxdec_path,
    probe_x86_filter_path,
    psb_json_output_path, rank_periods, rank_shared_periods, rebuild_assets_from_manifest,
    recover_complete_stream, recover_hxv4_effective, recover_hxv4_effective_for_name,
    recover_hxv4_keys_auto, recover_hxv4_keys_from_exe,
    recover_ordered_special_names,
    recover_coherent_runtime_cxdec_params_from_game_with_generated_values,
    recover_cxdec_params_from_game, recover_cxdec_params_from_game_with_generated_values,
    recover_riddle_special_fixed_params_from_pe,
    recover_riddle_special_fixed_params_from_pe_bytes,
    recover_static_cxdec_control_blocks, recover_static_cxdec_control_blocks_from_pe_bytes,
    recover_static_special_param_facts, recover_static_special_param_facts_from_pe_bytes,
    recover_special_index_with_max_xor_period,
    recover_special_index_with_progress,
    recover_special_index_with_xor_key, recover_stream, recovery_plan, reset_compute_telemetry,
    shared_cribs_for_name, sniff_bytes, specific_hypotheses_for_name, tag_to_string,
    validate_hypothesis, verify_roundtrip, visit_name_candidates, AmvEncodeOptions, Archive,
    is_protected_dummy_name,
    derive_special_params_from_archive_data_text, detect_startup_storage_redirect,
    extract_embedded_pe_modules, has_setup_archive_data_special_generator,
    setup_archive_data_text_candidates, symbolically_execute_tjs2, generation_from_probe,
    ComputeMode, ContentFilterProfile, CxdecEngine, CxdecGeneration, CxdecNameProfile,
    CxdecNativeFilter,
    EmoteTextureExportFormat, Entry,
    Error as LibraryError, FilterProbeOptions, Hxv4ExeKeyRecovery, Hxv4Index,
    Hxv4IndexEntry, Hxv4IndexKeys, Hxv4NameMap, Hxv4NativeFilterManager, OrderedNameRecovery,
    PbdValue, PeriodCandidate, PsbKeySource, RebuildOptions, RecoveredCxdecParams, RecoveryConfig,
    RootKind, SharedSample, SpecialContentValidation, SpecialIndexRecovery, SpecialRecoveryProgress,
    SpecialXorRecovery, SpecialXorScope, StartupStorageRedirect, TlgCodecInfo, TlgEncodeOptions,
    TlgExportFormat, TlgExportOptions, VerifyRoundtripOptions, X86Xp3FilterRuntime, Xp3PackOptions,
    YuzControlKey,
    PBD_JSON_SCHEMA,
    PSB_ROOT_JSON_SCHEMA,
};

fn apply_filter_session(
    module: &Path,
    file_offset: u64,
    file_hash: u32,
    bytes: &mut [u8],
) -> Result<(u32, String), LibraryError> {
    // Prefer a recovered pure-Rust family implementation. If the module is not
    // one of those known families, run the ordinary XP3 extraction callback in
    // the deterministic x86 emulator. Brute-force recovery must never be the
    // substitute for a callback that can be located and executed directly.
    if let Some(mut session) = open_filter_session(Some(module))? {
        let detection = session.detection().clone();
        session.apply(file_offset, file_hash, bytes)?;
        return Ok((
            detection.callback_va.unwrap_or(0),
            detection
                .callback_source
                .unwrap_or_else(|| "native-rust".to_string()),
        ));
    }

    let mut runtime = X86Xp3FilterRuntime::open(module, false)?;
    runtime.apply(file_offset, file_hash, bytes)?;
    Ok((
        runtime.callback_va(),
        runtime.callback_source().to_string(),
    ))
}

fn resolve_filter_module(target: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let detection = detect_filter(Some(target))?;
    let selected = detection.source_module.clone().ok_or_else(|| {
        cli_error(format!(
            "no executable XP3 content filter found under {}",
            target.display()
        ))
    })?;
    eprintln!(
        "[content-filter] selected backend={:?} profile={:?} module={} callback={} route={}",
        detection.backend,
        detection.content,
        selected.display(),
        detection
            .callback_va
            .map(|v| format!("0x{v:08x}"))
            .unwrap_or_else(|| "none".to_string()),
        detection.callback_source.as_deref().unwrap_or("none"),
    );
    if matches!(detection.content, ContentFilterProfile::None) {
        return Err(cli_error("selected module has no content-filter profile").into());
    }
    Ok(selected)
}

#[derive(Clone, Debug, Default)]
struct HxCliOptions {
    key: Option<String>,
    nonce: Option<String>,
    exe: Option<PathBuf>,
    no_exe_auto: bool,
    names_file: Option<PathBuf>,
    dictionaries: Vec<PathBuf>,
    game_dir: Option<PathBuf>,
    no_name_bootstrap: bool,
}

impl HxCliOptions {
    fn keys(&self) -> Result<Option<Hxv4IndexKeys>, io::Error> {
        let key = self
            .key
            .clone()
            .or_else(|| env::var("KRKR_HX_INDEX_KEY").ok())
            .or_else(|| env::var("KRKR_HX_INDEX_KEY1").ok());
        let nonce = self
            .nonce
            .clone()
            .or_else(|| env::var("KRKR_HX_INDEX_NONCE").ok())
            .or_else(|| env::var("KRKR_HX_INDEX_KEY2").ok());
        match (key, nonce) {
            (None, None) => Ok(None),
            (Some(key), Some(nonce)) => Hxv4IndexKeys::from_hex(&key, &nonce)
                .map(Some)
                .map_err(|e| cli_error(e.to_string())),
            _ => Err(cli_error("Hxv4 Special decryption requires both --hx-key (32 bytes) and --hx-nonce (24 bytes)")),
        }
    }

    fn explicit_exe(&self) -> Option<PathBuf> {
        self.exe
            .clone()
            .or_else(|| env::var("KRKR_EXE").ok().map(PathBuf::from))
            .or_else(|| env::var("KRKR_HX_EXE").ok().map(PathBuf::from))
    }

    fn exe_auto_enabled(&self) -> bool {
        !self.no_exe_auto
            && env::var("KRKR_NO_EXE_AUTO").ok().as_deref() != Some("1")
            && env::var("KRKR_HX_NO_EXE_AUTO").ok().as_deref() != Some("1")
    }

    fn load_names(&self, archive: &Archive) -> Result<Hxv4NameMap, Box<dyn std::error::Error>> {
        let mut map = Hxv4NameMap::default();
        let explicit = self.names_file.clone();
        let automatic = archive
            .path
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.join("HxNames.lst"));
        let names_path = explicit.or_else(|| automatic.filter(|p| p.is_file()));
        if let Some(path) = names_path {
            let loaded = Hxv4NameMap::load(&path)?;
            map.paths.extend(loaded.paths);
            map.names.extend(loaded.names);
            eprintln!(
                "Hxv4 names: loaded {} path hashes + {} filename hashes from {}",
                map.paths.len(),
                map.names.len(),
                path.display()
            );
        }
        for path in &self.dictionaries {
            let text = fs::read_to_string(path)?;
            let before = map.paths.len() + map.names.len();
            for line in text.lines() {
                let candidate = line.trim();
                if candidate.is_empty() || candidate.starts_with('#') || candidate.starts_with(';')
                {
                    continue;
                }
                map.add_candidate(candidate);
                if let Some(base) = Path::new(candidate).file_name().and_then(|x| x.to_str()) {
                    map.add_candidate(base);
                }
            }
            eprintln!(
                "Hxv4 names: hashed dictionary {} (+{} candidates)",
                path.display(),
                map.paths.len() + map.names.len() - before
            );
        }
        Ok(map)
    }
}

fn parse_hx_option(
    rest: &[String],
    i: &mut usize,
    hx: &mut HxCliOptions,
) -> Result<bool, io::Error> {
    match rest[*i].as_str() {
        "--hx-key" | "--hx-key1" | "--hx-index-key1" => {
            *i += 1;
            hx.key = Some(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --hx-key value"))?
                    .clone(),
            );
            Ok(true)
        }
        "--hx-nonce" | "--hx-key2" | "--hx-index-key2" => {
            *i += 1;
            hx.nonce = Some(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --hx-nonce value"))?
                    .clone(),
            );
            Ok(true)
        }
        "--exe" | "--hx-exe" => {
            *i += 1;
            hx.exe = Some(PathBuf::from(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --exe value"))?,
            ));
            Ok(true)
        }
        "--no-exe-auto" | "--no-hx-exe-auto" | "--no-hx-static" => {
            hx.no_exe_auto = true;
            Ok(true)
        }
        "--hx-names" => {
            *i += 1;
            hx.names_file = Some(PathBuf::from(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --hx-names value"))?,
            ));
            Ok(true)
        }
        "--name-dict" => {
            *i += 1;
            hx.dictionaries.push(PathBuf::from(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --name-dict value"))?,
            ));
            Ok(true)
        }
        "--hx-game-dir" => {
            *i += 1;
            hx.game_dir = Some(PathBuf::from(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --hx-game-dir value"))?,
            ));
            Ok(true)
        }
        "--no-hx-name-bootstrap" => {
            hx.no_name_bootstrap = true;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[derive(Clone, Debug)]
struct SpecialCliOptions {
    xor_key: Option<String>,
    xor_scope: SpecialXorScope,
    max_xor_period: usize,
}

impl Default for SpecialCliOptions {
    fn default() -> Self {
        Self {
            xor_key: None,
            xor_scope: SpecialXorScope::Prefix100,
            max_xor_period: 1024,
        }
    }
}

impl SpecialCliOptions {
    fn key(&self) -> Result<Option<Vec<u8>>, io::Error> {
        match &self.xor_key {
            Some(value) => parse_hex(value)
                .map(Some)
                .map_err(|err| cli_error(format!("invalid --special-xor-key: {err}"))),
            None => Ok(None),
        }
    }
}

fn parse_special_option(
    rest: &[String],
    i: &mut usize,
    special: &mut SpecialCliOptions,
) -> Result<bool, io::Error> {
    match rest[*i].as_str() {
        "--special-xor-key" => {
            *i += 1;
            special.xor_key = Some(
                rest.get(*i)
                    .ok_or_else(|| cli_error("missing --special-xor-key value"))?
                    .clone(),
            );
            Ok(true)
        }
        "--special-xor-scope" => {
            *i += 1;
            let value = rest
                .get(*i)
                .ok_or_else(|| cli_error("missing --special-xor-scope value"))?;
            special.xor_scope = match value.as_str() {
                "prefix" | "prefix100" => SpecialXorScope::Prefix100,
                "all" | "whole" => SpecialXorScope::Whole,
                _ => return Err(cli_error("--special-xor-scope must be prefix|whole")),
            };
            Ok(true)
        }
        "--special-max-period" => {
            *i += 1;
            special.max_xor_period = parse_usize(rest.get(*i), "--special-max-period")?;
            if special.max_xor_period == 0 || special.max_xor_period > 4096 {
                return Err(cli_error("--special-max-period must be in 1..=4096"));
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnpackImageMode {
    None,
    Png,
    Jpeg,
    Bmp,
}

impl Default for UnpackImageMode {
    fn default() -> Self {
        Self::None
    }
}

impl UnpackImageMode {
    /// Lossless user-facing representation used by `--unpacker-all`.
    const DEFAULT_UNPACK: Self = Self::Png;

    fn parse(value: &str, option: &str) -> Result<Self, io::Error> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "png" => Ok(Self::Png),
            "jpg" | "jpeg" => Ok(Self::Jpeg),
            "bmp" => Ok(Self::Bmp),
            _ => Err(cli_error(format!("{option} must be png|jpg|bmp|none"))),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Bmp => "bmp",
        }
    }

    const fn tlg_format(self) -> Option<TlgExportFormat> {
        match self {
            Self::None => None,
            Self::Png => Some(TlgExportFormat::Png),
            Self::Jpeg => Some(TlgExportFormat::Jpeg),
            Self::Bmp => Some(TlgExportFormat::Bmp),
        }
    }
}

/// Generic PSB-family postprocessing policy.  PSB/SCN/MTN/PIMG are all parsed
/// through Eluna; the option only controls user-visible derived output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnpackPsbMode {
    None,
    Json,
    Png,
    Jpeg,
    Bmp,
    /// Export the editable PSB root as JSON, decode all recognizable image blobs
    /// to lossless PNGs, and preserve unrecognized resource blobs as `.bin`. This is the default PSB-family policy selected by
    /// `--unpacker-all`.
    All,
}

impl Default for UnpackPsbMode {
    fn default() -> Self {
        Self::None
    }
}

impl UnpackPsbMode {
    const DEFAULT_UNPACK: Self = Self::All;

    fn parse(value: &str) -> Result<Self, io::Error> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "json" => Ok(Self::Json),
            "png" => Ok(Self::Png),
            "jpg" | "jpeg" => Ok(Self::Jpeg),
            "bmp" => Ok(Self::Bmp),
            "all" => Ok(Self::All),
            _ => Err(cli_error("--psb must be all|json|png|jpg|bmp|none")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Json => "json",
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Bmp => "bmp",
            Self::All => "all",
        }
    }

    const fn texture_format(self) -> Option<EmoteTextureExportFormat> {
        match self {
            Self::Png => Some(EmoteTextureExportFormat::Png),
            Self::Jpeg => Some(EmoteTextureExportFormat::Jpeg),
            Self::Bmp => Some(EmoteTextureExportFormat::Bmp),
            Self::All => Some(EmoteTextureExportFormat::Png),
            Self::None | Self::Json => None,
        }
    }

    const fn wants_json(self) -> bool {
        matches!(self, Self::Json | Self::All)
    }
}

/// PBD/TJS ns0/4s0 derived-output policy. The source binary is always kept;
/// JSON is an editable, variant-preserving round-trip representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnpackPbdMode {
    None,
    Json,
}

impl Default for UnpackPbdMode {
    fn default() -> Self {
        Self::None
    }
}

impl UnpackPbdMode {
    const DEFAULT_UNPACK: Self = Self::Json;

    fn parse(value: &str) -> Result<Self, io::Error> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "json" => Ok(Self::Json),
            _ => Err(cli_error("--pbd must be json|none")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Json => "json",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum UnpackAmvMode {
    #[default]
    None,
    Png,
}

impl UnpackAmvMode {
    const DEFAULT_UNPACK: Self = Self::Png;

    fn parse(value: &str) -> Result<Self, io::Error> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "png" => Ok(Self::Png),
            _ => Err(cli_error("--amv must be png|none")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Png => "png",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnpackTjsMode {
    None,
    Emit,
    Decompile,
}

impl Default for UnpackTjsMode {
    fn default() -> Self {
        Self::None
    }
}

impl UnpackTjsMode {
    /// High-level source is the most useful editable representation for the
    /// aggregate converter preset.  `emit` remains available explicitly when
    /// the lower-level executable TJS produced by tjs2dec is preferred.
    const DEFAULT_UNPACK: Self = Self::Decompile;

    fn parse(value: &str) -> Result<Self, io::Error> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "emit" => Ok(Self::Emit),
            "decompile" | "decompiled" => Ok(Self::Decompile),
            _ => Err(cli_error("--tjs must be emit|decompile|none")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Emit => "emit",
            Self::Decompile => "decompile",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct UnpackDecodeOptions {
    tjs: UnpackTjsMode,
    tlg: UnpackImageMode,
    psb: UnpackPsbMode,
    pbd: UnpackPbdMode,
    amv: UnpackAmvMode,
}

impl UnpackDecodeOptions {
    /// Enable every decoder using that decoder's canonical, round-trip-safe
    /// user-facing output. Normal `unpack` still defaults to no conversion.
    const fn all_decoder_defaults() -> Self {
        Self {
            tjs: UnpackTjsMode::DEFAULT_UNPACK,
            tlg: UnpackImageMode::DEFAULT_UNPACK,
            psb: UnpackPsbMode::DEFAULT_UNPACK,
            pbd: UnpackPbdMode::DEFAULT_UNPACK,
            amv: UnpackAmvMode::DEFAULT_UNPACK,
        }
    }
}

fn format_duration(seconds: f64) -> String {
    let total = seconds.max(0.0).round() as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours != 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

struct Progress {
    label: &'static str,
    total: usize,
    done: AtomicUsize,
    last_percent: AtomicUsize,
    started: Instant,
    enabled: bool,
}
impl Progress {
    fn new(label: &'static str, total: usize, enabled: bool) -> Self {
        Self {
            label,
            total,
            done: AtomicUsize::new(0),
            last_percent: AtomicUsize::new(usize::MAX),
            started: Instant::now(),
            enabled,
        }
    }
    fn tick(&self) {
        let done = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.enabled || self.total == 0 {
            return;
        }
        let pct = done.saturating_mul(100) / self.total;
        let old = self.last_percent.load(Ordering::Relaxed);
        if pct != old
            && self
                .last_percent
                .compare_exchange(old, pct, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let seconds = self.started.elapsed().as_secs_f64().max(0.001);
            let rate = done as f64 / seconds;
            let remaining = self.total.saturating_sub(done);
            let eta = if rate > 0.0 {
                remaining as f64 / rate
            } else {
                0.0
            };
            eprint!(
                "\r[{:<14}] {:>3}% {}/{} {:>8.1} entries/s eta={}",
                self.label,
                pct,
                done,
                self.total,
                rate,
                format_duration(eta)
            );
            if done == self.total {
                eprintln!();
            }
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return Ok(());
    };

    match command.as_str() {
        "devices" => {
            print_devices();
        }
        "decode-pbd" => {
            let input = PathBuf::from(required(&mut args, "PBD input")?);
            let output = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| pbd_json_output_path(&input));
            if args.next().is_some() {
                return Err(cli_error("decode-pbd accepts only <input.pbd> [output.json]").into());
            }
            let bytes = fs::read(&input)?;
            let document = decode_pbd(&bytes)?;
            let json = serde_json::to_vec_pretty(&document.to_json_document())?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, json)?;
            println!(
                "decoded PBD {} seed=0x{:08x} crypt={} iv_len={} -> {}",
                document.header.variant.label(),
                document.header.seed,
                document.header.crypt,
                document.header.iv.len(),
                output.display(),
            );
        }
        "encode-pbd" | "pack-pbd" => {
            let input = PathBuf::from(required(&mut args, "PBD JSON input")?);
            let output = PathBuf::from(required(&mut args, "PBD output")?);
            if args.next().is_some() {
                return Err(cli_error("encode-pbd accepts only <input.json> <output.pbd>").into());
            }
            encode_pbd_json_file(&input, &output)?;
            let rebuilt = decode_pbd_file(&output)?;
            println!(
                "encoded PBD {} seed=0x{:08x} crypt={} iv_len={} -> {}",
                rebuilt.header.variant.label(),
                rebuilt.header.seed,
                rebuilt.header.crypt,
                rebuilt.header.iv.len(),
                output.display(),
            );
        }
        "encode-amv" | "pack-amv" => {
            let frames_dir = PathBuf::from(required(&mut args, "AMV frames directory")?);
            let output = PathBuf::from(required(&mut args, "AMV output")?);
            let rest: Vec<String> = args.collect();
            let mut options = AmvEncodeOptions::default();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--fps" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --fps value"))?;
                        options.fps_den = value
                            .parse::<u32>()
                            .map_err(|_| cli_error("--fps must be a positive integer"))?;
                        options.fps_num = 1;
                        if options.fps_den == 0 {
                            return Err(cli_error("--fps must be a positive integer").into());
                        }
                    }
                    "--quality" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --quality value"))?;
                        options.quality = value
                            .parse::<u8>()
                            .map_err(|_| cli_error("--quality must be in 1..=100"))?;
                        if !(1..=100).contains(&options.quality) {
                            return Err(cli_error("--quality must be in 1..=100").into());
                        }
                    }
                    other => {
                        return Err(cli_error(format!("unknown encode-amv option {other}")).into())
                    }
                }
                i += 1;
            }
            if !frames_dir.is_dir() {
                return Err(cli_error(format!(
                    "AMV frame input must be a directory: {}",
                    frames_dir.display()
                ))
                .into());
            }
            let mut inputs = fs::read_dir(&frames_dir)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.extension()
                        .and_then(|value| value.to_str())
                        .map(|value| {
                            matches!(
                                value.to_ascii_lowercase().as_str(),
                                "png" | "jpg" | "jpeg" | "bmp"
                            )
                        })
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>();
            inputs.sort();
            if inputs.is_empty() {
                return Err(cli_error(format!(
                    "no PNG/JPEG/BMP frames found in {}",
                    frames_dir.display()
                ))
                .into());
            }
            encode_amv_image_files(&inputs, &output, options)?;
            println!(
                "encoded AMV Mode B {} frames fps={}/{} quality={} -> {}",
                inputs.len(),
                options.fps_den,
                options.fps_num,
                options.quality,
                output.display()
            );
        }
        "encode-tlg" | "pack-tlg" => {
            let input = PathBuf::from(required(&mut args, "input image")?);
            let output = PathBuf::from(required(&mut args, "TLG output")?);
            let rest: Vec<String> = args.collect();
            let mut components = 4u8;
            let mut allow_lossy = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--components" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --components value"))?;
                        components = value
                            .parse::<u8>()
                            .map_err(|_| cli_error("--components must be 1, 3, or 4"))?;
                        if !matches!(components, 1 | 3 | 4) {
                            return Err(cli_error("--components must be 1, 3, or 4").into());
                        }
                    }
                    "--allow-lossy" => allow_lossy = true,
                    other => {
                        return Err(cli_error(format!("unknown encode-tlg option {other}")).into())
                    }
                }
                i += 1;
            }
            encode_tlg_image_file(
                &input,
                &output,
                TlgEncodeOptions {
                    components,
                    allow_lossy,
                },
            )?;
            println!(
                "encoded TLG5 {} -> {} components={components}",
                input.display(),
                output.display()
            );
        }
        "rebuild-assets" | "encode-assets" => {
            let unpack_root = PathBuf::from(required(&mut args, "unpack directory")?);
            let rest: Vec<String> = args.collect();
            let mut output_root: Option<PathBuf> = None;
            let mut in_place = false;
            let mut allow_lossy = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--out-dir" => {
                        i += 1;
                        output_root = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --out-dir value"))?,
                        ));
                    }
                    "--in-place" => in_place = true,
                    "--allow-lossy" => allow_lossy = true,
                    other => {
                        return Err(
                            cli_error(format!("unknown rebuild-assets option {other}")).into()
                        )
                    }
                }
                i += 1;
            }
            if in_place && output_root.is_some() {
                return Err(cli_error("--in-place and --out-dir are mutually exclusive").into());
            }
            let output_root = if in_place {
                unpack_root.clone()
            } else {
                output_root.unwrap_or_else(|| unpack_root.join(".xp3-rebuilt"))
            };
            let report = rebuild_assets_from_manifest(
                &unpack_root,
                &RebuildOptions {
                    output_root: output_root.clone(),
                    allow_lossy,
                    changed_only: false,
                },
            )?;
            for record in &report.records {
                println!(
                    "[encode-asset  ] kind={} source={} output={} detail={}",
                    record.kind,
                    record.source_path,
                    record.output_path.display(),
                    record.detail
                );
            }
            println!(
                "rebuilt {} transformed assets into {}",
                report.records.len(),
                output_root.display()
            );
        }
        "verify-roundtrip" => {
            let unpack_root = PathBuf::from(required(&mut args, "unpack directory")?);
            let rest: Vec<String> = args.collect();
            let mut output = unpack_root.join(".xp3-roundtrip.xp3");
            let mut rebuilt_root = None;
            let mut source_archive = None;
            let mut allow_lossy = false;
            let mut preserve_physical_anchors = true;
            let mut json_output = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--output" | "--out" => {
                        i += 1;
                        output = PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --output value"))?,
                        );
                    }
                    "--rebuilt-dir" => {
                        i += 1;
                        rebuilt_root = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --rebuilt-dir value"))?,
                        ));
                    }
                    "--source-archive" => {
                        i += 1;
                        source_archive =
                            Some(PathBuf::from(rest.get(i).ok_or_else(|| {
                                cli_error("missing --source-archive value")
                            })?));
                    }
                    "--allow-lossy" => allow_lossy = true,
                    "--compact-layout" => preserve_physical_anchors = false,
                    "--json" => json_output = true,
                    other => {
                        return Err(
                            cli_error(format!("unknown verify-roundtrip option {other}")).into(),
                        )
                    }
                }
                i += 1;
            }
            let report = verify_roundtrip(
                &unpack_root,
                &VerifyRoundtripOptions {
                    output_archive: output,
                    rebuilt_root,
                    source_archive,
                    allow_lossy,
                    preserve_physical_anchors,
                },
            )?;
            if json_output {
                println!("{}", xp3_brute::roundtrip_report_json(&report)?);
            } else {
                for entry in &report.entries {
                    println!(
                        "[roundtrip     ] entry={} path={} pack={} format={} class={:?} result={}",
                        entry.entry_index,
                        entry.path,
                        entry.pack_mode,
                        entry.file_format.detected,
                        entry.file_format.classification,
                        if entry.passed { "PASS" } else { "FAIL" },
                    );
                    for check in &entry.xp3 {
                        println!(
                            "  XP3 {:<24} {:?}: {}",
                            check.name, check.status, check.detail
                        );
                    }
                    for check in &entry.file_format.checks {
                        println!(
                            "  FILE {:<24} {:?}: {}",
                            check.name, check.status, check.detail
                        );
                    }
                }
                println!(
                    "verify-roundtrip entries={} result={} output={}",
                    report.entries.len(),
                    if report.passed { "PASS" } else { "FAIL" },
                    report.output_archive
                );
            }
            if !report.passed {
                return Err(
                    cli_error("round-trip verification failed; see entry checks above").into(),
                );
            }
        }
        "pack" | "pack-xp3" => {
            let unpack_root = PathBuf::from(required(&mut args, "unpack directory")?);
            let output = PathBuf::from(required(&mut args, "XP3 output")?);
            let rest: Vec<String> = args.collect();
            let mut options = Xp3PackOptions::default();
            let mut verbose = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--source-archive" => {
                        i += 1;
                        options.source_archive =
                            Some(PathBuf::from(rest.get(i).ok_or_else(|| {
                                cli_error("missing --source-archive value")
                            })?));
                    }
                    "--rebuilt-dir" => {
                        i += 1;
                        options.rebuilt_root = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --rebuilt-dir value"))?,
                        ));
                    }
                    "--no-rebuild-assets" => options.rebuild_assets = false,
                    "--allow-lossy" => options.allow_lossy = true,
                    "--compact-layout" => options.preserve_physical_anchors = false,
                    "--verbose" => verbose = true,
                    other => return Err(cli_error(format!("unknown pack option {other}")).into()),
                }
                i += 1;
            }
            let report = pack_xp3_from_manifest(&unpack_root, &output, &options)?;
            if verbose {
                for entry in &report.entries {
                    println!(
                        "[pack-entry    ] index={} mode={} original={} stored={} segments={} source={}",
                        entry.entry_index,
                        entry.mode,
                        entry.original_size,
                        entry.archive_size,
                        entry.segments,
                        entry.source_path.as_deref().unwrap_or("<unresolved>"),
                    );
                }
            }
            println!(
                "packed XP3 {} bytes={} entries={} reused={} reencoded={} index_blocks={} root_chunks={} special_blobs={} exact_source={}",
                report.output.display(),
                report.bytes_written,
                report.entries.len(),
                report.reused_stored_entries,
                report.reencoded_entries,
                report.index_blocks,
                report.root_chunks,
                report.special_blobs,
                report.byte_identical_to_source.map(|value| if value { "yes" } else { "no" }).unwrap_or("n/a"),
            );
        }
        "decode-tlg" => {
            let input = PathBuf::from(required(&mut args, "TLG input")?);
            let output = PathBuf::from(required(&mut args, "image output")?);
            let rest: Vec<String> = args.collect();
            let mut explicit_format: Option<TlgExportFormat> = None;
            let mut jpeg_quality = 95u8;
            let mut show_tags = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--format" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --format value"))?;
                        explicit_format = Some(match value.to_ascii_lowercase().as_str() {
                            "png" => TlgExportFormat::Png,
                            "jpg" | "jpeg" => TlgExportFormat::Jpeg,
                            "bmp" => TlgExportFormat::Bmp,
                            _ => {
                                return Err(
                                    cli_error("--format must be png, jpg/jpeg, or bmp").into()
                                )
                            }
                        });
                    }
                    "--jpeg-quality" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --jpeg-quality value"))?;
                        jpeg_quality = value.parse::<u8>().map_err(|_| {
                            cli_error("--jpeg-quality must be an integer in 1..=100")
                        })?;
                        if !(1..=100).contains(&jpeg_quality) {
                            return Err(cli_error("--jpeg-quality must be in 1..=100").into());
                        }
                    }
                    "--show-tags" => show_tags = true,
                    other => {
                        return Err(cli_error(format!("unknown decode-tlg option: {other}")).into())
                    }
                }
                i += 1;
            }

            let format = match explicit_format {
                Some(format) => format,
                None => TlgExportFormat::from_extension(&output).ok_or_else(|| {
                    cli_error(format!(
                        "cannot infer output format from {}; use .png/.jpg/.jpeg/.bmp or --format",
                        output.display()
                    ))
                })?,
            };
            let decoded = decode_tlg_file(&input)?;
            export_decoded_tlg(
                &decoded,
                &output,
                TlgExportOptions {
                    format,
                    jpeg_quality,
                },
            )?;
            let container_name = if decoded.info.container.is_some() {
                "TLG0/SDS"
            } else {
                "raw"
            };
            println!(
                "decoded {} {} {}x{} components={} -> {} ({})",
                decoded.info.version.as_str(),
                container_name,
                decoded.info.width,
                decoded.info.height,
                decoded.info.components,
                output.display(),
                format.extension(),
            );
            if let Some(container) = &decoded.info.container {
                println!(
                    "  container raw_offset={} raw_size={} chunks={} tags={}",
                    container.raw_offset,
                    container.raw_size,
                    container.chunks.len(),
                    container.tags.len(),
                );
                for chunk in &container.chunks {
                    println!(
                        "  chunk name={} offset={} size={}",
                        chunk.name, chunk.data_offset, chunk.size
                    );
                }
                if show_tags {
                    for (key, value) in &container.tags {
                        println!("  tag {:?}={:?}", key, value);
                    }
                }
            }
        }
        "pe-unpack" | "pe-normalize" => {
            let input = PathBuf::from(required(&mut args, "packed PE input")?);
            let output = PathBuf::from(required(&mut args, "normalized PE output")?);
            if args.next().is_some() {
                return Err(cli_error(
                    "pe-unpack accepts only <input.exe> <output.exe>; the outer .bind section is retained",
                )
                .into());
            }
            let normalized = normalize_pe_file(&input)?;
            let report = normalized.report.ok_or_else(|| {
                cli_error(format!(
                    "{} is not a supported packed PE (currently SteamStub 3.1.x x86)",
                    input.display()
                ))
            })?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, &normalized.bytes)?;
            println!(
                "pe-unpack kind={} app_id={} entry=0x{:08x}->0x{:08x} code_rva=0x{:08x} code_size=0x{:x} bind=kept -> {}",
                report.kind.label(),
                report.steam_app_id,
                report.source_entry_rva,
                report.original_entry_rva,
                report.code_section_rva,
                report.code_section_raw_size,
                output.display(),
            );
        }
        "filter-probe" => {
            let target = PathBuf::from(required(
                &mut args,
                "game executable, PE module, or game directory",
            )?);
            let rest: Vec<String> = args.collect();
            let mut dynamic_v2link = false;
            let mut trace_code = false;
            for arg in rest {
                match arg.as_str() {
                    "--static-only" => dynamic_v2link = false,
                    "--dynamic-v2link" => dynamic_v2link = true,
                    "--trace-code" => trace_code = true,
                    other => {
                        return Err(
                            cli_error(format!("unknown filter-probe option: {other}")).into()
                        )
                    }
                }
            }
            let cxdec_reports = probe_cxdec_path(&target)?;
            for report in &cxdec_reports {
                println!(
                    "filter-module path={} family={} backend=native-candidate confidence={} image_base=0x{:08x} decc={} control={} callback_cfg={} builder={} builder_in_decc={} keys=0x{:x}/0x{:x} complete={} missing={}",
                    report.path.display(),
                    report.profile(),
                    report.confidence,
                    report.image_base,
                    report.decc_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                    report.control_block_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                    report.callback_config_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                    report.xcode_builder_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                    report.xcode_builder_in_decc,
                    report.key0.unwrap_or(0),
                    report.key1.unwrap_or(0),
                    report.native_complete(),
                    if report.missing_native_fields().is_empty() { "none".to_string() } else { report.missing_native_fields().join(",") },
                );
                println!("  reasons {}", report.reasons.join("; "));
                if report.profile() == "cxdec-legacy-decc-v1" || dynamic_v2link {
                    match CxdecNativeFilter::open(&report.path) {
                        Ok(filter) => println!(
                            "  native-init ok mode={} resolved-family={} lanes=128 control={} wrapper_period={} keys=0x{:x}/0x{:x}",
                            filter.init_mode(), filter.probe().profile(),
                            filter.probe().control_block_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                            filter.outer_xor_period().map(|v| v.to_string()).unwrap_or_else(|| "none".into()),
                            filter.key0(), filter.key1()
                        ),
                        Err(err) => println!("  native-init failed {err}"),
                    }
                } else {
                    println!(
                        "  native-init skipped (static CXDEC parameters incomplete or dynamic module execution not explicitly requested)"
                    );
                }
            }

            let recovered_params = recover_cxdec_params_from_game(&target)?;
            println!(
                "cxdec-params complete_candidates={}",
                recovered_params.len()
            );
            for (index, candidate) in recovered_params.iter().take(32).enumerate() {
                let generator = match candidate.content.generator {
                    xp3_brute::CxdecGeneratorKind::Classic => "classic".to_string(),
                    xp3_brute::CxdecGeneratorKind::Cabbage { random_seed } => {
                        format!("cabbage:random_seed=0x{random_seed:08x}")
                    }
                };
                println!(
                    "  candidate={} mask=0x{:08x} offset=0x{:08x} prolog={:?} even={:?} odd={:?} generator={} control_bytes={} prefix8={} mask_offset_module={} control_module={} dispatch_module={} random_seed_module={} wrapper_module={}",
                    index + 1,
                    candidate.content.mask,
                    candidate.content.offset,
                    candidate.content.prolog_order,
                    candidate.content.even_branch_order,
                    candidate.content.odd_branch_order,
                    generator,
                    candidate.content.control_block.len(),
                    !candidate.content.wrappers.is_empty(),
                    candidate.sources.mask_offset.display(),
                    candidate.sources.control_block.display(),
                    candidate.sources.dispatch_orders.display(),
                    candidate.sources.random_seed.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
                    candidate.sources.wrapper.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
                );
            }
            if recovered_params.len() > 32 {
                println!("  ... {} more candidates", recovered_params.len() - 32);
            }

            let reports = match probe_x86_filter_path(
                &target,
                FilterProbeOptions {
                    dynamic_v2link,
                    trace_code,
                },
            ) {
                Ok(value) => value,
                Err(err) if !cxdec_reports.is_empty() => {
                    println!("generic-x86-fallback-probe-error {err}");
                    Vec::new()
                }
                Err(err) => return Err(err.into()),
            };
            if reports.is_empty() && cxdec_reports.is_empty() && recovered_params.is_empty() {
                return Err(cli_error(format!(
                    "no XP3 extraction-filter candidate found under {}",
                    target.display()
                ))
                .into());
            }
            for report in &reports {
                println!(
                    "filter-module path={} backend=generic-x86 machine=0x{:04x} image_base=0x{:08x} v2link={} captured={}",
                    report.path.display(),
                    report.machine,
                    report.image_base,
                    report.v2link_va.map(|v| format!("0x{v:08x}")).unwrap_or_else(|| "none".into()),
                    report.captured_callback.map(|v| format!("0x{v:08x}")).unwrap_or_else(|| "none".into()),
                );
                if !report.requested_exports.is_empty() {
                    println!(
                        "  requested-exports {}",
                        report.requested_exports.join(" | ")
                    );
                }
                for note in &report.initialization_notes {
                    println!("  initialization-note {note}");
                }
                if let Some(error) = &report.dynamic_error {
                    println!("  dynamic-fallback-error {error}");
                }
                for (rank, candidate) in report.candidates.iter().take(8).enumerate() {
                    println!(
                        "  candidate rank={} callback=0x{:08x} proven={} score={} abi_score={} source={} reasons={}",
                        rank + 1,
                        candidate.callback_va,
                        candidate.registration.is_some(),
                        candidate.score,
                        candidate.abi_score,
                        candidate.source,
                        candidate.reasons.join("; "),
                    );
                    if let Some(provenance) = &candidate.registration {
                        println!(
                            "    registration v2link=0x{:08x} wrapper={} wrapper_call={} api_name=0x{:08x} name_xref=0x{:08x} resolver_call=0x{:08x} function_slot={} callback_push=0x{:08x} registration_call=0x{:08x}",
                            provenance.v2link_va,
                            provenance
                                .wrapper_va
                                .map(|value| format!("0x{value:08x}"))
                                .unwrap_or_else(|| "inline".into()),
                            provenance
                                .wrapper_call_va
                                .map(|value| format!("0x{value:08x}"))
                                .unwrap_or_else(|| "inline".into()),
                            provenance.api_name_va,
                            provenance.api_name_xref_va,
                            provenance.resolver_call_va,
                            provenance
                                .function_slot_va
                                .map(|value| format!("0x{value:08x}"))
                                .unwrap_or_else(|| "none".into()),
                            provenance.callback_push_va,
                            provenance.registration_call_va,
                        );
                    }
                }
            }
        }
        "filter-apply" => {
            let module = PathBuf::from(required(&mut args, "PE filter module")?);
            let input = PathBuf::from(required(&mut args, "input bytes")?);
            let output = PathBuf::from(required(&mut args, "output bytes")?);
            let rest: Vec<String> = args.collect();
            let mut file_hash: Option<u32> = None;
            let mut file_offset = 0u64;
            let mut trace_code = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--hash" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --hash value"))?;
                        file_hash = Some(
                            parse_integer_u64(value, "--hash")?
                                .try_into()
                                .map_err(|_| cli_error("--hash must fit u32"))?,
                        );
                    }
                    "--offset" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --offset value"))?;
                        file_offset = parse_integer_u64(value, "--offset")?;
                    }
                    "--trace-code" => trace_code = true,
                    other => {
                        return Err(
                            cli_error(format!("unknown filter-apply option: {other}")).into()
                        )
                    }
                }
                i += 1;
            }
            let file_hash =
                file_hash.ok_or_else(|| cli_error("filter-apply requires --hash <u32|0xHEX>"))?;
            let mut bytes = fs::read(&input)?;
            let callback;
            let source;
            let requested_exports;
            match CxdecNativeFilter::open(&module) {
                Ok(filter) => {
                    filter.apply(file_offset, file_hash, &mut bytes)?;
                    callback = 0;
                    source = format!("cxdec-native:{}", filter.init_mode());
                    requested_exports = Vec::new();
                    println!(
                        "cxdec-native profile={} init={} confidence={} keys=0x{:x}/0x{:x} control={} wrapper_period={} callback_cfg={} builder={}",
                        filter.probe().profile(),
                        filter.init_mode(),
                        filter.probe().confidence,
                        filter.key0(),
                        filter.key1(),
                        filter.probe().control_block_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                        filter.outer_xor_period().map(|v| v.to_string()).unwrap_or_else(|| "none".into()),
                        filter.probe().callback_config_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                        filter.probe().xcode_builder_rva.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
                    );
                }
                Err(_) => {
                    if trace_code {
                        let mut runtime = X86Xp3FilterRuntime::open(&module, true)?;
                        runtime.apply(file_offset, file_hash, &mut bytes)?;
                        callback = runtime.callback_va();
                        source = runtime.callback_source().to_string();
                        requested_exports = runtime.requested_exports().to_vec();
                    } else {
                        let (selected_callback, selected_source) =
                            apply_filter_session(&module, file_offset, file_hash, &mut bytes)?;
                        callback = selected_callback;
                        source = selected_source;
                        requested_exports = Vec::new();
                    }
                }
            }
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&output, &bytes)?;
            println!(
                "filter-applied module={} callback=0x{:08x} source={} offset={} hash=0x{:08x} bytes={} -> {}",
                module.display(),
                callback,
                source,
                file_offset,
                file_hash,
                bytes.len(),
                output.display(),
            );
            if !requested_exports.is_empty() {
                println!("  requested-exports {}", requested_exports.join(" | "));
            }
        }
        "exe-analyze" => {
            let exe = required(&mut args, "game executable")?;
            let rest: Vec<String> = args.collect();
            let mut archive_path: Option<PathBuf> = None;
            let mut dump_bootstrap: Option<PathBuf> = None;
            let mut dump_startup: Option<PathBuf> = None;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--archive" => {
                        i += 1;
                        archive_path = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --archive value"))?,
                        ));
                    }
                    "--dump-bootstrap" => {
                        i += 1;
                        dump_bootstrap =
                            Some(PathBuf::from(rest.get(i).ok_or_else(|| {
                                cli_error("missing --dump-bootstrap value")
                            })?));
                    }
                    "--dump-startup" => {
                        i += 1;
                        dump_startup = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --dump-startup value"))?,
                        ));
                    }
                    other => {
                        return Err(cli_error(format!("unknown exe-analyze option: {other}")).into())
                    }
                }
                i += 1;
            }
            let analysis = analyze_krkr_exe(Path::new(&exe)).map_err(cli_error)?;
            println!(
                "krkr-exe selected_pe=0x{:x} pe_candidates={} salt_file_offset=0x{:x} startup_path={} bootstrap_path={} bootstrap_dll_bytes={}",
                analysis.pe_offset, analysis.pe_candidates.len(), analysis.salt_file_offset,
                analysis.startup_bres_path, analysis.bootstrap_bres_path, analysis.bootstrap_dll.len()
            );
            for candidate in &analysis.pe_candidates {
                println!(
                    "  pe offset=0x{:x} machine=0x{:04x} sections={} resources={} krkr_markers={}",
                    candidate.file_offset,
                    candidate.machine,
                    candidate.sections,
                    candidate.has_resources,
                    candidate.kirikiri_markers
                );
            }
            println!(
                "krkr-bootstrap params={} unique={} warning={:?} prefix_candidates={} archive_seed_candidates={}",
                bytes_hex(&analysis.params), analysis.unique, analysis.warning,
                analysis.bootstrap_prefix_candidates.len(),
                analysis.archive_seed_candidates.iter().map(|v| bytes_hex(v)).collect::<Vec<_>>().join(",")
            );
            for value in analysis.bootstrap_prefix_candidates.iter().take(8) {
                println!("  bootstrap-prefix {:?}", value);
            }
            if let Some(path) = dump_bootstrap {
                fs::write(&path, &analysis.bootstrap_dll)?;
                println!("wrote bootstrap DLL {}", path.display());
            }
            if let Some(path) = dump_startup {
                fs::write(&path, &analysis.startup_tjs)?;
                println!("wrote STARTUP.TJS {}", path.display());
            }
            if let Some(path) = archive_path {
                let archive = Archive::open(&path)?;
                if !archive.is_hxv4() {
                    return Err(cli_error(format!("{} is not HXV4", path.display())).into());
                }
                let blob = archive.hxv4_special_index_bytes().ok_or_else(|| {
                    cli_error("Hxv4 special-index descriptor points outside archive")
                })?;
                let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
                let recovery =
                    recover_hxv4_keys_from_exe(Path::new(&exe), blob, flags).map_err(cli_error)?;
                println!(
                    "hxv4-exe validated key={} nonce_slot={} nonce={} nonce0={} nonce1={} archive_seed={} special_entries={} bootstrap_prefix={:?}",
                    recovery.key_hex(), recovery.nonce_slot, recovery.nonce_hex(), recovery.nonce0_hex(), recovery.nonce1_hex(),
                    recovery.archive_seed_hex(), recovery.index.entries.len(), recovery.bootstrap_prefix
                );
            }
        }
        "inspect" => {
            let path = required(&mut args, "archive")?;
            let archive = Archive::open(path)?;
            let rest: Vec<String> = args.collect();
            let mut hx = HxCliOptions::default();
            let mut special = SpecialCliOptions::default();
            let mut i = 0usize;
            while i < rest.len() {
                if parse_special_option(&rest, &mut i, &mut special)? {
                    i += 1;
                    continue;
                }
                if parse_hx_option(&rest, &mut i, &mut hx)? {
                    i += 1;
                    continue;
                }
                return Err(cli_error(format!("unknown inspect option: {}", rest[i])).into());
            }
            // HXV4 must resolve/authenticate Special before the ordinary entry
            // view is printed; fake names are not a valid basis for later work.
            let hx_index = if archive.is_hxv4() {
                load_hx_index(&archive, &hx)?
            } else {
                None
            };
            let ordered_names =
                recover_ordered_names_with_hx_options(&archive, &hx, &special, true)?;
            inspect(&archive, ordered_names.as_ref());
            inspect_hx_index(&archive, hx_index.as_ref())?;
        }
        "dump-special" => {
            let path = required(&mut args, "archive")?;
            let output = required(&mut args, "output file")?;
            let archive = Archive::open(path)?;
            let (root_index, data) = archive
                .root_chunks
                .iter()
                .enumerate()
                .find_map(|(i, _)| {
                    archive
                        .special_index_bytes_for_root(i)
                        .map(|data| (i, data))
                })
                .ok_or_else(|| {
                    cli_error("archive has no recognized out-of-line special-index descriptor")
                })?;
            fs::write(&output, data)?;
            println!(
                "wrote special-index blob root={} bytes={} {}",
                root_index,
                data.len(),
                output
            );
        }
        "scan-special" => {
            let path = required(&mut args, "archive")?;
            let archive = Archive::open(path)?;
            let rest: Vec<String> = args.collect();
            let mut special = SpecialCliOptions::default();
            let mut i = 0usize;
            while i < rest.len() {
                if !parse_special_option(&rest, &mut i, &mut special)? {
                    return Err(
                        cli_error(format!("unknown scan-special option: {}", rest[i])).into(),
                    );
                }
                i += 1;
            }
            scan_special(&archive, &special)?;
        }
        "decode-special" => {
            let path = required(&mut args, "archive")?;
            let output = required(&mut args, "output file")?;
            let archive = Archive::open(path)?;
            let rest: Vec<String> = args.collect();
            let mut special = SpecialCliOptions::default();
            let mut hx = HxCliOptions::default();
            let mut i = 0usize;
            while i < rest.len() {
                if parse_special_option(&rest, &mut i, &mut special)? {
                    i += 1;
                    continue;
                }
                if parse_hx_option(&rest, &mut i, &mut hx)? {
                    i += 1;
                    continue;
                }
                return Err(
                    cli_error(format!("unknown decode-special option: {}", rest[i])).into(),
                );
            }
            decode_special(&archive, Path::new(&output), &special, &hx)?;
        }
        "hx-index" => {
            let path = required(&mut args, "archive")?;
            let archive = Archive::open(path)?;
            let rest: Vec<String> = args.collect();
            let mut hx = HxCliOptions::default();
            let mut output: Option<PathBuf> = None;
            let mut i = 0usize;
            while i < rest.len() {
                if parse_hx_option(&rest, &mut i, &mut hx)? {
                    i += 1;
                    continue;
                }
                match rest[i].as_str() {
                    "--out" => {
                        i += 1;
                        output = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --out value"))?,
                        ));
                    }
                    other => {
                        return Err(cli_error(format!("unknown hx-index option: {other}")).into())
                    }
                }
                i += 1;
            }
            let index = load_hx_index(&archive, &hx)?.ok_or_else(|| cli_error("Hxv4 Hx-object index decryption requires validated key material. Automatic EXE analysis found no usable game EXE; use --exe PATH or explicit --hx-key/--hx-nonce."))?;
            print_hx_index(&index);
            if let Some(path) = output {
                write_hx_index_report(&index, &path)?;
                println!("wrote {}", path.display());
            }
        }
        "extract-raw" => {
            let path = required(&mut args, "archive")?;
            let out = required(&mut args, "output directory")?;
            extract_raw(&Archive::open(path)?, Path::new(&out))?;
        }
        "shared-probe" => {
            let path = required(&mut args, "archive")?;
            let archive = Archive::open(path)?;
            let mut max_period = 1024usize;
            let mut top = 20usize;
            let mut progress = true;
            let rest: Vec<String> = args.collect();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--max-period" => {
                        i += 1;
                        max_period = parse_usize(rest.get(i), "--max-period")?;
                    }
                    "--top" => {
                        i += 1;
                        top = parse_usize(rest.get(i), "--top")?;
                    }
                    "--no-progress" => {
                        progress = false;
                    }
                    other => {
                        return Err(
                            cli_error(format!("unknown shared-probe option: {other}")).into()
                        )
                    }
                }
                i += 1;
            }
            shared_probe(&archive, max_period, top, progress)?;
        }
        "unpack" => {
            let path = required(&mut args, "archive")?;
            let out = required(&mut args, "output directory")?;
            let archive = Archive::open(path)?;
            let mut max_period = 1024usize;
            let mut top_periods = 64usize;
            let mut exhaustive_dynamic = false;
            let mut compute_mode = ComputeMode::Auto;
            let mut hx = HxCliOptions::default();
            let mut special = SpecialCliOptions::default();
            let mut progress = true;
            let mut verbose = false;
            let mut decode_options = UnpackDecodeOptions::default();
            let mut unpacker_all = false;
            let mut x86_filter_target: Option<PathBuf> = None;
            let mut explicit_tjs = false;
            let mut explicit_tlg = false;
            let mut explicit_psb = false;
            let mut explicit_pbd = false;
            let mut explicit_amv = false;
            let rest: Vec<String> = args.collect();
            let mut i = 0usize;
            while i < rest.len() {
                if matches!(
                    rest[i].as_str(),
                    "--hx-key"
                        | "--hx-key1"
                        | "--hx-index-key1"
                        | "--hx-nonce"
                        | "--hx-key2"
                        | "--hx-index-key2"
                        | "--exe"
                        | "--hx-exe"
                        | "--no-exe-auto"
                        | "--no-hx-exe-auto"
                        | "--no-hx-static"
                        | "--hx-names"
                        | "--name-dict"
                        | "--hx-game-dir"
                        | "--no-hx-name-bootstrap"
                ) {
                    parse_hx_option(&rest, &mut i, &mut hx)?;
                    i += 1;
                    continue;
                }
                if matches!(
                    rest[i].as_str(),
                    "--special-xor-key" | "--special-xor-scope" | "--special-max-period"
                ) {
                    parse_special_option(&rest, &mut i, &mut special)?;
                    i += 1;
                    continue;
                }
                match rest[i].as_str() {
                    "--max-period" => {
                        i += 1;
                        max_period = parse_usize(rest.get(i), "--max-period")?;
                    }
                    "--top-periods" => {
                        i += 1;
                        top_periods = parse_usize(rest.get(i), "--top-periods")?;
                    }
                    "--exhaustive-dynamic" => exhaustive_dynamic = true,
                    "--compute" => {
                        i += 1;
                        compute_mode = parse_compute(rest.get(i))?;
                    }
                    "--unpacker-all" => unpacker_all = true,
                    "--filter-exe" | "--filter-pe" => {
                        i += 1;
                        x86_filter_target = Some(PathBuf::from(
                            rest.get(i)
                                .ok_or_else(|| cli_error("missing --filter-exe value"))?,
                        ));
                    }
                    "--tjs" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --tjs value"))?;
                        decode_options.tjs = UnpackTjsMode::parse(value)?;
                        explicit_tjs = true;
                    }
                    "--tlg" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --tlg value"))?;
                        decode_options.tlg = UnpackImageMode::parse(value, "--tlg")?;
                        explicit_tlg = true;
                    }
                    "--psb" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --psb value"))?;
                        decode_options.psb = UnpackPsbMode::parse(value)?;
                        explicit_psb = true;
                    }
                    "--pbd" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --pbd value"))?;
                        decode_options.pbd = UnpackPbdMode::parse(value)?;
                        explicit_pbd = true;
                    }
                    "--amv" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --amv value"))?;
                        decode_options.amv = UnpackAmvMode::parse(value)?;
                        explicit_amv = true;
                    }
                    "--no-progress" => progress = false,
                    "--verbose" => verbose = true,
                    other => {
                        return Err(cli_error(format!("unknown unpack option: {other}")).into())
                    }
                }
                i += 1;
            }
            if unpacker_all {
                let defaults = UnpackDecodeOptions::all_decoder_defaults();
                if !explicit_tjs {
                    decode_options.tjs = defaults.tjs;
                }
                if !explicit_tlg {
                    decode_options.tlg = defaults.tlg;
                }
                if !explicit_psb {
                    decode_options.psb = defaults.psb;
                }
                if !explicit_pbd {
                    decode_options.pbd = defaults.pbd;
                }
                if !explicit_amv {
                    decode_options.amv = defaults.amv;
                }
            }
            let x86_filter_module = match x86_filter_target.as_deref() {
                Some(target) => match resolve_filter_module(target) {
                    Ok(module) => Some(module),
                    Err(error) => {
                        eprintln!(
                            "[x86-filter    ] generic callback unavailable for {}: {}; static CXDEC parameter scan will still use the supplied target",
                            target.display(),
                            error,
                        );
                        None
                    }
                },
                None => None,
            };
            unpack(
                &archive,
                Path::new(&out),
                max_period,
                top_periods,
                exhaustive_dynamic,
                compute_mode,
                &hx,
                &special,
                &decode_options,
                x86_filter_module.as_deref(),
                x86_filter_target.as_deref(),
                progress,
                verbose,
            )?;
        }
        "xor-recover" => {
            let path = required(&mut args, "file")?;
            let data = fs::read(path)?;
            let mut min_period = 1usize;
            let mut max_period = 1024usize;
            let mut top = 20usize;
            let mut cribs = Vec::new();
            let rest: Vec<String> = args.collect();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--min-period" => {
                        i += 1;
                        min_period = parse_usize(rest.get(i), "--min-period")?;
                    }
                    "--max-period" => {
                        i += 1;
                        max_period = parse_usize(rest.get(i), "--max-period")?;
                    }
                    "--top" => {
                        i += 1;
                        top = parse_usize(rest.get(i), "--top")?;
                    }
                    "--crib" => {
                        i += 1;
                        let value = rest
                            .get(i)
                            .ok_or_else(|| cli_error("missing --crib value"))?;
                        cribs.push(parse_crib(value)?);
                    }
                    other => cribs.push(parse_crib(other)?),
                }
                i += 1;
            }
            let ranked = rank_periods(&data, &cribs, min_period, max_period)?;
            print_periods(&ranked, top);
        }
        "probe" => {
            let path = required(&mut args, "archive")?;
            let archive = Archive::open(path)?;
            let mut max_period = 1024usize;
            let mut top = 5usize;
            let mut exhaustive_dynamic = false;
            let mut compute_mode = ComputeMode::Auto;
            let rest: Vec<String> = args.collect();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--max-period" => {
                        i += 1;
                        max_period = parse_usize(rest.get(i), "--max-period")?;
                    }
                    "--top" => {
                        i += 1;
                        top = parse_usize(rest.get(i), "--top")?;
                    }
                    "--exhaustive-dynamic" => exhaustive_dynamic = true,
                    "--compute" => {
                        i += 1;
                        compute_mode = parse_compute(rest.get(i))?;
                    }
                    other => return Err(cli_error(format!("unknown probe option: {other}")).into()),
                }
                i += 1;
            }
            probe(&archive, max_period, top, exhaustive_dynamic, compute_mode)?;
        }
        "help" | "--help" | "-h" => usage(),
        _ => {
            usage();
            return Err(cli_error(format!("unknown command: {command}")).into());
        }
    }

    Ok(())
}

fn parse_integer_u64(value: &str, option: &str) -> Result<u64, io::Error> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    parsed.map_err(|_| {
        cli_error(format!(
            "{option} expects an integer or 0x-prefixed hexadecimal value, got {value:?}"
        ))
    })
}

fn cli_error(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn required(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, io::Error> {
    args.next()
        .ok_or_else(|| cli_error(format!("missing {name}")))
}

fn parse_usize(value: Option<&String>, option: &str) -> Result<usize, io::Error> {
    value
        .ok_or_else(|| cli_error(format!("missing {option} value")))?
        .parse::<usize>()
        .map_err(|_| cli_error(format!("invalid {option} value")))
}

fn parse_compute(value: Option<&String>) -> Result<ComputeMode, io::Error> {
    value
        .ok_or_else(|| cli_error("missing --compute value"))?
        .parse::<ComputeMode>()
        .map_err(cli_error)
}

fn print_devices() {
    println!("CPU: available (Rayon), kernel={}", cpu_backend_label());
    match gpu_info() {
        Ok(Some(info)) => {
            println!("GPU: {}", info.name);
            println!("  backend={}", info.backend);
            println!("  type={}", info.device_type);
            if !info.driver.is_empty() {
                println!("  driver={}", info.driver);
            }
            if !info.driver_info.is_empty() {
                println!("  driver_info={}", info.driver_info);
            }
        }
        Ok(None) => println!("GPU: disabled at build time; CPU fallback active"),
        Err(error) => println!("GPU: unavailable ({error}); CPU fallback active"),
    }
}

fn resolve_hx_keys(
    archive: &Archive,
    options: &HxCliOptions,
) -> Result<Option<Hxv4IndexKeys>, Box<dyn std::error::Error>> {
    if !archive.is_hxv4() {
        return Ok(None);
    }
    if let Some(keys) = options.keys()? {
        eprintln!("[hxv4-key     ] source=explicit key_bytes=32 nonce_bytes=24");
        return Ok(Some(keys));
    }

    let explicit_exe = options.explicit_exe();
    if explicit_exe.is_none() && !options.exe_auto_enabled() {
        return Ok(None);
    }
    let Some(archive_path) = archive.path.as_deref() else {
        if explicit_exe.is_some() {
            return Err(
                cli_error("--exe requires an archive opened from a filesystem path").into(),
            );
        }
        return Ok(None);
    };
    let blob = archive
        .hxv4_special_index_bytes()
        .ok_or_else(|| cli_error("Hxv4 special-index descriptor points outside archive"))?;
    let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
    let recovery = recover_hxv4_keys_auto(archive_path, blob, flags, explicit_exe.as_deref())
        .map_err(|e| cli_error(format!("HXV4 EXE analysis/key derivation failed: {e}")))?;
    let Some(recovery) = recovery else {
        return Ok(None);
    };
    eprintln!(
        "[hxv4-exe     ] exe={} selected_pe=0x{:x} bootstrap_candidates={} archive_seed={} nonce_slot={} special=authenticated",
        recovery.exe.display(), recovery.pe_offset, recovery.bootstrap_candidates_tested,
        recovery.archive_seed_hex(), recovery.nonce_slot
    );
    eprintln!(
        "[hxv4-key     ] source=exe-static key={} nonce={} nonce0={} nonce1={}",
        recovery.key_hex(),
        recovery.nonce_hex(),
        recovery.nonce0_hex(),
        recovery.nonce1_hex()
    );
    Ok(Some(recovery.keys))
}

fn load_hx_index(
    archive: &Archive,
    options: &HxCliOptions,
) -> Result<Option<Hxv4Index>, Box<dyn std::error::Error>> {
    if !archive.is_hxv4() {
        return Ok(None);
    }
    let Some(keys) = resolve_hx_keys(archive, options)? else {
        return Ok(None);
    };
    let blob = archive
        .hxv4_special_index_bytes()
        .ok_or_else(|| cli_error("Hxv4 special-index descriptor points outside archive"))?;

    // The authenticated/decompressed Special payload is internal recovery state.
    // `unpack` never materializes it inside the user extraction tree.

    let mut index = decrypt_hxv4_special_index(blob, &keys)?;
    let names = options.load_names(archive)?;
    index.apply_names(&names);
    Ok(Some(index))
}

fn resolve_hx_native_recovery(
    archive: &Archive,
    options: &HxCliOptions,
) -> Result<Option<Hxv4ExeKeyRecovery>, Box<dyn std::error::Error>> {
    if !archive.is_hxv4() {
        return Ok(None);
    }
    let explicit_exe = options.explicit_exe();
    if explicit_exe.is_none() && !options.exe_auto_enabled() {
        return Ok(None);
    }
    let Some(archive_path) = archive.path.as_deref() else {
        return Ok(None);
    };
    let blob = archive
        .hxv4_special_index_bytes()
        .ok_or_else(|| cli_error("Hxv4 special-index descriptor points outside archive"))?;
    let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
    let recovery = recover_hxv4_keys_auto(archive_path, blob, flags, explicit_exe.as_deref())
        .map_err(|e| cli_error(format!("HXV4 native FilterManager recovery failed: {e}")))?;
    Ok(recovery)
}

const HXV4_BOOTSTRAP_MAX_ROUNDS: usize = 32;
const HXV4_LOOSE_MINE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const HXV4_BLIND_TEXT_MAX_BYTES: usize = 2 * 1024 * 1024;
const HXV4_COMMON_EXTENSIONS: &[&str] = &[
    // Script / metadata families.
    "tjs", "ks", "kag", "pbd", "txt", "csv", "json", "asd", "ini", "cfg", "xml",
    // KiriKiri image / container families.
    "tlg", "png", "jpg", "jpeg", "webp", "gif", "bmp", "tga", "dds", "ico", "cur", "psb", "psb.m",
    "pimg", "scn", "mmo", "emtbytes", "mtn", "dpak",
    // Audio / video families commonly embedded in XP3.
    "ogg", "oga", "opus", "wav", "flac", "mp3", "mid", "midi", "mp4", "m4a", "m4v", "mov", "webm",
    "mkv", "avi", "wmv", "wma", "asf", "mpg", "mpeg", "m1v", "mpv", "m2v", "264", "h264", "avc",
    // Fonts, archives, and native plugins.
    "ttf", "otf", "ttc", "woff", "woff2", "tft", "zip", "jar", "7z", "gz", "dll", "tpm", "ax",
    "exe", "bin", "dat",
];

#[derive(Debug)]
struct Hxv4BootstrapArchive {
    path: PathBuf,
    archive: Archive,
    index: Hxv4Index,
    /// Entries already processed with a resolved real filename.
    processed_entries: HashSet<usize>,
    /// Hash-only entries already attempted through the filename-independent
    /// format/content bootstrap. A later exact name match can still process
    /// the same entry again through the stronger filename-specific path.
    blind_processed_entries: HashSet<usize>,
}

fn hxv4_game_root(archive: &Archive, options: &HxCliOptions) -> Option<PathBuf> {
    options
        .game_dir
        .clone()
        .or_else(|| archive.path.as_ref()?.parent().map(Path::to_path_buf))
}

#[derive(Debug, Default)]
struct Hxv4HashTargets {
    path_hashes: HashSet<[u8; 8]>,
    name_hashes: HashSet<[u8; 32]>,
    path_hash_hex: HashSet<String>,
    name_hash_hex: HashSet<String>,
}

impl Hxv4HashTargets {
    fn add_index(&mut self, index: &Hxv4Index) {
        for entry in &index.entries {
            self.path_hashes.insert(entry.path_hash);
            self.name_hashes.insert(entry.name_hash);
            self.path_hash_hex.insert(entry.path_hash_hex());
            self.name_hash_hex.insert(entry.name_hash_hex());
        }
    }

    fn retain_only_targets(&self, map: &mut Hxv4NameMap) {
        map.paths
            .retain(|hash, _| self.path_hash_hex.contains(hash));
        map.names
            .retain(|hash, _| self.name_hash_hex.contains(hash));
    }

    fn add_candidate(&self, map: &mut Hxv4NameMap, candidate: &str) -> usize {
        let before = map.paths.len() + map.names.len();
        let canonical = candidate.trim().replace('\\', "/");
        if canonical.is_empty() {
            return 0;
        }
        if canonical == "/" {
            let hash = hxv4_path_hash("/");
            if self.path_hashes.contains(&hash) {
                map.paths
                    .entry(hex_upper_main(&hash))
                    .or_insert_with(|| "/".to_string());
            }
            return map.paths.len() + map.names.len() - before;
        }

        let parts: Vec<&str> = canonical
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        if parts.is_empty() {
            return 0;
        }

        let basename = parts[parts.len() - 1];
        let name_hash = hxv4_filename_hash(basename);
        if self.name_hashes.contains(&name_hash) {
            map.names
                .entry(hex_upper_main(&name_hash))
                .or_insert_with(|| basename.to_string());
        }

        if parts.len() > 1 || canonical.starts_with('/') {
            let root_hash = hxv4_path_hash("/");
            if self.path_hashes.contains(&root_hash) {
                map.paths
                    .entry(hex_upper_main(&root_hash))
                    .or_insert_with(|| "/".to_string());
            }
            let dir_count = parts.len().saturating_sub(1);
            let mut prefix = String::new();
            for (idx, part) in parts.iter().take(dir_count).enumerate() {
                if idx != 0 {
                    prefix.push('/');
                }
                prefix.push_str(part);
                let hash = hxv4_path_hash(&prefix);
                if self.path_hashes.contains(&hash) {
                    map.paths
                        .entry(hex_upper_main(&hash))
                        .or_insert_with(|| prefix.clone());
                }
                let rooted = format!("/{prefix}");
                let rooted_hash = hxv4_path_hash(&rooted);
                if self.path_hashes.contains(&rooted_hash) {
                    map.paths
                        .entry(hex_upper_main(&rooted_hash))
                        .or_insert(rooted);
                }
            }
        }
        map.paths.len() + map.names.len() - before
    }
}

fn hex_upper_main(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02X}");
    }
    out
}

fn hxv4_map_size(map: &Hxv4NameMap) -> usize {
    map.paths.len() + map.names.len()
}

fn hxv4_index_resolved_names(index: &Hxv4Index) -> usize {
    index
        .entries
        .iter()
        .filter(|entry| entry.archive_slot == 0 && entry.name.is_some())
        .count()
}

fn hxv4_index_current_names(index: &Hxv4Index) -> usize {
    index
        .entries
        .iter()
        .filter(|entry| entry.archive_slot == 0)
        .count()
}

fn add_hxv4_candidate_variants(
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
    raw: &str,
) -> usize {
    let before = hxv4_map_size(map);
    let trimmed = raw.trim().trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | '[' | ']' | '{' | '}' | '(' | ')' | ',' | ';'
        )
    });
    if trimmed.is_empty() {
        return 0;
    }

    let normalized = trimmed.replace('\\', "/");
    let mut variants = [Some(normalized), None];
    if let Some((_, tail)) = trimmed.split_once("://./") {
        variants[1] = Some(tail.replace('\\', "/"));
    } else if let Some((_, tail)) = trimmed.split_once("://") {
        variants[1] = Some(tail.trim_start_matches("./").replace('\\', "/"));
    }

    for value in variants.into_iter().flatten() {
        let cut = value
            .split(|c| c == '?' || c == '#')
            .next()
            .unwrap_or(value.as_str());
        let value = cut.trim_start_matches("./").trim();
        if value.is_empty() {
            continue;
        }
        targets.add_candidate(map, value);

        let path = Path::new(value);
        let basename = path
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("");
        if !basename.is_empty() && !basename.contains('.') {
            let prefix = value.strip_suffix(basename).unwrap_or("");
            for ext in HXV4_COMMON_EXTENSIONS {
                let candidate = format!("{prefix}{basename}.{ext}");
                targets.add_candidate(map, &candidate);
                let upper = ext.to_ascii_uppercase();
                if upper != *ext {
                    let candidate = format!("{prefix}{basename}.{upper}");
                    targets.add_candidate(map, &candidate);
                }
            }
        }
    }
    hxv4_map_size(map).saturating_sub(before)
}

fn mine_pbd_value_names_into(map: &mut Hxv4NameMap, targets: &Hxv4HashTargets, value: &PbdValue) {
    match value {
        PbdValue::String { value } => {
            add_hxv4_candidate_variants(map, targets, value);
        }
        PbdValue::Array { items } => {
            for item in items {
                mine_pbd_value_names_into(map, targets, item);
            }
        }
        PbdValue::Dictionary { entries } => {
            for entry in entries {
                add_hxv4_candidate_variants(map, targets, &entry.key);
                mine_pbd_value_names_into(map, targets, &entry.value);
            }
        }
        PbdValue::Void | PbdValue::Integer { .. } | PbdValue::Double { .. } => {}
    }
}

fn mine_hxv4_candidates_into(
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
    bytes: &[u8],
) -> usize {
    let before = hxv4_map_size(map);
    // PBD stores its strings as structured UTF-16 values behind a per-type
    // checker (and, for 4s0, optional crypto/LZ4). Parse it first so filename
    // recovery sees the semantic strings instead of relying on raw-byte runs.
    if is_pbd_bytes(bytes) {
        if let Ok(document) = decode_pbd(bytes) {
            mine_pbd_value_names_into(map, targets, &document.root);
        }
    }
    visit_name_candidates(bytes, |candidate| {
        add_hxv4_candidate_variants(map, targets, candidate);
    });
    hxv4_map_size(map).saturating_sub(before)
}

fn mine_structured_script_into(
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
    name: &str,
    bytes: &[u8],
) -> Option<(usize, usize, &'static str)> {
    let report = analyze_script_names(name, bytes)?;
    let before = hxv4_map_size(map);
    for candidate in &report.candidates {
        add_hxv4_candidate_variants(map, targets, candidate);
    }
    Some((
        hxv4_map_size(map).saturating_sub(before),
        report.references.len(),
        report.kind.label(),
    ))
}

fn add_hxv4_numeric_neighbor_candidates(
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
    index: &Hxv4Index,
) -> usize {
    const RADIUS: i64 = 128;
    let before = hxv4_map_size(map);
    for entry in index.entries.iter().filter(|entry| entry.archive_slot == 0) {
        let Some(name) = entry.name.as_deref() else {
            continue;
        };
        let path = Path::new(name);
        let Some(file_name) = path.file_name().and_then(|part| part.to_str()) else {
            continue;
        };
        let (stem, suffix) = match file_name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => (stem, format!(".{ext}")),
            _ => (file_name, String::new()),
        };
        let chars: Vec<char> = stem.chars().collect();
        let Some(end) = chars
            .iter()
            .rposition(|c| c.is_ascii_digit())
            .map(|i| i + 1)
        else {
            continue;
        };
        let mut start = end;
        while start > 0 && chars[start - 1].is_ascii_digit() {
            start -= 1;
        }
        let digits: String = chars[start..end].iter().collect();
        if digits.is_empty() || digits.len() > 6 {
            continue;
        }
        let Ok(value) = digits.parse::<i64>() else {
            continue;
        };
        let prefix: String = chars[..start].iter().collect();
        let tail: String = chars[end..].iter().collect();
        let width = digits.len();
        let low = value.saturating_sub(RADIUS).max(0);
        let high = value.saturating_add(RADIUS);
        for candidate_value in low..=high {
            if candidate_value == value {
                continue;
            }
            let number = format!("{:0width$}", candidate_value, width = width);
            let candidate = format!("{prefix}{number}{tail}{suffix}");
            targets.add_candidate(map, &candidate);
        }
    }
    hxv4_map_size(map).saturating_sub(before)
}

fn collect_files_bounded(
    root: &Path,
    max_depth: usize,
    predicate: impl Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    fn walk(
        dir: &Path,
        depth: usize,
        max_depth: usize,
        predicate: &dyn Fn(&Path) -> bool,
        out: &mut Vec<PathBuf>,
    ) {
        if depth > max_depth {
            return;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                walk(&path, depth + 1, max_depth, predicate, out);
            } else if kind.is_file() && predicate(&path) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, 0, max_depth, &predicate, &mut out);
    out.sort();
    out.dedup();
    out
}

fn is_ext(path: &Path, want: &str) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(want))
}

fn seed_hxv4_names_from_executables(
    archive: &Archive,
    options: &HxCliOptions,
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
) -> usize {
    let Some(root) = hxv4_game_root(archive, options) else {
        return 0;
    };
    let mut exe_paths = Vec::new();
    if let Some(explicit) = options.explicit_exe() {
        exe_paths.push(explicit);
    } else if options.exe_auto_enabled() {
        exe_paths.extend(collect_files_bounded(&root, 1, |path| {
            xp3_brute::path_looks_like_pe32_executable(path)
        }));
        if let Some(parent) = root.parent() {
            exe_paths.extend(collect_files_bounded(parent, 0, |path| {
                xp3_brute::path_looks_like_pe32_executable(path)
            }));
        }
    }
    exe_paths.sort();
    exe_paths.dedup();

    let before = hxv4_map_size(map);
    let mut accepted = 0usize;
    for exe in exe_paths.into_iter().take(32) {
        let Ok(analysis) = analyze_krkr_exe(&exe) else {
            continue;
        };
        accepted += 1;
        add_hxv4_candidate_variants(map, targets, "startup.tjs");
        if let Some((added, references, kind)) =
            mine_structured_script_into(map, targets, "startup.tjs", &analysis.startup_tjs)
        {
            eprintln!(
                "[hxv4-script  ] source=exe-startup kind={} references={} hashes_added={}",
                kind, references, added
            );
        }
        mine_hxv4_candidates_into(map, targets, &analysis.startup_tjs);
        mine_hxv4_candidates_into(map, targets, &analysis.bootstrap_dll);
        for prefix in &analysis.bootstrap_prefix_candidates {
            add_hxv4_candidate_variants(map, targets, prefix);
        }
        eprintln!(
            "[hxv4-names   ] exe-seed={} selected_pe=0x{:x} startup_bytes={} bootstrap_bytes={}",
            exe.display(),
            analysis.pe_offset,
            analysis.startup_tjs.len(),
            analysis.bootstrap_dll.len()
        );
    }
    if accepted == 0 && options.exe_auto_enabled() {
        eprintln!(
            "[hxv4-names   ] no additional executable string source validated for name mining"
        );
    }
    hxv4_map_size(map).saturating_sub(before)
}

fn seed_hxv4_names_from_loose_files(
    archive: &Archive,
    options: &HxCliOptions,
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
) -> usize {
    let Some(root) = hxv4_game_root(archive, options) else {
        return 0;
    };
    let before = hxv4_map_size(map);
    let files = collect_files_bounded(&root, 2, |_| true);
    for path in files.into_iter().take(20_000) {
        if let Ok(relative) = path.strip_prefix(&root) {
            if let Some(value) = relative.to_str() {
                add_hxv4_candidate_variants(map, targets, value);
            }
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.len() > HXV4_LOOSE_MINE_MAX_BYTES {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(
            ext.as_str(),
            "tjs" | "ks" | "txt" | "csv" | "json" | "ini" | "cfg" | "xml" | "asd"
        ) {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            let display_name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");
            let _ = mine_structured_script_into(map, targets, display_name, &bytes);
            mine_hxv4_candidates_into(map, targets, &bytes);
        }
    }
    hxv4_map_size(map).saturating_sub(before)
}

fn recover_named_hxv4_plaintext(
    archive: &Archive,
    entry_index: usize,
    name: &str,
    compute_mode: ComputeMode,
    generic_config: &RecoveryConfig,
    native: Option<(&Hxv4NativeFilterManager, u64, u16)>,
) -> Result<Option<(Vec<u8>, &'static str)>, LibraryError> {
    let entry = archive.entries.get(entry_index).ok_or_else(|| {
        LibraryError::InvalidArgument("HXV4 bootstrap entry index out of range".to_string())
    })?;
    let mut raw = archive.reconstruct_entry(entry_index)?;
    let hypotheses = specific_hypotheses_for_name(name);

    if entry
        .adler
        .is_some_and(|expected| xp3_brute::adler32(&raw) == expected)
    {
        return Ok(Some((raw, "plain-adler")));
    }
    if let Some((manager, entry_key, local_flag)) = native {
        let state = manager.state_for_entry(entry_key, local_flag);
        state.apply(0, &mut raw);
        let actual_adler = xp3_brute::adler32(&raw);
        let adler_ok = entry.adler.map(|expected| actual_adler == expected);
        let format_ok = hypotheses
            .iter()
            .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong());
        if adler_ok == Some(true) || (entry.adler.is_none() && format_ok) {
            return Ok(Some((raw, "native-entry-key")));
        }
        // Once the reconstructed title FilterManager and Special record key
        // exist, a mismatch means our native reconstruction/mapping needs
        // fixing. Do not mask it by falling into the historical effective-
        // filter brute.
        log_hxv4_native_state_failure(
            archive,
            entry_index,
            raw.len(),
            &state,
            entry.adler,
            actual_adler,
        );
        return Ok(None);
    }
    if hypotheses
        .iter()
        .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
    {
        return Ok(Some((raw, "plain-format")));
    }
    if let Some(recovery) = recover_hxv4_effective_for_name(&raw, entry.adler, compute_mode, name)?
    {
        return Ok(Some((recovery.plaintext, "hxv4-effective-fallback")));
    }

    // Some titles combine the HXV4 index with an older repeating-XOR content
    // filter.  This fallback remains filename-gated and must pass the explicit
    // extension model (and adlr when present) before the plaintext is trusted.
    if !hypotheses.is_empty() {
        if let Some(best) = recover_complete_stream(&raw, &hypotheses, generic_config, entry.adler)?
            .into_iter()
            .next()
        {
            return Ok(Some((best.plaintext, "repeating-xor-fallback")));
        }
    }
    Ok(None)
}

#[derive(Debug)]
struct Hxv4BlindBootstrapRecovery {
    plaintext: Vec<u8>,
    format: Option<String>,
    method: &'static str,
}

#[derive(Debug)]
enum Hxv4BlindBootstrapOutcome {
    Recovered(Hxv4BlindBootstrapRecovery),
    NativeFailed { before_split: bool },
    NoMatch,
}

fn native_before_split(size: usize, split: u64) -> bool {
    (size as u64) <= split
}

fn log_hxv4_native_state_failure(
    archive: &Archive,
    entry_index: usize,
    size: usize,
    state: &xp3_brute::Hxv4NativeFilterState,
    expected_adler: Option<u32>,
    actual_adler: u32,
) {
    let prefix = state
        .prefix_xor
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let branch = if native_before_split(size, state.split) {
        "before-split"
    } else {
        "crossing-split"
    };
    eprintln!(
        "[hxv4-native-state] archive={} entry={} entry_key={:016x} local_flag=0x{:04x} open_flag={} size={} split={} branch={} left_drip={:016x} right_drip={:016x} left_xor={:02x} right_xor={:02x} prefix={} adler_expected={} adler_actual={:08x}",
        hxv4_archive_label(archive),
        entry_index,
        state.entry_key,
        state.local_flag,
        state.open_flag as u8,
        size,
        state.split,
        branch,
        state.left_drip,
        state.right_drip,
        state.left.xor_byte,
        state.right.xor_byte,
        prefix,
        expected_adler.map(|value| format!("{value:08x}")).unwrap_or_else(|| "-".to_string()),
        actual_adler,
    );
}

fn strong_builtin_format(bytes: &[u8]) -> Option<String> {
    builtin_hypotheses()
        .into_iter()
        .find(|hypothesis| validate_hypothesis(hypothesis.name, bytes).is_strong())
        .map(|hypothesis| hypothesis.name.to_string())
}

fn blind_repeating_xor_hypotheses() -> Vec<xp3_brute::FormatHypothesis> {
    // Filename-independent repeating-XOR recovery must stay bounded.  Start
    // with hypotheses that contribute at least four exact plaintext bytes; the
    // much more expensive statistical text models are a later fallback.
    builtin_hypotheses()
        .into_iter()
        .filter(|hypothesis| {
            hypothesis
                .cribs
                .iter()
                .map(|crib| crib.plaintext.len())
                .sum::<usize>()
                >= 4
        })
        .collect()
}

fn blind_text_hypotheses() -> Vec<xp3_brute::FormatHypothesis> {
    builtin_hypotheses()
        .into_iter()
        .filter(|hypothesis| {
            hypothesis.name.starts_with("Text/") || hypothesis.name.starts_with("Kirikiri/Text-")
        })
        .collect()
}

fn recover_hash_only_hxv4_plaintext(
    archive: &Archive,
    entry_index: usize,
    compute_mode: ComputeMode,
    generic_config: &RecoveryConfig,
    native: Option<(&Hxv4NativeFilterManager, u64, u16)>,
) -> Result<Hxv4BlindBootstrapOutcome, LibraryError> {
    let entry = archive.entries.get(entry_index).ok_or_else(|| {
        LibraryError::InvalidArgument("HXV4 bootstrap entry index out of range".to_string())
    })?;
    let mut raw = archive.reconstruct_entry(entry_index)?;

    // Some entries are not content-filtered. Adler is authoritative when the
    // archive supplied it; otherwise require a strong built-in grammar.
    if entry
        .adler
        .is_some_and(|expected| xp3_brute::adler32(&raw) == expected)
    {
        let format = strong_builtin_format(&raw);
        return Ok(Hxv4BlindBootstrapOutcome::Recovered(
            Hxv4BlindBootstrapRecovery {
                plaintext: raw,
                format,
                method: "plain-adler",
            },
        ));
    }
    if let Some(format) = strong_builtin_format(&raw) {
        return Ok(Hxv4BlindBootstrapOutcome::Recovered(
            Hxv4BlindBootstrapRecovery {
                plaintext: raw,
                format: Some(format),
                method: "plain-format",
            },
        ));
    }

    // Reconstructed HXV4 path recovered from the native
    // FilterManager/DripValue implementation. When this state is available, do
    // not fall through to the old per-entry format brute on a mismatch.
    if let Some((manager, entry_key, local_flag)) = native {
        let state = manager.state_for_entry(entry_key, local_flag);
        state.apply(0, &mut raw);
        let actual_adler = xp3_brute::adler32(&raw);
        if let Some(expected) = entry.adler {
            if actual_adler == expected {
                let format = strong_builtin_format(&raw);
                return Ok(Hxv4BlindBootstrapOutcome::Recovered(
                    Hxv4BlindBootstrapRecovery {
                        plaintext: raw,
                        format,
                        method: "native-entry-key",
                    },
                ));
            }
            log_hxv4_native_state_failure(
                archive,
                entry_index,
                raw.len(),
                &state,
                Some(expected),
                actual_adler,
            );
            return Ok(Hxv4BlindBootstrapOutcome::NativeFailed {
                before_split: native_before_split(raw.len(), state.split),
            });
        }
        if let Some(format) = strong_builtin_format(&raw) {
            return Ok(Hxv4BlindBootstrapOutcome::Recovered(
                Hxv4BlindBootstrapRecovery {
                    plaintext: raw,
                    format: Some(format),
                    method: "native-entry-key",
                },
            ));
        }
        log_hxv4_native_state_failure(archive, entry_index, raw.len(), &state, None, actual_adler);
        return Ok(Hxv4BlindBootstrapOutcome::NativeFailed {
            before_split: native_before_split(raw.len(), state.split),
        });
    }

    // Compatibility fallback only when no reconstructed native FilterManager
    // is available: try structural hypotheses against the effective filter.
    if let Some(recovery) = recover_hxv4_effective(&raw, entry.adler, compute_mode)? {
        return Ok(Hxv4BlindBootstrapOutcome::Recovered(
            Hxv4BlindBootstrapRecovery {
                plaintext: recovery.plaintext,
                format: Some(recovery.format),
                method: "hxv4-format",
            },
        ));
    }

    // Compatibility path for titles that put an older repeating-XOR filter
    // behind an HXV4 hash-only index.
    let hypotheses = blind_repeating_xor_hypotheses();
    if let Some(best) = recover_complete_stream(&raw, &hypotheses, generic_config, entry.adler)?
        .into_iter()
        .next()
    {
        return Ok(Hxv4BlindBootstrapOutcome::Recovered(
            Hxv4BlindBootstrapRecovery {
                plaintext: best.plaintext,
                format: Some(best.hypothesis),
                method: "xor-format",
            },
        ));
    }

    if raw.len() <= HXV4_BLIND_TEXT_MAX_BYTES {
        let text_hypotheses = blind_text_hypotheses();
        if let Some(best) =
            recover_complete_stream(&raw, &text_hypotheses, generic_config, entry.adler)?
                .into_iter()
                .next()
        {
            return Ok(Hxv4BlindBootstrapOutcome::Recovered(
                Hxv4BlindBootstrapRecovery {
                    plaintext: best.plaintext,
                    format: Some(best.hypothesis),
                    method: "xor-text",
                },
            ));
        }
    }
    Ok(Hxv4BlindBootstrapOutcome::NoMatch)
}

fn inferred_script_names(format: Option<&str>) -> &'static [&'static str] {
    match format.unwrap_or("") {
        "TJS2/Bytecode" => &["_hash_only.tjs"],
        name if name.starts_with("Text/") || name.starts_with("Kirikiri/Text-") => {
            // Without the real suffix we cannot distinguish source TJS from KAG.
            // Run both local parsers; exact native hash matching is still the
            // acceptance gate for every candidate they emit.
            &["_hash_only.tjs", "_hash_only.ks"]
        }
        _ => &[],
    }
}

fn hxv4_archive_label(archive: &Archive) -> String {
    let raw = archive
        .path
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("archive");
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn bootstrap_archive_round(
    archive: &Archive,
    index: &mut Hxv4Index,
    processed_entries: &mut HashSet<usize>,
    blind_processed_entries: &mut HashSet<usize>,
    allow_blind_probe: bool,
    native_filter: Option<&Hxv4NativeFilterManager>,
    map: &mut Hxv4NameMap,
    targets: &Hxv4HashTargets,
    compute_mode: ComputeMode,
    generic_config: &RecoveryConfig,
    output_dir: Option<&Path>,
    decode_options: &UnpackDecodeOptions,
    mut repack_meta: Option<&mut Xp3Meta>,
    round: usize,
    content_trace: &mut dyn Write,
    script_trace: &mut dyn Write,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    index.apply_names(map);
    let before_candidates = hxv4_map_size(map);
    let mut recovered_plaintexts = 0usize;
    let by_id: HashMap<u64, Hxv4IndexEntry> = index
        .entries
        .iter()
        .filter(|entry| entry.archive_slot == 0)
        .cloned()
        .map(|entry| (entry.id, entry))
        .collect();

    let explicit_startup = hxv4_startup_entry_index(&archive.entries);
    let archive_label = hxv4_archive_label(archive);
    let mut blind_attempts = 0usize;
    let mut native_verified = 0usize;
    let mut native_failed = 0usize;
    let mut native_failed_before_split = 0usize;
    let mut native_failed_crossing_split = 0usize;
    for (entry_index, entry) in archive.entries.iter().enumerate() {
        let native_meta = if Some(entry_index) == explicit_startup {
            index.entries.iter().find(|meta| {
                meta.archive_slot == 0
                    && meta
                        .name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case("startup.tjs"))
            })
        } else {
            entry.hxv4_id.and_then(|id| by_id.get(&id))
        };
        let native = native_filter.and_then(|manager| {
            native_meta.map(|meta| (manager, meta.entry_key, meta.filter_flag))
        });

        let real_name = if Some(entry_index) == explicit_startup {
            Some("startup.tjs".to_string())
        } else if let Some(id) = entry.hxv4_id {
            by_id.get(&id).and_then(|meta| {
                // The Special table also contains the startup record.  When
                // data.xp3 exposes startup as the ordinary entry, never attach
                // that record's name to a synthetic id by accident.
                meta.name
                    .as_ref()
                    .filter(|name| {
                        explicit_startup.is_none() || !name.eq_ignore_ascii_case("startup.tjs")
                    })
                    .cloned()
            })
        } else {
            None
        };

        if real_name.is_none() {
            if !allow_blind_probe {
                continue;
            }
            if blind_processed_entries.contains(&entry_index) {
                continue;
            }
            blind_processed_entries.insert(entry_index);
            blind_attempts += 1;
            if native_filter.is_some() && native.is_none() {
                native_failed += 1;
                eprintln!(
                    "[hxv4-native  ] archive={} entry={} id={} state=missing-special-record",
                    archive_label,
                    entry_index,
                    entry
                        .hxv4_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                );
                continue;
            }
            if blind_attempts == 1 || blind_attempts % 64 == 0 {
                if native_filter.is_some() {
                    eprintln!(
                        "[hxv4-native  ] probing archive={} attempted={} entry={}/{} verified={} failed={}",
                        archive_label, blind_attempts, entry_index + 1, archive.entries.len(), native_verified, native_failed,
                    );
                } else {
                    eprintln!(
                        "[hxv4-format  ] probing archive={} attempted={} entry={}/{}",
                        archive_label,
                        blind_attempts,
                        entry_index + 1,
                        archive.entries.len(),
                    );
                }
            }
            match recover_hash_only_hxv4_plaintext(
                archive,
                entry_index,
                compute_mode,
                generic_config,
                native,
            ) {
                Ok(Hxv4BlindBootstrapOutcome::Recovered(recovery)) => {
                    recovered_plaintexts += 1;
                    let Hxv4BlindBootstrapRecovery {
                        plaintext,
                        format,
                        method,
                    } = recovery;
                    if method == "native-entry-key" {
                        native_verified += 1;
                    }
                    let name_hash = entry
                        .hxv4_id
                        .and_then(|id| by_id.get(&id))
                        .map(Hxv4IndexEntry::name_hash_hex)
                        .unwrap_or_default();
                    let format_label = format.as_deref().unwrap_or("unknown");

                    // The wrapper is part of the archive plaintext (and therefore
                    // part of Adler validation), but it is not the user-facing
                    // script/text file.  Once the stream is verified, transparently
                    // expose the decoded KiriKiri text even though this hash-only
                    // entry may still have a synthetic .bin/.txt name.
                    let wrapper_mode = kirikiri_text_wrapper_mode(&plaintext);
                    let wrapper_bytes = plaintext.len();
                    let output_plaintext =
                        user_facing_text_bytes("<hash-only>", format.as_deref(), plaintext);
                    let transform_label = wrapper_mode
                        .map(|mode| format!("krkr-text-mode{mode}"))
                        .unwrap_or_else(|| "none".to_string());

                    // Hash-only plaintext is strictly bootstrap-internal.  It may
                    // contribute filename candidates, but it is not a user-visible
                    // extracted file until the authenticated Special hash resolves
                    // to a real logical name.
                    let output_string = "<internal-only>";
                    if method == "native-entry-key" {
                        eprintln!(
                            "[hxv4-native  ] round={} archive={} entry={} id={} name_hash={} adler=match format={} bytes={} wrapper_bytes={} transform={} output={}",
                            round,
                            archive_label,
                            entry_index,
                            entry.hxv4_id.map(|id| id.to_string()).unwrap_or_else(|| "-".to_string()),
                            if name_hash.is_empty() { "-" } else { &name_hash },
                            format_label,
                            output_plaintext.len(),
                            wrapper_bytes,
                            transform_label,
                            if output_string.is_empty() { "<disabled>" } else { &output_string },
                        );
                    } else {
                        eprintln!(
                            "[hxv4-format  ] round={} archive={} entry={} id={} name_hash={} method={} format={} bytes={} wrapper_bytes={} transform={} output={}",
                            round,
                            archive_label,
                            entry_index,
                            entry.hxv4_id.map(|id| id.to_string()).unwrap_or_else(|| "-".to_string()),
                            if name_hash.is_empty() { "-" } else { &name_hash },
                            method,
                            format_label,
                            output_plaintext.len(),
                            wrapper_bytes,
                            transform_label,
                            if output_string.is_empty() { "<disabled>" } else { &output_string },
                        );
                    }

                    // A hash-only PSB remains internal-only, but it is still
                    // authenticated plaintext.  Let Eluna parse it here so an
                    // Emote key discovered by brute force becomes immediately
                    // available to later PSBs.  No texture/resource files are
                    // emitted until a real logical filename is known.
                    prime_psb_global_key(
                        &output_plaintext,
                        &format!(
                            "round={round} archive={archive_label} entry={entry_index} hash-only"
                        ),
                    );

                    // This path does NOT declare the synthetic name to be real.
                    // It only mines the verified, user-facing plaintext for
                    // candidate names; Hxv4NameMap still accepts a filename solely
                    // by exact native hash match against the authenticated Special
                    // table.  KiriKiri text wrappers are already removed here so
                    // parsers/miners never need to inspect compressed/scrambled data.
                    for script_name in inferred_script_names(format.as_deref()) {
                        if let Some(report) = analyze_script_names(script_name, &output_plaintext) {
                            let parser_before = hxv4_map_size(map);
                            for candidate in &report.candidates {
                                add_hxv4_candidate_variants(map, targets, candidate);
                            }
                            let parser_added = hxv4_map_size(map).saturating_sub(parser_before);
                            for reference in &report.references {
                                writeln!(
                                    script_trace,
                                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                                    round,
                                    report_field(&archive_label),
                                    entry_index,
                                    entry.hxv4_id.map(|id| id.to_string()).unwrap_or_default(),
                                    report.kind.label(),
                                    reference.line,
                                    report_field(&reference.context),
                                    report_field(&reference.value),
                                )?;
                            }
                            eprintln!(
                                "[hxv4-script  ] round={} archive={} entry={} name=<hash-only> kind={} references={} candidates={} hashes_added={}",
                                round, archive_label, entry_index, report.kind.label(), report.references.len(), report.candidates.len(), parser_added,
                            );
                        }
                    }
                    mine_hxv4_candidates_into(map, targets, &output_plaintext);
                }
                Ok(Hxv4BlindBootstrapOutcome::NativeFailed { before_split }) => {
                    native_failed += 1;
                    if before_split {
                        native_failed_before_split += 1;
                    } else {
                        native_failed_crossing_split += 1;
                    }
                }
                Ok(Hxv4BlindBootstrapOutcome::NoMatch) => {
                    if native.is_some() {
                        native_failed += 1;
                    }
                }
                Err(err) => {
                    eprintln!(
                        "[hxv4-format  ] hash-only probe failed archive={} entry={} id={} error={}",
                        archive
                            .path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<memory>".to_string()),
                        entry_index,
                        entry
                            .hxv4_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        err,
                    );
                }
            }
            continue;
        }

        if processed_entries.contains(&entry_index) {
            continue;
        }
        let real_name = real_name.unwrap();
        processed_entries.insert(entry_index);

        match recover_named_hxv4_plaintext(
            archive,
            entry_index,
            &real_name,
            compute_mode,
            generic_config,
            native,
        ) {
            Ok(Some((plaintext, recovery_method))) => {
                recovered_plaintexts += 1;
                let display_name = if Some(entry_index) == explicit_startup {
                    "startup.tjs".to_string()
                } else {
                    entry
                        .hxv4_id
                        .and_then(|id| by_id.get(&id))
                        .map(Hxv4IndexEntry::display_path)
                        .unwrap_or_else(|| real_name.clone())
                };

                // KiriKiri text wrappers are an on-storage representation.
                // Keep Adler/format validation on the verified wrapper above, then
                // immediately replace it with the decoded user-facing bytes for
                // every bootstrap output and every subsequent name-mining parser.
                let wrapper_mode = kirikiri_text_wrapper_mode(&plaintext);
                let wrapper_bytes = plaintext.len();
                let content_format = strong_builtin_format(&plaintext);
                let UserFacingTextResult {
                    bytes: plaintext,
                    source_sha256,
                    transform,
                } = user_facing_text_asset(content_format.as_deref(), plaintext);
                let output_display_name = refine_generic_output_name(
                    &display_name,
                    content_format.as_deref(),
                    &plaintext,
                );
                let transform_label = wrapper_mode
                    .map(|mode| format!("krkr-text-mode{mode}"))
                    .unwrap_or_else(|| "none".to_string());

                // Named sibling archives are not written into this extraction
                // root, but their verified PSBs are still valid key oracles.
                // Current-archive outputs are parsed below while exporting
                // textures, so avoid decoding those twice.
                if output_dir.is_none() {
                    prime_psb_global_key(&plaintext, &format!(
                        "round={round} archive={archive_label} entry={entry_index} name={display_name}"
                    ));
                }

                if let Some(out_dir) = output_dir {
                    let relative = safe_relative_path(&output_display_name, entry_index);
                    if output_display_name != display_name {
                        eprintln!(
                            "[format-name   ] bootstrap round={} archive={} entry={} old={} new={} format={}",
                            round,
                            archive_label,
                            entry_index,
                            display_name,
                            output_display_name,
                            content_format.as_deref().unwrap_or("libmagic"),
                        );
                    }
                    let output = out_dir.join(relative);
                    let asset =
                        write_unpack_asset_output(&output, &plaintext, decode_options, out_dir)?;
                    if let Some(meta) = repack_meta.as_deref_mut() {
                        apply_asset_result_to_meta(
                            meta,
                            entry_index,
                            &display_name,
                            &asset,
                            out_dir,
                        );
                        if let Some(entry_meta) = meta.entries.get_mut(entry_index) {
                            entry_meta.recovery.status = match recovery_method {
                                "plain-adler" | "plain-format" => "plain",
                                "native-entry-key" => "hxv4-native",
                                "hxv4-effective-fallback" => "hxv4-effective-fallback",
                                "repeating-xor-fallback" => "hxv4-bootstrap-xor-fallback",
                                _ => "hxv4-bootstrap-unknown",
                            }
                            .to_string();
                            entry_meta.recovery.format = content_format.clone();
                            entry_meta.recovery.storage_plaintext_sha256 =
                                Some(source_sha256.clone());
                            if let Some(transform) = transform.clone() {
                                push_transform_unique(
                                    entry_meta,
                                    TransformMeta::KirikiriText(transform),
                                );
                            }
                        }
                    }
                    let output = asset.output;
                    writeln!(
                        content_trace,
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        round,
                        report_field(&archive_label),
                        entry_index,
                        entry.hxv4_id.map(|id| id.to_string()).unwrap_or_default(),
                        report_field(&display_name),
                        plaintext.len(),
                        report_field(&output.display().to_string()),
                        "named",
                        "name-specific",
                    )?;
                    eprintln!(
                        "[hxv4-bootstrap] round={} archive={} entry={} id={} name={} bytes={} wrapper_bytes={} transform={} output={}",
                        round,
                        archive_label,
                        entry_index,
                        entry.hxv4_id.map(|id| id.to_string()).unwrap_or_else(|| "-".to_string()),
                        display_name,
                        plaintext.len(),
                        wrapper_bytes,
                        transform_label,
                        output.display(),
                    );
                }

                // Structured script mining is the primary name-bootstrap path.
                // Compiled .tjs files are decompiled by tjs2dec, then our own
                // lexer/parser recovers literals with call/field context.  KS
                // files use our quote-aware KAG parser.  Exact HXV4 hashes still
                // decide whether any candidate is accepted as a real name.
                if let Some(report) = analyze_script_names(&output_display_name, &plaintext) {
                    let parser_before = hxv4_map_size(map);
                    for candidate in &report.candidates {
                        add_hxv4_candidate_variants(map, targets, candidate);
                    }
                    let parser_added = hxv4_map_size(map).saturating_sub(parser_before);
                    for reference in &report.references {
                        writeln!(
                            script_trace,
                            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            round,
                            report_field(&archive_label),
                            entry_index,
                            entry.hxv4_id.map(|id| id.to_string()).unwrap_or_default(),
                            report.kind.label(),
                            reference.line,
                            report_field(&reference.context),
                            report_field(&reference.value),
                        )?;
                    }
                    for note in &report.notes {
                        writeln!(
                            script_trace,
                            "{}\t{}\t{}\t{}\t{}\t0\tnote\t{}",
                            round,
                            report_field(&archive_label),
                            entry_index,
                            entry.hxv4_id.map(|id| id.to_string()).unwrap_or_default(),
                            report.kind.label(),
                            report_field(note),
                        )?;
                    }
                    // Decompiled/executable TJS2 text is intentionally kept
                    // in memory only. It exists solely to recover exact filenames.
                    eprintln!(
                        "[hxv4-script  ] round={} archive={} entry={} name={} kind={} references={} candidates={} hashes_added={} decompiled={}",
                        round,
                        archive_label,
                        entry_index,
                        display_name,
                        report.kind.label(),
                        report.references.len(),
                        report.candidates.len(),
                        parser_added,
                        if report.decompiled_tjs.is_some() { "yes" } else { "no" },
                    );
                }

                // Keep the old broad byte-string miner only as a recall fallback.
                // It cannot resolve anything unless the exact native hash matches.
                // `plaintext` is already transparently unwrapped when it is a
                // KiriKiri mode 0/1/2 text stream.
                mine_hxv4_candidates_into(map, targets, &plaintext);
            }
            Ok(None) => {
                if native.is_some() {
                    eprintln!(
                        "[hxv4-native  ] named archive={} entry={} name={} adler/format=mismatch; heuristic brute skipped",
                        archive_label, entry_index, real_name,
                    );
                }
            }
            Err(err) => {
                eprintln!(
                    "[hxv4-names   ] named seed could not be recovered archive={} entry={} name={} error={}",
                    archive.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<memory>".to_string()),
                    entry_index,
                    real_name,
                    err
                );
            }
        }
    }

    if allow_blind_probe && native_filter.is_some() && blind_attempts != 0 {
        eprintln!(
            "[hxv4-native  ] archive={} complete attempted={} verified={} failed={} failed_before_split={} failed_crossing_split={}",
            archive_label,
            blind_attempts,
            native_verified,
            native_failed,
            native_failed_before_split,
            native_failed_crossing_split,
        );
    }

    Ok((
        recovered_plaintexts,
        hxv4_map_size(map).saturating_sub(before_candidates),
    ))
}

fn discover_hxv4_sibling_archives(current: &Archive, options: &HxCliOptions) -> Vec<PathBuf> {
    let Some(root) = hxv4_game_root(current, options) else {
        return Vec::new();
    };
    let current_path = current
        .path
        .as_ref()
        .and_then(|path| fs::canonicalize(path).ok());
    collect_files_bounded(&root, 2, |path| is_ext(path, "xp3"))
        .into_iter()
        .filter(|path| {
            let canonical = fs::canonicalize(path).ok();
            canonical.is_none() || canonical != current_path
        })
        .take(256)
        .collect()
}

fn print_new_hxv4_names(
    index: &Hxv4Index,
    resolved_round: &mut HashMap<usize, usize>,
    round: usize,
) -> usize {
    let mut newly = Vec::new();
    for entry in index
        .entries
        .iter()
        .filter(|entry| entry.archive_slot == 0 && entry.name.is_some())
    {
        if resolved_round.contains_key(&entry.record_index) {
            continue;
        }
        resolved_round.insert(entry.record_index, round);
        newly.push(entry);
    }
    newly.sort_by_key(|entry| entry.record_index);
    for entry in &newly {
        eprintln!(
            "[hxv4-name    ] round={} record={} id={} path={} name={} full={}",
            round,
            entry.record_index,
            entry.id,
            entry.path.as_deref().unwrap_or("<unresolved>"),
            entry.name.as_deref().unwrap_or("<unresolved>"),
            entry.display_path(),
        );
    }
    newly.len()
}

fn bootstrap_hxv4_names(
    current_archive: &Archive,
    current_index: &mut Hxv4Index,
    options: &HxCliOptions,
    native_filter: Option<&Hxv4NativeFilterManager>,
    out_dir: &Path,
    compute_mode: ComputeMode,
    max_period: usize,
    top_periods: usize,
    exhaustive_dynamic: bool,
    decode_options: &UnpackDecodeOptions,
    repack_meta: &mut Xp3Meta,
) -> Result<(), Box<dyn std::error::Error>> {
    if options.no_name_bootstrap {
        return Ok(());
    }

    let mut names = options.load_names(current_archive)?;

    let generic_config = RecoveryConfig {
        min_period: 1,
        max_period,
        top_periods_per_hypothesis: top_periods.min(32).max(4),
        exhaustive_dynamic_periods: exhaustive_dynamic,
        max_refinement_rounds: 8,
        compute_mode,
        ..RecoveryConfig::default()
    };

    // Load sibling Special tables before mining any candidate strings.  The
    // union of their authenticated path/name hashes is the complete target set
    // for this game-level bootstrap.  Candidate strings that do not hash to one
    // of these targets are useless and must never be retained in memory.
    let sibling_paths = discover_hxv4_sibling_archives(current_archive, options);
    let mut siblings = Vec::<Hxv4BootstrapArchive>::new();
    for path in sibling_paths {
        let Ok(archive) = Archive::open(&path) else {
            continue;
        };
        if !archive.is_hxv4() {
            continue;
        }
        match load_hx_index(&archive, options) {
            Ok(Some(index)) => {
                siblings.push(Hxv4BootstrapArchive {
                    path,
                    archive,
                    index,
                    processed_entries: HashSet::new(),
                    blind_processed_entries: HashSet::new(),
                });
            }
            Ok(None) => {}
            Err(err) => eprintln!(
                "[hxv4-names   ] sibling skipped {}: {}",
                path.display(),
                err
            ),
        }
    }

    let mut targets = Hxv4HashTargets::default();
    targets.add_index(current_index);
    for state in &siblings {
        targets.add_index(&state.index);
    }
    let dictionary_before_filter = hxv4_map_size(&names);
    targets.retain_only_targets(&mut names);
    let dictionary_dropped = dictionary_before_filter.saturating_sub(hxv4_map_size(&names));

    add_hxv4_candidate_variants(&mut names, &targets, "startup.tjs");
    let exe_added =
        seed_hxv4_names_from_executables(current_archive, options, &mut names, &targets);
    let loose_added =
        seed_hxv4_names_from_loose_files(current_archive, options, &mut names, &targets);
    current_index.apply_names(&names);
    for state in &mut siblings {
        state.index.apply_names(&names);
    }

    let mut resolved_round = HashMap::<usize, usize>::new();
    let initially_resolved = print_new_hxv4_names(current_index, &mut resolved_round, 0);
    // Bootstrap diagnostics are deliberately not materialized under the user's
    // extraction directory.  Keep the existing trace plumbing pointed at sinks
    // so filename recovery can remain unchanged without creating side artifacts.
    let mut content_trace = io::sink();
    let mut script_trace = io::sink();
    eprintln!(
        "[hxv4-names   ] initial resolved names={} (each match is listed with [hxv4-name])",
        initially_resolved
    );

    let root = hxv4_game_root(current_archive, options)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<archive-dir-unavailable>".to_string());
    eprintln!(
        "[hxv4-names   ] bootstrap scope=game root={} sibling_hxv4={} target_paths={} target_names={} retained_dictionary_hashes={} dropped_unmatched_dictionary_hashes={} exe_seed_matches={} loose_seed_matches={}",
        root,
        siblings.len(),
        targets.path_hashes.len(),
        targets.name_hashes.len(),
        hxv4_map_size(&names),
        dictionary_dropped,
        exe_added,
        loose_added,
    );
    eprintln!(
        "[memory        ] hxv4_name_miner=streaming candidate_retention=target-hash-only trace_storage=internal-only"
    );

    let mut current_processed = HashSet::<usize>::new();
    let mut current_blind_processed = HashSet::<usize>::new();
    let mut format_bootstrap_active = false;
    for round in 1..=HXV4_BOOTSTRAP_MAX_ROUNDS {
        let before_map = hxv4_map_size(&names);
        let before_current = hxv4_index_resolved_names(current_index);
        let before_sibling: usize = siblings
            .iter()
            .map(|state| hxv4_index_resolved_names(&state.index))
            .sum();

        let (mut recovered_files, mut mined_hashes) = bootstrap_archive_round(
            current_archive,
            current_index,
            &mut current_processed,
            &mut current_blind_processed,
            format_bootstrap_active,
            native_filter,
            &mut names,
            &targets,
            compute_mode,
            &generic_config,
            Some(out_dir),
            decode_options,
            Some(repack_meta),
            round,
            &mut content_trace,
            &mut script_trace,
        )?;
        for state in &mut siblings {
            let (recovered, mined) = bootstrap_archive_round(
                &state.archive,
                &mut state.index,
                &mut state.processed_entries,
                &mut state.blind_processed_entries,
                format_bootstrap_active,
                native_filter,
                &mut names,
                &targets,
                compute_mode,
                &generic_config,
                None,
                decode_options,
                None,
                round,
                &mut content_trace,
                &mut script_trace,
            )?;
            recovered_files += recovered;
            mined_hashes += mined;
        }

        current_index.apply_names(&names);
        for state in &mut siblings {
            state.index.apply_names(&names);
        }
        let mut numeric_added =
            add_hxv4_numeric_neighbor_candidates(&mut names, &targets, current_index);
        for state in &siblings {
            numeric_added +=
                add_hxv4_numeric_neighbor_candidates(&mut names, &targets, &state.index);
        }
        if numeric_added != 0 {
            current_index.apply_names(&names);
            for state in &mut siblings {
                state.index.apply_names(&names);
            }
        }
        let newly_current = print_new_hxv4_names(current_index, &mut resolved_round, round);
        let after_current = hxv4_index_resolved_names(current_index);
        let after_sibling: usize = siblings
            .iter()
            .map(|state| hxv4_index_resolved_names(&state.index))
            .sum();
        let map_growth = hxv4_map_size(&names).saturating_sub(before_map);
        let resolved_growth = after_current.saturating_sub(before_current)
            + after_sibling.saturating_sub(before_sibling);
        eprintln!(
            "[hxv4-names   ] round={} mode={} recovered_files={} mined_hash_matches={} numeric_hash_matches={} matched_hash_growth={} retained_hashes={} resolved_growth={} newly_current={} current={}/{} sibling_resolved={}",
            round,
            if format_bootstrap_active { "hash+format" } else { "hash-only" },
            recovered_files,
            mined_hashes,
            numeric_added,
            map_growth,
            hxv4_map_size(&names),
            resolved_growth,
            newly_current,
            after_current,
            hxv4_index_current_names(current_index),
            after_sibling
        );
        content_trace.flush()?;
        script_trace.flush()?;
        if map_growth == 0 && resolved_growth == 0 {
            let current_unresolved =
                hxv4_index_current_names(current_index).saturating_sub(after_current);
            let sibling_total: usize = siblings
                .iter()
                .map(|state| hxv4_index_current_names(&state.index))
                .sum();
            let sibling_unresolved = sibling_total.saturating_sub(after_sibling);
            if !format_bootstrap_active && current_unresolved + sibling_unresolved != 0 {
                format_bootstrap_active = true;
                eprintln!(
                    "[hxv4-format  ] exact hash-name bootstrap reached a fixed point; enabling filename-independent content recovery for {} unresolved current + {} unresolved sibling entries (native_entry_key={})",
                    current_unresolved, sibling_unresolved, native_filter.is_some(),
                );
                continue;
            }
            break;
        }
    }

    for state in &siblings {
        eprintln!(
            "[hxv4-names   ] sibling={} resolved={}/{}",
            state.path.display(),
            hxv4_index_resolved_names(&state.index),
            hxv4_index_current_names(&state.index)
        );
    }

    content_trace.flush()?;
    script_trace.flush()?;
    eprintln!(
        "[hxv4-names   ] result current={}/{} diagnostics=internal-only output_root={}",
        hxv4_index_resolved_names(current_index),
        hxv4_index_current_names(current_index),
        out_dir.display(),
    );
    Ok(())
}

fn special_scope_label(scope: SpecialXorScope) -> &'static str {
    match scope {
        SpecialXorScope::Prefix100 => "prefix100",
        SpecialXorScope::Whole => "whole",
    }
}

fn print_special_xor_recovery(prefix: &str, xor: &SpecialXorRecovery) {
    println!(
        "{} xor-key scope={} period={} table_start=0x{:x} key={}",
        prefix,
        special_scope_label(xor.scope),
        xor.period(),
        xor.table_start,
        xor.key_hex()
    );
}

fn special_key_sidecar_path(output: &Path) -> PathBuf {
    let mut value = output.as_os_str().to_os_string();
    value.push(".xor-key.hex");
    PathBuf::from(value)
}

fn write_special_xor_sidecar(
    output: &Path,
    xor: &SpecialXorRecovery,
) -> Result<PathBuf, io::Error> {
    let path = special_key_sidecar_path(output);
    let text = format!(
        "scope={}\nperiod={}\ntable_start=0x{:x}\nkey={}\n",
        special_scope_label(xor.scope),
        xor.period(),
        xor.table_start,
        xor.key_hex()
    );
    fs::write(&path, text)?;
    Ok(path)
}

fn recover_cxdec_names_from_decoded(
    archive: &Archive,
    root_index: usize,
    decoder: CxdecNameProfile,
    decoded: &[u8],
) -> Option<(String, Vec<String>, u8)> {
    let Some(root) = archive.root_chunks.get(root_index) else {
        println!(
            "[special-validate] root={} stage=name-map status=reject reason=missing-root",
            root_index
        );
        return None;
    };
    let name_map = match decoder.parse_decoded_names(decoded) {
        Ok(value) => value,
        Err(err) => {
            println!(
                "[special-validate] root={} stage=records status=reject reason=parse error={}",
                root_index, err
            );
            return None;
        }
    };
    if name_map.records.is_empty() {
        println!(
            "[special-validate] root={} stage=records status=reject reason=empty",
            root_index
        );
        return None;
    }

    // Validate the record layout structurally.  The four-byte record tag is
    // retained as data but is deliberately not used as a family discriminator:
    // customized CXDEC builds may change it while keeping the same body layout.
    let mut cursor = 0usize;
    let mut signatures = HashMap::<u32, usize>::new();
    for (record_index, record) in name_map.records.iter().enumerate() {
        *signatures.entry(record.signature).or_default() += 1;
        let Some(name) = record.name.as_deref() else {
            println!(
                "[special-validate] root={} stage=records status=reject record={} tag=0x{:08x} reason=missing-name",
                root_index, record_index, record.signature
            );
            return None;
        };
        let units = name.encode_utf16().count();
        let Some(name_bytes) = units.checked_mul(2) else {
            println!(
                "[special-validate] root={} stage=records status=reject record={} reason=name-length-overflow",
                root_index, record_index
            );
            return None;
        };
        let Some(expected_body) = 6usize.checked_add(name_bytes).and_then(|v| v.checked_add(2)) else {
            println!(
                "[special-validate] root={} stage=records status=reject record={} reason=body-length-overflow",
                root_index, record_index
            );
            return None;
        };
        if record.entry_size != expected_body as u64 {
            println!(
                "[special-validate] root={} stage=records status=reject record={} tag=0x{:08x} body={} expected={} reason=body-size",
                root_index,
                record_index,
                record.signature,
                record.entry_size,
                expected_body
            );
            return None;
        }
        let Some(header_end) = cursor.checked_add(12) else {
            return None;
        };
        let Some(nul_offset) = header_end
            .checked_add(6)
            .and_then(|value| value.checked_add(name_bytes))
        else {
            return None;
        };
        let Some(record_end) = header_end
            .checked_add(usize::try_from(record.entry_size).ok()?)
        else {
            return None;
        };
        if record_end > decoded.len() {
            println!(
                "[special-validate] root={} stage=records status=reject record={} end={} decoded={} reason=record-overrun",
                root_index,
                record_index,
                record_end,
                decoded.len()
            );
            return None;
        }
        let nul_end = match nul_offset.checked_add(2) {
            Some(value) => value,
            None => return None,
        };
        if nul_end > record_end
            || decoded.get(nul_offset..nul_end) != Some(b"\0\0")
        {
            println!(
                "[special-validate] root={} stage=records status=reject record={} reason=missing-utf16-nul",
                root_index, record_index
            );
            return None;
        }
        cursor = record_end;
    }
    if cursor != decoded.len() {
        println!(
            "[special-validate] root={} stage=records status=reject consumed={} decoded={} reason=trailing-bytes",
            root_index,
            cursor,
            decoded.len()
        );
        return None;
    }

    let mut signature_summary = signatures
        .into_iter()
        .map(|(signature, count)| format!("0x{signature:08x}:{count}"))
        .collect::<Vec<_>>();
    signature_summary.sort();
    println!(
        "[special-validate] root={} stage=records status=ok records={} tags={}",
        root_index,
        name_map.records.len(),
        signature_summary.join(",")
    );

    // The protected ordinary XP3 name may be a lookup token, so its visible
    // UTF-16 length is not a constraint on the recovered real filename.  Map
    // by independently meaningful relations only: exact visible name, native
    // filename token, then the stored hash/adlr when it is unique.
    let tag_bytes = root.magic.to_le_bytes();
    let token_prefix = std::str::from_utf8(&tag_bytes).ok();
    let mut used_records = vec![false; name_map.records.len()];
    let mut names = Vec::with_capacity(archive.entries.len());
    let mut mapped = 0usize;
    let mut mapped_exact = 0usize;
    let mut mapped_token = 0usize;
    let mut mapped_hash = 0usize;
    let mut unresolved_entries = 0usize;
    let mut ambiguous_entries = 0usize;
    let mut unresolved_examples = Vec::new();

    for (entry_index, entry) in archive.entries.iter().enumerate() {
        if entry.name == "$" {
            names.push("startup.tjs".to_string());
            continue;
        }

        let mut selected = None;
        let mut selected_route = "";

        let exact = name_map
            .records
            .iter()
            .enumerate()
            .filter_map(|(record_index, record)| {
                if used_records[record_index] {
                    return None;
                }
                let name = record.name.as_deref()?;
                (name == entry.name || name == entry.preferred_name()).then_some(record_index)
            })
            .collect::<Vec<_>>();
        if exact.len() == 1 {
            selected = exact.first().copied();
            selected_route = "exact";
        }

        if selected.is_none() {
            if let Some(prefix) = token_prefix {
                let token_matches = name_map
                    .records
                    .iter()
                    .enumerate()
                    .filter_map(|(record_index, record)| {
                        if used_records[record_index] {
                            return None;
                        }
                        let name = record.name.as_deref()?;
                        let token = cxdec_filename_md5_token(prefix, name);
                        (token.eq_ignore_ascii_case(&entry.name)
                            || token.eq_ignore_ascii_case(entry.preferred_name()))
                        .then_some(record_index)
                    })
                    .collect::<Vec<_>>();
                if token_matches.len() == 1 {
                    selected = token_matches.first().copied();
                    selected_route = "token";
                } else if token_matches.len() > 1 {
                    ambiguous_entries += 1;
                }
            }
        }

        if selected.is_none() {
            if let Some(hash) = entry.adler {
                let hash_matches = name_map
                    .records
                    .iter()
                    .enumerate()
                    .filter_map(|(record_index, record)| {
                        (!used_records[record_index] && record.hash == hash)
                            .then_some(record_index)
                    })
                    .collect::<Vec<_>>();
                if hash_matches.len() == 1 {
                    selected = hash_matches.first().copied();
                    selected_route = "hash";
                } else if hash_matches.len() > 1 {
                    ambiguous_entries += 1;
                }
            }
        }

        let Some(record_index) = selected else {
            names.push(entry.preferred_name().to_string());
            unresolved_entries += 1;
            if unresolved_examples.len() < 4 {
                unresolved_examples.push(format!(
                    "entry={} visible={:?} adlr={}",
                    entry_index,
                    entry.preferred_name(),
                    entry
                        .adler
                        .map(|value| format!("0x{value:08x}"))
                        .unwrap_or_else(|| "none".to_string())
                ));
            }
            continue;
        };

        let recovered = name_map.records[record_index].name.as_ref()?.clone();
        used_records[record_index] = true;
        names.push(recovered);
        mapped += 1;
        match selected_route {
            "exact" => mapped_exact += 1,
            "token" => mapped_token += 1,
            "hash" => mapped_hash += 1,
            _ => {}
        }
    }

    let unused_records = used_records.iter().filter(|used| !**used).count();
    let unused_examples = name_map
        .records
        .iter()
        .enumerate()
        .filter(|(record_index, _)| !used_records[*record_index])
        .filter_map(|(record_index, record)| {
            record.name.as_deref().map(|name| {
                format!(
                    "record={} hash=0x{:08x} name={:?}",
                    record_index, record.hash, name
                )
            })
        })
        .take(4)
        .collect::<Vec<_>>();

    println!(
        "[special-validate] root={} stage=name-map status={} records={} mapped={} exact={} token={} hash={} unused_records={} unresolved_entries={} ambiguous_entries={} prefix={:?}",
        root_index,
        if mapped > 0 && unused_records == 0 { "ok" } else { "reject" },
        name_map.records.len(),
        mapped,
        mapped_exact,
        mapped_token,
        mapped_hash,
        unused_records,
        unresolved_entries,
        ambiguous_entries,
        token_prefix
    );
    for example in &unresolved_examples {
        println!(
            "[special-validate] root={} stage=name-map unresolved {}",
            root_index, example
        );
    }
    for example in &unused_examples {
        println!(
            "[special-validate] root={} stage=name-map unused {}",
            root_index, example
        );
    }

    if mapped == 0 || unused_records != 0 {
        return None;
    }

    Some((
        "cxdec-structural-token-hash".to_string(),
        names,
        100,
    ))
}

fn validate_special_fixed_params(
    archive: &Archive,
    roots: &[usize],
    fixed: xp3_brute::SpecialFixedParams,
    decoder_label: &str,
) -> Option<OrderedNameRecovery> {
    let decoder = CxdecNameProfile::Riddle {
        control_key: YuzControlKey(fixed.control_words),
        key: xp3_brute::YuzKey::riddle(fixed.seed0, fixed.seed1),
    };
    for &root_index in roots {
        let root = &archive.root_chunks[root_index];
        let Some(stored) = archive.special_index_bytes_for_root(root_index) else {
            continue;
        };
        let decoded = match decoder.decode_payload_bytes(stored) {
            Ok(value) => value,
            Err(err) => {
                println!(
                    "[special-validate] root={} stage=decrypt-zlib status=reject stored={} reason={}",
                    root_index,
                    stored.len(),
                    err
                );
                continue;
            }
        };
        if let Some(expected) = root
            .inferred_original_size
            .and_then(|value| usize::try_from(value).ok())
        {
            if decoded.len() != expected {
                println!(
                    "[special-validate] root={} stage=decrypt-zlib status=reject decoded={} expected={} reason=size",
                    root_index,
                    decoded.len(),
                    expected
                );
                continue;
            }
        }
        println!(
            "[special-validate] root={} stage=decrypt-zlib status=ok stored={} decoded={}",
            root_index,
            stored.len(),
            decoded.len()
        );
        let Some((layout, names, confidence)) =
            recover_cxdec_names_from_decoded(archive, root_index, decoder, &decoded)
        else {
            continue;
        };
        return Some(OrderedNameRecovery {
            root_index,
            decoder: decoder_label.to_string(),
            layout,
            names,
            confidence,
            decoded_size: decoded.len(),
            decoded: Some(decoded),
            xor: None,
        });
    }
    None
}

#[derive(Debug)]
struct SetupArchiveDataCandidates {
    archive_path: PathBuf,
    startup_route: String,
    startup_entries: usize,
    bootstrap_scripts_scanned: usize,
    values: Vec<(String, usize)>,
    symbolic_setup_calls: usize,
    symbolic_setup_unresolved: usize,
    symbolic_script_load_calls: usize,
    symbolic_script_load_unresolved: usize,
    symbolic_states_explored: usize,
    symbolic_steps_executed: usize,
    symbolic_objects_executed: usize,
    symbolic_truncated: bool,
}

#[derive(Debug, Default)]
struct StartupSetupDataScan {
    values: Vec<(String, usize)>,
    startup_entries: usize,
    bootstrap_scripts_scanned: usize,
    symbolic_setup_calls: usize,
    symbolic_setup_unresolved: usize,
    symbolic_script_load_calls: usize,
    symbolic_script_load_unresolved: usize,
    symbolic_states_explored: usize,
    symbolic_steps_executed: usize,
    symbolic_objects_executed: usize,
    symbolic_truncated: bool,
}

fn is_startup_tjs_name(name: &str) -> bool {
    name.rsplit(['/', '\\'])
        .next()
        .is_some_and(|base| base.eq_ignore_ascii_case("startup.tjs"))
}

fn normalized_archive_name(name: &str) -> String {
    name.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_ascii_lowercase()
}

fn referenced_tjs_entry(archive: &Archive, value: &str) -> Option<usize> {
    // KiriKiri storage strings may be either a plain archive-relative path or
    // `archive.xp3>path/to/script.tjs`.  The bootstrap archive is already
    // selected here, so compare the storage component after the last `>`.
    let storage = value.trim().rsplit_once('>').map_or(value.trim(), |(_, rhs)| rhs);
    let normalized = normalized_archive_name(storage);
    if !normalized.ends_with(".tjs") || normalized.is_empty() {
        return None;
    }
    if let Some((index, _)) = archive
        .entries
        .iter()
        .enumerate()
        .find(|(_, entry)| normalized_archive_name(entry.preferred_name()) == normalized)
    {
        return Some(index);
    }
    let basename = normalized.rsplit('/').next()?;
    let mut matches = archive.entries.iter().enumerate().filter_map(|(index, entry)| {
        let name = normalized_archive_name(entry.preferred_name());
        name.rsplit('/')
            .next()
            .is_some_and(|candidate| candidate == basename)
            .then_some(index)
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn startup_setup_data_candidates(
    archive: &Archive,
    native_startup_member: Option<&str>,
) -> StartupSetupDataScan {
    let startup_indices = if let Some(member) = native_startup_member {
        let member = normalized_archive_name(member);
        archive
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (normalized_archive_name(entry.preferred_name()) == member).then_some(index)
            })
            .collect::<Vec<_>>()
    } else {
        archive
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                is_startup_tjs_name(entry.preferred_name()).then_some(index)
            })
            .collect::<Vec<_>>()
    };

    let mut out = std::collections::BTreeMap::<String, usize>::new();
    let mut pending = std::collections::VecDeque::<usize>::from(startup_indices.clone());
    let mut visited = HashSet::<usize>::new();
    let mut scan = StartupSetupDataScan {
        startup_entries: startup_indices.len(),
        ..Default::default()
    };
    const MAX_BOOTSTRAP_SCRIPTS: usize = 64;

    while let Some(index) = pending.pop_front() {
        if visited.len() >= MAX_BOOTSTRAP_SCRIPTS || !visited.insert(index) {
            continue;
        }
        let Ok(bytes) = archive.reconstruct_entry(index) else {
            continue;
        };
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            continue;
        }

        if bytes.starts_with(b"TJS2100\0") {
            // For compiled TJS2, use the decompiler's CFG -> SSA -> ExprProgram
            // representation as the execution semantics.  String-pool entries
            // are constants used by bytecode, not setupArchiveData candidates.
            // Only values that actually reach a monitored call are accepted.
            match symbolically_execute_tjs2(&bytes) {
                Ok(report) => {
                    scan.symbolic_setup_calls += report.setup_archive_data_calls.len();
                    scan.symbolic_setup_unresolved += report.unresolved_setup_calls;
                    scan.symbolic_script_load_calls += report.script_load_calls.len();
                    scan.symbolic_script_load_unresolved += report.unresolved_script_load_calls;
                    scan.symbolic_states_explored += report.states_explored;
                    scan.symbolic_steps_executed += report.steps_executed;
                    scan.symbolic_objects_executed += report.objects_executed;
                    scan.symbolic_truncated |= report.truncated;

                    for call in report.setup_archive_data_calls {
                        if let Some(value) = call.argument {
                            out.entry(value).or_insert(index);
                        } else {
                            let mut repr = call.argument_repr;
                            if repr.chars().count() > 200 {
                                repr = repr.chars().take(200).collect::<String>() + "...";
                            }
                            eprintln!(
                                "[special       ] setupArchiveData unresolved entry={} object={} pc={} arg={}",
                                archive.entries[index].preferred_name(),
                                call.object_name.as_deref().unwrap_or("<anonymous>"),
                                call.pc,
                                repr,
                            );
                        }
                    }
                    for call in report.script_load_calls {
                        let Some(value) = call.argument else {
                            continue;
                        };
                        if let Some(next) = referenced_tjs_entry(archive, &value) {
                            if !visited.contains(&next) {
                                pending.push_back(next);
                            }
                        }
                    }
                }
                Err(error) => eprintln!(
                    "[special       ] tjs2_symbolic_error entry={} error={}",
                    archive.entries[index].preferred_name(),
                    error,
                ),
            }
            // A compiled TJS2 that the symbolic executor cannot resolve must
            // remain unresolved.  Do not fall back to trying every string-pool
            // constant: that was the source of the old false 36 candidates.
            continue;
        }

        // Source/wrapped TJS remains a separate path.  The existing source
        // evaluator handles direct calls, constants and simple concatenation.
        let values = setup_archive_data_text_candidates(&bytes);
        for value in values {
            if let Some(next) = referenced_tjs_entry(archive, &value) {
                if !visited.contains(&next) {
                    pending.push_back(next);
                }
            }
            out.entry(value).or_insert(index);
        }
    }

    scan.bootstrap_scripts_scanned = visited.len();
    scan.values = out.into_iter().collect();
    scan
}

fn find_case_insensitive_child(dir: &Path, file_name: &str) -> Option<PathBuf> {
    let direct = dir.join(file_name);
    if direct.is_file() {
        return Some(direct);
    }
    fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let ty = entry.file_type().ok()?;
        if !ty.is_file() {
            return None;
        }
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(file_name))
            .then(|| entry.path())
    })
}

fn discover_bootstrap_archive(
    archive: &Archive,
    scan_target: &Path,
    archive_name: &str,
) -> Option<PathBuf> {
    let mut roots = Vec::<PathBuf>::new();
    // The archive being unpacked identifies the game/archive directory most
    // directly.  This must work even when the caller supplied an EXE elsewhere
    // or is unpacking a sibling archive such as scn.xp3.
    if let Some(parent) = archive.path.as_deref().and_then(Path::parent) {
        roots.push(parent.to_path_buf());
    }
    let scan_root = if scan_target.is_dir() {
        Some(scan_target.to_path_buf())
    } else {
        scan_target.parent().map(Path::to_path_buf)
    };
    if let Some(root) = scan_root {
        if !roots.iter().any(|candidate| candidate == &root) {
            roots.push(root);
        }
    }

    for root in roots {
        if let Some(path) = find_case_insensitive_child(&root, archive_name) {
            return Some(path);
        }
    }
    None
}

fn bootstrap_setup_data_candidates(
    archive: &Archive,
    scan_target: &Path,
    redirect: Option<&StartupStorageRedirect>,
) -> Result<Option<SetupArchiveDataCandidates>, Box<dyn std::error::Error>> {
    let archive_name = redirect
        .map(|value| value.archive_name.as_str())
        .unwrap_or("data.xp3");
    let Some(data_path) = discover_bootstrap_archive(archive, scan_target, archive_name) else {
        return Ok(None);
    };
    let startup_member = redirect.map(|value| value.member_name.as_str());
    let startup_route = redirect
        .map(|value| {
            format!(
                "native-redirect:{}=>{}>{}",
                value.virtual_startup, value.archive_name, value.member_name
            )
        })
        .unwrap_or_else(|| "archive-name:startup.tjs".to_string());

    let current_is_data = archive.path.as_deref().is_some_and(|path| path == data_path);
    let scan = if current_is_data {
        startup_setup_data_candidates(archive, startup_member)
    } else {
        let data_archive = Archive::open(&data_path)
            .map_err(|error| cli_error(format!("failed to open bootstrap archive {}: {error}", data_path.display())))?;
        startup_setup_data_candidates(&data_archive, startup_member)
    };

    Ok(Some(SetupArchiveDataCandidates {
        archive_path: data_path,
        startup_route,
        startup_entries: scan.startup_entries,
        bootstrap_scripts_scanned: scan.bootstrap_scripts_scanned,
        values: scan.values,
        symbolic_setup_calls: scan.symbolic_setup_calls,
        symbolic_setup_unresolved: scan.symbolic_setup_unresolved,
        symbolic_script_load_calls: scan.symbolic_script_load_calls,
        symbolic_script_load_unresolved: scan.symbolic_script_load_unresolved,
        symbolic_states_explored: scan.symbolic_states_explored,
        symbolic_steps_executed: scan.symbolic_steps_executed,
        symbolic_objects_executed: scan.symbolic_objects_executed,
        symbolic_truncated: scan.symbolic_truncated,
    }))
}

fn verified_generated_values_from_bootstrap_archive(
    bootstrap_archive: &Archive,
    bootstrap: &SetupArchiveDataCandidates,
) -> Option<(Vec<u8>, (u32, u32), PathBuf)> {
    let roots = bootstrap_archive.indirect_special_roots();
    if roots.is_empty() {
        return None;
    }

    for (text, entry_index) in &bootstrap.values {
        let Ok(derived) = derive_special_params_from_archive_data_text(text) else {
            continue;
        };
        if validate_special_fixed_params(
            bootstrap_archive,
            &roots,
            derived.fixed,
            "setupArchiveData-generated-control-check",
        )
        .is_some()
        {
            let source = PathBuf::from(format!(
                "setupArchiveData:{}:entry[{entry_index}]",
                bootstrap.archive_path.display()
            ));
            return Some((
                derived.control_block,
                (derived.mask, derived.offset),
                source,
            ));
        }
    }
    None
}

fn unique_setup_generator_startup_redirect<'a>(
    modules: impl IntoIterator<Item = &'a xp3_brute::EmbeddedPeModule>,
) -> Option<StartupStorageRedirect> {
    let mut found: Option<StartupStorageRedirect> = None;
    for module in modules {
        let Some(candidate) = detect_startup_storage_redirect(&module.bytes) else {
            continue;
        };
        match &found {
            None => found = Some(candidate),
            Some(existing) if existing == &candidate => {}
            Some(_) => return None,
        }
    }
    found
}

fn verified_setup_archive_generated_values(
    archive: &Archive,
    scan_target: &Path,
) -> Result<(Vec<(Vec<u8>, PathBuf)>, Vec<((u32, u32), PathBuf)>), Box<dyn std::error::Error>> {
    let mut embedded = Vec::new();
    if scan_target.is_file() {
        embedded.extend(
            extract_embedded_pe_modules(scan_target).map_err(|e| cli_error(e.to_string()))?,
        );
    } else {
        for module in cxdec_candidate_modules(scan_target).map_err(|e| cli_error(e.to_string()))? {
            embedded.extend(
                extract_embedded_pe_modules(&module).map_err(|e| cli_error(e.to_string()))?,
            );
        }
    }
    let generators = embedded
        .iter()
        .filter(|module| has_setup_archive_data_special_generator(&module.bytes))
        .collect::<Vec<_>>();
    if generators.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let redirect = unique_setup_generator_startup_redirect(generators.iter().copied());

    let Some(bootstrap) =
        bootstrap_setup_data_candidates(archive, scan_target, redirect.as_ref())?
    else {
        return Ok((Vec::new(), Vec::new()));
    };

    let current_is_data = archive
        .path
        .as_deref()
        .is_some_and(|path| path == bootstrap.archive_path);
    let verified = if current_is_data {
        verified_generated_values_from_bootstrap_archive(archive, &bootstrap)
    } else {
        let data_archive = Archive::open(&bootstrap.archive_path).map_err(|error| {
            cli_error(format!(
                "failed to open bootstrap archive {} for Special validation: {error}",
                bootstrap.archive_path.display()
            ))
        })?;
        verified_generated_values_from_bootstrap_archive(&data_archive, &bootstrap)
    };

    let Some((control_block, mask_offset, source)) = verified else {
        return Ok((Vec::new(), Vec::new()));
    };
    Ok((
        vec![(control_block, source.clone())],
        vec![(mask_offset, source)],
    ))
}

fn recover_special_from_embedded_setup_generator(
    archive: &Archive,
    roots: &[usize],
    exe: &Path,
) -> Result<Option<OrderedNameRecovery>, Box<dyn std::error::Error>> {
    let embedded = extract_embedded_pe_modules(exe).map_err(|e| cli_error(e.to_string()))?;
    let generators = embedded
        .iter()
        .filter(|module| has_setup_archive_data_special_generator(&module.bytes))
        .collect::<Vec<_>>();
    if generators.is_empty() {
        if !embedded.is_empty() {
            eprintln!(
                "[special       ] embedded_pe={} setupArchiveData_generator=not-found",
                embedded.len()
            );
        }
        return Ok(None);
    }

    eprintln!(
        "[special       ] embedded_pe={} setupArchiveData_generator={} source={}",
        embedded.len(),
        generators.len(),
        generators
            .iter()
            .map(|module| module.label())
            .collect::<Vec<_>>()
            .join(",")
    );
    let redirect = unique_setup_generator_startup_redirect(generators.iter().copied());
    if let Some(redirect) = &redirect {
        eprintln!(
            "[special       ] startup_redirect virtual={} physical={}",
            redirect.virtual_startup, format!("{}>{}", redirect.archive_name, redirect.member_name)
        );
    }

    let Some(bootstrap) = bootstrap_setup_data_candidates(archive, exe, redirect.as_ref())? else {
        eprintln!(
            "[special       ] bootstrap_archive=not-found state=not-found search_root={}",
            exe.parent().unwrap_or_else(|| Path::new(".")).display()
        );
        return Ok(None);
    };
    eprintln!(
        "[special       ] bootstrap_archive={} startup_route={} startup_entries={} bootstrap_scripts={} setupArchiveData_calls={} resolved_values={} unresolved={} script_load_calls={} script_load_unresolved={} sym_objects={} sym_states={} sym_steps={} truncated={}",
        bootstrap.archive_path.display(),
        bootstrap.startup_route,
        bootstrap.startup_entries,
        bootstrap.bootstrap_scripts_scanned,
        bootstrap.symbolic_setup_calls,
        bootstrap.values.len(),
        bootstrap.symbolic_setup_unresolved,
        bootstrap.symbolic_script_load_calls,
        bootstrap.symbolic_script_load_unresolved,
        bootstrap.symbolic_objects_executed,
        bootstrap.symbolic_states_explored,
        bootstrap.symbolic_steps_executed,
        bootstrap.symbolic_truncated,
    );

    for (text, entry_index) in bootstrap.values {
        let Ok(derived) = derive_special_params_from_archive_data_text(&text) else {
            continue;
        };
        if let Some(recovery) = validate_special_fixed_params(
            archive,
            roots,
            derived.fixed,
            "setupArchiveData->SHAKE256+BLAKE2s/native-rust",
        ) {
            eprintln!(
                "[special       ] parameters verified source=setupArchiveData archive={} entry={} text_units={} seed0=0x{:08x} seed1=0x{:08x}",
                bootstrap.archive_path.display(),
                entry_index,
                text.encode_utf16().count(),
                derived.fixed.seed0,
                derived.fixed.seed1,
            );
            return Ok(Some(recovery));
        }
    }

    Ok(None)
}

fn recover_special_with_options(
    archive: &Archive,
    options: &SpecialCliOptions,
    progress_enabled: bool,
) -> Result<Option<SpecialIndexRecovery>, Box<dyn std::error::Error>> {
    if let Some(key) = options.key()? {
        return Ok(recover_special_index_with_xor_key(
            archive,
            &key,
            options.xor_scope,
        ));
    }
    if !progress_enabled || options.max_xor_period == 0 {
        return Ok(recover_special_index_with_max_xor_period(
            archive,
            options.max_xor_period,
        ));
    }

    let started = Instant::now();
    let state = Mutex::new(None::<(usize, SpecialXorScope, &'static str, usize, usize)>);
    let observer = |progress: SpecialRecoveryProgress| {
        let pct = if progress.total == 0 {
            100usize
        } else {
            progress.done.saturating_mul(100) / progress.total
        };
        let Ok(mut last) = state.lock() else {
            return;
        };
        let stage_changed = last
            .as_ref()
            .map(|(root, scope, compression, period, _)| {
                *root != progress.root_index
                    || *scope != progress.scope
                    || *compression != progress.compression
                    || *period != progress.period
            })
            .unwrap_or(true);
        let should_print = stage_changed
            || last
                .as_ref()
                .map(|(_, _, _, _, old_pct)| pct > *old_pct)
                .unwrap_or(true)
            || progress.done == progress.total;
        if !should_print {
            return;
        }
        *last = Some((
            progress.root_index,
            progress.scope,
            progress.compression,
            progress.period,
            pct,
        ));
        let seconds = started.elapsed().as_secs_f64().max(0.001);
        let rate = progress.done as f64 / seconds;
        eprint!(
            "\r[{:<14}] root={} {} {} p={} {:>3}% {}/{} {:>9.0} cand/s",
            "special-index",
            progress.root_index,
            special_scope_label(progress.scope),
            progress.compression,
            progress.period,
            pct,
            progress.done,
            progress.total,
            rate
        );
        if progress.done == progress.total {
            eprintln!();
        }
    };

    let result = recover_special_index_with_progress(archive, options.max_xor_period, &observer);
    // A successful `find_map_any` may stop a stage before `done == total`.
    // Terminate the carriage-return progress line explicitly so the recovered
    // key/result is never printed on top of it.
    if state
        .lock()
        .ok()
        .and_then(|last| last.as_ref().map(|(_, _, _, _, pct)| *pct))
        .is_some_and(|pct| pct < 100)
    {
        eprintln!();
    }
    Ok(result)
}

fn recover_early_plain_cxdec_names(
    archive: &Archive,
    roots: &[usize],
) -> Result<Option<OrderedNameRecovery>, Box<dyn std::error::Error>> {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct GroupEvidence {
        exact: usize,
        token: usize,
        hash: usize,
        token_like: usize,
    }

    fn group_evidence(archive: &Archive, map: &xp3_brute::CxdecNameMap) -> GroupEvidence {
        let mut evidence = GroupEvidence::default();
        for entry in &archive.entries {
            if entry.is_protected_dummy() || entry.name == "$" {
                continue;
            }
            let raw = entry.name.as_str();
            let preferred = entry.preferred_name();
            if looks_like_md5_lookup_token(raw) || looks_like_md5_lookup_token(preferred) {
                evidence.token_like += 1;
            }
            if map.records.iter().any(|record| {
                record
                    .name
                    .as_deref()
                    .is_some_and(|name| name == raw || name == preferred)
            }) {
                evidence.exact += 1;
            }
            if map.by_md5.iter().any(|(token, _)| {
                token.eq_ignore_ascii_case(raw) || token.eq_ignore_ascii_case(preferred)
            }) {
                evidence.token += 1;
            }
            if let Some(hash) = entry.adler {
                if map.records.iter().any(|record| record.hash == hash) {
                    evidence.hash += 1;
                }
            }
        }
        evidence
    }

    for &root_index in roots {
        let Some(root) = archive.root_chunks.get(root_index) else {
            continue;
        };
        let Some(stored) = archive.special_index_bytes_for_root(root_index) else {
            continue;
        };
        let decoded = match decode_plain_cxdec_name_payload(stored) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(expected) = root
            .inferred_original_size
            .and_then(|value| usize::try_from(value).ok())
        {
            if decoded.len() != expected {
                continue;
            }
        }

        // V1 carries a runtime string after the size tuple. The supplied native
        // implementation appends this value to the normalized UTF-16 filename
        // before MD5. It is a recovered data parameter, never family evidence.
        let token_suffix = if root.kind == RootKind::SpecialIndexV1 {
            root.inferred_name.as_deref()
        } else {
            None
        };
        let groups = match parse_structural_cxdec_name_record_groups(&decoded, token_suffix) {
            Ok(value) if !value.is_empty() => value,
            _ => continue,
        };

        // The native parser searches for one runtime-supplied four-byte record
        // signature. Do not hard-code that signature. Select the corresponding
        // group from archive-wide relations instead: exact names and native MD5
        // tokens are authoritative mapping evidence; the record u32/adlr
        // equality is only an auxiliary tie-breaker because its semantics vary
        // between generations.
        let mut ranked = groups
            .iter()
            .enumerate()
            .map(|(index, map)| (index, group_evidence(archive, map)))
            .collect::<Vec<_>>();
        ranked.sort_by(|(left_index, left), (right_index, right)| {
            let left_primary = left.exact + left.token;
            let right_primary = right.exact + right.token;
            right_primary
                .cmp(&left_primary)
                .then_with(|| right.token.cmp(&left.token))
                .then_with(|| right.exact.cmp(&left.exact))
                .then_with(|| right.hash.cmp(&left.hash))
                .then_with(|| groups[*right_index].records.len().cmp(&groups[*left_index].records.len()))
        });

        let Some(&(selected_index, selected_evidence)) = ranked.first() else {
            continue;
        };
        let selected_primary = selected_evidence.exact + selected_evidence.token;
        let tied = ranked.iter().skip(1).any(|(index, evidence)| {
            let primary = evidence.exact + evidence.token;
            primary == selected_primary
                && evidence.token == selected_evidence.token
                && evidence.exact == selected_evidence.exact
                && evidence.hash == selected_evidence.hash
                && groups[*index].records.len() == groups[selected_index].records.len()
        });
        let no_mapping_evidence = selected_primary == 0 && selected_evidence.hash == 0;
        if tied || (no_mapping_evidence && groups.len() != 1) {
            let summary = ranked
                .iter()
                .take(8)
                .map(|(index, evidence)| {
                    let signature = u32::from_le_bytes(groups[*index].section_id);
                    format!(
                        "sig=0x{signature:08x}:records={},exact={},token={},hash={}",
                        groups[*index].records.len(),
                        evidence.exact,
                        evidence.token,
                        evidence.hash
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(cli_error(format!(
                "recognized early CXDEC plain-zlib Special at root {root_index}, but structural name-record group selection is {}: {summary}",
                if tied { "ambiguous" } else { "unresolved" }
            ))
            .into());
        }

        let name_map = &groups[selected_index];
        let selected_signature = u32::from_le_bytes(name_map.section_id);
        eprintln!(
            "[special-names  ] root={} groups={} selected_signature=0x{:08x} records={} exact={} token={} hash_aux={} token_like_entries={}",
            root_index,
            groups.len(),
            selected_signature,
            name_map.records.len(),
            selected_evidence.exact,
            selected_evidence.token,
            selected_evidence.hash,
            selected_evidence.token_like,
        );

        let mut names = Vec::with_capacity(archive.entries.len());
        let mut mapped = 0usize;
        let mut mapped_shortcut = 0usize;
        let mut mapped_exact = 0usize;
        let mut mapped_token = 0usize;
        let mut mapped_hash = 0usize;
        let mut retained_visible = 0usize;
        let mut unresolved = Vec::new();

        for (entry_index, entry) in archive.entries.iter().enumerate() {
            if entry.is_protected_dummy() {
                names.push(entry.preferred_name().to_string());
                continue;
            }

            // Native FilenameMap shortcuts are aliases, not consuming entries
            // from the decoded table. The same decoded record may therefore be
            // reachable through a shortcut and through its normal token/hash.
            if entry.name == "$" {
                names.push("startup.tjs".to_string());
                mapped += 1;
                mapped_shortcut += 1;
                continue;
            }

            let raw = entry.name.as_str();
            let preferred = entry.preferred_name();
            let mut route = None::<(&'static str, String)>;

            let exact_names = name_map
                .records
                .iter()
                .filter_map(|record| record.name.as_deref())
                .filter(|name| *name == raw || *name == preferred)
                .collect::<HashSet<_>>();
            if exact_names.len() == 1 {
                route = exact_names
                    .into_iter()
                    .next()
                    .map(|name| ("exact", name.to_string()));
            }

            if route.is_none() {
                if let Some(name) = name_map.by_md5.iter().find_map(|(token, name)| {
                    (token.eq_ignore_ascii_case(raw) || token.eq_ignore_ascii_case(preferred))
                        .then_some(name.clone())
                }) {
                    route = Some(("token", name));
                }
            }

            // The first u32 in a decoded record is not assumed to *be* adlr.
            // Some nearby implementations use that equality as a lookup
            // fallback, so accept it only when it independently identifies one
            // distinct filename. It never participates in family detection.
            if route.is_none() {
                if let Some(hash) = entry.adler {
                    let hash_names = name_map
                        .records
                        .iter()
                        .filter(|record| record.hash == hash)
                        .filter_map(|record| record.name.as_deref())
                        .collect::<HashSet<_>>();
                    if hash_names.len() == 1 {
                        route = hash_names
                            .into_iter()
                            .next()
                            .map(|name| ("hash-aux", name.to_string()));
                    }
                }
            }

            if let Some((selected_route, recovered)) = route {
                names.push(recovered);
                mapped += 1;
                match selected_route {
                    "exact" => mapped_exact += 1,
                    "token" => mapped_token += 1,
                    "hash-aux" => mapped_hash += 1,
                    _ => {}
                }
                continue;
            }

            // An already-readable ordinary name does not need a Special table
            // override. A 32-hex lookup token, however, is not a real filename
            // and must never silently pass the name-complete gate.
            if !looks_like_md5_lookup_token(raw) && !looks_like_md5_lookup_token(preferred) {
                names.push(preferred.to_string());
                retained_visible += 1;
                continue;
            }

            names.push(preferred.to_string());
            if unresolved.len() < 8 {
                unresolved.push(format!(
                    "entry={} visible={:?} info_name_len={} adlr={}",
                    entry_index,
                    preferred,
                    entry.info_name_length,
                    entry
                        .adler
                        .map(|value| format!("0x{value:08x}"))
                        .unwrap_or_else(|| "none".to_string())
                ));
            }
        }

        if !unresolved.is_empty() {
            return Err(cli_error(format!(
                "recognized early CXDEC plain-zlib Special at root {root_index}, selected structural record signature=0x{selected_signature:08x}, but lookup-token mapping remains unresolved (records={} exact={} token={} hash_aux={} retained_visible={}): {}",
                name_map.records.len(),
                mapped_exact,
                mapped_token,
                mapped_hash,
                retained_visible,
                unresolved.join("; ")
            ))
            .into());
        }

        eprintln!(
            "[special-family ] root={} generation=early-dynamic-xcode strategy=plain-zlib-name-records product_param={} signature=0x{:08x} records={} mapped={} shortcut={} exact={} token={} hash_aux={} retained_visible={}",
            root_index,
            token_suffix.is_some(),
            selected_signature,
            name_map.records.len(),
            mapped,
            mapped_shortcut,
            mapped_exact,
            mapped_token,
            mapped_hash,
            retained_visible,
        );
        return Ok(Some(OrderedNameRecovery {
            root_index,
            decoder: "cxdec-early-plain-zlib".to_string(),
            layout: "cxdec-structural-name-records".to_string(),
            names,
            confidence: 100,
            decoded_size: decoded.len(),
            decoded: Some(decoded),
            xor: None,
        }));
    }
    Ok(None)
}

fn recover_ordered_names_with_hx_options(
    archive: &Archive,
    options: &HxCliOptions,
    special_options: &SpecialCliOptions,
    progress_enabled: bool,
) -> Result<Option<OrderedNameRecovery>, Box<dyn std::error::Error>> {
    // HXV4 Special is an authenticated XChaCha20-Poly1305 payload, not an
    // ordered M2/Yuzu repeating-XOR table.  Do not spend minutes feeding it to
    // the historical structured/period attack.  Explicit HXV4 material is
    // handled by `load_hx_index`, which parses the native hash/object table.
    if archive.is_hxv4() {
        return Ok(None);
    }

    // Ordered-name recovery exists only for archives that actually carry an
    // out-of-line indirect Special descriptor.  A normal Standard/Krkr2 XP3
    // may still have an executable next to it (and that executable may itself
    // embed ordinary TPM modules), but none of that is evidence that a Special
    // name layer exists.  Do not probe setupArchiveData, later Special cipher
    // state, or any other Special strategy unless the archive structure first
    // establishes that such a layer is present.  Content-filter detection is
    // independent and runs later in the unpack pipeline.
    if archive.indirect_special_roots().is_empty() {
        return Ok(None);
    }

    // A supplied or automatically discovered PE32 game executable takes
    // precedence over expensive archive-only brute force. Historically V1/V2 Special
    // payloads may be transformed by an arbitrary title-specific native
    // SpecialChunkDecoder over the first min(stored_size, 0x100) bytes before
    // zlib.  The archive-only repeating-XOR search is only one fallback model
    // and must not run for minutes before the executable has even been
    // inspected.
    //
    // First keep the cheap direct/raw/compressed checks (max period 0).  They
    // cover genuinely unprotected Special payloads without invoking any
    // brute-force stage.  If they fail, inspect the executable and fail closed
    // until the corresponding native Special decoder/key recovery is available.
    // This makes the missing executable-assisted path explicit instead of
    // silently discarding --exe and entering p=1..5 brute force.
    let exe = if let Some(explicit) = options.explicit_exe() {
        Some(explicit)
    } else if options.exe_auto_enabled() {
        archive
            .path
            .as_deref()
            .map(|archive_path| discover_game_executables(archive_path, None))
            .transpose()
            .map_err(cli_error)?
            .and_then(|candidates| candidates.into_iter().next())
    } else {
        None
    };

    if let Some(exe) = exe {
        // Identify the executable generation before selecting a Special
        // strategy. This probes disk and embedded PE modules by code semantics;
        // archive tags and product/title strings are not family evidence.
        let family_probes = probe_cxdec_game_modules(&exe)
            .map_err(|error| cli_error(error.to_string()))?;
        let early_dynamic = family_probes
            .iter()
            .filter(|probe| {
                generation_from_probe(probe) == CxdecGeneration::EarlyDynamicXcode
            })
            .collect::<Vec<_>>();
        if !early_dynamic.is_empty() {
            for probe in &early_dynamic {
                eprintln!(
                    "[special-family ] candidate=early-dynamic-xcode module={} confidence={} complete={} evidence={}",
                    probe.path.display(),
                    probe.confidence,
                    probe.native_complete(),
                    probe.reasons.join("; "),
                );
            }
            let roots = archive.indirect_special_roots();
            if let Some(recovery) = recover_early_plain_cxdec_names(archive, &roots)? {
                return Ok(Some(recovery));
            }
        }

        // A zero-period archive-only decode is a strategy candidate, not family
        // evidence. Run it only after known executable generations had their
        // own strategy first; this prevents a generic parser from bypassing
        // product-aware or generation-specific validation.
        if let Some(hit) = recover_special_index_with_max_xor_period(archive, 0) {
            return Ok(Some(hit.into_ordered_names()));
        }

        // Automatic extraction must be driven only by fixed parameters recovered
        // from the supplied game files. Known-title reference fixtures are
        // intentionally not tried here; they exist only in tests/reference
        // APIs and must never make production recovery look automatic.
        let roots = archive.indirect_special_roots();

        // Some executables keep the actual protection module as a compressed
        // `internal module` PE and manually map it at runtime.  When that
        // module exposes the setupArchiveData generator, reproduce the native
        // parameter derivation directly in Rust before trying materialized
        // static-state recovery.
        if let Some(recovery) =
            recover_special_from_embedded_setup_generator(archive, &roots, &exe)?
        {
            return Ok(Some(recovery));
        }

        // Later Special ciphers are parameterized only after their own cipher
        // semantics have been observed.  In particular, an arbitrary CXDEC
        // 4096-byte control table is not Special-cipher evidence: early content
        // filters use the same table shape without any setupArchiveData/ChaCha
        // Special layer.  First recover seed/fixed-state facts from actual
        // Special cipher call/data flow, then scan generic control tables only
        // when a seed pair proves that such a combination is meaningful.
        let modules = cxdec_candidate_modules(&exe).map_err(|e| cli_error(e.to_string()))?;
        let embedded_modules =
            extract_embedded_pe_modules(&exe).map_err(|e| cli_error(e.to_string()))?;
        let mut controls = Vec::<([u32; 8], PathBuf)>::new();
        let mut seeds = Vec::<(u32, u32, PathBuf, usize, &'static str)>::new();
        let mut combined = std::collections::BTreeMap::<
            ([u32; 8], u32, u32),
            (PathBuf, PathBuf, usize, &'static str),
        >::new();
        let mut special_cipher_evidence = 0usize;

        for module in &modules {
            // These facts require code/data-flow evidence tied to the later
            // complemented-ChaCha Special cipher. A sigma byte sequence alone
            // is deliberately insufficient.
            let facts = recover_static_special_param_facts(module)
                .map_err(|e| cli_error(e.to_string()))?;
            special_cipher_evidence += facts.len();
            for fact in facts {
                if let Some(control) = fact.control_words {
                    if !controls.iter().any(|(value, _)| *value == control) {
                        controls.push((control, module.clone()));
                    }
                }
                if let Some((seed0, seed1)) = fact.seeds {
                    if !seeds.iter().any(|(a, b, _, _, _)| *a == seed0 && *b == seed1) {
                        seeds.push((
                            seed0,
                            seed1,
                            module.clone(),
                            fact.evidence_rva as usize,
                            "static-call-arguments",
                        ));
                    }
                }
            }

            // A complete materialized 64-byte state proves the later Special
            // family and already contains every external parameter.
            let fixed_candidates = recover_riddle_special_fixed_params_from_pe(module)
                .map_err(|e| cli_error(e.to_string()))?;
            special_cipher_evidence += fixed_candidates.len();
            for candidate in fixed_candidates {
                let fixed = candidate.fixed;
                combined.entry((fixed.control_words, fixed.seed0, fixed.seed1)).or_insert((
                    module.clone(),
                    module.clone(),
                    candidate.file_offset,
                    candidate.representation,
                ));
            }
        }

        for embedded in &embedded_modules {
            let source = PathBuf::from(embedded.label());
            let facts = recover_static_special_param_facts_from_pe_bytes(&embedded.bytes)
                .map_err(|e| cli_error(e.to_string()))?;
            special_cipher_evidence += facts.len();
            for fact in facts {
                if let Some(control) = fact.control_words {
                    if !controls.iter().any(|(value, _)| *value == control) {
                        controls.push((control, source.clone()));
                    }
                }
                if let Some((seed0, seed1)) = fact.seeds {
                    if !seeds.iter().any(|(a, b, _, _, _)| *a == seed0 && *b == seed1) {
                        seeds.push((
                            seed0,
                            seed1,
                            source.clone(),
                            fact.evidence_rva as usize,
                            "embedded-static-call-arguments",
                        ));
                    }
                }
            }

            let fixed_candidates =
                recover_riddle_special_fixed_params_from_pe_bytes(&embedded.bytes);
            special_cipher_evidence += fixed_candidates.len();
            for candidate in fixed_candidates {
                let fixed = candidate.fixed;
                combined.entry((fixed.control_words, fixed.seed0, fixed.seed1)).or_insert((
                    source.clone(),
                    source.clone(),
                    candidate.file_offset,
                    candidate.representation,
                ));
            }
        }

        // Only a proven seed-bearing later Special cipher justifies combining
        // generic CXDEC control tables from other modules. This avoids treating
        // the early content-filter control table as a Special parameter source.
        if !seeds.is_empty() {
            for module in &modules {
                for block in recover_static_cxdec_control_blocks(module)
                    .map_err(|e| cli_error(e.to_string()))?
                {
                    if let Ok(control) = YuzControlKey::from_encoded_cxdec_control_block(&block) {
                        if !controls.iter().any(|(value, _)| *value == control.0) {
                            controls.push((control.0, module.clone()));
                        }
                    }
                }
            }
            for embedded in &embedded_modules {
                let source = PathBuf::from(embedded.label());
                for block in recover_static_cxdec_control_blocks_from_pe_bytes(&embedded.bytes)
                    .map_err(|e| cli_error(e.to_string()))?
                {
                    if let Ok(control) = YuzControlKey::from_encoded_cxdec_control_block(&block) {
                        if !controls.iter().any(|(value, _)| *value == control.0) {
                            controls.push((control.0, source.clone()));
                        }
                    }
                }
            }
        }

        for (control, control_source) in &controls {
            for (seed0, seed1, seed_source, seed_offset, representation) in &seeds {
                combined.entry((*control, *seed0, *seed1)).or_insert((
                    control_source.clone(),
                    seed_source.clone(),
                    *seed_offset,
                    *representation,
                ));
            }
        }

        if special_cipher_evidence == 0 && combined.is_empty() {
            let detected = family_probes
                .iter()
                .map(|probe| format!("{}:{}", probe.path.display(), probe.profile()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(cli_error(format!(
                "Special strategy unresolved after family detection: no setupArchiveData result and no later Special-cipher seed/fixed-state semantics were found; detected content families=[{detected}]"
            ))
            .into());
        }

        let total_pe = modules.len() + embedded_modules.len();
        eprintln!(
            "[special       ] scanned disk_pe={} embedded_pe={} total_pe={}",
            modules.len(),
            embedded_modules.len(),
            total_pe,
        );
        eprintln!(
            "[special       ] static parameters: control={} seed_pair={} combinations={}",
            controls.len(),
            seeds.len(),
            combined.len(),
        );

        for ((control, seed0, seed1), (control_source, seed_source, _seed_offset, _representation)) in combined {
            let fixed = xp3_brute::SpecialFixedParams::new(control, seed0, seed1);
            if let Some(recovery) = validate_special_fixed_params(
                archive,
                &roots,
                fixed,
                "special-static-params+zlib/native-rust",
            ) {
                eprintln!(
                    "[special       ] parameters verified control_source={} seed_source={} seed0=0x{:08x} seed1=0x{:08x}",
                    control_source.display(),
                    seed_source.display(),
                    fixed.seed0,
                    fixed.seed1,
                );
                return Ok(Some(recovery));
            }
        }

        return Err(cli_error(format!(
            "failed to recover Special parameters: disk_pe={} embedded_pe={} setupArchiveData candidates did not validate and static candidates did not validate (control={} seed_pair={})",
            modules.len(),
            embedded_modules.len(),
            controls.len(),
            seeds.len(),
        ))
        .into());
    }

    Ok(
        recover_special_with_options(archive, special_options, progress_enabled)?
            .map(SpecialIndexRecovery::into_ordered_names),
    )
}

fn decode_special(
    archive: &Archive,
    output: &Path,
    special_options: &SpecialCliOptions,
    hx_options: &HxCliOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "special-decode start roots={} entries={} family={} cpu_kernel={}",
        archive.root_chunks.len(),
        archive.entries.len(),
        if archive.is_hxv4() {
            "Hxv4"
        } else {
            "ordinary/legacy"
        },
        cpu_backend_label()
    );

    if archive.is_hxv4() {
        let startup = hxv4_startup_entry_index(&archive.entries);
        let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
        let blob = archive
            .hxv4_special_index_bytes()
            .ok_or_else(|| cli_error("Hxv4 special-index descriptor points outside archive"))?;
        let tag = hxv4_special_tag(blob)
            .map(|tag| tag.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .unwrap_or_else(|| "<missing>".to_string());
        eprintln!(
            "[special-index ] route=HXV4 cipher=xchacha20-poly1305 tag={} ciphertext_bytes={} nonce_slot={} nonce_bytes=24 startup_anchor={} repeating_xor_probe=skipped",
            tag,
            blob.len().saturating_sub(16),
            hxv4_special_nonce_slot(flags),
            startup.map(|i| i.to_string()).unwrap_or_else(|| "missing".to_string())
        );
        let keys = resolve_hx_keys(archive, hx_options)?.ok_or_else(|| cli_error(
            "Hxv4 Special is authenticated XChaCha20-Poly1305 and no validated key material could be recovered. Supply --exe PATH (or place the game PE32 executable next to the XP3/one directory above it), or provide --hx-key/--hx-nonce explicitly."
        ))?;
        let decoded = decrypt_hxv4_special_payload(blob, &keys)?;
        // Verify the native Hx object grammar as part of decode-special too.
        let index = decrypt_hxv4_special_index(blob, &keys)?;
        fs::write(output, &decoded)?;
        println!(
            "special-index decrypted decoder=hxv4-xchacha20poly1305->zlib layout=hx-object entries={} decoded_size={} output={}",
            index.entries.len(), decoded.len(), output.display()
        );
        return Ok(());
    }

    if let Some(recovery) = recover_special_with_options(archive, special_options, true)? {
        fs::write(output, &recovery.decoded)?;
        println!(
            "special-index decrypted root={} decoder={} layout={} names={} confidence={} decoded_size={} output={}",
            recovery.root_index, recovery.decoder, recovery.layout, recovery.names.len(),
            recovery.confidence, recovery.decoded.len(), output.display()
        );
        if let Some(xor) = &recovery.xor {
            print_special_xor_recovery("special-index recovered", xor);
            let key_path = write_special_xor_sidecar(output, xor)?;
            println!("special-index xor-key written {}", key_path.display());
        }
        return Ok(());
    }

    Err(cli_error(
        "special index remains encrypted/unknown: ordinary direct/structured/zero-period and bounded legacy models did not validate; optional --special-xor-key may be supplied when known",
    ).into())
}

fn inspect_hx_index(
    archive: &Archive,
    index: Option<&Hxv4Index>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !archive.is_hxv4() {
        return Ok(());
    }
    match index {
        Some(index) => print_hx_index(index),
        None => {
            let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
            let blob = archive.hxv4_special_index_bytes();
            let tag = blob
                .and_then(hxv4_special_tag)
                .map(|tag| tag.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .unwrap_or_else(|| "<missing>".to_string());
            println!(
                "hxv4 index state=encrypted key_material=missing cipher=xchacha20-poly1305 nonce_slot={} tag={} ciphertext_bytes={}",
                hxv4_special_nonce_slot(flags),
                tag,
                blob.map(|b| b.len().saturating_sub(16)).unwrap_or(0)
            );
        }
    }
    Ok(())
}

fn print_hx_index(index: &Hxv4Index) {
    let resolved = index.entries.iter().filter(|e| e.name.is_some()).count();
    let resolved_paths = index.entries.iter().filter(|e| e.path.is_some()).count();
    println!("hxv4 index decrypted entries={} inflated={} resolved_names={} resolved_paths={} hash_only={}", index.entries.len(), index.decompressed_size, resolved, resolved_paths, index.entries.len().saturating_sub(resolved));
    for e in index.entries.iter().take(20) {
        println!(
            "  record={} packed=0x{:016x} archive_slot={} filter_flag={} id={} entry_key=0x{:016x} path_hash={} name_hash={} path={}",
            e.record_index, e.packed, e.archive_slot, e.filter_flag, e.id, e.entry_key,
            e.path_hash_hex(), e.name_hash_hex(), e.display_path()
        );
    }
    if index.entries.len() > 20 {
        println!("  ... {} more", index.entries.len() - 20);
    }
}

fn write_hx_index_report(index: &Hxv4Index, path: &Path) -> io::Result<()> {
    let mut out = String::new();
    out.push_str("record\tpacked\tarchive_slot\tfilter_flag\tid\tentry_key\tpath_hash\tname_hash\tresolved_path\n");
    for e in &index.entries {
        out.push_str(&format!(
            "{}\t{:016x}\t{}\t{}\t{}\t{:016x}\t{}\t{}\t{}\n",
            e.record_index,
            e.packed,
            e.archive_slot,
            e.filter_flag,
            e.id,
            e.entry_key,
            e.path_hash_hex(),
            e.name_hash_hex(),
            e.display_path()
        ));
    }
    fs::write(path, out)
}

fn scan_special(
    archive: &Archive,
    special_options: &SpecialCliOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut any = false;
    for (i, root) in archive.root_chunks.iter().enumerate() {
        if let Some(blob) = archive.special_index_bytes_for_root(i) {
            any = true;
            println!(
                "special-root[{i}] kind={} tag={} offset=0x{:x} bytes={} original_size={}",
                root_kind(root.kind),
                tag_to_string(root.magic),
                root.inferred_offset.unwrap_or(0),
                blob.len(),
                root.inferred_original_size
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string())
            );
            for p in probe_blob(blob) {
                println!(
                    "  +0x{:x} confidence={} kind={:?} length={} decoded={} {}",
                    p.offset,
                    p.confidence,
                    p.kind,
                    p.length
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "?".into()),
                    p.decoded_length
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "?".into()),
                    p.label
                );
            }
        } else if root.kind == RootKind::Unknown {
            any = true;
            println!(
                "unknown-root[{i}] tag={} size={} index_block={} index_offset=0x{:x} state=inline-opaque",
                tag_to_string(root.magic), root.size, root.index_block, root.index_offset
            );
        }
    }
    if archive.is_hxv4() {
        let startup = hxv4_startup_entry_index(&archive.entries);
        let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
        let blob = archive.hxv4_special_index_bytes();
        let tag = blob
            .and_then(hxv4_special_tag)
            .map(|tag| tag.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .unwrap_or_else(|| "<missing>".to_string());
        println!(
            "special-index state=hxv4-aead cipher=xchacha20-poly1305 tag={} ciphertext_bytes={} nonce_slot={} nonce_bytes=24 repeating_xor_probe=skipped startup_anchor={}",
            tag,
            blob.map(|b| b.len().saturating_sub(16)).unwrap_or(0),
            hxv4_special_nonce_slot(flags),
            startup.map(|i| format!("entry[{i}]=startup.tjs")).unwrap_or_else(|| "missing".to_string())
        );
    } else if let Some(recovery) = recover_special_with_options(archive, special_options, true)? {
        println!(
            "special-index decrypted root={} decoder={} layout={} names={} confidence={} decoded_size={}",
            recovery.root_index, recovery.decoder, recovery.layout, recovery.names.len(),
            recovery.confidence, recovery.decoded.len()
        );
        if let Some(xor) = &recovery.xor {
            print_special_xor_recovery("special-index recovered", xor);
        }
        for (i, name) in recovery.names.iter().take(12).enumerate() {
            println!("  name[{i}]={name}");
        }
        if recovery.names.len() > 12 {
            println!("  ... {} more", recovery.names.len() - 12);
        }
    } else if any {
        println!("special-index state=encrypted/unknown ordinary direct/structured/zero-period models did not validate");
    }
    if !any {
        println!("no special/unknown XP3 root chunks found");
    }
    Ok(())
}

fn format_extension(format: &str) -> &'static str {
    if format.starts_with("TLG5") || format.starts_with("TLG6") || format.starts_with("TLG0/") {
        return "tlg";
    }
    if format.starts_with("Kirikiri/Text-") || format.starts_with("Text/") {
        return "txt";
    }
    if format.starts_with("Ogg/Opus") {
        return "opus";
    }
    match format {
        "PNG" => "png",
        "JPEG" => "jpg",
        "JPEG-XR/WMP" => "jxr",
        "Ogg" | "Ogg/Vorbis" | "Ogg/Theora" => "ogg",
        "WAVE/RIFF" => "wav",
        "AVI/RIFF" => "avi",
        "GIF87a" | "GIF89a" => "gif",
        "BMP" => "bmp",
        "WebP/RIFF" => "webp",
        "ZIP/local" | "ZIP/empty" => "zip",
        "7-Zip" => "7z",
        "gzip" => "gz",
        "TJS2/Bytecode" => "tjs",
        "PSB/M2-Emote" => "psb",
        "PSZ/PSB-shell" => "psz",
        "MDF/PSB-shell" => "mdf",
        "MFL/PSB-shell" => "mfl",
        "TrueType/sfnt" => "ttf",
        "OpenType/CFF" => "otf",
        "TrueType/Collection" => "ttc",
        "WOFF" => "woff",
        "WOFF2" => "woff2",
        name if name.starts_with("Kirikiri/PrerenderedFont-") => "tft",
        "FLAC" => "flac",
        "MP3/ID3" => "mp3",
        "MIDI" => "mid",
        "MP4/ISO-BMFF" => "mp4",
        "DDS" => "dds",
        "ICO" => "ico",
        "CUR" => "cur",
        "WebM/Matroska" => "webm",
        "ASF/WMV-WMA" => "asf",
        "MPEG-PS" => "mpg",
        "MPEG-1/Video" => "m1v",
        "H264/AnnexB-4" | "H264/AnnexB-3" => "h264",
        "Photoshop/PSD" => "psd",
        "TGA" => "tga",
        // MZ alone does not distinguish EXE/DLL/TPM/AX. Keep .bin unless a
        // more specific libmagic rule can determine the concrete PE subtype.
        "PE/COFF" => "bin",
        _ => "bin",
    }
}

fn hx_output_path(id: u64, meta: Option<&Hxv4IndexEntry>, format: Option<&str>) -> String {
    if let Some(meta) = meta {
        if meta.name.is_some() {
            return meta.display_path();
        }
        let ext = format.map(format_extension).unwrap_or("bin");
        return format!(
            "_hxv4_hash/{}/{:08x}_{}.{}",
            meta.path_hash_hex(),
            id,
            meta.name_hash_hex(),
            ext
        );
    }
    let ext = format.map(format_extension).unwrap_or("bin");
    format!("_hxv4_id/{id:08x}.{ext}")
}

fn root_kind(kind: RootKind) -> &'static str {
    match kind {
        RootKind::File => "File",
        RootKind::ProtectedFile => "protected-dummy/File",
        RootKind::AlternateName => "alt-name/M2-shaped",
        RootKind::SpecialIndexV1 => "special-index-v1-shaped",
        RootKind::SpecialIndexV2 => "special-index-v2-shaped",
        RootKind::SpecialIndexV3 => "special-index-v3-shaped",
        RootKind::SpecialIndexGeneric => "special-index-generic-shaped",
        RootKind::Hxv4SpecialIndex => "Hxv4-special-index",
        RootKind::Unknown => "unknown",
    }
}

fn inspect(archive: &Archive, ordered_names: Option<&OrderedNameRecovery>) {
    println!(
        "xp3_offset=0x{:x} index_blocks={} root_chunks={} entries={} hxv4={}",
        archive.xp3_offset,
        archive.index_blocks.len(),
        archive.root_chunks.len(),
        archive.entries.len(),
        archive.is_hxv4()
    );
    let plan = recovery_plan(archive);
    println!("strategy family={:?} plain={} shared_xor={} per_file_xor={} hxv4_effective={} unknown_chunk_probe={}", plan.family, plan.try_plain, plan.try_shared_repeating_xor, plan.try_per_file_repeating_xor, plan.try_hxv4_effective_filter, plan.probe_unknown_chunks);
    if let Some(names) = ordered_names {
        println!(
            "ordered_names source_root={} decoder={} layout={} count={} confidence={} decoded_size={}",
            names.root_index, names.decoder, names.layout, names.names.len(), names.confidence, names.decoded_size
        );
    }
    if let Some(hx) = &archive.hxv4 {
        let prefix = archive
            .hxv4_special_index_bytes()
            .map(|data| hex_prefix(data, 16))
            .unwrap_or_else(|| "<out-of-range>".to_string());
        println!(
            "hxv4 special_index offset=0x{:x} stored_size={} kind={} state=opaque/encrypted prefix16={}",
            hx.offset, hx.stored_size, hx.kind, prefix
        );
        println!(
            "hxv4 note: normal XP3 info names are synthetic entry ids; decrypt the special index before deciding whether its payload is ordered names, hashes, or another index layout"
        );
    }

    for (i, root) in archive.root_chunks.iter().enumerate() {
        print!(
            "root[{i}] block={} off=0x{:x} tag='{}' size={} kind={}",
            root.index_block,
            root.index_offset,
            tag_to_string(root.magic),
            root.size,
            root_kind(root.kind)
        );
        if let Some(name) = &root.inferred_name {
            print!(" name={name}");
        }
        if let Some(offset) = root.inferred_offset {
            print!(" target_off=0x{offset:x}");
        }
        if let Some(kind) = root.inferred_hxv4_kind {
            print!(" hxv4_kind={kind}");
        }
        if let Some(id) = root.inferred_hxv4_id {
            print!(" hxv4_id={id}");
        }
        println!();
    }

    for (i, entry) in archive.entries.iter().enumerate() {
        let ordered = ordered_names.and_then(|recovery| recovery.names.get(i));
        if let Some(id) = entry.hxv4_id {
            print!(
                "entry[{i}] hxv4_id={id} fake_name={} real_name={} org={} arc={} segs={}",
                entry.name,
                ordered.map(String::as_str).unwrap_or("<unknown>"),
                entry.original_size,
                entry.archive_size,
                entry.segments.len()
            );
        } else {
            print!(
                "entry[{i}] name={} info_name={} org={} arc={} segs={}",
                ordered
                    .map(String::as_str)
                    .unwrap_or_else(|| entry.preferred_name()),
                entry.name,
                entry.original_size,
                entry.archive_size,
                entry.segments.len()
            );
        }
        if let Some(alt) = &entry.alternate_name {
            print!(" alt_name={alt}");
        }
        if let Some(hash) = entry.alternate_hash {
            print!(" alt_hash=0x{hash:08x}");
        }
        if let Some(adler) = entry.adler {
            print!(" adlr=0x{adler:08x}");
        }
        print!(" info_name_len={}", entry.info_name_length);
        println!();
    }
}

fn extract_raw(archive: &Archive, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for (i, entry) in archive.entries.iter().enumerate() {
        let relative = entry_relative_path(entry, i);
        match archive.reconstruct_entry(i) {
            Ok(data) => {
                let output = out_dir.join(relative);
                write_output(&output, &data)?;
                println!("{i} {} {}", output.display(), data.len());
            }
            Err(err) => {
                let stored = archive.stored_entry_bytes(i).unwrap_or_default();
                let output = out_dir.join("_reconstruct_failed").join(relative);
                if !stored.is_empty() {
                    write_output(&output, &stored)?;
                }
                eprintln!(
                    "entry[{i}] reconstruct-failed name={} stored={} magic={} output={} error={err}",
                    entry.preferred_name(),
                    stored.len(),
                    magic_label(&stored),
                    if stored.is_empty() { "-".to_string() } else { output.display().to_string() }
                );
            }
        }
    }
    Ok(())
}

fn shared_probe(
    archive: &Archive,
    max_period: usize,
    top: usize,
    progress_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_SAMPLE_COUNT: usize = 512;
    const MAX_SAMPLE_BYTES: usize = 256 * 1024 * 1024;

    let ordered_names = recover_ordered_special_names(archive);
    if let Some(names) = &ordered_names {
        println!(
            "shared-probe using ordered special-index names: decoder={} layout={} names={}",
            names.decoder,
            names.layout,
            names.names.len()
        );
    }

    // Shared probing needs only a representative crib-bearing sample set to
    // rank periods. Keep that set strictly bounded; the full archive is never
    // retained as reconstructed Vecs.
    let mut candidates: Vec<(usize, Vec<xp3_brute::Crib>)> = archive
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let cribs =
                shared_cribs_for_name(effective_entry_name(entry, index, ordered_names.as_ref()));
            (!cribs.is_empty()).then_some((index, cribs))
        })
        .collect();
    candidates.sort_by_key(|(index, _)| archive.entries[*index].original_size);

    let reconstruct_progress = Arc::new(Progress::new(
        "reconstruct",
        candidates.len(),
        progress_enabled,
    ));
    let mut owned_samples: Vec<(Vec<u8>, Vec<xp3_brute::Crib>)> = Vec::new();
    let mut sample_bytes = 0usize;
    let mut sample_reconstruction_failures = 0usize;
    for (index, cribs) in candidates {
        if owned_samples.len() >= MAX_SAMPLE_COUNT {
            break;
        }
        let stream = match archive.reconstruct_entry(index) {
            Ok(stream) => stream,
            Err(err) => {
                sample_reconstruction_failures += 1;
                eprintln!(
                    "shared-probe excluding entry[{index}] name={} error={err}",
                    archive.entries[index].preferred_name()
                );
                reconstruct_progress.tick();
                continue;
            }
        };
        reconstruct_progress.tick();
        if stream.len() > MAX_SAMPLE_BYTES
            || sample_bytes.saturating_add(stream.len()) > MAX_SAMPLE_BYTES
        {
            continue;
        }
        sample_bytes += stream.len();
        owned_samples.push((stream, cribs));
    }

    if owned_samples.is_empty() {
        return Err(cli_error(
            "no entries have reliable extension-backed plaintext for shared-key probing",
        )
        .into());
    }

    eprintln!(
        "[memory        ] shared-probe samples={} bytes={} cap_bytes={} archive_wide_stream_cache=off",
        owned_samples.len(),
        sample_bytes,
        MAX_SAMPLE_BYTES,
    );
    let samples: Vec<SharedSample<'_>> = owned_samples
        .iter()
        .map(|(stream, cribs)| SharedSample {
            ciphertext: stream.as_slice(),
            cribs,
        })
        .collect();
    let ranked = rank_shared_periods(&samples, 1, max_period)?;
    let shared_sample_count = samples.len();
    drop(samples);
    drop(owned_samples);

    let adler_total = archive
        .entries
        .iter()
        .filter(|entry| entry.adler.is_some())
        .count();
    println!(
        "shared_samples={} shared_sample_bytes={} adlr_entries={} candidate_periods={} sample_reconstruct_failed={}",
        shared_sample_count,
        sample_bytes,
        adler_total,
        ranked.len(),
        sample_reconstruction_failures
    );

    let top_count = ranked.len().min(top);
    let mut adler_stats = vec![(0usize, 0usize); top_count];
    if top_count != 0 && adler_total != 0 {
        let validation_progress = Arc::new(Progress::new(
            "validate",
            archive.entries.len(),
            progress_enabled,
        ));
        for (index, entry) in archive.entries.iter().enumerate() {
            let Some(expected) = entry.adler else {
                validation_progress.tick();
                continue;
            };
            let mut stream = match archive.reconstruct_entry(index) {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!(
                        "shared-probe validation excluding entry[{index}] name={} error={err}",
                        entry.preferred_name()
                    );
                    validation_progress.tick();
                    continue;
                }
            };
            for (rank, candidate) in ranked.iter().take(top_count).enumerate() {
                if candidate.known_slots != candidate.period || candidate.conflicts != 0 {
                    continue;
                }
                adler_stats[rank].1 += 1;
                apply_complete_period_in_place(&mut stream, candidate);
                if xp3_brute::adler32(&stream) == expected {
                    adler_stats[rank].0 += 1;
                }
                // Repeating XOR is symmetric; restore the reconstructed bytes so
                // all top candidates can be checked without another full buffer.
                apply_complete_period_in_place(&mut stream, candidate);
            }
            validation_progress.tick();
        }
    }

    for (rank, candidate) in ranked.iter().take(top_count).enumerate() {
        let (matches, tested) = adler_stats[rank];
        if tested == 0 {
            println!(
                "rank={} period={} conflicts={} agreements={} known={}/{} implied={} adlr_matches=n/a",
                rank + 1,
                candidate.period,
                candidate.conflicts,
                candidate.agreements,
                candidate.known_slots,
                candidate.period,
                candidate.implied_plaintext_bytes
            );
        } else {
            println!(
                "rank={} period={} conflicts={} agreements={} known={}/{} implied={} adlr_matches={}/{}",
                rank + 1,
                candidate.period,
                candidate.conflicts,
                candidate.agreements,
                candidate.known_slots,
                candidate.period,
                candidate.implied_plaintext_bytes,
                matches,
                tested
            );
        }
    }
    Ok(())
}

fn apply_complete_period_in_place(bytes: &mut [u8], candidate: &PeriodCandidate) {
    debug_assert!(candidate.period != 0);
    debug_assert_eq!(candidate.known_slots, candidate.period);
    for (offset, byte) in bytes.iter_mut().enumerate() {
        let key = candidate.key[offset % candidate.period]
            .expect("complete repeating-XOR candidate contains an unknown key slot");
        *byte ^= key;
    }
}

fn validate_special_xor_as_content_key_streaming(
    archive: &Archive,
    xor: &SpecialXorRecovery,
    ordered_names: Option<&OrderedNameRecovery>,
) -> Result<SpecialContentValidation, LibraryError> {
    let candidate = complete_period_candidate_from_key(&xor.key)?;
    let mut reconstructed_entries = 0usize;
    let mut reconstruction_failures = 0usize;
    let mut adler_tested = 0usize;
    let mut adler_matches = 0usize;
    let mut strong_format_matches = 0usize;
    let mut joint_matches = 0usize;

    for (index, entry) in archive.entries.iter().enumerate() {
        let mut plaintext = match archive.reconstruct_entry(index) {
            Ok(stream) => stream,
            Err(err) => {
                reconstruction_failures += 1;
                log_reconstruction_failure(archive, index, &err);
                continue;
            }
        };
        reconstructed_entries += 1;
        apply_complete_period_in_place(&mut plaintext, &candidate);

        let adler_ok = if let Some(expected) = entry.adler {
            adler_tested += 1;
            let matches = xp3_brute::adler32(&plaintext) == expected;
            if matches {
                adler_matches += 1;
            }
            Some(matches)
        } else {
            None
        };

        let name = effective_entry_name(entry, index, ordered_names);
        let strong = hypotheses_for_name(name)
            .iter()
            .any(|hypothesis| validate_hypothesis(hypothesis.name, &plaintext).is_strong());
        if strong {
            strong_format_matches += 1;
            if adler_ok == Some(true) {
                joint_matches += 1;
            }
        }
        // `plaintext` is dropped here; validation never retains archive-sized
        // reconstructed/decrypted stream vectors.
    }

    let all_adler_match = adler_tested != 0 && adler_matches == adler_tested;
    let (accepted, reason) = if reconstructed_entries == 0 {
        (false, "no reconstructed entries available")
    } else if adler_tested != 0 && adler_matches != adler_tested {
        (
            false,
            "one or more XP3 adlr checks reject the Special-derived key",
        )
    } else if all_adler_match && strong_format_matches != 0 {
        (
            true,
            "all available adlr checks and strong format grammar agree",
        )
    } else if adler_tested == 0 && strong_format_matches >= 2 {
        (
            true,
            "no adlr metadata; at least two strong format grammars agree",
        )
    } else if adler_tested == 0 {
        (
            false,
            "insufficient independent format evidence without adlr metadata",
        )
    } else {
        (
            false,
            "adlr agrees but no strong extension-backed format grammar validates",
        )
    };

    Ok(SpecialContentValidation {
        candidate,
        reconstructed_entries,
        reconstruction_failures,
        adler_tested,
        adler_matches,
        strong_format_matches,
        joint_matches,
        accepted,
        reason,
    })
}

fn find_global_shared_key(
    archive: &Archive,
    max_period: usize,
    ordered_names: Option<&xp3_brute::OrderedNameRecovery>,
) -> Result<Option<xp3_brute::PeriodCandidate>, LibraryError> {
    // Shared-key probing is only an optimization. Keep its evidence pool
    // bounded so a large ordinary XP3 cannot force the whole reconstructed
    // archive to remain resident. Prefer small, extension-backed entries to
    // maximize independent crib coverage per byte of RAM.
    const MAX_SAMPLE_COUNT: usize = 512;
    const MAX_SAMPLE_BYTES: usize = 256 * 1024 * 1024;

    let mut candidates: Vec<(usize, Vec<xp3_brute::Crib>)> = archive
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let cribs = shared_cribs_for_name(effective_entry_name(entry, index, ordered_names));
            (!cribs.is_empty()).then_some((index, cribs))
        })
        .collect();
    candidates.sort_by_key(|(index, _)| archive.entries[*index].original_size);

    let mut owned_samples: Vec<(Vec<u8>, Vec<xp3_brute::Crib>)> = Vec::new();
    let mut sample_bytes = 0usize;
    for (index, cribs) in candidates {
        if owned_samples.len() >= MAX_SAMPLE_COUNT {
            break;
        }
        let stream = match archive.reconstruct_entry(index) {
            Ok(stream) => stream,
            Err(err) => {
                log_reconstruction_failure(archive, index, &err);
                continue;
            }
        };
        if stream.len() > MAX_SAMPLE_BYTES
            || sample_bytes.saturating_add(stream.len()) > MAX_SAMPLE_BYTES
        {
            continue;
        }
        sample_bytes = sample_bytes.saturating_add(stream.len());
        owned_samples.push((stream, cribs));
    }
    if owned_samples.len() < 2 {
        return Ok(None);
    }

    eprintln!(
        "[memory        ] shared-key samples={} bytes={} cap_bytes={} archive_wide_stream_cache=off",
        owned_samples.len(),
        sample_bytes,
        MAX_SAMPLE_BYTES,
    );
    let samples: Vec<SharedSample<'_>> = owned_samples
        .iter()
        .map(|(stream, cribs)| SharedSample {
            ciphertext: stream.as_slice(),
            cribs,
        })
        .collect();
    let ranked = rank_shared_periods(&samples, 1, max_period)?;
    drop(samples);
    drop(owned_samples);

    for candidate in ranked {
        if candidate.conflicts != 0 || candidate.known_slots != candidate.period {
            continue;
        }

        let mut adler_tested = 0usize;
        let mut strong_matches = 0usize;
        let mut rejected = false;
        for (index, entry) in archive.entries.iter().enumerate() {
            let mut plaintext = match archive.reconstruct_entry(index) {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            apply_complete_period_in_place(&mut plaintext, &candidate);

            if let Some(expected) = entry.adler {
                adler_tested += 1;
                if xp3_brute::adler32(&plaintext) != expected {
                    rejected = true;
                    break;
                }
            }

            let name = effective_entry_name(entry, index, ordered_names);
            let hypotheses = hypotheses_for_name(name);
            if !hypotheses.is_empty()
                && hypotheses
                    .iter()
                    .any(|hypothesis| validate_hypothesis(hypothesis.name, &plaintext).is_strong())
            {
                strong_matches += 1;
            }
        }
        if rejected || adler_tested < 2 {
            continue;
        }
        if strong_matches >= 2 {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn effective_entry_name<'a>(
    entry: &'a Entry,
    index: usize,
    ordered_names: Option<&'a xp3_brute::OrderedNameRecovery>,
) -> &'a str {
    ordered_names
        .and_then(|recovery| recovery.names.get(index))
        .map(String::as_str)
        .unwrap_or_else(|| entry.preferred_name())
}

fn print_compute_summary() {
    let t = compute_telemetry();
    println!(
        "compute summary cpu_kernel={} gpu_period_jobs={} gpu_period_candidates={} gpu_slot_jobs={} gpu_slot_candidates={} gpu_adler_jobs={} gpu_adler_candidates={} gpu_time_ms={} cpu_period_jobs={} cpu_slot_jobs={} gpu_busy_fallbacks={} gpu_error_fallbacks={}",
        cpu_backend_label(),
        t.gpu_period_jobs,
        t.gpu_period_candidates,
        t.gpu_slot_jobs,
        t.gpu_slot_candidates,
        t.gpu_adler_jobs,
        t.gpu_adler_candidates,
        t.gpu_time_ms,
        t.cpu_period_jobs,
        t.cpu_slot_jobs,
        t.gpu_busy_fallbacks,
        t.gpu_error_fallbacks,
    );
}

fn probe(
    archive: &Archive,
    max_period: usize,
    top: usize,
    exhaustive_dynamic: bool,
    compute_mode: ComputeMode,
) -> Result<(), Box<dyn std::error::Error>> {
    reset_compute_telemetry();
    let ordered_names = recover_ordered_special_names(archive);
    if let Some(names) = &ordered_names {
        eprintln!(
            "special-index ordered names active: root={} decoder={} layout={} names={} confidence={}",
            names.root_index, names.decoder, names.layout, names.names.len(), names.confidence
        );
    }
    let config = RecoveryConfig {
        min_period: 1,
        max_period,
        top_periods_per_hypothesis: top,
        exhaustive_dynamic_periods: exhaustive_dynamic,
        max_refinement_rounds: 12,
        compute_mode,
        ..RecoveryConfig::default()
    };

    let results: Vec<(
        usize,
        String,
        std::result::Result<xp3_brute::RecoveryReport, String>,
    )> = (0..archive.entries.len())
        .into_par_iter()
        .map(|i| {
            let entry = &archive.entries[i];
            let resolved_name = effective_entry_name(entry, i, ordered_names.as_ref());
            let name = resolved_name.to_string();
            let hypotheses = hypotheses_for_name(resolved_name);
            let result = match archive.reconstruct_entry(i) {
                Ok(data) => {
                    if hypotheses.is_empty() {
                        Ok(xp3_brute::RecoveryReport::default())
                    } else {
                        recover_stream(&data, &hypotheses, &config).map_err(|e| e.to_string())
                    }
                }
                Err(err) => Err(err.to_string()),
            };
            (i, name, result)
        })
        .collect();

    for (i, name, result) in results {
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                eprintln!("entry[{i}] {name}: reconstruct-failed error={error}");
                continue;
            }
        };
        println!("entry[{i}] {name}:");
        for candidate in report.candidates.iter().take(top) {
            let p = &candidate.period;
            if let Some(brute) = &candidate.brute {
                let combinations = brute
                    .combinations
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "overflow".to_string());
                println!(
                    "  format={} period={} conflicts={} agreements={} known={}/{} implied={} refine_rounds={} ambiguous={} entropy_bits={:.2} combinations={} brute={} mitm={} hist_reduced={} hist_singleton={}",
                    candidate.hypothesis,
                    p.period,
                    p.conflicts,
                    p.agreements,
                    p.known_slots,
                    p.period,
                    p.implied_plaintext_bytes,
                    candidate.refinement_rounds,
                    brute.ambiguous_slots,
                    brute.entropy_bits,
                    combinations,
                    brute.direct_feasible,
                    brute.mitm_feasible,
                    brute.histogram_reduced_slots,
                    brute.histogram_singleton_slots
                );
            } else {
                println!(
                    "  format={} period={} conflicts={} agreements={} known={}/{} implied={} refine_rounds={} brute=n/a",
                    candidate.hypothesis,
                    p.period,
                    p.conflicts,
                    p.agreements,
                    p.known_slots,
                    p.period,
                    p.implied_plaintext_bytes,
                    candidate.refinement_rounds
                );
            }
        }
    }
    print_compute_summary();
    Ok(())
}

#[derive(Debug)]
enum UnpackState {
    PlainRaw {
        format: Option<String>,
    },
    Recovered {
        format: String,
        period: usize,
        key: Vec<Option<u8>>,
        brute_used: bool,
        mitm: bool,
        gpu: bool,
        gpu_adapter: Option<String>,
        combinations: u128,
    },
    NativeCxdecRecovered {
        format: String,
        parameters: String,
        hash: u32,
    },
    X86FilterRecovered {
        format: String,
        module: String,
        callback: u32,
        source: String,
        hash: u32,
    },
    NativeHxRecovered {
        format: String,
        entry_key: u64,
        local_flag: u16,
        split: u64,
        left_xor: u8,
        right_xor: u8,
        corrections: usize,
    },
    HxRecovered {
        format: String,
        split: usize,
        left_xor: u8,
        right_xor: u8,
        corrections: usize,
        gpu: bool,
    },
    NativeHxMismatch {
        entry_key: u64,
        local_flag: u16,
        size: usize,
        split: u64,
        left_drip: u64,
        right_drip: u64,
        left_xor: u8,
        right_xor: u8,
        prefix_xor: [u8; 16],
        expected_adler: u32,
        actual_adler: u32,
    },
    /// Synthetic protected-archive warning node.  It is archive metadata/noise,
    /// not an extractable resource and must not be counted as unresolved.
    IgnoredProtectedDummy,
    Unresolved,
    ReconstructionFailed {
        error: String,
    },
}

#[derive(Debug)]
struct UnpackEntry {
    index: usize,
    name: String,
    hxv4_id: Option<u64>,
    bytes: Vec<u8>,
    /// Hash of verified plaintext before user-facing text normalization.
    storage_plaintext_sha256: Option<String>,
    text_transform: Option<KirikiriTextTransformMeta>,
    state: UnpackState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GlobalKeySource {
    SpecialIndex,
    SharedProbe,
}

impl GlobalKeySource {
    fn label(self) -> &'static str {
        match self {
            Self::SpecialIndex => "special-index",
            Self::SharedProbe => "shared-probe",
        }
    }
}

struct GlobalKeySelection {
    source: GlobalKeySource,
    candidate: PeriodCandidate,
}

fn should_try_generic_shared_key(
    is_hxv4: bool,
    special_content_key_accepted: bool,
    plan_allows_shared: bool,
) -> bool {
    plan_allows_shared && !is_hxv4 && !special_content_key_accepted
}

/// Enforce Special-index recovery as a hard precondition for content recovery.
///
/// A recognized Special descriptor is metadata needed to interpret the archive;
/// continuing with synthetic/fake names after failing to decode it makes later
/// format- and name-dependent recovery unsound.  HXV4 is stricter still: the
/// authenticated XChaCha20-Poly1305 table must have passed AEAD verification,
/// decompression, and native Hx-object parsing before any entry reconstruction
/// or per-entry filter solving is allowed to start.
fn require_special_before_content_recovery(
    is_hxv4: bool,
    has_special: bool,
    ordinary_special_decoded: bool,
    hxv4_special_decoded: bool,
    hxv4_nonce_slot: usize,
) -> Result<(), io::Error> {
    if is_hxv4 {
        if !has_special {
            return Err(cli_error(
                "HXV4 archive has no recognized Special-index descriptor; refusing to start entry recovery without the native index",
            ));
        }
        if !hxv4_special_decoded {
            return Err(cli_error(format!(
                "HXV4 Special index is locked: no authenticated/parsed XChaCha20-Poly1305 result is available (descriptor selects nonce_slot={hxv4_nonce_slot}); refusing to reconstruct or solve entries before Special recovery"
            )));
        }
        return Ok(());
    }

    if has_special && !ordinary_special_decoded {
        return Err(cli_error(
            "Special-index descriptor was found, but no decoder/key candidate passed strict validation; refusing to continue with data-side recovery before Special recovery",
        ));
    }

    Ok(())
}

fn hxv4_names_complete(required_names: usize, resolved_names: usize) -> bool {
    required_names == resolved_names
}

fn cleanup_legacy_unpack_artifacts(out_dir: &Path) -> io::Result<()> {
    // Older builds polluted the extraction root with diagnostic/raw sidecars.
    // These names are tool-reserved; remove only those known artifacts so a
    // reused output directory converges to the clean final-file layout.
    for dir in [
        "_hxv4",
        "_unresolved_raw",
        "_reconstruct_failed",
        "_hxv4_hash",
        "_hxv4_id",
    ] {
        let path = out_dir.join(dir);
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    for file in [
        "_xp3brute_report.tsv",
        "_special_index_decoded.bin",
        "_special_index_xor_key.txt",
        xp3_meta::XP3_META_FILE,
    ] {
        let path = out_dir.join(file);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn build_preserved_file_meta(archive: &Archive) -> Vec<PreservedFileMeta> {
    const TAG_SEGM: u32 = 0x6d67_6573;
    let mut out = Vec::new();
    for (root_index, root) in archive.root_chunks.iter().enumerate() {
        if !matches!(root.kind, RootKind::ProtectedFile) {
            continue;
        }
        let Some(block) = archive.index_blocks.get(root.index_block) else {
            continue;
        };
        let start = root.index_offset;
        let Some(body_start) = start.checked_add(12) else {
            continue;
        };
        let Ok(body_len) = usize::try_from(root.size) else {
            continue;
        };
        let Some(body_end) = body_start.checked_add(body_len) else {
            continue;
        };
        let Some(body) = block.decoded.get(body_start..body_end) else {
            continue;
        };
        let mut position = 0usize;
        let mut segments = Vec::new();
        let mut saw_segm = false;
        while position + 12 <= body.len() {
            let tag = u32::from_le_bytes(body[position..position + 4].try_into().unwrap());
            let len64 = u64::from_le_bytes(body[position + 4..position + 12].try_into().unwrap());
            let Ok(len) = usize::try_from(len64) else {
                break;
            };
            let data_start = position + 12;
            let Some(data_end) = data_start.checked_add(len) else {
                break;
            };
            if data_end > body.len() {
                break;
            }
            if tag == TAG_SEGM && len % 28 == 0 {
                saw_segm = true;
                for raw in body[data_start..data_end].chunks_exact(28) {
                    let flags = u32::from_le_bytes(raw[0..4].try_into().unwrap());
                    let archive_offset = u64::from_le_bytes(raw[4..12].try_into().unwrap());
                    let original_size = u64::from_le_bytes(raw[12..20].try_into().unwrap());
                    let archive_size = u64::from_le_bytes(raw[20..28].try_into().unwrap());
                    let Ok(size) = usize::try_from(archive_size) else {
                        continue;
                    };
                    match archive.physical_range(archive_offset, size) {
                        Ok(stored) => segments.push(PreservedSegmentMeta {
                            flags,
                            archive_offset,
                            original_size,
                            archive_size,
                            stored_sha256: xp3_meta::sha256_hex(&stored),
                            stored_base64: xp3_meta::b64(&stored),
                        }),
                        Err(err) => eprintln!(
                            "[xp3-meta      ] protected root={} segment offset={} size={} could not be retained: {}",
                            root_index, archive_offset, archive_size, err
                        ),
                    }
                }
            }
            position = data_end;
        }
        if saw_segm {
            out.push(PreservedFileMeta {
                root_chunk_index: root_index,
                kind: root_kind(root.kind).to_string(),
                segments,
            });
        }
    }
    out
}

fn retained_index_object(archive: &Archive, block: &xp3_brute::IndexBlock) -> Option<Vec<u8>> {
    let header = match block.flags & 0x07 {
        0 => 1u64 + 8,
        1 => 1u64 + 16,
        _ => return None,
    };
    let total = header
        .checked_add(block.stored_size)?
        .checked_add(if block.flags & 0x80 != 0 { 8 } else { 0 })?;
    let total = usize::try_from(total).ok()?;
    archive.physical_range(block.physical_offset, total).ok()
}

fn build_xp3_meta(
    archive: &Archive,
    out_dir: &Path,
    decode_options: &UnpackDecodeOptions,
) -> Xp3Meta {
    let source_file = archive
        .path
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("archive.xp3")
        .to_string();
    let entries = archive
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| EntryMeta {
            index,
            original: EntryOriginalMeta {
                root_chunk_index: entry.root_chunk_index,
                flags: entry.flags,
                original_size: entry.original_size,
                archive_size: entry.archive_size,
                info_name_length: entry.info_name_length,
                info_name: entry.name.clone(),
                alternate_name: entry.alternate_name.clone(),
                alternate_hash: entry.alternate_hash,
                hxv4_id: entry.hxv4_id,
                adler32_hex: entry.adler.map(|value| format!("{value:08x}")),
                original_filter_hash_hex: entry.adler.map(|value| format!("{value:08x}")),
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
                logical_path: None,
                output_path: None,
                hxv4_special_record_index: None,
                path_hash_hex: None,
                name_hash_hex: None,
            },
            recovery: EntryRecoveryMeta::default(),
            transforms: Vec::new(),
        })
        .collect();

    Xp3Meta {
        schema: XP3_META_SCHEMA.to_string(),
        producer: "xp3-brute".to_string(),
        producer_version: env!("CARGO_PKG_VERSION").to_string(),
        archive: ArchiveMeta {
            source_file,
            source_path: archive.path.as_ref().map(|path| path.display().to_string()),
            family: if archive.is_hxv4() {
                "hxv4"
            } else {
                "ordinary"
            }
            .to_string(),
            xp3_offset: archive.xp3_offset,
            physical_size: archive.physical_size(),
            entry_count: archive.entries.len(),
        },
        unpack: UnpackMeta {
            tjs: Some(decode_options.tjs.label().to_string()),
            tlg: decode_options.tlg.label().to_string(),
            psb: decode_options.psb.label().to_string(),
            pbd: decode_options.pbd.label().to_string(),
            amv: Some(decode_options.amv.label().to_string()),
            output_root: out_dir.display().to_string(),
        },
        policies: Default::default(),
        index_blocks: archive
            .index_blocks
            .iter()
            .enumerate()
            .map(|(index, block)| {
                let encoded = retained_index_object(archive, block);
                IndexBlockMeta {
                    index,
                    physical_offset: block.physical_offset,
                    flags: block.flags,
                    stored_size: block.stored_size,
                    original_size: block.original_size,
                    decoded_base64: xp3_meta::b64(&block.decoded),
                    decoded_sha256: xp3_meta::sha256_hex(&block.decoded),
                    encoded_base64: encoded.as_ref().map(|bytes| xp3_meta::b64(bytes)),
                    encoded_sha256: encoded.as_ref().map(|bytes| xp3_meta::sha256_hex(bytes)),
                }
            })
            .collect(),
        root_chunks: archive
            .root_chunks
            .iter()
            .enumerate()
            .map(|(index, root)| RootChunkMeta {
                index,
                magic_hex: format!("0x{:08x}", root.magic),
                size: root.size,
                index_block: root.index_block,
                index_offset: root.index_offset,
                kind: root_kind(root.kind).to_string(),
                inferred_name: root.inferred_name.clone(),
                inferred_hash: root.inferred_hash,
                inferred_offset: root.inferred_offset,
                inferred_original_size: root.inferred_original_size,
                inferred_archive_size: root.inferred_archive_size,
                inferred_hxv4_kind: root.inferred_hxv4_kind,
                inferred_hxv4_id: root.inferred_hxv4_id,
            })
            .collect(),
        special: Vec::new(),
        preserved_files: build_preserved_file_meta(archive),
        hxv4: None,
        keys: Vec::new(),
        x86_filter_modules: Vec::new(),
        entries,
    }
}

fn retain_x86_filter_module(meta: &mut Xp3Meta, module: &Path) -> Result<String, LibraryError> {
    let bytes = fs::read(module)?;
    let sha256 = xp3_meta::sha256_hex(&bytes);
    if !meta
        .x86_filter_modules
        .iter()
        .any(|existing| existing.sha256.eq_ignore_ascii_case(&sha256))
    {
        meta.x86_filter_modules.push(X86FilterModuleMeta {
            sha256: sha256.clone(),
            file_name: module
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "filter.tpm".to_string()),
            source_path: module
                .canonicalize()
                .ok()
                .map(|path| path.display().to_string()),
            pe32_base64: xp3_meta::b64(&bytes),
            guest_profile: "ja-JP-windows".to_string(),
            lcid_hex: "0x0411".to_string(),
            ansi_code_page: 932,
        });
    }
    Ok(sha256)
}

fn populate_special_meta(
    meta: &mut Xp3Meta,
    archive: &Archive,
    ordered_names: Option<&OrderedNameRecovery>,
) {
    meta.special.clear();
    for (root_index, root) in archive.root_chunks.iter().enumerate() {
        if !matches!(
            root.kind,
            RootKind::SpecialIndexV1
                | RootKind::SpecialIndexV2
                | RootKind::SpecialIndexV3
                | RootKind::SpecialIndexGeneric
                | RootKind::Hxv4SpecialIndex
        ) {
            continue;
        }
        let Some(blob) = archive.special_index_bytes_for_root(root_index) else {
            continue;
        };
        let decoded = ordered_names
            .filter(|recovery| recovery.root_index == root_index)
            .map(|recovery| OrdinarySpecialDecodedMeta {
                decoder: recovery.decoder.clone(),
                layout: recovery.layout.clone(),
                confidence: recovery.confidence,
                decoded_size: recovery.decoded_size,
                decoded_blob_base64: recovery.decoded.as_deref().map(xp3_meta::b64),
                xor: recovery
                    .xor
                    .as_ref()
                    .map(|xor| xp3_meta::complete_repeating_xor_key(&xor.key)),
                records: recovery
                    .names
                    .iter()
                    .enumerate()
                    .filter_map(|(record_index, recovered_name)| {
                        let entry = archive.entries.get(record_index)?;
                        let verified_m2 =
                            recovery.layout.contains("M2") || recovery.layout.contains("Yuzu");
                        Some(OrdinarySpecialRecordMeta {
                            record_index,
                            physical_entry_index: record_index,
                            recovered_name: recovered_name.clone(),
                            info_name_length: entry.info_name_length,
                            special_record_hash_hex: if verified_m2 {
                                entry.adler.map(|hash| format!("{hash:08x}"))
                            } else {
                                None
                            },
                            xp3_adler32_hex: entry.adler.map(|hash| format!("{hash:08x}")),
                        })
                    })
                    .collect(),
            });
        meta.special.push(SpecialChunkMeta {
            root_index,
            kind: root_kind(root.kind).to_string(),
            stored_blob_base64: xp3_meta::b64(blob),
            stored_blob_sha256: xp3_meta::sha256_hex(blob),
            decoded,
        });
        if let Some(recovery) = ordered_names.filter(|recovery| recovery.root_index == root_index) {
            if let Some(xor) = recovery.xor.as_ref() {
                meta.keys.push(KeyMeta {
                    kind: "special-index-repeating-xor".to_string(),
                    source: recovery.decoder.clone(),
                    entry_index: None,
                    logical_path: None,
                    repeating_xor: Some(xp3_meta::complete_repeating_xor_key(&xor.key)),
                    u32_hex: None,
                    bytes_hex: None,
                });
            }
        }
    }
}

fn boundary_meta(boundary: xp3_brute::Hxv4NativeBoundary) -> Hxv4BoundaryMeta {
    Hxv4BoundaryMeta {
        position0: boundary.position0,
        position1: boundary.position1,
        xor_byte_hex: format!("{:02x}", boundary.xor_byte),
        correction0_hex: format!("{:02x}", boundary.correction0),
        correction1_hex: format!("{:02x}", boundary.correction1),
    }
}

fn populate_hxv4_meta(
    meta: &mut Xp3Meta,
    archive: &Archive,
    index: &Hxv4Index,
    explicit_keys: Option<&Hxv4IndexKeys>,
    exe_recovery: Option<&Hxv4ExeKeyRecovery>,
    native_filter: Option<&Hxv4NativeFilterManager>,
) {
    let Some(descriptor) = archive.hxv4.as_ref() else {
        return;
    };
    let physical_by_id: HashMap<u64, usize> = archive
        .entries
        .iter()
        .enumerate()
        .filter_map(|(entry_index, entry)| entry.hxv4_id.map(|id| (id, entry_index)))
        .collect();

    let aead = if let Some(recovery) = exe_recovery {
        Some(Hxv4AeadMeta {
            source: "exe-static".to_string(),
            key_hex: recovery.key_hex(),
            nonce_hex: recovery.nonce_hex(),
            nonce_slot: recovery.nonce_slot,
            nonce0_hex: Some(recovery.nonce0_hex()),
            nonce1_hex: Some(recovery.nonce1_hex()),
            archive_seed_hex: Some(recovery.archive_seed_hex()),
            archive_unique_key: Some(recovery.archive_unique_key.clone()),
            bootstrap_prefix: Some(recovery.bootstrap_prefix.clone()),
            exe_file: Some(recovery.exe.display().to_string()),
            pe_offset: Some(recovery.pe_offset),
        })
    } else {
        explicit_keys.map(|keys| Hxv4AeadMeta {
            source: "explicit".to_string(),
            key_hex: xp3_meta::hex_lower(&keys.key),
            nonce_hex: xp3_meta::hex_lower(&keys.nonce),
            nonce_slot: hxv4_special_nonce_slot(descriptor.kind),
            nonce0_hex: None,
            nonce1_hex: None,
            archive_seed_hex: None,
            archive_unique_key: None,
            bootstrap_prefix: None,
            exe_file: None,
            pe_offset: None,
        })
    };
    let filter_manager = native_filter.map(|manager| Hxv4FilterManagerMeta {
        mask: manager.mask(),
        offset: manager.offset(),
        control_mode: manager.control_mode(),
        random_type: manager.random_type(),
        random_type_label: manager.random_type_label().to_string(),
        holder_low_hex: format!("0x{:08x}", manager.holder_low()),
        holder_high_hex: format!("0x{:08x}", manager.holder_high()),
    });

    let mut records = Vec::with_capacity(index.entries.len());
    for record in &index.entries {
        let physical_entry_index = physical_by_id.get(&record.id).copied();
        if let Some(entry_index) = physical_entry_index {
            if let Some(entry_meta) = meta.entries.get_mut(entry_index) {
                entry_meta.identity.hxv4_special_record_index = Some(record.record_index);
                entry_meta.identity.path_hash_hex = Some(record.path_hash_hex());
                entry_meta.identity.name_hash_hex = Some(record.name_hash_hex());
                entry_meta.identity.logical_path = if record.path.is_some() && record.name.is_some()
                {
                    Some(record.display_path())
                } else {
                    record.name.clone()
                };
            }
        }
        let output_path = physical_entry_index
            .and_then(|i| meta.entries.get(i))
            .and_then(|entry| entry.identity.output_path.clone());
        let filter_state = native_filter.map(|manager| {
            let state = manager.state_for_entry(record.entry_key, record.filter_flag);
            Hxv4FilterStateMeta {
                open_flag: state.open_flag,
                split: state.split,
                prefix_xor_hex: xp3_meta::hex_lower(&state.prefix_xor),
                left_drip_hex: format!("0x{:016x}", state.left_drip),
                right_drip_hex: format!("0x{:016x}", state.right_drip),
                left: boundary_meta(state.left),
                right: boundary_meta(state.right),
            }
        });
        records.push(Hxv4RecordMeta {
            record_index: record.record_index,
            packed_hex: format!("0x{:016x}", record.packed),
            archive_slot: record.archive_slot,
            local_flag_hex: format!("0x{:04x}", record.filter_flag),
            synthetic_id: record.id,
            entry_key_hex: format!("0x{:016x}", record.entry_key),
            path_hash_hex: record.path_hash_hex(),
            name_hash_hex: record.name_hash_hex(),
            resolved_path: record.path.clone(),
            resolved_name: record.name.clone(),
            physical_entry_index,
            output_path,
            filter_state,
        });
    }

    if let Some(aead_meta) = aead.as_ref() {
        let key_exists = meta.keys.iter().any(|entry| {
            entry.kind == "hxv4-special-aead-key"
                && entry.bytes_hex.as_deref() == Some(aead_meta.key_hex.as_str())
        });
        if !key_exists {
            meta.keys.push(KeyMeta {
                kind: "hxv4-special-aead-key".to_string(),
                source: aead_meta.source.clone(),
                entry_index: None,
                logical_path: None,
                repeating_xor: None,
                u32_hex: None,
                bytes_hex: Some(aead_meta.key_hex.clone()),
            });
        }
        let nonce_exists = meta.keys.iter().any(|entry| {
            entry.kind == "hxv4-special-aead-nonce"
                && entry.bytes_hex.as_deref() == Some(aead_meta.nonce_hex.as_str())
        });
        if !nonce_exists {
            meta.keys.push(KeyMeta {
                kind: "hxv4-special-aead-nonce".to_string(),
                source: format!("{};slot={}", aead_meta.source, aead_meta.nonce_slot),
                entry_index: None,
                logical_path: None,
                repeating_xor: None,
                u32_hex: None,
                bytes_hex: Some(aead_meta.nonce_hex.clone()),
            });
        }
    }

    meta.hxv4 = Some(Hxv4Meta {
        descriptor: Hxv4DescriptorMeta {
            offset: descriptor.offset,
            stored_size: descriptor.stored_size,
            kind: descriptor.kind,
            root_chunk_index: descriptor.root_chunk_index,
        },
        decompressed_special_size: index.decompressed_size,
        aead,
        filter_manager,
        records,
    });
}

fn sync_hxv4_output_paths(meta: &mut Xp3Meta) {
    let Some(hxv4) = meta.hxv4.as_mut() else {
        return;
    };
    for record in &mut hxv4.records {
        if let Some(index) = record.physical_entry_index {
            record.output_path = meta
                .entries
                .get(index)
                .and_then(|entry| entry.identity.output_path.clone());
        }
    }
}

fn push_transform_unique(entry: &mut EntryMeta, transform: TransformMeta) {
    let signature = serde_json::to_string(&transform).ok();
    let duplicate = signature.as_ref().is_some_and(|signature| {
        entry.transforms.iter().any(|existing| {
            serde_json::to_string(existing).ok().as_deref() == Some(signature.as_str())
        })
    });
    if !duplicate {
        entry.transforms.push(transform);
    }
}

fn push_key_unique(meta: &mut Xp3Meta, key: KeyMeta) {
    let signature = serde_json::to_string(&key).ok();
    let duplicate = signature.as_ref().is_some_and(|signature| {
        meta.keys.iter().any(|existing| {
            serde_json::to_string(existing).ok().as_deref() == Some(signature.as_str())
        })
    });
    if !duplicate {
        meta.keys.push(key);
    }
}

fn apply_asset_result_to_meta(
    meta: &mut Xp3Meta,
    entry_index: usize,
    logical_path: &str,
    result: &AssetWriteResult,
    out_dir: &Path,
) {
    if let Some(entry) = meta.entries.get_mut(entry_index) {
        entry.identity.logical_path = Some(logical_path.replace('\\', "/"));
        entry.identity.output_path = Some(xp3_meta::relative_path(out_dir, &result.output));
        for transform in result.transforms.iter().cloned() {
            push_transform_unique(entry, transform);
        }
    }
    for mut key in result.keys.iter().cloned() {
        key.entry_index = Some(entry_index);
        if key.logical_path.is_none() {
            key.logical_path = Some(logical_path.replace('\\', "/"));
        }
        push_key_unique(meta, key);
    }
}

fn add_global_emote_keys(meta: &mut Xp3Meta) {
    for key in xp3_brute::cached_emote_keys() {
        let value = format!("0x{key:08x}");
        if meta.keys.iter().any(|entry| {
            entry.kind == "emote-psb-key-global" && entry.u32_hex.as_deref() == Some(value.as_str())
        }) {
            continue;
        }
        meta.keys.push(KeyMeta {
            kind: "emote-psb-key-global".to_string(),
            source: "process-global-cache".to_string(),
            entry_index: None,
            logical_path: None,
            repeating_xor: None,
            u32_hex: Some(value),
            bytes_hex: None,
        });
    }
}

fn write_xp3_meta(out_dir: &Path, meta: &mut Xp3Meta) -> Result<(), Box<dyn std::error::Error>> {
    add_global_emote_keys(meta);
    sync_hxv4_output_paths(meta);
    let path = xp3_meta::write_manifest(out_dir, meta)?;
    eprintln!(
        "[xp3-meta      ] wrote {} entries={} keys={} special={} schema={}",
        path.display(),
        meta.entries.len(),
        meta.keys.len(),
        meta.special.len(),
        meta.schema
    );
    Ok(())
}


#[derive(Debug)]
struct CxdecParamValidation {
    adler_tested: usize,
    adler_matches: usize,
    strong_formats: usize,
}

fn cxdec_candidate_has_enough_evidence(validation: &CxdecParamValidation) -> bool {
    (validation.adler_matches >= 2)
        || (validation.adler_matches >= 1 && validation.strong_formats >= 1)
        || (validation.adler_tested == 0 && validation.strong_formats >= 2)
}

fn cxdec_special_name_map_active(ordered_names: Option<&OrderedNameRecovery>) -> bool {
    ordered_names.is_some_and(|recovery| recovery.layout == "cxdec-structural-token-hash")
}

fn cxdec_effective_entry_name<'a>(
    entry: &'a Entry,
    index: usize,
    ordered_names: Option<&'a OrderedNameRecovery>,
) -> &'a str {
    ordered_names
        .and_then(|recovery| recovery.names.get(index))
        .map(String::as_str)
        .unwrap_or_else(|| entry.preferred_name())
}

fn looks_like_md5_lookup_token(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn cxdec_entry_is_real_resource(
    entry: &Entry,
    index: usize,
    ordered_names: Option<&OrderedNameRecovery>,
) -> bool {
    let name = cxdec_effective_entry_name(entry, index, ordered_names);
    if is_protected_dummy_name(name) {
        return false;
    }
    if entry.name == "$" {
        return false;
    }

    if cxdec_special_name_map_active(ordered_names) {
        // This validated layout maps ordinary 32-hex lookup tokens to Special
        // records.  A visible non-token that survived unchanged was not backed
        // by the Special map and must not be used as content-cipher evidence.
        return looks_like_md5_lookup_token(&entry.name);
    }
    true
}

fn cxdec_effective_original_size(entry: &Entry, protected_index: bool) -> u64 {
    if !protected_index {
        return entry.original_size;
    }
    entry
        .segments
        .iter()
        .fold(0u64, |total, segment| total.saturating_add(segment.original_size))
}

fn reconstruct_cxdec_entry(
    archive: &Archive,
    index: usize,
    protected_index: bool,
) -> Result<Vec<u8>, LibraryError> {
    if protected_index {
        archive.reconstruct_entry_segments(index)
    } else {
        archive.reconstruct_entry(index)
    }
}

fn validate_cxdec_params_on_entries(
    archive: &Archive,
    engine: &CxdecEngine,
    ordered_names: Option<&OrderedNameRecovery>,
    indices: impl IntoIterator<Item = usize>,
) -> Result<Option<CxdecParamValidation>, LibraryError> {
    let mut validation = CxdecParamValidation {
        adler_tested: 0,
        adler_matches: 0,
        strong_formats: 0,
    };

    let protected_index = cxdec_special_name_map_active(ordered_names);
    for index in indices {
        let entry = &archive.entries[index];
        if !cxdec_entry_is_real_resource(entry, index, ordered_names) {
            continue;
        }
        let Some(file_hash) = entry.adler.or(entry.alternate_hash) else {
            continue;
        };
        let mut raw = match reconstruct_cxdec_entry(archive, index, protected_index) {
            Ok(value) => value,
            Err(_) => continue,
        };

        // Plain/unfiltered entries are not evidence for or against a CXDEC
        // parameter set; skip them before applying the candidate transform.
        if let Some(expected) = entry.adler {
            if xp3_brute::adler32(&raw) == expected {
                continue;
            }
        } else {
            let name = effective_entry_name(entry, index, ordered_names);
            let plain_is_strong = hypotheses_for_name(name)
                .iter()
                .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
                || strong_builtin_format(&raw).is_some();
            if plain_is_strong {
                continue;
            }
        }

        engine.apply(0, file_hash, &mut raw)?;

        if let Some(expected) = entry.adler {
            validation.adler_tested += 1;
            if xp3_brute::adler32(&raw) != expected {
                // One original XP3 adlr mismatch is enough to reject this
                // parameter combination immediately.
                return Ok(None);
            }
            validation.adler_matches += 1;
        }

        let name = effective_entry_name(entry, index, ordered_names);
        let strong = hypotheses_for_name(name)
            .iter()
            .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
            || strong_builtin_format(&raw).is_some();
        if strong {
            validation.strong_formats += 1;
        }
    }

    Ok(Some(validation))
}


#[derive(Clone, Debug)]
struct X86FilterValidation {
    adler_tested: usize,
    adler_matches: usize,
    strong_formats: usize,
}

#[derive(Clone, Debug)]
struct ValidatedX86Filter {
    module: PathBuf,
    callback_va: u32,
    callback_source: String,
    validation: X86FilterValidation,
    /// True when registration provenance was unavailable and the callback was
    /// selected solely by sandboxed execution plus archive-level validation.
    forced_callback: bool,
}

fn x86_filter_candidate_has_enough_evidence(validation: &X86FilterValidation) -> bool {
    (validation.adler_matches >= 2)
        || (validation.adler_matches >= 1 && validation.strong_formats >= 1)
        || (validation.adler_tested == 0 && validation.strong_formats >= 2)
}

fn x86_filter_candidate_survives_single_entry(validation: &X86FilterValidation) -> bool {
    if validation.adler_tested != 0 {
        validation.adler_matches == validation.adler_tested
    } else {
        validation.strong_formats >= 1
    }
}

fn x86_filter_hypothesis_priority(source: &str) -> u8 {
    match source {
        // A callback address written to engine/plugin state is much more
        // meaningful than a function body that merely resembles the ABI.
        "abi-v2link-hypothesis" => 0,
        "abi-global-store-hypothesis" => 1,
        "abi-callsite-hypothesis" => 2,
        "abi-body-scan-hypothesis" => 3,
        _ => 4,
    }
}

fn content_filter_validation_samples(
    archive: &Archive,
    ordered_names: Option<&OrderedNameRecovery>,
) -> Result<(Vec<usize>, u64), LibraryError> {
    let protected_index = cxdec_special_name_map_active(ordered_names);
    let mut candidates: Vec<usize> = (0..archive.entries.len())
        .filter(|&index| {
            cxdec_entry_is_real_resource(&archive.entries[index], index, ordered_names)
        })
        .collect();
    candidates.sort_by_key(|&index| {
        let entry = &archive.entries[index];
        (
            entry.adler.is_none(),
            cxdec_effective_original_size(entry, protected_index),
        )
    });

    const SAMPLE_COUNT: usize = 32;
    const SAMPLE_BYTES: u64 = 64 * 1024 * 1024;
    let mut selected = Vec::new();
    let mut sample_bytes = 0u64;
    for index in candidates {
        if selected.len() >= SAMPLE_COUNT {
            break;
        }
        let entry = &archive.entries[index];
        if entry.adler.or(entry.alternate_hash).is_none() {
            continue;
        }
        let size = cxdec_effective_original_size(entry, protected_index);
        if size > SAMPLE_BYTES || sample_bytes.saturating_add(size) > SAMPLE_BYTES {
            continue;
        }
        let raw = match reconstruct_cxdec_entry(archive, index, protected_index) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let needs_filter = if let Some(expected) = entry.adler {
            xp3_brute::adler32(&raw) != expected
        } else {
            let name = effective_entry_name(entry, index, ordered_names);
            !hypotheses_for_name(name)
                .iter()
                .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
                && strong_builtin_format(&raw).is_none()
        };
        if !needs_filter {
            continue;
        }
        selected.push(index);
        sample_bytes = sample_bytes.saturating_add(size);
    }
    Ok((selected, sample_bytes))
}

fn validate_x86_filter_module_on_entries(
    archive: &Archive,
    module: &Path,
    ordered_names: Option<&OrderedNameRecovery>,
    forced_callback: Option<(u32, &str)>,
    indices: impl IntoIterator<Item = usize>,
) -> Result<Option<(X86FilterValidation, u32, String)>, LibraryError> {
    let mut runtime = if let Some((callback_va, callback_source)) = forced_callback {
        X86Xp3FilterRuntime::open_with_callback(
            module,
            callback_va,
            callback_source.to_string(),
            false,
        )?
    } else {
        X86Xp3FilterRuntime::open(module, false)?
    };
    let callback_va = runtime.callback_va();
    let callback_source = runtime.callback_source().to_string();
    let protected_index = cxdec_special_name_map_active(ordered_names);
    let mut validation = X86FilterValidation {
        adler_tested: 0,
        adler_matches: 0,
        strong_formats: 0,
    };

    for index in indices {
        let entry = &archive.entries[index];
        if !cxdec_entry_is_real_resource(entry, index, ordered_names) {
            continue;
        }
        let Some(file_hash) = entry.adler.or(entry.alternate_hash) else {
            continue;
        };
        let mut raw = match reconstruct_cxdec_entry(archive, index, protected_index) {
            Ok(value) => value,
            Err(_) => continue,
        };

        // Plain resources are neutral evidence: a title may leave some entries
        // outside its extraction filter. Only resources that demonstrably still
        // need a transform are used to validate an emulated callback.
        if let Some(expected) = entry.adler {
            if xp3_brute::adler32(&raw) == expected {
                continue;
            }
        } else {
            let name = effective_entry_name(entry, index, ordered_names);
            let plain_is_strong = hypotheses_for_name(name)
                .iter()
                .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
                || strong_builtin_format(&raw).is_some();
            if plain_is_strong {
                continue;
            }
        }

        runtime.apply(0, file_hash, &mut raw)?;
        if let Some(expected) = entry.adler {
            validation.adler_tested += 1;
            if xp3_brute::adler32(&raw) != expected {
                return Ok(None);
            }
            validation.adler_matches += 1;
        }

        let name = effective_entry_name(entry, index, ordered_names);
        let strong = hypotheses_for_name(name)
            .iter()
            .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
            || strong_builtin_format(&raw).is_some();
        if strong {
            validation.strong_formats += 1;
        }
    }

    Ok(Some((validation, callback_va, callback_source)))
}

fn select_validated_x86_filter(
    archive: &Archive,
    scan_target: &Path,
    ordered_names: Option<&OrderedNameRecovery>,
) -> Result<Option<ValidatedX86Filter>, LibraryError> {
    let reports = match probe_x86_filter_path(
        scan_target,
        FilterProbeOptions {
            dynamic_v2link: true,
            trace_code: false,
        },
    ) {
        Ok(reports) => reports,
        Err(error) => {
            eprintln!(
                "[content-filter] route=generic-x86 target={} probe=failed error={}",
                scan_target.display(),
                error
            );
            return Ok(None);
        }
    };

    let (sample_indices, sample_bytes) = content_filter_validation_samples(archive, ordered_names)?;
    let proven_candidates = reports
        .iter()
        .map(|report| {
            usize::from(report.captured_callback.is_some())
                + report
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.registration.is_some())
                    .count()
        })
        .sum::<usize>();
    let abi_hypotheses = reports
        .iter()
        .map(|report| {
            report
                .candidates
                .iter()
                .filter(|candidate| candidate.registration.is_none())
                .count()
        })
        .sum::<usize>();
    eprintln!(
        "[content-filter] route=generic-x86 target={} modules={} proven_candidates={} abi_hypotheses={} sample_entries={} sample_bytes={}",
        scan_target.display(),
        reports.len(),
        proven_candidates,
        abi_hypotheses,
        sample_indices.len(),
        sample_bytes,
    );
    if reports.is_empty() || sample_indices.is_empty() {
        return Ok(None);
    }

    let mut passing = Vec::<ValidatedX86Filter>::new();

    // First exercise callbacks whose registration provenance is already known.
    // These remain highest priority, but registration discovery is not required
    // for later sandbox hypotheses.
    for report in &reports {
        let has_registration = report.captured_callback.is_some()
            || report
                .candidates
                .iter()
                .any(|candidate| candidate.registration.is_some());
        if !has_registration {
            continue;
        }
        match validate_x86_filter_module_on_entries(
            archive,
            &report.path,
            ordered_names,
            None,
            sample_indices.iter().copied(),
        ) {
            Ok(Some((validation, callback_va, callback_source)))
                if x86_filter_candidate_has_enough_evidence(&validation) =>
            {
                eprintln!(
                    "[content-filter] candidate=generic-x86 module={} callback=0x{:08x} source={} adlr={}/{} strong_formats={} decision=sample-pass",
                    report.path.display(),
                    callback_va,
                    callback_source,
                    validation.adler_matches,
                    validation.adler_tested,
                    validation.strong_formats,
                );
                passing.push(ValidatedX86Filter {
                    module: report.path.clone(),
                    callback_va,
                    callback_source,
                    validation,
                    forced_callback: false,
                });
            }
            Ok(Some(validation)) => {
                let (validation, callback_va, callback_source) = validation;
                eprintln!(
                    "[content-filter] candidate=generic-x86 module={} callback=0x{:08x} source={} adlr={}/{} strong_formats={} decision=insufficient-evidence",
                    report.path.display(),
                    callback_va,
                    callback_source,
                    validation.adler_matches,
                    validation.adler_tested,
                    validation.strong_formats,
                );
            }
            Ok(None) => eprintln!(
                "[content-filter] candidate=generic-x86 module={} decision=rejected reason=adlr-mismatch",
                report.path.display(),
            ),
            Err(error) => eprintln!(
                "[content-filter] candidate=generic-x86 module={} decision=rejected reason=emulation-error error={}",
                report.path.display(),
                error,
            ),
        }
    }

    #[derive(Clone)]
    struct X86HypothesisWork {
        module: PathBuf,
        callback_va: u32,
        source: String,
        abi_score: u32,
        priority: u8,
    }

    // Flatten hypotheses across every PE and rank them globally.  The previous
    // 16-per-module/128-total caps could declare "none" while thousands of
    // untested callbacks still existed.  That made brute force run before
    // native discovery had actually finished.  There is deliberately no hard
    // hypothesis cap now: a negative native result means every semantically
    // eligible callback was tested against real archive data.
    let mut hypotheses = Vec::<X86HypothesisWork>::new();
    for report in &reports {
        for candidate in report
            .candidates
            .iter()
            .filter(|candidate| candidate.registration.is_none())
        {
            hypotheses.push(X86HypothesisWork {
                module: report.path.clone(),
                callback_va: candidate.callback_va,
                source: candidate.source.clone(),
                abi_score: candidate.abi_score,
                priority: x86_filter_hypothesis_priority(&candidate.source),
            });
        }
    }
    hypotheses.sort_by_key(|candidate| {
        (
            candidate.priority,
            std::cmp::Reverse(candidate.abi_score),
            candidate.module.clone(),
            candidate.callback_va,
        )
    });
    hypotheses.dedup_by(|a, b| {
        a.module == b.module && a.callback_va == b.callback_va
    });

    let hypothesis_total = hypotheses.len();
    let mut hypothesis_tested = 0usize;
    let mut single_entry_survivors = 0usize;
    let mut four_entry_survivors = 0usize;
    let mut emulation_errors = 0usize;

    for candidate in hypotheses {
        hypothesis_tested += 1;
        if hypothesis_tested == 1 || hypothesis_tested % 64 == 0 {
            eprintln!(
                "[content-filter] generic-x86 hypothesis_progress={}/{} single_entry_survivors={} four_entry_survivors={} emulation_errors={}",
                hypothesis_tested,
                hypothesis_total,
                single_entry_survivors,
                four_entry_survivors,
                emulation_errors,
            );
        }
        let source = format!("{}:abi-score={}", candidate.source, candidate.abi_score);

        // Stage 1 is intentionally one real encrypted entry.  An incorrect
        // callback almost certainly fails its original adlr immediately, which
        // lets us exhaust a large hypothesis set without running 32 entries for
        // every function.
        let first = validate_x86_filter_module_on_entries(
            archive,
            &candidate.module,
            ordered_names,
            Some((candidate.callback_va, source.as_str())),
            sample_indices.iter().copied().take(1),
        );
        let first_ok = match first {
            Ok(Some((ref validation, _, _))) => {
                x86_filter_candidate_survives_single_entry(validation)
            }
            Err(_) => {
                emulation_errors += 1;
                false
            }
            _ => false,
        };
        if !first_ok {
            continue;
        }
        single_entry_survivors += 1;

        // Stage 2 requires the normal evidence threshold over four independent
        // entries before spending the full 32-entry validation budget.
        let preflight = validate_x86_filter_module_on_entries(
            archive,
            &candidate.module,
            ordered_names,
            Some((candidate.callback_va, source.as_str())),
            sample_indices.iter().copied().take(4),
        );
        let preflight_ok = matches!(
            preflight,
            Ok(Some((ref validation, _, _)))
                if x86_filter_candidate_has_enough_evidence(validation)
        );
        if !preflight_ok {
            continue;
        }
        four_entry_survivors += 1;

        match validate_x86_filter_module_on_entries(
            archive,
            &candidate.module,
            ordered_names,
            Some((candidate.callback_va, source.as_str())),
            sample_indices.iter().copied(),
        ) {
            Ok(Some((validation, callback_va, callback_source)))
                if x86_filter_candidate_has_enough_evidence(&validation) =>
            {
                eprintln!(
                    "[content-filter] candidate=generic-x86-hypothesis module={} callback=0x{:08x} source={} adlr={}/{} strong_formats={} decision=validated",
                    candidate.module.display(),
                    callback_va,
                    callback_source,
                    validation.adler_matches,
                    validation.adler_tested,
                    validation.strong_formats,
                );
                passing.push(ValidatedX86Filter {
                    module: candidate.module,
                    callback_va,
                    callback_source,
                    validation,
                    forced_callback: true,
                });
                // 32 real entries with original adlr/strong-format evidence are
                // authoritative enough to stop hypothesis discovery.  Any
                // ambiguity is still handled by the existing full-archive path
                // when multiple proven/validated callbacks have survived.
                break;
            }
            Err(_) => emulation_errors += 1,
            _ => {}
        }
    }
    eprintln!(
        "[content-filter] generic-x86 hypotheses_tested={}/{} single_entry_survivors={} four_entry_survivors={} emulation_errors={}",
        hypothesis_tested,
        hypothesis_total,
        single_entry_survivors,
        four_entry_survivors,
        emulation_errors,
    );

    if passing.is_empty() {
        eprintln!(
            "[content-filter] generic-x86 decision=none reason=all-semantic-hypotheses-rejected"
        );
        return Ok(None);
    }
    if passing.len() > 1 {
        // Ambiguity is resolved by validating the surviving callbacks against
        // the complete archive. This is expensive only in the unusual case
        // where multiple independently registered filters passed the bounded
        // sample; it is still preferable to guessing and then brute-forcing.
        let mut verified = Vec::new();
        for candidate in passing {
            match validate_x86_filter_module_on_entries(
                archive,
                &candidate.module,
                ordered_names,
                candidate
                    .forced_callback
                    .then_some((candidate.callback_va, candidate.callback_source.as_str())),
                0..archive.entries.len(),
            ) {
                Ok(Some((validation, callback_va, callback_source)))
                    if x86_filter_candidate_has_enough_evidence(&validation) =>
                {
                    verified.push(ValidatedX86Filter {
                        module: candidate.module,
                        callback_va,
                        callback_source,
                        validation,
                        forced_callback: candidate.forced_callback,
                    });
                }
                _ => {}
            }
        }
        passing = verified;
    }

    if passing.len() != 1 {
        eprintln!(
            "[content-filter] generic-x86 full_validation={} decision={}",
            passing.len(),
            if passing.is_empty() { "none" } else { "ambiguous" },
        );
        return Ok(None);
    }

    let selected = passing.pop().unwrap();
    eprintln!(
        "[content-filter] selected backend=generic-x86 module={} callback=0x{:08x} source={} adlr={}/{} strong_formats={} validation=archive-samples",
        selected.module.display(),
        selected.callback_va,
        selected.callback_source,
        selected.validation.adler_matches,
        selected.validation.adler_tested,
        selected.validation.strong_formats,
    );
    Ok(Some(selected))
}

fn select_recovered_cxdec_engine(
    archive: &Archive,
    scan_target: &Path,
    ordered_names: Option<&OrderedNameRecovery>,
) -> Result<Option<Arc<CxdecEngine>>, LibraryError> {
    let (generated_controls, generated_mask_offsets) =
        verified_setup_archive_generated_values(archive, scan_target)
            .map_err(|error| LibraryError::InvalidArgument(error.to_string()))?;
    let protected_index = cxdec_special_name_map_active(ordered_names);

    // Select samples from the Special-resolved resource set.  Protected CXDEC
    // indexes may deliberately lie in `info` about entry sizes, so ordering and
    // the byte budget use the physical `segm` sizes instead.  This prevents
    // tiny warning/decoy nodes from eliminating the correct native profile.
    let mut sample_indices: Vec<usize> = (0..archive.entries.len())
        .filter(|&index| {
            cxdec_entry_is_real_resource(&archive.entries[index], index, ordered_names)
        })
        .collect();
    sample_indices.sort_by_key(|&index| {
        cxdec_effective_original_size(&archive.entries[index], protected_index)
    });
    const SAMPLE_COUNT: usize = 32;
    const SAMPLE_BYTES: u64 = 64 * 1024 * 1024;
    let mut selected = Vec::new();
    let mut sample_bytes = 0u64;
    for index in sample_indices {
        if selected.len() >= SAMPLE_COUNT {
            break;
        }
        let entry = &archive.entries[index];
        if entry.adler.or(entry.alternate_hash).is_none() {
            continue;
        }
        let size = cxdec_effective_original_size(entry, protected_index);
        if size > SAMPLE_BYTES || sample_bytes.saturating_add(size) > SAMPLE_BYTES {
            continue;
        }
        let raw = match reconstruct_cxdec_entry(archive, index, protected_index) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let useful = if let Some(expected) = entry.adler {
            xp3_brute::adler32(&raw) != expected
        } else {
            let name = effective_entry_name(entry, index, ordered_names);
            !hypotheses_for_name(name)
                .iter()
                .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
                && strong_builtin_format(&raw).is_none()
        };
        if !useful {
            continue;
        }
        selected.push(index);
        sample_bytes = sample_bytes.saturating_add(size);
    }

    let coherent = recover_coherent_runtime_cxdec_params_from_game_with_generated_values(
        scan_target,
        &generated_controls,
        &generated_mask_offsets,
    )?;

    // Once one PE has been structurally tied to setupArchiveData + Cabbage +
    // RiddlePrefix8, never cross-mix its generator fields with unrelated game
    // modules.  A recognized coherent module that fails real-entry validation
    // is an implementation/recovery error and must not silently fall through to
    // multi-minute per-entry brute force.
    if !coherent.is_empty() {
        eprintln!(
            "[cxdec-params   ] route=coherent-runtime-module target={} candidates={} sample_entries={} sample_bytes={} protected_index={}",
            scan_target.display(),
            coherent.len(),
            selected.len(),
            sample_bytes,
            protected_index,
        );
        if selected.is_empty() {
            return Err(LibraryError::Format(
                "coherent CXDEC module found, but no Special-resolved encrypted entries were available for validation"
                    .to_string(),
            ));
        }

        let mut passing: Vec<(RecoveredCxdecParams, Arc<CxdecEngine>, CxdecParamValidation)> =
            Vec::new();
        for candidate in coherent {
            let engine = match CxdecEngine::new(candidate.content.clone()) {
                Ok(value) => Arc::new(value),
                Err(_) => continue,
            };
            let Some(validation) = validate_cxdec_params_on_entries(
                archive,
                engine.as_ref(),
                ordered_names,
                selected.iter().copied(),
            )? else {
                continue;
            };
            if cxdec_candidate_has_enough_evidence(&validation) {
                passing.push((candidate, engine, validation));
            }
        }
        if passing.is_empty() {
            return Err(LibraryError::Format(
                "coherent runtime CXDEC profile did not validate against Special-resolved archive entries"
                    .to_string(),
            ));
        }

        let all_indices = 0..archive.entries.len();
        let mut verified = Vec::new();
        for (candidate, engine, _) in passing {
            let Some(validation) = validate_cxdec_params_on_entries(
                archive,
                engine.as_ref(),
                ordered_names,
                all_indices.clone(),
            )? else {
                continue;
            };
            if cxdec_candidate_has_enough_evidence(&validation) {
                verified.push((candidate, engine, validation));
            }
        }
        if verified.len() != 1 {
            return Err(LibraryError::Format(format!(
                "coherent runtime CXDEC full validation produced {} candidates (expected exactly one)",
                verified.len()
            )));
        }

        let (candidate, engine, validation) = verified.pop().unwrap();
        let generator = match candidate.content.generator {
            xp3_brute::CxdecGeneratorKind::Classic => "classic".to_string(),
            xp3_brute::CxdecGeneratorKind::Cabbage { random_seed } => {
                format!("cabbage:random_seed=0x{random_seed:08x}")
            }
        };
        eprintln!(
            "[cxdec-params   ] verified route=coherent-runtime-module mask=0x{:08x} offset=0x{:08x} prolog={:?} even={:?} odd={:?} generator={} wrapper=prefix8 adlr={}/{} strong_formats={} module={}",
            candidate.content.mask,
            candidate.content.offset,
            candidate.content.prolog_order,
            candidate.content.even_branch_order,
            candidate.content.odd_branch_order,
            generator,
            validation.adler_matches,
            validation.adler_tested,
            validation.strong_formats,
            candidate.sources.dispatch_orders.display(),
        );
        return Ok(Some(engine));
    }

    // Compatibility fallback for older/other CXDEC variants where no single
    // module satisfies the coherent runtime anchors.  This remains bounded and
    // still validates every selected parameter set against real archive data.
    let candidates = recover_cxdec_params_from_game_with_generated_values(
        scan_target,
        &generated_controls,
        &generated_mask_offsets,
    )?;
    if candidates.is_empty() {
        eprintln!(
            "[cxdec-params   ] route=generic target={} candidates=0",
            scan_target.display()
        );
        return Ok(None);
    }

    eprintln!(
        "[cxdec-params   ] route=generic target={} candidates={} sample_entries={} sample_bytes={} protected_index={}",
        scan_target.display(),
        candidates.len(),
        selected.len(),
        sample_bytes,
        protected_index,
    );

    let mut passing: Vec<(RecoveredCxdecParams, Arc<CxdecEngine>, CxdecParamValidation)> = Vec::new();
    for candidate in candidates {
        let engine = match CxdecEngine::new(candidate.content.clone()) {
            Ok(value) => Arc::new(value),
            Err(_) => continue,
        };
        let Some(validation) = validate_cxdec_params_on_entries(
            archive,
            engine.as_ref(),
            ordered_names,
            selected.iter().copied(),
        )? else {
            continue;
        };
        if cxdec_candidate_has_enough_evidence(&validation) {
            passing.push((candidate, engine, validation));
        }
    }

    if passing.is_empty() {
        eprintln!("[cxdec-params   ] sample_validation=none");
        return Ok(None);
    }

    let all_indices = 0..archive.entries.len();
    let mut verified = Vec::new();
    for (candidate, engine, _) in passing {
        let Some(validation) = validate_cxdec_params_on_entries(
            archive,
            engine.as_ref(),
            ordered_names,
            all_indices.clone(),
        )? else {
            continue;
        };
        if cxdec_candidate_has_enough_evidence(&validation) {
            verified.push((candidate, engine, validation));
        }
    }

    if verified.len() != 1 {
        eprintln!(
            "[cxdec-params   ] full_validation={} decision={}",
            verified.len(),
            if verified.is_empty() { "none" } else { "ambiguous" },
        );
        return Ok(None);
    }

    let (candidate, engine, validation) = verified.pop().unwrap();
    let generator = match candidate.content.generator {
        xp3_brute::CxdecGeneratorKind::Classic => "classic".to_string(),
        xp3_brute::CxdecGeneratorKind::Cabbage { random_seed } => {
            format!("cabbage:random_seed=0x{random_seed:08x}")
        }
    };
    let wrapper = if candidate.content.wrappers.is_empty() {
        "none"
    } else {
        "prefix8"
    };
    eprintln!(
        "[cxdec-params   ] verified route=generic mask=0x{:08x} offset=0x{:08x} prolog={:?} even={:?} odd={:?} generator={} wrapper={} adlr={}/{} strong_formats={} mask_offset_module={} control_module={} dispatch_module={} random_seed_module={} wrapper_module={}",
        candidate.content.mask,
        candidate.content.offset,
        candidate.content.prolog_order,
        candidate.content.even_branch_order,
        candidate.content.odd_branch_order,
        generator,
        wrapper,
        validation.adler_matches,
        validation.adler_tested,
        validation.strong_formats,
        candidate.sources.mask_offset.display(),
        candidate.sources.control_block.display(),
        candidate.sources.dispatch_orders.display(),
        candidate.sources.random_seed.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
        candidate.sources.wrapper.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
    );
    Ok(Some(engine))
}

fn automatic_cxdec_scan_target(
    archive: &Archive,
    explicit_filter_target: Option<&Path>,
    hx_options: &HxCliOptions,
) -> Result<Option<PathBuf>, LibraryError> {
    if let Some(target) = explicit_filter_target {
        return Ok(Some(target.to_path_buf()));
    }
    if let Some(explicit) = hx_options.explicit_exe() {
        return Ok(Some(explicit));
    }
    if !hx_options.exe_auto_enabled() {
        return Ok(None);
    }
    let Some(archive_path) = archive.path.as_deref() else {
        return Ok(None);
    };
    let candidates = discover_game_executables(archive_path, None)
        .map_err(LibraryError::InvalidArgument)?;
    Ok(candidates.into_iter().next())
}

fn unpack(
    archive: &Archive,
    out_dir: &Path,
    max_period: usize,
    top_periods: usize,
    exhaustive_dynamic: bool,
    compute_mode: ComputeMode,
    hx_options: &HxCliOptions,
    special_options: &SpecialCliOptions,
    decode_options: &UnpackDecodeOptions,
    x86_filter_module: Option<&Path>,
    cxdec_scan_target: Option<&Path>,
    progress_enabled: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    reset_compute_telemetry();
    cleanup_legacy_unpack_artifacts(out_dir)?;
    fs::create_dir_all(out_dir)?;
    let mut xp3_meta = build_xp3_meta(archive, out_dir, decode_options);
    eprintln!(
        "[output        ] mode=clean root={} diagnostics=internal-only tjs={} tlg={} psb={} pbd={} global_psb_key_cache=on",
        out_dir.display(), decode_options.tjs.label(), decode_options.tlg.label(), decode_options.psb.label(), decode_options.pbd.label(),
    );
    if let Some(module) = x86_filter_module {
        eprintln!(
            "[content-filter] explicit module candidate={} policy=validate-before-use",
            module.display(),
        );
    }
    let plan = recovery_plan(archive);
    eprintln!(
        "xp3brute start entries={} family={:?} compute={} cpu_kernel={} progress={}",
        archive.entries.len(),
        plan.family,
        compute_mode,
        cpu_backend_label(),
        if progress_enabled { "on" } else { "off" }
    );
    let special_roots: Vec<(usize, &xp3_brute::RootChunk)> = archive
        .root_chunks
        .iter()
        .enumerate()
        .filter(|(_, root)| {
            matches!(
                root.kind,
                RootKind::SpecialIndexV1
                    | RootKind::SpecialIndexV2
                    | RootKind::SpecialIndexV3
                    | RootKind::SpecialIndexGeneric
                    | RootKind::Hxv4SpecialIndex
            )
        })
        .collect();
    let has_special = !special_roots.is_empty();
    let special_started = Instant::now();
    if has_special {
        eprintln!(
            "[special       ] found count={} archive_variant={}",
            special_roots.len(),
            if archive.is_hxv4() {
                "HXV4"
            } else {
                "indirect-special"
            }
        );
        for (root_index, root) in &special_roots {
            let offset = root
                .inferred_offset
                .map(|value| format!("0x{value:x}"))
                .unwrap_or_else(|| "-".to_string());
            let stored = root
                .inferred_archive_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            let original = root
                .inferred_original_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            eprintln!(
                "[special       ] root={} variant={} offset={} stored={} original={} descriptor_size={}",
                root_index, root_kind(root.kind), offset, stored, original, root.size
            );
        }
        if archive.is_hxv4() {
            let key_present = hx_options.key.is_some()
                || env::var("KRKR_HX_INDEX_KEY").is_ok()
                || env::var("KRKR_HX_INDEX_KEY1").is_ok();
            let nonce_present = hx_options.nonce.is_some()
                || env::var("KRKR_HX_INDEX_NONCE").is_ok()
                || env::var("KRKR_HX_INDEX_KEY2").is_ok();
            let exe_recovery = hx_options.explicit_exe().is_some() || hx_options.exe_auto_enabled();
            let startup = hxv4_startup_entry_index(&archive.entries);
            let flags = archive.hxv4.as_ref().map(|hx| hx.kind).unwrap_or(0);
            let blob = archive.hxv4_special_index_bytes();
            let tag = blob
                .and_then(hxv4_special_tag)
                .map(|tag| tag.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .unwrap_or_else(|| "<missing>".to_string());
            eprintln!(
                "[special-index ] route=HXV4 cipher=xchacha20-poly1305 tag={} ciphertext_bytes={} nonce_slot={} nonce_bytes=24 key_material={} startup_anchor={} repeating_xor_probe=skipped",
                tag,
                blob.map(|b| b.len().saturating_sub(16)).unwrap_or(0),
                hxv4_special_nonce_slot(flags),
                if key_present && nonce_present { "explicit" } else if key_present || nonce_present { "partial" } else if exe_recovery { "exe-auto" } else { "missing" },
                startup.map(|i| format!("entry[{i}]=startup.tjs")).unwrap_or_else(|| "missing".to_string())
            );
        } else {
            eprintln!(
                "[special       ] recovering parameters from game executable (roots={})",
                archive.indirect_special_roots().len(),
            );
        }
    }
    let ordered_names = recover_ordered_names_with_hx_options(
        archive,
        hx_options,
        special_options,
        progress_enabled,
    )?;
    if let Some(names) = &ordered_names {
        eprintln!(
            "[special-index ] candidate accepted root={} decoder={} layout={} names={} confidence={} decoded_size={} elapsed={:.3}s",
            names.root_index, names.decoder, names.layout, names.names.len(), names.confidence, names.decoded_size,
            special_started.elapsed().as_secs_f64()
        );
        if let Some(decoded) = names.decoded.as_deref() {
            eprintln!(
                "[special-index ] plaintext decoded bytes={} storage=internal-only",
                decoded.len(),
            );
        }
        if let Some(xor) = &names.xor {
            eprintln!(
                "[special-index ] xor-key scope={} period={} table_start=0x{:x} key={}",
                special_scope_label(xor.scope),
                xor.period(),
                xor.table_start,
                xor.key_hex()
            );
            eprintln!("[special-index ] xor-key storage=internal-only");
        }
    } else if has_special && !archive.is_hxv4() {
        eprintln!(
            "[special-index ] candidate rejected: no decoder/key candidate passed strict index validation after {:.3}s",
            special_started.elapsed().as_secs_f64()
        );
    }

    populate_special_meta(&mut xp3_meta, archive, ordered_names.as_ref());

    let mut hx_index = load_hx_index(archive, hx_options)?;
    let hxv4_nonce_slot = archive
        .hxv4
        .as_ref()
        .map(|hx| hxv4_special_nonce_slot(hx.kind))
        .unwrap_or(0);
    require_special_before_content_recovery(
        archive.is_hxv4(),
        has_special,
        ordered_names.is_some(),
        hx_index.is_some(),
        hxv4_nonce_slot,
    )?;

    // Reconstruct the title's native ordinary-entry FilterManager once and
    // share it between the filename bootstrap and the final parallel unpack.
    // This is independent from the Special AEAD key: Special authentication
    // gives us each record's `entry_key`; the FilterManager turns that key into
    // the reconstructed symmetric stream XOR candidate used for file contents.
    let hx_native_recovery = if archive.is_hxv4() {
        resolve_hx_native_recovery(archive, hx_options)?
    } else {
        None
    };
    let hx_native_filter = hx_native_recovery
        .as_ref()
        .map(|recovery| recovery.native_filter.clone());
    if let Some(manager) = hx_native_filter.as_ref() {
        eprintln!(
            "[hxv4-native  ] FilterManager=reconstructed lanes=128 control_mode={} rng={} mask=0x{:04x} offset=0x{:04x} holder={:08x}:{:08x} transform=symmetric-xor",
            manager.control_mode(),
            manager.random_type_label(),
            manager.mask(),
            manager.offset(),
            manager.holder_high(),
            manager.holder_low(),
        );
    } else if archive.is_hxv4() {
        eprintln!("[hxv4-native  ] FilterManager=unavailable; reconstructed entry_key content path disabled");
    }

    if let Some(index) = hx_index.as_ref() {
        let explicit_hx_keys = hx_options.keys()?;
        populate_hxv4_meta(
            &mut xp3_meta,
            archive,
            index,
            explicit_hx_keys.as_ref(),
            hx_native_recovery.as_ref(),
            hx_native_filter.as_ref(),
        );
    }

    if let Some(index) = hx_index.as_mut() {
        let before_entries = index.entries.iter().filter(|e| e.archive_slot == 0).count();
        let before_resolved = index
            .entries
            .iter()
            .filter(|e| e.archive_slot == 0 && e.name.is_some())
            .count();
        eprintln!(
            "Hxv4 special index decrypted: entries={} current_archive_entries={} resolved_plaintext_names={} hash_only={}",
            index.entries.len(), before_entries, before_resolved, before_entries.saturating_sub(before_resolved)
        );
        if before_resolved != before_entries {
            eprintln!("Hxv4 note: hash-only names detected; starting the game-wide filename bootstrap before any ordinary content recovery.");
            bootstrap_hxv4_names(
                archive,
                index,
                hx_options,
                hx_native_filter.as_ref(),
                out_dir,
                compute_mode,
                max_period,
                top_periods,
                exhaustive_dynamic,
                decode_options,
                &mut xp3_meta,
            )?;
        }
        let current_entries = index.entries.iter().filter(|e| e.archive_slot == 0).count();
        let resolved_current = index
            .entries
            .iter()
            .filter(|e| e.archive_slot == 0 && e.name.is_some())
            .count();
        let explicit_hx_keys = hx_options.keys()?;
        populate_hxv4_meta(
            &mut xp3_meta,
            archive,
            index,
            explicit_hx_keys.as_ref(),
            hx_native_recovery.as_ref(),
            hx_native_filter.as_ref(),
        );
        if !hxv4_names_complete(current_entries, resolved_current) {
            eprintln!(
                "[hxv4-names   ] fixed-point current={}/{} unresolved={}; recovered named plaintexts were written directly under {} and all bootstrap/TJS2 diagnostics stayed internal",
                resolved_current,
                current_entries,
                current_entries.saturating_sub(resolved_current),
                out_dir.display(),
            );
            eprintln!(
                "[hxv4-names   ] ordinary reconstruct/solve/unpack is intentionally skipped until every required filename is resolved"
            );
            print_compute_summary();
            write_xp3_meta(out_dir, &mut xp3_meta)?;
            return Ok(());
        }
    }
    let hx_startup_index = if archive.is_hxv4() {
        hxv4_startup_entry_index(&archive.entries)
    } else {
        None
    };
    let has_explicit_startup = hx_startup_index.is_some();
    let hx_index_by_id: HashMap<u64, Hxv4IndexEntry> = hx_index
        .as_ref()
        .map(|idx| {
            idx.entries
                .iter()
                .filter(|entry| {
                    entry.archive_slot == 0
                        && !(has_explicit_startup
                            && entry
                                .name
                                .as_deref()
                                .is_some_and(|name| name.eq_ignore_ascii_case("startup.tjs")))
                })
                .cloned()
                .map(|entry| (entry.id, entry))
                .collect()
        })
        .unwrap_or_default();

    // Bind every physical XP3 entry to the authenticated Special record key and local flag.
    // Synthetic HXV4 ids are Special first-integer.low32; the high32 carries
    // archive_slot/local_flag. The one explicit
    // data.xp3 startup entry is represented outside that synthetic-id stream
    // and is matched to the Special record whose exact recovered name is
    // `startup.tjs`.
    let startup_native_meta = hx_startup_index.and_then(|_| {
        hx_index
            .as_ref()?
            .entries
            .iter()
            .find(|meta| {
                meta.archive_slot == 0
                    && meta
                        .name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case("startup.tjs"))
            })
            .map(|meta| (meta.entry_key, meta.filter_flag))
    });
    let hx_native_entry_meta: Vec<Option<(u64, u16)>> = archive
        .entries
        .iter()
        .enumerate()
        .map(|(entry_index, entry)| {
            if Some(entry_index) == hx_startup_index {
                startup_native_meta
            } else {
                entry
                    .hxv4_id
                    .and_then(|id| hx_index_by_id.get(&id))
                    .map(|meta| (meta.entry_key, meta.filter_flag))
            }
        })
        .collect();

    if let Some(hx) = &archive.hxv4 {
        eprintln!(
            "Hxv4 detected: special_index=0x{:x}+{} kind={} fake-name entries={} Special gate=authenticated+parsed+names-complete; ordinary entry recovery is now permitted",
            hx.offset,
            hx.stored_size,
            hx.kind,
            archive.entries.iter().filter(|entry| entry.hxv4_id.is_some()).count()
        );
    }

    let config = RecoveryConfig {
        min_period: 1,
        max_period,
        top_periods_per_hypothesis: top_periods,
        exhaustive_dynamic_periods: exhaustive_dynamic,
        max_refinement_rounds: 12,
        compute_mode,
        ..RecoveryConfig::default()
    };

    // `unpack` never materializes the complete reconstructed archive. Shared-key
    // probing/validation uses bounded or streaming evidence, and final recovery
    // reconstructs each entry only when it is about to be solved.
    eprintln!(
        "[memory        ] archive_backing={} physical_size={} archive_wide_stream_cache=off",
        if archive.is_file_backed() {
            "file"
        } else {
            "memory"
        },
        archive.physical_size(),
    );

    // HXV4 has no archive-wide reconstructed-stream cache anymore. Probe the
    // startup anchor once for diagnostics; the buffer is dropped immediately.
    if let Some(index) = hx_startup_index {
        let entry = &archive.entries[index];
        match archive.reconstruct_entry(index) {
            Ok(raw) => {
                let adler_ok = entry.adler
                    .map(|expected| xp3_brute::adler32(&raw) == expected);
                let strong_tjs = hypotheses_for_name("startup.tjs")
                    .iter()
                    .any(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong());
                if adler_ok == Some(true) || (entry.adler.is_none() && strong_tjs) {
                    let hints = inspect_hxv4_startup_plaintext(index, &raw);
                    eprintln!(
                        "[hxv4-startup ] anchor=entry[{}] name=startup.tjs state=plaintext adlr={} bootstrap_prefix={} media_name={}",
                        index,
                        adler_ok.map(|ok| if ok { "match" } else { "mismatch" }).unwrap_or("none"),
                        hints.bootstrap_prefix.as_deref().unwrap_or("<not-mined>"),
                        hints.media_name
                    );
                } else {
                    eprintln!(
                        "[hxv4-startup ] anchor=entry[{}] name=startup.tjs state=protected/recovery-needed adlr={}",
                        index,
                        adler_ok.map(|ok| if ok { "match" } else { "mismatch" }).unwrap_or("none")
                    );
                }
            }
            Err(err) => eprintln!(
                "[hxv4-startup ] anchor=entry[{}] name=startup.tjs state=reconstruct-failed error={}",
                index, err
            ),
        }
    }

    // A key recovered from the Special index is not automatically a content
    // key. Test it first because, when a title reuses that key, this is the
    // cheapest archive-wide path. Failed XP3 reconstructions are excluded from
    // the evidence pool and therefore cannot erase a valid Special result.
    let mut global_key: Option<GlobalKeySelection> = None;
    if let Some(names) = ordered_names.as_ref() {
        if let Some(xor) = names.xor.as_ref() {
            eprintln!(
                "[special-key   ] validating period={} scope={} against reconstructed entry streams",
                xor.period(),
                special_scope_label(xor.scope)
            );
            let validation =
                validate_special_xor_as_content_key_streaming(archive, xor, Some(names))?;
            eprintln!(
                "[special-key   ] evidence reconstructed={}/{} reconstruct_failed={} adlr={}/{} strong_formats={} joint={} decision={} reason={}",
                validation.reconstructed_entries,
                archive.entries.len(),
                validation.reconstruction_failures,
                validation.adler_matches,
                validation.adler_tested,
                validation.strong_format_matches,
                validation.joint_matches,
                if validation.accepted { "accepted" } else { "rejected" },
                validation.reason
            );
            if validation.accepted {
                eprintln!(
                    "[special-key   ] candidate accepted period={} full-stream validation=yes; using Special-derived key for unpack",
                    validation.candidate.period
                );
                global_key = Some(GlobalKeySelection {
                    source: GlobalKeySource::SpecialIndex,
                    candidate: validation.candidate,
                });
            } else {
                eprintln!(
                    "[recovery      ] Special index remains preserved for names/metadata, but its XOR key is not proven as a content key; falling back"
                );
            }
        } else if has_special {
            if archive.is_hxv4() {
                eprintln!(
                    "[special-key   ] no repeating-XOR content candidate: HXV4 Special index uses its dedicated ChaCha decoder"
                );
            } else {
                eprintln!(
                    "[special-key   ] no repeating-XOR content candidate was produced by the validated Special decoder"
                );
            }
        }
    }

    // Before any generic XOR inference, recover and validate the title's real
    // ordinary-entry extraction filter. Known CXDEC families are reconstructed
    // into Rust first; only when no known-family engine is available do we
    // emulate a registered generic x86 XP3 callback. Brute force is terminal
    // fallback, never a substitute for this discovery/emulation stage.
    let special_content_key_accepted = global_key
        .as_ref()
        .is_some_and(|key| key.source == GlobalKeySource::SpecialIndex);
    let mut recovered_fixed_cxdec_engine: Option<Arc<CxdecEngine>> = None;
    let mut validated_x86_filter: Option<ValidatedX86Filter> = None;
    let mut x86_filter_module_sha: Option<String> = None;

    if global_key.is_none() && !archive.is_hxv4() {
        let scan_target = automatic_cxdec_scan_target(
            archive,
            cxdec_scan_target,
            hx_options,
        )?;
        if let Some(target) = scan_target.as_deref() {
            recovered_fixed_cxdec_engine =
                select_recovered_cxdec_engine(archive, target, ordered_names.as_ref())?;

            if recovered_fixed_cxdec_engine.is_none() {
                let generic_target = x86_filter_module.unwrap_or(target);
                validated_x86_filter =
                    select_validated_x86_filter(archive, generic_target, ordered_names.as_ref())?;
            }
        } else if let Some(module) = x86_filter_module {
            validated_x86_filter =
                select_validated_x86_filter(archive, module, ordered_names.as_ref())?;
        }

        if let Some(selection) = validated_x86_filter.as_ref() {
            x86_filter_module_sha = Some(retain_x86_filter_module(
                &mut xp3_meta,
                &selection.module,
            )?);
            eprintln!(
                "[x86-filter    ] enabled module={} callback=0x{:08x} source={} policy=validated-emulation-before-brute",
                selection.module.display(),
                selection.callback_va,
                selection.callback_source,
            );
        }
    }

    let native_content_filter_ready =
        recovered_fixed_cxdec_engine.is_some() || validated_x86_filter.is_some();
    if global_key.is_none() {
        if archive.is_hxv4() {
            eprintln!(
                "[recovery      ] generic shared-key probe skipped for HXV4 so the dedicated per-entry Hx filter runs first; generic per-file XOR remains a validated fallback"
            );
        } else if native_content_filter_ready {
            eprintln!(
                "[recovery      ] generic shared-key probe skipped because a validated native/emulated content filter is available; brute remains terminal fallback"
            );
        } else if should_try_generic_shared_key(
            archive.is_hxv4(),
            special_content_key_accepted,
            plan.try_shared_repeating_xor,
        ) {
            if has_special {
                eprintln!("[recovery      ] native content-filter strategies exhausted; falling back to generic shared-key probe");
            } else {
                eprintln!("[recovery      ] no validated native content filter; entering generic shared-key fallback");
            }
            if let Some(candidate) =
                find_global_shared_key(archive, max_period, ordered_names.as_ref())?
            {
                global_key = Some(GlobalKeySelection {
                    source: GlobalKeySource::SharedProbe,
                    candidate,
                });
            }
        }
    } else {
        eprintln!("[recovery      ] native-filter and generic shared-key probes skipped because validated Special-derived content key already succeeded");
    }

    // A validated archive-wide key can be applied directly. This path is used
    // both for the historical shared-key optimization and, with higher priority,
    // for a Special-derived content key that independently passed entry checks.
    if let Some(global) = global_key {
        println!(
            "global-key validated source={} period={} known={}/{} streaming=yes",
            global.source.label(),
            global.candidate.period,
            global.candidate.known_slots,
            global.candidate.period,
        );
        xp3_meta.keys.push(KeyMeta {
            kind: "archive-global-repeating-xor".to_string(),
            source: global.source.label().to_string(),
            entry_index: None,
            logical_path: None,
            repeating_xor: Some(xp3_meta::repeating_xor_key(&global.candidate.key)),
            u32_hex: None,
            bytes_hex: None,
        });
        let mut solved = 0usize;
        let mut ignored = 0usize;
        let mut reconstruct_failed = 0usize;
        let unpack_progress = Progress::new("unpack", archive.entries.len(), progress_enabled);
        for (index, entry) in archive.entries.iter().enumerate() {
            let resolved_name = effective_entry_name(entry, index, ordered_names.as_ref());
            if entry.is_protected_dummy() || is_protected_dummy_name(resolved_name) {
                ignored += 1;
                if let Some(entry_meta) = xp3_meta.entries.get_mut(index) {
                    entry_meta.recovery.status = "ignored-protected-dummy".to_string();
                    entry_meta.recovery.detail = Some(
                        "synthetic protected-archive warning node; preserved as archive metadata and intentionally not extracted"
                            .to_string(),
                    );
                }
                unpack_progress.tick();
                continue;
            }
            match archive.reconstruct_entry(index) {
                Ok(mut plaintext) => {
                    apply_complete_period_in_place(&mut plaintext, &global.candidate);
                    let strong_format = hypotheses_for_name(resolved_name)
                        .into_iter()
                        .find(|hypothesis| {
                            validate_hypothesis(hypothesis.name, &plaintext).is_strong()
                        })
                        .map(|hypothesis| hypothesis.name.to_string())
                        .or_else(|| strong_builtin_format(&plaintext));
                    let output_name = ordered_names
                        .as_ref()
                        .and_then(|r| r.names.get(index))
                        .cloned()
                        .unwrap_or_else(|| {
                            entry
                                .hxv4_id
                                .map(|id| {
                                    hx_output_path(
                                        id,
                                        hx_index_by_id.get(&id),
                                        strong_format.as_deref(),
                                    )
                                })
                                .unwrap_or_else(|| resolved_name.to_string())
                        });
                    let UserFacingTextResult {
                        bytes: output_bytes,
                        source_sha256,
                        transform,
                    } = user_facing_text_asset(strong_format.as_deref(), plaintext);
                    let final_output_name = refine_generic_output_name(
                        &output_name,
                        strong_format.as_deref(),
                        &output_bytes,
                    );
                    if final_output_name != output_name {
                        eprintln!(
                            "[format-name   ] entry={} old={} new={} format={}",
                            index,
                            output_name,
                            final_output_name,
                            strong_format.as_deref().unwrap_or("libmagic"),
                        );
                    }
                    let output = out_dir.join(safe_relative_path(&final_output_name, index));
                    let asset =
                        write_unpack_asset_output(&output, &output_bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(&mut xp3_meta, index, &output_name, &asset, out_dir);
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(index) {
                        entry_meta.recovery.status = "global-repeating-xor".to_string();
                        entry_meta.recovery.format = strong_format.clone();
                        entry_meta.recovery.storage_plaintext_sha256 = Some(source_sha256);
                        if let Some(transform) = transform {
                            push_transform_unique(
                                entry_meta,
                                TransformMeta::KirikiriText(transform),
                            );
                        }
                        // The archive-global key is recorded once in `meta.keys`.
                        // Do not duplicate a non-bruteforced key into every entry.
                        entry_meta.recovery.repeating_xor = None;
                    }
                    solved += 1;
                    if verbose {
                        println!(
                            "entry[{index}] recovered source={} period={} {}",
                            global.source.label(),
                            global.candidate.period,
                            asset.output.display()
                        );
                    }
                }
                Err(err) => {
                    let stored = archive.stored_entry_bytes(index).unwrap_or_default();
                    reconstruct_failed += 1;
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(index) {
                        entry_meta.recovery.status = "reconstruct-failed".to_string();
                        entry_meta.recovery.detail = Some(err.to_string());
                    }
                    eprintln!(
                        "entry[{index}] reconstruct-failed name={} stored={} magic={} output=<not-written> error={err}",
                        entry.preferred_name(),
                        stored.len(),
                        magic_label(&stored),
                    );
                }
            }
            unpack_progress.tick();
        }
        println!(
            "summary total={} solved={} unresolved={} ignored={} reconstruct_failed={} global_key_source={}",
            archive.entries.len(),
            solved,
            reconstruct_failed,
            ignored,
            reconstruct_failed,
            global.source.label()
        );
        print_compute_summary();
        write_xp3_meta(out_dir, &mut xp3_meta)?;
        return Ok(());
    }

    if has_special {
        if archive.is_hxv4() {
            eprintln!("[recovery      ] HXV4 Special index authenticated and parsed; no archive-wide content key selected, continuing with gated per-entry content recovery");
        } else {
            eprintln!("[recovery      ] Special index decoded and validated; no Special-derived global content key selected, continuing with per-entry recovery");
        }
    }

    // Otherwise fall back to independent per-file recovery. Each entry is
    // reconstructed, solved, written, and dropped in a bounded batch. No
    // archive-wide reconstructed-stream cache exists on this path.

    let worker_count = rayon::current_num_threads().max(1);
    let batch_size = env::var("KRKR_UNPACK_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value != 0)
        .unwrap_or(worker_count.min(8))
        .min(64);
    let batch_byte_limit = env::var("KRKR_UNPACK_BATCH_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|&value| value != 0)
        .unwrap_or(512 * 1024 * 1024);
    eprintln!(
        "[memory        ] unpack pipeline=bounded batch_size={} batch_bytes={} workers={} archive_wide_stream_cache=off",
        batch_size,
        batch_byte_limit,
        worker_count,
    );

    let cxdec_protected_index = cxdec_special_name_map_active(ordered_names.as_ref());
    let reconstruct_progress = Arc::new(Progress::new(
        "reconstruct",
        archive.entries.len(),
        progress_enabled,
    ));
    let solve_progress = Arc::new(Progress::new(
        "solve",
        archive.entries.len(),
        progress_enabled,
    ));
    let solve_one = |
        index: usize,
        mut x86_runtime: Option<&mut X86Xp3FilterRuntime>,
    | -> Result<UnpackEntry, LibraryError> {
        let entry = &archive.entries[index];
        let resolved_name = effective_entry_name(entry, index, ordered_names.as_ref());

        // The protected-archive warning node is deliberate metadata/noise.
        // Preserve it in the parsed archive/xp3-meta for round-tripping, but do
        // not reconstruct, decrypt, write, or count it as an unresolved game
        // resource.
        if entry.is_protected_dummy() || is_protected_dummy_name(resolved_name) {
            reconstruct_progress.tick();
            return Ok(UnpackEntry {
                index,
                name: resolved_name.to_string(),
                hxv4_id: entry.hxv4_id,
                bytes: Vec::new(),
                storage_plaintext_sha256: None,
                text_transform: None,
                state: UnpackState::IgnoredProtectedDummy,
            });
        }

        // Protected CXDEC indexes can also contain lookup nodes that are not
        // backed by the validated Special filename map.  Keep those as genuine
        // unresolved entries; only the explicit protected warning node above is
        // ignored.  The `$` storage member is kept because native CxFilterFS
        // maps it to the real startup.tjs.
        if cxdec_protected_index
            && entry.name != "$"
            && !cxdec_entry_is_real_resource(entry, index, ordered_names.as_ref())
        {
            reconstruct_progress.tick();
            return Ok(UnpackEntry {
                index,
                name: resolved_name.to_string(),
                hxv4_id: entry.hxv4_id,
                bytes: Vec::new(),
                storage_plaintext_sha256: None,
                text_transform: None,
                state: UnpackState::Unresolved,
            });
        }

        let mut raw = match reconstruct_cxdec_entry(archive, index, cxdec_protected_index) {
            Ok(raw) => {
                reconstruct_progress.tick();
                raw
            }
            Err(err) => {
                reconstruct_progress.tick();
                let stored = archive.stored_entry_bytes(index).unwrap_or_default();
                return Ok(UnpackEntry {
                    index,
                    name: resolved_name.to_string(),
                    hxv4_id: entry.hxv4_id,
                    bytes: stored,
                    storage_plaintext_sha256: None,
                    text_transform: None,
                    state: UnpackState::ReconstructionFailed {
                        error: err.to_string(),
                    },
                });
            }
        };
        let hypotheses = hypotheses_for_name(resolved_name);

        if entry.adler.is_some() && archive.adler_matches(index, &raw)? == Some(true) {
            let strong_plain_format = strong_builtin_format(&raw);
            let UserFacingTextResult {
                bytes,
                source_sha256,
                transform,
            } = user_facing_text_asset(strong_plain_format.as_deref(), raw);
            return Ok(UnpackEntry {
                index,
                name: ordered_names
                    .as_ref()
                    .and_then(|r| r.names.get(index))
                    .cloned()
                    .unwrap_or_else(|| {
                        entry
                            .hxv4_id
                            .map(|id| hx_output_path(id, hx_index_by_id.get(&id), None))
                            .unwrap_or_else(|| resolved_name.to_string())
                    }),
                hxv4_id: entry.hxv4_id,
                bytes,
                storage_plaintext_sha256: Some(source_sha256),
                text_transform: transform,
                state: UnpackState::PlainRaw {
                    format: strong_plain_format,
                },
            });
        }

        // When adlr is absent, a strong content validator can still prove
        // that no extraction filter needs to be removed.
        if entry.adler.is_none() {
            let strong_plain_format = hypotheses
                .iter()
                .find(|h| validate_hypothesis(h.name, &raw).is_strong())
                .map(|h| h.name.to_string());
            if strong_plain_format.is_some() {
                let UserFacingTextResult {
                    bytes,
                    source_sha256,
                    transform,
                } = user_facing_text_asset(strong_plain_format.as_deref(), raw);
                return Ok(UnpackEntry {
                    index,
                    name: ordered_names
                        .as_ref()
                        .and_then(|r| r.names.get(index))
                        .cloned()
                        .unwrap_or_else(|| {
                            entry
                                .hxv4_id
                                .map(|id| hx_output_path(id, hx_index_by_id.get(&id), None))
                                .unwrap_or_else(|| resolved_name.to_string())
                        }),
                    hxv4_id: entry.hxv4_id,
                    bytes,
                    storage_plaintext_sha256: Some(source_sha256),
                    text_transform: transform,
                    state: UnpackState::PlainRaw {
                        format: strong_plain_format,
                    },
                });
            }
        }

        // A pure-Rust content engine may be used only after its external fixed
        // parameters have been recovered from the supplied game files. Accept
        // each entry only when the archive's original adlr matches after
        // decryption. This path executes no game code.
        if let Some(engine) = recovered_fixed_cxdec_engine.as_deref() {
            if let Some(file_hash) = entry.adler.or(entry.alternate_hash) {
                let mut candidate = raw.clone();
                engine.apply(0, file_hash, &mut candidate)?;
                let adler_verified = entry
                    .adler
                    .map(|expected| xp3_brute::adler32(&candidate) == expected);
                let format = hypotheses
                    .iter()
                    .find(|hypothesis| {
                        validate_hypothesis(hypothesis.name, &candidate).is_strong()
                    })
                    .map(|hypothesis| hypothesis.name.to_string())
                    .or_else(|| strong_builtin_format(&candidate));
                if adler_verified == Some(true)
                    || (entry.adler.is_none() && format.is_some())
                {
                    let format = format.unwrap_or_else(|| "adler-verified".to_string());
                    let UserFacingTextResult {
                        bytes,
                        source_sha256,
                        transform,
                    } = user_facing_text_asset(Some(&format), candidate);
                    return Ok(UnpackEntry {
                        index,
                        name: ordered_names
                            .as_ref()
                            .and_then(|r| r.names.get(index))
                            .cloned()
                            .unwrap_or_else(|| resolved_name.to_string()),
                        hxv4_id: entry.hxv4_id,
                        bytes,
                        storage_plaintext_sha256: Some(source_sha256),
                        text_transform: transform,
                        state: UnpackState::NativeCxdecRecovered {
                            format,
                            parameters: "recovered-native-cxdec".to_string(),
                            hash: file_hash,
                        },
                    });
                }
            }
        }

        // Generic x86 extraction-filter fast path. Selection has already been
        // validated on real archive entries before any brute-force probe. The
        // persistent emulator is initialized once and reused across bounded
        // batches so lazily generated code and module state are retained.
        if let Some(selection) = validated_x86_filter.as_ref() {
            if let Some(file_hash) = entry.adler.or(entry.alternate_hash) {
                let runtime = x86_runtime.as_deref_mut().ok_or_else(|| {
                    LibraryError::Format(format!(
                        "validated x86 filter {} has no persistent runtime",
                        selection.module.display()
                    ))
                })?;
                let mut candidate = raw.clone();
                runtime.set_execution_context(index, resolved_name);
                runtime.apply(0, file_hash, &mut candidate)?;
                let adler_verified = entry
                    .adler
                    .map(|expected| xp3_brute::adler32(&candidate) == expected);
                let format = hypotheses
                    .iter()
                    .find(|hypothesis| {
                        validate_hypothesis(hypothesis.name, &candidate).is_strong()
                    })
                    .map(|hypothesis| hypothesis.name.to_string())
                    .or_else(|| strong_builtin_format(&candidate));
                if adler_verified == Some(true)
                    || (entry.adler.is_none() && format.is_some())
                {
                    let format = format.unwrap_or_else(|| "adler-verified".to_string());
                    let UserFacingTextResult {
                        bytes,
                        source_sha256,
                        transform,
                    } = user_facing_text_asset(Some(&format), candidate);
                    return Ok(UnpackEntry {
                        index,
                        name: ordered_names
                            .as_ref()
                            .and_then(|r| r.names.get(index))
                            .cloned()
                            .unwrap_or_else(|| resolved_name.to_string()),
                        hxv4_id: entry.hxv4_id,
                        bytes,
                        storage_plaintext_sha256: Some(source_sha256),
                        text_transform: transform,
                        state: UnpackState::X86FilterRecovered {
                            format,
                            module: selection.module.display().to_string(),
                            callback: selection.callback_va,
                            source: selection.callback_source.clone(),
                            hash: file_hash,
                        },
                    });
                }
            }
        }

        // Reconstructed HXV4 ordinary-entry path. Apply the symmetric filter
        // in-place. On Adler mismatch, applying it a second time restores the
        // original reconstructed stream, avoiding a full-size raw.clone().
        if archive.is_hxv4() {
            if let (Some(manager), Some((entry_key, local_flag))) =
                (hx_native_filter.as_ref(), hx_native_entry_meta[index])
            {
                let state = manager.state_for_entry(entry_key, local_flag);
                state.apply(0, &mut raw);
                let actual_adler = xp3_brute::adler32(&raw);
                if let Some(expected_adler) = entry.adler {
                    if actual_adler != expected_adler {
                        let size = raw.len();
                        state.apply(0, &mut raw);
                        return Ok(UnpackEntry {
                            index,
                            name: ordered_names
                                .as_ref()
                                .and_then(|r| r.names.get(index))
                                .cloned()
                                .unwrap_or_else(|| {
                                    entry
                                        .hxv4_id
                                        .map(|id| hx_output_path(id, hx_index_by_id.get(&id), None))
                                        .unwrap_or_else(|| resolved_name.to_string())
                                }),
                            hxv4_id: entry.hxv4_id,
                            bytes: raw,
                            storage_plaintext_sha256: None,
                            text_transform: None,
                            state: UnpackState::NativeHxMismatch {
                                entry_key,
                                local_flag,
                                size,
                                split: state.split,
                                left_drip: state.left_drip,
                                right_drip: state.right_drip,
                                left_xor: state.left.xor_byte,
                                right_xor: state.right.xor_byte,
                                prefix_xor: state.prefix_xor,
                                expected_adler,
                                actual_adler,
                            },
                        });
                    }
                }
                let format = hypotheses
                    .iter()
                    .find(|hypothesis| validate_hypothesis(hypothesis.name, &raw).is_strong())
                    .map(|hypothesis| hypothesis.name.to_string())
                    .or_else(|| strong_builtin_format(&raw))
                    .unwrap_or_else(|| {
                        if entry.adler.is_some() {
                            "adler-verified".to_string()
                        } else {
                            "native-unchecked".to_string()
                        }
                    });
                let corrections = (state.left.correction0 != 0) as usize
                    + (state.left.correction1 != 0) as usize
                    + (state.right.correction0 != 0) as usize
                    + (state.right.correction1 != 0) as usize;
                let UserFacingTextResult {
                    bytes,
                    source_sha256,
                    transform,
                } = user_facing_text_asset(Some(&format), raw);
                return Ok(UnpackEntry {
                    index,
                    name: ordered_names
                        .as_ref()
                        .and_then(|r| r.names.get(index))
                        .cloned()
                        .unwrap_or_else(|| {
                            entry
                                .hxv4_id
                                .map(|id| {
                                    hx_output_path(id, hx_index_by_id.get(&id), Some(&format))
                                })
                                .unwrap_or_else(|| resolved_name.to_string())
                        }),
                    hxv4_id: entry.hxv4_id,
                    bytes,
                    storage_plaintext_sha256: Some(source_sha256),
                    text_transform: transform,
                    state: UnpackState::NativeHxRecovered {
                        format,
                        entry_key,
                        local_flag,
                        split: state.split,
                        left_xor: state.left.xor_byte,
                        right_xor: state.right.xor_byte,
                        corrections,
                    },
                });
            }
        }

        if archive.is_hxv4() && hx_native_filter.is_some() {
            // The reconstructed manager exists but this physical entry could not be
            // associated with a Special record key. Do not hide a mapping bug by
            // entering heuristic/generic brute paths.
            return Ok(UnpackEntry {
                index,
                name: ordered_names
                    .as_ref()
                    .and_then(|r| r.names.get(index))
                    .cloned()
                    .unwrap_or_else(|| {
                        entry
                            .hxv4_id
                            .map(|id| hx_output_path(id, hx_index_by_id.get(&id), None))
                            .unwrap_or_else(|| resolved_name.to_string())
                    }),
                hxv4_id: entry.hxv4_id,
                bytes: raw,
                storage_plaintext_sha256: None,
                text_transform: None,
                state: UnpackState::Unresolved,
            });
        }

        // Compatibility fallback for HXV4 titles where the reconstructed native
        // FilterManager could not be reconstructed. The fallback may allocate a
        // second plaintext buffer, but bounded batching caps the number of such
        // buffers alive at once.
        if archive.is_hxv4() && entry.hxv4_id.is_some() {
            let id = entry.hxv4_id.unwrap();
            let meta = hx_index_by_id.get(&id);
            if let Some(recovery) = recover_hxv4_effective(&raw, entry.adler, compute_mode)? {
                let name = ordered_names
                    .as_ref()
                    .and_then(|r| r.names.get(index))
                    .cloned()
                    .unwrap_or_else(|| hx_output_path(id, meta, Some(&recovery.format)));
                let UserFacingTextResult {
                    bytes,
                    source_sha256,
                    transform,
                } = user_facing_text_asset(Some(&recovery.format), recovery.plaintext);
                return Ok(UnpackEntry {
                    index,
                    name,
                    hxv4_id: entry.hxv4_id,
                    bytes,
                    storage_plaintext_sha256: Some(source_sha256),
                    text_transform: transform,
                    state: UnpackState::HxRecovered {
                        format: recovery.format,
                        split: recovery.filter.split_position,
                        left_xor: recovery.filter.left_xor,
                        right_xor: recovery.filter.right_xor,
                        corrections: recovery.filter.corrections.len(),
                        gpu: recovery.gpu_used,
                    },
                });
            }
        }

        if hypotheses.is_empty() {
            return Ok(UnpackEntry {
                index,
                name: ordered_names
                    .as_ref()
                    .and_then(|r| r.names.get(index))
                    .cloned()
                    .unwrap_or_else(|| {
                        entry
                            .hxv4_id
                            .map(|id| hx_output_path(id, hx_index_by_id.get(&id), None))
                            .unwrap_or_else(|| resolved_name.to_string())
                    }),
                hxv4_id: entry.hxv4_id,
                bytes: raw,
                storage_plaintext_sha256: None,
                text_transform: None,
                state: UnpackState::Unresolved,
            });
        }

        let recovered = recover_complete_stream(&raw, &hypotheses, &config, entry.adler)?;
        if let Some(best) = recovered.into_iter().next() {
            let output_name = ordered_names
                .as_ref()
                .and_then(|r| r.names.get(index))
                .cloned()
                .unwrap_or_else(|| {
                    entry
                        .hxv4_id
                        .map(|id| {
                            hx_output_path(id, hx_index_by_id.get(&id), Some(&best.hypothesis))
                        })
                        .unwrap_or_else(|| resolved_name.to_string())
                });
            let UserFacingTextResult {
                bytes,
                source_sha256,
                transform,
            } = user_facing_text_asset(Some(&best.hypothesis), best.plaintext);
            return Ok(UnpackEntry {
                index,
                name: output_name,
                hxv4_id: entry.hxv4_id,
                bytes,
                storage_plaintext_sha256: Some(source_sha256),
                text_transform: transform,
                state: UnpackState::Recovered {
                    format: best.hypothesis,
                    period: best.period.period,
                    key: best.period.key.clone(),
                    brute_used: best.brute_used,
                    mitm: best.brute_used_mitm,
                    gpu: best.brute_used_gpu,
                    gpu_adapter: best.gpu_adapter,
                    combinations: best.brute_combinations_considered,
                },
            });
        }

        Ok(UnpackEntry {
            index,
            name: ordered_names
                .as_ref()
                .and_then(|r| r.names.get(index))
                .cloned()
                .unwrap_or_else(|| {
                    entry
                        .hxv4_id
                        .map(|id| hx_output_path(id, hx_index_by_id.get(&id), None))
                        .unwrap_or_else(|| resolved_name.to_string())
                }),
            hxv4_id: entry.hxv4_id,
            bytes: raw,
            storage_plaintext_sha256: None,
            text_transform: None,
            state: UnpackState::Unresolved,
        })
    };

    let mut solved = 0usize;
    let mut unresolved = 0usize;
    let mut ignored = 0usize;
    let mut reconstruct_failed = 0usize;
    let mut report = Vec::<String>::with_capacity(archive.entries.len() + 1);
    report.push("entry\tstatus\tname\tinfo_name\thxv4_id\tformat\toutput\tdetail".to_string());
    let unpack_progress = Progress::new("unpack", archive.entries.len(), progress_enabled);

    // Generic x86 runtimes are intentionally kept out of cross-thread state:
    // Unicorn is not shared between Rayon workers. Keep one initialized runtime
    // alive across all bounded batches instead of re-running DllMain/V2Link for
    // every entry. Known pure-Rust filters still use the normal parallel path.
    let mut persistent_x86_runtime = validated_x86_filter
        .as_ref()
        .map(|selection| {
            if selection.forced_callback {
                X86Xp3FilterRuntime::open_with_callback(
                    &selection.module,
                    selection.callback_va,
                    selection.callback_source.clone(),
                    false,
                )
            } else {
                X86Xp3FilterRuntime::open(&selection.module, false)
            }
        })
        .transpose()?;
    if let Some(selection) = validated_x86_filter.as_ref() {
        eprintln!(
            "[x86-filter    ] execution=persistent-emulator module={} callback=0x{:08x} batching=bounded parallelism=1",
            selection.module.display(),
            selection.callback_va,
        );
        if let Some(runtime) = persistent_x86_runtime.as_mut() {
            runtime.enable_validated_production_execution();
            eprintln!(
                "[x86-filter    ] execution-mode=validated-fast instruction_count=off watchdog_s=120 reason=avoid-unicorn-per-instruction-count-hook"
            );
            runtime.enable_execution_diagnostics(true)?;
            runtime.print_initialization_diagnostics();
        }
    }

    let mut batch_start = 0usize;
    while batch_start < archive.entries.len() {
        let mut batch_end = batch_start;
        let mut batch_estimated_bytes = 0u64;
        while batch_end < archive.entries.len() && batch_end - batch_start < batch_size {
            let entry = &archive.entries[batch_end];
            let next_bytes = if cxdec_protected_index {
                let original = cxdec_effective_original_size(entry, true);
                let archived = entry.segments.iter().fold(0u64, |total, segment| {
                    total.saturating_add(segment.archive_size)
                });
                original.max(archived)
            } else {
                entry.original_size.max(entry.archive_size)
            };
            if batch_end != batch_start
                && batch_estimated_bytes.saturating_add(next_bytes) > batch_byte_limit
            {
                break;
            }
            batch_estimated_bytes = batch_estimated_bytes.saturating_add(next_bytes);
            batch_end += 1;
        }
        // Even a single resource may be larger than the configured byte cap;
        // process it alone rather than stalling the pipeline.
        if batch_end == batch_start {
            batch_end += 1;
        }

        let results: Vec<Result<UnpackEntry, LibraryError>> =
            if let Some(runtime) = persistent_x86_runtime.as_mut() {
                (batch_start..batch_end)
                    .map(|index| {
                        let result = solve_one(index, Some(&mut *runtime));
                        solve_progress.tick();
                        result
                    })
                    .collect()
            } else {
                (batch_start..batch_end)
                    .into_par_iter()
                    .map(|index| {
                        let result = solve_one(index, None);
                        solve_progress.tick();
                        result
                    })
                    .collect()
            };

        for result in results {
            let item = result?;

            if Some(item.index) == hx_startup_index
                && !matches!(
                    &item.state,
                    UnpackState::IgnoredProtectedDummy
                        | UnpackState::Unresolved
                        | UnpackState::NativeHxMismatch { .. }
                        | UnpackState::ReconstructionFailed { .. }
                )
            {
                let hints = inspect_hxv4_startup_plaintext(item.index, &item.bytes);
                eprintln!(
                    "[hxv4-startup ] recovered anchor=entry[{}] bootstrap_prefix={} media_name={} bytes={}",
                    item.index,
                    hints.bootstrap_prefix.as_deref().unwrap_or("<not-mined>"),
                    hints.media_name,
                    item.bytes.len()
                );
            }

            let source_entry = &archive.entries[item.index];
            let report_name = report_field(&item.name);
            let report_info_name = report_field(&source_entry.name);
            let report_hx_id = item
                .hxv4_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string());
            if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                if let Some(hash) = item.storage_plaintext_sha256.as_ref() {
                    entry_meta.recovery.storage_plaintext_sha256 = Some(hash.clone());
                }
                if let Some(transform) = item.text_transform.clone() {
                    push_transform_unique(entry_meta, TransformMeta::KirikiriText(transform));
                }
            }
            match &item.state {
                UnpackState::PlainRaw { format } => {
                    let relative = solved_item_relative_path(&item, format.as_deref());
                    let logical = item.name.replace('\\', "/");
                    let output = out_dir.join(&relative);
                    let asset =
                        write_unpack_asset_output(&output, &item.bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(
                        &mut xp3_meta,
                        item.index,
                        &logical,
                        &asset,
                        out_dir,
                    );
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "plain".to_string();
                        entry_meta.recovery.format = format.clone();
                    }
                    let output = asset.output;
                    solved += 1;
                    if verbose {
                        println!("entry[{}] plain {}", item.index, output.display());
                    }
                    report.push(format!(
                        "{}\tplain\t{}\t{}\t{}\t-\t{}\t-",
                        item.index,
                        report_name,
                        report_info_name,
                        report_hx_id,
                        report_field(&output.display().to_string())
                    ));
                }
                UnpackState::Recovered {
                    format,
                    period,
                    key,
                    brute_used,
                    mitm,
                    gpu,
                    gpu_adapter,
                    combinations,
                } => {
                    let relative = solved_item_relative_path(&item, Some(format.as_str()));
                    let logical = item.name.replace('\\', "/");
                    let output = out_dir.join(&relative);
                    let asset =
                        write_unpack_asset_output(&output, &item.bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(
                        &mut xp3_meta,
                        item.index,
                        &logical,
                        &asset,
                        out_dir,
                    );
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "per-file-repeating-xor".to_string();
                        entry_meta.recovery.format = Some(format.clone());
                        // Per-file recovery keys are persisted only when the
                        // solver actually had to brute-force them. Constraint/crib
                        // recovery is reproducible and does not belong in the
                        // repack manifest as stored key material.
                        entry_meta.recovery.repeating_xor = if *brute_used {
                            Some(RepeatingXorRecoveryMeta {
                                key: xp3_meta::repeating_xor_key(key),
                                brute_used: true,
                                mitm: *mitm,
                                gpu: *gpu,
                                gpu_adapter: gpu_adapter.clone(),
                                combinations: combinations.to_string(),
                            })
                        } else {
                            None
                        };
                    }
                    if *brute_used {
                        xp3_meta.keys.push(KeyMeta {
                            kind: "per-entry-repeating-xor".to_string(),
                            source: "validated-bruteforce".to_string(),
                            entry_index: Some(item.index),
                            logical_path: Some(logical.clone()),
                            repeating_xor: Some(xp3_meta::repeating_xor_key(key)),
                            u32_hex: None,
                            bytes_hex: None,
                        });
                    }
                    let output = asset.output;
                    solved += 1;
                    if verbose {
                        println!(
                            "entry[{}] recovered period={} format={} brute={} mitm={} gpu={} adapter={} combinations={} {}",
                            item.index, period, format, brute_used, mitm, gpu, gpu_adapter.as_deref().unwrap_or("-"), combinations, output.display()
                        );
                    }
                    report.push(format!("{}\trecovered\t{}\t{}\t{}\t{}\t{}\tperiod={};brute={};mitm={};gpu={};adapter={};combinations={}",
                        item.index, report_name, report_info_name, report_hx_id, report_field(format), report_field(&output.display().to_string()), period, brute_used, mitm, gpu, report_field(gpu_adapter.as_deref().unwrap_or("-")), combinations));
                }
                UnpackState::NativeCxdecRecovered {
                    format,
                    parameters,
                    hash,
                } => {
                    let relative = solved_item_relative_path(&item, Some(format.as_str()));
                    let logical = item.name.replace('\\', "/");
                    let output = out_dir.join(&relative);
                    let asset =
                        write_unpack_asset_output(&output, &item.bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(
                        &mut xp3_meta,
                        item.index,
                        &logical,
                        &asset,
                        out_dir,
                    );
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "native-cxdec".to_string();
                        entry_meta.recovery.format = Some(format.clone());
                        entry_meta.recovery.detail = Some(format!(
                            "parameters={};hash=0x{:08x};validation=adlr-or-strong-format", parameters, hash
                        ));
                    }
                    let output = asset.output;
                    solved += 1;
                    if verbose {
                        println!(
                            "entry[{}] native-cxdec parameters={} format={} hash=0x{:08x} {}",
                            item.index, parameters, format, hash, output.display()
                        );
                    }
                    report.push(format!(
                        "{}\tnative-cxdec\t{}\t{}\t{}\t{}\t{}\tparameters={};hash=0x{:08x};verified=adlr-or-strong-format",
                        item.index,
                        report_name,
                        report_info_name,
                        report_hx_id,
                        report_field(format),
                        report_field(&output.display().to_string()),
                        report_field(parameters),
                        hash,
                    ));
                }
                UnpackState::X86FilterRecovered {
                    format,
                    module,
                    callback,
                    source,
                    hash,
                } => {
                    let relative = solved_item_relative_path(&item, Some(format.as_str()));
                    let logical = item.name.replace('\\', "/");
                    let output = out_dir.join(&relative);
                    let asset =
                        write_unpack_asset_output(&output, &item.bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(
                        &mut xp3_meta,
                        item.index,
                        &logical,
                        &asset,
                        out_dir,
                    );
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "x86-emulated-filter".to_string();
                        entry_meta.recovery.format = Some(format.clone());
                        entry_meta.recovery.x86_filter = Some(X86FilterRecoveryMeta {
                            module_sha256: x86_filter_module_sha.clone().ok_or_else(|| {
                                LibraryError::Format(
                                    "x86-filter recovery lost its retained module".to_string(),
                                )
                            })?,
                            callback_va_hex: format!("0x{callback:08x}"),
                            callback_source: source.clone(),
                            file_hash_hex: format!("0x{hash:08x}"),
                        });
                    }
                    let output = asset.output;
                    solved += 1;
                    if verbose {
                        println!(
                            "entry[{}] x86-filter format={} callback=0x{:08x} hash=0x{:08x} source={} module={} {}",
                            item.index, format, callback, hash, source, module, output.display()
                        );
                    }
                    report.push(format!(
                        "{}\tx86-filter\t{}\t{}\t{}\t{}\t{}\tmodule={};callback=0x{:08x};hash=0x{:08x};source={}",
                        item.index,
                        report_name,
                        report_info_name,
                        report_hx_id,
                        report_field(format),
                        report_field(&output.display().to_string()),
                        report_field(module),
                        callback,
                        hash,
                        report_field(source),
                    ));
                }
                UnpackState::NativeHxRecovered {
                    format,
                    entry_key,
                    local_flag,
                    split,
                    left_xor,
                    right_xor,
                    corrections,
                } => {
                    let relative = solved_item_relative_path(&item, Some(format.as_str()));
                    let logical = item.name.replace('\\', "/");
                    let output = out_dir.join(&relative);
                    let asset =
                        write_unpack_asset_output(&output, &item.bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(
                        &mut xp3_meta,
                        item.index,
                        &logical,
                        &asset,
                        out_dir,
                    );
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "hxv4-native".to_string();
                        entry_meta.recovery.format = Some(format.clone());
                        entry_meta.recovery.hxv4_native = Some(Hxv4NativeRecoveryMeta {
                            entry_key_hex: format!("0x{:016x}", entry_key),
                            local_flag_hex: format!("0x{:04x}", local_flag),
                            split: *split,
                            left_xor_hex: format!("{:02x}", left_xor),
                            right_xor_hex: format!("{:02x}", right_xor),
                            corrections: *corrections,
                        });
                    }
                    let output = asset.output;
                    solved += 1;
                    if verbose {
                        println!(
                            "entry[{}] hx-native format={} entry_key={:016x} local_flag=0x{:04x} split={} span_xor={:02x}/{:02x} corrections={} {}",
                            item.index, format, entry_key, local_flag, split, left_xor, right_xor, corrections, output.display()
                        );
                    }
                    report.push(format!(
                        "{}\thx-native\t{}\t{}\t{}\t{}\t{}\tentry_key={:016x};local_flag=0x{:04x};split={};span_xor={:02x}/{:02x};corrections={};verified=native{}",
                        item.index,
                        report_name,
                        report_info_name,
                        report_hx_id,
                        report_field(format),
                        report_field(&output.display().to_string()),
                        entry_key,
                        local_flag,
                        split,
                        left_xor,
                        right_xor,
                        corrections,
                        if archive.entries[item.index].adler.is_some() { "+adler" } else { "" },
                    ));
                }
                UnpackState::HxRecovered {
                    format,
                    split,
                    left_xor,
                    right_xor,
                    corrections,
                    gpu,
                } => {
                    let relative = solved_item_relative_path(&item, Some(format.as_str()));
                    let logical = item.name.replace('\\', "/");
                    let output = out_dir.join(&relative);
                    let asset =
                        write_unpack_asset_output(&output, &item.bytes, decode_options, out_dir)?;
                    apply_asset_result_to_meta(
                        &mut xp3_meta,
                        item.index,
                        &logical,
                        &asset,
                        out_dir,
                    );
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "hxv4-effective-fallback".to_string();
                        entry_meta.recovery.format = Some(format.clone());
                        entry_meta.recovery.detail = Some(format!(
                            "split={};left_xor={:02x};right_xor={:02x};corrections={};gpu={}",
                            split, left_xor, right_xor, corrections, gpu
                        ));
                    }
                    let output = asset.output;
                    solved += 1;
                    if verbose {
                        println!("entry[{}] hx-recovered format={} split={} span_xor={:02x}/{:02x} corrections={} gpu={} {}", item.index, format, split, left_xor, right_xor, corrections, gpu, output.display());
                    }
                    report.push(format!("{}\thx-recovered\t{}\t{}\t{}\t{}\t{}\tsplit={};span_xor={:02x}/{:02x};corrections={};gpu={}",
                        item.index, report_name, report_info_name, report_hx_id, report_field(format), report_field(&output.display().to_string()), split, left_xor, right_xor, corrections, gpu));
                }
                UnpackState::NativeHxMismatch {
                    entry_key,
                    local_flag,
                    size,
                    split,
                    left_drip,
                    right_drip,
                    left_xor,
                    right_xor,
                    prefix_xor,
                    expected_adler,
                    actual_adler,
                } => {
                    unresolved += 1;
                    let prefix = prefix_xor
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    let branch = if native_before_split(*size, *split) {
                        "before-split"
                    } else {
                        "crossing-split"
                    };
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "hxv4-native-mismatch".to_string();
                        entry_meta.recovery.hxv4_native = Some(Hxv4NativeRecoveryMeta {
                            entry_key_hex: format!("0x{:016x}", entry_key),
                            local_flag_hex: format!("0x{:04x}", local_flag),
                            split: *split,
                            left_xor_hex: format!("{:02x}", left_xor),
                            right_xor_hex: format!("{:02x}", right_xor),
                            corrections: 0,
                        });
                        entry_meta.recovery.detail = Some(format!("branch={branch};left_drip={:016x};right_drip={:016x};prefix={prefix};expected_adler={:08x};actual_adler={:08x}", left_drip, right_drip, expected_adler, actual_adler));
                    }
                    eprintln!(
                        "[hxv4-native-state] entry={} entry_key={:016x} local_flag=0x{:04x} size={} split={} branch={} left_drip={:016x} right_drip={:016x} left_xor={:02x} right_xor={:02x} prefix={} adler_expected={:08x} adler_actual={:08x}; heuristic brute skipped",
                        item.index,
                        entry_key,
                        local_flag,
                        size,
                        split,
                        branch,
                        left_drip,
                        right_drip,
                        left_xor,
                        right_xor,
                        prefix,
                        expected_adler,
                        actual_adler,
                    );
                    report.push(format!(
                        "{}\thx-native-mismatch\t{}\t{}\t{}\t-\t{}\tentry_key={:016x};local_flag=0x{:04x};size={};split={};branch={};left_drip={:016x};right_drip={:016x};span_xor={:02x}/{:02x};prefix={};expected_adler={:08x};actual_adler={:08x};fallback=skipped",
                        item.index,
                        report_name,
                        report_info_name,
                        report_hx_id,
                        "<not-written>",
                        entry_key,
                        local_flag,
                        size,
                        split,
                        branch,
                        left_drip,
                        right_drip,
                        left_xor,
                        right_xor,
                        prefix,
                        expected_adler,
                        actual_adler,
                    ));
                }
                UnpackState::IgnoredProtectedDummy => {
                    ignored += 1;
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "ignored-protected-dummy".to_string();
                        entry_meta.recovery.detail = Some(
                            "synthetic protected-archive warning node; preserved as archive metadata and intentionally not extracted"
                                .to_string(),
                        );
                    }
                    if verbose {
                        println!(
                            "entry[{}] ignored-protected-dummy output=<not-written>",
                            item.index
                        );
                    }
                    report.push(format!(
                        "{}\tignored-protected-dummy\t{}\t{}\t{}\t-\t<not-written>\tarchive-metadata",
                        item.index, report_name, report_info_name, report_hx_id
                    ));
                }
                UnpackState::Unresolved => {
                    unresolved += 1;
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "unresolved".to_string();
                    }
                    if verbose {
                        println!("entry[{}] unresolved output=<not-written>", item.index);
                    }
                    report.push(format!(
                        "{}\tunresolved\t{}\t{}\t{}\t-\t<not-written>\t-",
                        item.index, report_name, report_info_name, report_hx_id
                    ));
                }
                UnpackState::ReconstructionFailed { error } => {
                    reconstruct_failed += 1;
                    unresolved += 1;
                    if let Some(entry_meta) = xp3_meta.entries.get_mut(item.index) {
                        entry_meta.recovery.status = "reconstruct-failed".to_string();
                        entry_meta.recovery.detail = Some(error.clone());
                    }
                    report.push(format!(
                        "{}\treconstruct-failed\t{}\t{}\t{}\t-\t<not-written>\t{}",
                        item.index,
                        report_name,
                        report_info_name,
                        report_hx_id,
                        report_field(error)
                    ));
                    eprintln!(
                        "entry[{}] reconstruct-failed name={} stored={} magic={} output=<not-written> error={}",
                        item.index,
                        item.name,
                        item.bytes.len(),
                        magic_label(&item.bytes),
                        error
                    );
                }
            }
            unpack_progress.tick();
            // `item` (including its potentially very large Vec<u8>) is dropped
            // here before the next batch is materialized.
        }
        batch_start = batch_end;
    }

    // `out_dir` is an extraction tree, not a diagnostic workspace.  The
    // in-memory report is intentionally dropped after console diagnostics.
    drop(report);
    println!(
        "summary total={} solved={} unresolved={} ignored={} reconstruct_failed={}",
        archive.entries.len(),
        solved,
        unresolved,
        ignored,
        reconstruct_failed
    );
    print_compute_summary();
    write_xp3_meta(out_dir, &mut xp3_meta)?;
    Ok(())
}

fn kirikiri_text_wrapper_mode(bytes: &[u8]) -> Option<u8> {
    if bytes.len() >= 5
        && bytes[0..2] == [0xfe, 0xfe]
        && bytes[3..5] == [0xff, 0xfe]
        && bytes[2] <= 2
    {
        Some(bytes[2])
    } else {
        None
    }
}

fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(2).saturating_add(2));
    out.extend_from_slice(&[0xff, 0xfe]);
    for word in text.encode_utf16() {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn cp932_to_utf16le_with_bom(bytes: &[u8]) -> Option<Vec<u8>> {
    let (text, had_errors) = SHIFT_JIS.decode_without_bom_handling(bytes);
    if had_errors {
        return None;
    }
    Some(utf16le_with_bom(&text))
}

#[derive(Debug)]
struct UserFacingTextResult {
    bytes: Vec<u8>,
    source_sha256: String,
    transform: Option<KirikiriTextTransformMeta>,
}

fn user_facing_text_asset(format: Option<&str>, bytes: Vec<u8>) -> UserFacingTextResult {
    let source_sha256 = xp3_meta::sha256_hex(&bytes);

    // KiriKiri's FE FE <mode> FF FE wrapper is an on-storage representation,
    // not a filename convention. XP3 Adler validation is deliberately done by
    // callers before this transform because the checksum covers the wrapper.
    if let Some(mode) = kirikiri_text_wrapper_mode(&bytes) {
        if let Some(decoded) = decode_kirikiri_text(&bytes) {
            let output_sha256 = xp3_meta::sha256_hex(&decoded);
            return UserFacingTextResult {
                bytes: decoded,
                source_sha256,
                transform: Some(KirikiriTextTransformMeta {
                    source_encoding_or_wrapper: format!("kirikiri-fe-fe-mode{mode}"),
                    output_encoding: "utf-16le".to_string(),
                    bom_hex: "fffe".to_string(),
                    output_sha256: Some(output_sha256),
                    kirikiri_wrapper_mode: Some(mode),
                    reversible_with_encoder: true,
                }),
            };
        }
    }

    // Plain Shift-JIS/CP932 has no BOM. Once the recovery/validator has already
    // proved this exact text model, normalize the extracted file to UTF-16LE.
    if format == Some("Text/CP932") {
        if let Some(decoded) = cp932_to_utf16le_with_bom(&bytes) {
            let output_sha256 = xp3_meta::sha256_hex(&decoded);
            return UserFacingTextResult {
                bytes: decoded,
                source_sha256,
                transform: Some(KirikiriTextTransformMeta {
                    source_encoding_or_wrapper: "cp932".to_string(),
                    output_encoding: "utf-16le".to_string(),
                    bom_hex: "fffe".to_string(),
                    output_sha256: Some(output_sha256),
                    kirikiri_wrapper_mode: None,
                    reversible_with_encoder: true,
                }),
            };
        }
    }

    UserFacingTextResult {
        bytes,
        source_sha256,
        transform: None,
    }
}

fn user_facing_text_bytes(_name: &str, format: Option<&str>, bytes: Vec<u8>) -> Vec<u8> {
    user_facing_text_asset(format, bytes).bytes
}

fn segment_method_label(flags: u32) -> &'static str {
    match flags & 0x07 {
        0 => "raw",
        1 => "zlib",
        _ => "unsupported",
    }
}

fn log_reconstruction_failure(archive: &Archive, index: usize, err: &LibraryError) {
    let Some(entry) = archive.entries.get(index) else {
        eprintln!("[reconstruct   ] failed entry[{index}] error={err}");
        return;
    };
    eprintln!(
        "[reconstruct   ] failed entry[{index}] name={} info_flags=0x{:08x} original_size={} archive_size={} segments={} error={err}",
        entry.preferred_name(),
        entry.flags,
        entry.original_size,
        entry.archive_size,
        entry.segments.len()
    );
    for (segment_index, segment) in entry.segments.iter().enumerate() {
        eprintln!(
            "[reconstruct   ]   segment[{segment_index}] method={} flags=0x{:08x} offset=0x{:x} original_size={} archive_size={}",
            segment_method_label(segment.flags),
            segment.flags,
            segment.archive_offset,
            segment.original_size,
            segment.archive_size
        );
    }
    let stored = archive.stored_entry_bytes(index).unwrap_or_default();
    eprintln!(
        "[reconstruct   ]   stored_bytes={} magic={}",
        stored.len(),
        magic_label(&stored)
    );
}

fn entry_relative_path(entry: &Entry, index: usize) -> PathBuf {
    if let Some(id) = entry.hxv4_id {
        PathBuf::from("_hxv4_id").join(format!("{id:08x}.bin"))
    } else {
        safe_relative_path(entry.preferred_name(), index)
    }
}

fn output_extension_is_generic(name: &str) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    ext.is_empty() || matches!(ext.as_str(), "bin" | "dat")
}

fn valid_output_extension(extension: &str) -> bool {
    !extension.is_empty()
        && extension.len() <= 16
        && extension
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn meaningful_output_extension(extension: &str) -> bool {
    valid_output_extension(extension)
        && !matches!(extension.to_ascii_lowercase().as_str(), "bin" | "dat")
}

fn canonical_magic_extension(bytes: &[u8]) -> Option<String> {
    let guess = sniff_bytes(bytes)?;
    let extensions: Vec<String> = guess
        .extensions
        .into_iter()
        .filter(|extension| meaningful_output_extension(extension))
        .collect();
    if extensions.len() == 1 {
        return extensions.into_iter().next();
    }

    // When a libmagic rule advertises aliases, do not choose one arbitrarily.
    // Use the MIME type (or a subtype-specific message for PE) only where it
    // determines a canonical extension; otherwise keep the generic filename.
    let canonical = match guess.mime_type.as_str() {
        "application/x-kirikiri-prerendered-font" => Some("tft"),
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/bmp" | "image/x-ms-bmp" => Some("bmp"),
        "image/tiff" => Some("tif"),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some("ico"),
        "audio/mpeg" => Some("mp3"),
        "audio/flac" | "audio/x-flac" => Some("flac"),
        "audio/ogg" | "application/ogg" => Some("ogg"),
        "video/ogg" => Some("ogv"),
        "video/webm" => Some("webm"),
        "video/x-matroska" => Some("mkv"),
        "audio/wav" | "audio/x-wav" => Some("wav"),
        "video/x-msvideo" => Some("avi"),
        "video/mp4" => Some("mp4"),
        "audio/mp4" => Some("m4a"),
        "application/zip" => Some("zip"),
        "application/gzip" | "application/x-gzip" => Some("gz"),
        "application/x-7z-compressed" => Some("7z"),
        "font/ttf" | "application/x-font-ttf" => Some("ttf"),
        "font/otf" | "application/x-font-opentype" => Some("otf"),
        "font/collection" => Some("ttc"),
        "font/woff" => Some("woff"),
        "font/woff2" => Some("woff2"),
        "text/plain" => Some("txt"),
        "text/html" => Some("html"),
        "text/css" => Some("css"),
        "text/javascript" | "application/javascript" => Some("js"),
        "application/json" => Some("json"),
        "application/xml" | "text/xml" => Some("xml"),
        "image/svg+xml" => Some("svg"),
        "application/pdf" => Some("pdf"),
        _ => None,
    };
    if let Some(canonical) = canonical {
        if extensions.is_empty()
            || extensions
                .iter()
                .any(|extension| extension.eq_ignore_ascii_case(canonical))
        {
            return Some(canonical.to_string());
        }
    }

    let message = guess.message.to_ascii_lowercase();
    if message.contains("pe32") || message.contains("portable executable") {
        if message.contains("(dll)") || message.contains("dynamic link library") {
            return Some("dll".to_string());
        }
        if message.contains("executable") {
            return Some("exe".to_string());
        }
    }
    None
}

fn canonical_format_extension(format: &str) -> Option<&'static str> {
    let extension = format_extension(format);
    (extension != "bin").then_some(extension)
}

fn refine_generic_output_name(name: &str, format: Option<&str>, bytes: &[u8]) -> String {
    if !output_extension_is_generic(name) {
        return name.to_string();
    }

    let extension = format
        .and_then(canonical_format_extension)
        .map(|extension| extension.to_string())
        .or_else(|| {
            strong_builtin_format(bytes).and_then(|format| {
                canonical_format_extension(&format).map(|extension| extension.to_string())
            })
        })
        .or_else(|| canonical_magic_extension(bytes));
    let Some(extension) = extension.filter(|extension| meaningful_output_extension(extension))
    else {
        return name.to_string();
    };

    let mut path = PathBuf::from(name);
    path.set_extension(extension);
    path.to_string_lossy().into_owned()
}

fn solved_item_relative_path(item: &UnpackEntry, format: Option<&str>) -> PathBuf {
    let refined = refine_generic_output_name(&item.name, format, &item.bytes);
    if refined != item.name {
        eprintln!(
            "[format-name   ] entry={} old={} new={} format={}",
            item.index,
            item.name,
            refined,
            format.unwrap_or("libmagic"),
        );
    }
    safe_relative_path(&refined, item.index)
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn magic_label(bytes: &[u8]) -> String {
    sniff_bytes(bytes)
        .map(|guess| {
            format!(
                "{}|{}|strength={}",
                guess.mime_type,
                guess.message.replace(' ', "_"),
                guess.strength
            )
        })
        .unwrap_or_else(|| "n/a".to_string())
}

fn report_field(value: &str) -> String {
    value
        .replace('\t', " ")
        .replace('\r', " ")
        .replace('\n', " ")
}

fn write_output(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

fn is_tlg_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"TLG0.0\0sds\x1a")
        || bytes.starts_with(b"TLG5.0\0raw\x1a")
        || bytes.starts_with(b"TLG6.0\0raw\x1a")
}

#[derive(Debug)]
struct AssetWriteResult {
    output: PathBuf,
    transforms: Vec<TransformMeta>,
    keys: Vec<KeyMeta>,
}

fn tlg_codec_meta(codec: &TlgCodecInfo) -> TlgCodecMeta {
    match codec {
        TlgCodecInfo::Tlg5 { block_height } => TlgCodecMeta::Tlg5 {
            block_height: *block_height,
        },
        TlgCodecInfo::Tlg6 {
            data_flag,
            color_type,
            external_golomb_table,
            max_bit_length,
        } => TlgCodecMeta::Tlg6 {
            data_flag: *data_flag,
            color_type: *color_type,
            external_golomb_table: *external_golomb_table,
            max_bit_length: *max_bit_length,
        },
    }
}

fn tlg_container_meta(bytes: &[u8], container: &xp3_brute::TlgContainerInfo) -> TlgContainerMeta {
    let chunks = container
        .chunks
        .iter()
        .enumerate()
        .filter_map(|(order, chunk)| {
            let end = chunk.data_offset.checked_add(chunk.size as usize)?;
            let payload = bytes.get(chunk.data_offset..end)?;
            Some(TlgContainerChunkMeta {
                name: chunk.name.clone(),
                order,
                payload_base64: xp3_meta::b64(payload),
            })
        })
        .collect();
    TlgContainerMeta {
        raw_offset: container.raw_offset,
        raw_size: container.raw_size,
        chunks,
    }
}

/// Apply user-requested archive-output conversion without changing recovery.
fn output_is_tjs(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tjs"))
}

fn render_tjs2_user_source(bytes: &[u8], mode: UnpackTjsMode) -> Result<Vec<u8>, String> {
    let file = load_tjs2_bytecode(bytes)
        .map_err(|err| format!("tjs2dec bytecode load failed: {err}"))?;
    let source = match mode {
        UnpackTjsMode::Emit => emit_executable_tjs(&file)
            .map_err(|err| format!("tjs2dec executable-TJS emission failed: {err}"))?,
        UnpackTjsMode::Decompile => dump_tjs_source_high(&file)
            .map_err(|err| format!("tjs2dec high-level decompile failed: {err}"))?,
        UnpackTjsMode::None => {
            return Err("TJS conversion requested with mode=none".to_string())
        }
    };

    // KiriKiri source scripts are written as ordinary text, not recompiled
    // TJS2 bytecode. UTF-16LE+BOM is already the canonical editable text
    // representation used by this unpacker and is accepted by KiriKiri's text
    // loader without depending on the host locale.
    Ok(utf16le_with_bom(&source))
}

/// Every destructive/derived conversion returns a manifest record sufficient
/// for a future repacker to reconnect the edited artifact to its source asset.
/// TJS2 source conversion is intentionally *not* recorded as a reversible
/// transform: the unpacked `.tjs` becomes authoritative source text and pack
/// writes that text back directly rather than trying to compile it to bytecode.
/// TLG is an image, so conversion replaces the raw TLG output. PSB is a
/// model/container, so the PSB itself is retained while derived resource blobs
/// are exported when requested.
fn write_unpack_asset_output(
    output: &Path,
    bytes: &[u8],
    options: &UnpackDecodeOptions,
    meta_root: &Path,
) -> Result<AssetWriteResult, Box<dyn std::error::Error>> {
    let rendered_tjs = if !matches!(options.tjs, UnpackTjsMode::None)
        && output_is_tjs(output)
        && bytes.starts_with(b"TJS2100\0")
    {
        match render_tjs2_user_source(bytes, options.tjs) {
            Ok(source) => {
                eprintln!(
                    "[tjs           ] file={} mode={} output=same-path encoding=utf-16le",
                    output.display(),
                    options.tjs.label(),
                );
                Some(source)
            }
            Err(err) => {
                eprintln!(
                    "[tjs           ] file={} mode={} failed: {}; preserving original TJS2 bytecode",
                    output.display(),
                    options.tjs.label(),
                    err,
                );
                None
            }
        }
    } else {
        None
    };
    let bytes = rendered_tjs.as_deref().unwrap_or(bytes);

    if let Some(format) = options.tlg.tlg_format() {
        if is_tlg_bytes(bytes) {
            match decode_tlg(bytes) {
                Ok(decoded) => {
                    let mut converted = output.to_path_buf();
                    converted.set_extension(format.extension());
                    export_decoded_tlg(
                        &decoded,
                        &converted,
                        TlgExportOptions {
                            format,
                            jpeg_quality: 95,
                        },
                    )?;
                    let converted_sha256 = xp3_meta::sha256_hex(&fs::read(&converted)?);
                    if converted != output && output.exists() {
                        let _ = fs::remove_file(output);
                    }
                    eprintln!(
                        "[tlg           ] source={} output={} format={} version={} container={}",
                        output.display(),
                        converted.display(),
                        format.extension(),
                        decoded.info.version.as_str(),
                        if decoded.info.container.is_some() {
                            "TLG0/SDS"
                        } else {
                            "raw"
                        },
                    );
                    let transform = TransformMeta::TlgImage(TlgTransformMeta {
                        source_asset_path: xp3_meta::relative_path(meta_root, output),
                        source_size: bytes.len(),
                        source_sha256: xp3_meta::sha256_hex(bytes),
                        output_path: xp3_meta::relative_path(meta_root, &converted),
                        output_format: format.extension().to_string(),
                        output_sha256: Some(converted_sha256),
                        lossless_pixels: !matches!(format, TlgExportFormat::Jpeg),
                        version: decoded.info.version.as_str().to_string(),
                        width: decoded.info.width,
                        height: decoded.info.height,
                        components: decoded.info.components,
                        decoded_rgba_sha256: xp3_meta::sha256_hex(&decoded.rgba),
                        codec: tlg_codec_meta(&decoded.info.codec),
                        container: decoded
                            .info
                            .container
                            .as_ref()
                            .map(|container| tlg_container_meta(bytes, container)),
                    });
                    return Ok(AssetWriteResult {
                        output: converted,
                        transforms: vec![transform],
                        keys: Vec::new(),
                    });
                }
                Err(err) => {
                    eprintln!(
                        "[tlg           ] source={} requested={} decode failed: {}; preserving raw TLG",
                        output.display(), options.tlg.label(), err
                    );
                }
            }
        }
    }

    write_output(output, bytes)?;
    let mut transforms = postprocess_pbd_output(output, bytes, options.pbd, meta_root);
    let (psb_transforms, keys) = postprocess_psb_output(output, bytes, options.psb, meta_root);
    transforms.extend(psb_transforms);
    transforms.extend(postprocess_amv_output(
        output,
        bytes,
        options.amv,
        meta_root,
    ));
    Ok(AssetWriteResult {
        output: output.to_path_buf(),
        transforms,
        keys,
    })
}

fn postprocess_amv_output(
    output: &Path,
    bytes: &[u8],
    mode: UnpackAmvMode,
    meta_root: &Path,
) -> Vec<TransformMeta> {
    let mut transforms = Vec::new();
    if !is_amv_bytes(bytes) {
        return transforms;
    }
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("movie.amv");
    let frames_dir = output.with_file_name(format!("{file_name}.frames"));
    if matches!(mode, UnpackAmvMode::None) {
        if frames_dir.is_dir() {
            let _ = fs::remove_dir_all(&frames_dir);
        }
        return transforms;
    }
    let decoded = match decode_amv(bytes) {
        Ok(decoded) => decoded,
        Err(err) => {
            eprintln!(
                "[amv           ] file={} decode failed: {}",
                output.display(),
                err
            );
            return transforms;
        }
    };
    if frames_dir.is_dir() {
        if let Err(err) = fs::remove_dir_all(&frames_dir) {
            eprintln!(
                "[amv           ] stale frame cleanup failed {}: {}",
                frames_dir.display(),
                err
            );
            return transforms;
        }
    }
    let paths = match export_amv_frames(&decoded, &frames_dir) {
        Ok(paths) => paths,
        Err(err) => {
            eprintln!(
                "[amv           ] frame export failed {}: {}",
                frames_dir.display(),
                err
            );
            return transforms;
        }
    };
    let duration_ms = u64::from(decoded.info.fps_num)
        .checked_mul(1000)
        .map(|value| value / u64::from(decoded.info.fps_den));
    let source_path = xp3_meta::relative_path(meta_root, output);
    let source_sha256 = xp3_meta::sha256_hex(bytes);
    for (index, path) in paths.into_iter().enumerate() {
        let output_sha256 = fs::read(&path)
            .ok()
            .map(|frame| xp3_meta::sha256_hex(&frame));
        transforms.push(TransformMeta::AmvFrame(AmvFrameTransformMeta {
            source_container_path: source_path.clone(),
            source_size: bytes.len(),
            source_sha256: source_sha256.clone(),
            output_path: xp3_meta::relative_path(meta_root, &path),
            frame_index: index,
            output_format: "png".to_string(),
            output_sha256,
            lossless_pixels: true,
            frame_duration_ms: duration_ms,
            container_variant: Some(decoded.info.variant.label().to_string()),
            width: Some(decoded.info.width),
            height: Some(decoded.info.height),
            frame_count: Some(decoded.info.frame_count),
            fps_num: Some(decoded.info.fps_num),
            fps_den: Some(decoded.info.fps_den),
            attr: Some(decoded.info.attr),
            source_container_retained: true,
        }));
    }
    eprintln!(
        "[amv           ] file={} variant={} frames={} dimensions={}x{} fps={}/{} output={}",
        output.display(),
        decoded.info.variant.label(),
        decoded.info.frame_count,
        decoded.info.width,
        decoded.info.height,
        decoded.info.fps_den,
        decoded.info.fps_num,
        frames_dir.display()
    );
    transforms
}

fn postprocess_pbd_output(
    output: &Path,
    bytes: &[u8],
    mode: UnpackPbdMode,
    meta_root: &Path,
) -> Vec<TransformMeta> {
    let mut transforms = Vec::new();
    if !is_pbd_bytes(bytes) {
        return transforms;
    }
    let decoded = match decode_pbd(bytes) {
        Ok(decoded) => decoded,
        Err(err) => {
            eprintln!(
                "[pbd           ] file={} structural decode failed: {}",
                output.display(),
                err
            );
            return transforms;
        }
    };
    eprintln!(
        "[pbd           ] file={} variant={} seed=0x{:08x} crypt={} iv_len={} mode={}",
        output.display(),
        decoded.header.variant.label(),
        decoded.header.seed,
        decoded.header.crypt,
        decoded.header.iv.len(),
        mode.label(),
    );

    let json_path = pbd_json_output_path(output);
    if matches!(mode, UnpackPbdMode::None) {
        // A rerun with --pbd none must not leave a stale derived file that
        // would later be mistaken for an editable repack source.
        let _ = fs::remove_file(&json_path);
        return transforms;
    }

    match export_pbd_json(bytes, output) {
        Ok(written) => {
            let json_bytes = match fs::read(&written) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!(
                        "[pbd-json      ] output={} metadata read failed: {}",
                        written.display(),
                        err
                    );
                    return transforms;
                }
            };
            let json = decoded.to_json_document();
            eprintln!(
                "[pbd-json      ] output={} schema={}",
                written.display(),
                PBD_JSON_SCHEMA
            );
            transforms.push(TransformMeta::PbdJson(PbdJsonTransformMeta {
                source_binary_path: xp3_meta::relative_path(meta_root, output),
                source_size: bytes.len(),
                source_sha256: xp3_meta::sha256_hex(bytes),
                output_path: xp3_meta::relative_path(meta_root, &written),
                output_sha256: xp3_meta::sha256_hex(&json_bytes),
                schema: PBD_JSON_SCHEMA.to_string(),
                variant: json.format.variant,
                seed_hex: json.format.seed_hex,
                crypt: json.format.crypt,
                iv_hex: json.format.iv_hex,
                trailer_hex: json.format.trailer_hex,
                lz4_block_size: json.format.lz4_block_size,
                lz4_terminated: json.format.lz4_terminated,
                source_binary_retained: true,
                repack_strategy: "variant-preserving-pbd-v1".to_string(),
            }));
        }
        Err(err) => eprintln!(
            "[pbd-json      ] file={} export failed: {}",
            output.display(),
            err
        ),
    }
    transforms
}

fn log_psb_key_source(source: PsbKeySource, context: &str) {
    match source {
        PsbKeySource::None => {}
        PsbKeySource::Cached(key) => {
            eprintln!("[psb-key       ] reuse=0x{key:08x} source={context}");
        }
        PsbKeySource::Bruteforced { key, tested_keys } => {
            eprintln!(
                "[psb-key       ] found=0x{key:08x} tested={} source={} cache=global",
                tested_keys, context
            );
        }
    }
}

fn prime_psb_global_key(bytes: &[u8], context: &str) {
    if !is_psb_family_bytes(bytes) {
        return;
    }
    match decode_psb_with_global_key(bytes) {
        Ok(Some(decoded)) => log_psb_key_source(decoded.key_source, context),
        Ok(None) => {}
        Err(err) => eprintln!(
            "[psb           ] source={} parse/key-recovery failed: {}",
            context, err
        ),
    }
}

fn psb_wrapper_label(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"PSB\0") {
        "raw-psb"
    } else if bytes.starts_with(b"mdf") {
        "mdf"
    } else if bytes.starts_with(&0x184D_2204u32.to_le_bytes()) {
        "lz4-frame"
    } else {
        "unknown"
    }
}

fn psb_source_meta(
    output: &Path,
    bytes: &[u8],
    decoded: &xp3_brute::DecodedPsb,
    meta_root: &Path,
) -> PsbSourceMeta {
    PsbSourceMeta {
        source_binary_path: xp3_meta::relative_path(meta_root, output),
        source_size: bytes.len(),
        source_sha256: xp3_meta::sha256_hex(bytes),
        normalized_size: decoded.normalized.len(),
        normalized_sha256: xp3_meta::sha256_hex(&decoded.normalized),
        wrapper: psb_wrapper_label(bytes).to_string(),
        psb_version: decoded.psb.version as u64,
        encrypted_input: decoded.psb.encrypted,
        emote_key_hex: match decoded.key_source {
            PsbKeySource::Bruteforced { key, .. } => Some(format!("0x{key:08x}")),
            PsbKeySource::Cached(_) | PsbKeySource::None => None,
        },
    }
}

fn postprocess_psb_output(
    output: &Path,
    bytes: &[u8],
    mode: UnpackPsbMode,
    meta_root: &Path,
) -> (Vec<TransformMeta>, Vec<KeyMeta>) {
    let mut transforms = Vec::new();
    let mut keys = Vec::new();
    if !is_psb_family_bytes(bytes) {
        return (transforms, keys);
    }
    let decoded = match decode_psb_with_global_key(bytes) {
        Ok(Some(decoded)) => decoded,
        Ok(None) => return (transforms, keys),
        Err(err) => {
            eprintln!(
                "[psb           ] file={} parse/key-recovery failed: {}",
                output.display(),
                err
            );
            return (transforms, keys);
        }
    };
    log_psb_key_source(decoded.key_source, &output.display().to_string());
    eprintln!(
        "[psb           ] file={} version={} resources={} extra_resources={} encrypted_input={} normalized_bytes={} mode={}",
        output.display(),
        decoded.psb.version,
        decoded.psb.resources.len(),
        decoded.psb.extra_resources.len(),
        decoded.psb.encrypted,
        decoded.normalized.len(),
        mode.label(),
    );

    if let PsbKeySource::Bruteforced { key, tested_keys } = decoded.key_source {
        keys.push(KeyMeta {
            kind: "emote-psb-key".to_string(),
            source: format!("emote-bruteforce;tested={tested_keys}"),
            entry_index: None,
            logical_path: Some(xp3_meta::relative_path(meta_root, output)),
            repeating_xor: None,
            u32_hex: Some(format!("0x{key:08x}")),
            bytes_hex: None,
        });
    }

    let source_meta = psb_source_meta(output, bytes, &decoded, meta_root);
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("asset.psb");
    let resource_dir = output.with_file_name(format!("{file_name}.resources"));
    // Clean the namespace used by the older Emote-only exporter as well.
    let legacy_texture_dir = output.with_file_name(format!("{file_name}.textures"));
    let json_path = psb_json_output_path(output);

    if mode.wants_json() {
        if matches!(mode, UnpackPsbMode::Json) {
            for dir in [&resource_dir, &legacy_texture_dir] {
                if dir.is_dir() {
                    if let Err(err) = fs::remove_dir_all(dir) {
                        eprintln!(
                            "[psb-resource  ] stale resource cleanup failed {}: {}",
                            dir.display(),
                            err
                        );
                    }
                }
            }
        }
        match export_psb_root_json(&decoded, output) {
            Ok(path) => {
                eprintln!(
                    "[psb-json      ] file={} output={} schema=psb-root-v1",
                    output.display(),
                    path.display()
                );
                let output_sha256 = fs::read(&path)
                    .ok()
                    .map(|bytes| xp3_meta::sha256_hex(&bytes));
                transforms.push(TransformMeta::PsbRootJson(PsbRootJsonTransformMeta {
                    source: source_meta.clone(),
                    output_path: xp3_meta::relative_path(meta_root, &path),
                    output_sha256,
                    schema: PSB_ROOT_JSON_SCHEMA.to_string(),
                    source_binary_retained: true,
                }));
            }
            Err(err) => eprintln!(
                "[psb-json      ] file={} export failed: {}",
                output.display(),
                err
            ),
        }
        if matches!(mode, UnpackPsbMode::Json) {
            return (transforms, keys);
        }
    }

    if !mode.wants_json() && json_path.is_file() {
        if let Err(err) = fs::remove_file(&json_path) {
            eprintln!(
                "[psb-json      ] stale JSON cleanup failed {}: {}",
                json_path.display(),
                err
            );
        }
    }

    let Some(format) = mode.texture_format() else {
        for dir in [&resource_dir, &legacy_texture_dir] {
            if dir.is_dir() {
                if let Err(err) = fs::remove_dir_all(dir) {
                    eprintln!(
                        "[psb-resource  ] stale resource cleanup failed {}: {}",
                        dir.display(),
                        err
                    );
                }
            }
        }
        return (transforms, keys);
    };

    if legacy_texture_dir.is_dir() {
        if let Err(err) = fs::remove_dir_all(&legacy_texture_dir) {
            eprintln!(
                "[psb-resource  ] stale legacy texture cleanup failed {}: {}",
                legacy_texture_dir.display(),
                err
            );
        }
    }

    let include_unknown_raw = matches!(mode, UnpackPsbMode::All);
    match export_psb_resources_detailed(&decoded, output, format, include_unknown_raw) {
        Ok(records) if !records.is_empty() => {
            let image_count = records.iter().filter(|record| !record.raw_blob).count();
            let raw_count = records.len().saturating_sub(image_count);
            eprintln!(
                "[psb-resource  ] file={} files={} images={} raw={} image_format={}",
                output.display(),
                records.len(),
                image_count,
                raw_count,
                format.extension(),
            );
            for record in records {
                if record.raw_blob {
                    eprintln!(
                        "[psb-blob      ] table={} index={} semantic={} object={} output={}{}",
                        record.table.label(),
                        record.resource_index,
                        record.semantic.as_deref().unwrap_or("unknown"),
                        record.object_path.as_deref().unwrap_or("-"),
                        record.path.display(),
                        record
                            .decode_error
                            .as_deref()
                            .map(|error| format!(" decode_error={error}"))
                            .unwrap_or_default(),
                    );
                    transforms.push(TransformMeta::PsbResourceBlob(
                        PsbResourceBlobTransformMeta {
                            source: source_meta.clone(),
                            output_path: xp3_meta::relative_path(meta_root, &record.path),
                            source_binary_retained: true,
                            resource_table: record.table.label().to_string(),
                            resource_index: record.resource_index,
                            blob_size: record.source_blob_size,
                            blob_sha256: record.source_blob_sha256,
                            semantic_candidate: record.semantic,
                            object_path: record.object_path,
                            full_width: record.full_width,
                            full_height: record.full_height,
                            palette_resource_table: record
                                .palette_table
                                .map(|table| table.label().to_string()),
                            palette_resource_index: record.palette_index,
                            decode_error: record.decode_error,
                        },
                    ));
                    continue;
                }

                let Some(exported_format) = record.exported_format else {
                    continue;
                };
                eprintln!(
                    "[psb-image     ] table={} index={} semantic={} object={} output={}",
                    record.table.label(),
                    record.resource_index,
                    record.semantic.as_deref().unwrap_or("fallback"),
                    record.object_path.as_deref().unwrap_or("-"),
                    record.path.display()
                );
                let output_sha256 = fs::read(&record.path)
                    .ok()
                    .map(|bytes| xp3_meta::sha256_hex(&bytes));
                transforms.push(TransformMeta::PsbTexture(PsbTextureTransformMeta {
                    source: source_meta.clone(),
                    output_path: xp3_meta::relative_path(meta_root, &record.path),
                    output_sha256,
                    output_format: exported_format.extension().to_string(),
                    lossless_pixels: !matches!(exported_format, EmoteTextureExportFormat::Jpeg),
                    source_binary_retained: true,
                    resource_table: record.table.label().to_string(),
                    resource_index: record.resource_index,
                    name: record.name,
                    width: record.width.unwrap_or(0),
                    height: record.height.unwrap_or(0),
                    semantic: record.semantic,
                    object_path: record.object_path,
                    full_width: record.full_width,
                    full_height: record.full_height,
                    palette_resource_table: record
                        .palette_table
                        .map(|table| table.label().to_string()),
                    palette_resource_index: record.palette_index,
                    source_format: record.source_format,
                    compress: record.compress,
                    bit_count: record.bit_count,
                    spec: record.spec,
                    emote_key_hex: match decoded.key_source {
                        PsbKeySource::Bruteforced { key, .. } => Some(format!("0x{key:08x}")),
                        PsbKeySource::Cached(_) | PsbKeySource::None => None,
                    },
                }));
            }
        }
        Ok(_) => {}
        Err(err) => eprintln!(
            "[psb-resource  ] file={} blob decode/export failed: {}",
            output.display(),
            err
        ),
    }
    (transforms, keys)
}

fn print_periods(ranked: &[xp3_brute::PeriodCandidate], top: usize) {
    for (i, candidate) in ranked.iter().take(top).enumerate() {
        println!(
            "rank={} period={} conflicts={} conflict_weight={} agreements={} agreement_weight={} known={}/{} implied_plaintext={}",
            i + 1,
            candidate.period,
            candidate.conflicts,
            candidate.conflict_weight,
            candidate.agreements,
            candidate.agreement_weight,
            candidate.known_slots,
            candidate.period,
            candidate.implied_plaintext_bytes
        );
    }
}

fn safe_relative_path(name: &str, index: usize) -> PathBuf {
    let normalized = name.replace('\\', "/");
    let path = Path::new(&normalized);
    let mut clean = PathBuf::new();
    for component in path.components() {
        if let Component::Normal(value) = component {
            clean.push(value);
        }
    }
    if clean.as_os_str().is_empty() {
        PathBuf::from(format!("entry_{index:06}.bin"))
    } else {
        clean
    }
}

fn usage() {
    eprintln!(
        "xp3brute\n\
         \n\
         Commands:\n\
           devices\n\
           decode-pbd <input.pbd> [output.json]\n\
           encode-pbd|pack-pbd <input.json> <output.pbd>\n\
           encode-amv|pack-amv <frames-dir> <output.amv> [--fps N] [--quality 1..=100]\n\
           encode-tlg|pack-tlg <input.png|jpg|bmp> <output.tlg> [--components 1|3|4] [--allow-lossy]\n\
           rebuild-assets|encode-assets <unpack-dir> [--out-dir DIR|--in-place] [--allow-lossy]\n\
           verify-roundtrip <unpack-dir> [--output FILE] [--source-archive ORIGINAL.xp3]\n\
                            [--rebuilt-dir DIR] [--allow-lossy] [--compact-layout] [--json]\n\
           pack|pack-xp3 <unpack-dir> <output.xp3> [--source-archive ORIGINAL.xp3] [--rebuilt-dir DIR]\n\
                         [--no-rebuild-assets] [--allow-lossy] [--compact-layout] [--verbose]\n\
           decode-tlg <input.tlg> <output.png|jpg|bmp> [--format png|jpg|jpeg|bmp]\n\
                      [--jpeg-quality 1..100] [--show-tags]\n\
           pe-unpack|pe-normalize <packed.exe> <output.exe>\n\
           filter-probe <game.exe|module.dll|plugin.tpm|game-dir> [--static-only|--dynamic-v2link] [--trace-code]\n\
           filter-apply <module.dll|plugin.tpm> <input> <output> --hash N [--offset N] [--trace-code]\n\
           exe-analyze <game.exe> [--archive data.xp3] [--dump-bootstrap FILE] [--dump-startup FILE]\n\
           inspect <archive> [--special-max-period 1..4096] [--special-xor-key HEX]\n\
                   [--special-xor-scope prefix|whole]\n\
                   [--exe game.exe] [--no-exe-auto] [--hx-key HEX64 --hx-nonce HEX48]\n\
                   [--hx-names HxNames.lst] [--name-dict FILE]\n\
           scan-special <archive> [--special-max-period 1..4096]\n\
                        [--special-xor-key HEX --special-xor-scope prefix|whole]\n\
           decode-special <archive> <output> [--special-max-period 1..4096]\n\
                          [--special-xor-key HEX --special-xor-scope prefix|whole]\n\
                          [--exe game.exe] [--no-exe-auto] [--hx-key HEX64 --hx-nonce HEX48]\n\
           dump-special <archive> <output>\n\
           hx-index <archive> [--exe game.exe] [--no-exe-auto] [--hx-key HEX64 --hx-nonce HEX48]\n\
                    [--hx-names HxNames.lst] [--name-dict FILE] [--out FILE]\n\
           extract-raw <archive> <out-dir>\n\
           shared-probe <archive> [--max-period N] [--top N] [--no-progress]\n\
           unpack <archive> <out-dir> [--max-period N] [--top-periods N] [--exhaustive-dynamic]\n\
                  [--compute auto|cpu|gpu|hybrid] [--special-max-period 1..4096]\n\
                  [--special-xor-key HEX --special-xor-scope prefix|whole]\n\
                  [--exe game.exe] [--no-exe-auto] [--hx-key HEX64 --hx-nonce HEX48] [--hx-names HxNames.lst]\n\
                  [--name-dict FILE] [--hx-game-dir DIR] [--no-hx-name-bootstrap]\n\
                  [--filter-exe game.exe|module.dll|plugin.tpm|game-dir]\n\
                  [--unpacker-all] [--tjs emit|decompile|none] [--tlg png|jpg|bmp|none]\n\
                  [--psb all|json|png|jpg|bmp|none] [--pbd json|none] [--amv png|none]\n\
                  [--no-progress] [--verbose]\n\
                  (normal unpack defaults to no derived conversion; --unpacker-all enables\n\
                   TJS2->high-level source, TLG->PNG, PSB-family->JSON+PNG image blobs+raw unknown blobs,\n\
                   PBD->JSON, and AMV->PNG frames; explicit per-decoder options override --unpacker-all\n\
                   regardless of command-line order)\n\
           probe <archive> [--max-period N] [--top N] [--exhaustive-dynamic] [--compute auto|cpu|gpu|hybrid]\n\
           xor-recover <file> [--min-period N] [--max-period N] [--top N] --crib OFFSET:HEX ...\n\
         \n\
         Historical special-index recovery follows KrkrExtract semantics:\n\
           descriptor -> stored blob -> optional transform of first min(size,0x100) bytes\n\
                      -> zlib -> sequential M2/Yuzu chunks -> order/hash/name-length validation.\n\
         --special-max-period controls the structured whole-blob repeating-XOR attack (default 1024);\n\
         exact M2 size/adlr/name-length constraints recover large keys without exhaustive search.\n\
         The historical zlib/gzip decompressor-oracle brute force remains capped at period 5.\n\
         --special-xor-key supplies a known byte keystream directly.  A title-specific native\n\
         CxFilter that is not equivalent to these bounded models remains unresolved rather than\n\
         fabricating names.  Structured special-index recovery uses CPU/Rayon; wgpu remains\n\
         available for the large regular content-recovery kernels.\n\
         Hxv4 Special is a separate authenticated envelope: tag[16] + XChaCha20 ciphertext.\n\
         Descriptor bit 0 selects nonce slot 0/1.  Repeating-XOR/M2 period attacks are skipped.\n\
         By default HXV4 scans sibling/parent EXEs, unwraps embedded PE images, decrypts bres\n\
         STARTUP.TJS + BOOTSTRAP, reproduces the FilterManager KDF, and accepts key material\n\
         only after Poly1305 + zlib + native Hx-object parsing succeeds.  --exe selects an\n\
         explicit container; --hx-key/--hx-nonce remains the highest-priority manual override.\n\
         unpack fails closed until this Special gate succeeds; entry reconstruction/solve never\n\
         runs with a locked Hxv4 Special.\n\
         Hash-only HXV4 indices run a game-wide exact hash-name bootstrap before ordinary content recovery.\n\
         Resolved names are tried first. At the first hash-name fixed point, unresolved entries may be\n\
         recovered through filename-independent strong format hypotheses only to mine more exact hash candidates;\n\
         synthetic format names never satisfy the filename gate by themselves.\n\
         startup.tjs is a data.xp3 bootstrap anchor, not an invariant of sibling HXV4 archives.\n\
         extract-raw reconstructs XP3 raw/zlib segments but does not apply a title-specific\n\
         extraction filter."
    );
}
#[cfg(test)]
mod cli_routing_tests {
    use super::*;

    #[test]
    fn unpack_image_conversion_defaults_to_none_and_accepts_expected_formats() {
        let defaults = UnpackDecodeOptions::default();
        assert_eq!(defaults.tjs, UnpackTjsMode::None);
        assert_eq!(defaults.tlg, UnpackImageMode::None);
        assert_eq!(defaults.psb, UnpackPsbMode::None);
        assert_eq!(defaults.pbd, UnpackPbdMode::None);
        assert_eq!(defaults.amv, UnpackAmvMode::None);

        let all = UnpackDecodeOptions::all_decoder_defaults();
        assert_eq!(all.tjs, UnpackTjsMode::Decompile);
        assert_eq!(all.tlg, UnpackImageMode::Png);
        assert_eq!(all.psb, UnpackPsbMode::All);
        assert_eq!(all.pbd, UnpackPbdMode::Json);
        assert_eq!(all.amv, UnpackAmvMode::Png);
        assert!(all.psb.wants_json());
        assert_eq!(
            all.psb.texture_format(),
            Some(EmoteTextureExportFormat::Png)
        );

        assert_eq!(
            UnpackImageMode::parse("png", "--tlg").unwrap(),
            UnpackImageMode::Png
        );
        assert_eq!(
            UnpackImageMode::parse("jpeg", "--tlg").unwrap(),
            UnpackImageMode::Jpeg
        );
        assert_eq!(UnpackPsbMode::parse("bmp").unwrap(), UnpackPsbMode::Bmp);
        assert_eq!(UnpackPsbMode::parse("json").unwrap(), UnpackPsbMode::Json);
        assert_eq!(UnpackPsbMode::parse("all").unwrap(), UnpackPsbMode::All);
        assert_eq!(UnpackPsbMode::parse("none").unwrap(), UnpackPsbMode::None);
        assert_eq!(UnpackPbdMode::parse("json").unwrap(), UnpackPbdMode::Json);
        assert_eq!(UnpackPbdMode::parse("none").unwrap(), UnpackPbdMode::None);
        assert_eq!(UnpackAmvMode::parse("png").unwrap(), UnpackAmvMode::Png);
        assert_eq!(UnpackTjsMode::parse("emit").unwrap(), UnpackTjsMode::Emit);
        assert_eq!(
            UnpackTjsMode::parse("decompile").unwrap(),
            UnpackTjsMode::Decompile
        );
        assert!(UnpackTjsMode::parse("source").is_err());
        assert!(UnpackImageMode::parse("webp", "--tlg").is_err());
        assert_eq!(EmoteTextureExportFormat::Jpeg.extension(), "jpg");
    }

    #[test]
    fn hxv4_candidate_retention_keeps_only_authenticated_target_hashes() {
        let wanted = hxv4_filename_hash("wanted_resource.psb");
        let mut targets = Hxv4HashTargets::default();
        targets.name_hashes.insert(wanted);
        targets.name_hash_hex.insert(hex_upper_main(&wanted));
        let mut map = Hxv4NameMap::default();

        for candidate in ["randomA", "randomB.bin", "other/path/noise.dat"] {
            add_hxv4_candidate_variants(&mut map, &targets, candidate);
        }
        assert!(map.names.is_empty());
        assert!(map.paths.is_empty());

        add_hxv4_candidate_variants(&mut map, &targets, "wanted_resource.psb");
        assert_eq!(map.names.len(), 1);
        assert_eq!(
            map.names.values().next().map(String::as_str),
            Some("wanted_resource.psb")
        );
    }

    #[test]
    fn no_special_ordinary_archive_keeps_generic_shared_fallback() {
        assert!(should_try_generic_shared_key(false, false, true));
    }

    #[test]
    fn validated_special_content_key_suppresses_generic_shared_probe() {
        assert!(!should_try_generic_shared_key(false, true, true));
    }

    #[test]
    fn hxv4_suppresses_generic_shared_probe_before_dedicated_filter() {
        assert!(!should_try_generic_shared_key(true, false, true));
    }

    #[test]
    fn ordinary_special_is_a_hard_gate_when_decode_fails() {
        let err = require_special_before_content_recovery(false, true, false, false, 0)
            .expect_err("undecoded Special must block entry recovery");
        assert!(err.to_string().contains("refusing to continue"));
    }

    #[test]
    fn ordinary_archive_without_special_is_not_blocked() {
        require_special_before_content_recovery(false, false, false, false, 0)
            .expect("ordinary archive without Special keeps the legacy path");
    }

    #[test]
    fn hxv4_requires_authenticated_parsed_special_before_entry_recovery() {
        let err = require_special_before_content_recovery(true, true, false, false, 1)
            .expect_err("locked HXV4 Special must block entry recovery");
        let message = err.to_string();
        assert!(message.contains("nonce_slot=1"));
        assert!(message.contains("refusing to reconstruct or solve entries"));

        require_special_before_content_recovery(true, true, false, true, 1)
            .expect("authenticated and parsed HXV4 Special opens the gate");
    }

    #[test]
    fn hxv4_without_special_descriptor_is_rejected() {
        let err = require_special_before_content_recovery(true, false, false, false, 0)
            .expect_err("HXV4 without Special descriptor must fail closed");
        assert!(err
            .to_string()
            .contains("no recognized Special-index descriptor"));
    }

    #[test]
    fn hxv4_partial_names_do_not_open_ordinary_content_recovery() {
        assert!(!hxv4_names_complete(1921, 10));
    }

    #[test]
    fn hxv4_all_current_archive_names_open_ordinary_content_recovery() {
        assert!(hxv4_names_complete(1921, 1921));
    }

    #[test]
    fn hxv4_hash_name_extension_completion_covers_tlg_and_psb() {
        assert!(HXV4_COMMON_EXTENSIONS.contains(&"tlg"));
        assert!(HXV4_COMMON_EXTENSIONS.contains(&"psb"));
        assert!(HXV4_COMMON_EXTENSIONS.contains(&"psb.m"));
        assert!(HXV4_COMMON_EXTENSIONS.contains(&"tft"));
    }

    #[test]
    fn hxv4_blind_xor_hypotheses_have_useful_exact_cribs() {
        let hypotheses = blind_repeating_xor_hypotheses();
        assert!(!hypotheses.is_empty());
        assert!(hypotheses.iter().all(|hypothesis| {
            hypothesis
                .cribs
                .iter()
                .map(|crib| crib.plaintext.len())
                .sum::<usize>()
                >= 4
        }));
    }

    #[test]
    fn user_facing_output_transparently_inflates_kirikiri_mode2_even_for_bin_name() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;

        // KiriKiri stores FF FE outside the zlib payload. The compressed body
        // contains only UTF-16LE code units, while the size field counts that
        // body and therefore excludes the BOM.
        let mut body = Vec::new();
        for word in "storage=title_bg1.mtn\r\n".encode_utf16() {
            body.extend_from_slice(&word.to_le_bytes());
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut wrapped = vec![0xfe, 0xfe, 0x02, 0xff, 0xfe];
        wrapped.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        wrapped.extend_from_slice(&(body.len() as u64).to_le_bytes());
        wrapped.extend_from_slice(&compressed);

        let mut expected = vec![0xff, 0xfe];
        expected.extend_from_slice(&body);
        assert_eq!(kirikiri_text_wrapper_mode(&wrapped), Some(2));
        assert_eq!(
            user_facing_text_bytes("00000000.bin", Some("Kirikiri/Text-mode2"), wrapped),
            expected
        );
    }

    #[test]
    fn user_facing_output_unwraps_kirikiri_mode1_by_content_not_extension() {
        let words: Vec<u16> = "abc".encode_utf16().collect();
        let mut wrapped = vec![0xfe, 0xfe, 0x01, 0xff, 0xfe];
        for mut word in words {
            word = ((word & 0xaaaa) >> 1) | ((word & 0x5555) << 1);
            wrapped.extend_from_slice(&word.to_le_bytes());
        }

        let output = user_facing_text_bytes("hash-only.bin", Some("Kirikiri/Text-mode1"), wrapped);
        assert_eq!(&output[..2], &[0xff, 0xfe]);
        let decoded: Vec<u16> = output[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(String::from_utf16(&decoded).unwrap(), "abc");
    }

    #[test]
    fn verified_cp932_output_is_normalized_to_utf16le_with_bom() {
        // CP932 bytes for "日本語\r\n".
        let cp932 = vec![0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea, 0x0d, 0x0a];
        let output = user_facing_text_bytes("script.tjs", Some("Text/CP932"), cp932);
        assert!(output.starts_with(&[0xff, 0xfe]));
        let words: Vec<u16> = output[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(String::from_utf16(&words).unwrap(), "日本語\r\n");
    }

    #[test]
    fn unverified_cp932_like_bytes_are_not_transcoded() {
        let raw = vec![0x93, 0xfa, 0x96, 0x7b];
        assert_eq!(
            user_facing_text_bytes("unknown.bin", None, raw.clone()),
            raw
        );
    }

    #[test]
    fn verified_generic_bin_is_renamed_from_recovered_format() {
        assert_eq!(
            refine_generic_output_name("graphics/title.bin", Some("PNG"), b""),
            "graphics/title.png"
        );
        assert_eq!(
            refine_generic_output_name("font.bin", Some("Kirikiri/PrerenderedFont-v1"), b""),
            "font.tft"
        );
        assert_eq!(
            refine_generic_output_name("script.bin", Some("Kirikiri/Text-mode2"), b""),
            "script.txt"
        );
    }

    #[cfg(feature = "magic-sniff")]
    #[test]
    fn generic_bin_uses_pure_rust_libmagic_extension_when_no_format_hint_exists() {
        let mut bytes = b"TVP pre-rendered font\x1a\x01\x02".to_vec();
        bytes.resize(36, 0);
        assert_eq!(
            refine_generic_output_name("font.bin", None, &bytes),
            "font.tft"
        );
    }

    #[test]
    fn meaningful_existing_extension_is_not_rewritten() {
        assert_eq!(
            refine_generic_output_name("script.ks", Some("PNG"), b"\x89PNG\r\n\x1a\n"),
            "script.ks"
        );
    }

    #[test]
    fn generic_bin_stays_bin_when_format_cannot_be_determined() {
        assert_eq!(
            refine_generic_output_name("unknown.bin", None, &[]),
            "unknown.bin"
        );
    }

    #[test]
    fn clean_unpack_output_removes_only_legacy_tool_artifacts() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "krkr-xp3-brute-clean-output-{}-{nonce}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("_hxv4/decompiled_tjs")).unwrap();
        fs::create_dir_all(root.join("_unresolved_raw")).unwrap();
        fs::write(root.join("_xp3brute_report.tsv"), b"old report").unwrap();
        fs::write(root.join("keep.png"), b"user file").unwrap();

        cleanup_legacy_unpack_artifacts(&root).unwrap();

        assert!(!root.join("_hxv4").exists());
        assert!(!root.join("_unresolved_raw").exists());
        assert!(!root.join("_xp3brute_report.tsv").exists());
        assert_eq!(fs::read(root.join("keep.png")).unwrap(), b"user file");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hxv4_blind_text_fallback_contains_source_encodings() {
        let hypotheses = blind_text_hypotheses();
        assert!(hypotheses
            .iter()
            .any(|hypothesis| hypothesis.name == "Text/UTF-8"));
        assert!(hypotheses
            .iter()
            .any(|hypothesis| hypothesis.name == "Text/CP932"));
    }
}
