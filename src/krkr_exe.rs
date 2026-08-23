//! Static Kirikiri/HXV4 executable analysis and Special-key recovery.
//!
//! Some commercial launchers wrap the real Kirikiri PE inside another PE.  The
//! analyzer therefore treats an EXE as a byte container, enumerates every valid
//! embedded PE image, and only accepts an image after its bres resources can be
//! decrypted and `STARTUP.TJS` validates as `TJS2100\0`.
//!
//! For the known HXV4 FilterManager family the bootstrap KDF can be reproduced
//! without running the game.  The recovered key/nonce tuple is never accepted
//! by heuristics: it must authenticate the XChaCha20-Poly1305 Special payload,
//! inflate it, and pass the strict native Hx object parser.

use crate::hxv4::{decrypt_hxv4_special_index, hxv4_special_nonce_slot, Hxv4Index, Hxv4IndexKeys};
use crate::hxv4_native::Hxv4NativeFilterManager;
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use flate2::read::ZlibDecoder;
use pelite::resources::Name;
use pelite::PeFile;
use sha3::{Digest, Sha3_384};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const RESOURCE_SALT_LEN: usize = 0x2000;
const STARTUP_RESOURCE: &str = "STARTUP.TJS";
const BOOTSTRAP_RESOURCE: &str = "BOOTSTRAP";
const DEFAULT_ARCHIVE_SEED: [u8; 8] = [0xce, 0xea, 0xaf, 0x2c, 0xef, 0xbe, 0xad, 0xde];
const KNOWN_ARCHIVE_SEED_RVA: u32 = 0x81758;
const XOPT_MARKER: [u8; 24] = [
    0x2d, 0x00, 0x2d, 0x00, 0x78, 0x00, 0x6f, 0x00, 0x70, 0x00, 0x74, 0x00, 0x2d, 0x00, 0x2d, 0x00,
    0x6e, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const OBFUSCATED_CHACHA_CONSTANT: [u8; 16] = [
    0x9a, 0x87, 0x8f, 0x9e, 0x91, 0x9b, 0xdf, 0xcc, 0xcd, 0xd2, 0x9d, 0x86, 0x8b, 0x9a, 0xdf, 0x94,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KrkrExePeCandidate {
    /// File offset of this PE image inside the supplied EXE/container.
    pub file_offset: usize,
    pub machine: u16,
    pub sections: u16,
    pub has_resources: bool,
    pub kirikiri_markers: usize,
}

#[derive(Clone, Debug)]
pub struct KrkrExeAnalysis {
    pub exe: PathBuf,
    /// Selected inner PE image.  Zero means the outer EXE itself was selected.
    pub pe_offset: usize,
    pub pe_candidates: Vec<KrkrExePeCandidate>,
    pub salt_file_offset: usize,
    pub startup_bres_path: String,
    pub bootstrap_bres_path: String,
    pub startup_tjs: Vec<u8>,
    pub bootstrap_dll: Vec<u8>,
    pub bootstrap_prefix_candidates: Vec<String>,
    pub params: Vec<u8>,
    pub warning: String,
    pub unique: String,
    pub unique_utf16le: Vec<u8>,
    pub archive_seed_candidates: Vec<[u8; 8]>,
}

#[derive(Clone, Debug)]
pub struct Hxv4ExeKeyRecovery {
    pub exe: PathBuf,
    pub pe_offset: usize,
    pub keys: Hxv4IndexKeys,
    pub key: [u8; 32],
    pub nonce0: [u8; 24],
    pub nonce1: [u8; 24],
    pub nonce_slot: usize,
    pub bootstrap_prefix: String,
    pub archive_seed: [u8; 8],
    /// Exact Storages.archiveUniqueKey/UNIQUE string recovered from the game
    /// bootstrap resources. Preserve it for round-trip filter reconstruction.
    pub archive_unique_key: String,
    pub bootstrap_candidates_tested: usize,
    /// Reconstructed game-wide ordinary-entry FilterManager, including the
    /// archiveUniqueKey-derived holder state used by the open_flag branch.
    pub native_filter: Hxv4NativeFilterManager,
    pub index: Hxv4Index,
}

impl Hxv4ExeKeyRecovery {
    pub fn key_hex(&self) -> String {
        hex_lower(&self.key)
    }
    pub fn nonce_hex(&self) -> String {
        hex_lower(&self.keys.nonce)
    }
    pub fn nonce0_hex(&self) -> String {
        hex_lower(&self.nonce0)
    }
    pub fn nonce1_hex(&self) -> String {
        hex_lower(&self.nonce1)
    }
    pub fn archive_seed_hex(&self) -> String {
        hex_lower(&self.archive_seed)
    }
}

/// Analyze a game executable/container.  Every embedded PE is inspected, so a
/// small launcher that embeds the real Kirikiri executable is handled without a
/// separate unpacking step.
pub fn analyze_krkr_exe(path: &Path) -> Result<KrkrExeAnalysis, String> {
    let source = fs::read(path).map_err(|e| format!("cannot read EXE {}: {e}", path.display()))?;
    let normalized = crate::pe_normalize::normalize_pe_bytes(&source)
        .map_err(|e| format!("cannot normalize executable {}: {e}", path.display()))?;
    let bytes = normalized.bytes;
    let pe_candidates = scan_pe_candidates(&bytes);
    if pe_candidates.is_empty() {
        return Err("no valid PE image found in executable/container".to_string());
    }

    let mut failures = Vec::new();
    // Prefer candidates with resources and Kirikiri markers, but validation of
    // STARTUP.TJS/BOOTSTRAP remains the actual acceptance criterion.
    let mut order: Vec<usize> = (0..pe_candidates.len()).collect();
    order.sort_by_key(|&i| {
        let c = &pe_candidates[i];
        (
            std::cmp::Reverse(c.has_resources),
            std::cmp::Reverse(c.kirikiri_markers),
            c.file_offset,
        )
    });

    for i in order {
        let candidate = &pe_candidates[i];
        let image = &bytes[candidate.file_offset..];
        match analyze_pe_image(
            path,
            &bytes,
            image,
            candidate.file_offset,
            pe_candidates.clone(),
        ) {
            Ok(value) => return Ok(value),
            Err(err) => failures.push(format!("PE@0x{:x}: {err}", candidate.file_offset)),
        }
    }

    let detail = failures.into_iter().take(8).collect::<Vec<_>>().join("; ");
    Err(format!(
        "no embedded PE yielded validated Kirikiri bres bootstrap resources: {detail}"
    ))
}

/// Recover and *validate* the HXV4 Special key material from one executable.
/// The descriptor chooses nonce0/nonce1; the candidate is accepted only if the
/// complete Special authenticates and parses.
pub fn recover_hxv4_keys_from_exe(
    exe: &Path,
    special_blob: &[u8],
    descriptor_flags: u16,
) -> Result<Hxv4ExeKeyRecovery, String> {
    let analysis = analyze_krkr_exe(exe)?;
    recover_hxv4_keys_from_analysis(&analysis, special_blob, descriptor_flags)
}

/// Discover the main PE32 game executable next to the XP3 (and one parent
/// directory above it), then perform nested-PE analysis and strict Special
/// validation.  Discovery is content-first and extension-independent.
pub fn recover_hxv4_keys_auto(
    archive_path: &Path,
    special_blob: &[u8],
    descriptor_flags: u16,
    explicit_exe: Option<&Path>,
) -> Result<Option<Hxv4ExeKeyRecovery>, String> {
    let candidates = discover_game_executables(archive_path, explicit_exe)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut errors = Vec::new();
    for exe in candidates {
        match recover_hxv4_keys_from_exe(&exe, special_blob, descriptor_flags) {
            Ok(recovery) => return Ok(Some(recovery)),
            Err(err) => errors.push(format!("{}: {err}", exe.display())),
        }
    }
    Err(errors.join("; "))
}

fn recover_hxv4_keys_from_analysis(
    analysis: &KrkrExeAnalysis,
    special_blob: &[u8],
    descriptor_flags: u16,
) -> Result<Hxv4ExeKeyRecovery, String> {
    let nonce_slot = hxv4_special_nonce_slot(descriptor_flags);
    let mut prefixes = analysis.bootstrap_prefix_candidates.clone();
    if !prefixes.iter().any(|s| s == &analysis.unique) {
        prefixes.push(analysis.unique.clone());
    }
    if prefixes.is_empty() {
        return Err("no bootstrap-prefix candidates found in STARTUP.TJS/config".to_string());
    }

    let mut tested = 0usize;
    for prefix in prefixes.into_iter().take(4096) {
        let shared = match derive_bootstrap_shared(&analysis.params, &analysis.warning, &prefix) {
            Ok(value) => value,
            Err(_) => continue,
        };
        tested += 1;
        let key = shared.key;
        let nonce1 = shared.nonce1;

        if nonce_slot == 1 {
            let seed = analysis
                .archive_seed_candidates
                .first()
                .copied()
                .unwrap_or(DEFAULT_ARCHIVE_SEED);
            let nonce0 = derive_nonce0(&analysis.unique_utf16le, &seed)?;
            let keys = Hxv4IndexKeys { key, nonce: nonce1 };
            if let Ok(index) = decrypt_hxv4_special_index(special_blob, &keys) {
                let native_filter =
                    derive_native_filter_manager(&analysis.params, &shared.material, &nonce0)?;
                return Ok(Hxv4ExeKeyRecovery {
                    exe: analysis.exe.clone(),
                    pe_offset: analysis.pe_offset,
                    keys,
                    key,
                    nonce0,
                    nonce1,
                    nonce_slot,
                    bootstrap_prefix: prefix,
                    archive_seed: seed,
                    archive_unique_key: analysis.unique.clone(),
                    bootstrap_candidates_tested: tested,
                    native_filter,
                    index,
                });
            }
            continue;
        }

        for &seed in &analysis.archive_seed_candidates {
            let nonce0 = derive_nonce0(&analysis.unique_utf16le, &seed)?;
            let keys = Hxv4IndexKeys { key, nonce: nonce0 };
            if let Ok(index) = decrypt_hxv4_special_index(special_blob, &keys) {
                let native_filter =
                    derive_native_filter_manager(&analysis.params, &shared.material, &nonce0)?;
                return Ok(Hxv4ExeKeyRecovery {
                    exe: analysis.exe.clone(),
                    pe_offset: analysis.pe_offset,
                    keys,
                    key,
                    nonce0,
                    nonce1,
                    nonce_slot,
                    bootstrap_prefix: prefix,
                    archive_seed: seed,
                    archive_unique_key: analysis.unique.clone(),
                    bootstrap_candidates_tested: tested,
                    native_filter,
                    index,
                });
            }
        }
    }

    Err(format!(
        "derived {} bootstrap candidate(s), but no key/descriptor-selected nonce authenticated the HXV4 Special",
        tested
    ))
}

#[derive(Clone, Debug)]
struct SharedDerived {
    key: [u8; 32],
    nonce1: [u8; 24],
    material: [u8; 64],
}

fn derive_bootstrap_shared(
    params: &[u8],
    warning: &str,
    prefix: &str,
) -> Result<SharedDerived, String> {
    let mut final_bootstrap = utf16_bytes(prefix);
    final_bootstrap.extend_from_slice(&utf16_bytes(warning));

    // sub_10010550 calls the bundled Argon2i implementation with m=8 KiB,
    // t=3, p=1, version 0x13.  The 16-byte salt is first squeezed from PARAMS
    // by the Cx Keccak sponge (rate 0x90, domain 0x06).
    let mut salt = [0u8; 16];
    CxSponge::new(0x90, 0x06).absorb(params).squeeze(&mut salt);
    let argon_params =
        Params::new(8, 3, 1, Some(64)).map_err(|e| format!("Argon2 params: {e:?}"))?;
    let argon = Argon2::new(Algorithm::Argon2i, Version::V0x13, argon_params);
    let mut material = [0u8; 64];
    argon
        .hash_password_into(&final_bootstrap, &salt, &mut material)
        .map_err(|e| format!("Argon2i bootstrap derivation failed: {e:?}"))?;

    let key_a = derive_key_block(&final_bootstrap, 32, 0)?;
    let nonce1_a = derive_key_block(params, 32, 1)?;
    let mut key = [0u8; 32];
    let mut nonce1_full = [0u8; 32];
    for i in 0..32 {
        key[i] = key_a[i] ^ material[i];
        nonce1_full[i] = nonce1_a[i] ^ material[i];
    }
    let mut nonce1 = [0u8; 24];
    nonce1.copy_from_slice(&nonce1_full[..24]);
    Ok(SharedDerived {
        key,
        nonce1,
        material,
    })
}

fn derive_native_filter_manager(
    params: &[u8],
    material: &[u8; 64],
    nonce0: &[u8; 24],
) -> Result<Hxv4NativeFilterManager, String> {
    if !valid_params(params) {
        return Err("invalid HXV4 PARAMS for native content FilterManager".to_string());
    }

    // sub_10010550: after Argon2i, absorb all 64 material bytes into the
    // rate=136/domain=0x1f Cx sponge and squeeze 0x2000 bytes.
    let mut shake = vec![0u8; 0x2000];
    CxSponge::new(136, 0x1f)
        .absorb(material)
        .squeeze(&mut shake);

    // sub_1000F620: PARAMS bit0 selects either the first 0x1000-byte block
    // unchanged (mode 1), or first XOR second (mode 2).
    let mode = (params[17] & 1) + 1;
    let mut words = vec![0u32; 1024];
    for (index, word) in words.iter_mut().enumerate() {
        let at = index * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&shake[at..at + 4]);
        if mode == 2 {
            for i in 0..4 {
                bytes[i] ^= shake[0x1000 + at + i];
            }
        }
        *word = u32::from_le_bytes(bytes);
    }

    // Storages.archiveUniqueKey -> sub_10011A80 -> sub_100157D0.  The latter
    // derives exactly the same 32-byte `unique XOR modifier` block as nonce0
    // and stores its first two little-endian words in FilterManagerImpl[2:4].
    // sub_10013C60 applies those holder words when open_flag == 0.
    let holder_low = le_u32(&nonce0[0..4]);
    let holder_high = le_u32(&nonce0[4..8]);
    Ok(
        Hxv4NativeFilterManager::from_params_and_table(params, &words)?
            .with_holder_words(holder_low, holder_high),
    )
}

fn derive_nonce0(unique_utf16le: &[u8], archive_seed: &[u8; 8]) -> Result<[u8; 24], String> {
    let unique = derive_key_block(unique_utf16le, 32, 2)?;
    let seed = le_u32(&archive_seed[..4]);
    let modifier = derive_key_block(archive_seed, 32, seed)?;
    let mut full = [0u8; 32];
    for i in 0..32 {
        full[i] = unique[i] ^ modifier[i];
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&full[..24]);
    Ok(nonce)
}

fn analyze_pe_image(
    exe_path: &Path,
    whole_file: &[u8],
    image: &[u8],
    base: usize,
    candidates: Vec<KrkrExePeCandidate>,
) -> Result<KrkrExeAnalysis, String> {
    let pe = PeFile::from_bytes(image).map_err(|e| format!("invalid PE: {e}"))?;
    let salt_rva = find_resource_salt_rva(image, &pe)?;
    let salt = pe
        .derva_slice::<u8>(salt_rva, RESOURCE_SALT_LEN)
        .map_err(|e| format!("cannot read 0x{RESOURCE_SALT_LEN:x}-byte bres salt: {e}"))?;
    let salt_rel = (salt.as_ptr() as usize).saturating_sub(image.as_ptr() as usize);
    let salt_file_offset = base.saturating_add(salt_rel);
    if salt_file_offset + RESOURCE_SALT_LEN > whole_file.len() {
        return Err("mapped bres salt lies outside outer EXE".to_string());
    }

    let resources = pe
        .resources()
        .map_err(|e| format!("cannot read PE resources: {e}"))?;
    let startup_encrypted = resources
        .find_resource(&[
            Name::Id(pelite::image::RT_RCDATA as u32),
            Name::Str(STARTUP_RESOURCE),
        ])
        .map_err(|e| format!("RCDATA/{STARTUP_RESOURCE} not found: {e}"))?;
    let text127 = resources
        .find_resource(&[Name::Str("TEXT"), Name::Id(127)])
        .map_err(|e| format!("TEXT/127 not found: {e}"))?;
    let startup_bres_path = parse_bres_storage_path(&decode_utf16le(text127)?)?;
    let startup_tjs = decrypt_bres_resource(startup_encrypted, &startup_bres_path, salt);
    if !startup_tjs.starts_with(b"TJS2100\0") {
        return Err("STARTUP.TJS failed TJS2100 validation after bres decryption".to_string());
    }

    let bootstrap_bres_path = find_bootstrap_filter_path(&startup_tjs)?;
    let bootstrap_encrypted = resources
        .find_resource(&[
            Name::Id(pelite::image::RT_RCDATA as u32),
            Name::Str(BOOTSTRAP_RESOURCE),
        ])
        .map_err(|e| format!("RCDATA/{BOOTSTRAP_RESOURCE} not found: {e}"))?;
    let bootstrap_packed = decrypt_bres_resource(bootstrap_encrypted, &bootstrap_bres_path, salt);
    let bootstrap_dll = unpack_bootstrap(&bootstrap_packed)?;
    if !bootstrap_dll.starts_with(b"MZ") {
        return Err("decrypted BOOTSTRAP payload is not a PE image".to_string());
    }

    let params = find_bootstrap_item(&bootstrap_dll, "PARAMS", valid_params)?;
    let warning_bytes = find_bootstrap_item(&bootstrap_dll, "WARNING", |p| {
        !p.is_empty()
            && p.is_ascii()
            && std::str::from_utf8(p)
                .map_or(false, |s| s.starts_with("Warning!") && s.contains("author"))
    })?;
    let warning =
        String::from_utf8(warning_bytes).map_err(|e| format!("invalid WARNING UTF-8: {e}"))?;
    let unique_utf16le = find_bootstrap_item(&bootstrap_dll, "UNIQUE", valid_unique)?;
    let unique = decode_utf16le(&unique_utf16le)?;
    let archive_seed_candidates = archive_seed_candidates(&bootstrap_dll)?;
    let bootstrap_prefix_candidates = bootstrap_input_candidates(&startup_tjs);

    Ok(KrkrExeAnalysis {
        exe: exe_path.to_path_buf(),
        pe_offset: base,
        pe_candidates: candidates,
        salt_file_offset,
        startup_bres_path,
        bootstrap_bres_path,
        startup_tjs,
        bootstrap_dll,
        bootstrap_prefix_candidates,
        params,
        warning,
        unique,
        unique_utf16le,
        archive_seed_candidates,
    })
}

pub fn scan_pe_candidates(bytes: &[u8]) -> Vec<KrkrExePeCandidate> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 0x40 <= bytes.len() {
        let Some(rel) = bytes[pos..].windows(2).position(|w| w == b"MZ") else {
            break;
        };
        let at = pos + rel;
        if let Some(candidate) = inspect_pe_candidate(bytes, at) {
            out.push(candidate);
        }
        pos = at + 2;
    }
    out.sort_by_key(|c| c.file_offset);
    out.dedup_by_key(|c| c.file_offset);
    out
}

fn inspect_pe_candidate(bytes: &[u8], at: usize) -> Option<KrkrExePeCandidate> {
    let image = bytes.get(at..)?;
    if image.len() < 0x40 {
        return None;
    }
    let pe_off = le_u32(image.get(0x3c..0x40)?) as usize;
    if pe_off > 0x20_0000 || pe_off.checked_add(24)? > image.len() {
        return None;
    }
    if image.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }
    let machine = le_u16(image.get(pe_off + 4..pe_off + 6)?);
    let sections = le_u16(image.get(pe_off + 6..pe_off + 8)?);
    if sections == 0 || sections > 96 {
        return None;
    }
    let pe = PeFile::from_bytes(image).ok()?;
    let has_resources = pe.resources().is_ok();
    let marker_needles: [&[u8]; 6] = [
        b"tTVPXP3Archive",
        b"tTVPCryptoFilter",
        b"Kirikiri Z",
        b"STARTUP.TJS",
        b"BOOTSTRAP",
        b"bres://./",
    ];
    let kirikiri_markers = marker_needles
        .iter()
        .filter(|needle| contains_bytes(image, needle))
        .count();
    Some(KrkrExePeCandidate {
        file_offset: at,
        machine,
        sections,
        has_resources,
        kirikiri_markers,
    })
}

pub fn discover_game_executables(
    archive_path: &Path,
    explicit: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(format!("game executable not found: {}", path.display()));
        }
        if !crate::magic_sniff::path_looks_like_pe32_executable(path) {
            return Err(format!(
                "--exe is not an i386 PE32 executable image: {}",
                path.display()
            ));
        }
        return Ok(vec![path.to_path_buf()]);
    }

    let archive_dir = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let mut dirs = vec![archive_dir.to_path_buf()];
    if let Some(parent) = archive_dir.parent() {
        if parent != archive_dir {
            dirs.push(parent.to_path_buf());
        }
    }

    let mut unique = BTreeSet::new();
    for dir in dirs {
        let entries = match fs::read_dir(&dir) {
            Ok(v) => v,
            Err(_) if dir != archive_dir => continue,
            Err(e) => return Err(format!("cannot scan {} for game executable: {e}", dir.display())),
        };
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            if crate::magic_sniff::path_looks_like_pe32_executable(&path) {
                unique.insert(path);
            }
        }
    }

    let mut out: Vec<_> = unique.into_iter().collect();
    out.sort_by_key(|path| {
        let name = path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let auxiliary = [
            "config", "launcher", "patch", "setup", "support", "unins", "update",
        ]
        .iter()
        .any(|token| name.contains(token));
        let in_archive_dir = path.parent() == Some(archive_dir);
        (auxiliary, !in_archive_dir, name)
    });
    Ok(out)
}

fn find_resource_salt_rva(bytes: &[u8], pe: &PeFile<'_>) -> Result<u32, String> {
    let image_base = pe_image_base(bytes)?;
    let mut matches = Vec::new();
    let mut pos = 0usize;
    while pos + 0x21 <= bytes.len() {
        if bytes[pos] == 0x83
            && bytes[pos + 1] == 0x3d
            && bytes[pos + 6] == 0x00
            && bytes[pos + 7] == 0x0f
            && bytes[pos + 8] == 0x86
            && bytes[pos + 13] == 0xc7
            && bytes[pos + 14] == 0x05
            && bytes[pos + 23] == 0xc7
            && bytes[pos + 24] == 0x05
            && bytes[pos + 29..pos + 33] == [0x00, 0x20, 0x00, 0x00]
        {
            let va = le_u32(&bytes[pos + 19..pos + 23]) as u64;
            if va >= image_base {
                let rva64 = va - image_base;
                if rva64 <= u32::MAX as u64 {
                    let rva = rva64 as u32;
                    if pe.derva_slice::<u8>(rva, RESOURCE_SALT_LEN).is_ok() {
                        matches.push(rva);
                    }
                }
            }
        }
        pos += 1;
    }
    matches.sort_unstable();
    matches.dedup();
    match matches.as_slice() {
        [rva] => Ok(*rva),
        [] => Err("bres salt pointer pattern not found".to_string()),
        _ => {
            // Multiple patterns can exist in a wrapper-heavy binary.  Validate
            // candidates later by STARTUP.TJS instead of fabricating one.  The
            // selected inner PE normally collapses this to one candidate.
            Err(format!(
                "bres salt pointer pattern is ambiguous ({} candidates)",
                matches.len()
            ))
        }
    }
}

fn pe_image_base(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return Err("missing DOS MZ header".to_string());
    }
    let pe_off = le_u32(&bytes[0x3c..0x40]) as usize;
    let optional = pe_off
        .checked_add(24)
        .ok_or_else(|| "PE header overflow".to_string())?;
    if optional + 0x20 > bytes.len() || bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err("missing PE signature".to_string());
    }
    match le_u16(&bytes[optional..optional + 2]) {
        0x10b => Ok(le_u32(&bytes[optional + 0x1c..optional + 0x20]) as u64),
        0x20b => Ok(le_u64(&bytes[optional + 0x18..optional + 0x20])),
        magic => Err(format!(
            "unsupported PE optional-header magic 0x{magic:04x}"
        )),
    }
}

fn decode_utf16le(data: &[u8]) -> Result<String, String> {
    if data.len() % 2 != 0 {
        return Err("odd-length UTF-16LE data".to_string());
    }
    let words: Vec<u16> = data.chunks_exact(2).map(le_u16).collect();
    String::from_utf16(&words)
        .map(|s| s.trim_end_matches('\0').to_string())
        .map_err(|e| format!("invalid UTF-16LE: {e}"))
}

fn parse_bres_storage_path(value: &str) -> Result<String, String> {
    let value = value.trim_matches('\0');
    let Some(inner) = value
        .strip_prefix("bres://./")
        .and_then(|v| v.strip_suffix('/'))
    else {
        return Err(format!(
            "unexpected startup base-storage resource {value:?}"
        ));
    };
    if inner.is_empty() || inner.contains('/') || inner.contains('\\') {
        return Err(format!("invalid bres filter path {inner:?}"));
    }
    Ok(inner.to_string())
}

fn find_bootstrap_filter_path(startup: &[u8]) -> Result<String, String> {
    let mut matches = Vec::new();
    for value in tjs2_string_constants(startup)? {
        let Some(path) = value
            .strip_prefix("bres://./")
            .and_then(|v| v.strip_suffix("/bootstrap"))
        else {
            continue;
        };
        if !path.is_empty() && !path.contains('/') && !path.contains('\\') {
            matches.push(path.to_string());
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err("bres bootstrap path not found in STARTUP.TJS string pool".to_string()),
        _ => Err(format!(
            "bootstrap filter path is ambiguous: {}",
            matches.join(", ")
        )),
    }
}

fn tjs2_string_constants(startup: &[u8]) -> Result<Vec<String>, String> {
    if startup.len() < 28 || !startup.starts_with(b"TJS2100\0") {
        return Err("not TJS2100 bytecode".to_string());
    }
    let declared = le_u32(&startup[8..12]) as usize;
    if declared != startup.len() || startup.get(12..16) != Some(b"DATA") {
        return Err("TJS2 size/DATA header mismatch".to_string());
    }
    let data_size = le_u32(&startup[16..20]) as usize;
    let data_end = 12usize
        .checked_add(data_size)
        .ok_or_else(|| "TJS2 DATA size overflow".to_string())?;
    if data_size < 8 || data_end > startup.len() {
        return Err("TJS2 DATA chunk out of range".to_string());
    }
    let payload = &startup[20..data_end];
    let mut pos = 0usize;
    fn read_count(data: &[u8], pos: &mut usize) -> Result<usize, String> {
        let end = pos
            .checked_add(4)
            .ok_or_else(|| "TJS2 pool offset overflow".to_string())?;
        let raw = data
            .get(*pos..end)
            .ok_or_else(|| "TJS2 pool count truncated".to_string())?;
        *pos = end;
        Ok(le_u32(raw) as usize)
    }
    fn skip(data: &[u8], pos: &mut usize, amount: usize) -> Result<(), String> {
        let end = pos
            .checked_add(amount)
            .ok_or_else(|| "TJS2 pool size overflow".to_string())?;
        if end > data.len() {
            return Err("TJS2 pool payload truncated".to_string());
        }
        *pos = end;
        Ok(())
    }
    fn align4(data: &[u8], pos: &mut usize) -> Result<(), String> {
        let aligned = pos
            .checked_add(3)
            .ok_or_else(|| "TJS2 alignment overflow".to_string())?
            & !3;
        if aligned > data.len() {
            return Err("TJS2 aligned pool exceeds DATA".to_string());
        }
        *pos = aligned;
        Ok(())
    }
    let byte_count = read_count(payload, &mut pos)?;
    skip(payload, &mut pos, byte_count)?;
    align4(payload, &mut pos)?;
    let short_count = read_count(payload, &mut pos)?;
    skip(
        payload,
        &mut pos,
        short_count
            .checked_mul(2)
            .ok_or_else(|| "TJS2 short pool overflow".to_string())?,
    )?;
    if short_count & 1 != 0 {
        skip(payload, &mut pos, 2)?;
    }
    for width in [4usize, 8, 8] {
        let count = read_count(payload, &mut pos)?;
        skip(
            payload,
            &mut pos,
            count
                .checked_mul(width)
                .ok_or_else(|| "TJS2 numeric pool overflow".to_string())?,
        )?;
    }
    let string_count = read_count(payload, &mut pos)?;
    if string_count > payload.len() / 4 {
        return Err("TJS2 string-pool count implausible".to_string());
    }
    let mut strings = Vec::with_capacity(string_count);
    for _ in 0..string_count {
        let len = read_count(payload, &mut pos)?;
        let byte_len = len
            .checked_mul(2)
            .ok_or_else(|| "TJS2 string size overflow".to_string())?;
        let end = pos
            .checked_add(byte_len)
            .ok_or_else(|| "TJS2 string offset overflow".to_string())?;
        let raw = payload
            .get(pos..end)
            .ok_or_else(|| "TJS2 string truncated".to_string())?;
        let units: Vec<u16> = raw.chunks_exact(2).map(le_u16).collect();
        strings.push(
            String::from_utf16(&units).map_err(|e| format!("invalid TJS2 UTF-16 string: {e}"))?,
        );
        pos = end;
        if len & 1 != 0 {
            skip(payload, &mut pos, 2)?;
        }
    }
    let octet_count = read_count(payload, &mut pos)?;
    for _ in 0..octet_count {
        let len = read_count(payload, &mut pos)?;
        skip(payload, &mut pos, len)?;
        align4(payload, &mut pos)?;
    }
    if pos != payload.len() {
        return Err("TJS2 DATA constant-pool trailing bytes".to_string());
    }
    Ok(strings)
}

fn bootstrap_input_candidates(startup: &[u8]) -> Vec<String> {
    let Ok(constants) = tjs2_string_constants(startup) else {
        return Vec::new();
    };
    let mut values = BTreeSet::new();
    for value in constants {
        let value = value.trim().to_string();
        if value.len() >= 4
            && value.len() <= 1024
            && !value.starts_with("bres://")
            && !value.chars().any(|ch| ch == '\0' || ch.is_control())
        {
            values.insert(value);
        }
    }
    let mut out: Vec<_> = values.into_iter().collect();
    out.sort_by_key(|s| {
        let lower = s.to_ascii_lowercase();
        let rights = !lower.contains("rights reserved");
        let copyright = !(lower.contains("copyright") || lower.contains("(c)"));
        let all = !lower.contains("all");
        (rights, copyright, all, s.len(), s.clone())
    });
    out
}

fn decrypt_bres_resource(input: &[u8], path: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_384::new();
    for word in path.encode_utf16() {
        Digest::update(&mut hasher, word.to_le_bytes());
    }
    Digest::update(&mut hasher, salt);
    let material: [u8; 48] = hasher.finalize().into();

    let mut stored = [0u32; 16];
    for i in 0..4 {
        stored[i] = le_u32(&OBFUSCATED_CHACHA_CONSTANT[i * 4..i * 4 + 4]);
    }
    for i in 0..8 {
        stored[4 + i] = !le_u32(&material[i * 4..i * 4 + 4]);
    }
    stored[12] = u32::MAX;
    stored[13] = u32::MAX;
    stored[14] = !le_u32(&material[0x20..0x24]);
    stored[15] = !le_u32(&material[0x24..0x28]);
    let qword1_low = le_u32(&material[0x28..0x2c]);
    let qword1_high = le_u32(&material[0x2c..0x30]);

    let mut output = vec![0u8; input.len()];
    for (block_index, (src, dst)) in input.chunks(64).zip(output.chunks_mut(64)).enumerate() {
        let mut block_stored = stored;
        let counter = !(((qword1_high as u64) << 32) | ((qword1_low ^ block_index as u32) as u64));
        block_stored[12] = counter as u32;
        block_stored[13] = (counter >> 32) as u32;
        let mut initial = [0u32; 16];
        for i in 0..16 {
            initial[i] = !block_stored[i];
        }
        let transformed = chacha_transform(initial, 4);
        let mut stream = [0u8; 64];
        for i in 0..16 {
            stream[i * 4..i * 4 + 4]
                .copy_from_slice(&transformed[i].wrapping_add(initial[i]).to_le_bytes());
        }
        for i in 0..src.len() {
            dst[i] = src[i] ^ stream[i];
        }
    }
    output
}

fn unpack_bootstrap(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 8 {
        return Err("decrypted BOOTSTRAP payload truncated".to_string());
    }
    let packed = le_u32(&data[..4]) as usize;
    let unpacked = le_u32(&data[4..8]) as usize;
    if packed != data.len() - 8 {
        return Err(format!(
            "BOOTSTRAP packed-size mismatch: header={packed} actual={}",
            data.len() - 8
        ));
    }
    let mut decoder = ZlibDecoder::new(&data[8..]);
    let mut out = Vec::with_capacity(unpacked);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("BOOTSTRAP zlib failed: {e}"))?;
    if out.len() != unpacked {
        return Err(format!(
            "BOOTSTRAP unpacked-size mismatch: header={unpacked} actual={}",
            out.len()
        ));
    }
    Ok(out)
}

fn find_bootstrap_item<F>(data: &[u8], name: &str, valid: F) -> Result<Vec<u8>, String>
where
    F: Fn(&[u8]) -> bool,
{
    let mut tag = name.as_bytes().to_vec();
    tag.push(0);
    let mut start = 0usize;
    while start + tag.len() <= data.len() {
        let Some(rel) = data[start..]
            .windows(tag.len())
            .position(|w| w == tag.as_slice())
        else {
            break;
        };
        let at = start + rel;
        let len_at = at + tag.len();
        if len_at + 2 > data.len() {
            break;
        }
        let len = le_u16(&data[len_at..len_at + 2]) as usize;
        let payload_at = len_at + 2;
        if payload_at + len <= data.len() {
            let payload = &data[payload_at..payload_at + len];
            if valid(payload) {
                return Ok(payload.to_vec());
            }
        }
        start = at + 1;
    }
    Err(format!("BOOTSTRAP {name} item not found"))
}

fn valid_params(data: &[u8]) -> bool {
    data.len() >= 0x16
        && permutation_valid(&data[14..17], 3)
        && permutation_valid(&data[8..14], 6)
        && permutation_valid(&data[0..8], 8)
}
fn permutation_valid(data: &[u8], n: usize) -> bool {
    if data.len() != n {
        return false;
    }
    let mut seen = vec![false; n];
    for &value in data {
        let i = value as usize;
        if i >= n || seen[i] {
            return false;
        }
        seen[i] = true;
    }
    true
}
fn valid_unique(data: &[u8]) -> bool {
    if data.len() < 2 || data.len() % 2 != 0 {
        return false;
    }
    decode_utf16le(data).map_or(false, |s| s.starts_with('{') && s.ends_with('}'))
}

fn archive_seed_candidates(bootstrap: &[u8]) -> Result<Vec<[u8; 8]>, String> {
    let mut values = BTreeSet::new();
    if let Ok(pe) = PeFile::from_bytes(bootstrap) {
        if let Ok(raw) = pe.derva_slice::<u8>(KNOWN_ARCHIVE_SEED_RVA, 8) {
            let mut seed = [0u8; 8];
            seed.copy_from_slice(raw);
            if seed.iter().any(|&b| b != 0) {
                values.insert(seed);
            }
        }
    }
    if let Some(at) = bootstrap
        .windows(XOPT_MARKER.len())
        .position(|w| w == XOPT_MARKER.as_slice())
    {
        let key_at = at + XOPT_MARKER.len();
        if key_at + 8 <= bootstrap.len() {
            let mut seed = [0u8; 8];
            seed.copy_from_slice(&bootstrap[key_at..key_at + 8]);
            if seed.iter().any(|&b| b != 0) {
                values.insert(seed);
            }
        }
    }
    // Compiler-pattern fallback used by this FilterManager family.
    let mut pos = 0usize;
    while pos + 0x50 <= bootstrap.len() {
        if bootstrap[pos] == 0xc7
            && bootstrap[pos + 1] == 0x45
            && bootstrap[pos + 7] == 0xc7
            && bootstrap[pos + 8] == 0x45
            && bootstrap[pos + 14..pos + 17] == [0x0f, 0x45, 0xf0]
            && bootstrap[pos + 9] == bootstrap[pos + 2].wrapping_add(4)
            && has_unique_kdf_use(&bootstrap[pos + 17..pos + 0x50])
        {
            let mut seed = [0u8; 8];
            seed[..4].copy_from_slice(&bootstrap[pos + 3..pos + 7]);
            seed[4..].copy_from_slice(&bootstrap[pos + 10..pos + 14]);
            if seed.iter().any(|&b| b != 0) {
                values.insert(seed);
            }
        }
        pos += 1;
    }
    // Always retain the native fallback used when no external archive seed is
    // registered.  AEAD validation decides whether it applies to this title.
    values.insert(DEFAULT_ARCHIVE_SEED);
    Ok(values.into_iter().collect())
}

fn has_unique_kdf_use(window: &[u8]) -> bool {
    let Some(at) = window.windows(2).position(|w| w == [0xff, 0x36]) else {
        return false;
    };
    let tail = &window[at + 2..];
    tail.windows(2).any(|w| w == [0x6a, 0x08]) && tail.contains(&0x56) && tail.contains(&0xe8)
}

fn derive_key_block(input: &[u8], size: usize, seed: u32) -> Result<Vec<u8>, String> {
    if size == 0 || size > 32 || size % 4 != 0 {
        return Err("invalid BLAKE2s key-block size".to_string());
    }
    let mut words = vec![0u32; size / 4];
    let mut state = 0x0100_0193u32.wrapping_mul(seed ^ 0x811c_9dc5);
    for (index, &byte) in input.iter().enumerate() {
        let mut value = (byte as u32) ^ state;
        value ^= value >> 17;
        value = value.wrapping_mul(0xed5a_d4bb);
        value ^= value >> 11;
        value = value.wrapping_mul(0xac4c_1b51);
        value ^= value >> 15;
        value = value.wrapping_mul(0x3184_8bab);
        state = value ^ (value >> 14);
        let slot = index % words.len();
        words[slot] ^= state;
    }
    let mut prehash = Vec::with_capacity(size);
    for word in words {
        prehash.extend_from_slice(&word.to_le_bytes());
    }
    let mut hasher = Blake2sVar::new(size).map_err(|e| e.to_string())?;
    Update::update(&mut hasher, input);
    Update::update(&mut hasher, &prehash);
    let mut out = vec![0u8; size];
    hasher
        .finalize_variable(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[derive(Clone, Debug)]
struct CxSponge {
    rate: usize,
    position: usize,
    state: [u64; 25],
    domain: u8,
}
impl CxSponge {
    fn new(rate: usize, domain: u8) -> Self {
        Self {
            rate,
            position: 0,
            state: [0; 25],
            domain,
        }
    }
    fn absorb(mut self, input: &[u8]) -> Self {
        let mut off = 0usize;
        while off < input.len() {
            let count = (self.rate - self.position).min(input.len() - off);
            xor_state_bytes(&mut self.state, self.position, &input[off..off + count]);
            self.position += count;
            off += count;
            if self.position == self.rate {
                keccak_f1600(&mut self.state);
                self.position = 0;
            }
        }
        self
    }
    fn squeeze(mut self, output: &mut [u8]) {
        xor_state_bytes(&mut self.state, self.position, &[self.domain]);
        let last = self.rate - 1;
        self.state[last / 8] ^= 0x80u64 << (8 * (last % 8));
        keccak_f1600(&mut self.state);
        let mut off = 0usize;
        while off < output.len() {
            let count = self.rate.min(output.len() - off);
            read_state_bytes(&self.state, &mut output[off..off + count]);
            off += count;
            if off < output.len() {
                keccak_f1600(&mut self.state);
            }
        }
    }
}
fn xor_state_bytes(state: &mut [u64; 25], offset: usize, input: &[u8]) {
    for (i, &byte) in input.iter().enumerate() {
        let pos = offset + i;
        state[pos / 8] ^= (byte as u64) << (8 * (pos % 8));
    }
}
fn read_state_bytes(state: &[u64; 25], output: &mut [u8]) {
    for (i, byte) in output.iter_mut().enumerate() {
        *byte = (state[i / 8] >> (8 * (i % 8))) as u8;
    }
}
fn keccak_f1600(a: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const R: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    for &rc in &RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let nx = y;
                let ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = a[x + 5 * y].rotate_left(R[x + 5 * y]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

fn chacha_transform(mut x: [u32; 16], double_rounds: usize) -> [u32; 16] {
    for _ in 0..double_rounds {
        quarter(&mut x, 0, 4, 8, 12);
        quarter(&mut x, 1, 5, 9, 13);
        quarter(&mut x, 2, 6, 10, 14);
        quarter(&mut x, 3, 7, 11, 15);
        quarter(&mut x, 0, 5, 10, 15);
        quarter(&mut x, 1, 6, 11, 12);
        quarter(&mut x, 2, 7, 8, 13);
        quarter(&mut x, 3, 4, 9, 14);
    }
    x
}
fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

fn utf16_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(|w| w.to_le_bytes()).collect()
}
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
fn le_u16(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}
fn le_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}
fn le_u64(data: &[u8]) -> u64 {
    u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}
fn hex_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_kdf_vector() {
        // Synthetic vector: keeps the KDF stable without embedding material
        // recovered from any real title into the source tree.
        let params = hex_bytes("00010203040506070001020304050102000134127856");
        let warning = "Warning! synthetic author rights.";
        let prefix = "Synthetic Bootstrap (C) Test.";
        let shared = derive_bootstrap_shared(&params, warning, prefix).unwrap();
        assert_eq!(
            hex_lower(&shared.key),
            "354bb298eaeb75f75ab6df8d841048d55521bee04f3dd693b05cbc927066aa6a"
        );
        assert_eq!(
            hex_lower(&shared.nonce1),
            "58aec2a530568ea05441a827570ec3e4b1acd53f954306f1"
        );
        let unique = utf16_bytes("{SyntheticUnique}");
        let seed: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let nonce0 = derive_nonce0(&unique, &seed).unwrap();
        assert_eq!(
            hex_lower(&nonce0),
            "cc5306ef36018797a6227da78d6a9b1dff9648ee4d40f089"
        );
        let manager = derive_native_filter_manager(&params, &shared.material, &nonce0).unwrap();
        assert_eq!(manager.holder_low(), 0xef06_53cc);
        assert_eq!(manager.holder_high(), 0x9787_0136);
    }

    #[test]
    fn embedded_pe_scanner_rejects_bare_mz_noise() {
        let mut bytes = vec![0u8; 256];
        bytes[32..34].copy_from_slice(b"MZ");
        assert!(scan_pe_candidates(&bytes).is_empty());
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
