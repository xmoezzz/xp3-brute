//! Special-index decryption and order-preserving filename recovery.
//!
//! This module follows the historical KrkrExtract pipeline instead of carving
//! path-looking strings out of ciphertext:
//!
//! 1. locate the out-of-line special-index blob;
//! 2. try the blob as a normal compressed/raw structured stream;
//! 3. before archive-wide content solving, attack large-period whole-blob XOR
//!    directly from structured plaintext redundancy (zero-byte modes plus exact
//!    M2 size/hash/name-length constraints);
//! 4. for historical SenrenBanka/CxFilter-style variants, remove the transform
//!    from the first `min(stored_size, 0x100)` bytes (the exact boundary used by
//!    KrkrExtract) and then decompress;
//! 5. parse the decoded chunk stream sequentially;
//! 6. bind filename records to ordinary XP3 entries by order, validating the
//!    per-record hash and raw `info.FileNameLength` leaked by the ordinary index.
//!
//! Unknown chunks are skipped with the generic XP3 `tag:u32 + size:u64`
//! framing when their bounds are valid.  They never disable older recovery
//! paths.  Loose/binwalk-style signature probing remains a diagnostic concern
//! (`chunk_probe`) and is deliberately not a correctness oracle here.

use crate::simd::xor_repeating_in_place;
use crate::xp3::{is_protected_dummy_name, Archive, Entry, RootChunk, RootKind};
use flate2::read::{GzDecoder, ZlibDecoder};
use rayon::prelude::*;
use std::io::{self, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_SPECIAL_DECODE: usize = 256 * 1024 * 1024;
const HISTORICAL_PREFIX: usize = 0x100;
const AUTO_MAX_XOR_PERIOD: usize = 1024;
/// Upper bound for the structured whole-special-index attack.  Unlike the
/// historical decompressor-oracle brute force, this path does not enumerate
/// 256^period keys: it derives key bytes from repeated M2 record structure.
const HARD_MAX_XOR_PERIOD: usize = 4096;
/// The legacy zlib/gzip header brute force is still exponential in the number
/// of unknown key bytes, so keep its old hard bound independently.
const LEGACY_BRUTE_MAX_XOR_PERIOD: usize = 5;
const MAX_RECORD_NAME_CHARS: usize = 0x4000;
const MAX_CHUNK_BODY: usize = 256 * 1024 * 1024;

/// zlib headers emitted by common `compress2` levels.  Historical KrkrExtract's
/// own SenrenBanka-compatible packer uses `Z_BEST_COMPRESSION`, so `78 DA` is
/// intentionally tried first.
const ZLIB_HEADER_DA: &[u8] = &[0x78, 0xDA];
const ZLIB_HEADER_9C: &[u8] = &[0x78, 0x9C];
const ZLIB_HEADER_5E: &[u8] = &[0x78, 0x5E];
const ZLIB_HEADER_01: &[u8] = &[0x78, 0x01];
const COMMON_ZLIB_HEADERS: [&[u8]; 4] = [
    ZLIB_HEADER_DA,
    ZLIB_HEADER_9C,
    ZLIB_HEADER_5E,
    ZLIB_HEADER_01,
];
const GZIP_HEADER: &[u8] = &[0x1f, 0x8b, 0x08];
const GZIP_HEADERS: [&[u8]; 1] = [GZIP_HEADER];

#[derive(Clone, Copy, Debug)]
enum SpecialCompression {
    Zlib,
    Gzip,
}

impl SpecialCompression {
    fn label(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Gzip => "gzip",
        }
    }

    fn headers(self) -> &'static [&'static [u8]] {
        match self {
            Self::Zlib => &COMMON_ZLIB_HEADERS,
            Self::Gzip => &GZIP_HEADERS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialXorScope {
    /// Match historical KrkrExtract/CxFilter behavior: transform only the first
    /// `min(stored_size, 0x100)` compressed bytes.
    Prefix100,
    /// Compatibility path for titles that apply the same transform to the whole
    /// compressed special-index stream.
    Whole,
}

impl SpecialXorScope {
    fn limit(self, size: usize) -> usize {
        match self {
            Self::Prefix100 => size.min(HISTORICAL_PREFIX),
            Self::Whole => size,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Prefix100 => "prefix100",
            Self::Whole => "whole",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecialXorRecovery {
    /// Recovered/supplied repeating-XOR key, in residue order.
    pub key: Vec<u8>,
    /// Portion of the stored special blob to which the key applies.
    pub scope: SpecialXorScope,
    /// First plaintext table byte used by the structured recovery.  Zero for
    /// whole-stream/legacy wrapper models.
    pub table_start: usize,
}

impl SpecialXorRecovery {
    pub fn period(&self) -> usize {
        self.key.len()
    }

    pub fn key_hex(&self) -> String {
        hex_key(&self.key)
    }
}

#[derive(Clone, Debug)]
pub struct OrderedNameRecovery {
    pub root_index: usize,
    pub decoder: String,
    pub layout: String,
    pub names: Vec<String>,
    pub confidence: u8,
    pub decoded_size: usize,
    /// Plaintext special-index bytes when ownership was transferred by the
    /// caller.  This lets `unpack` persist the actual recovered special chunk
    /// without running the attack a second time.
    pub decoded: Option<Vec<u8>>,
    /// Present when the successful special-index decoder used a repeating-XOR
    /// key.  Keeping this in the public recovery result makes the successful
    /// local search visible to callers instead of discarding the key after
    /// validation.
    pub xor: Option<SpecialXorRecovery>,
}

/// Full successful special-index recovery.  `decoded` is the plaintext
/// post-decompression index stream and can be dumped for reverse engineering.
#[derive(Clone, Debug)]
pub struct SpecialIndexRecovery {
    pub root_index: usize,
    pub decoder: String,
    pub layout: String,
    pub names: Vec<String>,
    pub confidence: u8,
    pub decoded: Vec<u8>,
    /// Exact repeating-XOR key used by the successful decoder, when applicable.
    pub xor: Option<SpecialXorRecovery>,
}

impl SpecialIndexRecovery {
    pub fn ordered_names(&self) -> OrderedNameRecovery {
        OrderedNameRecovery {
            root_index: self.root_index,
            decoder: self.decoder.clone(),
            layout: self.layout.clone(),
            names: self.names.clone(),
            confidence: self.confidence,
            decoded_size: self.decoded.len(),
            decoded: None,
            xor: self.xor.clone(),
        }
    }

    /// Convert into the ordered-name view while transferring ownership of the
    /// decrypted special-index plaintext.  CLI paths use this so successful
    /// recovery can be dumped without repeating the search.
    pub fn into_ordered_names(self) -> OrderedNameRecovery {
        let decoded_size = self.decoded.len();
        OrderedNameRecovery {
            root_index: self.root_index,
            decoder: self.decoder,
            layout: self.layout,
            names: self.names,
            confidence: self.confidence,
            decoded_size,
            decoded: Some(self.decoded),
            xor: self.xor,
        }
    }
}

/// Coarse-grained progress emitted by the bounded historical special-index
/// brute-force path.  Updates are chunked so progress reporting does not add an
/// atomic operation to every decompression candidate.
#[derive(Clone, Copy, Debug)]
pub struct SpecialRecoveryProgress {
    pub root_index: usize,
    pub scope: SpecialXorScope,
    pub compression: &'static str,
    pub period: usize,
    pub done: usize,
    pub total: usize,
}

#[derive(Clone, Debug)]
struct ParsedNameRecord {
    name: String,
    hash: u32,
    chars: u16,
}

/// Historical/default automatic special-index recovery.
///
/// It first attempts normal compression, then bounded repeating-XOR models for
/// the historical <=0x100 transformed prefix and for a whole-stream compatibility
/// variant.  A candidate is returned only after the decompressed record stream
/// validates against the ordinary XP3 index.
pub fn recover_special_index(archive: &Archive) -> Option<SpecialIndexRecovery> {
    recover_special_index_internal(archive, None, AUTO_MAX_XOR_PERIOD, None)
}

/// Same as [`recover_special_index`] but lets the caller expand the repeating-XOR
/// search used by the structured whole-special-index attack.  Large periods do
/// not trigger an exponential key search: M2/Yuzu record size, `adlr`, and raw
/// filename-length fields are treated as known plaintext and recover key bytes
/// directly.  The older decompressor-oracle brute force remains capped at
/// [`LEGACY_BRUTE_MAX_XOR_PERIOD`].
pub fn recover_special_index_with_max_xor_period(
    archive: &Archive,
    max_period: usize,
) -> Option<SpecialIndexRecovery> {
    recover_special_index_internal(archive, None, max_period.min(HARD_MAX_XOR_PERIOD), None)
}

/// Bounded historical recovery with progress notifications.  This is intended
/// for CLI/front-end use; correctness is identical to
/// [`recover_special_index_with_max_xor_period`].
pub fn recover_special_index_with_progress(
    archive: &Archive,
    max_period: usize,
    observer: &(dyn Fn(SpecialRecoveryProgress) + Sync),
) -> Option<SpecialIndexRecovery> {
    recover_special_index_internal(
        archive,
        None,
        max_period.min(HARD_MAX_XOR_PERIOD),
        Some(observer),
    )
}

/// Recover a special index using an explicitly supplied repeating-XOR key.
/// This is useful when a title-specific decoder has already been reduced to a
/// byte keystream externally; it still receives the same strict record checks.
pub fn recover_special_index_with_xor_key(
    archive: &Archive,
    key: &[u8],
    scope: SpecialXorScope,
) -> Option<SpecialIndexRecovery> {
    if key.is_empty() {
        return None;
    }
    recover_special_index_internal(archive, Some((key, scope)), 0, None)
}

pub fn recover_ordered_special_names(archive: &Archive) -> Option<OrderedNameRecovery> {
    recover_special_index(archive).map(|r| r.ordered_names())
}

pub fn recover_ordered_special_names_with_xor_key(
    archive: &Archive,
    key: &[u8],
    scope: SpecialXorScope,
) -> Option<OrderedNameRecovery> {
    recover_special_index_with_xor_key(archive, key, scope).map(|r| r.ordered_names())
}

fn recover_special_index_internal(
    archive: &Archive,
    explicit_xor: Option<(&[u8], SpecialXorScope)>,
    auto_max_period: usize,
    observer: Option<&(dyn Fn(SpecialRecoveryProgress) + Sync)>,
) -> Option<SpecialIndexRecovery> {
    if archive.entries.is_empty() {
        return None;
    }

    let mut best: Option<SpecialIndexRecovery> = None;
    for (root_index, root) in archive.root_chunks.iter().enumerate() {
        if !is_special_root(root.kind) {
            continue;
        }

        // The root kind describes how the archive advertises this out-of-line
        // Special payload; it is not, by itself, proof of one encryption model.
        // In particular, an Hxv4 archive-family marker must not suppress the
        // archive-only structured/zero-period attack.  Let the payload decide:
        // every automatic candidate below is accepted only after the same strict
        // archive-aware M2/Yuzu/XP3 structure validation.  Explicit Hxv4
        // ChaCha material is handled as an additional decoder by the caller.
        if !special_root_allows_archive_only_probe(root.kind) {
            continue;
        }

        let Some(blob) = archive.special_index_bytes_for_root(root_index) else {
            continue;
        };

        // 1) Plain/unprotected historical special index: zlib first, exactly as
        // `IsEncryptedSenrenBanka*` did before deciding a decoder was required.
        for (decoder, decoded) in direct_decode_candidates(blob, root) {
            if let Some((layout, names, confidence)) =
                recover_ordered_names_from_decoded_for_archive(&decoded, archive)
            {
                consider(
                    &mut best,
                    SpecialIndexRecovery {
                        root_index,
                        decoder,
                        layout,
                        names,
                        confidence,
                        decoded,
                        xor: None,
                    },
                );
            }
        }

        // A strict direct hit cannot be improved by a brute wrapper candidate.
        if best
            .as_ref()
            .is_some_and(|r| r.root_index == root_index && r.confidence == 100)
        {
            continue;
        }

        // 2) Explicit title/user key, if supplied.
        if let Some((key, scope)) = explicit_xor {
            // Explicit keys apply to raw structured special payloads as well as
            // compressed wrappers.  This mirrors the automatic whole-blob path
            // instead of forcing every supplied key through zlib/gzip.
            let mut raw = blob.to_vec();
            let limit = scope.limit(raw.len());
            xor_repeating_in_place(&mut raw[..limit], key, 0);
            if let Some((layout, names, confidence)) =
                recover_ordered_names_from_decoded_for_archive(&raw, archive)
            {
                consider(
                    &mut best,
                    SpecialIndexRecovery {
                        root_index,
                        decoder: format!(
                            "xor-{}-period{}->raw-structured",
                            scope.label(),
                            key.len()
                        ),
                        layout,
                        names,
                        confidence,
                        decoded: raw,
                        xor: Some(SpecialXorRecovery {
                            key: key.to_vec(),
                            scope,
                            table_start: 0,
                        }),
                    },
                );
            }

            let expected_size = root
                .inferred_original_size
                .and_then(|v| usize::try_from(v).ok());
            for compression in [SpecialCompression::Zlib, SpecialCompression::Gzip] {
                if let Some(decoded) = try_compressed_xor(
                    blob,
                    key,
                    scope.limit(blob.len()),
                    expected_size,
                    compression,
                ) {
                    if let Some((layout, names, confidence)) =
                        recover_ordered_names_from_decoded_for_archive(&decoded, archive)
                    {
                        consider(
                            &mut best,
                            SpecialIndexRecovery {
                                root_index,
                                decoder: format!(
                                    "xor-{}-period{}->{}",
                                    scope.label(),
                                    key.len(),
                                    compression.label()
                                ),
                                layout,
                                names,
                                confidence,
                                decoded,
                                xor: Some(SpecialXorRecovery {
                                    key: key.to_vec(),
                                    scope,
                                    table_start: 0,
                                }),
                            },
                        );
                    }
                }
            }
            continue;
        }

        // 3) Attack a whole-blob repeating XOR *before* touching the expensive
        // per-entry content solver.
        //
        // First try the cheapest ciphertext-only zero-mode key.  Structured
        // special indices contain many zero bytes (UTF-16LE high bytes, small
        // integer high bytes, padding/reserved fields), so for each residue the
        // modal ciphertext byte is often the key byte itself.
        if auto_max_period != 0 {
            if let Some(hit) =
                recover_zero_mode_whole_xor(archive, root_index, root, blob, auto_max_period)
            {
                return Some(hit);
            }

            // If zero-mode alone is not complete enough, use the stronger
            // ordered-M2 oracle.  The ordinary XP3 index leaks enough plaintext
            // to recover even a 1024-byte period without enumerating a 1024-byte
            // key:
            //
            //   chunk.size  = 6 + 2*FileNameLength (+ optional UTF-16 NUL)
            //   body.hash   = entry.adlr
            //   body.chars  = entry.info_name_length
            //
            // A candidate table start/period is accepted only when all of those
            // constraints agree on the same repeating key and the existing
            // strict ordered-record parser validates every retained entry.
            if let Some(hit) =
                recover_structured_whole_xor(archive, root_index, blob, auto_max_period, observer)
            {
                return Some(hit);
            }
        }

        // 4) Historical archive-only decompressor-oracle brute models.  The
        // decoder discovered by KrkrExtract was title-specific and arbitrary
        // native code, so this path does not pretend every decoder is repeating
        // XOR.  This legacy path is intentionally kept at <=5 because its search
        // is exponential; large-period work belongs to the structured path above.
        if auto_max_period != 0 {
            if let Some(hit) = brute_historical_xor(
                archive,
                root_index,
                root,
                blob,
                auto_max_period.min(LEGACY_BRUTE_MAX_XOR_PERIOD),
                observer,
            ) {
                consider(&mut best, hit);
            }
        }
    }
    best
}

fn special_root_allows_archive_only_probe(kind: RootKind) -> bool {
    is_special_root(kind)
}

fn is_special_root(kind: RootKind) -> bool {
    matches!(
        kind,
        RootKind::SpecialIndexV1
            | RootKind::SpecialIndexV2
            | RootKind::SpecialIndexV3
            | RootKind::SpecialIndexGeneric
            | RootKind::Hxv4SpecialIndex
    )
}

fn consider(best: &mut Option<SpecialIndexRecovery>, candidate: SpecialIndexRecovery) {
    let replace = best
        .as_ref()
        .map(|old| {
            candidate.confidence > old.confidence
                || (candidate.confidence == old.confidence
                    && candidate.decoded.len() < old.decoded.len())
        })
        .unwrap_or(true);
    if replace {
        *best = Some(candidate);
    }
}

fn direct_decode_candidates(blob: &[u8], root: &RootChunk) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let expected_size = root
        .inferred_original_size
        .and_then(|v| usize::try_from(v).ok());

    if let Some(decoded) = try_zlib_exact(blob, expected_size) {
        out.push(("zlib".to_string(), decoded));
    }
    if let Some(decoded) = try_gzip_exact(blob, expected_size) {
        out.push(("gzip".to_string(), decoded));
    }

    // Some variants reference an already-decoded root stream.  Raw is allowed
    // only because the *strict* archive-aware parser below must validate every
    // filename record; no string carving is performed on arbitrary ciphertext.
    if blob.len() <= MAX_SPECIAL_DECODE {
        out.push(("raw-structured".to_string(), blob.to_vec()));
    }
    out
}

#[derive(Clone, Debug)]
struct StructuredLayoutModel {
    /// Known plaintext bytes relative to the first retained M2/Yuzu record.
    constraints: Vec<(usize, u8)>,
    /// Relative start of every retained record.  The four-byte dynamic tag at
    /// these locations is unknown, but it is identical across records and can
    /// therefore provide another set of repeating-key equations.
    record_starts: Vec<usize>,
    /// UTF-16 high-byte locations.  These are not exact constraints because
    /// Japanese/non-ASCII names need not have a zero high byte; they are used
    /// only as a statistical zero vote when exact metadata leaves a key slot
    /// unresolved.
    filename_high_offsets: Vec<usize>,
    span: usize,
}

#[derive(Clone, Debug)]
struct StructuredXorHit {
    period: usize,
    start: usize,
    trailing_nul: bool,
    exact_known: usize,
    zero_guessed: usize,
    key: Vec<u8>,
    decoded: Vec<u8>,
    names: Vec<String>,
}

/// Build the contiguous M2/Yuzu layout implied by the ordinary XP3 index.
///
/// The tag and filename bytes are intentionally left unknown.  Everything else
/// below is exact plaintext leaked by the ordinary index:
///
///   tag:u32                  unknown, but repeated
///   payload_size:u64         6 + 2*chars (+ optional UTF-16 NUL)
///   hash:u32                 entry.adlr
///   chars:u16                entry.info_name_length
///   filename:utf16le         unknown
///   optional_nul:u16         0
fn build_structured_layout(
    entries: &[Entry],
    trailing_nul: bool,
    limit: usize,
) -> Option<StructuredLayoutModel> {
    let take = limit.min(entries.len());
    if take == 0 {
        return None;
    }

    let mut constraints = Vec::with_capacity(take.saturating_mul(16));
    let mut record_starts = Vec::with_capacity(take);
    let mut filename_high_offsets = Vec::new();
    let mut rel = 0usize;

    for entry in entries.iter().take(take) {
        let chars = entry.info_name_length;
        // The strict verified M2 path also requires both fields, so there is no
        // benefit in fabricating a structural model when either is absent.
        let hash = entry.adler?;
        if chars == 0 || chars as usize > MAX_RECORD_NAME_CHARS {
            return None;
        }

        let filename_bytes = (chars as usize).checked_mul(2)?;
        let trailing = if trailing_nul { 2usize } else { 0usize };
        let payload_size = 6usize.checked_add(filename_bytes)?.checked_add(trailing)?;
        let body = rel.checked_add(12)?;

        record_starts.push(rel);

        for (j, byte) in (payload_size as u64)
            .to_le_bytes()
            .iter()
            .copied()
            .enumerate()
        {
            constraints.push((rel.checked_add(4)?.checked_add(j)?, byte));
        }
        for (j, byte) in hash.to_le_bytes().iter().copied().enumerate() {
            constraints.push((body.checked_add(j)?, byte));
        }
        for (j, byte) in chars.to_le_bytes().iter().copied().enumerate() {
            constraints.push((body.checked_add(4)?.checked_add(j)?, byte));
        }

        let name_start = body.checked_add(6)?;
        for ch in 0..chars as usize {
            filename_high_offsets.push(name_start.checked_add(ch.checked_mul(2)?)?.checked_add(1)?);
        }

        if trailing_nul {
            let nul = name_start.checked_add(filename_bytes)?;
            constraints.push((nul, 0));
            constraints.push((nul.checked_add(1)?, 0));
        }

        rel = rel.checked_add(12)?.checked_add(payload_size)?;
    }

    Some(StructuredLayoutModel {
        constraints,
        record_starts,
        filename_high_offsets,
        span: rel,
    })
}

fn derive_structured_pattern(
    blob: &[u8],
    start: usize,
    period: usize,
    constraints: &[(usize, u8)],
    pattern: &mut [Option<u8>],
) -> Option<(usize, usize)> {
    if period == 0 || pattern.len() != period {
        return None;
    }
    pattern.fill(None);
    let mut known = 0usize;
    let mut repeats = 0usize;

    for &(rel, plain) in constraints {
        let absolute = start.checked_add(rel)?;
        let cipher = *blob.get(absolute)?;
        let residue = absolute % period;
        let key = cipher ^ plain;
        match pattern[residue] {
            Some(old) if old != key => return None,
            Some(_) => repeats += 1,
            None => {
                pattern[residue] = Some(key);
                known += 1;
            }
        }
    }
    Some((known, repeats))
}

fn known_pattern_bytes(pattern: &[Option<u8>]) -> usize {
    pattern.iter().filter(|value| value.is_some()).count()
}

/// Once exact metadata has recovered some residues, the repeated dynamic record
/// tag can recover more: C[pos+j] ^ K[(pos+j)%L] must be the same tag byte for
/// every record.  Only a perfectly consistent tag byte is accepted here.
fn augment_with_repeated_tag(
    blob: &[u8],
    start: usize,
    period: usize,
    record_starts: &[usize],
    pattern: &mut [Option<u8>],
) -> bool {
    for tag_byte in 0..4usize {
        let mut inferred_tag: Option<u8> = None;
        let mut observations = 0usize;

        for &record_rel in record_starts {
            let Some(absolute) = start
                .checked_add(record_rel)
                .and_then(|v| v.checked_add(tag_byte))
            else {
                return false;
            };
            let Some(&cipher) = blob.get(absolute) else {
                return false;
            };
            let residue = absolute % period;
            let Some(key) = pattern[residue] else {
                continue;
            };
            let candidate = cipher ^ key;
            match inferred_tag {
                Some(old) if old != candidate => return false,
                Some(_) => observations += 1,
                None => {
                    inferred_tag = Some(candidate);
                    observations = 1;
                }
            }
        }

        // A single observation merely transfers one unknown to another.  Two
        // agreeing exact observations are enough to identify this tag byte.
        let Some(tag) = inferred_tag.filter(|_| observations >= 2) else {
            continue;
        };

        for &record_rel in record_starts {
            let Some(absolute) = start
                .checked_add(record_rel)
                .and_then(|v| v.checked_add(tag_byte))
            else {
                return false;
            };
            let Some(&cipher) = blob.get(absolute) else {
                return false;
            };
            let residue = absolute % period;
            let key = cipher ^ tag;
            match pattern[residue] {
                Some(old) if old != key => return false,
                Some(_) => {}
                None => pattern[residue] = Some(key),
            }
        }
    }
    true
}

fn most_frequent_byte(hist: &[u32; 256]) -> Option<(u8, u32, u32)> {
    let mut best = 0usize;
    let mut best_count = 0u32;
    let mut second = 0u32;
    for (byte, &count) in hist.iter().enumerate() {
        if count > best_count {
            second = best_count;
            best_count = count;
            best = byte;
        } else if count > second {
            second = count;
        }
    }
    (best_count != 0).then_some((best as u8, best_count, second))
}

/// Complete still-unknown residues with the zero-byte signal discussed in the
/// attack model.  Exact metadata and repeated-tag equations always win.  The
/// UTF-16 high-byte histogram is preferred only when it has a clear mode; the
/// generic table-wide mode is the fallback.  These guesses are never trusted by
/// themselves: the fully decrypted stream must pass the strict M2/archive oracle.
fn complete_pattern_with_zero_votes(
    blob: &[u8],
    start: usize,
    model: &StructuredLayoutModel,
    period: usize,
    pattern: &mut [Option<u8>],
    prefer_utf16_high: bool,
) -> Option<usize> {
    let end = start.checked_add(model.span)?;
    if end > blob.len() {
        return None;
    }

    let mut table_hist = vec![[0u32; 256]; period];
    for absolute in start..end {
        table_hist[absolute % period][blob[absolute] as usize] += 1;
    }

    let mut high_hist = if prefer_utf16_high {
        Some(vec![[0u32; 256]; period])
    } else {
        None
    };
    if let Some(hist) = high_hist.as_mut() {
        for &rel in &model.filename_high_offsets {
            let absolute = start.checked_add(rel)?;
            let &cipher = blob.get(absolute)?;
            hist[absolute % period][cipher as usize] += 1;
        }
    }

    let mut guessed = 0usize;
    for residue in 0..period {
        if pattern[residue].is_some() {
            continue;
        }

        let mut chosen = None;
        if let Some(hist) = high_hist.as_ref() {
            if let Some((byte, best, second)) = most_frequent_byte(&hist[residue]) {
                // Do not turn a handful of Japanese/non-ASCII high bytes into a
                // hard assumption.  A clear repeated mode is required.
                if best >= 3 && best >= second.saturating_add(2) {
                    chosen = Some(byte);
                }
            }
        }
        if chosen.is_none() {
            chosen = most_frequent_byte(&table_hist[residue]).map(|(byte, _, _)| byte);
        }
        pattern[residue] = chosen;
        if chosen.is_some() {
            guessed += 1;
        }
    }
    Some(guessed)
}

fn structured_period_candidates(max_period: usize) -> Vec<usize> {
    let max_period = max_period.min(HARD_MAX_XOR_PERIOD);
    if max_period == 0 {
        return Vec::new();
    }

    // The command-line value is tried as an exact high-priority hypothesis,
    // followed by the common power-of-two periods used by the content solver.
    // This keeps the structured attack cheap while making the default 1024 case
    // immediate.  Small historical periods still get exhaustive treatment from
    // brute_historical_xor().
    let mut out = Vec::new();
    for period in [max_period, 1024usize, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1] {
        if period != 0 && period <= max_period && !out.contains(&period) {
            out.push(period);
        }
    }
    out
}

fn zero_mode_key(blob: &[u8], period: usize) -> Option<Vec<u8>> {
    if period == 0 || blob.is_empty() {
        return None;
    }
    let mut hist = vec![[0u32; 256]; period];
    for (offset, &cipher) in blob.iter().enumerate() {
        hist[offset % period][cipher as usize] += 1;
    }
    let mut key = Vec::with_capacity(period);
    for residue in 0..period {
        key.push(most_frequent_byte(&hist[residue])?.0);
    }
    Some(key)
}

/// Use the zero-mode key only as a *locator*, never as proof.  The correct M2
/// table start should make the first retained entry's exact six-byte
/// `adlr || FileNameLength` anchor decrypt better than random positions even if
/// a few key residues have the wrong mode.  Exact consistency and full parsing
/// still decide acceptance.
fn zero_seeded_table_starts(
    blob: &[u8],
    entries: &[Entry],
    period: usize,
    max_start: usize,
    limit: usize,
) -> Vec<usize> {
    let Some(first) = entries.first() else {
        return Vec::new();
    };
    let Some(hash) = first.adler else {
        return Vec::new();
    };
    if first.info_name_length == 0 {
        return Vec::new();
    }
    let Some(mode_key) = zero_mode_key(blob, period) else {
        return Vec::new();
    };

    let mut needle = [0u8; 6];
    needle[..4].copy_from_slice(&hash.to_le_bytes());
    needle[4..].copy_from_slice(&first.info_name_length.to_le_bytes());

    // score buckets 0..=6.  Keeping score>=2 avoids retaining the enormous
    // random score-0/1 population while still tolerating several wrong mode
    // residues in the initial statistical key.
    let mut buckets: Vec<Vec<usize>> = (0..=6).map(|_| Vec::new()).collect();
    if blob.len() < 18 {
        return Vec::new();
    }
    let last_body = blob.len().saturating_sub(needle.len());
    for body_start in 12..=last_body {
        let start = body_start - 12;
        if start > max_start {
            break;
        }
        let mut score = 0usize;
        for (j, &plain) in needle.iter().enumerate() {
            let absolute = body_start + j;
            if blob[absolute] ^ mode_key[absolute % period] == plain {
                score += 1;
            }
        }
        if score >= 2 {
            buckets[score].push(start);
        }
    }

    let mut out = Vec::with_capacity(limit.min(512));
    for score in (2..=6).rev() {
        for &start in &buckets[score] {
            if !out.contains(&start) {
                out.push(start);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

fn try_structured_candidate(
    blob: &[u8],
    entries: &[Entry],
    start: usize,
    period: usize,
    trailing_nul: bool,
    full: &StructuredLayoutModel,
) -> Option<StructuredXorHit> {
    let mut exact = vec![None; period];
    let (exact_known_before_tag, _) =
        derive_structured_pattern(blob, start, period, &full.constraints, &mut exact)?;
    if !augment_with_repeated_tag(blob, start, period, &full.record_starts, &mut exact) {
        return None;
    }
    let exact_known = known_pattern_bytes(&exact).max(exact_known_before_tag);

    // Try the filename-specific zero vote first, then the more generic
    // table-wide zero mode.  In the common 1024-byte case the exact size/hash/
    // length constraints usually cover every residue, so neither path guesses.
    for prefer_utf16_high in [true, false] {
        let mut candidate = exact.clone();
        let zero_guessed = complete_pattern_with_zero_votes(
            blob,
            start,
            full,
            period,
            &mut candidate,
            prefer_utf16_high,
        )?;
        if candidate.iter().any(|value| value.is_none()) {
            continue;
        }
        let key: Vec<u8> = candidate.into_iter().map(|value| value.unwrap()).collect();
        let mut decoded = blob.to_vec();
        xor_repeating_in_place(&mut decoded, &key, 0);

        let Some(names) = scan_m2_chunks_against_entries(&decoded, entries) else {
            continue;
        };
        if names.len() != entries.len() {
            continue;
        }
        return Some(StructuredXorHit {
            period,
            start,
            trailing_nul,
            exact_known,
            zero_guessed,
            key,
            decoded,
            names,
        });
    }
    None
}

/// Recover a raw structured M2/Yuzu special index protected by a whole-stream
/// repeating XOR.  This is intentionally CPU/Rayon work: for period 1024 the
/// useful problem is consistency of a few tens of thousands of exact byte
/// equations, not a GPU-sized 256^1024 brute-force search.
fn recover_structured_m2_xor_blob(
    blob: &[u8],
    entries: &[Entry],
    max_period: usize,
    root_index: usize,
    observer: Option<&(dyn Fn(SpecialRecoveryProgress) + Sync)>,
) -> Option<StructuredXorHit> {
    if entries.len() < 2 || blob.len() < 18 {
        return None;
    }

    for period in structured_period_candidates(max_period) {
        if period == 0 || period > blob.len() {
            continue;
        }

        let probe_entries = (period / 8).max(64).min(512).min(entries.len());
        let required_repeats = (period / 32).max(16).min(128);

        for trailing_nul in [false, true] {
            let Some(full) = build_structured_layout(entries, trailing_nul, entries.len()) else {
                continue;
            };
            if full.span > blob.len() {
                continue;
            }
            let Some(probe) = build_structured_layout(entries, trailing_nul, probe_entries) else {
                continue;
            };

            let max_start = blob.len() - full.span;

            // First use the plaintext-zero mode as a cheap locator for the exact
            // first-record anchor.  These candidates are still subjected to all
            // exact constraints and the full parser; the statistical seed is
            // never an acceptance criterion.
            let seeded = zero_seeded_table_starts(blob, entries, period, max_start, 512);
            if !seeded.is_empty() {
                let mut quick_pattern = vec![None; period];
                for start in seeded {
                    let Some((_, repeats)) = derive_structured_pattern(
                        blob,
                        start,
                        period,
                        &probe.constraints,
                        &mut quick_pattern,
                    ) else {
                        continue;
                    };
                    if repeats < required_repeats {
                        continue;
                    }
                    if let Some(hit) =
                        try_structured_candidate(blob, entries, start, period, trailing_nul, &full)
                    {
                        return Some(hit);
                    }
                }
            }

            // If the zero-mode locator was too noisy (for example, a heavily
            // non-ASCII table), fall back to a parallel exact-consistency scan.
            let total = max_start.saturating_add(1);
            if let Some(observer) = observer {
                observer(SpecialRecoveryProgress {
                    root_index,
                    scope: SpecialXorScope::Whole,
                    compression: if trailing_nul {
                        "structured-m2+nul"
                    } else {
                        "structured-m2"
                    },
                    period,
                    done: 0,
                    total,
                });
            }

            let chunk_size = 256usize;
            let chunk_count = (total + chunk_size - 1) / chunk_size;
            let completed = AtomicUsize::new(0);

            let hit = (0..chunk_count)
                .into_par_iter()
                .find_map_any(|chunk_index| {
                    let begin = chunk_index * chunk_size;
                    let end = (begin + chunk_size).min(total);
                    let mut quick_pattern = vec![None; period];
                    let mut processed = 0usize;

                    for start in begin..end {
                        processed += 1;
                        let Some((_, repeats)) = derive_structured_pattern(
                            blob,
                            start,
                            period,
                            &probe.constraints,
                            &mut quick_pattern,
                        ) else {
                            continue;
                        };
                        if repeats < required_repeats {
                            continue;
                        }

                        if let Some(hit) = try_structured_candidate(
                            blob,
                            entries,
                            start,
                            period,
                            trailing_nul,
                            &full,
                        ) {
                            let done =
                                completed.fetch_add(processed, Ordering::Relaxed) + processed;
                            if let Some(observer) = observer {
                                observer(SpecialRecoveryProgress {
                                    root_index,
                                    scope: SpecialXorScope::Whole,
                                    compression: if trailing_nul {
                                        "structured-m2+nul"
                                    } else {
                                        "structured-m2"
                                    },
                                    period,
                                    done: done.min(total),
                                    total,
                                });
                            }
                            return Some(hit);
                        }
                    }

                    let done = completed.fetch_add(processed, Ordering::Relaxed) + processed;
                    if let Some(observer) = observer {
                        observer(SpecialRecoveryProgress {
                            root_index,
                            scope: SpecialXorScope::Whole,
                            compression: if trailing_nul {
                                "structured-m2+nul"
                            } else {
                                "structured-m2"
                            },
                            period,
                            done: done.min(total),
                            total,
                        });
                    }
                    None
                });

            if hit.is_some() {
                return hit;
            }
        }
    }
    None
}

/// Cheapest large-period special-index attempt: assume plaintext zero is common
/// for each residue, decrypt with the modal ciphertext byte, and immediately
/// hand the result to the existing strict parsers.  The mode itself is never
/// treated as proof.
fn recover_zero_mode_whole_xor(
    archive: &Archive,
    root_index: usize,
    root: &RootChunk,
    blob: &[u8],
    max_period: usize,
) -> Option<SpecialIndexRecovery> {
    for period in structured_period_candidates(max_period) {
        if period == 0 || period > blob.len() {
            continue;
        }
        let key = zero_mode_key(blob, period)?;
        let mut candidate = blob.to_vec();
        xor_repeating_in_place(&mut candidate, &key, 0);

        // Raw structured plaintext is the expected fast case.  Reuse the same
        // direct wrapper decoder as the normal path so a statistically recovered
        // key can also expose zlib/gzip when applicable.
        for (wrapper, decoded) in direct_decode_candidates(&candidate, root) {
            let Some((layout, names, confidence)) =
                recover_ordered_names_from_decoded_for_archive(&decoded, archive)
            else {
                continue;
            };
            return Some(SpecialIndexRecovery {
                root_index,
                decoder: format!("zero-mode-xor-whole-period{}->{}", period, wrapper),
                layout,
                names,
                confidence,
                decoded,
                xor: Some(SpecialXorRecovery {
                    key,
                    scope: SpecialXorScope::Whole,
                    table_start: 0,
                }),
            });
        }
    }
    None
}

fn recover_structured_whole_xor(
    archive: &Archive,
    root_index: usize,
    blob: &[u8],
    max_period: usize,
    observer: Option<&(dyn Fn(SpecialRecoveryProgress) + Sync)>,
) -> Option<SpecialIndexRecovery> {
    let hit = recover_structured_m2_xor_blob(
        blob,
        &archive.entries,
        max_period.min(HARD_MAX_XOR_PERIOD),
        root_index,
        observer,
    )?;

    Some(SpecialIndexRecovery {
        root_index,
        decoder: format!(
            "structured-xor-whole-period{}-start0x{:x}-exact{}/{}-zero{}{}",
            hit.period,
            hit.start,
            hit.exact_known,
            hit.period,
            hit.zero_guessed,
            if hit.trailing_nul { "-nul" } else { "" }
        ),
        layout: "ordered-M2/Yuzu-verified".to_string(),
        names: hit.names,
        confidence: 100,
        decoded: hit.decoded,
        xor: Some(SpecialXorRecovery {
            key: hit.key,
            scope: SpecialXorScope::Whole,
            table_start: hit.start,
        }),
    })
}

fn brute_historical_xor(
    archive: &Archive,
    root_index: usize,
    root: &RootChunk,
    blob: &[u8],
    max_period: usize,
    observer: Option<&(dyn Fn(SpecialRecoveryProgress) + Sync)>,
) -> Option<SpecialIndexRecovery> {
    if blob.len() < 3 {
        return None;
    }
    let expected_size = root
        .inferred_original_size
        .and_then(|v| usize::try_from(v).ok());
    let max_period = max_period.min(LEGACY_BRUTE_MAX_XOR_PERIOD).max(1);

    // Historical prefix transform first.  Whole-stream repeating XOR is a
    // secondary compatibility model and never suppresses the prefix path.
    for scope in [SpecialXorScope::Prefix100, SpecialXorScope::Whole] {
        // zlib is the historical KrkrExtract/SenrenBanka path. gzip is a cheap
        // compatibility extension for later wrappers because its first three
        // bytes are fixed and therefore constrain more key residues.
        for compression in [SpecialCompression::Zlib, SpecialCompression::Gzip] {
            for period in 1..=max_period {
                for &header in compression.headers() {
                    let Some(pattern) = derive_key_pattern(blob, period, header) else {
                        continue;
                    };
                    let unknown = pattern.iter().filter(|value| value.is_none()).count();
                    let total = 256usize.checked_pow(unknown as u32)?;

                    if let Some(observer) = observer {
                        observer(SpecialRecoveryProgress {
                            root_index,
                            scope,
                            compression: compression.label(),
                            period,
                            done: 0,
                            total,
                        });
                    }

                    // Chunk candidate assignments.  This both lowers Rayon
                    // scheduling overhead and lets progress reporting update once
                    // per block instead of once per zlib/gzip attempt.
                    let chunk_size = if total >= (1 << 20) {
                        4096usize
                    } else {
                        256usize
                    };
                    let chunk_count = (total + chunk_size - 1) / chunk_size;
                    let completed = AtomicUsize::new(0);
                    let hit = (0..chunk_count)
                        .into_par_iter()
                        .find_map_any(|chunk_index| {
                            let begin = chunk_index * chunk_size;
                            let end = (begin + chunk_size).min(total);
                            let mut processed = 0usize;
                            for assignment in begin..end {
                                processed += 1;
                                let Some(key) = complete_key_pattern(&pattern, assignment) else {
                                    continue;
                                };
                                let Some(decoded) = try_compressed_xor(
                                    blob,
                                    &key,
                                    scope.limit(blob.len()),
                                    expected_size,
                                    compression,
                                ) else {
                                    continue;
                                };
                                let Some((layout, names, confidence)) =
                                    recover_ordered_names_from_decoded_for_archive(
                                        &decoded, archive,
                                    )
                                else {
                                    continue;
                                };
                                let done =
                                    completed.fetch_add(processed, Ordering::Relaxed) + processed;
                                if let Some(observer) = observer {
                                    observer(SpecialRecoveryProgress {
                                        root_index,
                                        scope,
                                        compression: compression.label(),
                                        period,
                                        done: done.min(total),
                                        total,
                                    });
                                }
                                return Some(SpecialIndexRecovery {
                                    root_index,
                                    decoder: format!(
                                        "historical-xor-{}-period{}-key{}->{}",
                                        scope.label(),
                                        period,
                                        hex_key(&key),
                                        compression.label()
                                    ),
                                    layout,
                                    names,
                                    confidence,
                                    decoded,
                                    xor: Some(SpecialXorRecovery {
                                        key,
                                        scope,
                                        table_start: 0,
                                    }),
                                });
                            }
                            let done =
                                completed.fetch_add(processed, Ordering::Relaxed) + processed;
                            if let Some(observer) = observer {
                                observer(SpecialRecoveryProgress {
                                    root_index,
                                    scope,
                                    compression: compression.label(),
                                    period,
                                    done: done.min(total),
                                    total,
                                });
                            }
                            None
                        });
                    if hit.is_some() {
                        return hit;
                    }
                }
            }
        }
    }
    None
}

fn derive_key_pattern(blob: &[u8], period: usize, known_prefix: &[u8]) -> Option<Vec<Option<u8>>> {
    if period == 0 || blob.len() < known_prefix.len() || known_prefix.is_empty() {
        return None;
    }
    let mut pattern = vec![None; period];
    for (offset, &plain) in known_prefix.iter().enumerate() {
        let residue = offset % period;
        let key_byte = blob[offset] ^ plain;
        match pattern[residue] {
            Some(old) if old != key_byte => return None,
            Some(_) => {}
            None => pattern[residue] = Some(key_byte),
        }
    }
    Some(pattern)
}

fn complete_key_pattern(pattern: &[Option<u8>], mut assignment: usize) -> Option<Vec<u8>> {
    if pattern.is_empty() {
        return None;
    }
    let mut key = Vec::with_capacity(pattern.len());
    for value in pattern {
        match value {
            Some(byte) => key.push(*byte),
            None => {
                key.push((assignment & 0xff) as u8);
                assignment >>= 8;
            }
        }
    }
    Some(key)
}

fn hex_key(key: &[u8]) -> String {
    let mut out = String::with_capacity(key.len() * 2);
    for byte in key {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Strict archive-aware parser for a *plaintext* special-index stream.
///
/// For historical M2/Yuzu records the ordinary XP3 index gives us two strong
/// per-entry invariants: the record hash is the corresponding `adlr`, and the
/// record filename length is the raw `info.FileNameLength`.  This is the primary
/// acceptance path and is intentionally stronger than filename plausibility.
pub fn recover_ordered_names_from_decoded_for_archive(
    data: &[u8],
    archive: &Archive,
) -> Option<(String, Vec<String>, u8)> {
    if let Some(names) = scan_m2_chunks_against_archive(data, archive) {
        return Some(("ordered-M2/Yuzu-verified".to_string(), names, 100));
    }

    // A title may put a complete ordinary XP3 File/info stream in the special
    // payload.  This is also exact structural parsing, although it cannot use
    // the M2 hash/length leak.
    if let Some(names) = scan_xp3_file_stream(data, archive.entries.len()) {
        if names.len() == archive.entries.len() {
            return Some(("ordered-XP3-File-info".to_string(), names, 99));
        }
    }

    // After a family-specific decoder (e.g. Hx) has already produced plaintext,
    // retain narrowly structured ordered-table compatibility.  Random ciphertext
    // never reaches this point through automatic recovery unless it has also
    // passed a real decompressor.
    recover_ordered_names_from_decoded(data, archive.entries.len())
}

/// Parse an already-decoded special-index payload when ordinary XP3 metadata is
/// unavailable to the caller.  This compatibility API is structure-only: it no
/// longer performs NUL-string carving over arbitrary byte ranges.
pub fn recover_ordered_names_from_decoded(
    data: &[u8],
    expected: usize,
) -> Option<(String, Vec<String>, u8)> {
    if expected == 0 {
        return None;
    }

    if let Some(names) = scan_m2_name_chunks_structural(data, expected) {
        return Some(("ordered-M2-chunks".to_string(), names, 96));
    }
    if let Some(names) = scan_xp3_file_stream(data, expected) {
        return Some(("ordered-XP3-File-info".to_string(), names, 95));
    }
    if let Some(names) = scan_len_prefixed_utf16_exact(data, expected, 2) {
        return Some(("ordered-u16len-utf16".to_string(), names, 90));
    }
    if let Some(names) = scan_len_prefixed_utf16_exact(data, expected, 4) {
        return Some(("ordered-u32len-utf16".to_string(), names, 89));
    }
    None
}

fn scan_m2_chunks_against_archive(data: &[u8], archive: &Archive) -> Option<Vec<String>> {
    scan_m2_chunks_against_entries(data, &archive.entries)
}

fn scan_m2_chunks_against_entries(data: &[u8], entries: &[Entry]) -> Option<Vec<String>> {
    if entries.is_empty() || data.len() < 18 {
        return None;
    }

    // Do not assume the ordered name stream starts at byte zero.  The ordinary
    // XP3 index leaks the first retained entry's Adler/hash and its *real*
    // UTF-16 filename length, so the 6-byte M2 body prefix is a strong locator:
    //
    //     body[0..4] = adlr/hash, body[4..6] = FileNameLength
    //
    // Search that exact prefix across the complete decoded special payload,
    // then step back 12 bytes to the generic `tag:u32 + size:u64` header and
    // validate the whole ordered stream.  This is structure reconstruction,
    // not ciphertext/string carving, and it allows arbitrarily large vendor
    // metadata before the filename table.
    if let Some(first) = entries.first() {
        if let (Some(hash), chars) = (first.adler, first.info_name_length) {
            if chars != 0 {
                let mut needle = [0u8; 6];
                needle[..4].copy_from_slice(&hash.to_le_bytes());
                needle[4..].copy_from_slice(&chars.to_le_bytes());
                let mut from = 12usize;
                while let Some(body_start) = find_bytes_from(data, &needle, from) {
                    if body_start >= 12 {
                        let start = body_start - 12;
                        if let Some(names) = walk_verified_chunk_stream(&data[start..], entries) {
                            if names.len() == entries.len() {
                                return Some(names);
                            }
                        }
                    }
                    from = body_start.saturating_add(1);
                    if from >= data.len() {
                        break;
                    }
                }
            }
        }
    }

    // Compatibility fallback for a special payload whose ordinary first entry
    // lacks `adlr`/raw length.  Keep this bounded because it does not have the
    // strong 6-byte locator above.
    let scan_end = data.len().min(4096);
    for start in 0..scan_end {
        if let Some(names) = walk_verified_chunk_stream(&data[start..], entries) {
            if names.len() == entries.len() {
                return Some(names);
            }
        }
    }
    None
}

fn find_bytes_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty()
        || from > haystack.len()
        || needle.len() > haystack.len().saturating_sub(from)
    {
        return None;
    }
    let first = needle[0];
    let last = haystack.len() - needle.len();
    let mut i = from;
    while i <= last {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn walk_verified_chunk_stream(data: &[u8], entries: &[Entry]) -> Option<Vec<String>> {
    let mut pos = 0usize;
    let mut entry_index = 0usize;
    let mut names = Vec::with_capacity(entries.len());
    let mut learned_record_tag: Option<u32> = None;
    let mut saw_chunk = false;
    let mut unknown_chunks = 0usize;

    while pos < data.len() && entry_index < entries.len() {
        if pos + 12 > data.len() {
            return None;
        }
        let tag = read_u32(data, pos)?;
        let payload_size = usize::try_from(read_u64(data, pos + 4)?).ok()?;
        if payload_size > MAX_CHUNK_BODY {
            return None;
        }
        let body_start = pos.checked_add(12)?;
        let end = body_start.checked_add(payload_size)?;
        if end > data.len() {
            return None;
        }
        saw_chunk = true;
        let body = &data[body_start..end];
        let record = parse_m2_record(body);

        match learned_record_tag {
            Some(record_tag) if tag == record_tag => {
                // Once the dynamic M2/Yuzu magic has been learned, every chunk
                // carrying that same magic is a filename record.  A malformed or
                // metadata-mismatching record invalidates the candidate instead of
                // being reclassified as an "unknown" chunk; otherwise a wrong
                // decryption could skip evidence until it accidentally aligns.
                let record = record?;
                if is_protected_like(&record.name) {
                    // Some protected XP3 archives retain the warning pseudo-file
                    // as an ordinary Entry, while others drop it during parsing.
                    // Preserve positional alignment in both cases: consume the
                    // archive Entry only when it is itself the protected dummy.
                    if entries
                        .get(entry_index)
                        .is_some_and(Entry::is_protected_dummy)
                    {
                        names.push(record.name);
                        entry_index += 1;
                    }
                    pos = end;
                    continue;
                }
                let expected = entries.get(entry_index)?;
                if !record_matches_entry(&record, expected) {
                    return None;
                }
                names.push(record.name);
                entry_index += 1;
                pos = end;
                continue;
            }
            Some(_) => {
                // Future/unknown side metadata keeps the generic XP3 root framing.
                // It does not consume an ordinary file entry.
                unknown_chunks += 1;
                if unknown_chunks > 4096 {
                    return None;
                }
                pos = end;
                continue;
            }
            None => {
                if let Some(record) = record {
                    if is_protected_like(&record.name) {
                        // The protected pseudo-record uses the same dynamic M2 tag.
                        // Archives differ on whether the ordinary XP3 index retains
                        // the corresponding warning Entry.  If it is retained, keep
                        // the ordered-name vector aligned by consuming it here;
                        // otherwise skip only the Special record.
                        learned_record_tag = Some(tag);
                        if entries
                            .get(entry_index)
                            .is_some_and(Entry::is_protected_dummy)
                        {
                            names.push(record.name);
                            entry_index += 1;
                        }
                        pos = end;
                        continue;
                    }
                    let expected = entries.get(entry_index)?;
                    if record_matches_entry(&record, expected) {
                        learned_record_tag = Some(tag);
                        names.push(record.name);
                        entry_index += 1;
                        pos = end;
                        continue;
                    }
                }

                // A small vendor preamble or side chunk may precede the first
                // filename record.  Bounds have already been checked, so preserve
                // synchronization and keep looking; the first accepted record still
                // has to match both leaked hash and raw filename length.
                unknown_chunks += 1;
                if unknown_chunks > 4096 {
                    return None;
                }
                pos = end;
            }
        }
    }

    if saw_chunk && learned_record_tag.is_some() && entry_index == entries.len() {
        Some(names)
    } else {
        None
    }
}

fn parse_m2_record(body: &[u8]) -> Option<ParsedNameRecord> {
    if body.len() < 6 {
        return None;
    }
    let hash = read_u32(body, 0)?;
    let chars = read_u16(body, 4)?;
    let char_count = chars as usize;
    if char_count == 0 || char_count > MAX_RECORD_NAME_CHARS {
        return None;
    }
    let byte_len = char_count.checked_mul(2)?;
    let name_end = 6usize.checked_add(byte_len)?;
    if name_end > body.len() {
        return None;
    }

    // Historical variants are exact-length or carry one UTF-16 NUL.  Future
    // fields are not accepted here because hash+length matching is used as a
    // cryptographic oracle; widening this parser would weaken that oracle.
    let trailing = &body[name_end..];
    if !(trailing.is_empty() || trailing == &[0, 0]) {
        return None;
    }
    let name = decode_utf16le(&body[6..name_end])?;
    if !plausible_name(&name) {
        return None;
    }
    Some(ParsedNameRecord {
        name: normalize_name(name),
        hash,
        chars,
    })
}

fn record_matches_entry(record: &ParsedNameRecord, entry: &Entry) -> bool {
    let hash_ok = entry.adler.map(|v| v == record.hash).unwrap_or(false);
    let length_ok = entry.info_name_length != 0 && entry.info_name_length == record.chars;
    hash_ok && length_ok
}

fn scan_m2_name_chunks_structural(data: &[u8], expected: usize) -> Option<Vec<String>> {
    if expected == 0 || data.len() < 18 {
        return None;
    }
    let scan_end = data.len().min(4096);
    for start in 0..scan_end {
        let mut pos = start;
        let mut names = Vec::with_capacity(expected);
        let mut learned_tag: Option<u32> = None;
        let mut unknown_chunks = 0usize;
        while pos + 12 <= data.len() && names.len() < expected {
            let tag = read_u32(data, pos)?;
            let payload = usize::try_from(read_u64(data, pos + 4)?).ok()?;
            if payload > MAX_CHUNK_BODY {
                break;
            }
            let body_start = pos.checked_add(12)?;
            let end = body_start.checked_add(payload)?;
            if end > data.len() {
                break;
            }
            let record = parse_m2_record(&data[body_start..end]);
            match learned_tag {
                Some(record_tag) if tag == record_tag => {
                    let Some(record) = record else {
                        break;
                    };
                    if !is_protected_like(&record.name) {
                        names.push(record.name);
                    }
                }
                Some(_) => {
                    unknown_chunks += 1;
                    if unknown_chunks > 4096 {
                        break;
                    }
                }
                None => {
                    if let Some(record) = record {
                        learned_tag = Some(tag);
                        if !is_protected_like(&record.name) {
                            names.push(record.name);
                        }
                    } else {
                        unknown_chunks += 1;
                        if unknown_chunks > 4096 {
                            break;
                        }
                    }
                }
            }
            pos = end;
        }
        if learned_tag.is_some() && names.len() == expected {
            return Some(names);
        }
    }
    None
}

fn scan_xp3_file_stream(data: &[u8], expected: usize) -> Option<Vec<String>> {
    if expected == 0 {
        return None;
    }
    let scan_end = data.len().min(4096);
    for start in 0..scan_end {
        if data.get(start..start + 4) != Some(b"File") {
            continue;
        }
        let mut pos = start;
        let mut names = Vec::with_capacity(expected);
        while pos + 12 <= data.len() && data.get(pos..pos + 4) == Some(b"File") {
            let file_size = usize::try_from(read_u64(data, pos + 4)?).ok()?;
            let file_end = pos.checked_add(12)?.checked_add(file_size)?;
            if file_end > data.len() {
                break;
            }
            let name = parse_info_name(&data[pos + 12..file_end])?;
            if !is_protected_like(&name) {
                names.push(name);
            }
            pos = file_end;
            if names.len() > expected {
                break;
            }
        }
        if names.len() == expected {
            return Some(names);
        }
    }
    None
}

fn parse_info_name(file_payload: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos + 12 <= file_payload.len() {
        let tag = file_payload.get(pos..pos + 4)?;
        let size = usize::try_from(read_u64(file_payload, pos + 4)?).ok()?;
        let body_start = pos.checked_add(12)?;
        let end = body_start.checked_add(size)?;
        if end > file_payload.len() {
            return None;
        }
        if tag == b"info" {
            if size < 22 {
                return None;
            }
            let chars = read_u16(file_payload, body_start + 20)? as usize;
            let bytes = chars.checked_mul(2)?;
            let name_start = body_start.checked_add(22)?;
            let name_end = name_start.checked_add(bytes)?;
            if name_end > end {
                return None;
            }
            let name = decode_utf16le(&file_payload[name_start..name_end])?;
            return plausible_name(&name).then(|| normalize_name(name));
        }
        pos = end;
    }
    None
}

fn scan_len_prefixed_utf16_exact(
    data: &[u8],
    expected: usize,
    width: usize,
) -> Option<Vec<String>> {
    if !matches!(width, 2 | 4) || expected == 0 {
        return None;
    }
    let scan_end = data.len().min(4096);
    for start in 0..scan_end {
        let mut pos = start;
        let mut names = Vec::with_capacity(expected);
        while names.len() < expected && pos + width <= data.len() {
            let chars = if width == 2 {
                read_u16(data, pos)? as usize
            } else {
                usize::try_from(read_u32(data, pos)?).ok()?
            };
            if chars == 0 || chars > MAX_RECORD_NAME_CHARS {
                break;
            }
            let byte_len = chars.checked_mul(2)?;
            let name_start = pos.checked_add(width)?;
            let name_end = name_start.checked_add(byte_len)?;
            if name_end > data.len() {
                break;
            }
            let name = decode_utf16le(&data[name_start..name_end])?;
            if !pathish_name(&name) {
                break;
            }
            names.push(normalize_name(name));
            pos = name_end;
            if pos + 2 <= data.len() && data[pos] == 0 && data[pos + 1] == 0 {
                pos += 2;
            }
        }
        if names.len() == expected {
            return Some(names);
        }
    }
    None
}

struct XorReader<'a> {
    data: &'a [u8],
    key: &'a [u8],
    xor_limit: usize,
    position: usize,
}

impl<'a> XorReader<'a> {
    fn new(data: &'a [u8], key: &'a [u8], xor_limit: usize) -> Self {
        Self {
            data,
            key,
            xor_limit: xor_limit.min(data.len()),
            position: 0,
        }
    }
}

impl Read for XorReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.data.len() || out.is_empty() {
            return Ok(0);
        }
        let count = out.len().min(self.data.len() - self.position);
        out[..count].copy_from_slice(&self.data[self.position..self.position + count]);
        if self.position < self.xor_limit {
            let xor_count = count.min(self.xor_limit - self.position);
            xor_repeating_in_place(&mut out[..xor_count], self.key, self.position);
        }
        self.position += count;
        Ok(count)
    }
}

fn try_compressed_xor(
    data: &[u8],
    key: &[u8],
    xor_limit: usize,
    expected_size: Option<usize>,
    compression: SpecialCompression,
) -> Option<Vec<u8>> {
    if key.is_empty() {
        return None;
    }
    let reader = XorReader::new(data, key, xor_limit);
    match compression {
        SpecialCompression::Zlib => read_limited(ZlibDecoder::new(reader), expected_size),
        SpecialCompression::Gzip => read_limited(GzDecoder::new(reader), expected_size),
    }
}

fn try_zlib_exact(data: &[u8], expected_size: Option<usize>) -> Option<Vec<u8>> {
    read_limited(ZlibDecoder::new(data), expected_size)
}

fn try_gzip_exact(data: &[u8], expected_size: Option<usize>) -> Option<Vec<u8>> {
    read_limited(GzDecoder::new(data), expected_size)
}

fn read_limited(mut reader: impl Read, expected_size: Option<usize>) -> Option<Vec<u8>> {
    let limit = expected_size
        .map(|v| v.min(MAX_SPECIAL_DECODE))
        .unwrap_or(MAX_SPECIAL_DECODE);
    let initial = expected_size.unwrap_or(8192).min(16 * 1024 * 1024);
    let mut out = Vec::with_capacity(initial);
    let mut buf = [0u8; 8192];
    loop {
        let count = reader.read(&mut buf).ok()?;
        if count == 0 {
            break;
        }
        if out.len().checked_add(count)? > limit {
            return None;
        }
        out.extend_from_slice(&buf[..count]);
    }
    if expected_size.is_some_and(|expected| out.len() != expected) {
        return None;
    }
    Some(out)
}

fn is_protected_like(name: &str) -> bool {
    is_protected_dummy_name(name)
        || name.contains("protected archive")
        || name.contains("Extracting this archive")
        || (name.contains('展') && name.contains('警'))
}

fn pathish_name(name: &str) -> bool {
    plausible_name(name) && (name.contains('/') || name.contains('\\') || has_extension(name))
}

fn has_extension(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.rfind('.')
        .is_some_and(|dot| dot > 0 && dot + 1 < base.len() && base.len() - dot <= 16)
}

fn plausible_name(name: &str) -> bool {
    let s = name.trim_matches('\0').trim();
    if s.is_empty() || s.len() > 8192 {
        return false;
    }
    if s.chars().any(|c| c.is_control() && c != '\t') {
        return false;
    }
    let total = s.chars().count().max(1);
    let valid = s.chars().filter(|&c| c != '\u{fffd}').count();
    valid * 10 >= total * 9
}

fn normalize_name(name: String) -> String {
    name.trim_matches('\0').trim().replace('\\', "/")
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16(&words).ok()
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(off..off + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xp3::Entry;

    fn m2_record(magic: &[u8; 4], hash: u32, name: &str) -> Vec<u8> {
        let words: Vec<u16> = name.encode_utf16().collect();
        let payload = 6 + words.len() * 2;
        let mut out = Vec::new();
        out.extend_from_slice(magic);
        out.extend_from_slice(&(payload as u64).to_le_bytes());
        out.extend_from_slice(&hash.to_le_bytes());
        out.extend_from_slice(&(words.len() as u16).to_le_bytes());
        for word in words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn structural_m2_parser_learns_magic() {
        let mut data = Vec::new();
        data.extend_from_slice(&m2_record(b"ABCD", 1, "scenario/a.ks"));
        data.extend_from_slice(&m2_record(b"ABCD", 2, "image/b.png"));
        let got = recover_ordered_names_from_decoded(&data, 2).unwrap();
        assert_eq!(got.0, "ordered-M2-chunks");
        assert_eq!(got.1, vec!["scenario/a.ks", "image/b.png"]);
    }

    #[test]
    fn verified_stream_consumes_retained_protected_dummy_entry() {
        let protected = "$$$ This is a protected archive. $$$ synthetic warning.txt";
        let real = "scenario/real.ks";
        let mut data = Vec::new();
        data.extend_from_slice(&m2_record(b"hnfn", 0x6897_92e4, protected));
        data.extend_from_slice(&m2_record(b"hnfn", 0x1122_3344, real));

        let entries = vec![
            Entry {
                name: protected.to_string(),
                info_name_length: protected.encode_utf16().count() as u16,
                adler: Some(0x6897_92e4),
                ..Entry::default()
            },
            Entry {
                name: "hashed-or-visible-token".to_string(),
                info_name_length: real.encode_utf16().count() as u16,
                adler: Some(0x1122_3344),
                ..Entry::default()
            },
        ];

        let got = walk_verified_chunk_stream(&data, &entries).unwrap();
        assert_eq!(got, vec![protected.to_string(), real.to_string()]);
    }

    #[test]
    fn verified_stream_skips_unknown_chunk_without_consuming_entry() {
        let names = ["scenario/a.ks", "image/b.png"];
        let mut data = Vec::new();
        data.extend_from_slice(&m2_record(b"Yuzu", 0x11223344, names[0]));
        data.extend_from_slice(b"NEW!");
        data.extend_from_slice(&3u64.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3]);
        data.extend_from_slice(&m2_record(b"Yuzu", 0x55667788, names[1]));

        let entries = vec![
            Entry {
                info_name_length: names[0].encode_utf16().count() as u16,
                adler: Some(0x11223344),
                ..Entry::default()
            },
            Entry {
                info_name_length: names[1].encode_utf16().count() as u16,
                adler: Some(0x55667788),
                ..Entry::default()
            },
        ];
        let got = walk_verified_chunk_stream(&data, &entries).unwrap();
        assert_eq!(got, names);
    }

    #[test]
    fn xor_reader_only_changes_requested_prefix() {
        let data = [1u8, 2, 3, 4, 5, 6];
        let key = [0x10u8, 0x20];
        let mut reader = XorReader::new(&data, &key, 4);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, vec![0x11, 0x22, 0x13, 0x24, 5, 6]);
    }
    #[test]
    fn historical_prefix_transform_round_trip_matches_krkrextract_ordering() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let mut entries = Vec::new();
        let mut plain_index = Vec::new();
        for i in 0..32u32 {
            let name = format!(
                "scenario/route_{i:02}/scene_{:08x}.ks",
                i.wrapping_mul(0x9e37_79b9)
            );
            let hash = 0x1020_3040u32.wrapping_add(i.wrapping_mul(0x0101_0101));
            plain_index.extend_from_slice(&m2_record(b"M2X!", hash, &name));
            entries.push(Entry {
                info_name_length: name.encode_utf16().count() as u16,
                adler: Some(hash),
                ..Entry::default()
            });
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&plain_index).unwrap();
        let mut stored = encoder.finish().unwrap();
        assert!(stored.len() > HISTORICAL_PREFIX);

        let key = [0x31u8, 0xa7, 0x5c, 0xe2];
        xor_repeating_in_place(&mut stored[..HISTORICAL_PREFIX], &key, 0);
        let decoded = try_compressed_xor(
            &stored,
            &key,
            HISTORICAL_PREFIX,
            Some(plain_index.len()),
            SpecialCompression::Zlib,
        )
        .unwrap();
        assert_eq!(decoded, plain_index);
        let names = walk_verified_chunk_stream(&decoded, &entries).unwrap();
        assert_eq!(names.len(), entries.len());
        assert_eq!(names[0], "scenario/route_00/scene_00000000.ks");
    }

    #[test]
    fn verified_m2_stream_can_start_deep_inside_plain_special_payload() {
        let name = "scenario/deep/real_name.ks";
        let hash = 0x44332211u32;
        let mut data = vec![0x5au8; 32 * 1024];
        data.extend_from_slice(&m2_record(b"FUT!", hash, name));
        let entries = vec![Entry {
            info_name_length: name.encode_utf16().count() as u16,
            adler: Some(hash),
            ..Entry::default()
        }];
        let got = scan_m2_chunks_against_entries(&data, &entries).unwrap();
        assert_eq!(got, vec![name]);
    }

    #[test]
    fn structured_whole_xor_recovers_period_1024_from_m2_metadata() {
        let mut entries = Vec::new();
        let mut plain = vec![0x5au8; 137];
        let mut expected_names = Vec::new();

        for i in 0..320u32 {
            // Vary record lengths so size/hash/name-length constraints walk
            // across every residue of a 1024-byte repeating key.
            let suffix = "x".repeat((i as usize) % 13);
            let name = format!("scenario/route_{:02}/scene_{:05}_{}.ks", i % 17, i, suffix);
            let hash = 0x1020_3040u32.wrapping_add(i.wrapping_mul(0x0101_0101));
            plain.extend_from_slice(&m2_record(b"Yuzu", hash, &name));
            entries.push(Entry {
                info_name_length: name.encode_utf16().count() as u16,
                adler: Some(hash),
                ..Entry::default()
            });
            expected_names.push(name);
        }

        let key: Vec<u8> = (0..1024usize)
            .map(|i| ((i.wrapping_mul(73).wrapping_add(19)) & 0xff) as u8)
            .collect();
        let mut encrypted = plain.clone();
        xor_repeating_in_place(&mut encrypted, &key, 0);

        let hit = recover_structured_m2_xor_blob(&encrypted, &entries, 1024, 0, None)
            .expect("structured period-1024 special-index recovery");

        assert_eq!(hit.period, 1024);
        assert_eq!(hit.start, 137);
        assert_eq!(hit.key, key);
        assert_eq!(hit.decoded, plain);
        assert_eq!(hit.names, expected_names);
        assert_eq!(hit.exact_known, 1024);
        assert_eq!(hit.zero_guessed, 0);
    }

    #[test]
    fn ordered_name_transfer_preserves_decoded_and_xor_key() {
        let recovery = SpecialIndexRecovery {
            root_index: 3,
            decoder: "test".to_string(),
            layout: "ordered-test".to_string(),
            names: vec!["a.ks".to_string()],
            confidence: 100,
            decoded: vec![1, 2, 3, 4],
            xor: Some(SpecialXorRecovery {
                key: vec![0x12, 0x34],
                scope: SpecialXorScope::Whole,
                table_start: 7,
            }),
        };
        let ordered = recovery.into_ordered_names();
        assert_eq!(ordered.decoded_size, 4);
        assert_eq!(ordered.decoded.as_deref(), Some(&[1, 2, 3, 4][..]));
        let xor = ordered.xor.expect("xor metadata");
        assert_eq!(xor.period(), 2);
        assert_eq!(xor.key_hex(), "1234");
        assert_eq!(xor.table_start, 7);
    }

    #[test]
    fn hxv4_special_index_keeps_archive_only_structured_probe() {
        assert!(special_root_allows_archive_only_probe(
            RootKind::Hxv4SpecialIndex
        ));
    }

    #[test]
    fn ordinary_special_index_keeps_archive_only_structured_probe() {
        for kind in [
            RootKind::SpecialIndexV1,
            RootKind::SpecialIndexV2,
            RootKind::SpecialIndexV3,
            RootKind::SpecialIndexGeneric,
        ] {
            assert!(special_root_allows_archive_only_probe(kind));
        }
    }

    #[test]
    fn non_special_roots_do_not_enter_special_recovery() {
        for kind in [
            RootKind::File,
            RootKind::ProtectedFile,
            RootKind::AlternateName,
            RootKind::Unknown,
        ] {
            assert!(!is_special_root(kind));
        }
    }

    #[test]
    fn learned_dynamic_m2_tag_rejects_same_tag_metadata_mismatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&m2_record(b"ZZZZ", 0x11111111, "a/one.ks"));
        data.extend_from_slice(&m2_record(b"ZZZZ", 0x99999999, "b/wrong.ks"));
        data.extend_from_slice(&m2_record(b"ZZZZ", 0x22222222, "b/two.ks"));
        let entries = vec![
            Entry {
                info_name_length: "a/one.ks".encode_utf16().count() as u16,
                adler: Some(0x11111111),
                ..Entry::default()
            },
            Entry {
                info_name_length: "b/two.ks".encode_utf16().count() as u16,
                adler: Some(0x22222222),
                ..Entry::default()
            },
        ];
        assert!(walk_verified_chunk_stream(&data, &entries).is_none());
    }
}
