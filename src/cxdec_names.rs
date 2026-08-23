//! Native CXDEC filename metadata decoders.
//!
//! The filename/Special transform is deliberately independent from the
//! content-filter generation. Historical four-byte section tags are mutable
//! vendor labels and are never used as authoritative family identifiers.

use crate::{
    cxdec_classic::{CxdecContentWrapper, CxdecEngine, CxdecGeneratorKind, CxdecProfile},
    special_cipher::{
        ComplementedChaCha8Cipher, ComplementedChaCha8Profile, SpecialFixedParams, CHACHA_SIGMA,
        COMPLEMENTED_CHACHA_SIGMA,
    },
    Error, Result,
};
use flate2::read::ZlibDecoder;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const MAX_DECOMPRESSED_NAMES: u64 = 64 * 1024 * 1024;
const ENCRYPTED_NAMES_PREFIX: usize = 0x100;

/// Legacy six-word serialized state adapter used by historical Nana/Riddle
/// APIs. Words 0..3 are cipher constants, not recovered game parameters; only
/// the final two words carry external seed values. New recovery code should
/// return [`SpecialFixedParams`] instead of this representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YuzKey(pub [u32; 6]);

/// Legacy adapter for the eight external control words passed as `key1` to
/// GARbro's Riddle `YuzDecryptor`. These are fixed parameters, unlike the
/// sigma/round constants that belong to the cipher implementation itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YuzControlKey(pub [u32; 8]);

/// Historical serialized-state prefix derived from ChaCha sigma. These are
/// algorithm constants, not game fixed parameters and not key material.
const RIDDLE_YUZ_SIGMA: [u32; 4] = CHACHA_SIGMA;
const RIDDLE_YUZ_PREFIX: [u32; 4] = COMPLEMENTED_CHACHA_SIGMA;

impl YuzKey {
    pub const fn riddle(seed0: u32, seed1: u32) -> Self {
        Self([
            RIDDLE_YUZ_PREFIX[0],
            RIDDLE_YUZ_PREFIX[1],
            RIDDLE_YUZ_PREFIX[2],
            RIDDLE_YUZ_PREFIX[3],
            seed0,
            seed1,
        ])
    }

    pub const fn riddle_seeds(self) -> (u32, u32) {
        (self.0[4], self.0[5])
    }
}

impl YuzControlKey {
    /// Build from the decoded 1024-word control block representation used by
    /// GARbro's `CxEncryption.ControlBlock` / `YuzDecryptor`.
    pub fn from_control_block(control_block: &[u8]) -> Result<Self> {
        if control_block.len() < 32 {
            return Err(Error::invalid(format!(
                "Riddle Yuz control block has {} bytes; at least 32 are required",
                control_block.len()
            )));
        }
        let mut words = [0u32; 8];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_le_bytes(control_block[start..start + 4].try_into().unwrap());
        }
        Ok(Self(words))
    }

    /// Build from the 4096-byte encoded CXDEC table as it is stored in the
    /// PE/TPM. GARbro recovers `ControlBlock[i] = ~src[i]`; Riddle's name
    /// cipher consumes those decoded words, while the content evaluator sees
    /// the encoded/raw lookup values after the second complement performed by
    /// `MOV_EAX_INDIRECT`.
    pub fn from_encoded_cxdec_control_block(control_block: &[u8]) -> Result<Self> {
        if control_block.len() < 32 {
            return Err(Error::invalid(format!(
                "encoded CXDEC control block has {} bytes; at least 32 are required",
                control_block.len()
            )));
        }
        let mut words = [0u32; 8];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            let encoded =
                u32::from_le_bytes(control_block[start..start + 4].try_into().unwrap());
            *word = !encoded;
        }
        Ok(Self(words))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiddleSpecialSeedCandidate {
    pub seed0: u32,
    pub seed1: u32,
    pub file_offset: usize,
    pub representation: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiddleSpecialFixedParamsCandidate {
    /// Complete external fixed parameters required by the Special cipher.
    /// Algorithm constants such as sigma/round/rotation values are never
    /// included here and are never counted as recovered parameters.
    pub fixed: SpecialFixedParams,
    pub file_offset: usize,
    pub representation: &'static str,
}

/// Recover a *complete materialized Special state* from a normalized PE.
///
/// This fast path only accepts representations that contain all ten external
/// fixed words (`control[8] + seed0 + seed1`).  The cipher's own sigma words
/// are used solely as a structural state-layout check; finding sigma by itself
/// is not a parameter hit and never produces a candidate.  In particular, the
/// old `!sigma || word || word` 24-byte scan is intentionally gone because it
/// misclassified unrelated ChaCha users (for example PackinOne) as title-key
/// material.
pub fn recover_riddle_special_fixed_params_from_pe(
    path: impl AsRef<Path>,
) -> Result<Vec<RiddleSpecialFixedParamsCandidate>> {
    let normalized = crate::pe_normalize::normalize_pe_file(path)?;
    Ok(recover_riddle_special_fixed_params_from_pe_bytes(
        &normalized.bytes,
    ))
}

/// Recover the two Special seeds from a complete materialized 64-byte state.
/// Raw `!sigma || word || word` data is intentionally rejected here because
/// unrelated ChaCha code can have the same layout by accident; seed-only
/// recovery from PE code is handled by the x86 data-flow scanner.
pub fn recover_riddle_special_seed_candidates_from_pe(
    path: impl AsRef<Path>,
) -> Result<Vec<RiddleSpecialSeedCandidate>> {
    let normalized = crate::pe_normalize::normalize_pe_file(path)?;
    Ok(recover_riddle_special_seed_candidates_from_bytes(
        &normalized.bytes,
    ))
}

fn recover_riddle_special_seed_candidates_from_bytes(
    bytes: &[u8],
) -> Vec<RiddleSpecialSeedCandidate> {
    let mut out = BTreeMap::<(u32, u32), RiddleSpecialSeedCandidate>::new();

    // Only a complete materialized state is strong enough to recover seeds by
    // raw-data scanning.  A bare !sigma||word||word sequence is common in
    // unrelated ChaCha code: the following DWORDs can simply be pointers or
    // other constants.  Seed-only recovery therefore belongs to the x86
    // call/data-flow scanner in legacy_cxdec.rs, not to this byte scanner.
    if bytes.len() >= 64 {
        for offset in 0..=bytes.len() - 64 {
            let mut words = [0u32; 16];
            for (i, word) in words.iter_mut().enumerate() {
                let p = offset + i * 4;
                *word = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            }
            let hit = if words[..4] == RIDDLE_YUZ_PREFIX[..]
                && words[12] == u32::MAX
                && words[13] == u32::MAX
            {
                Some((!words[14], !words[15], "stored-special-state"))
            } else if words[..4] == RIDDLE_YUZ_SIGMA[..]
                && words[12] == 0
                && words[13] == 0
            {
                Some((words[14], words[15], "working-special-state"))
            } else {
                None
            };
            if let Some((seed0, seed1, representation)) = hit {
                out.insert(
                    (seed0, seed1),
                    RiddleSpecialSeedCandidate {
                        seed0,
                        seed1,
                        file_offset: offset,
                        representation,
                    },
                );
            }
        }
    }

    out.into_values().collect()
}

/// Byte-backed counterpart used for a structurally extracted embedded PE.
/// The input must be normalized PE image bytes; no module code is executed.
pub fn recover_riddle_special_fixed_params_from_pe_bytes(
    bytes: &[u8],
) -> Vec<RiddleSpecialFixedParamsCandidate> {
    let mut out = BTreeMap::<([u32; 8], u32, u32), RiddleSpecialFixedParamsCandidate>::new();

    if bytes.len() < 64 {
        return Vec::new();
    }

    for offset in 0..=bytes.len() - 64 {
        let mut words = [0u32; 16];
        for (i, word) in words.iter_mut().enumerate() {
            let p = offset + i * 4;
            *word = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        }

        // Stored/base state:
        // !sigma || logical-control[8] || FFFFFFFF FFFFFFFF || !seed0 !seed1.
        if words[..4] == RIDDLE_YUZ_PREFIX[..]
            && words[12] == u32::MAX
            && words[13] == u32::MAX
        {
            let mut control = [0u32; 8];
            control.copy_from_slice(&words[4..12]);
            let seed0 = !words[14];
            let seed1 = !words[15];
            let fixed = SpecialFixedParams::new(control, seed0, seed1);
            out.entry((control, seed0, seed1)).or_insert(
                RiddleSpecialFixedParamsCandidate {
                    fixed,
                    file_offset: offset,
                    representation: "stored-special-state",
                },
            );
        }

        // Complemented working state:
        // sigma || !logical-control[8] || 0 0 || seed0 seed1.
        if words[..4] == RIDDLE_YUZ_SIGMA[..] && words[12] == 0 && words[13] == 0 {
            let mut control = [0u32; 8];
            for (dst, encoded) in control.iter_mut().zip(&words[4..12]) {
                *dst = !*encoded;
            }
            let seed0 = words[14];
            let seed1 = words[15];
            let fixed = SpecialFixedParams::new(control, seed0, seed1);
            out.entry((control, seed0, seed1)).or_insert(
                RiddleSpecialFixedParamsCandidate {
                    fixed,
                    file_offset: offset,
                    representation: "working-special-state",
                },
            );
        }
    }

    out.into_values().collect()
}

/// Complete external fixed parameters for the Riddle-style Rust algorithms.
/// PE/DLL/TPM analysis is only a way of producing these values; algorithm
/// constants remain inside the Rust implementations and are not represented
/// here. Neither the content engine nor the filename decoder executes game code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiddleFixedParams {
    /// External fixed parameters for ordinary-entry content decryption.
    pub content: CxdecProfile,
    /// External fixed parameters for the Special/name stream cipher.
    /// Algorithm-internal constants are intentionally absent.
    pub special: SpecialFixedParams,
}

/// Backward-compatible public name. New code should use [`RiddleFixedParams`].
pub type RiddleCxdecProfile = RiddleFixedParams;

/// Published Riddle Joker reference scheme parameters.  These constants are
/// provided only for explicit compatibility/reference construction; automatic
/// family detection must not select a title from these values or from an XP3
/// four-byte tag.  The 4096-byte logical control block remains external.
pub const RIDDLE_JOKER_MASK: u32 = 0x118;
pub const RIDDLE_JOKER_OFFSET: u32 = 0x10f;
pub const RIDDLE_JOKER_PROLOG_ORDER: [u8; 3] = [0, 1, 2];
pub const RIDDLE_JOKER_ODD_BRANCH_ORDER: [u8; 6] = [2, 5, 3, 4, 1, 0];
pub const RIDDLE_JOKER_EVEN_BRANCH_ORDER: [u8; 8] = [0, 2, 3, 1, 5, 6, 7, 4];
pub const RIDDLE_JOKER_RANDOM_SEED: u32 = 0x92d6_8ca2;
pub const RIDDLE_JOKER_SPECIAL_SEED0: u32 = 0xbdd7_2518;
pub const RIDDLE_JOKER_SPECIAL_SEED1: u32 = 0xd541_d24c;

/// Construct the complete published Riddle Joker profile from its external
/// logical 4096-byte control block.  Nothing here performs detection.  This is
/// intentionally an explicit reference/preset constructor so recovered static
/// material can be checked against a known-good algorithm instance.
pub fn riddle_joker_builtin_profile() -> Result<RiddleCxdecProfile> {
    riddle_joker_reference_profile(
        include_bytes!("known_profiles/riddle_joker_control.bin").to_vec(),
    )
}

pub fn riddle_joker_reference_profile(
    logical_control_block: Vec<u8>,
) -> Result<RiddleCxdecProfile> {
    if logical_control_block.len() != crate::cxdec_classic::CLASSIC_CXDEC_CONTROL_BLOCK_SIZE {
        return Err(Error::invalid(format!(
            "Riddle Joker logical control block has {} bytes, expected {}",
            logical_control_block.len(),
            crate::cxdec_classic::CLASSIC_CXDEC_CONTROL_BLOCK_SIZE
        )));
    }

    let special_control = YuzControlKey::from_control_block(&logical_control_block)?;

    // GARbro/msg-tool scheme-side `riddle.bin` stores the logical ControlBlock.
    // CxdecProfile intentionally stores the PE/TPM encoded representation,
    // because the generated content program's MOV_EAX_INDIRECT effectively
    // sees `~logical`.  Convert exactly once at this boundary.
    let mut encoded_control_block = logical_control_block;
    for chunk in encoded_control_block.chunks_exact_mut(4) {
        let logical = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        chunk.copy_from_slice(&(!logical).to_le_bytes());
    }

    let profile = RiddleCxdecProfile {
        content: CxdecProfile {
            mask: RIDDLE_JOKER_MASK,
            offset: RIDDLE_JOKER_OFFSET,
            prolog_order: RIDDLE_JOKER_PROLOG_ORDER,
            even_branch_order: RIDDLE_JOKER_EVEN_BRANCH_ORDER,
            odd_branch_order: RIDDLE_JOKER_ODD_BRANCH_ORDER,
            control_block: encoded_control_block,
            generator: CxdecGeneratorKind::Cabbage {
                random_seed: RIDDLE_JOKER_RANDOM_SEED,
            },
            wrappers: vec![CxdecContentWrapper::RiddlePrefix8],
        },
        special: SpecialFixedParams::new(
            special_control.0,
            RIDDLE_JOKER_SPECIAL_SEED0,
            RIDDLE_JOKER_SPECIAL_SEED1,
        ),
    };
    profile.validate()?;
    Ok(profile)
}

impl RiddleFixedParams {
    pub fn validate(&self) -> Result<()> {
        self.content.validate()?;
        if !matches!(self.content.generator, CxdecGeneratorKind::Cabbage { .. }) {
            return Err(Error::invalid(
                "Riddle CXDEC content profile must use the Cabbage generator",
            ));
        }
        if !self
            .content
            .wrappers
            .contains(&CxdecContentWrapper::RiddlePrefix8)
        {
            return Err(Error::invalid(
                "Riddle CXDEC content profile is missing the RiddlePrefix8 wrapper",
            ));
        }
        Ok(())
    }

    pub fn content_engine(&self) -> Result<CxdecEngine> {
        self.validate()?;
        CxdecEngine::new(self.content.clone())
    }

    /// Return the ten external words that initialize the Special stream cipher.
    /// This is the precise boundary between static profile recovery and the
    /// fixed Rust algorithm.
    pub fn special_profile(&self) -> Result<ComplementedChaCha8Profile> {
        self.validate()?;
        Ok(self.special)
    }

    pub fn name_profile(&self) -> Result<CxdecNameProfile> {
        let special = self.special_profile()?;
        Ok(CxdecNameProfile::Riddle {
            control_key: YuzControlKey(special.control_words),
            key: YuzKey::riddle(special.seed0, special.seed1),
        })
    }

    pub fn decode_special(&self, stored: &[u8]) -> Result<Vec<u8>> {
        self.name_profile()?.decode_payload_bytes(stored)
    }
}

/// Historical filename-metadata family label. Four-byte XP3 root tags may
/// provide a compatibility hint, but never authoritative family detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxdecNameSectionKind {
    Senren,
    Cabbage,
    Nana,
    Riddle,
}

impl CxdecNameSectionKind {
    /// Known historical tag for compatibility output/tests only.
    pub const fn section_id(self) -> [u8; 4] {
        match self {
            Self::Senren => *b"sen:",
            Self::Cabbage => *b"cbg:",
            Self::Nana => *b"dls:",
            Self::Riddle => *b"yuz:",
        }
    }

    /// Return a weak compatibility hint for a historically observed tag. The
    /// caller must not use this result as family classification.
    pub fn from_known_tag_hint(id: [u8; 4]) -> Option<Self> {
        match id {
            value if value == *b"sen:" => Some(Self::Senren),
            value if value == *b"cbg:" => Some(Self::Cabbage),
            value if value == *b"dls:" => Some(Self::Nana),
            value if value == *b"yuz:" => Some(Self::Riddle),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxdecNameProfile {
    Senren,
    Cabbage,
    Nana {
        key: YuzKey,
    },
    Riddle {
        control_key: YuzControlKey,
        key: YuzKey,
    },
}

impl CxdecNameProfile {
    pub const fn section_id(self) -> [u8; 4] {
        match self {
            Self::Senren => *b"sen:",
            Self::Cabbage => *b"cbg:",
            Self::Nana { .. } => *b"dls:",
            Self::Riddle { .. } => *b"yuz:",
        }
    }

    pub const fn kind(self) -> CxdecNameSectionKind {
        match self {
            Self::Senren => CxdecNameSectionKind::Senren,
            Self::Cabbage => CxdecNameSectionKind::Cabbage,
            Self::Nana { .. } => CxdecNameSectionKind::Nana,
            Self::Riddle { .. } => CxdecNameSectionKind::Riddle,
        }
    }

    /// Decrypt (when required) and zlib-decompress a complete CXDEC filename
    /// payload. Family selection is supplied by the recovered profile, never
    /// by the XP3 root tag.
    pub fn decode_payload_bytes(self, stored: &[u8]) -> Result<Vec<u8>> {
        let mut encoded = stored.to_vec();
        let encrypted_len = encoded.len().min(ENCRYPTED_NAMES_PREFIX);
        match self {
            Self::Senren | Self::Cabbage => {}
            Self::Nana { key } => NanaDecryptor::new(key).apply(&mut encoded[..encrypted_len]),
            Self::Riddle { control_key, key } => {
                YuzDecryptor::new(control_key, key).apply(&mut encoded[..encrypted_len])
            }
        }

        decode_cxdec_name_zlib(&encoded)
    }

    /// Decrypt, zlib-decompress, and parse a complete CXDEC filename metadata
    /// section. `section_id` in the returned map is a compatibility label only.
    pub fn decode(self, stored: &[u8]) -> Result<CxdecNameMap> {
        self.decode_with_token_suffix(stored, None)
    }

    /// Decode with an optional UTF-16 token suffix recovered from the Special
    /// descriptor. Early V1 CXDEC builds append this runtime product string to
    /// the normalized filename before MD5. It is data, not a family marker.
    pub fn decode_with_token_suffix(
        self,
        stored: &[u8],
        token_suffix: Option<&str>,
    ) -> Result<CxdecNameMap> {
        let decoded = self.decode_payload_bytes(stored)?;
        self.parse_decoded_names_with_token_suffix(&decoded, token_suffix)
    }

    /// Parse an already decrypted/decompressed CXDEC filename payload.
    ///
    /// This keeps Special validation single-pass: callers that have already
    /// authenticated the native decrypt + zlib result must not feed the same
    /// bytes back through the cipher a second time.
    pub fn parse_decoded_names(self, decoded: &[u8]) -> Result<CxdecNameMap> {
        self.parse_decoded_names_with_token_suffix(decoded, None)
    }

    pub fn parse_decoded_names_with_token_suffix(
        self,
        decoded: &[u8],
        token_suffix: Option<&str>,
    ) -> Result<CxdecNameMap> {
        parse_name_records(self.section_id(), decoded, token_suffix)
    }
}

/// Decode a plain zlib-wrapped name payload after an executable-generation
/// gate has selected this strategy. No archive tag or title string is
/// consulted here.
pub fn decode_plain_cxdec_name_payload(stored: &[u8]) -> Result<Vec<u8>> {
    decode_cxdec_name_zlib(stored)
}

/// Parse the structural record stream used by early plain-zlib Special data.
/// The zero section id deliberately means "not selected by tag"; automatic
/// recovery must validate record boundaries and archive mappings instead.
///
/// This compatibility helper retains the historical all-record view. New
/// automatic recovery should prefer [`parse_structural_cxdec_name_record_groups`],
/// because the native parser selects one repeated record signature while other
/// top-level chunks may coexist in the same decoded stream.
pub fn parse_structural_cxdec_name_records(
    decoded: &[u8],
    token_suffix: Option<&str>,
) -> Result<CxdecNameMap> {
    parse_name_records([0; 4], decoded, token_suffix)
}

/// Parse an early plain-zlib Special stream into candidate record groups.
///
/// The native implementation searches the decoded top-level chunk stream for
/// one runtime-supplied four-byte signature and parses only records carrying
/// that signature.  The literal signature is vendor data, so automatic
/// recovery must never hard-code it.  Instead we parse every bounded top-level
/// chunk, retain chunks whose body has the native `u32 + i16 + UTF-16` record
/// shape, and group them by their observed signature.  The caller then chooses
/// the group by archive-wide mapping evidence.
pub fn parse_structural_cxdec_name_record_groups(
    decoded: &[u8],
    token_suffix: Option<&str>,
) -> Result<Vec<CxdecNameMap>> {
    let mut grouped = BTreeMap::<u32, Vec<CxdecNameRecord>>::new();
    let mut cursor = 0usize;

    while cursor < decoded.len() {
        let header_end = cursor
            .checked_add(12)
            .ok_or_else(|| Error::format("CXDEC structural chunk header overflow"))?;
        if header_end > decoded.len() {
            return Err(Error::format("truncated CXDEC structural chunk header"));
        }

        let signature = read_u32(decoded, cursor);
        let signed_size = read_i64(decoded, cursor + 4);
        if signed_size < 0 {
            return Err(Error::format("negative CXDEC structural chunk size"));
        }
        let entry_size = signed_size as u64;
        let body_size = usize::try_from(entry_size)
            .map_err(|_| Error::format("CXDEC structural chunk size does not fit usize"))?;
        let record_end = header_end
            .checked_add(body_size)
            .ok_or_else(|| Error::format("CXDEC structural chunk range overflow"))?;
        if record_end > decoded.len() {
            return Err(Error::format("truncated CXDEC structural chunk body"));
        }

        if body_size >= 6 {
            let hash = read_u32(decoded, header_end);
            let name_units = read_i16(decoded, header_end + 4);
            if name_units > 0 {
                let unit_count = name_units as usize;
                let byte_count = unit_count
                    .checked_mul(2)
                    .ok_or_else(|| Error::format("CXDEC UTF-16 filename length overflow"))?;
                if byte_count <= body_size - 6 {
                    let bytes = &decoded[header_end + 6..header_end + 6 + byte_count];
                    let units = bytes
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect::<Vec<_>>();
                    if let Ok(value) = String::from_utf16(&units) {
                        if !value.is_empty()
                            && !value.chars().any(|ch| ch == '\0' || ch.is_control())
                        {
                            grouped.entry(signature).or_default().push(CxdecNameRecord {
                                signature,
                                entry_size,
                                hash,
                                name: Some(value),
                            });
                        }
                    }
                }
            }
        }

        cursor = record_end;
    }

    let mut out = Vec::with_capacity(grouped.len());
    for (signature, records) in grouped {
        let mut by_hash = BTreeMap::new();
        let mut by_md5 = BTreeMap::new();
        for record in &records {
            if let Some(name) = record.name.as_deref() {
                by_hash.entry(record.hash).or_insert_with(|| name.to_string());
                by_md5
                    .entry(filename_md5_token(name, token_suffix))
                    .or_insert_with(|| name.to_string());
            }
        }
        out.push(CxdecNameMap {
            section_id: signature.to_le_bytes(),
            records,
            by_hash,
            by_md5,
            shortcuts: BTreeMap::from([("$".to_string(), "startup.tjs".to_string())]),
        });
    }
    Ok(out)
}

fn decode_cxdec_name_zlib(encoded: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(encoded);
    let mut decoded = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_NAMES + 1)
        .read_to_end(&mut decoded)?;
    if decoded.len() as u64 > MAX_DECOMPRESSED_NAMES {
        return Err(Error::format(
            "CXDEC filename section exceeds the 64 MiB safety limit",
        ));
    }
    Ok(decoded)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxdecNameRecord {
    pub signature: u32,
    /// Size stored after the entry header, before the fixed hash/name prefix is
    /// consumed.
    pub entry_size: u64,
    pub hash: u32,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxdecNameMap {
    pub section_id: [u8; 4],
    pub records: Vec<CxdecNameRecord>,
    /// Lookup keyed by the first u32 stored in each decoded record. Its exact
    /// semantics are generation-dependent; automatic family detection must not
    /// assume that it is identical to the ordinary XP3 `adlr` value.
    pub by_hash: BTreeMap<u32, String>,
    /// Lowercase UTF-16LE MD5 tokens used as ordinary XP3 `info` names by
    /// Senren-family archives.
    pub by_md5: BTreeMap<String, String>,
    pub shortcuts: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxdecNameApplyReport {
    pub section_root_index: usize,
    pub kind: CxdecNameSectionKind,
    pub mapped_entries: usize,
    pub unresolved_entries: usize,
}

impl CxdecNameMap {
    pub fn name_for_hash(&self, hash: u32) -> Option<&str> {
        self.by_hash.get(&hash).map(String::as_str)
    }

    /// Compatibility resolver: shortcut/MD5 token first, then a caller-supplied
    /// u32 lookup value, otherwise retain the archive's visible name. The caller
    /// is responsible for proving what that u32 means for the selected family.
    pub fn resolve<'a>(&'a self, hash: Option<u32>, visible_name: &'a str) -> &'a str {
        self.shortcuts
            .get(visible_name)
            .or_else(|| self.by_md5.get(visible_name))
            .or_else(|| hash.and_then(|value| self.by_hash.get(&value)))
            .map(String::as_str)
            .unwrap_or(visible_name)
    }
}

fn parse_name_records(
    section_id: [u8; 4],
    decoded: &[u8],
    token_suffix: Option<&str>,
) -> Result<CxdecNameMap> {
    let mut records = Vec::new();
    let mut by_hash = BTreeMap::new();
    let mut by_md5 = BTreeMap::new();
    let mut cursor = 0usize;
    while cursor < decoded.len() {
        let header_end = cursor
            .checked_add(12)
            .ok_or_else(|| Error::format("CXDEC name-record header overflow"))?;
        if header_end > decoded.len() {
            return Err(Error::format("truncated CXDEC name-record header"));
        }
        let signature = read_u32(decoded, cursor);
        let signed_size = read_i64(decoded, cursor + 4);
        if signed_size < 0 {
            return Err(Error::format("negative CXDEC name-record size"));
        }
        let entry_size = signed_size as u64;
        let body_size = usize::try_from(entry_size)
            .map_err(|_| Error::format("CXDEC name-record size does not fit usize"))?;
        let record_end = header_end
            .checked_add(body_size)
            .ok_or_else(|| Error::format("CXDEC name-record range overflow"))?;
        if record_end > decoded.len() {
            return Err(Error::format("truncated CXDEC name-record body"));
        }
        if body_size < 6 {
            return Err(Error::format(
                "CXDEC name-record body is shorter than hash/name header",
            ));
        }

        let hash = read_u32(decoded, header_end);
        let name_units = read_i16(decoded, header_end + 4);
        let name = if name_units > 0 {
            let unit_count = name_units as usize;
            let byte_count = unit_count
                .checked_mul(2)
                .ok_or_else(|| Error::format("CXDEC UTF-16 filename length overflow"))?;
            if byte_count > body_size - 6 {
                return Err(Error::format(
                    "CXDEC UTF-16 filename exceeds its record body",
                ));
            }
            let bytes = &decoded[header_end + 6..header_end + 6 + byte_count];
            let units = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            let value = String::from_utf16_lossy(&units);
            by_hash.entry(hash).or_insert_with(|| value.clone());
            by_md5.insert(filename_md5_token(&value, token_suffix), value.clone());
            Some(value)
        } else {
            None
        };
        records.push(CxdecNameRecord {
            signature,
            entry_size,
            hash,
            name,
        });
        cursor = record_end;
    }

    let mut shortcuts = BTreeMap::new();
    shortcuts.insert("$".to_string(), "startup.tjs".to_string());
    Ok(CxdecNameMap {
        section_id,
        records,
        by_hash,
        by_md5,
        shortcuts,
    })
}

fn filename_md5_token(name: &str, token_suffix: Option<&str>) -> String {
    let normalized = normalize_cxdec_filename(name);
    let bytes = normalized
        .encode_utf16()
        .chain(token_suffix.unwrap_or("").encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    md5_digest(&bytes)
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Normalize a storage path exactly like the native CXDEC helper used before
/// filename-token MD5 calculation:
///
/// - ASCII `A`..`Z` become lowercase;
/// - `\\` becomes `/`;
/// - leading `/` characters are removed;
/// - repeated `/` characters collapse to one.
///
/// Non-ASCII code units are left unchanged.
pub fn normalize_cxdec_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut saw_non_slash = false;
    let mut previous_slash = false;

    for ch in name.chars() {
        let ch = match ch {
            'A'..='Z' => ((ch as u8) + b'a' - b'A') as char,
            '\\' => '/',
            other => other,
        };

        if ch == '/' {
            if !saw_non_slash || previous_slash {
                continue;
            }
            previous_slash = true;
            out.push('/');
            continue;
        }

        saw_non_slash = true;
        previous_slash = false;
        out.push(ch);
    }

    out
}

/// Calculate the ordinary-XP3 filename token used by native CXDEC name maps.
///
/// `prefix` is runtime data (for Riddle Joker it is the actual four-byte
/// Special tag `yuz:`), not a family-detection constant.
pub fn cxdec_filename_md5_token(prefix: &str, name: &str) -> String {
    let normalized = normalize_cxdec_filename(name);
    let bytes = prefix
        .encode_utf16()
        .chain(normalized.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    md5_digest(&bytes)
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// RFC 1321 MD5 is kept local to avoid adding a dependency solely for the
// Senren filename token lookup.  It is not used for any security decision.
fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut state = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for chunk in padded.chunks_exact(64) {
        let words: [u32; 16] = std::array::from_fn(|index| {
            u32::from_le_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap())
        });
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let next = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(words[g])
                .rotate_left(S[i])
                .wrapping_add(b);
            (a, b, c, d) = (d, next, b, c);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut digest = [0u8; 16];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_i16(bytes: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// GARbro-compatible Nana name-list cipher.  Applying it twice restores the
/// input because the generated stream is XORed with the data.
#[derive(Clone, Debug)]
pub struct NanaDecryptor {
    state: [u32; 27],
    seed: u64,
}

impl NanaDecryptor {
    pub fn new(key: YuzKey) -> Self {
        let words = key.0;
        let mut state = [0u32; 27];
        let mut s = [words[1], words[2], words[3]];
        let mut k = words[0];
        state[0] = k;
        for i in 0..26u32 {
            let slot = (i % 3) as usize;
            let m = s[slot].rotate_right(8);
            let n = i ^ k.wrapping_add(m);
            k = n ^ k.rotate_left(3);
            state[i as usize + 1] = k;
            s[slot] = n;
        }
        Self {
            state,
            seed: (u64::from(words[5]) << 32) | u64::from(words[4]),
        }
    }

    pub fn apply(&self, data: &mut [u8]) {
        for (block, chunk) in data.chunks_mut(8).enumerate() {
            let counter = block as u64 + 1;
            let key = self.transform_key(counter ^ self.seed).to_le_bytes();
            for (byte, key_byte) in chunk.iter_mut().zip(key) {
                *byte ^= key_byte;
            }
        }
    }

    fn transform_key(&self, key: u64) -> u64 {
        let mut lo = key as u32;
        let mut hi = (key >> 32) as u32;
        for state in self.state {
            hi = hi.rotate_right(8);
            hi = hi.wrapping_add(lo);
            hi ^= state;
            lo = lo.rotate_left(3) ^ hi;
        }
        (u64::from(hi) << 32) | u64::from(lo)
    }
}

/// Compatibility wrapper for the historical Riddle/Yuz name-list cipher.
///
/// The cryptographic implementation itself is algorithm-oriented and lives in
/// `special_cipher`; this wrapper only adapts the historical key/control data
/// structures used by the CXDEC name-metadata layer.
#[derive(Clone, Copy, Debug)]
pub struct YuzDecryptor {
    cipher: ComplementedChaCha8Cipher,
}

impl YuzDecryptor {
    pub const fn new(control_key: YuzControlKey, key: YuzKey) -> Self {
        Self {
            cipher: ComplementedChaCha8Cipher::new(ComplementedChaCha8Profile::new(
                control_key.0,
                key.0[4],
                key.0[5],
            )),
        }
    }

    pub fn apply(&self, data: &mut [u8]) {
        self.cipher.apply(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
    use std::io::{Read, Write};

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn names_fixture() -> Vec<u8> {
        let mut plain = Vec::new();
        for (signature, hash, name, padding) in [
            (0x656c_6946u32, 0x1122_3344u32, "startup.tjs", 3usize),
            (0x6d67_4973u32, 0xaabb_ccddu32, "画像/立ち絵.png", 0usize),
        ] {
            let units = name.encode_utf16().collect::<Vec<_>>();
            let size = 6 + units.len() * 2 + padding;
            plain.extend_from_slice(&signature.to_le_bytes());
            plain.extend_from_slice(&(size as i64).to_le_bytes());
            plain.extend_from_slice(&hash.to_le_bytes());
            plain.extend_from_slice(&(units.len() as i16).to_le_bytes());
            for unit in units {
                plain.extend_from_slice(&unit.to_le_bytes());
            }
            plain.resize(plain.len() + padding, 0xcc);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&plain).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn structural_name_records_are_grouped_by_observed_signature_without_tag_constants() {
        let compressed = names_fixture();
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();

        let groups = parse_structural_cxdec_name_record_groups(&decoded, None).unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|group| group.records.len() == 1));
        let mut signatures = groups
            .iter()
            .map(|group| u32::from_le_bytes(group.section_id))
            .collect::<Vec<_>>();
        signatures.sort_unstable();
        assert_eq!(signatures, vec![0x656c_6946, 0x6d67_4973]);
    }

    #[test]
    fn senren_and_cabbage_names_are_hash_keyed() {
        for profile in [CxdecNameProfile::Senren, CxdecNameProfile::Cabbage] {
            let names = profile.decode(&names_fixture()).unwrap();
            assert_eq!(names.section_id, profile.section_id());
            assert_eq!(names.name_for_hash(0x1122_3344), Some("startup.tjs"));
            assert_eq!(names.name_for_hash(0xaabb_ccdd), Some("画像/立ち絵.png"));
            let token = filename_md5_token("画像/立ち絵.png", None);
            assert_eq!(names.resolve(None, &token), "画像/立ち絵.png");
            assert_eq!(names.resolve(None, "$"), "startup.tjs");
            assert_eq!(names.resolve(Some(0x1122_3344), "opaque"), "startup.tjs");
            assert_eq!(
                names.shortcuts.get("$").map(String::as_str),
                Some("startup.tjs")
            );
        }
    }

    #[test]
    fn native_filename_normalization_matches_riddle_helper() {
        assert_eq!(
            normalize_cxdec_filename(r"///System\\//Foo/BAR.tjs"),
            "system/foo/bar.tjs"
        );
        assert_eq!(
            normalize_cxdec_filename("画像/立ち絵.PNG"),
            "画像/立ち絵.png"
        );
    }

    #[test]
    fn early_v1_filename_token_appends_runtime_product_after_normalized_name() {
        assert_eq!(
            filename_md5_token(r"///Scenario\STARTUP.TJS", Some("SenrenBanka")),
            "8e0434204884dd6caa6d740969331374"
        );
    }

    #[test]
    fn riddle_filename_token_matches_ida_vector() {
        assert_eq!(
            cxdec_filename_md5_token("yuz:", "AppConfig.tjs"),
            "64e0b5d3b3a4668da15675dd0c7bf16b"
        );
    }

    #[test]
    fn nana_and_riddle_decrypt_only_the_first_0x100_bytes() {
        let key = YuzKey([
            0x0123_4567,
            0x89ab_cdef,
            0x0bad_f00d,
            0xc001_d00d,
            0x1357_9bdf,
            0x2468_ace0,
        ]);
        let control_key = YuzControlKey([
            0x0001_0203,
            0x0405_0607,
            0x0809_0a0b,
            0x0c0d_0e0f,
            0x1020_3040,
            0x5060_7080,
            0x90a0_b0c0,
            0xd0e0_f000,
        ]);
        let mut fixture = names_fixture();
        fixture.resize(400, 0x5a);
        for profile in [
            CxdecNameProfile::Nana { key },
            CxdecNameProfile::Riddle { control_key, key },
        ] {
            let mut encrypted = fixture.clone();
            match profile {
                CxdecNameProfile::Nana { key } => {
                    NanaDecryptor::new(key).apply(&mut encrypted[..0x100])
                }
                CxdecNameProfile::Riddle { control_key, key } => {
                    YuzDecryptor::new(control_key, key).apply(&mut encrypted[..0x100])
                }
                _ => unreachable!(),
            }
            assert_eq!(&encrypted[0x100..], &fixture[0x100..]);
            let decoded = profile.decode(&encrypted).unwrap();
            assert_eq!(decoded.name_for_hash(0xaabb_ccdd), Some("画像/立ち絵.png"));
        }
    }

    #[test]
    fn nana_keystream_matches_independent_reference_vector() {
        let key = YuzKey([
            0x0123_4567,
            0x89ab_cdef,
            0x0bad_f00d,
            0xc001_d00d,
            0x1357_9bdf,
            0x2468_ace0,
        ]);
        let mut actual = vec![0u8; 64];
        NanaDecryptor::new(key).apply(&mut actual);
        assert_eq!(
            actual,
            hex_bytes(concat!(
                "6c58535f8780fdeb8aadc486f71eefb1",
                "65e88c45c6a3e5ad3c3ccdfb47d06c51",
                "2dfe3878d9a63012a9693576f67ea3df",
                "c028f5618e4e0f388c64429e395a627f"
            ))
        );
    }

    #[test]
    fn yuz_keystream_matches_independent_reference_vector() {
        let key = YuzKey([
            0x0123_4567,
            0x89ab_cdef,
            0x0bad_f00d,
            0xc001_d00d,
            0x1357_9bdf,
            0x2468_ace0,
        ]);
        let control_key = YuzControlKey([
            0x0001_0203,
            0x0405_0607,
            0x0809_0a0b,
            0x0c0d_0e0f,
            0x1020_3040,
            0x5060_7080,
            0x90a0_b0c0,
            0xd0e0_f000,
        ]);
        let mut actual = vec![0u8; 128];
        YuzDecryptor::new(control_key, key).apply(&mut actual);
        assert_eq!(
            actual,
            hex_bytes(concat!(
                "bfa578d2ad12496ad0cf017ca64b9dc5",
                "283cfc6e2086a15c381d489fedb1a278",
                "7745c24b327d05460eca1921ceaefcf6",
                "fd7be6cd94aaca63c3a991e9b4196aed",
                "f3e196adb3ea95b57e13d4a7f97bd12",
                "ff8d08ab023f18f11e59064ae90aa2ad",
                "03eb93ea5a966611d9d554304857173f2",
                "098f7c027b56bbcec783e5cd4e3d9f6c"
            ))
        );
    }

    #[test]
    fn materialized_state_recovers_complete_fixed_params() {
        let control = [
            0x1020_3040,
            0x5060_7080,
            0x90a0_b0c0,
            0xd0e0_f000,
            0x1122_3344,
            0x5566_7788,
            0x99aa_bbcc,
            0xddee_ff00,
        ];
        let seed0 = 0xbdd7_2518;
        let seed1 = 0xd541_d24c;
        let mut bytes = vec![0xa5; 31];
        for word in RIDDLE_YUZ_PREFIX {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        for word in control {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&(!seed0).to_le_bytes());
        bytes.extend_from_slice(&(!seed1).to_le_bytes());

        let candidates = recover_riddle_special_fixed_params_from_bytes(&bytes);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].fixed, SpecialFixedParams::new(control, seed0, seed1));
        assert_eq!(candidates[0].representation, "stored-special-state");
        assert_eq!(candidates[0].file_offset, 31);
    }

    #[test]
    fn sigma_plus_two_words_is_not_treated_as_a_seed_pair() {
        let key = YuzKey::riddle(0x1357_9bdf, 0x2468_ace0);
        let mut bytes = Vec::new();
        for word in key.0 {
            bytes.extend_from_slice(&word.to_le_bytes());
        }

        // The same 16-byte sigma constant appears in ordinary ChaCha code.
        // The two following DWORDs are not parameters unless x86 data flow
        // proves that they are passed as the seed arguments.
        assert!(recover_riddle_special_fixed_params_from_bytes(&bytes).is_empty());
        assert!(recover_riddle_special_seed_candidates_from_bytes(&bytes).is_empty());
    }

    #[test]
    fn working_yuz_state_uncomplements_control_words() {
        let control = [
            0x0102_0304,
            0x1112_1314,
            0x2122_2324,
            0x3132_3334,
            0x4142_4344,
            0x5152_5354,
            0x6162_6364,
            0x7172_7374,
        ];
        let seed0 = 0x89ab_cdef;
        let seed1 = 0x7654_3210;
        let mut bytes = Vec::new();
        for word in RIDDLE_YUZ_SIGMA {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        for word in control {
            bytes.extend_from_slice(&(!word).to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&seed0.to_le_bytes());
        bytes.extend_from_slice(&seed1.to_le_bytes());

        let candidates = recover_riddle_special_fixed_params_from_bytes(&bytes);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].fixed, SpecialFixedParams::new(control, seed0, seed1));
        assert_eq!(candidates[0].representation, "working-special-state");
    }

    #[test]
    fn riddle_special_decode_is_profile_driven_not_tag_driven() {
        let control = YuzControlKey([
            0x1020_3040,
            0x5060_7080,
            0x90a0_b0c0,
            0xd0e0_f000,
            0x1122_3344,
            0x5566_7788,
            0x99aa_bbcc,
            0xddee_ff00,
        ]);
        let key = YuzKey::riddle(0x1357_9bdf, 0x2468_ace0);
        let plain = names_fixture();
        let mut stored = plain.clone();
        let prefix = stored.len().min(ENCRYPTED_NAMES_PREFIX);
        YuzDecryptor::new(control, key).apply(&mut stored[..prefix]);

        let decoded = CxdecNameProfile::Riddle {
            control_key: control,
            key,
        }
        .decode_payload_bytes(&stored)
        .unwrap();

        let mut decoder = ZlibDecoder::new(plain.as_slice());
        let mut expected = Vec::new();
        decoder.read_to_end(&mut expected).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn encoded_cxdec_control_block_is_complemented_for_yuz_names() {
        let decoded = [
            0x1122_3344u32,
            0x5566_7788,
            0x99aa_bbcc,
            0xddee_ff00,
            0x0102_0304,
            0x1112_1314,
            0x2122_2324,
            0x3132_3334,
        ];
        let mut encoded = Vec::new();
        for word in decoded {
            encoded.extend_from_slice(&(!word).to_le_bytes());
        }
        assert_eq!(
            YuzControlKey::from_encoded_cxdec_control_block(&encoded).unwrap(),
            YuzControlKey(decoded)
        );
    }

    #[test]
    fn riddle_joker_reference_scheme_exposes_exact_special_inputs() {
        // Scheme-side riddle.bin is already the logical GARbro ControlBlock.
        // The reference constructor converts it once for the content engine,
        // while Special gets the original logical words back.
        let profile = riddle_joker_reference_profile(vec![
            0u8;
            crate::cxdec_classic::CLASSIC_CXDEC_CONTROL_BLOCK_SIZE
        ])
        .unwrap();
        let special = profile.special_profile().unwrap();
        assert_eq!(special.control_words, [0u32; 8]);
        assert_eq!(&profile.content.control_block[..32], &[0xff; 32]);
        assert_eq!(special.seed0, RIDDLE_JOKER_SPECIAL_SEED0);
        assert_eq!(special.seed1, RIDDLE_JOKER_SPECIAL_SEED1);
        assert_eq!(profile.content.mask, RIDDLE_JOKER_MASK);
        assert_eq!(profile.content.offset, RIDDLE_JOKER_OFFSET);
        assert_eq!(
            profile.content.generator,
            CxdecGeneratorKind::Cabbage {
                random_seed: RIDDLE_JOKER_RANDOM_SEED
            }
        );
    }

    #[test]
    fn complete_riddle_profile_requires_owned_native_parameters() {
        let content = CxdecProfile {
            mask: 0x118,
            offset: 0x10f,
            prolog_order: [0, 1, 2],
            even_branch_order: [0, 2, 3, 1, 5, 6, 7, 4],
            odd_branch_order: [2, 5, 3, 4, 1, 0],
            control_block: vec![
                0u8;
                crate::cxdec_classic::CLASSIC_CXDEC_CONTROL_BLOCK_SIZE
            ],
            generator: CxdecGeneratorKind::Cabbage {
                random_seed: 0x92d6_8ca2,
            },
            wrappers: vec![CxdecContentWrapper::RiddlePrefix8],
        };
        let profile = RiddleCxdecProfile {
            content,
            special: SpecialFixedParams::new(
                [u32::MAX; 8],
                0xbdd7_2518,
                0xd541_d24c,
            ),
        };
        profile.validate().unwrap();
        assert_eq!(
            profile.name_profile().unwrap(),
            CxdecNameProfile::Riddle {
                control_key: YuzControlKey([u32::MAX; 8]),
                key: YuzKey::riddle(0xbdd7_2518, 0xd541_d24c),
            }
        );
    }

}
