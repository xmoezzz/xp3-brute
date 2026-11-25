use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use std::hash::Hasher;
use std::io::Read;

use serde::Deserialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use siphasher::sip::SipHasher24;
use xp3_brute::{
    cxdec_filename_md5_token, Archive, CxdecEngine, CxdecGeneratorKind, CxdecNameProfile,
    CxdecProfile, OrderedNameRecovery, RootKind, YuzKey,
};

#[derive(Clone)]
pub(super) struct NanaProfile {
    key: YuzKey,
    content: Option<CxdecProfile>,
}

#[derive(Clone, Default)]
pub(super) struct NanaOptions {
    pub(super) profile: Option<PathBuf>,
    pub(super) key: Option<PathBuf>,
    pub(super) generator: Option<PathBuf>,
}

impl NanaOptions {
    pub(super) fn load(&self) -> Result<Option<NanaProfile>, Box<dyn std::error::Error>> {
        match (&self.profile, &self.key, &self.generator) {
            (Some(profile), None, None) => NanaProfile::load(profile).map(Some),
            (None, Some(key), generator) => {
                NanaProfile::from_key_file(key, generator.as_deref()).map(Some)
            }
            (None, None, None) => Ok(None),
            (None, None, Some(_)) => {
                Err(super::cli_error("--nana-generator requires --nana-key").into())
            }
            (Some(_), _, _) => Err(super::cli_error(
                "--nana-profile conflicts with --nana-key and --nana-generator",
            )
            .into()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    name_state: [u32; 6],
    content: ContentFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentFile {
    mask: u32,
    offset: u32,
    prolog_order: [u8; 3],
    even_branch_order: [u8; 8],
    odd_branch_order: [u8; 6],
    random_seed: u32,
    control_block_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratorFile {
    prolog_order: [u8; 3],
    even_branch_order: [u8; 8],
    odd_branch_order: [u8; 6],
    random_seed: u32,
}

struct KeyMaterial {
    key: YuzKey,
    control_block: Vec<u8>,
    mask: u32,
    offset: u32,
}

fn read_small_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const MAX_BYTES: usize = 16 * 1024;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(super::cli_error("Nana input exceeds 16 KiB").into());
    }
    Ok(bytes)
}

fn decode_key_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"\xff\xfe") || bytes.starts_with(b"\xfe\xff") {
        let body = &bytes[2..];
        if body.len() % 2 != 0 {
            return None;
        }
        let convert = if bytes[0] == 0xff {
            u16::from_le_bytes
        } else {
            u16::from_be_bytes
        };
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| convert([pair[0], pair[1]]))
            .collect();
        return String::from_utf16(&units).ok();
    }
    if let Some(body) = bytes.strip_prefix(b"\xef\xbb\xbf") {
        return std::str::from_utf8(body).ok().map(str::to_owned);
    }
    std::str::from_utf8(bytes)
        .ok()
        .map(str::to_owned)
        .or_else(|| {
            encoding_rs::SHIFT_JIS
                .decode_without_bom_handling_and_without_replacement(bytes)
                .map(|value| value.into_owned())
        })
}

fn derive_key_material(line: &str) -> Result<KeyMaterial, Box<dyn std::error::Error>> {
    if line.is_empty() || line.encode_utf16().count() > 4096 || line.contains('\0') {
        return Err(super::cli_error("invalid Nana key first line").into());
    }
    let text: Vec<u8> = line.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut shake = Shake256::default();
    shake.update(&text);
    let mut control_block = vec![0; 4096];
    XofReader::read(&mut shake.finalize_xof(), &mut control_block);

    let sip_key = control_block[..16].try_into().unwrap();
    let mut sip = SipHasher24::new_with_key(&sip_key);
    sip.write(&text);
    let digest = sip.finish();
    let digest_words = [digest as u32, (digest >> 32) as u32];
    let low = digest_words[0];
    let key = YuzKey(std::array::from_fn(|index| {
        let start = index * 4;
        let control_word = u32::from_le_bytes(control_block[start..start + 4].try_into().unwrap());
        control_word ^ digest_words[index % 2]
    }));
    Ok(KeyMaterial {
        key,
        control_block,
        mask: 0x100 + (low & 0x1ff),
        offset: 0x20 + ((low >> 9) & 0x7f) + ((low >> 16) & 0xff),
    })
}

impl NanaProfile {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = fs::read(path)?;
        let file: ProfileFile = serde_json::from_slice(&bytes).map_err(|error| {
            super::cli_error(format!(
                "invalid Nana profile JSON at line {}, column {}",
                error.line(),
                error.column()
            ))
        })?;
        let table = path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(file.content.control_block_file);
        let content = CxdecProfile {
            mask: file.content.mask,
            offset: file.content.offset,
            prolog_order: file.content.prolog_order,
            even_branch_order: file.content.even_branch_order,
            odd_branch_order: file.content.odd_branch_order,
            control_block: fs::read(table)?,
            generator: CxdecGeneratorKind::Cabbage {
                random_seed: file.content.random_seed,
            },
            wrappers: Vec::new(),
        };
        content.validate()?;
        Ok(Self {
            key: YuzKey(file.name_state),
            content: Some(content),
        })
    }

    fn from_key_file(
        key_path: &Path,
        generator_path: Option<&Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key_bytes = read_small_file(key_path)?;
        let text = decode_key_text(&key_bytes)
            .ok_or_else(|| super::cli_error("invalid Nana key text encoding"))?;
        let first_line = text.split(['\r', '\n']).next().unwrap_or_default();
        let material = derive_key_material(first_line)?;
        let content = if let Some(path) = generator_path {
            let generator: GeneratorFile = serde_json::from_slice(&read_small_file(path)?)
                .map_err(|error| {
                    super::cli_error(format!(
                        "invalid Nana generator JSON at line {}, column {}",
                        error.line(),
                        error.column()
                    ))
                })?;
            let content = CxdecProfile {
                mask: material.mask,
                offset: material.offset,
                prolog_order: generator.prolog_order,
                even_branch_order: generator.even_branch_order,
                odd_branch_order: generator.odd_branch_order,
                control_block: material.control_block,
                generator: CxdecGeneratorKind::Cabbage {
                    random_seed: generator.random_seed,
                },
                wrappers: Vec::new(),
            };
            content.validate()?;
            Some(content)
        } else {
            None
        };
        Ok(Self {
            key: material.key,
            content,
        })
    }

    pub(super) fn content_engine(&self) -> Result<CxdecEngine, Box<dyn std::error::Error>> {
        let content = self.content.as_ref().ok_or_else(|| {
            super::cli_error("unpack with --nana-key requires --nana-generator FILE")
        })?;
        Ok(CxdecEngine::new(content.clone())?)
    }

    pub(super) fn recover_names(
        &self,
        archive: &Archive,
    ) -> Result<OrderedNameRecovery, Box<dyn std::error::Error>> {
        let roots = archive.indirect_special_roots();
        let [root_index] = roots.as_slice() else {
            return Err(super::cli_error("Nana profile requires one indirect dls: index").into());
        };
        let root = &archive.root_chunks[*root_index];
        if archive.is_hxv4()
            || root.kind != RootKind::SpecialIndexV2
            || root.magic.to_le_bytes() != *b"dls:"
        {
            return Err(
                super::cli_error("Nana profile requires an ordinary XP3 dls: descriptor").into(),
            );
        }

        let stored = archive
            .special_index_bytes_for_root(*root_index)
            .ok_or_else(|| super::cli_error("dls: payload is out of range"))?;
        let size = root
            .inferred_original_size
            .ok_or_else(|| super::cli_error("dls: descriptor lacks the decoded size"))?;
        let decoder = CxdecNameProfile::Nana { key: self.key };
        let decoded = decoder.decode_payload_bytes_exact(stored, size)?;
        let records = decoder.parse_decoded_names(&decoded)?.records;
        if records.is_empty() {
            return Err(super::cli_error("dls: empty filename table").into());
        }

        let mut remaining = decoded.as_slice();
        let mut names_by_token = HashMap::with_capacity(records.len());
        for record in records {
            let name = record
                .name
                .ok_or_else(|| super::cli_error("dls: missing name"))?;
            let body_size = 8 + name.encode_utf16().count() * 2;
            if record.entry_size != body_size as u64
                || remaining.get(12 + body_size - 2..12 + body_size) != Some(b"\0\0")
                || !valid_name(&name)
            {
                return Err(super::cli_error("dls: invalid filename record").into());
            }
            remaining = &remaining[12 + body_size..];
            let token = cxdec_filename_md5_token("dls:", &name);
            if names_by_token.insert(token, (record.hash, name)).is_some() {
                return Err(super::cli_error("dls: duplicate filename token").into());
            }
        }

        let mut names = Vec::with_capacity(archive.entries.len());
        let mut output_paths = HashSet::with_capacity(archive.entries.len());
        for (index, entry) in archive.entries.iter().enumerate() {
            let name = if let Some((adler, name)) =
                names_by_token.remove(&entry.name.to_ascii_lowercase())
            {
                if entry.adler != Some(adler) {
                    return Err(super::cli_error(format!(
                        "dls: Adler-32 mismatch for File {index}"
                    ))
                    .into());
                }
                name
            } else {
                // An unmatched hash-shaped name is still a missing record.
                // Literal names can also carry the protected info flag, so
                // check their reconstructed bytes against the archive Adler-32.
                if entry.name.len() == 32 && entry.name.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(super::cli_error(format!(
                        "dls: no filename token for File {index}"
                    ))
                    .into());
                }
                if !valid_name(&entry.name) {
                    return Err(super::cli_error(format!(
                        "dls: invalid direct filename for File {index}"
                    ))
                    .into());
                }
                let bytes = archive.reconstruct_entry_segments(index)?;
                if archive.adler_matches(index, &bytes)? != Some(true) {
                    return Err(super::cli_error(format!(
                        "dls: direct File {index} did not pass the plaintext Adler-32 check"
                    ))
                    .into());
                }
                entry.name.clone()
            };
            if !output_paths.insert(name.replace('\\', "/").to_lowercase()) {
                return Err(super::cli_error(format!(
                    "dls: duplicate output path for File {index}"
                ))
                .into());
            }
            names.push(name);
        }
        if !names_by_token.is_empty() {
            return Err(super::cli_error("dls: filename record has no File entry").into());
        }
        for path in &output_paths {
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if output_paths.contains(prefix) {
                    return Err(super::cli_error("dls: conflicting output path").into());
                }
                parent = prefix;
            }
        }
        Ok(OrderedNameRecovery {
            root_index: *root_index,
            decoder: "nana-profile".to_string(),
            layout: "nana-dls-token-adler".to_string(),
            names,
            confidence: 100,
            decoded_size: decoded.len(),
            decoded: Some(decoded),
            xor: None,
        })
    }
}

fn valid_name(name: &str) -> bool {
    !name.chars().any(char::is_control)
        && name.split(['/', '\\']).all(|part| {
            !part.is_empty()
                && !part.ends_with([' ', '.'])
                && !part.contains([':', '<', '>', '"', '|', '*', '?'])
        })
}
