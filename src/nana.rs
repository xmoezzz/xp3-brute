use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use xp3_brute::{
    cxdec_filename_md5_token, Archive, CxdecEngine, CxdecGeneratorKind, CxdecNameProfile,
    CxdecProfile, OrderedNameRecovery, RootKind, YuzKey,
};

#[derive(Clone)]
pub(super) struct NanaProfile {
    key: YuzKey,
    content: CxdecProfile,
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

impl NanaProfile {
    pub(super) fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
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
            content,
        })
    }

    pub(super) fn content_engine(&self) -> xp3_brute::Result<CxdecEngine> {
        CxdecEngine::new(self.content.clone())
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
        if records.is_empty() || records.len() != archive.entries.len() {
            return Err(super::cli_error("dls: name count does not match the File index").into());
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
                || name.chars().any(char::is_control)
                || name
                    .split(['/', '\\'])
                    .any(|part| part.is_empty() || matches!(part, "." | "..") || part.contains(':'))
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
        for (index, entry) in archive.entries.iter().enumerate() {
            let (adler, name) = names_by_token
                .remove(&entry.name.to_ascii_lowercase())
                .ok_or_else(|| {
                    super::cli_error(format!("dls: no filename token for File {index}"))
                })?;
            if entry.adler != Some(adler) {
                return Err(
                    super::cli_error(format!("dls: Adler-32 mismatch for File {index}")).into(),
                );
            }
            names.push(name);
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
