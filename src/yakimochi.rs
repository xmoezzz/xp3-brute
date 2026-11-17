mod kbad;

use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tjs2dec::{load_tjs2_bytecode, Tjs2File, Variant};
use xp3_brute::{adler32, Archive};

use crate::madocrypt::MadoCrypt;
use kbad::Value;

const KBAD_MAGIC: &[u8] = b"KBAD100\0";
const METADATA_LIMIT: u64 = 16 * 1024 * 1024;

struct Naming {
    alphabet: [char; 256],
    salt: String,
}

impl Naming {
    fn token(&self, logical: &str) -> String {
        let mut hash = Sha256::new();
        for unit in logical.encode_utf16() {
            hash.update(unit.to_le_bytes());
        }
        let mut token: String = hash
            .finalize()
            .iter()
            .map(|byte| self.alphabet[*byte as usize])
            .collect();
        token.push_str(".tlg");
        token
    }
}

pub(crate) fn recover_names(
    archive: &Archive,
    filter: MadoCrypt,
) -> Result<HashMap<usize, String>> {
    let path = archive
        .path
        .as_deref()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("fgimage.xp3"))
        })
        .ok_or_else(|| invalid("--restore-names requires a MadoCrypt fgimage.xp3"))?;

    let data_path = data_archive(path)
        .ok_or_else(|| invalid("could not find the game's data.xp3 next to fgimage.xp3"))?;
    let data = Archive::open(data_path).map_err(Error::other)?;
    let utils = load_script(&data, filter, "utils.tjs")?;
    let layers = load_script(&data, filter, "psdlayer.tjs")?;
    let character = load_script(&data, filter, "kagenvcharacterex.tjs")?;
    let naming = naming_rules(&utils, &layers)?;

    let indexed: HashMap<_, _> = archive
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.name.as_str(), index))
        .collect();

    // The character loader names the bootstrap KBAD files by physical token.
    let mut config_indices = HashSet::new();
    let mut configs = Vec::new();
    for literal in &character.const_pools.strings {
        if !literal.ends_with(".tlg") || literal.encode_utf16().count() != 36 {
            continue;
        }
        if let Some(&index) = indexed.get(literal.as_str()) {
            if config_indices.insert(index) {
                let bytes = read_asset(archive, index, filter)?;
                if bytes.starts_with(KBAD_MAGIC) {
                    configs.push(kbad::parse(&bytes)?);
                }
            }
        }
    }

    let characters = only(configs.iter().filter_map(|value| value.get("map")))
        .and_then(Value::map)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| invalid("could not identify charinit data from the character loader"))?;

    let mut poses = Vec::new();
    for (name, definition) in characters {
        let name = name
            .text()
            .ok_or_else(|| invalid("invalid character name"))?;
        let definitions = definition
            .get("map")
            .and_then(Value::map)
            .ok_or_else(|| invalid("invalid character pose map"))?;
        for (pose, detail) in definitions {
            let pose = pose.text().ok_or_else(|| invalid("invalid pose key"))?;
            let base = detail
                .get("filename")
                .and_then(Value::text)
                .filter(|base| {
                    !base.is_empty()
                        && base
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
                .ok_or_else(|| invalid("invalid pose filename"))?;
            poses.push((name, pose, base));
        }
    }
    if poses.is_empty() {
        return Err(invalid("no poses found in the character definitions"));
    }
    let levels = only(configs.iter().filter(|value| {
        poses.iter().all(|&(character, pose, _)| {
            value
                .get(character)
                .and_then(|value| value.get(pose))
                .and_then(Value::array)
                .is_some_and(|levels| !levels.is_empty())
        })
    }))
    .ok_or_else(|| invalid("could not identify the character level definitions"))?;

    let mut aliases = HashMap::new();
    let mut metadata = config_indices;
    let mut output_names = HashSet::new();
    for (character, pose, base) in poses {
        let count = levels
            .get(character)
            .unwrap()
            .get(pose)
            .unwrap()
            .array()
            .unwrap()
            .len();
        for level in 0..count {
            let fgd_name = format!("{base}_{level}");
            let token = naming.token(&fgd_name);
            let &index = indexed
                .get(token.as_str())
                .ok_or_else(|| invalid(format!("missing pose metadata for {fgd_name}")))?;
            metadata.insert(index);
            let model = kbad::parse(&read_asset(archive, index, filter)?)?;
            let layers = model
                .array()
                .ok_or_else(|| invalid("invalid pose layer array"))?;
            for layer in layers.iter().skip(1) {
                let Some(id) = image_layer_id(layer) else {
                    continue;
                };
                let logical = format!("{fgd_name}_{id}");
                let token = naming.token(&format!("{logical}{}", naming.salt));
                let Some(&entry) = indexed.get(token.as_str()) else {
                    continue;
                };
                let filename = format!("{logical}.tlg");
                if let Some(previous) = aliases.get(&entry) {
                    if previous != &filename {
                        return Err(invalid("ambiguous layer token"));
                    }
                    continue;
                }
                if indexed.contains_key(filename.as_str()) || !output_names.insert(filename.clone())
                {
                    return Err(invalid(
                        "a restored layer name collides with an output path",
                    ));
                }
                aliases.insert(entry, filename);
            }
        }
    }

    if aliases.is_empty() || aliases.keys().any(|entry| metadata.contains(entry)) {
        return Err(invalid(
            "layer name mapping does not match the foreground image index",
        ));
    }
    Ok(aliases)
}

fn data_archive(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .take(2)
        .map(|dir| dir.join("data.xp3"))
        .find(|path| path.is_file())
}

fn load_script(archive: &Archive, filter: MadoCrypt, name: &str) -> Result<Tjs2File> {
    let entry = only(
        archive
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.name.eq_ignore_ascii_case(name).then_some(index)),
    )
    .ok_or_else(|| invalid(format!("could not identify {name} in data.xp3")))?;
    load_tjs2_bytecode(&read_asset(archive, entry, filter)?)
        .map_err(|_| invalid(format!("could not parse {name} as TJS2")))
}

fn naming_rules(utils: &Tjs2File, layers: &Tjs2File) -> Result<Naming> {
    let alphabet = only(utils.const_pools.strings.iter().filter_map(|text| {
        let chars: [char; 256] = text.chars().collect::<Vec<_>>().try_into().ok()?;
        (chars.iter().copied().collect::<HashSet<_>>().len() == chars.len()
            && chars.iter().all(|c| c.len_utf16() == 1 && !c.is_control()))
        .then_some(chars)
    }))
    .ok_or_else(|| invalid("could not identify the filename alphabet in utils.tjs"))?;
    let function = only(
        layers
            .objects
            .iter()
            .filter(|object| object.name.as_deref() == Some("getLayerImageName")),
    )
    .ok_or_else(|| invalid("could not identify getLayerImageName in psdlayer.tjs"))?;
    let literals: HashSet<_> = function
        .data
        .iter()
        .filter_map(|variant| match variant {
            Variant::String(index) => layers.const_pools.strings.get(*index as usize),
            _ => None,
        })
        .map(String::as_str)
        .collect();
    if !literals.contains("getSHA256Name") || !literals.contains("_") {
        return Err(invalid("unexpected layer filename function"));
    }
    let salt = only(
        literals
            .into_iter()
            .filter(|value| !matches!(*value, "" | "_" | "System" | "getSHA256Name")),
    )
    .ok_or_else(|| invalid("could not identify the layer filename salt"))?;
    Ok(Naming {
        alphabet,
        salt: salt.to_string(),
    })
}

fn read_asset(archive: &Archive, index: usize, filter: MadoCrypt) -> Result<Vec<u8>> {
    let entry = &archive.entries[index];
    if entry.original_size > METADATA_LIMIT {
        return Err(invalid(
            "TJS or KBAD filename metadata exceeds the size limit",
        ));
    }
    let checksum = entry
        .adler
        .ok_or_else(|| invalid("filename metadata lacks Adler-32"))?;
    let mut bytes = archive.reconstruct_entry(index).map_err(Error::other)?;
    if adler32(&bytes) == checksum {
        return Ok(bytes);
    }
    filter.apply(checksum, 0, &mut bytes);
    if adler32(&bytes) != checksum {
        return Err(invalid("filename metadata failed Adler-32 validation"));
    }
    Ok(bytes)
}

fn image_layer_id(layer: &Value) -> Option<u32> {
    if layer.get("layer_type")?.integer()? != 0 {
        return None;
    }
    u32::try_from(layer.get("layer_id")?.integer()?).ok()
}

fn only<T>(items: impl IntoIterator<Item = T>) -> Option<T> {
    let mut items = items.into_iter();
    let first = items.next()?;
    items.next().is_none().then_some(first)
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}
