use super::{hxv4_game_root, load_hx_index, HxCliOptions};
use encoding_rs::{SHIFT_JIS, UTF_16BE, UTF_16LE};
use std::collections::{HashMap, HashSet};

use xp3_brute::decoder::tlg::inspect_tlg;
use xp3_brute::{
    adler32, analyze_script_names, decode_kirikiri_text, decode_pbd, hxv4_filename_hash,
    is_pbd_bytes, Archive, Hxv4Index, Hxv4IndexEntry, Hxv4NativeFilterManager, PbdValue,
};

type Group = [u8; 8];
type Dimensions = (u32, u32);
type EntryHash = (Group, [u8; 32]);

const METADATA_LIMIT: usize = 2 * 1024 * 1024;
const CHARACTER_LIST_LIMIT: u64 = 64 * 1024;
const MAX_TIER: u32 = 4;
const MAX_EXTRA_LAYER_ID: u32 = 10_000;

#[derive(Debug)]
struct Layer {
    id: u32,
    size: Dimensions,
}

enum Asset {
    Tlg(Dimensions),
    Table(Vec<Layer>),
    Text {
        source: String,
        layers: Option<Vec<Layer>>,
    },
}

impl Asset {
    fn layers(&self) -> Option<&[Layer]> {
        match self {
            Self::Table(layers)
            | Self::Text {
                layers: Some(layers),
                ..
            } => Some(layers),
            _ => None,
        }
    }
}

// Positions refer to authenticated Special records, so equal basenames in
// different directories retain their own identity.
#[derive(Default)]
struct Catalog {
    matches: HashMap<EntryHash, Option<usize>>,
    assets: HashMap<usize, Asset>,
    names: HashMap<usize, String>,
}

pub(super) fn recover(
    archive: &Archive,
    index: &mut Hxv4Index,
    filter: &Hxv4NativeFilterManager,
    options: &HxCliOptions,
) -> usize {
    let by_id: HashMap<_, _> = archive
        .entries
        .iter()
        .enumerate()
        .filter_map(|(position, entry)| Some((entry.hxv4_id?, (position, entry.adler?))))
        .collect();
    let mut catalog = Catalog::default();
    for (position, record) in index
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.archive_slot == 0)
    {
        catalog
            .matches
            .entry((record.path_hash, record.name_hash))
            .and_modify(|match_id| *match_id = None)
            .or_insert(Some(position));
        let Some(&(entry, checksum)) = by_id.get(&record.id) else {
            continue;
        };
        let Some(payload) = verified_payload(archive, filter, record, entry, checksum) else {
            continue;
        };
        if let Some(asset) = read_asset(&payload) {
            catalog.assets.insert(position, asset);
        }
    }
    resolve_catalog(index, catalog, || {
        sibling_stand_aliases(archive, filter, options)
    })
}

fn verified_payload(
    archive: &Archive,
    filter: &Hxv4NativeFilterManager,
    record: &Hxv4IndexEntry,
    entry: usize,
    checksum: u32,
) -> Option<Vec<u8>> {
    let mut payload = archive.reconstruct_entry(entry).ok()?;
    filter
        .state_for_entry(record.entry_key, record.filter_flag)
        .apply(0, &mut payload);
    (adler32(&payload) == checksum).then_some(payload)
}

fn sibling_stand_aliases(
    foreground: &Archive,
    filter: &Hxv4NativeFilterManager,
    options: &HxCliOptions,
) -> HashSet<String> {
    let Some(root) = hxv4_game_root(foreground, options) else {
        return HashSet::new();
    };
    let path = root.join("data.xp3");
    if foreground.path.as_ref().is_some_and(|current| {
        current
            .canonicalize()
            .ok()
            .is_some_and(|current| path.canonicalize().ok().as_ref() == Some(&current))
    }) {
        return HashSet::new();
    }
    let Ok(archive) = Archive::open(path) else {
        return HashSet::new();
    };
    let Ok(Some(index)) = load_hx_index(&archive, options) else {
        return HashSet::new();
    };
    let records: HashMap<_, _> = index
        .entries
        .iter()
        .filter(|record| record.archive_slot == 0)
        .map(|record| (record.id, record))
        .collect();
    let mut aliases = HashSet::new();
    for (position, entry) in archive.entries.iter().enumerate() {
        if entry.original_size > CHARACTER_LIST_LIMIT {
            continue;
        }
        let Some((record, checksum)) = entry
            .hxv4_id
            .and_then(|id| records.get(&id))
            .zip(entry.adler)
        else {
            continue;
        };
        if let Some(source) = verified_payload(&archive, filter, record, position, checksum)
            .and_then(|payload| read_text(&payload))
        {
            aliases.extend(character_stand_aliases(&source).map(str::to_owned));
        }
    }
    aliases
}

fn resolve_catalog(
    index: &mut Hxv4Index,
    mut catalog: Catalog,
    external_aliases: impl FnOnce() -> HashSet<String>,
) -> usize {
    let groups: HashSet<_> = catalog.matches.keys().map(|(group, _)| *group).collect();
    let mut models = HashSet::new();
    let mut aliases = HashSet::new();
    let mut stands = HashSet::new();
    for (position, asset) in &catalog.assets {
        let group = index.entries[*position].path_hash;
        let Asset::Text {
            source,
            layers: None,
        } = asset
        else {
            continue;
        };
        for name in [
            "backlogface.csv",
            "emotion.csv",
            "emotion.txt",
            "facezoom.csv",
            "standposition.txt",
        ] {
            if catalog.lookup(group, name) == Some(*position) {
                catalog.names.insert(*position, name.to_owned());
                if name == "standposition.txt" {
                    for model in stand_position_models(source) {
                        models.insert(model.to_owned());
                    }
                }
            }
        }
        let (definition_models, definition_aliases) = read_definitions(
            &mut catalog.names,
            &catalog.matches,
            group,
            *position,
            source,
        );
        aliases.extend(definition_aliases);
        if stand_source(source).is_some() {
            stands.insert(*position);
        }
        for model in definition_models {
            if !model.starts_with("face") {
                models.insert(format!("face{model}"));
            }
            models.insert(model);
        }
    }

    // A stand definition may be stored with global configuration, while its
    // tables live in separate character directories. Only the table-to-image
    // link is constrained to a directory.
    for alias in aliases {
        claim_asset(&mut catalog, &groups, &alias, "sinfo");
    }
    for model in models {
        let role = model
            .rsplit_once('_')
            .filter(|(_, variant)| {
                !variant.is_empty() && variant.bytes().all(|b| b.is_ascii_digit())
            })
            .map_or(model.as_str(), |(role, _)| role);
        let role = if role == model {
            role.trim_end_matches(|ch: char| ch.is_ascii_digit())
        } else {
            role
        };
        for stem in [model.as_str(), role] {
            if valid_basename(stem) {
                claim_asset(&mut catalog, &groups, &format!("{stem}.stand"), "stand");
            }
        }
        for stem in std::iter::once(model.clone())
            .chain((0..=MAX_TIER).map(|tier| format!("{model}_{tier}")))
        {
            for extension in ["sinfo", "pbd", "txt"] {
                claim_asset(
                    &mut catalog,
                    &groups,
                    &format!("{stem}.{extension}"),
                    extension,
                );
            }
        }
    }

    // Character lists in data.xp3 can name distinct .stand entries that all
    // reference the same model. Only search the sibling if local models left
    // stand definitions unnamed.
    if stands.iter().any(|position| {
        !catalog.names.contains_key(position) && index.entries[*position].name.is_none()
    }) {
        for alias in external_aliases() {
            claim_asset(&mut catalog, &groups, &alias, "stand");
        }
    }

    let tables: Vec<_> = catalog
        .assets
        .iter()
        .filter_map(|(&position, asset)| {
            let record = &index.entries[position];
            let name = catalog.names.get(&position).or(record.name.as_ref())?;
            if hxv4_filename_hash(name) != record.name_hash {
                return None;
            }
            let (stem, _) = name.rsplit_once('.')?;
            Some((record.path_hash, stem.to_owned(), asset.layers()?))
        })
        .collect();

    let mut max_layer = 0;
    let mut listed = HashSet::new();
    for (group, stem, layers) in &tables {
        for layer in *layers {
            max_layer = max_layer.max(layer.id);
            listed.insert((*group, stem.as_str(), layer.id));
            let name = format!("{stem}_{}.tlg", layer.id);
            if let Some(position) = catalog.lookup(*group, &name) {
                if let Some(Asset::Tlg(actual)) = catalog.assets.get(&position) {
                    if layer.size == *actual || (layer.size == (0, 0) && *actual == (32, 32)) {
                        catalog.names.insert(position, name);
                    }
                }
            }
        }
    }

    // Some engines retain TLGs absent from the active layer table. Only try
    // numbered names under verified table stems and within the observed range.
    if catalog.assets.iter().any(|(position, asset)| {
        matches!(asset, Asset::Tlg(_))
            && !catalog.names.contains_key(position)
            && index.entries[*position].name.is_none()
    }) {
        for (group, stem, _) in &tables {
            for id in (0..=max_layer.min(MAX_EXTRA_LAYER_ID))
                .filter(|id| !listed.contains(&(*group, stem.as_str(), *id)))
            {
                let name = format!("{stem}_{id}.tlg");
                if let Some(position) = catalog.lookup(*group, &name) {
                    if matches!(catalog.assets.get(&position), Some(Asset::Tlg(_))) {
                        catalog.names.entry(position).or_insert(name);
                    }
                }
            }
        }
    }

    let mut paths = HashMap::new();
    for (position, record) in index.entries.iter().enumerate() {
        if record.archive_slot == 0 {
            if let Some(name) = record.name.as_ref().or(catalog.names.get(&position)) {
                *paths
                    .entry(case_folded_path(record, name))
                    .or_insert(0usize) += 1;
            }
        }
    }
    let mut restored = 0;
    for (position, name) in catalog.names {
        let record = &mut index.entries[position];
        if record.name.is_none() && paths.get(&case_folded_path(record, &name)) == Some(&1) {
            record.name = Some(name);
            restored += 1;
        }
    }
    restored
}

fn case_folded_path(record: &Hxv4IndexEntry, name: &str) -> String {
    let dir = record
        .path
        .clone()
        .unwrap_or_else(|| record.path_hash_hex());
    format!("{}/{name}", dir.trim_matches(['/', '\\']))
        .replace('\\', "/")
        .to_lowercase()
}

fn claim_asset(catalog: &mut Catalog, groups: &HashSet<Group>, name: &str, extension: &str) {
    let hash = hxv4_filename_hash(name);
    for group in groups {
        let Some(Some(position)) = catalog.matches.get(&(*group, hash)) else {
            continue;
        };
        if matches!(
            (extension, catalog.assets.get(position)),
            ("pbd", Some(Asset::Table(_)))
                | (
                    "txt",
                    Some(Asset::Text {
                        layers: Some(_),
                        ..
                    })
                )
                | ("sinfo", Some(Asset::Text { layers: None, .. }))
        ) || matches!(
            (extension, catalog.assets.get(position)),
            ("stand", Some(Asset::Text { source, layers: None }))
                if stand_source(source).is_some()
        ) {
            catalog.names.insert(*position, name.to_owned());
        }
    }
}

impl Catalog {
    fn lookup(&self, group: Group, name: &str) -> Option<usize> {
        exact_match(&self.matches, group, name)
    }
}

fn exact_match(
    matches: &HashMap<EntryHash, Option<usize>>,
    group: Group,
    name: &str,
) -> Option<usize> {
    matches
        .get(&(group, hxv4_filename_hash(name)))
        .copied()
        .flatten()
}

fn read_asset(bytes: &[u8]) -> Option<Asset> {
    if bytes.starts_with(b"TLG") {
        let info = inspect_tlg(bytes).ok()?;
        return Some(Asset::Tlg((info.width, info.height)));
    }
    if bytes.len() > METADATA_LIMIT {
        return None;
    }
    if is_pbd_bytes(bytes) {
        let document = decode_pbd(bytes).ok()?;
        return Some(Asset::Table(pbd_layers(&document.root)?));
    }
    let source = read_text(bytes)?;
    let layers = text_layers(&source);
    Some(Asset::Text { source, layers })
}

fn read_text(bytes: &[u8]) -> Option<String> {
    let unwrapped = decode_kirikiri_text(bytes);
    let bytes = unwrapped.as_deref().unwrap_or(bytes);
    let source = if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        UTF_16LE
            .decode_without_bom_handling_and_without_replacement(bytes)?
            .into_owned()
    } else if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
        UTF_16BE
            .decode_without_bom_handling_and_without_replacement(bytes)?
            .into_owned()
    } else {
        std::str::from_utf8(bytes)
            .map_or_else(
                |_| SHIFT_JIS.decode_without_bom_handling_and_without_replacement(bytes),
                |text| Some(text.into()),
            )?
            .trim_start_matches('\u{feff}')
            .to_owned()
    };
    if source.is_empty()
        || source
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\t' | '\r' | '\n'))
    {
        return None;
    }
    Some(source)
}

fn pbd_layers(root: &PbdValue) -> Option<Vec<Layer>> {
    let PbdValue::Array { items } = root else {
        return None;
    };
    let layers = items
        .iter()
        .skip(1)
        .filter_map(|row| {
            let PbdValue::Dictionary { entries } = row else {
                return None;
            };
            let number = |key| {
                entries
                    .iter()
                    .find(|entry| entry.key == key)
                    .and_then(|entry| {
                        let PbdValue::Integer { value } = entry.value else {
                            return None;
                        };
                        u32::try_from(value).ok()
                    })
            };
            (number("layer_type")? == 0).then_some(())?;
            Some(Layer {
                id: number("layer_id")?,
                size: (number("width")?, number("height")?),
            })
        })
        .collect::<Vec<_>>();
    (!layers.is_empty()).then_some(layers)
}

fn text_layers(source: &str) -> Option<Vec<Layer>> {
    let mut lines = source.lines();
    let header: Vec<_> = lines
        .next()?
        .strip_prefix("#layer_type\t")?
        .split('\t')
        .collect();
    let column = |name| {
        header
            .iter()
            .position(|column| *column == name)
            .map(|i| i + 1)
    };
    let (id, width, height) = (column("layer_id")?, column("width")?, column("height")?);
    let layers = lines
        .filter_map(|line| {
            let row: Vec<_> = line.split('\t').collect();
            if row.first() != Some(&"0") {
                return None;
            }
            let number = |column: usize| row.get(column)?.trim().parse::<u32>().ok();
            Some(Layer {
                id: number(id)?,
                size: (number(width)?, number(height)?),
            })
        })
        .collect::<Vec<_>>();
    (!layers.is_empty()).then_some(layers)
}

fn read_definitions(
    names: &mut HashMap<usize, String>,
    matches: &HashMap<EntryHash, Option<usize>>,
    group: Group,
    position: usize,
    source: &str,
) -> (Vec<String>, Vec<String>) {
    let Some(text) = stand_source(source) else {
        return (
            sinfo_stem(source.trim_start())
                .map(str::to_owned)
                .into_iter()
                .collect(),
            Vec::new(),
        );
    };
    let Some(script) = analyze_script_names("stand.tjs", text.as_bytes()) else {
        return (Vec::new(), Vec::new());
    };
    let models: Vec<_> = script
        .references
        .iter()
        .filter(|item| item.context == "field:filename" && valid_basename(&item.value))
        .map(|item| item.value.clone())
        .collect();
    let aliases: Vec<_> = script
        .references
        .iter()
        .filter(|item| {
            item.context == "field:sinfo"
                && valid_basename(&item.value)
                && item.value.ends_with(".sinfo")
        })
        .map(|item| item.value.as_str())
        .collect();

    for model in &models {
        let role = model
            .split_once('_')
            .map_or(model.as_str(), |(head, _)| head);
        let role = role
            .rsplit_once("ポーズ")
            .filter(|(_, tail)| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()))
            .map_or(role, |(head, _)| head);
        let mut candidates = vec![
            format!("{model}.stand"),
            format!("{role}.stand"),
            format!("face{role}.stand"),
        ];
        if let Some(role) = numbered_pose_role(model) {
            candidates.push(format!("{role}.stand"));
            candidates.push(format!("face{role}.stand"));
        }
        let ending = format!("_{model}.sinfo");
        for alias in &aliases {
            if let Some(prefix) = alias.strip_suffix(&ending) {
                candidates.push(format!("{prefix}_{role}.stand"));
            }
        }
        for candidate in candidates {
            if exact_match(matches, group, &candidate) == Some(position) {
                names.insert(position, candidate);
            }
        }
    }
    (models, aliases.into_iter().map(str::to_owned).collect())
}

fn stand_source(mut text: &str) -> Option<&str> {
    text = text.trim_start();
    while text.starts_with('#') {
        text = text.split_once('\n')?.1.trim_start();
    }
    let text = text.strip_prefix("(const)").unwrap_or(text).trim_start();
    ((text.starts_with('[') || text.starts_with("%[")) && text.contains("filename")).then_some(text)
}

fn stand_position_models(source: &str) -> impl Iterator<Item = &str> {
    source.lines().filter_map(|line| {
        let (model, options) = line.split_once('\t')?;
        (!model.starts_with('#')
            && valid_basename(model)
            && options
                .split('\t')
                .step_by(2)
                .any(|key| key == "leveloffset"))
        .then_some(model)
    })
}

fn character_stand_aliases(source: &str) -> impl Iterator<Item = &str> {
    source.lines().filter_map(|line| {
        let line = line.trim();
        let (character, fields) = line.split_once(',')?;
        let name = fields.split(',').next()?.trim().trim_matches('"');
        (!character.starts_with('#')
            && valid_basename(character.trim().trim_matches('"'))
            && valid_basename(name)
            && name.ends_with(".stand"))
        .then_some(name)
    })
}

// Some stand definitions append the pose number directly to the role name,
// followed by a separate numeric variant, as in `花12_1`.
fn numbered_pose_role(model: &str) -> Option<&str> {
    let (pose, variant) = model.rsplit_once('_')?;
    let role = pose.trim_end_matches(|ch: char| ch.is_ascii_digit());
    (!role.is_empty()
        && role.len() < pose.len()
        && !variant.is_empty()
        && variant.bytes().all(|ch| ch.is_ascii_digit()))
    .then_some(role)
}

fn sinfo_stem(text: &str) -> Option<&str> {
    let mut lines = text.lines();
    let stem = lines.next()?.split_once('\t')?.0.strip_prefix('#')?.trim();
    (valid_basename(stem)
        && lines.any(|line| line.starts_with("dress\t") || line.starts_with("face\t")))
    .then_some(stem)
}

fn valid_basename(name: &str) -> bool {
    !name.is_empty()
        && name.encode_utf16().count() <= 255
        && !name.starts_with('.')
        && !name.ends_with([' ', '.'])
        && !name
            .chars()
            .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_for<const N: usize>(fixtures: [(u8, &str, Asset); N]) -> (Hxv4Index, Catalog) {
        let mut index = Hxv4Index::default();
        let mut catalog = Catalog::default();
        for (position, (group, name, asset)) in fixtures.into_iter().enumerate() {
            let path_hash = [group; 8];
            let name_hash = hxv4_filename_hash(name);
            index.entries.push(Hxv4IndexEntry {
                record_index: position,
                packed: position as u64,
                id: position as u64,
                archive_slot: 0,
                filter_flag: 0,
                entry_key: 0,
                path_hash,
                name_hash,
                path: None,
                name: None,
            });
            catalog
                .matches
                .entry((path_hash, name_hash))
                .and_modify(|match_id| *match_id = None)
                .or_insert(Some(position));
            catalog.assets.insert(position, asset);
        }
        (index, catalog)
    }

    #[test]
    fn recovers_cp932_stands_and_sinfo_from_character_metadata() {
        let cp932 = |source: &str| {
            let (bytes, _, errors) = encoding_rs::SHIFT_JIS.encode(source);
            assert!(!errors);
            read_asset(&bytes).unwrap()
        };
        let alias_list = "#役名,ファイル,位置\n影,影_鳥.stand,中央\n#未使用,影_未使用.stand\n";
        let fixtures = [
            (
                1,
                "standposition.txt",
                cp932("#位置定義\n花_苗_1\tleveloffset\t[0]\txoffset\tint 0\n"),
            ),
            (
                1,
                "花_苗.stand",
                cp932("#立ち絵定義\n[%[\"filename\"=>\"花1\"]]"),
            ),
            (1, "花.stand", cp932("[%[\"filename\"=>\"花2\"]]")),
            (2, "花_苗_1.sinfo", cp932("#衣装定義\n衣装\t01\n")),
            (
                2,
                "花1.txt",
                cp932("#layer_type\tname\theight\tlayer_id\twidth\n0\t通常\t8\t3\t6\n"),
            ),
            (2, "花1_3.tlg", Asset::Tlg((6, 8))),
            (2, "花1_2.tlg", Asset::Tlg((6, 8))),
            (3, "影_鳥.stand", cp932("[%[\"filename\"=>\"影_魚\"]]")),
            (3, "影_未使用.stand", cp932("[%[\"filename\"=>\"影_魚\"]]")),
            (3, "unknown.sinfo", cp932("#出典不明\n衣装\t01\n")),
        ];
        let (mut index, catalog) = catalog_for(fixtures);
        assert_eq!(
            resolve_catalog(&mut index, catalog, || character_stand_aliases(alias_list)
                .map(str::to_owned)
                .collect()),
            8
        );
        for (position, name) in [
            "standposition.txt",
            "花_苗.stand",
            "花.stand",
            "花_苗_1.sinfo",
            "花1.txt",
            "花1_3.tlg",
            "花1_2.tlg",
            "影_鳥.stand",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(index.entries[position].name.as_deref(), Some(name));
        }
        assert!(index.entries[8..].iter().all(|entry| entry.name.is_none()));
        assert!(read_asset(&[0x82]).is_none());
    }

    #[test]
    fn recovers_stand_name_from_numbered_pose_and_variant() {
        let group = [1; 8];
        let stand_name = "花_苗.stand";
        let targets = HashMap::from([((group, hxv4_filename_hash(stand_name)), Some(3))]);
        let mut names = HashMap::new();
        let source = r#"[%["filename"=>"花_苗12_1"], %["filename"=>"花_苗3_2"]]"#;

        let (models, _) = read_definitions(&mut names, &targets, group, 2, source);
        assert_eq!(models, ["花_苗12_1", "花_苗3_2"]);
        assert!(names.is_empty());

        read_definitions(&mut names, &targets, group, 3, source);
        assert_eq!(names.get(&3).map(String::as_str), Some(stand_name));
        assert_eq!(numbered_pose_role("花_苗12_"), None);
        assert_eq!(numbered_pose_role("花_苗12_casual"), None);
        assert_eq!(numbered_pose_role("12_1"), None);
    }

    #[test]
    fn follows_stand_layer_tables_and_keeps_ambiguous_or_unverified_names() {
        let stand = r#"[%["filename"=>"花ポーズ1", "sinfo"=>"extra_花ポーズ1.sinfo"],%["filename"=>"Name"],%["filename"=>"name"]]"#;
        let table = "#layer_type\tname\theight\tlayer_id\twidth\n\t\t90\t\t120\n0\t正常\t8\t3\t6\n0\t不一致\t8\t4\t6\n0\t空\t0\t5\t0\n";
        let fixtures = [
            (3, "extra_花.stand", read_asset(stand.as_bytes()).unwrap()),
            (
                1,
                "extra_花ポーズ1.sinfo",
                read_asset(b"definition").unwrap(),
            ),
            (
                1,
                "face花ポーズ1_2.txt",
                read_asset(table.as_bytes()).unwrap(),
            ),
            (1, "face花ポーズ1_2_3.tlg", Asset::Tlg((6, 8))),
            (1, "face花ポーズ1_2_4.tlg", Asset::Tlg((8, 6))),
            (1, "face花ポーズ1_2_5.tlg", Asset::Tlg((32, 32))),
            (1, "face花ポーズ1_2_2.tlg", Asset::Tlg((6, 8))),
            (2, "face花ポーズ1_2_3.tlg", Asset::Tlg((6, 8))),
            (1, "face花ポーズ1_2_6.tlg", Asset::Tlg((6, 8))),
            (1, "face花ポーズ1_2_1.tlg", Asset::Tlg((6, 8))),
            (1, "face花ポーズ1_2_1.tlg", Asset::Tlg((6, 8))),
            (1, "Name.sinfo", read_asset(b"definition").unwrap()),
            (1, "name.sinfo", read_asset(b"definition").unwrap()),
        ];
        let (mut index, catalog) = catalog_for(fixtures);
        assert_eq!(resolve_catalog(&mut index, catalog, HashSet::new), 6);
        for position in [0, 1, 2, 3, 5, 6] {
            assert_eq!(
                hxv4_filename_hash(index.entries[position].name.as_deref().unwrap()),
                index.entries[position].name_hash,
            );
        }
        for position in [4, 7, 8, 9, 10, 11, 12] {
            assert!(index.entries[position].name.is_none());
        }
    }
}
