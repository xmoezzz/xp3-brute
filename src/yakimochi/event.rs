use std::collections::{HashMap, HashSet};
use std::io::Result;

use xp3_brute::Archive;

use super::{
    function_literals, invalid, kbad::Value, load_script, read_asset, read_named_asset, tjs_const,
    token, MadoCrypt, NameAliases,
};

const EVENT_PREFIX: &str = "event_";
const LARGE_SUFFIX: &str = "_大";

pub(super) fn recover(
    archive: &Archive,
    data: &Archive,
    filter: MadoCrypt,
    alphabet: &[char; 256],
) -> Result<NameAliases> {
    let script = load_script(data, filter, "biscrat_kagenvevent.tjs")?;
    let valid_loader = function_literals(&script, "loadInfo").is_some_and(|literals| {
        [EVENT_PREFIX, "getSHA256Name", ".tlg", "evalStorage"]
            .iter()
            .all(|marker| literals.contains(marker))
    });
    if !valid_loader {
        return Err(invalid(
            "could not identify the Yakimochi EV definition loader",
        ));
    }

    let gallery = tjs_const::parse(&read_named_asset(data, filter, "init_cg.tjs")?)?;
    let mut indexed = HashMap::new();
    let mut occupied = HashSet::new();
    for (index, entry) in archive.entries.iter().enumerate() {
        indexed
            .entry(entry.name.as_str())
            .and_modify(|previous| *previous = None)
            .or_insert(Some(index));
        occupied.insert(entry.name.to_ascii_lowercase());
    }

    let mut aliases = NameAliases::new();
    let mut insert_alias = |index, name: String| {
        if aliases.contains_key(&index) || !occupied.insert(name.to_ascii_lowercase()) {
            return Err(invalid(format!("ambiguous EV output path {name}")));
        }
        aliases.insert(index, name);
        Ok(())
    };

    for base in event_bases(&gallery)? {
        for event in [base.to_owned(), format!("{base}{LARGE_SUFFIX}")] {
            // The gallery catalogs the base name once. The archive distinguishes
            // normal and large definitions by their hashed storage names.
            let logical = format!("{EVENT_PREFIX}{event}");
            let physical = token(alphabet, &logical);
            let Some(index) = indexed.get(physical.as_str()) else {
                continue;
            };
            let index = index.ok_or_else(|| invalid(format!("ambiguous EV definition {event}")))?;
            let definition = tjs_const::parse(&read_asset(archive, index, filter)?)
                .map_err(|err| invalid(format!("invalid EV definition {event}: {err}")))?;
            insert_alias(index, format!("{logical}.tlg"))?;
            for (number, stem) in image_layers(&definition)? {
                let filename = format!("{stem}.tlg");
                if let Some(layer) = indexed.get(filename.as_str()) {
                    let layer = layer
                        .ok_or_else(|| invalid(format!("ambiguous EV layer {event} {number}")))?;
                    insert_alias(layer, format!("{event}_{number}.tlg"))?;
                }
            }
        }
    }

    if aliases.is_empty() {
        return Err(invalid("no EV definitions matched the image archive index"));
    }
    Ok(aliases)
}

fn event_bases(gallery: &Value) -> Result<HashSet<&str>> {
    let mut bases = HashSet::new();
    let groups = gallery.map().ok_or_else(|| invalid("invalid EV gallery"))?;
    for (_, group) in groups {
        for entry in group
            .array()
            .ok_or_else(|| invalid("invalid EV gallery group"))?
        {
            let Some(events) = entry.get("events") else {
                continue;
            };
            for event in events
                .array()
                .ok_or_else(|| invalid("invalid EV gallery event array"))?
            {
                let name = event
                    .get("name")
                    .and_then(Value::text)
                    .ok_or_else(|| invalid("missing EV gallery event name"))?;
                let base = name.strip_suffix(LARGE_SUFFIX).unwrap_or(name);
                let suffix = base.strip_prefix("ev_").unwrap_or_default();
                if suffix.is_empty()
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    return Err(invalid("invalid EV gallery event name"));
                }
                bases.insert(base);
            }
        }
    }
    Ok(bases)
}

fn image_layers(definition: &Value) -> Result<Vec<(u32, &str)>> {
    let keys = definition
        .get("keys")
        .and_then(Value::array)
        .ok_or_else(|| invalid("missing EV definition layer keys"))?;
    let info = definition
        .get("info")
        .and_then(Value::map)
        .ok_or_else(|| invalid("missing EV definition layer info"))?;
    let mut layers = HashMap::new();
    for (id, layer) in info {
        let id = id.text().ok_or_else(|| invalid("invalid EV layer ID"))?;
        if layers.insert(id, layer).is_some() {
            return Err(invalid("duplicate EV layer ID"));
        }
    }
    let mut numbers = HashSet::new();
    let mut refs = Vec::with_capacity(keys.len());
    for key in keys {
        let layer = key
            .text()
            .and_then(|id| layers.remove(id))
            .ok_or_else(|| invalid("EV layer key is missing or repeated"))?;
        let number = layer
            .get("layerNumber")
            .and_then(Value::integer)
            .and_then(|number| u32::try_from(number).ok())
            .filter(|number| numbers.insert(*number))
            .ok_or_else(|| invalid("invalid or repeated EV layer number"))?;
        let stem = layer
            .get("filename")
            .and_then(Value::text)
            .filter(|stem| stem.encode_utf16().count() == 32 && !stem.contains(['/', '\\', '.']))
            .ok_or_else(|| invalid("invalid EV layer filename token"))?;
        refs.push((number, stem));
    }
    if !layers.is_empty() {
        return Err(invalid(
            "EV definition has layer info absent from the key array",
        ));
    }
    Ok(refs)
}
