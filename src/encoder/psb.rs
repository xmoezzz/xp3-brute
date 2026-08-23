//! PSB-family encoder driven by the typed JSON/resource transforms in
//! `xp3-meta.yaml`.
//!
//! The encoder deliberately does not patch PSB offsets in place.  It parses the
//! editable typed JSON into an ordered serde value, overlays edited resource
//! sidecars, serializes a fresh PSB v2/v3/v4 with `emote-psb`, reapplies the
//! original Emote XOR stream when necessary, and finally restores the original
//! raw/MDF/LZ4 wrapper.

use crate::decoder::psb::{decode_psb_with_key, psb_roundtrip_json, PSB_ROOT_JSON_SCHEMA};
use crate::encoder::tlg::{encode_tlg_image, TlgEncodeOptions};
use crate::xp3_meta::{
    sha256_hex, PsbResourceBlobTransformMeta, PsbRootJsonTransformMeta, PsbSourceMeta,
    PsbTextureTransformMeta,
};
use crate::{Error, Result};
use emote_psb::psb::write::PsbWriter;
use emote_psb::value::{
    PsbCompilerArray, PsbCompilerBinaryTree, PsbCompilerBool, PsbCompilerDecimal,
    PsbCompilerNumber, PsbCompilerResource, PsbCompilerString, PsbExtraResource, PsbResource,
};
use flate2::{write::ZlibEncoder, Compression};
use image::{DynamicImage, ImageFormat, RgbaImage};
use lz4_flex::frame::FrameEncoder;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Component, Path, PathBuf};

fn safe_sidecar_path(root: &Path, value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(Error::invalid(format!(
            "manifest path must be relative: {value:?}"
        )));
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::invalid(format!("unsafe manifest path: {value:?}")));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(Error::invalid("empty manifest path"));
    }
    Ok(root.join(relative))
}

#[derive(Debug, Clone)]
pub struct PsbRebuildInput<'a> {
    pub source: &'a PsbSourceMeta,
    pub root_json: Option<&'a PsbRootJsonTransformMeta>,
    pub textures: Vec<&'a PsbTextureTransformMeta>,
    pub raw_blobs: Vec<&'a PsbResourceBlobTransformMeta>,
    pub emote_key: Option<u32>,
    pub allow_lossy: bool,
}

#[derive(Debug, Clone)]
enum RoundtripPsbValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f32),
    Double(f64),
    String(String),
    Resource(u32),
    ExtraResource(u32),
    List(Vec<RoundtripPsbValue>),
    Object(Vec<(String, RoundtripPsbValue)>),
    Compiler(CompilerTag),
}

#[derive(Debug, Clone, Copy)]
enum CompilerTag {
    Number,
    String,
    Resource,
    Decimal,
    Array,
    Bool,
    BinaryTree,
}

impl Serialize for RoundtripPsbValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Int(value) => serializer.serialize_i64(*value),
            Self::Float(value) => serializer.serialize_f32(*value),
            Self::Double(value) => serializer.serialize_f64(*value),
            Self::String(value) => serializer.serialize_str(value),
            Self::Resource(index) => PsbResource(*index).serialize(serializer),
            Self::ExtraResource(index) => PsbExtraResource(*index).serialize(serializer),
            Self::List(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            Self::Compiler(tag) => match tag {
                CompilerTag::Number => PsbCompilerNumber.serialize(serializer),
                CompilerTag::String => PsbCompilerString.serialize(serializer),
                CompilerTag::Resource => PsbCompilerResource.serialize(serializer),
                CompilerTag::Decimal => PsbCompilerDecimal.serialize(serializer),
                CompilerTag::Array => PsbCompilerArray.serialize(serializer),
                CompilerTag::Bool => PsbCompilerBool.serialize(serializer),
                CompilerTag::BinaryTree => PsbCompilerBinaryTree.serialize(serializer),
            },
        }
    }
}

fn json_error(message: impl Into<String>) -> Error {
    Error::format(message.into())
}

fn required_field<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| json_error(format!("PSB typed JSON is missing {key:?}")))
}

fn parse_hex_u32_bits(value: &Value, label: &str) -> Result<u32> {
    let text = value
        .as_str()
        .ok_or_else(|| json_error(format!("{label} must be a hexadecimal string")))?;
    u32::from_str_radix(text.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| json_error(format!("invalid {label}: {text:?}")))
}

fn parse_hex_u64_bits(value: &Value, label: &str) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| json_error(format!("{label} must be a hexadecimal string")))?;
    u64::from_str_radix(text.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| json_error(format!("invalid {label}: {text:?}")))
}

fn parse_typed_value(value: &Value) -> Result<RoundtripPsbValue> {
    let object = value
        .as_object()
        .ok_or_else(|| json_error("PSB typed value must be an object"))?;
    let kind = required_field(object, "$type")?
        .as_str()
        .ok_or_else(|| json_error("PSB $type must be a string"))?;
    match kind {
        "null" => Ok(RoundtripPsbValue::Null),
        "bool" => Ok(RoundtripPsbValue::Bool(
            required_field(object, "value")?
                .as_bool()
                .ok_or_else(|| json_error("PSB bool.value must be boolean"))?,
        )),
        "int" => Ok(RoundtripPsbValue::Int(
            required_field(object, "value")?
                .as_i64()
                .ok_or_else(|| json_error("PSB int.value must fit i64"))?,
        )),
        "float" => Ok(RoundtripPsbValue::Float(f32::from_bits(
            parse_hex_u32_bits(required_field(object, "bits")?, "PSB float.bits")?,
        ))),
        "double" => Ok(RoundtripPsbValue::Double(f64::from_bits(
            parse_hex_u64_bits(required_field(object, "bits")?, "PSB double.bits")?,
        ))),
        "string" => Ok(RoundtripPsbValue::String(
            required_field(object, "value")?
                .as_str()
                .ok_or_else(|| json_error("PSB string.value must be a string"))?
                .to_string(),
        )),
        "resource" => Ok(RoundtripPsbValue::Resource(
            u32::try_from(
                required_field(object, "index")?
                    .as_u64()
                    .ok_or_else(|| json_error("PSB resource.index must be unsigned"))?,
            )
            .map_err(|_| json_error("PSB resource.index exceeds u32"))?,
        )),
        "extra_resource" => Ok(RoundtripPsbValue::ExtraResource(
            u32::try_from(
                required_field(object, "index")?
                    .as_u64()
                    .ok_or_else(|| json_error("PSB extra_resource.index must be unsigned"))?,
            )
            .map_err(|_| json_error("PSB extra_resource.index exceeds u32"))?,
        )),
        "list" => {
            let items = required_field(object, "items")?
                .as_array()
                .ok_or_else(|| json_error("PSB list.items must be an array"))?;
            Ok(RoundtripPsbValue::List(
                items
                    .iter()
                    .map(parse_typed_value)
                    .collect::<Result<Vec<_>>>()?,
            ))
        }
        "object" => {
            let entries = required_field(object, "entries")?
                .as_array()
                .ok_or_else(|| json_error("PSB object.entries must be an array"))?;
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                let entry = entry
                    .as_object()
                    .ok_or_else(|| json_error("PSB object entry must be an object"))?;
                let key = required_field(entry, "key")?
                    .as_str()
                    .ok_or_else(|| json_error("PSB object entry key must be a string"))?
                    .to_string();
                let value = parse_typed_value(required_field(entry, "value")?)?;
                out.push((key, value));
            }
            Ok(RoundtripPsbValue::Object(out))
        }
        "compiler" => {
            let tag = required_field(object, "tag")?
                .as_str()
                .ok_or_else(|| json_error("PSB compiler.tag must be a string"))?;
            let tag = match tag {
                "integer" | "number" => CompilerTag::Number,
                "string" => CompilerTag::String,
                "resource" => CompilerTag::Resource,
                "decimal" => CompilerTag::Decimal,
                "array" => CompilerTag::Array,
                "bool" => CompilerTag::Bool,
                "binary_tree" | "binary-tree" => CompilerTag::BinaryTree,
                _ => return Err(json_error(format!("unknown PSB compiler tag {tag:?}"))),
            };
            Ok(RoundtripPsbValue::Compiler(tag))
        }
        _ => Err(json_error(format!("unknown PSB typed value {kind:?}"))),
    }
}

fn root_from_document(document: &Value) -> Result<(u16, RoundtripPsbValue)> {
    if document.get("$schema").and_then(Value::as_str) != Some(PSB_ROOT_JSON_SCHEMA) {
        return Err(json_error(format!(
            "PSB JSON schema must be {PSB_ROOT_JSON_SCHEMA:?}"
        )));
    }
    let psb = document
        .get("psb")
        .and_then(Value::as_object)
        .ok_or_else(|| json_error("PSB typed JSON is missing psb object"))?;
    let version = u16::try_from(
        required_field(psb, "version")?
            .as_u64()
            .ok_or_else(|| json_error("PSB version must be unsigned"))?,
    )
    .map_err(|_| json_error("PSB version exceeds u16"))?;
    if !(2..=4).contains(&version) {
        return Err(Error::unsupported(format!(
            "PSB writer supports versions 2..=4, got {version}"
        )));
    }
    let root = parse_typed_value(required_field(psb, "root")?)?;
    Ok((version, root))
}

fn validate_resource_refs(
    value: &RoundtripPsbValue,
    resources_len: usize,
    extra_len: usize,
) -> Result<()> {
    match value {
        RoundtripPsbValue::Resource(index) => {
            if (*index as usize) >= resources_len {
                return Err(Error::format(format!(
                    "PSB typed JSON references resource[{index}], but only {resources_len} resources exist"
                )));
            }
        }
        RoundtripPsbValue::ExtraResource(index) => {
            if (*index as usize) >= extra_len {
                return Err(Error::format(format!(
                    "PSB typed JSON references extra_resource[{index}], but only {extra_len} extra resources exist"
                )));
            }
        }
        RoundtripPsbValue::List(items) => {
            for item in items {
                validate_resource_refs(item, resources_len, extra_len)?;
            }
        }
        RoundtripPsbValue::Object(entries) => {
            for (_, item) in entries {
                validate_resource_refs(item, resources_len, extra_len)?;
            }
        }
        RoundtripPsbValue::Null
        | RoundtripPsbValue::Bool(_)
        | RoundtripPsbValue::Int(_)
        | RoundtripPsbValue::Float(_)
        | RoundtripPsbValue::Double(_)
        | RoundtripPsbValue::String(_)
        | RoundtripPsbValue::Compiler(_) => {}
    }
    Ok(())
}

fn parse_key_hex(value: &str) -> Result<u32> {
    u32::from_str_radix(
        value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .map_err(|_| Error::format(format!("invalid Emote PSB key {value:?}")))
}

pub fn key_from_source(source: &PsbSourceMeta) -> Result<Option<u32>> {
    source
        .emote_key_hex
        .as_deref()
        .map(parse_key_hex)
        .transpose()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceTable {
    Resource,
    Extra,
}

impl ResourceTable {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "resource" => Ok(Self::Resource),
            "extra-resource" | "extra_resource" => Ok(Self::Extra),
            _ => Err(Error::format(format!(
                "unknown PSB resource table {value:?}"
            ))),
        }
    }
}

fn resource<'a>(
    resources: &'a [Vec<u8>],
    extra: &'a [Vec<u8>],
    table: ResourceTable,
    index: u32,
) -> Result<&'a [u8]> {
    let index = index as usize;
    match table {
        ResourceTable::Resource => resources.get(index),
        ResourceTable::Extra => extra.get(index),
    }
    .map(Vec::as_slice)
    .ok_or_else(|| {
        Error::format(format!(
            "PSB resource index out of range: {table:?}[{index}]"
        ))
    })
}

fn replace_resource(
    resources: &mut [Vec<u8>],
    extra: &mut [Vec<u8>],
    table: ResourceTable,
    index: u32,
    bytes: Vec<u8>,
) -> Result<()> {
    let index = index as usize;
    let slot = match table {
        ResourceTable::Resource => resources.get_mut(index),
        ResourceTable::Extra => extra.get_mut(index),
    }
    .ok_or_else(|| {
        Error::format(format!(
            "PSB resource index out of range: {table:?}[{index}]"
        ))
    })?;
    *slot = bytes;
    Ok(())
}

fn decode_rl(bytes: &[u8], align: usize, expected_len: usize) -> Result<Vec<u8>> {
    if align == 0 || expected_len % align != 0 {
        return Err(Error::format("invalid PSB RL alignment/length"));
    }
    let mut out = Vec::with_capacity(expected_len);
    let mut pos = 0usize;
    while out.len() < expected_len {
        let cmd = *bytes
            .get(pos)
            .ok_or_else(|| Error::format("truncated PSB RL command"))?;
        pos += 1;
        if cmd & 0x80 != 0 {
            let count = ((cmd ^ 0x80) as usize) + 3;
            let end = pos
                .checked_add(align)
                .ok_or_else(|| Error::format("PSB RL overflow"))?;
            let value = bytes
                .get(pos..end)
                .ok_or_else(|| Error::format("truncated PSB RL repeat"))?;
            pos = end;
            for _ in 0..count {
                out.extend_from_slice(value);
                if out.len() > expected_len {
                    return Err(Error::format("PSB RL repeat exceeds expected image size"));
                }
            }
        } else {
            let count = cmd as usize + 1;
            let len = count
                .checked_mul(align)
                .ok_or_else(|| Error::format("PSB RL literal overflow"))?;
            let end = pos
                .checked_add(len)
                .ok_or_else(|| Error::format("PSB RL overflow"))?;
            let literal = bytes
                .get(pos..end)
                .ok_or_else(|| Error::format("truncated PSB RL literal"))?;
            pos = end;
            out.extend_from_slice(literal);
            if out.len() > expected_len {
                return Err(Error::format("PSB RL literal exceeds expected image size"));
            }
        }
    }
    if out.len() != expected_len {
        return Err(Error::format("PSB RL decoded size mismatch"));
    }
    Ok(out)
}

fn encode_rl(bytes: &[u8], align: usize) -> Result<Vec<u8>> {
    if align == 0 || bytes.len() % align != 0 {
        return Err(Error::format("invalid PSB RL input alignment"));
    }
    let count = bytes.len() / align;
    let elem = |i: usize| &bytes[i * align..(i + 1) * align];
    let run_len = |start: usize| -> usize {
        let mut n = 1usize;
        while start + n < count && n < 130 && elem(start + n) == elem(start) {
            n += 1;
        }
        n
    };

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < count {
        let run = run_len(i);
        if run >= 3 {
            out.push(0x80 | ((run - 3) as u8));
            out.extend_from_slice(elem(i));
            i += run;
            continue;
        }

        let start = i;
        i += 1;
        while i < count && i - start < 128 {
            if run_len(i) >= 3 {
                break;
            }
            i += 1;
        }
        let literal_count = i - start;
        out.push((literal_count - 1) as u8);
        out.extend_from_slice(&bytes[start * align..i * align]);
    }
    Ok(out)
}

fn uses_rl(compress: Option<&str>) -> bool {
    compress.is_some_and(|value| value.eq_ignore_ascii_case("RL"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Raw32Order {
    Bgra,
    Rgba,
    Bgrx,
    Rgbx,
}

fn big_endian_rgba_spec(spec: Option<&str>) -> bool {
    matches!(
        spec.map(str::to_ascii_lowercase).as_deref(),
        Some("common" | "ems" | "vita" | "psp" | "ps3")
    )
}

fn raw32_order(format: Option<&str>, spec: Option<&str>) -> Raw32Order {
    let normalized = format.map(|value| value.to_ascii_uppercase());
    match normalized.as_deref() {
        None | Some("RGBA") | Some("RGBA8") => {
            if big_endian_rgba_spec(spec) {
                Raw32Order::Rgba
            } else {
                Raw32Order::Bgra
            }
        }
        Some("BERGBA8") => Raw32Order::Rgba,
        Some("LERGBA8")
        | Some("BGRA8")
        | Some("ARGB8")
        | Some("A8R8G8B8")
        | Some("D3DFMTA8R8G8B8") => Raw32Order::Bgra,
        Some("BGRX8") | Some("X8R8G8B8") | Some("D3DFMTX8R8G8B8") => Raw32Order::Bgrx,
        Some("RGBX8") | Some("RGBX") => Raw32Order::Rgbx,
        _ => {
            if big_endian_rgba_spec(spec) {
                Raw32Order::Rgba
            } else {
                Raw32Order::Bgra
            }
        }
    }
}

fn overlay_raw32(
    old: &[u8],
    image: &RgbaImage,
    full_width: u32,
    full_height: u32,
    order: Raw32Order,
    allow_lossy: bool,
) -> Result<Vec<u8>> {
    let expected = (full_width as usize)
        .checked_mul(full_height as usize)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| Error::unsupported("PSB texture dimensions overflow"))?;
    if old.len() != expected {
        return Err(Error::format(format!(
            "PSB raw32 size mismatch: expected {expected}, got {}",
            old.len()
        )));
    }
    if image.width() > full_width || image.height() > full_height {
        return Err(Error::format(
            "edited PSB texture exceeds full source surface",
        ));
    }
    let mut out = old.to_vec();
    for y in 0..image.height() {
        for x in 0..image.width() {
            let px = image.get_pixel(x, y).0;
            if matches!(order, Raw32Order::Bgrx | Raw32Order::Rgbx) && px[3] != 0xff && !allow_lossy
            {
                return Err(Error::unsupported(
                    "edited alpha cannot be represented by PSB X8 pixel format",
                ));
            }
            let offset = ((y as usize) * (full_width as usize) + x as usize) * 4;
            let encoded = match order {
                Raw32Order::Bgra => [px[2], px[1], px[0], px[3]],
                Raw32Order::Rgba => [px[0], px[1], px[2], px[3]],
                Raw32Order::Bgrx => [px[2], px[1], px[0], 0xff],
                Raw32Order::Rgbx => [px[0], px[1], px[2], 0xff],
            };
            out[offset..offset + 4].copy_from_slice(&encoded);
        }
    }
    Ok(out)
}

fn overlay_rgba4444(
    old: &[u8],
    image: &RgbaImage,
    full_width: u32,
    full_height: u32,
) -> Result<Vec<u8>> {
    let expected = (full_width as usize)
        .checked_mul(full_height as usize)
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| Error::unsupported("PSB RGBA4444 dimensions overflow"))?;
    if old.len() != expected {
        return Err(Error::format(format!(
            "PSB RGBA4444 size mismatch: expected {expected}, got {}",
            old.len()
        )));
    }
    if image.width() > full_width || image.height() > full_height {
        return Err(Error::format(
            "edited PSB RGBA4444 texture exceeds full source surface",
        ));
    }
    let mut out = old.to_vec();
    let nibble = |value: u8| -> u16 { ((value as u16 + 8) / 17).min(15) };
    for y in 0..image.height() {
        for x in 0..image.width() {
            let px = image.get_pixel(x, y).0;
            // KrkrExtract/Eluna decode layout: B | G<<4 | R<<8 | A<<12.
            let value =
                nibble(px[2]) | (nibble(px[1]) << 4) | (nibble(px[0]) << 8) | (nibble(px[3]) << 12);
            let offset = ((y as usize) * (full_width as usize) + x as usize) * 2;
            out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    Ok(out)
}

fn overlay_indexed8(
    old_indices: &[u8],
    old_palette: &[u8],
    image: &RgbaImage,
    full_width: u32,
    full_height: u32,
    allow_lossy: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let expected = (full_width as usize)
        .checked_mul(full_height as usize)
        .ok_or_else(|| Error::unsupported("PSB indexed texture dimensions overflow"))?;
    if old_indices.len() != expected {
        return Err(Error::format(format!(
            "PSB indexed pixel size mismatch: expected {expected}, got {}",
            old_indices.len()
        )));
    }
    if old_palette.len() < 256 * 4 {
        return Err(Error::format(
            "PSB indexed bitmap palette is shorter than 1024 bytes",
        ));
    }
    if image.width() > full_width || image.height() > full_height {
        return Err(Error::format(
            "edited PSB indexed texture exceeds full source surface",
        ));
    }
    if !allow_lossy && image.pixels().any(|px| px.0[3] != 0xff) {
        return Err(Error::unsupported(
            "PSB indexed bitmap palette does not preserve edited alpha",
        ));
    }

    let palette_rgb = |index: u8| {
        let offset = index as usize * 4;
        [
            old_palette[offset + 2],
            old_palette[offset + 1],
            old_palette[offset],
        ]
    };
    let mut indices = old_indices.to_vec();
    let mut all_found = true;
    for y in 0..image.height() {
        for x in 0..image.width() {
            let px = image.get_pixel(x, y).0;
            let rgb = [px[0], px[1], px[2]];
            let found = (0u16..=255).find(|index| palette_rgb(*index as u8) == rgb);
            if let Some(index) = found {
                indices[(y as usize) * full_width as usize + x as usize] = index as u8;
            } else {
                all_found = false;
                break;
            }
        }
        if !all_found {
            break;
        }
    }
    if all_found {
        return Ok((indices, old_palette.to_vec()));
    }

    // Rebuild a palette for the complete full surface so pixels outside a
    // truncated editable rectangle keep their original visible colors.
    let mut full_rgb = Vec::<[u8; 3]>::with_capacity(expected);
    for &index in old_indices {
        full_rgb.push(palette_rgb(index));
    }
    for y in 0..image.height() {
        for x in 0..image.width() {
            let px = image.get_pixel(x, y).0;
            full_rgb[(y as usize) * full_width as usize + x as usize] = [px[0], px[1], px[2]];
        }
    }

    let mut colors = Vec::<[u8; 3]>::new();
    let mut rebuilt_indices = Vec::with_capacity(expected);
    for rgb in full_rgb {
        let index = if let Some(index) = colors.iter().position(|candidate| *candidate == rgb) {
            index
        } else {
            if colors.len() == 256 {
                return Err(Error::unsupported(
                    "edited PSB indexed bitmap requires more than 256 colors",
                ));
            }
            colors.push(rgb);
            colors.len() - 1
        };
        rebuilt_indices.push(index as u8);
    }
    let mut palette = vec![0u8; 256 * 4];
    for (index, rgb) in colors.iter().enumerate() {
        let offset = index * 4;
        palette[offset] = rgb[2];
        palette[offset + 1] = rgb[1];
        palette[offset + 2] = rgb[0];
        palette[offset + 3] = 0;
    }
    Ok((rebuilt_indices, palette))
}

fn encode_self_describing_image(
    image: &RgbaImage,
    format: &str,
    allow_lossy: bool,
) -> Result<Vec<u8>> {
    let format_lower = format.to_ascii_lowercase();
    if matches!(format_lower.as_str(), "tlg" | "tlg5" | "tlg6") {
        return encode_tlg_image(
            image,
            TlgEncodeOptions {
                components: 4,
                allow_lossy,
            },
        );
    }
    let image_format = match format_lower.as_str() {
        "png" => ImageFormat::Png,
        "bmp" => ImageFormat::Bmp,
        "jpg" | "jpeg" => {
            if !allow_lossy {
                return Err(Error::unsupported(
                    "rewriting an embedded JPEG resource is lossy; pass --allow-lossy",
                ));
            }
            ImageFormat::Jpeg
        }
        other => {
            return Err(Error::unsupported(format!(
                "no PSB embedded-image encoder for {other:?}"
            )))
        }
    };
    let mut cursor = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image.clone())
        .write_to(&mut cursor, image_format)
        .map_err(|err| Error::format(format!("embedded PSB image encode failed: {err}")))?;
    Ok(cursor.into_inner())
}

fn apply_texture(
    unpack_root: &Path,
    meta: &PsbTextureTransformMeta,
    resources: &mut [Vec<u8>],
    extra: &mut [Vec<u8>],
    allow_lossy: bool,
) -> Result<()> {
    if !meta.lossless_pixels && !allow_lossy {
        return Err(Error::unsupported(format!(
            "PSB texture sidecar {} is lossy ({}); pass --allow-lossy",
            meta.output_path, meta.output_format
        )));
    }
    let image = image::open(safe_sidecar_path(unpack_root, &meta.output_path)?)
        .map_err(|err| {
            Error::format(format!(
                "cannot read PSB texture sidecar {}: {err}",
                meta.output_path
            ))
        })?
        .to_rgba8();
    if image.width() != meta.width || image.height() != meta.height {
        return Err(Error::format(format!(
            "PSB sidecar dimensions changed for {}: meta={}x{}, image={}x{}",
            meta.output_path,
            meta.width,
            meta.height,
            image.width(),
            image.height()
        )));
    }

    let table = ResourceTable::parse(&meta.resource_table)?;
    let old_blob = resource(resources, extra, table, meta.resource_index)?.to_vec();
    let full_width = meta.full_width.unwrap_or(meta.width);
    let full_height = meta.full_height.unwrap_or(meta.height);
    let semantic = meta.semantic.as_deref().unwrap_or("embedded-image");

    let new_blob = match semantic {
        "generic-bitmap" => {
            if let (Some(pal_table), Some(pal_index)) =
                (&meta.palette_resource_table, meta.palette_resource_index)
            {
                let pal_table = ResourceTable::parse(pal_table)?;
                let palette = resource(resources, extra, pal_table, pal_index)?.to_vec();
                let expected = (full_width as usize)
                    .checked_mul(full_height as usize)
                    .ok_or_else(|| Error::unsupported("PSB indexed texture dimensions overflow"))?;
                let raw = if uses_rl(meta.compress.as_deref()) {
                    decode_rl(&old_blob, 1, expected)?
                } else {
                    old_blob
                };
                let (indices, palette) =
                    overlay_indexed8(&raw, &palette, &image, full_width, full_height, allow_lossy)?;
                replace_resource(resources, extra, pal_table, pal_index, palette)?;
                if uses_rl(meta.compress.as_deref()) {
                    encode_rl(&indices, 1)?
                } else {
                    indices
                }
            } else {
                let expected = (full_width as usize)
                    .checked_mul(full_height as usize)
                    .and_then(|n| n.checked_mul(4))
                    .ok_or_else(|| Error::unsupported("PSB texture dimensions overflow"))?;
                let raw = if uses_rl(meta.compress.as_deref()) {
                    decode_rl(&old_blob, 4, expected)?
                } else {
                    old_blob
                };
                let raw = overlay_raw32(
                    &raw,
                    &image,
                    full_width,
                    full_height,
                    Raw32Order::Bgra,
                    allow_lossy,
                )?;
                if uses_rl(meta.compress.as_deref()) {
                    encode_rl(&raw, 4)?
                } else {
                    raw
                }
            }
        }
        "emote-texture" | "emote-schema-fallback" => {
            let format = meta.source_format.as_deref().unwrap_or("RGBA8");
            if format.eq_ignore_ascii_case("RGBA4444") {
                let expected = (full_width as usize)
                    .checked_mul(full_height as usize)
                    .and_then(|n| n.checked_mul(2))
                    .ok_or_else(|| Error::unsupported("PSB RGBA4444 dimensions overflow"))?;
                let raw = if uses_rl(meta.compress.as_deref()) {
                    decode_rl(&old_blob, 2, expected)?
                } else {
                    old_blob
                };
                let raw = overlay_rgba4444(&raw, &image, full_width, full_height)?;
                if uses_rl(meta.compress.as_deref()) {
                    encode_rl(&raw, 2)?
                } else {
                    raw
                }
            } else {
                let expected = (full_width as usize)
                    .checked_mul(full_height as usize)
                    .and_then(|n| n.checked_mul(4))
                    .ok_or_else(|| Error::unsupported("PSB texture dimensions overflow"))?;
                let raw = if uses_rl(meta.compress.as_deref()) {
                    decode_rl(&old_blob, 4, expected)?
                } else {
                    old_blob
                };
                let raw = overlay_raw32(
                    &raw,
                    &image,
                    full_width,
                    full_height,
                    raw32_order(meta.source_format.as_deref(), meta.spec.as_deref()),
                    allow_lossy,
                )?;
                if uses_rl(meta.compress.as_deref()) {
                    encode_rl(&raw, 4)?
                } else {
                    raw
                }
            }
        }
        "embedded-image" => encode_self_describing_image(
            &image,
            meta.source_format.as_deref().unwrap_or(&meta.output_format),
            allow_lossy,
        )?,
        other => {
            if let Some(format) = meta.source_format.as_deref() {
                encode_self_describing_image(&image, format, allow_lossy)?
            } else {
                return Err(Error::unsupported(format!(
                    "PSB resource {}:{} has image sidecar but unsupported semantic {other:?}",
                    meta.resource_table, meta.resource_index
                )));
            }
        }
    };
    replace_resource(resources, extra, table, meta.resource_index, new_blob)
}

fn write_plain_psb(
    version: u16,
    root: &RoundtripPsbValue,
    resources: &[Vec<u8>],
    extra: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = PsbWriter::new(version, false, root, &mut cursor)
            .map_err(|err| Error::format(format!("PSB serialization failed: {err}")))?;
        for bytes in resources {
            writer.add_resource(Cursor::new(bytes.clone()))?;
        }
        if version >= 4 {
            for bytes in extra {
                writer.add_extra(Cursor::new(bytes.clone()))?;
            }
        } else if !extra.is_empty() {
            return Err(Error::unsupported(format!(
                "PSB v{version} cannot contain extra resources"
            )));
        }
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

#[cfg(test)]
pub(crate) fn test_psb_resource_fixture(resource: &[u8]) -> Vec<u8> {
    let root = RoundtripPsbValue::Object(vec![
        (
            "kind".to_string(),
            RoundtripPsbValue::String("xp3-full-chain".to_string()),
        ),
        ("payload".to_string(), RoundtripPsbValue::Resource(0)),
    ]);
    write_plain_psb(4, &root, &[resource.to_vec()], &[]).unwrap()
}

#[derive(Clone, Debug)]
struct PsbCipher {
    state: [u32; 5],
}

impl PsbCipher {
    fn new(private_key: u32) -> Self {
        Self {
            state: [0x075BCD15, 0x159A55E5, 0x1F123BB5, private_key, 0],
        }
    }

    fn apply(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            if self.state[4] == 0 {
                let v5 = self.state[3];
                let v6 = self.state[0] ^ self.state[0].wrapping_shl(11);
                self.state[0] = self.state[1];
                self.state[1] = self.state[2];
                let eax = v6 ^ v5 ^ ((v6 ^ (v5 >> 11)) >> 8);
                self.state[2] = v5;
                self.state[3] = eax;
                self.state[4] = eax;
            }
            *byte ^= self.state[4] as u8;
            self.state[4] >>= 8;
        }
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| Error::format("truncated PSB header"))?;
    Ok(u16::from_le_bytes(raw.try_into().unwrap()))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::format("truncated PSB header"))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn encrypt_psb(mut bytes: Vec<u8>, key: u32, mut flags: u16) -> Result<Vec<u8>> {
    let version = read_u16_le(&bytes, 4)?;
    if flags & 0x0003 == 0 {
        // Some old v2 data relies on implicit body encryption.  Emit the body
        // bit explicitly so a rebuilt file is unambiguous to modern readers.
        flags = 0x0002;
    }
    bytes
        .get_mut(6..8)
        .ok_or_else(|| Error::format("truncated PSB flags"))?
        .copy_from_slice(&flags.to_le_bytes());

    let name_offset = read_u32_le(&bytes, 12)? as usize;
    let resource_offset = read_u32_le(&bytes, 24)? as usize;
    let mut cipher = PsbCipher::new(key);
    if flags & 0x0001 != 0 {
        let header_len = if version <= 2 { 0x20usize } else { 0x24usize };
        let end = 8usize
            .checked_add(header_len)
            .ok_or_else(|| Error::format("PSB header encryption overflow"))?;
        let region = bytes
            .get_mut(8..end)
            .ok_or_else(|| Error::format("truncated PSB encrypted header"))?;
        cipher.apply(region);
    }
    if flags & 0x0002 != 0 {
        if name_offset > resource_offset || resource_offset > bytes.len() {
            return Err(Error::format("invalid PSB body encryption offsets"));
        }
        cipher.apply(&mut bytes[name_offset..resource_offset]);
    }
    Ok(bytes)
}

fn wrap_source(bytes: &[u8], wrapper: &str) -> Result<Vec<u8>> {
    match wrapper {
        "raw-psb" => Ok(bytes.to_vec()),
        "mdf" => {
            let size = u32::try_from(bytes.len())
                .map_err(|_| Error::unsupported("PSB too large for MDF u32 size"))?;
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(bytes)?;
            let compressed = encoder.finish()?;
            let mut out = Vec::with_capacity(compressed.len() + 8);
            out.extend_from_slice(b"mdf\0");
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&compressed);
            Ok(out)
        }
        "lz4-frame" => {
            let mut encoder = FrameEncoder::new(Vec::new());
            encoder.write_all(bytes)?;
            encoder
                .finish()
                .map_err(|err| Error::format(format!("LZ4 frame encode failed: {err}")))
        }
        other => Err(Error::unsupported(format!(
            "cannot restore unknown PSB wrapper {other:?}"
        ))),
    }
}

/// Rebuild a PSB/SCN/MTN/PIMG asset from its manifest group.
pub fn rebuild_psb_from_transforms(
    unpack_root: &Path,
    input: PsbRebuildInput<'_>,
) -> Result<Vec<u8>> {
    let source_path = safe_sidecar_path(unpack_root, &input.source.source_binary_path)?;
    let source_bytes = fs::read(&source_path)?;
    if source_bytes.len() != input.source.source_size {
        return Err(Error::format(format!(
            "retained PSB rebuild template size changed for {}: manifest={} actual={}",
            input.source.source_binary_path,
            input.source.source_size,
            source_bytes.len()
        )));
    }
    let source_hash = sha256_hex(&source_bytes);
    if !source_hash.eq_ignore_ascii_case(&input.source.source_sha256) {
        return Err(Error::format(format!(
            "retained PSB rebuild template hash changed for {}: manifest={} actual={}",
            input.source.source_binary_path, input.source.source_sha256, source_hash
        )));
    }
    let key = match input.emote_key {
        Some(key) => Some(key),
        None => key_from_source(input.source)?,
    };
    if input.source.encrypted_input && key.is_none() {
        return Err(Error::unsupported(format!(
            "encrypted PSB {} has no Emote key in its transform/global manifest keys",
            input.source.source_binary_path
        )));
    }
    let decoded = decode_psb_with_key(&source_bytes, key)
        .map_err(|err| {
            Error::format(format!(
                "cannot decode PSB rebuild template {}: {err}",
                source_path.display()
            ))
        })?
        .ok_or_else(|| {
            Error::format(format!(
                "{} is not a PSB-family asset",
                source_path.display()
            ))
        })?;

    let mut resources = (0..decoded.psb.resources.len())
        .map(|index| {
            decoded
                .psb
                .resource_bytes(&decoded.normalized, index)
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::format(format!("cannot read PSB resource {index}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut extra = decoded.extra_resource_blobs.clone();

    // Raw resource sidecars are the lowest-level authoritative edit. Texture
    // sidecars are applied afterwards so an edited PNG wins if both exist.
    for meta in &input.raw_blobs {
        let bytes = fs::read(safe_sidecar_path(unpack_root, &meta.output_path)?)?;
        replace_resource(
            &mut resources,
            &mut extra,
            ResourceTable::parse(&meta.resource_table)?,
            meta.resource_index,
            bytes,
        )?;
    }
    for meta in &input.textures {
        apply_texture(
            unpack_root,
            meta,
            &mut resources,
            &mut extra,
            input.allow_lossy,
        )?;
    }

    let document = if let Some(meta) = input.root_json {
        let bytes = fs::read(safe_sidecar_path(unpack_root, &meta.output_path)?)?;
        serde_json::from_slice::<Value>(&bytes).map_err(|err| {
            Error::format(format!(
                "invalid PSB typed JSON {}: {err}",
                meta.output_path
            ))
        })?
    } else {
        psb_roundtrip_json(&decoded, Some(&source_path))
    };
    let (version, root) = root_from_document(&document)?;
    if version as u64 != input.source.psb_version {
        return Err(Error::unsupported(format!(
            "edited PSB typed JSON changes version from {} to {version}; version changes are not a round-trip edit",
            input.source.psb_version
        )));
    }
    validate_resource_refs(&root, resources.len(), extra.len())?;
    let plain = write_plain_psb(version, &root, &resources, &extra)?;

    let normalized = if input.source.encrypted_input {
        let flags = decoded.psb.header.flags;
        encrypt_psb(plain, key.unwrap(), flags)?
    } else {
        plain
    };
    wrap_source(&normalized, &input.source.wrapper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::psb::{decode_psb_with_key, psb_value_to_roundtrip_json};
    use crate::xp3_meta::PsbResourceBlobTransformMeta;
    use serde_json::json;

    #[test]
    fn typed_json_preserves_float_bits_and_order() {
        let value = json!({
            "$type":"object",
            "entries":[
                {"key":"b","value":{"$type":"float","bits":"0x80000000","display":"-0"}},
                {"key":"a","value":{"$type":"resource","index":3}}
            ]
        });
        let parsed = parse_typed_value(&value).unwrap();
        match parsed {
            RoundtripPsbValue::Object(entries) => {
                assert_eq!(entries[0].0, "b");
                assert_eq!(entries[1].0, "a");
                match entries[0].1 {
                    RoundtripPsbValue::Float(v) => assert_eq!(v.to_bits(), 0x80000000),
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn resource_reference_validation_rejects_out_of_range() {
        let root =
            RoundtripPsbValue::Object(vec![("pixel".to_string(), RoundtripPsbValue::Resource(2))]);
        assert!(validate_resource_refs(&root, 2, 0).is_err());
        assert!(validate_resource_refs(&root, 3, 0).is_ok());
    }

    #[test]
    fn rl_roundtrip() {
        let src = vec![1u8, 1, 1, 1, 2, 3, 4, 4, 4, 7, 8];
        let encoded = encode_rl(&src, 1).unwrap();
        assert_eq!(decode_rl(&encoded, 1, src.len()).unwrap(), src);
    }

    #[test]
    fn modified_resource_blob_rebuilds_and_reparses_with_stable_index() {
        let root_dir =
            std::env::temp_dir().join(format!("xp3-psb-modified-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).unwrap();
        let root = RoundtripPsbValue::Object(vec![
            (
                "name".to_string(),
                RoundtripPsbValue::String("sample".to_string()),
            ),
            ("payload".to_string(), RoundtripPsbValue::Resource(0)),
        ]);
        let original_resource = b"original-resource".to_vec();
        let source_bytes = write_plain_psb(4, &root, &[original_resource.clone()], &[]).unwrap();
        fs::write(root_dir.join("scene.scn"), &source_bytes).unwrap();
        let decoded_source = decode_psb_with_key(&source_bytes, None).unwrap().unwrap();
        let source = PsbSourceMeta {
            source_binary_path: "scene.scn".to_string(),
            source_size: source_bytes.len(),
            source_sha256: sha256_hex(&source_bytes),
            normalized_size: decoded_source.normalized.len(),
            normalized_sha256: sha256_hex(&decoded_source.normalized),
            wrapper: "raw-psb".to_string(),
            psb_version: 4,
            encrypted_input: false,
            emote_key_hex: None,
        };
        let modified_resource = b"modified-resource-2026".to_vec();
        fs::write(root_dir.join("resource-0.bin"), &modified_resource).unwrap();
        let blob = PsbResourceBlobTransformMeta {
            source: source.clone(),
            output_path: "resource-0.bin".to_string(),
            source_binary_retained: true,
            resource_table: "resource".to_string(),
            resource_index: 0,
            blob_size: original_resource.len(),
            blob_sha256: sha256_hex(&original_resource),
            semantic_candidate: None,
            object_path: Some("/payload".to_string()),
            full_width: None,
            full_height: None,
            palette_resource_table: None,
            palette_resource_index: None,
            decode_error: None,
        };
        let rebuilt = rebuild_psb_from_transforms(
            &root_dir,
            PsbRebuildInput {
                source: &source,
                root_json: None,
                textures: Vec::new(),
                raw_blobs: vec![&blob],
                emote_key: None,
                allow_lossy: false,
            },
        )
        .unwrap();
        let decoded = decode_psb_with_key(&rebuilt, None).unwrap().unwrap();
        assert_eq!(decoded.psb.version, 4);
        assert_eq!(
            decoded.psb.resource_bytes(&decoded.normalized, 0).unwrap(),
            modified_resource
        );
        assert_eq!(
            psb_value_to_roundtrip_json(&decoded_source.psb.root),
            psb_value_to_roundtrip_json(&decoded.psb.root)
        );
        fs::remove_dir_all(root_dir).unwrap();
    }

    #[test]
    fn psb_family_wrappers_encryption_and_subtype_paths_rebuild_semantically() {
        let root_dir = std::env::temp_dir().join(format!(
            "xp3-psb-family-roundtrip-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).unwrap();

        let root = RoundtripPsbValue::Object(vec![
            (
                "kind".to_string(),
                RoundtripPsbValue::String("roundtrip".to_string()),
            ),
            (
                "ordered".to_string(),
                RoundtripPsbValue::List(vec![
                    RoundtripPsbValue::Int(7),
                    RoundtripPsbValue::Resource(0),
                ]),
            ),
        ]);
        let resource = b"stable-resource-identity".to_vec();
        let plain = write_plain_psb(4, &root, std::slice::from_ref(&resource), &[]).unwrap();
        let key = 0x1357_9bdf;

        for (extension, wrapper, encrypted) in [
            ("psb", "raw-psb", false),
            ("scn", "mdf", true),
            ("mtn", "lz4-frame", true),
            ("pimg", "raw-psb", true),
        ] {
            let normalized = if encrypted {
                encrypt_psb(plain.clone(), key, 0x0003).unwrap()
            } else {
                plain.clone()
            };
            let source_bytes = wrap_source(&normalized, wrapper).unwrap();
            let relative = format!("asset.{extension}");
            fs::write(root_dir.join(&relative), &source_bytes).unwrap();
            let decoded_source = decode_psb_with_key(&source_bytes, encrypted.then_some(key))
                .unwrap()
                .unwrap();
            assert_eq!(decoded_source.psb.encrypted, encrypted);

            let source = PsbSourceMeta {
                source_binary_path: relative.clone(),
                source_size: source_bytes.len(),
                source_sha256: sha256_hex(&source_bytes),
                normalized_size: decoded_source.normalized.len(),
                normalized_sha256: sha256_hex(&decoded_source.normalized),
                wrapper: wrapper.to_string(),
                psb_version: 4,
                encrypted_input: encrypted,
                emote_key_hex: encrypted.then(|| format!("0x{key:08x}")),
            };
            let rebuilt = rebuild_psb_from_transforms(
                &root_dir,
                PsbRebuildInput {
                    source: &source,
                    root_json: None,
                    textures: Vec::new(),
                    raw_blobs: Vec::new(),
                    emote_key: None,
                    allow_lossy: false,
                },
            )
            .unwrap();
            let decoded_rebuilt = decode_psb_with_key(&rebuilt, encrypted.then_some(key))
                .unwrap()
                .unwrap();

            assert_eq!(decoded_rebuilt.psb.version, decoded_source.psb.version);
            assert_eq!(decoded_rebuilt.psb.encrypted, encrypted);
            assert_eq!(
                psb_value_to_roundtrip_json(&decoded_rebuilt.psb.root),
                psb_value_to_roundtrip_json(&decoded_source.psb.root)
            );
            assert_eq!(
                decoded_rebuilt
                    .psb
                    .resource_bytes(&decoded_rebuilt.normalized, 0)
                    .unwrap(),
                resource
            );
            match wrapper {
                "raw-psb" => assert!(rebuilt.starts_with(b"PSB\0")),
                "mdf" => assert!(rebuilt.starts_with(b"mdf\0")),
                "lz4-frame" => assert!(rebuilt.starts_with(&[0x04, 0x22, 0x4d, 0x18])),
                _ => unreachable!(),
            }
        }

        fs::remove_dir_all(root_dir).unwrap();
    }

    #[test]
    fn encrypted_emote_texture_edit_restores_wrapper_key_pixels_and_root() {
        let root_dir = std::env::temp_dir().join(format!(
            "xp3-emote-texture-roundtrip-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).unwrap();

        let root = RoundtripPsbValue::Object(vec![
            (
                "animation".to_string(),
                RoundtripPsbValue::List(vec![
                    RoundtripPsbValue::Int(12),
                    RoundtripPsbValue::String("loop".to_string()),
                ]),
            ),
            ("pixel".to_string(), RoundtripPsbValue::Resource(0)),
        ]);
        let old_bgra = vec![0u8; 2 * 2 * 4];
        let plain = write_plain_psb(4, &root, &[old_bgra], &[]).unwrap();
        let key = 0x2468_ace0;
        let encrypted = encrypt_psb(plain, key, 0x0003).unwrap();
        let source_bytes = wrap_source(&encrypted, "mdf").unwrap();
        fs::write(root_dir.join("motion.mtn"), &source_bytes).unwrap();
        let decoded_source = decode_psb_with_key(&source_bytes, Some(key))
            .unwrap()
            .unwrap();
        let source = PsbSourceMeta {
            source_binary_path: "motion.mtn".to_string(),
            source_size: source_bytes.len(),
            source_sha256: sha256_hex(&source_bytes),
            normalized_size: decoded_source.normalized.len(),
            normalized_sha256: sha256_hex(&decoded_source.normalized),
            wrapper: "mdf".to_string(),
            psb_version: 4,
            encrypted_input: true,
            emote_key_hex: Some(format!("0x{key:08x}")),
        };

        let edited = RgbaImage::from_fn(2, 2, |x, y| {
            image::Rgba([
                10 + x as u8,
                20 + y as u8,
                30 + (x + y) as u8,
                200 + x as u8,
            ])
        });
        edited.save(root_dir.join("texture.png")).unwrap();
        let texture = PsbTextureTransformMeta {
            source: source.clone(),
            output_path: "texture.png".to_string(),
            output_sha256: None,
            output_format: "png".to_string(),
            lossless_pixels: true,
            source_binary_retained: true,
            resource_table: "resource".to_string(),
            resource_index: 0,
            name: "texture".to_string(),
            width: 2,
            height: 2,
            semantic: Some("emote-texture".to_string()),
            object_path: Some("/pixel".to_string()),
            full_width: Some(2),
            full_height: Some(2),
            palette_resource_table: None,
            palette_resource_index: None,
            source_format: Some("RGBA8".to_string()),
            compress: None,
            bit_count: Some(32),
            spec: Some("win".to_string()),
            emote_key_hex: Some(format!("0x{key:08x}")),
        };
        let rebuilt = rebuild_psb_from_transforms(
            &root_dir,
            PsbRebuildInput {
                source: &source,
                root_json: None,
                textures: vec![&texture],
                raw_blobs: Vec::new(),
                emote_key: None,
                allow_lossy: false,
            },
        )
        .unwrap();
        assert!(rebuilt.starts_with(b"mdf\0"));
        let decoded_rebuilt = decode_psb_with_key(&rebuilt, Some(key)).unwrap().unwrap();
        assert!(decoded_rebuilt.psb.encrypted);
        assert_eq!(
            psb_value_to_roundtrip_json(&decoded_rebuilt.psb.root),
            psb_value_to_roundtrip_json(&decoded_source.psb.root)
        );
        let expected_bgra = edited
            .pixels()
            .flat_map(|pixel| {
                let [r, g, b, a] = pixel.0;
                [b, g, r, a]
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decoded_rebuilt
                .psb
                .resource_bytes(&decoded_rebuilt.normalized, 0),
            Some(expected_bgra.as_slice())
        );

        fs::remove_dir_all(root_dir).unwrap();
    }
}
