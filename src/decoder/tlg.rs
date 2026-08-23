//! KiriKiri TLG5/TLG6 image decoding and TLG0 structured-data containers.
//!
//! KiriKiri accepts three on-disk forms:
//! - raw `TLG5.0\0raw\x1a`
//! - raw `TLG6.0\0raw\x1a`
//! - `TLG0.0\0sds\x1a`, a structured-data container containing one raw TLG
//!   stream followed by named chunks.  The standard `tags` chunk stores
//!   UTF-8 metadata in KiriKiri's length-prefixed `NAME=VALUE,` syntax.
//!
//! The raw TLG codec is delegated to the pure-Rust `tlg-rs` decoder.  The TLG0
//! wrapper is parsed here instead of through `tlg-rs::TlgReader` so unknown
//! chunks are preserved in the inspection result and malformed/truncated
//! containers fail deterministically.

use crate::{Error, Result};
use image::{ColorType, ImageFormat};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tlg::tlg5::Tlg5Decoder;
use tlg::tlg6::Tlg6Decoder;
use tlg::tlg_type::{PixelLayout, TlgDecoderTrait};

pub const TLG0_MAGIC: &[u8; 11] = b"TLG0.0\0sds\x1a";
pub const TLG5_MAGIC: &[u8; 11] = b"TLG5.0\0raw\x1a";
pub const TLG6_MAGIC: &[u8; 11] = b"TLG6.0\0raw\x1a";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlgVersion {
    Tlg5,
    Tlg6,
}

impl TlgVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tlg5 => "TLG5",
            Self::Tlg6 => "TLG6",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlgContainerChunk {
    /// Four-byte chunk identifier, rendered losslessly where possible.
    pub name: String,
    /// Offset of the chunk payload in the original TLG0 file.
    pub data_offset: usize,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlgContainerInfo {
    pub raw_offset: usize,
    pub raw_size: u32,
    pub chunks: Vec<TlgContainerChunk>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlgCodecInfo {
    Tlg5 {
        block_height: u32,
    },
    Tlg6 {
        data_flag: u8,
        color_type: u8,
        external_golomb_table: u8,
        max_bit_length: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlgInfo {
    pub version: TlgVersion,
    pub width: u32,
    pub height: u32,
    pub components: u8,
    /// Header parameters required by a future encoder. These values are kept
    /// even when `unpack --tlg` replaces the original TLG with PNG/JPEG/BMP.
    pub codec: TlgCodecInfo,
    pub container: Option<TlgContainerInfo>,
}

#[derive(Clone, Debug)]
pub struct DecodedTlg {
    pub info: TlgInfo,
    /// Canonical straight-alpha RGBA8 pixels, row-major, top-to-bottom.
    pub rgba: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlgExportFormat {
    Png,
    Jpeg,
    Bmp,
}

impl TlgExportFormat {
    pub fn from_extension(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "png" => Some(Self::Png),
            "jpg" | "jpeg" => Some(Self::Jpeg),
            "bmp" => Some(Self::Bmp),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Bmp => "bmp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlgExportOptions {
    pub format: TlgExportFormat,
    /// JPEG encoder quality. Ignored for PNG/BMP.
    pub jpeg_quality: u8,
}

impl Default for TlgExportOptions {
    fn default() -> Self {
        Self {
            format: TlgExportFormat::Png,
            jpeg_quality: 95,
        }
    }
}

struct RawView<'a> {
    raw: &'a [u8],
    version: TlgVersion,
    container: Option<TlgContainerInfo>,
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::format("TLG offset overflow"))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::format("truncated TLG u32"))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn checked_end(start: usize, len: usize, total: usize, what: &str) -> Result<usize> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::format(format!("{what} length overflow")))?;
    if end > total {
        return Err(Error::format(format!("truncated {what}")));
    }
    Ok(end)
}

fn chunk_name(bytes: &[u8; 4]) -> String {
    if bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
    }
}

fn raw_version(raw: &[u8]) -> Result<TlgVersion> {
    if raw.starts_with(TLG5_MAGIC) {
        Ok(TlgVersion::Tlg5)
    } else if raw.starts_with(TLG6_MAGIC) {
        Ok(TlgVersion::Tlg6)
    } else {
        Err(Error::format("TLG raw stream is neither TLG5 nor TLG6"))
    }
}

fn parse_decimal_len(data: &[u8], pos: &mut usize, label: &str) -> Result<usize> {
    let start = *pos;
    let mut value = 0usize;
    while let Some(&b) = data.get(*pos) {
        if !b.is_ascii_digit() {
            break;
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as usize))
            .ok_or_else(|| Error::format(format!("TLG0 tags {label} length overflow")))?;
        *pos += 1;
    }
    if *pos == start || data.get(*pos) != Some(&b':') {
        return Err(Error::format(format!("malformed TLG0 tags {label} length")));
    }
    *pos += 1;
    Ok(value)
}

/// Parse KiriKiri's `tags` payload exactly by byte length.
///
/// Both names and values are UTF-8. Lengths are byte lengths rather than Rust
/// character counts, which matters for Japanese metadata.
pub fn parse_tlg0_tags(data: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut tags = BTreeMap::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let name_len = parse_decimal_len(data, &mut pos, "name")?;
        let name_end = checked_end(pos, name_len, data.len(), "TLG0 tag name")?;
        let name = std::str::from_utf8(&data[pos..name_end])
            .map_err(|_| Error::format("TLG0 tag name is not UTF-8"))?
            .to_owned();
        pos = name_end;
        if data.get(pos) != Some(&b'=') {
            return Err(Error::format("malformed TLG0 tags: missing '='"));
        }
        pos += 1;

        let value_len = parse_decimal_len(data, &mut pos, "value")?;
        let value_end = checked_end(pos, value_len, data.len(), "TLG0 tag value")?;
        let value = std::str::from_utf8(&data[pos..value_end])
            .map_err(|_| Error::format("TLG0 tag value is not UTF-8"))?
            .to_owned();
        pos = value_end;
        if data.get(pos) != Some(&b',') {
            return Err(Error::format("malformed TLG0 tags: missing trailing ','"));
        }
        pos += 1;
        tags.insert(name, value);
    }
    Ok(tags)
}

fn split_stream(bytes: &[u8]) -> Result<RawView<'_>> {
    if bytes.starts_with(TLG5_MAGIC) || bytes.starts_with(TLG6_MAGIC) {
        return Ok(RawView {
            raw: bytes,
            version: raw_version(bytes)?,
            container: None,
        });
    }

    if !bytes.starts_with(TLG0_MAGIC) {
        return Err(Error::format("not a TLG0/TLG5/TLG6 stream"));
    }
    if bytes.len() < 15 {
        return Err(Error::format("truncated TLG0 header"));
    }

    let raw_size = read_u32_le(bytes, 11)?;
    let raw_offset = 15usize;
    let raw_end = checked_end(
        raw_offset,
        raw_size as usize,
        bytes.len(),
        "TLG0 raw stream",
    )?;
    let raw = &bytes[raw_offset..raw_end];
    let version = raw_version(raw)?;

    let mut chunks = Vec::new();
    let mut tags = BTreeMap::new();
    let mut pos = raw_end;
    while pos < bytes.len() {
        // KiriKiri's loader simply stops if it cannot read another 4-byte
        // chunk name, so tolerate a short trailer but never a partial header
        // after a complete name.
        if bytes.len() - pos < 4 {
            break;
        }
        let name_raw: [u8; 4] = bytes[pos..pos + 4].try_into().unwrap();
        pos += 4;
        if bytes.len() - pos < 4 {
            return Err(Error::format("truncated TLG0 chunk size"));
        }
        let size = read_u32_le(bytes, pos)?;
        pos += 4;
        let data_offset = pos;
        let data_end = checked_end(pos, size as usize, bytes.len(), "TLG0 chunk payload")?;

        if &name_raw == b"tags" {
            for (key, value) in parse_tlg0_tags(&bytes[pos..data_end])? {
                tags.insert(key, value);
            }
        }
        chunks.push(TlgContainerChunk {
            name: chunk_name(&name_raw),
            data_offset,
            size,
        });
        pos = data_end;
    }

    Ok(RawView {
        raw,
        version,
        container: Some(TlgContainerInfo {
            raw_offset,
            raw_size,
            chunks,
            tags,
        }),
    })
}

fn raw_header_info(raw: &[u8], version: TlgVersion) -> Result<(u32, u32, u8, TlgCodecInfo)> {
    match version {
        TlgVersion::Tlg5 => {
            // magic[11], colors[1], width[4], height[4], blockheight[4]
            if raw.len() < 24 {
                return Err(Error::format("truncated TLG5 header"));
            }
            let components = raw[11];
            if !matches!(components, 3 | 4) {
                return Err(Error::format(format!(
                    "unsupported TLG5 component count {components}"
                )));
            }
            let block_height = read_u32_le(raw, 20)?;
            Ok((
                read_u32_le(raw, 12)?,
                read_u32_le(raw, 16)?,
                components,
                TlgCodecInfo::Tlg5 { block_height },
            ))
        }
        TlgVersion::Tlg6 => {
            // magic[11], colors/data-flag/color-type/golomb-table[4], width/height
            if raw.len() < 27 {
                return Err(Error::format("truncated TLG6 header"));
            }
            let components = raw[11];
            if !matches!(components, 1 | 3 | 4) {
                return Err(Error::format(format!(
                    "unsupported TLG6 component count {components}"
                )));
            }
            if raw[12..15] != [0, 0, 0] {
                return Err(Error::unsupported(format!(
                    "TLG6 control flags are not supported: data={} color_type={} external_golomb={}",
                    raw[12], raw[13], raw[14]
                )));
            }
            let max_bit_length = read_u32_le(raw, 23)?;
            Ok((
                read_u32_le(raw, 15)?,
                read_u32_le(raw, 19)?,
                components,
                TlgCodecInfo::Tlg6 {
                    data_flag: raw[12],
                    color_type: raw[13],
                    external_golomb_table: raw[14],
                    max_bit_length,
                },
            ))
        }
    }
}

/// Inspect the TLG header/container without entropy-decoding pixel data.
pub fn inspect_tlg(bytes: &[u8]) -> Result<TlgInfo> {
    let view = split_stream(bytes)?;
    let (width, height, components, codec) = raw_header_info(view.raw, view.version)?;
    if width == 0 || height == 0 {
        return Err(Error::format("TLG dimensions must be non-zero"));
    }
    Ok(TlgInfo {
        version: view.version,
        width,
        height,
        components,
        codec,
        container: view.container,
    })
}

fn expected_len(width: u32, height: u32, channels: usize) -> Result<usize> {
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(channels))
        .ok_or_else(|| Error::format("decoded TLG dimensions overflow address space"))
}

fn pixels_to_rgba(
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    layout: PixelLayout,
) -> Result<Vec<u8>> {
    let count = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| Error::format("decoded TLG dimensions overflow address space"))?;
    let mut rgba = Vec::with_capacity(
        count
            .checked_mul(4)
            .ok_or_else(|| Error::format("decoded TLG RGBA size overflow"))?,
    );

    match layout {
        PixelLayout::Rgba => {
            if pixels.len() != expected_len(width, height, 4)? {
                return Err(Error::format(format!(
                    "TLG decoder returned {} RGBA bytes, expected {}",
                    pixels.len(),
                    expected_len(width, height, 4)?
                )));
            }
            return Ok(pixels);
        }
        PixelLayout::Rgb => {
            if pixels.len() != expected_len(width, height, 3)? {
                return Err(Error::format("TLG decoder returned invalid RGB byte count"));
            }
            for pixel in pixels.chunks_exact(3) {
                rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 0xff]);
            }
        }
        PixelLayout::Gray => {
            // tlg-rs currently materializes TLG6 one-component images as RGB
            // in its image-facing reader. Accept that canonical representation,
            // while also accepting a true one-byte grayscale buffer so the
            // wrapper remains compatible with future decoder changes.
            if pixels.len() == expected_len(width, height, 3)? {
                for pixel in pixels.chunks_exact(3) {
                    rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 0xff]);
                }
            } else if pixels.len() == expected_len(width, height, 1)? {
                for &gray in &pixels {
                    rgba.extend_from_slice(&[gray, gray, gray, 0xff]);
                }
            } else {
                return Err(Error::format(
                    "TLG decoder returned invalid grayscale byte count",
                ));
            }
        }
    }
    Ok(rgba)
}

/// Decode raw TLG5/TLG6 or a TLG0/SDS container to canonical RGBA8 pixels.
pub fn decode_tlg(bytes: &[u8]) -> Result<DecodedTlg> {
    let view = split_stream(bytes)?;
    let container = view.container.clone();
    let version = view.version;
    let (header_width, header_height, components, codec) = raw_header_info(view.raw, version)?;
    if header_width == 0 || header_height == 0 {
        return Err(Error::format("TLG dimensions must be non-zero"));
    }
    // Reject arithmetic-overflow dimensions before handing them to the codec.
    let _ = expected_len(header_width, header_height, 4)?;

    // `tlg-rs 0.1.1`'s aggregate TlgReader consumes the raw magic while
    // selecting a decoder and then passes the stream after that magic to a
    // decoder which expects to read it again. Invoke the concrete decoder on
    // the complete raw stream instead.
    let decoded = match version {
        TlgVersion::Tlg5 => {
            Tlg5Decoder::from_data(view.raw.to_vec()).and_then(TlgDecoderTrait::decode)
        }
        TlgVersion::Tlg6 => {
            Tlg6Decoder::from_data(view.raw.to_vec()).and_then(TlgDecoderTrait::decode)
        }
    };
    let (pixels, decoded_info) = decoded
        .map_err(|err| Error::format(format!("{} decode failed: {err}", version.as_str())))?;

    if decoded_info.width != header_width || decoded_info.height != header_height {
        return Err(Error::format(format!(
            "{} decoded dimensions {}x{} disagree with header {}x{}",
            version.as_str(),
            decoded_info.width,
            decoded_info.height,
            header_width,
            header_height
        )));
    }

    let rgba = pixels_to_rgba(
        pixels,
        decoded_info.width,
        decoded_info.height,
        decoded_info.pixel_layout,
    )?;
    Ok(DecodedTlg {
        info: TlgInfo {
            version,
            width: decoded_info.width,
            height: decoded_info.height,
            components,
            codec,
            container,
        },
        rgba,
    })
}

pub fn decode_tlg_file(path: impl AsRef<Path>) -> Result<DecodedTlg> {
    let bytes = fs::read(path)?;
    decode_tlg(&bytes)
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Export decoded pixels as PNG, JPEG, or BMP.
///
/// PNG and BMP retain the alpha channel. JPEG has no alpha channel, so its
/// alpha byte is dropped without compositing; the original RGB samples are
/// retained verbatim before lossy JPEG encoding.
pub fn export_decoded_tlg(
    decoded: &DecodedTlg,
    output: impl AsRef<Path>,
    options: TlgExportOptions,
) -> Result<()> {
    let output = output.as_ref();
    ensure_parent(output)?;
    if !(1..=100).contains(&options.jpeg_quality) {
        return Err(Error::invalid("JPEG quality must be in 1..=100"));
    }

    let expected = expected_len(decoded.info.width, decoded.info.height, 4)?;
    if decoded.rgba.len() != expected {
        return Err(Error::format("decoded TLG RGBA buffer has invalid length"));
    }

    match options.format {
        TlgExportFormat::Png => image::save_buffer_with_format(
            output,
            &decoded.rgba,
            decoded.info.width,
            decoded.info.height,
            ColorType::Rgba8,
            ImageFormat::Png,
        )
        .map_err(|err| Error::format(format!("PNG encode failed: {err}")))?,
        TlgExportFormat::Bmp => image::save_buffer_with_format(
            output,
            &decoded.rgba,
            decoded.info.width,
            decoded.info.height,
            ColorType::Rgba8,
            ImageFormat::Bmp,
        )
        .map_err(|err| Error::format(format!("BMP encode failed: {err}")))?,
        TlgExportFormat::Jpeg => {
            let pixel_count = (decoded.info.width as usize)
                .checked_mul(decoded.info.height as usize)
                .ok_or_else(|| Error::format("JPEG pixel count overflow"))?;
            let mut rgb = Vec::with_capacity(pixel_count * 3);
            for pixel in decoded.rgba.chunks_exact(4) {
                rgb.extend_from_slice(&pixel[..3]);
            }
            let file = File::create(output)?;
            let mut writer = BufWriter::new(file);
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
                &mut writer,
                options.jpeg_quality,
            );
            encoder
                .encode(
                    &rgb,
                    decoded.info.width,
                    decoded.info.height,
                    ColorType::Rgb8.into(),
                )
                .map_err(|err| Error::format(format!("JPEG encode failed: {err}")))?;
            drop(encoder);
            writer.flush()?;
        }
    }
    Ok(())
}

pub fn decode_tlg_to_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    options: TlgExportOptions,
) -> Result<TlgInfo> {
    let decoded = decode_tlg_file(input)?;
    export_decoded_tlg(&decoded, output, options)?;
    Ok(decoded.info)
}

/// Choose the output format from a PNG/JPG/JPEG/BMP filename.
pub fn output_options_for_path(
    path: impl AsRef<Path>,
    jpeg_quality: u8,
) -> Result<TlgExportOptions> {
    let path = path.as_ref();
    let format = TlgExportFormat::from_extension(path).ok_or_else(|| {
        Error::invalid(format!(
            "TLG output extension must be .png, .jpg/.jpeg, or .bmp: {}",
            path.display()
        ))
    })?;
    Ok(TlgExportOptions {
        format,
        jpeg_quality,
    })
}

/// Return a sibling output path with a canonical extension.
pub fn with_output_extension(path: impl AsRef<Path>, format: TlgExportFormat) -> PathBuf {
    let mut path = path.as_ref().to_path_buf();
    path.set_extension(format.extension());
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_tlg5_header(width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(TLG5_MAGIC);
        data.push(4);
        data.extend_from_slice(&width.to_le_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data
    }

    #[test]
    fn recognizes_raw_tlg5_header() {
        let data = raw_tlg5_header(640, 480);
        let info = inspect_tlg(&data).unwrap();
        assert_eq!(info.version, TlgVersion::Tlg5);
        assert_eq!((info.width, info.height, info.components), (640, 480, 4));
        assert!(info.container.is_none());
    }

    #[test]
    fn tlg0_container_preserves_unknown_chunks_and_parses_utf8_tags() {
        let raw = raw_tlg5_header(320, 200);
        let tags = "4:LEFT=2:20,6:名前=6:背景,".as_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(TLG0_MAGIC);
        data.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        data.extend_from_slice(&raw);
        data.extend_from_slice(b"tags");
        data.extend_from_slice(&(tags.len() as u32).to_le_bytes());
        data.extend_from_slice(tags);
        data.extend_from_slice(b"abcd");
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"xyz");

        let info = inspect_tlg(&data).unwrap();
        let container = info.container.unwrap();
        assert_eq!(container.raw_size as usize, raw.len());
        assert_eq!(container.chunks.len(), 2);
        assert_eq!(container.chunks[0].name, "tags");
        assert_eq!(container.chunks[1].name, "abcd");
        assert_eq!(container.tags.get("LEFT").map(String::as_str), Some("20"));
        assert_eq!(container.tags.get("名前").map(String::as_str), Some("背景"));
    }

    #[test]
    fn output_format_is_selected_by_extension() {
        assert_eq!(
            TlgExportFormat::from_extension(Path::new("a.png")),
            Some(TlgExportFormat::Png)
        );
        assert_eq!(
            TlgExportFormat::from_extension(Path::new("a.JPEG")),
            Some(TlgExportFormat::Jpeg)
        );
        assert_eq!(
            TlgExportFormat::from_extension(Path::new("a.bmp")),
            Some(TlgExportFormat::Bmp)
        );
        assert_eq!(TlgExportFormat::from_extension(Path::new("a.webp")), None);
    }
}
