//! TLG encoding and `xp3-meta.yaml` driven TLG reconstruction.
//!
//! `libtlg-rs` currently provides a TLG5 writer.  Edited TLG5 assets therefore
//! remain TLG5, while edited TLG6 assets are canonicalized to a lossless TLG5
//! stream.  If the source was wrapped in TLG0/SDS, the exact non-image chunks
//! retained in the manifest are appended around the newly encoded raw stream.

use crate::xp3_meta::{TlgContainerMeta, TlgTransformMeta};
use crate::{Error, Result};
use base64::Engine as _;
use image::RgbaImage;
use libtlg_rs::{save_tlg, Tlg, TlgColorType};
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};

const TLG0_MAGIC: &[u8; 11] = b"TLG0.0\0sds\x1a";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlgEncodeOptions {
    pub components: u8,
    pub allow_lossy: bool,
}

impl Default for TlgEncodeOptions {
    fn default() -> Self {
        Self {
            components: 4,
            allow_lossy: false,
        }
    }
}

fn libtlg_error(err: impl std::fmt::Display) -> Error {
    Error::format(format!("TLG encode failed: {err}"))
}

fn image_error(err: impl std::fmt::Display) -> Error {
    Error::format(format!("image decode/encode failed: {err}"))
}

fn rgba_to_tlg_pixels(
    image: &RgbaImage,
    options: TlgEncodeOptions,
) -> Result<(TlgColorType, Vec<u8>)> {
    let rgba = image.as_raw();
    match options.components {
        4 => {
            let mut out = Vec::with_capacity(rgba.len());
            for px in rgba.chunks_exact(4) {
                out.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
            }
            Ok((TlgColorType::Bgra32, out))
        }
        3 => {
            if !options.allow_lossy && rgba.chunks_exact(4).any(|px| px[3] != 0xff) {
                return Err(Error::unsupported(
                    "TLG BGR24 cannot preserve edited alpha; use 4 components or --allow-lossy",
                ));
            }
            let mut out =
                Vec::with_capacity((image.width() as usize) * (image.height() as usize) * 3);
            for px in rgba.chunks_exact(4) {
                out.extend_from_slice(&[px[2], px[1], px[0]]);
            }
            Ok((TlgColorType::Bgr24, out))
        }
        1 => {
            if !options.allow_lossy
                && rgba
                    .chunks_exact(4)
                    .any(|px| px[0] != px[1] || px[1] != px[2] || px[3] != 0xff)
            {
                return Err(Error::unsupported(
                    "TLG grayscale cannot preserve a non-grayscale/alpha edit; use --allow-lossy",
                ));
            }
            let mut out = Vec::with_capacity((image.width() as usize) * (image.height() as usize));
            for px in rgba.chunks_exact(4) {
                let gray = if px[0] == px[1] && px[1] == px[2] {
                    px[0]
                } else {
                    // Integer BT.601 luma. Only reached when lossy output is explicitly allowed.
                    ((77u32 * px[0] as u32 + 150u32 * px[1] as u32 + 29u32 * px[2] as u32 + 128)
                        >> 8) as u8
                };
                out.push(gray);
            }
            Ok((TlgColorType::Grayscale8, out))
        }
        other => Err(Error::invalid(format!(
            "TLG component count must be 1, 3, or 4, got {other}"
        ))),
    }
}

pub fn encode_tlg_image(image: &RgbaImage, options: TlgEncodeOptions) -> Result<Vec<u8>> {
    let (color, data) = rgba_to_tlg_pixels(image, options)?;
    let tlg = Tlg {
        tags: HashMap::new(),
        version: 5,
        width: image.width(),
        height: image.height(),
        color,
        data,
    };
    let mut cursor = Cursor::new(Vec::new());
    save_tlg(&tlg, &mut cursor).map_err(libtlg_error)?;
    Ok(cursor.into_inner())
}

pub fn encode_tlg_image_file(input: &Path, output: &Path, options: TlgEncodeOptions) -> Result<()> {
    let image = image::open(input).map_err(image_error)?.to_rgba8();
    let bytes = encode_tlg_image(&image, options)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, bytes)?;
    Ok(())
}

fn chunk_name_bytes(name: &str) -> Result<[u8; 4]> {
    let bytes = name.as_bytes();
    if bytes.len() == 4 {
        return Ok(bytes.try_into().unwrap());
    }
    if bytes.len() == 8 && bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 4];
        for i in 0..4 {
            let pair = &name[i * 2..i * 2 + 2];
            out[i] = u8::from_str_radix(pair, 16)
                .map_err(|_| Error::format(format!("invalid TLG0 chunk name {name:?}")))?;
        }
        return Ok(out);
    }
    Err(Error::format(format!(
        "TLG0 chunk name must be four bytes or eight hex digits, got {name:?}"
    )))
}

fn wrap_tlg0(raw: &[u8], container: &TlgContainerMeta) -> Result<Vec<u8>> {
    let raw_len = u32::try_from(raw.len())
        .map_err(|_| Error::unsupported("encoded TLG raw stream exceeds TLG0 u32 size field"))?;
    let mut chunks = container.chunks.clone();
    chunks.sort_by_key(|chunk| chunk.order);

    let mut out = Vec::with_capacity(raw.len().saturating_add(64));
    out.extend_from_slice(TLG0_MAGIC);
    out.extend_from_slice(&raw_len.to_le_bytes());
    out.extend_from_slice(raw);
    for chunk in chunks {
        let name = chunk_name_bytes(&chunk.name)?;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(chunk.payload_base64.as_bytes())
            .map_err(|err| Error::format(format!("invalid TLG0 chunk base64: {err}")))?;
        let size = u32::try_from(payload.len())
            .map_err(|_| Error::unsupported("TLG0 chunk exceeds u32 size field"))?;
        out.extend_from_slice(&name);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&payload);
    }
    Ok(out)
}

/// Rebuild one TLG source asset from the image sidecar recorded in the manifest.
///
/// The sidecar dimensions must still match the decoded source dimensions.  A
/// JPEG sidecar is rejected unless `allow_lossy` is explicit because the pixels
/// stored in it no longer represent an exact decoder output.
pub fn rebuild_tlg_from_transform(
    unpack_root: &Path,
    transform: &TlgTransformMeta,
    allow_lossy: bool,
) -> Result<Vec<u8>> {
    if !transform.lossless_pixels && !allow_lossy {
        return Err(Error::unsupported(format!(
            "TLG sidecar {} is lossy ({}); pass --allow-lossy to rebuild it",
            transform.output_path, transform.output_format
        )));
    }
    let sidecar = safe_sidecar_path(unpack_root, &transform.output_path)?;
    let image = image::open(&sidecar).map_err(image_error)?.to_rgba8();
    if image.width() != transform.width || image.height() != transform.height {
        return Err(Error::format(format!(
            "TLG sidecar dimensions changed: meta={}x{}, image={}x{} ({})",
            transform.width,
            transform.height,
            image.width(),
            image.height(),
            sidecar.display()
        )));
    }

    let raw = encode_tlg_image(
        &image,
        TlgEncodeOptions {
            components: transform.components,
            allow_lossy,
        },
    )?;
    match &transform.container {
        Some(container) => wrap_tlg0(&raw, container),
        None => Ok(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::tlg::decode_tlg;
    use crate::xp3_meta::{sha256_hex, TlgCodecMeta};

    #[test]
    fn preserves_literal_and_hex_chunk_names() {
        assert_eq!(chunk_name_bytes("tags").unwrap(), *b"tags");
        assert_eq!(chunk_name_bytes("000102FF").unwrap(), [0, 1, 2, 0xff]);
    }

    #[test]
    fn modified_png_pixel_is_consumed_and_redecoded() {
        let root =
            std::env::temp_dir().join(format!("xp3-tlg-modified-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let image = RgbaImage::from_fn(8, 8, |x, y| {
            image::Rgba([(x * 17) as u8, (y * 19) as u8, 77, (x + y * 2) as u8])
        });
        image.save(root.join("edited.png")).unwrap();
        let png = fs::read(root.join("edited.png")).unwrap();
        let transform = TlgTransformMeta {
            source_asset_path: "image.tlg".to_string(),
            source_size: 0,
            source_sha256: String::new(),
            output_path: "edited.png".to_string(),
            output_format: "png".to_string(),
            output_sha256: Some(sha256_hex(&png)),
            lossless_pixels: true,
            version: "TLG5".to_string(),
            width: 8,
            height: 8,
            components: 4,
            decoded_rgba_sha256: String::new(),
            codec: TlgCodecMeta::Tlg5 { block_height: 4 },
            container: None,
        };
        let rebuilt = rebuild_tlg_from_transform(&root, &transform, false).unwrap();
        let decoded = decode_tlg(&rebuilt).unwrap();
        assert_eq!(decoded.rgba, image.into_raw());
        fs::remove_dir_all(root).unwrap();
    }
}
