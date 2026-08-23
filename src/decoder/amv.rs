//! AJPM/AlphaMovie decoding used by expansion and round-trip verification.
//!
//! Encoding intentionally lives in `encoder::amv`; decoding goes through the
//! independently maintained reference decoder so an encoder bug cannot prove
//! its own output correct by sharing the same bitstream implementation.

use crate::{Error, Result};
use amv_decoder::{AmvDecoder, AmvFile, AmvMode};
use image::{ImageBuffer, Rgba};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmvVariant {
    ModeA,
    ModeB,
}

impl AmvVariant {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModeA => "mode-a",
            Self::ModeB => "mode-b",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmvInfo {
    pub variant: AmvVariant,
    pub frame_count: u32,
    pub fps_num: u32,
    pub fps_den: u32,
    pub width: u16,
    pub height: u16,
    pub attr: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAmvFrame {
    pub index: u32,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAmv {
    pub info: AmvInfo,
    pub frames: Vec<DecodedAmvFrame>,
}

pub fn is_amv_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"AJPM")
}

pub fn decode_amv(bytes: &[u8]) -> Result<DecodedAmv> {
    let mut file = AmvFile::from_reader(Cursor::new(bytes))
        .map_err(|err| Error::format(format!("AMV parse failed: {err:#}")))?;
    let header = file.header.clone();
    let mode = file.mode;
    let mut decoder = AmvDecoder::new(header.clone(), mode, file.qtables.clone())
        .map_err(|err| Error::format(format!("AMV decoder setup failed: {err:#}")))?;
    let decoded = decoder
        .decode_all(&mut file, None)
        .map_err(|err| Error::format(format!("AMV frame decode failed: {err:#}")))?;
    if decoded.len() != header.frame_count as usize {
        return Err(Error::format(format!(
            "AMV decoded frame count mismatch: header={} decoded={}",
            header.frame_count,
            decoded.len()
        )));
    }
    let expected = usize::from(header.width)
        .checked_mul(usize::from(header.height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| Error::format("AMV dimensions overflow RGBA buffer"))?;
    let mut frames = Vec::with_capacity(decoded.len());
    for frame in decoded {
        if frame.width != header.width
            || frame.height != header.height
            || frame.rgba.len() != expected
        {
            return Err(Error::format(format!(
                "AMV frame {} has invalid canvas {}x{} / {} bytes",
                frame.index,
                frame.width,
                frame.height,
                frame.rgba.len()
            )));
        }
        frames.push(DecodedAmvFrame {
            index: frame.index,
            rgba: frame.rgba,
        });
    }
    Ok(DecodedAmv {
        info: AmvInfo {
            variant: match mode {
                AmvMode::A => AmvVariant::ModeA,
                AmvMode::B => AmvVariant::ModeB,
            },
            frame_count: header.frame_count,
            fps_num: header.fps_num,
            fps_den: header.fps_den,
            width: header.width,
            height: header.height,
            attr: header.attr,
        },
        frames,
    })
}

pub fn export_amv_frames(decoded: &DecodedAmv, output_dir: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(output_dir)?;
    let mut paths = Vec::with_capacity(decoded.frames.len());
    for frame in &decoded.frames {
        let image = ImageBuffer::<Rgba<u8>, _>::from_raw(
            u32::from(decoded.info.width),
            u32::from(decoded.info.height),
            frame.rgba.clone(),
        )
        .ok_or_else(|| Error::format("AMV decoder returned an invalid RGBA buffer"))?;
        let path = output_dir.join(format!("frame_{:06}.png", frame.index));
        image
            .save(&path)
            .map_err(|err| Error::format(format!("cannot write {}: {err}", path.display())))?;
        paths.push(path);
    }
    Ok(paths)
}
