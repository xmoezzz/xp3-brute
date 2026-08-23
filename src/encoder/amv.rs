//! AJPM/AlphaMovie (`.amv`) Mode B encoder.
//!
//! The stream is JPEG-like rather than a JPEG file: 16x16 4:2:0 macroblocks,
//! standard baseline JPEG Huffman tables, three file-level quantization tables,
//! and an additional four alpha blocks per macroblock.  Manifest rebuilding is
//! template based so packets for unedited frames remain byte-for-byte intact.

use crate::xp3_meta::{sha256_hex, AmvFrameTransformMeta};
use crate::{Error, Result};
use crate::{OperationContext, ProgressOutcome, ProgressUnit};
use image::RgbaImage;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

const MAGIC: &[u8; 4] = b"AJPM";
const FRAME_TAG: &[u8; 4] = b"FRAM";
const FILE_HEADER_SIZE: usize = 40;
const MODE_B_HEADER_SIZE: usize = 232;
const MODE_B_QTABLE_SIZE: usize = 192;

#[derive(Debug, Clone, Copy)]
pub struct AmvEncodeOptions {
    /// AMV stores frame duration as the rational `fps_num / fps_den` seconds.
    pub fps_num: u32,
    pub fps_den: u32,
    /// JPEG-style quality in the inclusive range 1..=100.
    pub quality: u8,
}

impl Default for AmvEncodeOptions {
    fn default() -> Self {
        Self {
            fps_num: 1,
            fps_den: 30,
            quality: 75,
        }
    }
}

#[derive(Debug)]
struct ModeBTemplate<'a> {
    header: &'a [u8],
    width: u16,
    height: u16,
    q_luma: [u8; 64],
    q_chroma: [u8; 64],
    q_alpha: [u8; 64],
    packets: Vec<ModeBPacket<'a>>,
    trailing: &'a [u8],
}

#[derive(Debug)]
struct ModeBPacket<'a> {
    raw: &'a [u8],
    tag: [u8; 4],
    frame_id: u32,
}

pub fn encode_amv_frames(frames: &[RgbaImage], options: AmvEncodeOptions) -> Result<Vec<u8>> {
    encode_amv_frames_with_context(frames, options, &OperationContext::silent())
}

pub fn encode_amv_frames_with_context(
    frames: &[RgbaImage],
    options: AmvEncodeOptions,
    context: &OperationContext,
) -> Result<Vec<u8>> {
    validate_options(options)?;
    let first = frames
        .first()
        .ok_or_else(|| Error::invalid("AMV encoding requires at least one frame"))?;
    let width = u16::try_from(first.width())
        .map_err(|_| Error::invalid("AMV frame width exceeds 65535"))?;
    let height = u16::try_from(first.height())
        .map_err(|_| Error::invalid("AMV frame height exceeds 65535"))?;
    if width == 0 || height == 0 {
        return Err(Error::invalid("AMV frame dimensions must be non-zero"));
    }
    if frames
        .iter()
        .any(|frame| frame.dimensions() != first.dimensions())
    {
        return Err(Error::invalid(
            "all AMV frames must have identical dimensions",
        ));
    }
    let frame_count =
        u32::try_from(frames.len()).map_err(|_| Error::invalid("AMV frame count exceeds u32"))?;
    let (q_luma, q_chroma) = scaled_quant_tables(options.quality);
    let q_alpha = q_luma;
    let task = context.start_task(
        "encode-amv",
        Some(u64::from(frame_count)),
        ProgressUnit::Frames,
    );

    let mut output = encode_header(
        frame_count,
        options.fps_num,
        options.fps_den,
        width,
        height,
        &q_luma,
        &q_chroma,
        &q_alpha,
    );
    for (index, frame) in frames.iter().enumerate() {
        if task.is_cancelled() {
            let message = format!("AMV encoding cancelled before frame {index}");
            task.finish(ProgressOutcome::Cancelled, Some(message.clone()));
            return Err(Error::cancelled(message));
        }
        let packet = match encode_mode_b_packet(
            frame,
            index as u32,
            *FRAME_TAG,
            &q_luma,
            &q_chroma,
            &q_alpha,
        ) {
            Ok(packet) => packet,
            Err(err) => {
                task.finish(ProgressOutcome::Failed, Some(err.to_string()));
                return Err(err);
            }
        };
        output.extend_from_slice(&packet);
        task.advance(1);
    }
    task.finish(ProgressOutcome::Success, None);
    Ok(output)
}

pub fn encode_amv_image_files(
    inputs: &[PathBuf],
    output: &Path,
    options: AmvEncodeOptions,
) -> Result<()> {
    encode_amv_image_files_with_context(inputs, output, options, &OperationContext::silent())
}

pub fn encode_amv_image_files_with_context(
    inputs: &[PathBuf],
    output: &Path,
    options: AmvEncodeOptions,
    context: &OperationContext,
) -> Result<()> {
    let mut frames = Vec::with_capacity(inputs.len());
    for path in inputs {
        let image = image::open(path).map_err(|err| {
            Error::format(format!("cannot decode AMV frame {}: {err}", path.display()))
        })?;
        frames.push(image.to_rgba8());
    }
    let bytes = encode_amv_frames_with_context(&frames, options, context)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, bytes)?;
    Ok(())
}

/// Rebuild a retained Mode B container, replacing only frames named in the manifest.
///
/// Untouched packet bytes, the original header/quantization tables, frame IDs,
/// tags, and any trailing data are preserved exactly. Edited frames are always
/// encoded as full-canvas packets; this avoids depending on a previous frame's
/// pixels when the replacement sidecar is a complete RGBA image.
pub fn rebuild_amv_from_transforms(
    unpack_root: &Path,
    source_container_path: &str,
    transforms: &[AmvFrameTransformMeta],
    allow_lossy: bool,
) -> Result<Vec<u8>> {
    if transforms.is_empty() {
        return Err(Error::invalid(
            "AMV rebuild requires at least one frame transform",
        ));
    }
    if !allow_lossy {
        return Err(Error::unsupported(
            "AMV uses lossy DCT encoding; pass --allow-lossy to rebuild edited frames",
        ));
    }
    let source_relative = safe_relative(source_container_path)?;
    let source_path = unpack_root.join(source_relative);
    let source = fs::read(&source_path)?;
    let source_hash = sha256_hex(&source);
    let template = parse_mode_b_template(&source)?;
    let mut replacements = BTreeMap::<usize, RgbaImage>::new();

    for meta in transforms {
        if meta.source_container_path != source_container_path {
            return Err(Error::format(format!(
                "AMV transform source mismatch: {:?} != {:?}",
                meta.source_container_path, source_container_path
            )));
        }
        if !meta.source_container_retained {
            return Err(Error::unsupported(format!(
                "AMV transform for frame {} does not retain its source container",
                meta.frame_index
            )));
        }
        if meta.source_size != source.len()
            || !meta.source_sha256.eq_ignore_ascii_case(&source_hash)
        {
            return Err(Error::format(format!(
                "retained AMV source identity does not match manifest for {:?}",
                source_container_path
            )));
        }
        if meta.frame_index >= template.packets.len() {
            return Err(Error::format(format!(
                "AMV frame index {} is outside retained container frame count {}",
                meta.frame_index,
                template.packets.len()
            )));
        }
        let extension_ok = matches!(
            meta.output_format.to_ascii_lowercase().as_str(),
            "png" | "rgba-png"
        );
        if !extension_ok {
            return Err(Error::unsupported(format!(
                "AMV frame {} output format {:?} is not supported; expected PNG",
                meta.frame_index, meta.output_format
            )));
        }
        let sidecar = unpack_root.join(safe_relative(&meta.output_path)?);
        let frame = image::open(&sidecar)
            .map_err(|err| {
                Error::format(format!(
                    "cannot decode AMV sidecar {}: {err}",
                    sidecar.display()
                ))
            })?
            .to_rgba8();
        if frame.dimensions() != (u32::from(template.width), u32::from(template.height)) {
            return Err(Error::invalid(format!(
                "AMV sidecar {} is {}x{}, expected {}x{}",
                sidecar.display(),
                frame.width(),
                frame.height(),
                template.width,
                template.height
            )));
        }
        if replacements.insert(meta.frame_index, frame).is_some() {
            return Err(Error::format(format!(
                "multiple AMV transforms replace frame {}",
                meta.frame_index
            )));
        }
    }

    let mut output = Vec::with_capacity(source.len());
    output.extend_from_slice(template.header);
    for (index, packet) in template.packets.iter().enumerate() {
        if let Some(frame) = replacements.get(&index) {
            output.extend_from_slice(&encode_mode_b_packet(
                frame,
                packet.frame_id,
                packet.tag,
                &template.q_luma,
                &template.q_chroma,
                &template.q_alpha,
            )?);
        } else {
            output.extend_from_slice(packet.raw);
        }
    }
    output.extend_from_slice(template.trailing);
    Ok(output)
}

fn validate_options(options: AmvEncodeOptions) -> Result<()> {
    if options.fps_num == 0 || options.fps_den == 0 {
        return Err(Error::invalid(
            "AMV frame-duration numerator and denominator must be non-zero",
        ));
    }
    if !(1..=100).contains(&options.quality) {
        return Err(Error::invalid("AMV quality must be in 1..=100"));
    }
    Ok(())
}

fn encode_header(
    frame_count: u32,
    fps_num: u32,
    fps_den: u32,
    width: u16,
    height: u16,
    q_luma: &[u8; 64],
    q_chroma: &[u8; 64],
    q_alpha: &[u8; 64],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MODE_B_HEADER_SIZE);
    out.extend_from_slice(MAGIC);
    put_u32(&mut out, 0); // unknown 04
    put_u32(&mut out, 0); // revision
    put_u32(&mut out, MODE_B_HEADER_SIZE as u32);
    put_u32(&mut out, 0); // unknown 10
    put_u32(&mut out, frame_count);
    put_u32(&mut out, fps_num);
    put_u32(&mut out, fps_den);
    put_u16(&mut out, width);
    put_u16(&mut out, height);
    out.push(1); // Mode B / alpha
    out.extend_from_slice(&[0; 3]);
    out.extend_from_slice(q_luma);
    out.extend_from_slice(q_chroma);
    out.extend_from_slice(q_alpha);
    debug_assert_eq!(out.len(), MODE_B_HEADER_SIZE);
    out
}

fn parse_mode_b_template(bytes: &[u8]) -> Result<ModeBTemplate<'_>> {
    if bytes.len() < FILE_HEADER_SIZE || &bytes[..4] != MAGIC {
        return Err(Error::format("not an AJPM/AMV container"));
    }
    let revision = read_u32(bytes, 8)?;
    let header_size = read_u32(bytes, 12)? as usize;
    let frame_count = read_u32(bytes, 20)? as usize;
    let width = read_u16(bytes, 32)?;
    let height = read_u16(bytes, 34)?;
    let attr = bytes[36];
    if revision != 0 {
        return Err(Error::unsupported(format!(
            "AMV revision {revision} is not supported"
        )));
    }
    if attr & 1 == 0 || attr & 2 != 0 || header_size != MODE_B_HEADER_SIZE {
        return Err(Error::unsupported(format!(
            "AMV template is not supported Mode B (attr=0x{attr:02x}, header_size={header_size}); Mode A encoding is intentionally unavailable"
        )));
    }
    if width == 0 || height == 0 || bytes.len() < header_size {
        return Err(Error::format("invalid AMV header dimensions or size"));
    }
    let qbytes = &bytes[FILE_HEADER_SIZE..FILE_HEADER_SIZE + MODE_B_QTABLE_SIZE];
    let mut q_luma = [0u8; 64];
    let mut q_chroma = [0u8; 64];
    let mut q_alpha = [0u8; 64];
    q_luma.copy_from_slice(&qbytes[..64]);
    q_chroma.copy_from_slice(&qbytes[64..128]);
    q_alpha.copy_from_slice(&qbytes[128..192]);
    if q_luma.contains(&0) || q_chroma.contains(&0) || q_alpha.contains(&0) {
        return Err(Error::format("AMV quantization tables contain zero"));
    }

    let mut packets = Vec::with_capacity(frame_count);
    let mut offset = header_size;
    for index in 0..frame_count {
        let fixed_end = offset
            .checked_add(20)
            .ok_or_else(|| Error::format("AMV packet offset overflow"))?;
        if fixed_end > bytes.len() {
            return Err(Error::format(format!(
                "AMV frame {index} has a truncated packet header"
            )));
        }
        let chunk_size = read_u32(bytes, offset + 4)? as usize;
        if chunk_size < 12 {
            return Err(Error::format(format!(
                "AMV frame {index} chunk size is smaller than 12"
            )));
        }
        let packet_size = chunk_size
            .checked_add(8)
            .ok_or_else(|| Error::format("AMV packet size overflow"))?;
        let end = offset
            .checked_add(packet_size)
            .ok_or_else(|| Error::format("AMV packet offset overflow"))?;
        if end > bytes.len() {
            return Err(Error::format(format!(
                "AMV frame {index} payload is truncated"
            )));
        }
        let packet_w = read_u16(bytes, offset + 16)?;
        let packet_h = read_u16(bytes, offset + 18)?;
        if packet_w == 0 || packet_h == 0 || packet_w % 16 != 0 || packet_h % 16 != 0 {
            return Err(Error::format(format!(
                "AMV frame {index} rectangle is not 16-aligned"
            )));
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&bytes[offset..offset + 4]);
        packets.push(ModeBPacket {
            raw: &bytes[offset..end],
            tag,
            frame_id: read_u32(bytes, offset + 8)?,
        });
        offset = end;
    }
    Ok(ModeBTemplate {
        header: &bytes[..header_size],
        width,
        height,
        q_luma,
        q_chroma,
        q_alpha,
        packets,
        trailing: &bytes[offset..],
    })
}

fn encode_mode_b_packet(
    frame: &RgbaImage,
    frame_id: u32,
    tag: [u8; 4],
    q_luma: &[u8; 64],
    q_chroma: &[u8; 64],
    q_alpha: &[u8; 64],
) -> Result<Vec<u8>> {
    let aligned_width = align16(frame.width())?;
    let aligned_height = align16(frame.height())?;
    let payload = encode_macroblocks(
        frame,
        aligned_width,
        aligned_height,
        q_luma,
        q_chroma,
        q_alpha,
    )?;
    let chunk_size = u32::try_from(12usize + payload.len())
        .map_err(|_| Error::invalid("encoded AMV frame packet exceeds u32"))?;
    let mut out = Vec::with_capacity(payload.len() + 20);
    out.extend_from_slice(&tag);
    put_u32(&mut out, chunk_size);
    put_u32(&mut out, frame_id);
    put_i16(&mut out, 0);
    put_i16(&mut out, 0);
    put_u16(&mut out, aligned_width);
    put_u16(&mut out, aligned_height);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn encode_macroblocks(
    frame: &RgbaImage,
    aligned_width: u16,
    aligned_height: u16,
    q_luma: &[u8; 64],
    q_chroma: &[u8; 64],
    q_alpha: &[u8; 64],
) -> Result<Vec<u8>> {
    let h = HuffmanSet::standard()?;
    let mut writer = BitWriter::default();
    let mut chroma_dc = 0i32;
    let mut luma_dc = 0i32;
    for my in (0..u32::from(aligned_height)).step_by(16) {
        for mx in (0..u32::from(aligned_width)).step_by(16) {
            let mut y = [[0f64; 64]; 4];
            let mut a = [[0f64; 64]; 4];
            let mut cb = [0f64; 64];
            let mut cr = [0f64; 64];
            for sy in 0..16u32 {
                for sx in 0..16u32 {
                    let px = frame.get_pixel(
                        (mx + sx).min(frame.width() - 1),
                        (my + sy).min(frame.height() - 1),
                    );
                    let r = f64::from(px[0]);
                    let g = f64::from(px[1]);
                    let b = f64::from(px[2]);
                    let yy = 0.299 * r + 0.587 * g + 0.114 * b;
                    let block = ((sy / 8) * 2 + sx / 8) as usize;
                    let pos = ((sy % 8) * 8 + sx % 8) as usize;
                    y[block][pos] = yy - 128.0;
                    a[block][pos] = f64::from(px[3]) - 128.0;
                }
            }
            for cy in 0..8u32 {
                for cx in 0..8u32 {
                    let mut cb_sum = 0.0;
                    let mut cr_sum = 0.0;
                    for dy in 0..2u32 {
                        for dx in 0..2u32 {
                            let px = frame.get_pixel(
                                (mx + cx * 2 + dx).min(frame.width() - 1),
                                (my + cy * 2 + dy).min(frame.height() - 1),
                            );
                            let r = f64::from(px[0]);
                            let g = f64::from(px[1]);
                            let b = f64::from(px[2]);
                            cb_sum += -0.168736 * r - 0.331264 * g + 0.5 * b;
                            cr_sum += 0.5 * r - 0.418688 * g - 0.081312 * b;
                        }
                    }
                    cb[(cy * 8 + cx) as usize] = cb_sum / 4.0;
                    cr[(cy * 8 + cx) as usize] = cr_sum / 4.0;
                }
            }
            encode_block(
                &mut writer,
                &fdct_quantize(&cb, q_chroma),
                &mut chroma_dc,
                &h.dc_chroma,
                &h.ac_chroma,
            )?;
            encode_block(
                &mut writer,
                &fdct_quantize(&cr, q_chroma),
                &mut chroma_dc,
                &h.dc_chroma,
                &h.ac_chroma,
            )?;
            for block in &y {
                encode_block(
                    &mut writer,
                    &fdct_quantize(block, q_luma),
                    &mut luma_dc,
                    &h.dc_luma,
                    &h.ac_luma,
                )?;
            }
            for block in &a {
                encode_block(
                    &mut writer,
                    &fdct_quantize(block, q_alpha),
                    &mut luma_dc,
                    &h.dc_luma,
                    &h.ac_luma,
                )?;
            }
        }
    }
    Ok(writer.finish())
}

fn fdct_quantize(samples: &[f64; 64], qtable: &[u8; 64]) -> [i32; 64] {
    let basis = dct_basis();
    let mut horizontal = [[0f64; 8]; 8];
    for y in 0..8 {
        for u in 0..8 {
            horizontal[y][u] = (0..8).map(|x| samples[y * 8 + x] * basis[u][x]).sum();
        }
    }
    let mut out = [0i32; 64];
    for v in 0..8 {
        for u in 0..8 {
            let dct = (0..8).map(|y| horizontal[y][u] * basis[v][y]).sum::<f64>();
            // The AMV decoder multiplies each coefficient by q * 4 before IDCT.
            out[v * 8 + u] = (dct / (f64::from(qtable[v * 8 + u]) * 4.0)).round() as i32;
        }
    }
    out
}

fn dct_basis() -> &'static [[f64; 8]; 8] {
    static BASIS: OnceLock<[[f64; 8]; 8]> = OnceLock::new();
    BASIS.get_or_init(|| {
        let mut basis = [[0f64; 8]; 8];
        for u in 0..8 {
            let normalization = if u == 0 {
                0.5 * std::f64::consts::FRAC_1_SQRT_2
            } else {
                0.5
            };
            for x in 0..8 {
                basis[u][x] = normalization
                    * (((2 * x + 1) as f64 * u as f64 * std::f64::consts::PI) / 16.0).cos();
            }
        }
        basis
    })
}

fn encode_block(
    writer: &mut BitWriter,
    coeff: &[i32; 64],
    predictor: &mut i32,
    dc: &HuffmanEncoder,
    ac: &HuffmanEncoder,
) -> Result<()> {
    let difference = coeff[0] - *predictor;
    *predictor = coeff[0];
    let dc_size = magnitude_size(difference);
    dc.write(writer, dc_size)?;
    write_amplitude(writer, difference, dc_size);

    let mut run = 0u8;
    for &natural_index in ZIGZAG.iter().skip(1) {
        let value = coeff[natural_index];
        if value == 0 {
            run += 1;
            continue;
        }
        while run >= 16 {
            ac.write(writer, 0xf0)?;
            run -= 16;
        }
        let size = magnitude_size(value);
        if size > 15 {
            return Err(Error::format(
                "AMV quantized AC coefficient exceeds Huffman representation",
            ));
        }
        ac.write(writer, (run << 4) | size)?;
        write_amplitude(writer, value, size);
        run = 0;
    }
    if run != 0 {
        ac.write(writer, 0x00)?;
    }
    Ok(())
}

fn magnitude_size(value: i32) -> u8 {
    if value == 0 {
        0
    } else {
        (32 - value.unsigned_abs().leading_zeros()) as u8
    }
}

fn write_amplitude(writer: &mut BitWriter, value: i32, size: u8) {
    if size == 0 {
        return;
    }
    let bits = if value >= 0 {
        value as u32
    } else {
        ((1u32 << size) as i32 - 1 + value) as u32
    };
    writer.write(bits, size);
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    used: u8,
}

impl BitWriter {
    fn write(&mut self, value: u32, length: u8) {
        for shift in (0..length).rev() {
            self.current = (self.current << 1) | ((value >> shift) as u8 & 1);
            self.used += 1;
            if self.used == 8 {
                self.bytes.push(self.current);
                self.current = 0;
                self.used = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 {
            self.current <<= 8 - self.used;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

#[derive(Clone)]
struct HuffmanEncoder {
    codes: [Option<(u16, u8)>; 256],
}

impl HuffmanEncoder {
    fn new(bits: &[u8; 16], values: &[u8]) -> Result<Self> {
        if bits.iter().map(|&v| usize::from(v)).sum::<usize>() != values.len() {
            return Err(Error::format("invalid built-in JPEG Huffman table"));
        }
        let mut codes = [None; 256];
        let mut code = 0u16;
        let mut index = 0usize;
        for (slot, &count) in bits.iter().enumerate() {
            let length = slot as u8 + 1;
            for _ in 0..count {
                codes[values[index] as usize] = Some((code, length));
                code += 1;
                index += 1;
            }
            code <<= 1;
        }
        Ok(Self { codes })
    }
    fn write(&self, writer: &mut BitWriter, symbol: u8) -> Result<()> {
        let (code, length) = self.codes[symbol as usize].ok_or_else(|| {
            Error::format(format!("no JPEG Huffman code for symbol 0x{symbol:02x}"))
        })?;
        writer.write(u32::from(code), length);
        Ok(())
    }
}

struct HuffmanSet {
    dc_luma: HuffmanEncoder,
    ac_luma: HuffmanEncoder,
    dc_chroma: HuffmanEncoder,
    ac_chroma: HuffmanEncoder,
}

impl HuffmanSet {
    fn standard() -> Result<Self> {
        Ok(Self {
            dc_luma: HuffmanEncoder::new(&DC_LUMA_BITS, &DC_VALUES)?,
            ac_luma: HuffmanEncoder::new(&AC_LUMA_BITS, &AC_LUMA_VALUES)?,
            dc_chroma: HuffmanEncoder::new(&DC_CHROMA_BITS, &DC_VALUES)?,
            ac_chroma: HuffmanEncoder::new(&AC_CHROMA_BITS, &AC_CHROMA_VALUES)?,
        })
    }
}

fn scaled_quant_tables(quality: u8) -> ([u8; 64], [u8; 64]) {
    let scale = if quality < 50 {
        5000 / u32::from(quality)
    } else {
        200 - u32::from(quality) * 2
    };
    let scale_one = |base: &[u8; 64]| {
        let mut out = [0u8; 64];
        for (dst, &src) in out.iter_mut().zip(base) {
            *dst = (((u32::from(src) * scale + 50) / 100).clamp(1, 255)) as u8;
        }
        out
    };
    (scale_one(&BASE_LUMA_Q), scale_one(&BASE_CHROMA_Q))
}

fn align16(value: u32) -> Result<u16> {
    let aligned = value
        .checked_add(15)
        .ok_or_else(|| Error::invalid("AMV dimension overflow"))?
        & !15;
    u16::try_from(aligned).map_err(|_| Error::invalid("16-aligned AMV dimension exceeds 65535"))
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(Error::invalid(format!(
            "manifest path must be relative: {value:?}"
        )));
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::invalid(format!("unsafe manifest path: {value:?}")))
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::invalid("empty manifest path"));
    }
    Ok(out)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| Error::format("truncated AMV integer"))?
        .try_into()
        .unwrap();
    Ok(u16::from_le_bytes(raw))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::format("truncated AMV integer"))?
        .try_into()
        .unwrap();
    Ok(u32::from_le_bytes(raw))
}
fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_i16(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

const BASE_LUMA_Q: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const BASE_CHROMA_Q: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

const DC_LUMA_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const DC_CHROMA_BITS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const DC_VALUES: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const AC_LUMA_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const AC_CHROMA_BITS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77];

const AC_LUMA_VALUES: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];
const AC_CHROMA_VALUES: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, ProgressEvent, ProgressEventKind};
    use std::sync::{Arc, Mutex};

    #[test]
    fn emits_parseable_mode_b_with_aligned_packet() {
        let frame = RgbaImage::from_fn(17, 19, |x, y| {
            image::Rgba([(x * 11) as u8, (y * 7) as u8, 91, (x + y) as u8])
        });
        let bytes = encode_amv_frames(&[frame], AmvEncodeOptions::default()).unwrap();
        let parsed = parse_mode_b_template(&bytes).unwrap();
        assert_eq!((parsed.width, parsed.height), (17, 19));
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(read_u16(&bytes, MODE_B_HEADER_SIZE + 16).unwrap(), 32);
        assert_eq!(read_u16(&bytes, MODE_B_HEADER_SIZE + 18).unwrap(), 32);
        assert_eq!(
            parsed.packets[0].raw.len(),
            read_u32(&bytes, MODE_B_HEADER_SIZE + 4).unwrap() as usize + 8
        );
    }

    #[test]
    fn rejects_bad_options_and_frame_shapes() {
        let a = RgbaImage::new(16, 16);
        let b = RgbaImage::new(32, 16);
        assert!(encode_amv_frames(&[a.clone(), b], AmvEncodeOptions::default()).is_err());
        assert!(encode_amv_frames(
            &[a],
            AmvEncodeOptions {
                quality: 0,
                ..AmvEncodeOptions::default()
            }
        )
        .is_err());
    }

    #[test]
    fn mode_a_template_fails_closed() {
        let mut bytes = vec![0u8; 168];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[12..16].copy_from_slice(&168u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&16u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&16u16.to_le_bytes());
        bytes[36] = 2;
        assert!(matches!(
            parse_mode_b_template(&bytes),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn template_rebuild_preserves_untouched_packets() {
        let root = std::env::temp_dir().join(format!("xp3-amv-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let first = RgbaImage::from_pixel(16, 16, image::Rgba([10, 20, 30, 255]));
        let second = RgbaImage::from_pixel(16, 16, image::Rgba([40, 50, 60, 128]));
        let mut source = encode_amv_frames(&[first, second], AmvEncodeOptions::default()).unwrap();
        source.extend_from_slice(b"opaque-trailer");
        fs::write(root.join("movie.amv"), &source).unwrap();
        let replacement = RgbaImage::from_pixel(16, 16, image::Rgba([220, 90, 12, 77]));
        replacement.save(root.join("frame1.png")).unwrap();
        let meta = AmvFrameTransformMeta {
            source_container_path: "movie.amv".to_string(),
            source_size: source.len(),
            source_sha256: sha256_hex(&source),
            output_path: "frame1.png".to_string(),
            frame_index: 1,
            output_format: "png".to_string(),
            output_sha256: Some(sha256_hex(&fs::read(root.join("frame1.png")).unwrap())),
            lossless_pixels: true,
            frame_duration_ms: None,
            container_variant: Some("mode-b".to_string()),
            width: Some(16),
            height: Some(16),
            frame_count: Some(2),
            fps_num: Some(1),
            fps_den: Some(30),
            attr: Some(1),
            source_container_retained: true,
        };
        assert!(rebuild_amv_from_transforms(&root, "movie.amv", &[meta.clone()], false).is_err());
        let rebuilt = rebuild_amv_from_transforms(&root, "movie.amv", &[meta], true).unwrap();
        let before = parse_mode_b_template(&source).unwrap();
        let after = parse_mode_b_template(&rebuilt).unwrap();
        assert_eq!(before.header, after.header);
        assert_eq!(before.packets[0].raw, after.packets[0].raw);
        assert_ne!(before.packets[1].raw, after.packets[1].raw);
        assert_eq!(after.trailing, b"opaque-trailer");
        let decoded_source = crate::decode_amv(&source).unwrap();
        let decoded_rebuilt = crate::decode_amv(&rebuilt).unwrap();
        assert_eq!(decoded_source.info, decoded_rebuilt.info);
        assert_eq!(decoded_source.frames[0], decoded_rebuilt.frames[0]);
        assert_ne!(
            decoded_source.frames[1].rgba,
            decoded_rebuilt.frames[1].rgba
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn context_api_reports_each_encoded_frame() {
        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let captured = events.clone();
        let context = OperationContext::new(Arc::new(move |event| {
            captured.lock().unwrap().push(event);
        }));
        let frames = [RgbaImage::new(16, 16), RgbaImage::new(16, 16)];
        encode_amv_frames_with_context(&frames, AmvEncodeOptions::default(), &context).unwrap();
        let events = events.lock().unwrap();
        assert_eq!(events.first().unwrap().kind, ProgressEventKind::Started);
        assert_eq!(events.last().unwrap().kind, ProgressEventKind::Finished);
        assert_eq!(events.last().unwrap().current, 2);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == ProgressEventKind::Advanced)
                .count(),
            2
        );
    }

    #[test]
    fn context_api_honors_preexisting_cancellation() {
        let token = CancellationToken::default();
        token.cancel();
        let context = OperationContext::with_cancellation(Arc::new(crate::NoopProgressSink), token);
        let error = encode_amv_frames_with_context(
            &[RgbaImage::new(16, 16)],
            AmvEncodeOptions::default(),
            &context,
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cancelled(_)));
    }
}
