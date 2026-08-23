//! Binwalk-style probing for XP3 index/special-index blobs.
//!
//! This module is deliberately diagnostic and conservative.  It never turns a
//! signature hit into a successful extraction by itself.  The goal is to find
//! plausible nested compression/container/chunk boundaries so future variants
//! can be classified without breaking known archive families.

use crate::format::builtin_hypotheses;
use crate::validate::validate_hypothesis;
use crate::xp3::XP3_MAGIC;
use flate2::read::{GzDecoder, ZlibDecoder};
use std::io::Read;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    Xp3Signature,
    RootChunk,
    Zlib,
    Gzip,
    CompressionSignature,
    KnownFormat,
    XorWrapped,
    HighEntropy,
}

#[derive(Clone, Debug)]
pub struct ChunkProbe {
    pub offset: usize,
    pub length: Option<usize>,
    pub kind: ProbeKind,
    pub label: String,
    pub confidence: u8,
    pub decoded_length: Option<usize>,
}

pub fn probe_blob(data: &[u8]) -> Vec<ChunkProbe> {
    let mut out = Vec::new();
    scan_signature(
        data,
        &XP3_MAGIC,
        "XP3",
        ProbeKind::Xp3Signature,
        100,
        &mut out,
    );
    scan_zlib(data, &mut out);
    scan_gzip(data, &mut out);
    scan_signature(
        data,
        &[0x28, 0xb5, 0x2f, 0xfd],
        "zstd frame",
        ProbeKind::CompressionSignature,
        90,
        &mut out,
    );
    scan_signature(
        data,
        &[0xfd, b'7', b'z', b'X', b'Z', 0x00],
        "xz/lzma2 stream",
        ProbeKind::CompressionSignature,
        90,
        &mut out,
    );
    scan_signature(
        data,
        b"BZh",
        "bzip2 stream",
        ProbeKind::CompressionSignature,
        88,
        &mut out,
    );
    scan_signature(
        data,
        &[0x04, 0x22, 0x4d, 0x18],
        "lz4 frame",
        ProbeKind::CompressionSignature,
        88,
        &mut out,
    );
    scan_root_chunks(data, &mut out);
    scan_known_formats(data, &mut out);
    scan_single_byte_xor_wrapper(data, &mut out);
    if data.len() >= 256 {
        let entropy = shannon_entropy(&data[..data.len().min(8192)]);
        if entropy >= 7.65 {
            out.push(ChunkProbe {
                offset: 0,
                length: Some(data.len()),
                kind: ProbeKind::HighEntropy,
                label: format!("high-entropy/possibly-encrypted entropy={entropy:.3}"),
                confidence: 55,
                decoded_length: None,
            });
        }
    }
    out.sort_by_key(|p| (p.offset, std::cmp::Reverse(p.confidence)));
    out.dedup_by(|a, b| a.offset == b.offset && a.label == b.label);
    out
}

fn scan_signature(
    data: &[u8],
    needle: &[u8],
    label: &str,
    kind: ProbeKind,
    confidence: u8,
    out: &mut Vec<ChunkProbe>,
) {
    if needle.is_empty() || data.len() < needle.len() {
        return;
    }
    for offset in 0..=data.len() - needle.len() {
        if &data[offset..offset + needle.len()] == needle {
            out.push(ChunkProbe {
                offset,
                length: None,
                kind: kind.clone(),
                label: label.to_string(),
                confidence,
                decoded_length: None,
            });
        }
    }
}

fn scan_zlib(data: &[u8], out: &mut Vec<ChunkProbe>) {
    for offset in 0..data.len().saturating_sub(2) {
        let cmf = data[offset];
        let flg = data[offset + 1];
        if cmf & 0x0f != 8 || (u16::from(cmf) * 256 + u16::from(flg)) % 31 != 0 {
            continue;
        }
        let mut decoder = ZlibDecoder::new(&data[offset..]);
        let mut decoded = Vec::new();
        if decoder.read_to_end(&mut decoded).is_ok() && !decoded.is_empty() {
            out.push(ChunkProbe {
                offset,
                length: None,
                kind: ProbeKind::Zlib,
                label: "zlib stream".to_string(),
                confidence: 90,
                decoded_length: Some(decoded.len()),
            });
            if let Some(count) = xp3_root_stream_count(&decoded) {
                out.push(ChunkProbe {
                    offset,
                    length: None,
                    kind: ProbeKind::RootChunk,
                    label: format!("zlib -> XP3-like root stream chunks={count}"),
                    confidence: 99,
                    decoded_length: Some(decoded.len()),
                });
            }
        }
    }
}

fn scan_gzip(data: &[u8], out: &mut Vec<ChunkProbe>) {
    for offset in 0..data.len().saturating_sub(3) {
        if data[offset..].starts_with(&[0x1f, 0x8b, 0x08]) {
            let mut decoder = GzDecoder::new(&data[offset..]);
            let mut decoded = Vec::new();
            if decoder.read_to_end(&mut decoded).is_ok() && !decoded.is_empty() {
                out.push(ChunkProbe {
                    offset,
                    length: None,
                    kind: ProbeKind::Gzip,
                    label: "gzip stream".to_string(),
                    confidence: 95,
                    decoded_length: Some(decoded.len()),
                });
            }
        }
    }
}

fn scan_root_chunks(data: &[u8], out: &mut Vec<ChunkProbe>) {
    // XP3 root chunks are tag:u32 + payload_size:u64.  Unknown tags are useful
    // too, but require a printable-ish FourCC and a payload fully in bounds.
    for offset in 0..data.len().saturating_sub(12) {
        let tag = &data[offset..offset + 4];
        if !tag.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            continue;
        }
        let size = u64::from_le_bytes(data[offset + 4..offset + 12].try_into().unwrap());
        let Ok(size) = usize::try_from(size) else {
            continue;
        };
        if size > data.len().saturating_sub(offset + 12) {
            continue;
        }
        let label = String::from_utf8_lossy(tag).into_owned();
        out.push(ChunkProbe {
            offset,
            length: Some(12 + size),
            kind: ProbeKind::RootChunk,
            label: format!("XP3-like root chunk {label:?} payload={size}"),
            confidence: if tag == b"File"
                || tag == b"info"
                || tag == b"segm"
                || tag == b"adlr"
                || tag == b"time"
                || tag == b"Hxv4"
            {
                98
            } else {
                70
            },
            decoded_length: None,
        });
    }
}

fn scan_known_formats(data: &[u8], out: &mut Vec<ChunkProbe>) {
    for h in builtin_hypotheses() {
        // Use only hypotheses with an exact offset-0 crib.  This is a scanner,
        // not a decryption oracle, so partial/weak guesses are intentionally
        // ignored.
        let Some(crib) = h
            .cribs
            .iter()
            .find(|c| c.offset == 0 && c.plaintext.len() >= 3)
        else {
            continue;
        };
        if data.len() < crib.plaintext.len() {
            continue;
        }
        for offset in 0..=data.len() - crib.plaintext.len() {
            if &data[offset..offset + crib.plaintext.len()] != crib.plaintext.as_slice() {
                continue;
            }
            let strong = if offset == 0 {
                validate_hypothesis(h.name, data).is_strong()
            } else {
                false
            };
            out.push(ChunkProbe {
                offset,
                length: None,
                kind: ProbeKind::KnownFormat,
                label: h.name.to_string(),
                confidence: if strong { 100 } else { 75 },
                decoded_length: None,
            });
        }
    }
}

fn xp3_root_stream_count(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    let mut count = 0usize;
    while pos + 12 <= data.len() {
        let tag = &data[pos..pos + 4];
        if !tag.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            return None;
        }
        let size = u64::from_le_bytes(data[pos + 4..pos + 12].try_into().ok()?);
        let size = usize::try_from(size).ok()?;
        let end = pos.checked_add(12)?.checked_add(size)?;
        if end > data.len() {
            return None;
        }
        count += 1;
        pos = end;
    }
    (count > 0 && pos == data.len()).then_some(count)
}

/// Cheap transform probe for historical/custom special-index wrappers.
///
/// This deliberately considers only one-byte XOR over the whole blob.  It is
/// not a decoder policy and never marks an archive solved; it is an inexpensive
/// way to discover that an otherwise opaque chunk is simply wrapping zlib,
/// gzip, XP3 root records, or another well-known container.  More complicated
/// title-specific transforms remain opaque and are reported by entropy instead
/// of being guessed.
fn scan_single_byte_xor_wrapper(data: &[u8], out: &mut Vec<ChunkProbe>) {
    if data.len() < 4 || data.len() > 64 * 1024 * 1024 {
        return;
    }
    for key in 1u16..=255 {
        let key = key as u8;
        let p0 = data[0] ^ key;
        let p1 = data[1] ^ key;
        let zlib_header = p0 & 0x0f == 8 && (u16::from(p0) * 256 + u16::from(p1)) % 31 == 0;
        let gzip_header = data.len() >= 3 && p0 == 0x1f && p1 == 0x8b && (data[2] ^ key) == 0x08;
        let xp3_header = data.len() >= XP3_MAGIC.len()
            && XP3_MAGIC
                .iter()
                .enumerate()
                .all(|(i, &b)| (data[i] ^ key) == b);
        let root_header = data.len() >= 12
            && [b"File", b"Hxv4", b"info", b"segm"]
                .iter()
                .any(|tag| tag.iter().enumerate().all(|(i, &b)| (data[i] ^ key) == b));
        if !(zlib_header || gzip_header || xp3_header || root_header) {
            continue;
        }

        let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
        if zlib_header {
            let mut z = ZlibDecoder::new(decoded.as_slice());
            let mut inflated = Vec::new();
            if z.read_to_end(&mut inflated).is_ok() && !inflated.is_empty() {
                let nested = xp3_root_stream_count(&inflated)
                    .map(|n| format!(" -> XP3-like root stream chunks={n}"))
                    .unwrap_or_default();
                out.push(ChunkProbe {
                    offset: 0,
                    length: Some(data.len()),
                    kind: ProbeKind::XorWrapped,
                    label: format!("xor-byte 0x{key:02x} -> zlib{nested}"),
                    confidence: if nested.is_empty() { 88 } else { 99 },
                    decoded_length: Some(inflated.len()),
                });
            }
        } else if gzip_header {
            let mut gz = GzDecoder::new(decoded.as_slice());
            let mut inflated = Vec::new();
            if gz.read_to_end(&mut inflated).is_ok() && !inflated.is_empty() {
                out.push(ChunkProbe {
                    offset: 0,
                    length: Some(data.len()),
                    kind: ProbeKind::XorWrapped,
                    label: format!("xor-byte 0x{key:02x} -> gzip"),
                    confidence: 92,
                    decoded_length: Some(inflated.len()),
                });
            }
        } else if xp3_header || root_header {
            out.push(ChunkProbe {
                offset: 0,
                length: Some(data.len()),
                kind: ProbeKind::XorWrapped,
                label: format!(
                    "xor-byte 0x{key:02x} -> {}",
                    if xp3_header {
                        "XP3 signature"
                    } else {
                        "XP3-like root prefix"
                    }
                ),
                confidence: 96,
                decoded_length: None,
            });
        }
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognizes_nested_zlib() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"File\x00\x00\x00\x00").unwrap();
        let z = enc.finish().unwrap();
        let mut blob = vec![0x55; 17];
        blob.extend_from_slice(&z);
        assert!(probe_blob(&blob)
            .iter()
            .any(|p| p.kind == ProbeKind::Zlib && p.offset == 17));
    }
}
