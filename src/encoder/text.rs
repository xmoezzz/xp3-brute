//! Inverse transforms for user-facing KiriKiri text normalization.
//!
//! `unpack` normalizes FE FE mode 0/1/2 storage wrappers and validated CP932
//! text to UTF-16LE with a BOM.  Repacking must restore the recorded source
//! representation before archive-level filters/checksums are applied.

use crate::xp3_meta::KirikiriTextTransformMeta;
use crate::{Error, Result};
use encoding_rs::SHIFT_JIS;
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;

fn utf16le_words(bytes: &[u8]) -> Result<Vec<u16>> {
    let body = if bytes.starts_with(&[0xff, 0xfe]) {
        &bytes[2..]
    } else {
        bytes
    };
    if body.len() % 2 != 0 {
        return Err(Error::format("UTF-16LE sidecar has an odd byte length"));
    }
    Ok(body
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn utf16le_body(bytes: &[u8]) -> Result<Vec<u8>> {
    let words = utf16le_words(bytes)?;
    let mut out = Vec::with_capacity(words.len() * 2);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

fn mode0_encode_word(plain: u16) -> Result<u16> {
    if plain < 0x20 {
        return Ok(plain);
    }
    // Invert decode: p.low = e.low ^ 1 and
    // p.high = e.high ^ (e.low & 0xfe).
    let plain_low = plain as u8;
    let plain_high = (plain >> 8) as u8;
    let encoded_low = plain_low ^ 1;
    let encoded_high = plain_high ^ (encoded_low & 0xfe);
    let encoded = u16::from_le_bytes([encoded_low, encoded_high]);

    // The engine decoder deliberately leaves encoded words below U+0020
    // untouched.  A few otherwise-valid UTF-16 code units therefore have no
    // safe FE FE mode-0 preimage.  Refuse those edits instead of emitting a
    // wrapper which decodes to different text.
    if encoded < 0x20 {
        return Err(Error::unsupported(format!(
            "UTF-16 code unit U+{plain:04X} cannot be represented reversibly in KiriKiri FE FE mode 0"
        )));
    }
    Ok(encoded)
}

fn mode1_encode_word(plain: u16) -> u16 {
    // Adjacent-bit swapping is an involution.
    ((plain & 0xaaaa) >> 1) | ((plain & 0x5555) << 1)
}

fn encode_wrapper(bytes: &[u8], mode: u8) -> Result<Vec<u8>> {
    let words = utf16le_words(bytes)?;
    let mut out = Vec::new();
    out.extend_from_slice(&[0xfe, 0xfe, mode, 0xff, 0xfe]);
    match mode {
        0 | 1 => {
            out.reserve(words.len() * 2);
            for word in words {
                let encoded = if mode == 0 {
                    mode0_encode_word(word)?
                } else {
                    mode1_encode_word(word)
                };
                out.extend_from_slice(&encoded.to_le_bytes());
            }
            Ok(out)
        }
        2 => {
            let body = utf16le_body(bytes)?;
            let raw_len = u64::try_from(body.len()).map_err(|_| {
                Error::unsupported("KiriKiri text is too large for mode-2 u64 size")
            })?;
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&body)?;
            let compressed = encoder.finish()?;
            let compressed_len = u64::try_from(compressed.len())
                .map_err(|_| Error::unsupported("KiriKiri mode-2 compressed text is too large"))?;
            out.extend_from_slice(&compressed_len.to_le_bytes());
            out.extend_from_slice(&raw_len.to_le_bytes());
            out.extend_from_slice(&compressed);
            Ok(out)
        }
        other => Err(Error::unsupported(format!(
            "unsupported KiriKiri FE FE text wrapper mode {other}"
        ))),
    }
}

fn encode_cp932(bytes: &[u8]) -> Result<Vec<u8>> {
    let words = utf16le_words(bytes)?;
    let text = String::from_utf16(&words)
        .map_err(|_| Error::format("UTF-16LE sidecar contains invalid surrogate pairs"))?;
    let (encoded, _, had_errors) = SHIFT_JIS.encode(&text);
    if had_errors {
        return Err(Error::unsupported(
            "edited UTF-16LE text contains characters that cannot be represented in CP932",
        ));
    }
    Ok(encoded.into_owned())
}

pub fn rebuild_kirikiri_text(
    sidecar_bytes: &[u8],
    transform: &KirikiriTextTransformMeta,
) -> Result<Vec<u8>> {
    if !transform.reversible_with_encoder {
        return Err(Error::unsupported(format!(
            "text transform {:?} is marked non-reversible",
            transform.source_encoding_or_wrapper
        )));
    }
    if !transform.output_encoding.eq_ignore_ascii_case("utf-16le") {
        return Err(Error::unsupported(format!(
            "text encoder expects UTF-16LE sidecars, got {:?}",
            transform.output_encoding
        )));
    }
    if let Some(mode) = transform.kirikiri_wrapper_mode {
        return encode_wrapper(sidecar_bytes, mode);
    }
    if transform
        .source_encoding_or_wrapper
        .eq_ignore_ascii_case("cp932")
    {
        return encode_cp932(sidecar_bytes);
    }
    Err(Error::unsupported(format!(
        "no inverse text encoder for {:?}",
        transform.source_encoding_or_wrapper
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::decode_kirikiri_text;

    fn utf16(text: &str) -> Vec<u8> {
        let mut out = vec![0xff, 0xfe];
        for word in text.encode_utf16() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn mode0_and_mode1_roundtrip() {
        let plain = utf16("abc 日本語\r\n");
        for mode in [0, 1] {
            let wrapped = encode_wrapper(&plain, mode).unwrap();
            assert_eq!(decode_kirikiri_text(&wrapped).unwrap(), plain);
        }
    }

    #[test]
    fn mode0_rejects_non_representable_word() {
        // U+0202 would encode to 0x0003, which the decoder intentionally
        // treats as a literal control code rather than decrypting.
        assert!(mode0_encode_word(0x0202).is_err());
    }

    #[test]
    fn mode2_roundtrip() {
        let plain = utf16("mode2 日本語\n");
        let wrapped = encode_wrapper(&plain, 2).unwrap();
        assert_eq!(decode_kirikiri_text(&wrapped).unwrap(), plain);
    }

    #[test]
    fn modified_sidecar_rebuild_preserves_mode_bom_and_line_endings() {
        let edited = utf16("edited 日本語\r\nsecond line\r\n");
        let transform = KirikiriTextTransformMeta {
            source_encoding_or_wrapper: "kirikiri-fe-fe-mode2".to_string(),
            output_encoding: "utf-16le".to_string(),
            bom_hex: "fffe".to_string(),
            output_sha256: None,
            kirikiri_wrapper_mode: Some(2),
            reversible_with_encoder: true,
        };
        let rebuilt = rebuild_kirikiri_text(&edited, &transform).unwrap();
        assert_eq!(&rebuilt[..3], &[0xfe, 0xfe, 2]);
        assert_eq!(decode_kirikiri_text(&rebuilt).unwrap(), edited);
    }
}
