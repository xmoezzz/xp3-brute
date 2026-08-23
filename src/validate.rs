use encoding_rs::SHIFT_JIS;
use flate2::read::{GzDecoder, ZlibDecoder};
use std::collections::HashMap;
use std::io::Read;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationResult {
    pub valid: bool,
    /// 0..100. Automatic extraction should prefer strong validators (>= 80).
    pub strength: u8,
    pub reason: &'static str,
}

impl ValidationResult {
    pub const fn valid(strength: u8, reason: &'static str) -> Self {
        Self {
            valid: true,
            strength,
            reason,
        }
    }

    pub const fn invalid(reason: &'static str) -> Self {
        Self {
            valid: false,
            strength: 0,
            reason,
        }
    }

    pub fn is_strong(&self) -> bool {
        self.valid && self.strength >= 80
    }
}

pub fn validate_hypothesis(name: &str, bytes: &[u8]) -> ValidationResult {
    match name {
        "PNG" => validate_png(bytes),
        "JPEG" => validate_jpeg(bytes),
        "JPEG-XR/WMP" => validate_jpeg_xr(bytes),
        "Ogg" => validate_ogg(bytes),
        "Ogg/Vorbis" => validate_vorbis(bytes),
        "Ogg/Opus" | "Ogg/Opus-family0" | "Ogg/Opus-family0-smalltags" => validate_opus(bytes),
        "WAVE/RIFF" => validate_riff(bytes, b"WAVE"),
        "AVI/RIFF" => validate_riff(bytes, b"AVI "),
        "WebP/RIFF" => validate_riff(bytes, b"WEBP"),
        "GIF87a" => validate_gif(bytes, b"GIF87a"),
        "GIF89a" => validate_gif(bytes, b"GIF89a"),
        "BMP" => validate_bmp(bytes),
        "ZIP/local" | "ZIP/empty" => validate_zip(bytes),
        "7-Zip" => validate_7z(bytes),
        "gzip" => validate_gzip(bytes),
        "Text/UTF-16LE-BOM" => validate_utf16_text(bytes, true, true),
        "Text/UTF-16LE" => validate_utf16_text(bytes, true, false),
        "Text/UTF-16BE-BOM" => validate_utf16_text(bytes, false, true),
        "Text/UTF-16BE" => validate_utf16_text(bytes, false, false),
        "Text/UTF-8-BOM" => validate_utf8_text(bytes, true),
        "Text/UTF-8" => validate_utf8_text(bytes, false),
        "Text/CP932" => validate_cp932_text(bytes),
        "Kirikiri/Text-mode0" => validate_kirikiri_text(bytes, 0),
        "Kirikiri/Text-mode1" => validate_kirikiri_text(bytes, 1),
        "Kirikiri/Text-mode2" => validate_kirikiri_text(bytes, 2),
        "TJS2/Bytecode" => validate_tjs2_bytecode(bytes),
        "KiriKiri/PBD-ns0" | "KiriKiri/PBD-4s0" => validate_pbd(bytes),
        "PSB/M2-Emote" => validate_psb(bytes),
        "PSZ/PSB-shell" => validate_psb_shell(bytes, b"PSZ"),
        "MDF/PSB-shell" => validate_psb_shell(bytes, b"mdf"),
        "MFL/PSB-shell" => validate_psb_shell(bytes, b"mfl"),
        "TrueType/sfnt" => validate_sfnt(bytes, b"\x00\x01\x00\x00"),
        "OpenType/CFF" => validate_sfnt(bytes, b"OTTO"),
        "TrueType/Collection" => validate_ttc(bytes),
        "WOFF" => validate_woff(bytes, b"wOFF"),
        "WOFF2" => validate_woff2(bytes),
        "Kirikiri/PrerenderedFont-v0" => validate_prerendered_font(bytes, Some(0)),
        "Kirikiri/PrerenderedFont-v1" => validate_prerendered_font(bytes, Some(1)),
        "FLAC" => validate_flac(bytes),
        "MP4/ISO-BMFF" => validate_iso_bmff(bytes),
        "MIDI" => validate_midi(bytes),
        "DDS" => validate_dds(bytes),
        "ICO" => validate_icon(bytes, 1),
        "CUR" => validate_icon(bytes, 2),
        "WebM/Matroska" => validate_ebml(bytes),
        "MP3/ID3" => validate_id3(bytes),
        "PE/COFF" => validate_pe(bytes),
        "ASF/WMV-WMA" => validate_asf(bytes),
        "MPEG-PS" => validate_mpeg_ps(bytes),
        "MPEG-1/Video" => validate_mpeg1_video(bytes),
        "H264/AnnexB-4" | "H264/AnnexB-3" => validate_h264_annexb(bytes),
        "Photoshop/PSD" => validate_psd(bytes),
        "TGA" => validate_tga(bytes),
        name if name.starts_with("TLG5") => validate_tlg5(bytes, 0),
        name if name.starts_with("TLG6") => validate_tlg6(bytes, 0),
        "TLG0/TLG5" => validate_tlg5(bytes, 15),
        name if name.starts_with("TLG0/TLG6") => validate_tlg6(bytes, 15),
        _ => ValidationResult::invalid("no validator"),
    }
}

fn validate_png(bytes: &[u8]) -> ValidationResult {
    const SIG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if !bytes.starts_with(SIG) {
        return ValidationResult::invalid("PNG signature mismatch");
    }

    let mut position = 8usize;
    let mut chunks = 0usize;
    while position + 12 <= bytes.len() {
        let length = u32::from_be_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        let chunk_start = position + 4;
        let Some(crc_pos) = chunk_start
            .checked_add(4)
            .and_then(|x| x.checked_add(length))
        else {
            return ValidationResult::invalid("PNG chunk length overflow");
        };
        if crc_pos + 4 > bytes.len() {
            return ValidationResult::invalid("PNG chunk exceeds file");
        }
        let kind = &bytes[chunk_start..chunk_start + 4];
        if chunks == 0 && (kind != &b"IHDR"[..] || length != 13) {
            return ValidationResult::invalid("PNG first chunk is not IHDR/13");
        }
        let expected = u32::from_be_bytes([
            bytes[crc_pos],
            bytes[crc_pos + 1],
            bytes[crc_pos + 2],
            bytes[crc_pos + 3],
        ]);
        let actual = crc32_ieee(&bytes[chunk_start..crc_pos]);
        if actual != expected {
            return ValidationResult::invalid("PNG chunk CRC mismatch");
        }
        chunks += 1;
        position = crc_pos + 4;
        if kind == &b"IEND"[..] {
            return if length == 0 && position == bytes.len() {
                ValidationResult::valid(100, "PNG grammar and CRCs valid")
            } else {
                ValidationResult::invalid("invalid PNG IEND")
            };
        }
    }
    ValidationResult::invalid("PNG missing IEND")
}

fn validate_jpeg(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 4 || !bytes.starts_with(&[0xff, 0xd8]) {
        return ValidationResult::invalid("JPEG SOI missing");
    }

    let mut pos = 2usize;
    let mut saw_sof = false;
    let mut saw_sos = false;
    let mut in_entropy = false;

    while pos < bytes.len() {
        if in_entropy {
            // Scan entropy-coded data. FF00 is byte stuffing and FFD0..D7 are
            // restart markers; any other marker exits entropy mode.
            let mut found_marker = None;
            let mut i = pos;
            while i + 1 < bytes.len() {
                if bytes[i] != 0xff {
                    i += 1;
                    continue;
                }
                let marker_pos = i;
                while i < bytes.len() && bytes[i] == 0xff {
                    i += 1;
                }
                if i >= bytes.len() {
                    return ValidationResult::invalid("JPEG entropy stream ends in marker fill");
                }
                let code = bytes[i];
                if code == 0x00 || (0xd0..=0xd7).contains(&code) {
                    i += 1;
                    continue;
                }
                found_marker = Some(marker_pos);
                break;
            }
            let Some(marker_pos) = found_marker else {
                return ValidationResult::invalid("JPEG entropy stream missing EOI");
            };
            pos = marker_pos;
            in_entropy = false;
        }

        if bytes.get(pos) != Some(&0xff) {
            return ValidationResult::invalid("JPEG marker prefix missing");
        }
        while pos < bytes.len() && bytes[pos] == 0xff {
            pos += 1;
        }
        if pos >= bytes.len() {
            return ValidationResult::invalid("JPEG truncated marker");
        }
        let marker = bytes[pos];
        pos += 1;

        match marker {
            0xd9 => {
                if !saw_sof || !saw_sos {
                    return ValidationResult::invalid("JPEG ended before frame/scan");
                }
                if bytes[pos..].iter().all(|&b| b == 0) {
                    return ValidationResult::valid(98, "JPEG marker/segment/scan grammar valid");
                }
                return ValidationResult::invalid("JPEG has non-padding bytes after EOI");
            }
            0xd8 => return ValidationResult::invalid("JPEG duplicate SOI"),
            0x01 | 0xd0..=0xd7 => {
                // TEM/restart markers carry no length. Restarts are normally
                // consumed while scanning entropy data, but accepting them here
                // keeps the parser robust to scan-boundary placement.
                continue;
            }
            _ => {}
        }

        if pos + 2 > bytes.len() {
            return ValidationResult::invalid("JPEG segment length truncated");
        }
        let length = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if length < 2 {
            return ValidationResult::invalid("JPEG segment length invalid");
        }
        let segment_start = pos + 2;
        let Some(segment_end) = pos.checked_add(length) else {
            return ValidationResult::invalid("JPEG segment length overflow");
        };
        if segment_end > bytes.len() {
            return ValidationResult::invalid("JPEG segment exceeds file");
        }

        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if length < 11 || segment_start + 6 > segment_end {
                return ValidationResult::invalid("JPEG SOF segment too short");
            }
            let height = u16::from_be_bytes([bytes[segment_start + 1], bytes[segment_start + 2]]);
            let width = u16::from_be_bytes([bytes[segment_start + 3], bytes[segment_start + 4]]);
            let components = bytes[segment_start + 5] as usize;
            if width == 0 || height == 0 || components == 0 || length != 8 + 3 * components {
                return ValidationResult::invalid("JPEG SOF dimensions/components invalid");
            }
            saw_sof = true;
        } else if marker == 0xda {
            if length < 6 || segment_start >= segment_end {
                return ValidationResult::invalid("JPEG SOS segment invalid");
            }
            let components = bytes[segment_start] as usize;
            if components == 0 || length != 6 + 2 * components {
                return ValidationResult::invalid("JPEG SOS components/length invalid");
            }
            saw_sos = true;
            in_entropy = true;
        }

        pos = segment_end;
    }

    ValidationResult::invalid("JPEG missing EOI")
}

fn validate_jpeg_xr(bytes: &[u8]) -> ValidationResult {
    if bytes.len() >= 8 && bytes.starts_with(&[0x49, 0x49, 0xbc, 0x01]) {
        // JPEG XR's WMP container is TIFF-like, but implementing its complete
        // IFD grammar is outside this recovery core for now.  Keep this below
        // the automatic-solve threshold: the signature is valuable exact key
        // evidence without being treated as independent proof of plaintext.
        ValidationResult::valid(70, "JPEG XR/WMP signature recognized")
    } else {
        ValidationResult::invalid("JPEG XR/WMP signature invalid")
    }
}

#[derive(Clone, Debug)]
struct OggPage<'a> {
    header_type: u8,
    granule: u64,
    serial: u32,
    sequence: u32,
    lacing: &'a [u8],
    body: &'a [u8],
}

fn parse_ogg_pages(bytes: &[u8]) -> std::result::Result<Vec<OggPage<'_>>, &'static str> {
    let mut pages = Vec::new();
    let mut position = 0usize;
    let mut sequences: HashMap<u32, u32> = HashMap::new();

    while position < bytes.len() {
        if position + 27 > bytes.len() {
            return Err("Ogg page header truncated");
        }
        if &bytes[position..position + 4] != b"OggS" || bytes[position + 4] != 0 {
            return Err("Ogg capture/version mismatch");
        }
        let segments = bytes[position + 26] as usize;
        let table_end = position + 27 + segments;
        if table_end > bytes.len() {
            return Err("Ogg lacing table truncated");
        }
        let lacing = &bytes[position + 27..table_end];
        let body_len: usize = lacing.iter().map(|&x| x as usize).sum();
        let Some(end) = table_end.checked_add(body_len) else {
            return Err("Ogg page length overflow");
        };
        if end > bytes.len() {
            return Err("Ogg page body truncated");
        }

        let page = &bytes[position..end];
        let expected_crc = le_u32(&bytes[position + 22..position + 26]);
        if ogg_crc32(page) != expected_crc {
            return Err("Ogg page CRC mismatch");
        }

        let serial = le_u32(&bytes[position + 14..position + 18]);
        let sequence = le_u32(&bytes[position + 18..position + 22]);
        if let Some(previous) = sequences.get(&serial) {
            if sequence != previous.wrapping_add(1) {
                return Err("Ogg page sequence discontinuity");
            }
        } else if sequence != 0 || bytes[position + 5] & 0x02 == 0 {
            return Err("Ogg logical stream does not start with BOS/sequence 0");
        }
        sequences.insert(serial, sequence);

        pages.push(OggPage {
            header_type: bytes[position + 5],
            granule: le_u64(&bytes[position + 6..position + 14]),
            serial,
            sequence,
            lacing,
            body: &bytes[table_end..end],
        });
        position = end;
    }

    if pages.is_empty() {
        Err("Ogg contains no pages")
    } else {
        Ok(pages)
    }
}

fn validate_ogg(bytes: &[u8]) -> ValidationResult {
    match parse_ogg_pages(bytes) {
        Ok(_) => ValidationResult::valid(100, "all Ogg pages, CRCs, and sequences valid"),
        Err(reason) => ValidationResult::invalid(reason),
    }
}

fn validate_vorbis(bytes: &[u8]) -> ValidationResult {
    let pages = match parse_ogg_pages(bytes) {
        Ok(pages) => pages,
        Err(reason) => return ValidationResult::invalid(reason),
    };
    let first = &pages[0];
    if first.header_type & 0x02 == 0 || first.sequence != 0 || first.granule != 0 {
        return ValidationResult::invalid("Vorbis ID page BOS/sequence/granule invalid");
    }
    if first.body.len() < 30 || !first.body.starts_with(b"\x01vorbis") {
        return ValidationResult::invalid("Vorbis identification packet missing");
    }
    let version = le_u32(&first.body[7..11]);
    let channels = first.body[11];
    let sample_rate = le_u32(&first.body[12..16]);
    if version != 0 || channels == 0 || sample_rate == 0 {
        return ValidationResult::invalid("Vorbis identification fields invalid");
    }
    if first.body[29] & 0x01 == 0 {
        return ValidationResult::invalid("Vorbis framing flag missing");
    }
    ValidationResult::valid(
        100,
        "Ogg/Vorbis pages, CRCs and identification header valid",
    )
}

fn validate_opus(bytes: &[u8]) -> ValidationResult {
    let pages = match parse_ogg_pages(bytes) {
        Ok(pages) => pages,
        Err(reason) => return ValidationResult::invalid(reason),
    };
    let first = &pages[0];
    if first.header_type & 0x02 == 0 || first.sequence != 0 || first.granule != 0 {
        return ValidationResult::invalid("Opus ID page BOS/sequence/granule invalid");
    }
    if first.lacing.is_empty() || *first.lacing.last().unwrap_or(&255) == 255 {
        return ValidationResult::invalid("OpusHead does not complete on first page");
    }
    // RFC 7845 requires the ID packet to be the only packet on the first page.
    if first.lacing[..first.lacing.len().saturating_sub(1)]
        .iter()
        .any(|&x| x < 255)
    {
        return ValidationResult::invalid("Opus ID page contains more than one packet");
    }
    if first.body.len() < 19 || !first.body.starts_with(b"OpusHead") {
        return ValidationResult::invalid("OpusHead packet missing");
    }
    let version = first.body[8];
    let channels = first.body[9] as usize;
    if version == 0 || version >= 16 || channels == 0 {
        return ValidationResult::invalid("OpusHead version/channel count invalid");
    }
    let mapping = first.body[18];
    if mapping == 0 {
        if first.body.len() != 19 || channels > 2 {
            return ValidationResult::invalid("Opus mapping-family-0 header invalid");
        }
    } else {
        let required = 21usize.saturating_add(channels);
        if first.body.len() < required {
            return ValidationResult::invalid("Opus channel mapping table truncated");
        }
    }

    // The second mandatory packet begins on the second page and starts with
    // OpusTags.  It may span multiple pages, so only its prefix is required.
    if pages.len() < 2 || !pages[1].body.starts_with(b"OpusTags") {
        return ValidationResult::invalid("OpusTags packet missing on second page");
    }
    if pages[1].serial != first.serial {
        return ValidationResult::invalid("Opus header pages use different serial numbers");
    }

    ValidationResult::valid(100, "Ogg/Opus pages, CRCs, and mandatory headers valid")
}

fn validate_riff(bytes: &[u8], form: &[u8; 4]) -> ValidationResult {
    if bytes.len() < 12 || !bytes.starts_with(b"RIFF") || &bytes[8..12] != &form[..] {
        return ValidationResult::invalid("RIFF header/form mismatch");
    }
    let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize + 8;
    if declared != bytes.len() && declared + 1 != bytes.len() {
        return ValidationResult::invalid("RIFF declared size mismatch");
    }

    let logical_end = declared.min(bytes.len());
    let mut position = 12usize;
    let mut chunks = 0usize;
    let mut wave_fmt = false;
    let mut wave_data = false;
    let mut avi_hdrl = false;
    let mut avi_movi = false;
    let mut webp_payload = false;

    while position < logical_end {
        if position + 8 > logical_end {
            return ValidationResult::invalid("RIFF truncated chunk header");
        }
        let id = &bytes[position..position + 4];
        let size = u32::from_le_bytes([
            bytes[position + 4],
            bytes[position + 5],
            bytes[position + 6],
            bytes[position + 7],
        ]) as usize;
        let payload = position + 8;
        let Some(end) = payload.checked_add(size) else {
            return ValidationResult::invalid("RIFF chunk size overflow");
        };
        if end > logical_end {
            return ValidationResult::invalid("RIFF chunk exceeds file");
        }

        if form == b"WAVE" {
            if id == b"fmt " {
                if size < 16 {
                    return ValidationResult::invalid("WAVE fmt chunk too small");
                }
                wave_fmt = true;
            } else if id == b"data" {
                wave_data = true;
            }
        } else if form == b"AVI " {
            if id == b"LIST" && size >= 4 {
                let list_type = &bytes[payload..payload + 4];
                avi_hdrl |= list_type == b"hdrl";
                avi_movi |= list_type == b"movi";
            }
        } else if form == b"WEBP" {
            webp_payload |= id == b"VP8 " || id == b"VP8L" || id == b"VP8X";
        }

        chunks += 1;
        position = end + (size & 1);
        if position > logical_end {
            return ValidationResult::invalid("RIFF padding exceeds file");
        }
    }

    if position != logical_end || chunks == 0 {
        return ValidationResult::invalid("RIFF chunk walk did not consume file");
    }
    let semantic_ok = if form == b"WAVE" {
        wave_fmt && wave_data
    } else if form == b"AVI " {
        avi_hdrl && avi_movi
    } else if form == b"WEBP" {
        webp_payload
    } else {
        false
    };
    if semantic_ok {
        ValidationResult::valid(95, "RIFF chunk grammar and required form chunks valid")
    } else {
        ValidationResult::invalid("RIFF required form chunks missing")
    }
}

fn skip_gif_sub_blocks(bytes: &[u8], mut position: usize) -> Option<usize> {
    loop {
        let &size = bytes.get(position)?;
        position += 1;
        if size == 0 {
            return Some(position);
        }
        position = position.checked_add(size as usize)?;
        if position > bytes.len() {
            return None;
        }
    }
}

fn validate_gif(bytes: &[u8], signature: &[u8; 6]) -> ValidationResult {
    if bytes.len() < 14 || !bytes.starts_with(signature) {
        return ValidationResult::invalid("GIF signature invalid");
    }
    let width = u16::from_le_bytes([bytes[6], bytes[7]]);
    let height = u16::from_le_bytes([bytes[8], bytes[9]]);
    if width == 0 || height == 0 {
        return ValidationResult::invalid("GIF logical screen dimensions invalid");
    }

    let packed = bytes[10];
    let mut position = 13usize;
    if packed & 0x80 != 0 {
        let entries = 1usize << (((packed & 0x07) as usize) + 1);
        position = match position.checked_add(entries * 3) {
            Some(value) if value <= bytes.len() => value,
            _ => return ValidationResult::invalid("GIF global color table exceeds file"),
        };
    }

    let mut images = 0usize;
    let mut blocks = 0usize;
    loop {
        let Some(&introducer) = bytes.get(position) else {
            return ValidationResult::invalid("GIF missing trailer");
        };
        match introducer {
            0x3b => {
                if position + 1 != bytes.len() || images == 0 {
                    return ValidationResult::invalid("GIF trailer position/image count invalid");
                }
                return ValidationResult::valid(98, "GIF block grammar consumed complete file");
            }
            0x21 => {
                // Extension introducer + label, followed by a sequence of data sub-blocks.
                if position + 2 > bytes.len() {
                    return ValidationResult::invalid("GIF truncated extension");
                }
                position = match skip_gif_sub_blocks(bytes, position + 2) {
                    Some(value) => value,
                    None => return ValidationResult::invalid("GIF extension sub-block invalid"),
                };
            }
            0x2c => {
                // Image descriptor is 10 bytes including the 0x2c introducer.
                if position + 10 > bytes.len() {
                    return ValidationResult::invalid("GIF truncated image descriptor");
                }
                let image_width = u16::from_le_bytes([bytes[position + 5], bytes[position + 6]]);
                let image_height = u16::from_le_bytes([bytes[position + 7], bytes[position + 8]]);
                if image_width == 0 || image_height == 0 {
                    return ValidationResult::invalid("GIF image dimensions invalid");
                }
                let image_packed = bytes[position + 9];
                position += 10;
                if image_packed & 0x80 != 0 {
                    let entries = 1usize << (((image_packed & 0x07) as usize) + 1);
                    position = match position.checked_add(entries * 3) {
                        Some(value) if value <= bytes.len() => value,
                        _ => {
                            return ValidationResult::invalid("GIF local color table exceeds file")
                        }
                    };
                }
                let Some(&lzw_min_code_size) = bytes.get(position) else {
                    return ValidationResult::invalid("GIF missing LZW code size");
                };
                if !(2..=8).contains(&lzw_min_code_size) {
                    return ValidationResult::invalid("GIF LZW code size invalid");
                }
                position = match skip_gif_sub_blocks(bytes, position + 1) {
                    Some(value) => value,
                    None => return ValidationResult::invalid("GIF image data sub-block invalid"),
                };
                images += 1;
            }
            _ => return ValidationResult::invalid("GIF invalid block introducer"),
        }
        blocks += 1;
        if blocks > bytes.len() {
            return ValidationResult::invalid("GIF block walk did not converge");
        }
    }
}

fn plausible_text_char(ch: char) -> bool {
    matches!(ch, '\n' | '\r' | '\t')
        || (!ch.is_control()
            && !matches!(ch, '\u{fffe}' | '\u{ffff}')
            && !(('\u{e000}'..='\u{f8ff}').contains(&ch)))
}

fn validate_decoded_text(text: &str) -> ValidationResult {
    let total = text.chars().count();
    if total < 4 {
        return ValidationResult::invalid("text too short");
    }

    let mut plausible = 0usize;
    let mut controls = 0usize;
    let mut ascii_signal = 0usize;
    let mut structural = 0usize;
    let mut whitespace = 0usize;
    let mut replacement = 0usize;

    for ch in text.chars() {
        plausible += if plausible_text_char(ch) { 1 } else { 0 };
        controls += if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
            1
        } else {
            0
        };
        replacement += if ch == '\u{fffd}' { 1 } else { 0 };
        if ch.is_ascii_alphanumeric() || ch.is_ascii_whitespace() {
            ascii_signal += 1;
        }
        if matches!(
            ch,
            '{' | '}'
                | '['
                | ']'
                | '('
                | ')'
                | ';'
                | '='
                | ','
                | '.'
                | '@'
                | '/'
                | '*'
                | '+'
                | '-'
                | '_'
                | '<'
                | '>'
                | '"'
                | '\''
                | '\\'
                | ':'
                | '#'
                | '$'
                | '%'
                | '&'
                | '|'
                | '!'
                | '?'
        ) {
            structural += 1;
        }
        whitespace += if matches!(ch, ' ' | '\n' | '\r' | '\t') {
            1
        } else {
            0
        };
    }

    if controls != 0 || replacement != 0 || plausible * 100 < total * 98 {
        return ValidationResult::invalid("decoded text contains invalid/control characters");
    }

    // A valid Unicode decoding alone is far too weak: a wrong XOR key can
    // easily turn random bytes into syntactically valid CJK code points.  TJS,
    // KAG/KS, INI, CSV and related KiriKiri resources always carry a measurable
    // amount of ASCII syntax, identifiers, whitespace, or line structure.
    let ascii_pct = ascii_signal * 100 / total;
    let structure_pct = (structural + whitespace) * 100 / total;
    let has_line_structure = text.contains('\n') || text.contains('\r');
    let strong_signal = if total < 32 {
        ascii_pct >= 20 || structural >= 2
    } else {
        ascii_pct >= 8 || structure_pct >= 6 || (has_line_structure && ascii_pct >= 5)
    };

    if strong_signal {
        ValidationResult::valid(95, "text encoding and script-like structure valid")
    } else {
        ValidationResult::invalid("decoded text lacks TJS/KAG/text structural signal")
    }
}

fn validate_utf16_text(bytes: &[u8], little_endian: bool, require_bom: bool) -> ValidationResult {
    let bom = if little_endian {
        [0xff, 0xfe]
    } else {
        [0xfe, 0xff]
    };
    let start = if bytes.starts_with(&bom) {
        2
    } else if require_bom {
        return ValidationResult::invalid("UTF-16 BOM missing");
    } else {
        0
    };
    if bytes.len().saturating_sub(start) < 4 || (bytes.len() - start) % 2 != 0 {
        return ValidationResult::invalid("UTF-16 length invalid");
    }
    let units: Vec<u16> = bytes[start..]
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    let Ok(text) = String::from_utf16(&units) else {
        return ValidationResult::invalid("UTF-16 contains invalid surrogate sequence");
    };
    validate_decoded_text(&text)
}

fn validate_utf8_text(bytes: &[u8], require_bom: bool) -> ValidationResult {
    let start = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        3
    } else if require_bom {
        return ValidationResult::invalid("UTF-8 BOM missing");
    } else {
        0
    };
    let Ok(text) = std::str::from_utf8(&bytes[start..]) else {
        return ValidationResult::invalid("UTF-8 decoding failed");
    };
    validate_decoded_text(text)
}

fn validate_cp932_text(bytes: &[u8]) -> ValidationResult {
    if bytes.is_empty() {
        return ValidationResult::invalid("CP932 text empty");
    }
    let (text, had_errors) = SHIFT_JIS.decode_without_bom_handling(bytes);
    if had_errors {
        return ValidationResult::invalid("CP932/Shift-JIS decoding failed");
    }
    validate_decoded_text(&text)
}

fn decoded_text_bytes_are_plausible(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return validate_utf16_text(bytes, true, true).is_strong();
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return validate_utf16_text(bytes, false, true).is_strong();
    }
    if validate_utf8_text(bytes, false).is_strong() {
        return true;
    }
    validate_cp932_text(bytes).is_strong()
}

/// Decode KiriKiri's standard FE FE text wrappers.  The returned bytes are the
/// user-facing text payload, not the encrypted/XOR storage stream.  Validation
/// and XP3 adlr checks must be performed on the wrapper before this transform.
pub fn decode_kirikiri_text(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 5 || bytes[0..2] != [0xfe, 0xfe] || bytes[3..5] != [0xff, 0xfe] {
        return None;
    }
    match bytes[2] {
        0 | 1 => {
            if (bytes.len() - 5) % 2 != 0 {
                return None;
            }
            let mut decoded = Vec::with_capacity(bytes.len() - 3);
            decoded.extend_from_slice(&[0xff, 0xfe]);
            for pair in bytes[5..].chunks_exact(2) {
                let mut ch = u16::from_le_bytes([pair[0], pair[1]]);
                if bytes[2] == 1 {
                    ch = ((ch & 0xaaaa) >> 1) | ((ch & 0x5555) << 1);
                } else if ch >= 0x20 {
                    ch ^= ((ch & 0x00fe) << 8) ^ 1;
                }
                decoded.extend_from_slice(&ch.to_le_bytes());
            }
            Some(decoded)
        }
        2 => {
            if bytes.len() < 21 {
                return None;
            }
            let compressed =
                usize::try_from(u64::from_le_bytes(bytes[5..13].try_into().ok()?)).ok()?;
            let uncompressed =
                usize::try_from(u64::from_le_bytes(bytes[13..21].try_into().ok()?)).ok()?;
            if uncompressed > (1usize << 30) || 21usize.checked_add(compressed)? != bytes.len() {
                return None;
            }
            let mut decoder = ZlibDecoder::new(&bytes[21..]);
            let mut body = Vec::with_capacity(uncompressed.min(16 * 1024 * 1024));
            decoder.read_to_end(&mut body).ok()?;
            if body.len() != uncompressed {
                return None;
            }

            // KiriKiri writes the UTF-16LE BOM outside the mode-2 zlib stream:
            // FE FE 02 | FF FE | compressed_size | uncompressed_size | zlib(body).
            // The size fields therefore describe only the UTF-16LE body. Restore
            // the consumed BOM for a normal user-facing Unicode text file.
            if body.starts_with(&[0xff, 0xfe]) {
                Some(body)
            } else {
                let mut decoded = Vec::with_capacity(body.len().saturating_add(2));
                decoded.extend_from_slice(&[0xff, 0xfe]);
                decoded.extend_from_slice(&body);
                Some(decoded)
            }
        }
        _ => None,
    }
}

fn validate_kirikiri_text(bytes: &[u8], expected_mode: u8) -> ValidationResult {
    if bytes.len() < 5
        || bytes[0..2] != [0xfe, 0xfe]
        || bytes[2] != expected_mode
        || bytes[3..5] != [0xff, 0xfe]
    {
        return ValidationResult::invalid("KiriKiri text header/mode/BOM mismatch");
    }
    let Some(decoded) = decode_kirikiri_text(bytes) else {
        return ValidationResult::invalid("KiriKiri text decoding failed");
    };
    if decoded_text_bytes_are_plausible(&decoded) {
        let strength = if expected_mode == 2 { 100 } else { 98 };
        ValidationResult::valid(
            strength,
            "KiriKiri text wrapper fully decodes and validates",
        )
    } else {
        ValidationResult::invalid("KiriKiri text output implausible")
    }
}

fn tjs2_read_u32(bytes: &[u8], position: &mut usize) -> Option<u32> {
    let end = position.checked_add(4)?;
    let chunk = bytes.get(*position..end)?;
    *position = end;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn tjs2_skip(bytes: &[u8], position: &mut usize, count: usize) -> bool {
    let Some(end) = position.checked_add(count) else {
        return false;
    };
    if end > bytes.len() {
        return false;
    }
    *position = end;
    true
}

fn tjs2_align4(bytes: &[u8], position: &mut usize) -> bool {
    let aligned = (*position + 3) & !3;
    if aligned > bytes.len() {
        return false;
    }
    *position = aligned;
    true
}

fn validate_tjs2_data_payload(bytes: &[u8]) -> bool {
    let mut pos = 0usize;

    // byte pool + 4-byte alignment
    let Some(count) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
        return false;
    };
    if !tjs2_skip(bytes, &mut pos, count) || !tjs2_align4(bytes, &mut pos) {
        return false;
    }

    // short pool + one u16 pad when the count is odd
    let Some(count) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
        return false;
    };
    let Some(size) = count.checked_mul(2) else {
        return false;
    };
    if !tjs2_skip(bytes, &mut pos, size) {
        return false;
    }
    if count & 1 != 0 && !tjs2_skip(bytes, &mut pos, 2) {
        return false;
    }

    // int, long and double pools
    for width in [4usize, 8, 8] {
        let Some(count) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
            return false;
        };
        let Some(size) = count.checked_mul(width) else {
            return false;
        };
        if !tjs2_skip(bytes, &mut pos, size) {
            return false;
        }
    }

    // UTF-16LE string pool.  Verify surrogate correctness instead of merely
    // trusting lengths, then consume the 2-byte pad used for odd unit counts.
    let Some(string_count) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
        return false;
    };
    if string_count > bytes.len() / 4 {
        return false;
    }
    for _ in 0..string_count {
        let Some(len) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
            return false;
        };
        let Some(byte_len) = len.checked_mul(2) else {
            return false;
        };
        let Some(end) = pos.checked_add(byte_len) else {
            return false;
        };
        let Some(raw) = bytes.get(pos..end) else {
            return false;
        };
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if String::from_utf16(&units).is_err() {
            return false;
        }
        pos = end;
        if len & 1 != 0 && !tjs2_skip(bytes, &mut pos, 2) {
            return false;
        }
    }

    // octet pool, each element individually aligned to 4 bytes.
    let Some(octet_count) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
        return false;
    };
    if octet_count > bytes.len() / 4 {
        return false;
    }
    for _ in 0..octet_count {
        let Some(len) = tjs2_read_u32(bytes, &mut pos).map(|v| v as usize) else {
            return false;
        };
        if !tjs2_skip(bytes, &mut pos, len) || !tjs2_align4(bytes, &mut pos) {
            return false;
        }
    }

    pos == bytes.len()
}

fn validate_pbd(bytes: &[u8]) -> ValidationResult {
    match crate::decoder::pbd::decode_pbd(bytes) {
        Ok(_) => ValidationResult::valid(100, "PBD typed stream and wrapper valid"),
        Err(_) => ValidationResult::invalid("PBD structural validation failed"),
    }
}

fn validate_tjs2_bytecode(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 28 || !bytes.starts_with(b"TJS2100\0") {
        return ValidationResult::invalid("TJS2 bytecode header invalid");
    }
    let declared = le_u32(&bytes[8..12]) as usize;
    if declared != bytes.len() || &bytes[12..16] != b"DATA" {
        return ValidationResult::invalid("TJS2 bytecode size/DATA tag invalid");
    }
    let data_size = le_u32(&bytes[16..20]) as usize;
    if data_size < 8 {
        return ValidationResult::invalid("TJS2 DATA chunk too small");
    }
    let Some(data_end) = 12usize.checked_add(data_size) else {
        return ValidationResult::invalid("TJS2 DATA chunk size overflow");
    };
    if data_end + 8 > bytes.len() || &bytes[data_end..data_end + 4] != b"OBJS" {
        return ValidationResult::invalid("TJS2 OBJS chunk missing/out of range");
    }
    if !validate_tjs2_data_payload(&bytes[20..data_end]) {
        return ValidationResult::invalid("TJS2 DATA constant-pool grammar invalid");
    }

    let objs_size = le_u32(&bytes[data_end + 4..data_end + 8]) as usize;
    if objs_size < 16 {
        return ValidationResult::invalid("TJS2 OBJS chunk too small");
    }
    let Some(objs_end) = data_end.checked_add(objs_size) else {
        return ValidationResult::invalid("TJS2 OBJS chunk size overflow");
    };
    if objs_end != bytes.len() {
        return ValidationResult::invalid("TJS2 chunk layout/trailing bytes invalid");
    }
    let payload = &bytes[data_end + 8..objs_end];
    if payload.len() < 8 {
        return ValidationResult::invalid("TJS2 OBJS header truncated");
    }
    let toplevel = i32::from_le_bytes(payload[0..4].try_into().unwrap());
    let object_count = i32::from_le_bytes(payload[4..8].try_into().unwrap());
    if object_count < 0 || (object_count == 0 && payload.len() != 8) {
        return ValidationResult::invalid("TJS2 OBJS object count/payload invalid");
    }
    if object_count > 0 {
        if payload.len() < 16 || &payload[8..12] != b"TJS2" {
            return ValidationResult::invalid("TJS2 first object tag missing");
        }
        if toplevel < -1 || toplevel >= object_count {
            return ValidationResult::invalid("TJS2 toplevel object index invalid");
        }
    }

    ValidationResult::valid(100, "TJS2100 header, DATA pools and OBJS layout valid")
}

fn validate_bmp(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 14 || !bytes.starts_with(b"BM") {
        return ValidationResult::invalid("BMP signature invalid");
    }
    let declared = le_u32(&bytes[2..6]) as usize;
    let pixel_offset = le_u32(&bytes[10..14]) as usize;
    if declared == bytes.len() && (14..=bytes.len()).contains(&pixel_offset) {
        ValidationResult::valid(85, "BMP size and pixel offset valid")
    } else {
        ValidationResult::invalid("BMP size/offset invalid")
    }
}

fn validate_zip(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 4 || !bytes.starts_with(b"PK") {
        return ValidationResult::invalid("ZIP signature invalid");
    }
    let start = bytes.len().saturating_sub(65_557);
    let found_eocd = bytes[start..]
        .windows(4)
        .rposition(|window| window == &b"PK\x05\x06"[..])
        .map(|relative| start + relative);
    let Some(position) = found_eocd else {
        return ValidationResult::invalid("ZIP EOCD not found");
    };
    if position + 22 > bytes.len() {
        return ValidationResult::invalid("ZIP EOCD truncated");
    }
    let comment_len = u16::from_le_bytes([bytes[position + 20], bytes[position + 21]]) as usize;
    if position + 22 + comment_len == bytes.len() {
        ValidationResult::valid(90, "ZIP EOCD structurally valid")
    } else {
        ValidationResult::invalid("ZIP EOCD/comment size mismatch")
    }
}

fn validate_7z(bytes: &[u8]) -> ValidationResult {
    const SIG: &[u8] = &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
    if bytes.len() < 32 || !bytes.starts_with(SIG) {
        return ValidationResult::invalid("7z signature invalid");
    }
    let expected_start_crc = le_u32(&bytes[8..12]);
    if crc32_ieee(&bytes[12..32]) != expected_start_crc {
        return ValidationResult::invalid("7z start-header CRC mismatch");
    }
    let next_offset = le_u64(&bytes[12..20]);
    let next_size = le_u64(&bytes[20..28]);
    let Some(next_end) = 32u64
        .checked_add(next_offset)
        .and_then(|x| x.checked_add(next_size))
    else {
        return ValidationResult::invalid("7z next-header offset overflow");
    };
    if next_end > bytes.len() as u64 {
        return ValidationResult::invalid("7z next header outside file");
    }
    ValidationResult::valid(95, "7z start-header CRC and bounds valid")
}

fn validate_gzip(bytes: &[u8]) -> ValidationResult {
    if !bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        return ValidationResult::invalid("gzip signature invalid");
    }
    let mut decoder = GzDecoder::new(bytes);
    let mut sink = Vec::new();
    match decoder.read_to_end(&mut sink) {
        Ok(_) => ValidationResult::valid(100, "gzip decompression and trailer valid"),
        Err(_) => ValidationResult::invalid("gzip decompression failed"),
    }
}

fn read_le_width(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    if width == 0 || width > 8 || offset.checked_add(width)? > bytes.len() {
        return None;
    }
    let mut value = 0u64;
    for i in 0..width {
        value |= (bytes[offset + i] as u64) << (i * 8);
    }
    Some(value)
}

fn parse_psb_array(bytes: &[u8], offset: usize) -> Option<(Vec<u64>, usize)> {
    let count_width = (*bytes.get(offset)?).checked_sub(0x0c)? as usize;
    if !(1..=8).contains(&count_width) {
        return None;
    }
    let count = read_le_width(bytes, offset + 1, count_width)?;
    if count > 10_000_000 {
        return None;
    }
    let width_tag_offset = offset.checked_add(1 + count_width)?;
    let entry_width = (*bytes.get(width_tag_offset)?).checked_sub(0x0c)? as usize;
    if !(1..=8).contains(&entry_width) {
        return None;
    }
    let data_offset = width_tag_offset + 1;
    let byte_len = usize::try_from(count).ok()?.checked_mul(entry_width)?;
    let end = data_offset.checked_add(byte_len)?;
    if end > bytes.len() {
        return None;
    }
    let mut values = Vec::with_capacity(usize::try_from(count).ok()?);
    for i in 0..usize::try_from(count).ok()? {
        values.push(read_le_width(
            bytes,
            data_offset + i * entry_width,
            entry_width,
        )?);
    }
    Some((values, end))
}

fn validate_psb_shell(bytes: &[u8], signature: &[u8]) -> ValidationResult {
    if bytes.len() >= signature.len() && bytes.starts_with(signature) {
        // Recognition only. PSZ/MDF shell compression/encryption must be
        // removed before the inner PSB grammar can prove the payload.
        ValidationResult::valid(65, "PSB-family shell signature recognized")
    } else {
        ValidationResult::invalid("PSB-family shell signature invalid")
    }
}

fn validate_psb(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 40 || !bytes.starts_with(b"PSB\0") {
        return ValidationResult::invalid("PSB signature/header invalid");
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if !(1..=4).contains(&version) {
        return ValidationResult::invalid("PSB version implausible");
    }
    let header_size = if version >= 3 { 44usize } else { 40usize };
    if bytes.len() < header_size {
        return ValidationResult::invalid("PSB versioned header truncated");
    }

    let offset_encrypt = le_u32(&bytes[8..12]) as usize;
    let offset_names = le_u32(&bytes[12..16]) as usize;
    let offset_strings = le_u32(&bytes[16..20]) as usize;
    let offset_strings_data = le_u32(&bytes[20..24]) as usize;
    let offset_chunk_offsets = le_u32(&bytes[24..28]) as usize;
    let offset_chunk_lengths = le_u32(&bytes[28..32]) as usize;
    let offset_chunk_data = le_u32(&bytes[32..36]) as usize;
    let offset_entries = le_u32(&bytes[36..40]) as usize;
    let offsets = [
        offset_encrypt,
        offset_names,
        offset_strings,
        offset_strings_data,
        offset_chunk_offsets,
        offset_chunk_lengths,
        offset_chunk_data,
        offset_entries,
    ];
    if offsets
        .iter()
        .any(|&offset| offset < header_size || offset >= bytes.len())
    {
        return ValidationResult::invalid("PSB section offset outside file/header");
    }
    if offset_encrypt != offset_names {
        return ValidationResult::invalid("PSB encryption/name offsets disagree");
    }
    if version >= 3 {
        let emote = le_u32(&bytes[40..44]) as usize;
        if emote != 0 && (emote < header_size || emote >= bytes.len()) {
            return ValidationResult::invalid("PSB emote offset outside file");
        }
    }

    // The name trie is three packed arrays back-to-back in the historical M2
    // PSB layout used by KrkrExtract.
    let Some((_name1, name2_offset)) = parse_psb_array(bytes, offset_names) else {
        return ValidationResult::invalid("PSB name array 1 invalid");
    };
    let Some((_name2, name3_offset)) = parse_psb_array(bytes, name2_offset) else {
        return ValidationResult::invalid("PSB name array 2 invalid");
    };
    let Some((_name3, name_end)) = parse_psb_array(bytes, name3_offset) else {
        return ValidationResult::invalid("PSB name array 3 invalid");
    };
    if name_end > offset_strings {
        return ValidationResult::invalid("PSB name arrays overlap strings table");
    }

    let Some((string_offsets, string_end)) = parse_psb_array(bytes, offset_strings) else {
        return ValidationResult::invalid("PSB strings offset array invalid");
    };
    if string_end > offset_strings_data {
        return ValidationResult::invalid("PSB string offset array overlaps string data");
    }
    let string_data_end = [
        offset_chunk_offsets,
        offset_chunk_lengths,
        offset_chunk_data,
        offset_entries,
    ]
    .into_iter()
    .filter(|&offset| offset >= offset_strings_data)
    .min()
    .unwrap_or(bytes.len());
    let string_data_len = string_data_end.saturating_sub(offset_strings_data) as u64;
    if string_offsets
        .iter()
        .any(|&offset| offset > string_data_len)
    {
        return ValidationResult::invalid("PSB string offset outside string-data section");
    }

    let Some((chunk_offsets, chunk_offsets_end)) = parse_psb_array(bytes, offset_chunk_offsets)
    else {
        return ValidationResult::invalid("PSB chunk-offset array invalid");
    };
    let Some((chunk_lengths, chunk_lengths_end)) = parse_psb_array(bytes, offset_chunk_lengths)
    else {
        return ValidationResult::invalid("PSB chunk-length array invalid");
    };
    if chunk_offsets.len() != chunk_lengths.len() {
        return ValidationResult::invalid("PSB chunk offset/length counts disagree");
    }
    if chunk_offsets_end > bytes.len() || chunk_lengths_end > bytes.len() {
        return ValidationResult::invalid("PSB chunk metadata exceeds file");
    }
    for (&offset, &length) in chunk_offsets.iter().zip(&chunk_lengths) {
        let Some(end) = offset.checked_add(length) else {
            return ValidationResult::invalid("PSB chunk range overflow");
        };
        if end > bytes.len().saturating_sub(offset_chunk_data) as u64 {
            return ValidationResult::invalid("PSB chunk range outside chunk-data section");
        }
    }

    let Some(&root_type) = bytes.get(offset_entries) else {
        return ValidationResult::invalid("PSB entries offset invalid");
    };
    if root_type != 0x20 && root_type != 0x21 {
        return ValidationResult::invalid("PSB root is not a collection/object");
    }

    ValidationResult::valid(
        98,
        "PSB/M2 header, packed arrays, chunks, and root object valid",
    )
}

fn be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}
fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
fn be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn validate_sfnt_at(bytes: &[u8], base: usize, expected: Option<&[u8; 4]>) -> bool {
    if base.checked_add(12).is_none() || base + 12 > bytes.len() {
        return false;
    }
    if let Some(signature) = expected {
        if &bytes[base..base + 4] != signature {
            return false;
        }
    } else if &bytes[base..base + 4] != b"\0\x01\0\0" && &bytes[base..base + 4] != b"OTTO" {
        return false;
    }
    let count = be_u16(&bytes[base + 4..base + 6]) as usize;
    if count == 0 || count > 4096 || base + 12 + count * 16 > bytes.len() {
        return false;
    }
    let mut has_head = false;
    let mut has_cmap = false;
    let mut has_maxp = false;
    for i in 0..count {
        let record = base + 12 + i * 16;
        let tag = &bytes[record..record + 4];
        let offset = be_u32(&bytes[record + 8..record + 12]) as usize;
        let length = be_u32(&bytes[record + 12..record + 16]) as usize;
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        if offset < base || end > bytes.len() {
            return false;
        }
        if tag == b"head" {
            has_head = true;
            if length < 16
                || offset + 16 > bytes.len()
                || be_u32(&bytes[offset + 12..offset + 16]) != 0x5f0f3cf5
            {
                return false;
            }
        } else if tag == b"cmap" {
            has_cmap = true;
        } else if tag == b"maxp" {
            has_maxp = true;
        }
    }
    has_head && has_cmap && has_maxp
}

fn validate_sfnt(bytes: &[u8], signature: &[u8; 4]) -> ValidationResult {
    if validate_sfnt_at(bytes, 0, Some(signature)) {
        ValidationResult::valid(98, "sfnt table directory and required tables valid")
    } else {
        ValidationResult::invalid("sfnt grammar invalid")
    }
}

fn validate_ttc(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 12 || !bytes.starts_with(b"ttcf") {
        return ValidationResult::invalid("TTC header invalid");
    }
    let count = be_u32(&bytes[8..12]) as usize;
    if count == 0 || count > 1024 || 12 + count * 4 > bytes.len() {
        return ValidationResult::invalid("TTC font count invalid");
    }
    for i in 0..count {
        let offset = be_u32(&bytes[12 + i * 4..16 + i * 4]) as usize;
        if !validate_sfnt_at(bytes, offset, None) {
            return ValidationResult::invalid("TTC member sfnt invalid");
        }
    }
    ValidationResult::valid(98, "TTC header and member sfnt tables valid")
}

fn validate_woff(bytes: &[u8], signature: &[u8; 4]) -> ValidationResult {
    if bytes.len() < 44 || &bytes[..4] != signature || be_u32(&bytes[8..12]) as usize != bytes.len()
    {
        return ValidationResult::invalid("WOFF header/length invalid");
    }
    let count = be_u16(&bytes[12..14]) as usize;
    if count == 0 || count > 4096 || 44 + count * 20 > bytes.len() {
        return ValidationResult::invalid("WOFF table directory invalid");
    }
    for i in 0..count {
        let p = 44 + i * 20;
        let offset = be_u32(&bytes[p + 4..p + 8]) as usize;
        let compressed = be_u32(&bytes[p + 8..p + 12]) as usize;
        let original = be_u32(&bytes[p + 12..p + 16]) as usize;
        if compressed == 0
            || compressed > original
            || offset.checked_add(compressed).is_none()
            || offset + compressed > bytes.len()
        {
            return ValidationResult::invalid("WOFF table range invalid");
        }
    }
    ValidationResult::valid(95, "WOFF header and table ranges valid")
}

fn validate_woff2(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 48
        || !bytes.starts_with(b"wOF2")
        || be_u32(&bytes[8..12]) as usize != bytes.len()
    {
        return ValidationResult::invalid("WOFF2 header/length invalid");
    }
    let count = be_u16(&bytes[12..14]);
    if count == 0 {
        return ValidationResult::invalid("WOFF2 has no tables");
    }
    ValidationResult::valid(
        75,
        "WOFF2 header recognized; compressed directory not fully validated",
    )
}

fn validate_prerendered_font(bytes: &[u8], expected_version: Option<u8>) -> ValidationResult {
    const MAGIC: &[u8] = b"TVP pre-rendered font\x1a";
    const HEADER_SIZE: usize = 36;
    const ITEM_SIZE: usize = 20;

    if bytes.len() < HEADER_SIZE || !bytes.starts_with(MAGIC) {
        return ValidationResult::invalid("KiriKiri pre-rendered font signature/header invalid");
    }

    let version = bytes[22];
    if !matches!(version, 0 | 1) || expected_version.is_some_and(|expected| expected != version) {
        return ValidationResult::invalid("KiriKiri pre-rendered font version invalid");
    }
    if bytes[23] != 2 {
        return ValidationResult::invalid("KiriKiri pre-rendered font is not 16-bit Unicode");
    }

    let count = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
    let char_index = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
    let glyph_index = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    if count == 0 {
        return ValidationResult::invalid("KiriKiri pre-rendered font has empty character index");
    }

    let Some(char_index_size) = count.checked_mul(2) else {
        return ValidationResult::invalid("KiriKiri pre-rendered font character index overflow");
    };
    let Some(glyph_index_size) = count.checked_mul(ITEM_SIZE) else {
        return ValidationResult::invalid("KiriKiri pre-rendered font glyph index overflow");
    };
    let Some(char_index_end) = char_index.checked_add(char_index_size) else {
        return ValidationResult::invalid("KiriKiri pre-rendered font character index overflow");
    };
    let Some(glyph_index_end) = glyph_index.checked_add(glyph_index_size) else {
        return ValidationResult::invalid("KiriKiri pre-rendered font glyph index overflow");
    };
    if char_index < HEADER_SIZE
        || glyph_index < HEADER_SIZE
        || char_index_end > bytes.len()
        || glyph_index_end > bytes.len()
    {
        return ValidationResult::invalid("KiriKiri pre-rendered font index outside file");
    }

    let chars = &bytes[char_index..char_index_end];
    let mut previous = None;
    for pair in chars.chunks_exact(2) {
        let ch = u16::from_le_bytes([pair[0], pair[1]]);
        if previous.is_some_and(|prev| ch <= prev) {
            return ValidationResult::invalid(
                "KiriKiri pre-rendered font character index is not sorted",
            );
        }
        previous = Some(ch);
    }

    for item in bytes[glyph_index..glyph_index_end].chunks_exact(ITEM_SIZE) {
        let offset = u32::from_le_bytes(item[0..4].try_into().unwrap()) as usize;
        let width = u16::from_le_bytes(item[4..6].try_into().unwrap());
        let height = u16::from_le_bytes(item[6..8].try_into().unwrap());
        if width != 0 && height != 0 && (offset < HEADER_SIZE || offset >= bytes.len()) {
            return ValidationResult::invalid(
                "KiriKiri pre-rendered font glyph bitmap offset outside file",
            );
        }
    }

    ValidationResult::valid(100, "KiriKiri pre-rendered font header and indexes valid")
}

fn validate_flac(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 8 || !bytes.starts_with(b"fLaC") {
        return ValidationResult::invalid("FLAC signature invalid");
    }
    let mut pos = 4usize;
    let mut index = 0usize;
    let mut saw_last = false;
    while pos + 4 <= bytes.len() {
        let header = bytes[pos];
        let block_type = header & 0x7f;
        let last = header & 0x80 != 0;
        let len = ((bytes[pos + 1] as usize) << 16)
            | ((bytes[pos + 2] as usize) << 8)
            | bytes[pos + 3] as usize;
        pos += 4;
        if index == 0 && (block_type != 0 || len != 34) {
            return ValidationResult::invalid("FLAC first metadata block is not STREAMINFO/34");
        }
        if block_type == 127 || pos.checked_add(len).is_none() || pos + len > bytes.len() {
            return ValidationResult::invalid("FLAC metadata block invalid");
        }
        pos += len;
        index += 1;
        if last {
            saw_last = true;
            break;
        }
        if index > 1024 {
            return ValidationResult::invalid("FLAC metadata chain implausibly long");
        }
    }
    if !saw_last || pos >= bytes.len() {
        return ValidationResult::invalid("FLAC metadata chain/audio payload incomplete");
    }
    ValidationResult::valid(95, "FLAC STREAMINFO and metadata chain valid")
}

fn validate_iso_bmff(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 16 || &bytes[4..8] != b"ftyp" {
        return ValidationResult::invalid("ISO-BMFF ftyp box missing");
    }
    let mut pos = 0usize;
    let mut boxes = 0usize;
    let mut saw_ftyp = false;
    let mut saw_moov = false;
    let mut saw_mdat = false;
    let mut saw_moof = false;
    while pos < bytes.len() {
        if pos + 8 > bytes.len() {
            return ValidationResult::invalid("ISO-BMFF trailing box header truncated");
        }
        let size32 = be_u32(&bytes[pos..pos + 4]) as u64;
        let kind = &bytes[pos + 4..pos + 8];
        let (header, size) = if size32 == 1 {
            if pos + 16 > bytes.len() {
                return ValidationResult::invalid("ISO-BMFF extended box truncated");
            }
            (16usize, be_u64(&bytes[pos + 8..pos + 16]))
        } else if size32 == 0 {
            (8usize, (bytes.len() - pos) as u64)
        } else {
            (8usize, size32)
        };
        if size < header as u64 || size > usize::MAX as u64 {
            return ValidationResult::invalid("ISO-BMFF box size invalid");
        }
        let end = match pos.checked_add(size as usize) {
            Some(end) if end <= bytes.len() => end,
            _ => return ValidationResult::invalid("ISO-BMFF box exceeds file"),
        };
        saw_ftyp |= kind == b"ftyp";
        saw_moov |= kind == b"moov";
        saw_mdat |= kind == b"mdat";
        saw_moof |= kind == b"moof";
        boxes += 1;
        pos = end;
        if boxes > 100_000 {
            return ValidationResult::invalid("ISO-BMFF box count implausible");
        }
    }
    if saw_ftyp && saw_moov && (saw_mdat || saw_moof) {
        ValidationResult::valid(95, "ISO-BMFF top-level box grammar valid")
    } else {
        ValidationResult::invalid("ISO-BMFF required boxes missing")
    }
}

fn validate_midi(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 14 || !bytes.starts_with(b"MThd") || be_u32(&bytes[4..8]) != 6 {
        return ValidationResult::invalid("MIDI header invalid");
    }
    let format = be_u16(&bytes[8..10]);
    let tracks = be_u16(&bytes[10..12]) as usize;
    let division = be_u16(&bytes[12..14]);
    if format > 2 || tracks == 0 || division == 0 {
        return ValidationResult::invalid("MIDI header fields invalid");
    }
    let mut pos = 14usize;
    for _ in 0..tracks {
        if pos + 8 > bytes.len() || &bytes[pos..pos + 4] != b"MTrk" {
            return ValidationResult::invalid("MIDI track header invalid");
        }
        let len = be_u32(&bytes[pos + 4..pos + 8]) as usize;
        pos += 8;
        if pos.checked_add(len).is_none() || pos + len > bytes.len() {
            return ValidationResult::invalid("MIDI track exceeds file");
        }
        pos += len;
    }
    if pos == bytes.len() {
        ValidationResult::valid(95, "MIDI header and track chunk grammar valid")
    } else {
        ValidationResult::invalid("MIDI trailing/unaccounted data")
    }
}

fn validate_dds(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 128
        || !bytes.starts_with(b"DDS ")
        || le_u32(&bytes[4..8]) != 124
        || le_u32(&bytes[76..80]) != 32
    {
        return ValidationResult::invalid("DDS header sizes/signature invalid");
    }
    let height = le_u32(&bytes[12..16]);
    let width = le_u32(&bytes[16..20]);
    if width == 0 || height == 0 || width > 1_000_000 || height > 1_000_000 {
        return ValidationResult::invalid("DDS dimensions invalid");
    }
    ValidationResult::valid(90, "DDS fixed header and dimensions valid")
}

fn validate_icon(bytes: &[u8], kind: u16) -> ValidationResult {
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != 0
        || u16::from_le_bytes([bytes[2], bytes[3]]) != kind
    {
        return ValidationResult::invalid("ICO/CUR header invalid");
    }
    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    if count == 0 || count > 4096 || 6 + count * 16 > bytes.len() {
        return ValidationResult::invalid("ICO/CUR directory count invalid");
    }
    for i in 0..count {
        let p = 6 + i * 16;
        let size = le_u32(&bytes[p + 8..p + 12]) as usize;
        let offset = le_u32(&bytes[p + 12..p + 16]) as usize;
        if size == 0
            || offset < 6 + count * 16
            || offset.checked_add(size).is_none()
            || offset + size > bytes.len()
        {
            return ValidationResult::invalid("ICO/CUR image range invalid");
        }
    }
    ValidationResult::valid(95, "ICO/CUR directory and image ranges valid")
}

fn validate_ebml(bytes: &[u8]) -> ValidationResult {
    if bytes.len() >= 8 && bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        ValidationResult::valid(
            70,
            "EBML signature recognized; full Matroska grammar not validated",
        )
    } else {
        ValidationResult::invalid("EBML signature invalid")
    }
}

fn validate_id3(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 10 || !bytes.starts_with(b"ID3") || bytes[3] == 0xff || bytes[4] == 0xff {
        return ValidationResult::invalid("ID3 header invalid");
    }
    if bytes[6..10].iter().any(|&b| b & 0x80 != 0) {
        return ValidationResult::invalid("ID3 syncsafe size invalid");
    }
    let size = ((bytes[6] as usize) << 21)
        | ((bytes[7] as usize) << 14)
        | ((bytes[8] as usize) << 7)
        | bytes[9] as usize;
    if 10usize.checked_add(size).is_none() || 10 + size > bytes.len() {
        return ValidationResult::invalid("ID3 tag exceeds file");
    }
    ValidationResult::valid(70, "ID3 tag header/size valid; MP3 frames not fully parsed")
}

fn validate_pe(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return ValidationResult::invalid("PE DOS header invalid");
    }
    let pe_offset = le_u32(&bytes[0x3c..0x40]) as usize;
    if pe_offset.checked_add(24).is_none()
        || pe_offset + 24 > bytes.len()
        || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0"
    {
        return ValidationResult::invalid("PE signature/offset invalid");
    }
    let sections = u16::from_le_bytes([bytes[pe_offset + 6], bytes[pe_offset + 7]]) as usize;
    let optional_size = u16::from_le_bytes([bytes[pe_offset + 20], bytes[pe_offset + 21]]) as usize;
    if sections == 0 || sections > 96 {
        return ValidationResult::invalid("PE section count invalid");
    }
    let table = pe_offset + 24 + optional_size;
    if table.checked_add(sections * 40).is_none() || table + sections * 40 > bytes.len() {
        return ValidationResult::invalid("PE section table outside file");
    }
    for i in 0..sections {
        let p = table + i * 40;
        let raw_size = le_u32(&bytes[p + 16..p + 20]) as usize;
        let raw_offset = le_u32(&bytes[p + 20..p + 24]) as usize;
        if raw_size != 0
            && (raw_offset.checked_add(raw_size).is_none() || raw_offset + raw_size > bytes.len())
        {
            return ValidationResult::invalid("PE section raw range outside file");
        }
    }
    ValidationResult::valid(95, "PE signature and section table/ranges valid")
}

fn validate_asf(bytes: &[u8]) -> ValidationResult {
    const ASF_HEADER: &[u8] = &[
        0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce,
        0x6c,
    ];
    if bytes.len() < 30 || !bytes.starts_with(ASF_HEADER) {
        return ValidationResult::invalid("ASF header GUID invalid");
    }
    let header_size = le_u64(&bytes[16..24]);
    let object_count = le_u32(&bytes[24..28]) as usize;
    if header_size < 30
        || header_size > bytes.len() as u64
        || object_count == 0
        || object_count > 100_000
        || bytes[28] != 1
        || bytes[29] != 2
    {
        return ValidationResult::invalid("ASF header fields invalid");
    }
    let header_end = header_size as usize;
    let mut pos = 30usize;
    for _ in 0..object_count {
        if pos + 24 > header_end {
            return ValidationResult::invalid("ASF child object header truncated");
        }
        let size = le_u64(&bytes[pos + 16..pos + 24]);
        if size < 24 || size > usize::MAX as u64 {
            return ValidationResult::invalid("ASF child object size invalid");
        }
        let Some(end) = pos.checked_add(size as usize) else {
            return ValidationResult::invalid("ASF child object range overflow");
        };
        if end > header_end {
            return ValidationResult::invalid("ASF child object exceeds header");
        }
        pos = end;
    }
    if pos != header_end {
        return ValidationResult::invalid("ASF header object count/size mismatch");
    }
    ValidationResult::valid(95, "ASF header object grammar valid")
}

fn validate_mpeg_ps(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 14 || !bytes.starts_with(&[0x00, 0x00, 0x01, 0xba]) {
        return ValidationResult::invalid("MPEG program-stream pack header invalid");
    }
    let mut start_codes = 0usize;
    for window in bytes.windows(4) {
        if window[0] == 0 && window[1] == 0 && window[2] == 1 {
            start_codes += 1;
        }
    }
    if start_codes < 3 {
        return ValidationResult::invalid("MPEG program stream lacks packet structure");
    }
    ValidationResult::valid(75, "MPEG program-stream start-code structure recognized")
}

fn validate_mpeg1_video(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 12 || !bytes.starts_with(&[0x00, 0x00, 0x01, 0xb3]) {
        return ValidationResult::invalid("MPEG-1 sequence header invalid");
    }

    // ISO/IEC 11172-2 sequence_header(): 12-bit width, 12-bit height,
    // 4-bit aspect-ratio code and 4-bit frame-rate code.
    let width = ((bytes[4] as u16) << 4) | ((bytes[5] as u16) >> 4);
    let height = (((bytes[5] as u16) & 0x0f) << 8) | bytes[6] as u16;
    let aspect = bytes[7] >> 4;
    let frame_rate = bytes[7] & 0x0f;
    if width == 0 || height == 0 || aspect == 0 || !(1..=8).contains(&frame_rate) {
        return ValidationResult::invalid("MPEG-1 sequence dimensions/rate invalid");
    }
    // marker_bit follows the 18-bit bit_rate_value.
    if bytes[10] & 0x20 == 0 {
        return ValidationResult::invalid("MPEG-1 sequence marker bit missing");
    }

    let mut pictures = 0usize;
    let mut structural_codes = 0usize;
    for window in bytes.windows(4) {
        if window[0..3] == [0x00, 0x00, 0x01] {
            match window[3] {
                0x00 => pictures += 1, // picture_start_code
                0xb3 | 0xb5 | 0xb7 | 0xb8 => structural_codes += 1,
                _ => {}
            }
        }
    }
    if pictures == 0 || structural_codes == 0 {
        return ValidationResult::invalid("MPEG-1 video lacks picture/sequence structure");
    }
    ValidationResult::valid(90, "MPEG-1 video sequence and picture structure valid")
}

fn annexb_start_code(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= bytes.len() {
        if i + 4 <= bytes.len() && bytes[i..i + 4] == [0x00, 0x00, 0x00, 0x01] {
            return Some((i, 4));
        }
        if bytes[i..i + 3] == [0x00, 0x00, 0x01] {
            return Some((i, 3));
        }
        i += 1;
    }
    None
}

fn validate_h264_annexb(bytes: &[u8]) -> ValidationResult {
    let Some((first, _)) = annexb_start_code(bytes, 0) else {
        return ValidationResult::invalid("H.264 Annex-B start code missing");
    };
    if first != 0 {
        return ValidationResult::invalid("H.264 Annex-B has leading non-start-code bytes");
    }

    let mut pos = 0usize;
    let mut nals = 0usize;
    let mut has_sps = false;
    let mut has_pps = false;
    let mut has_slice = false;
    while let Some((start, prefix)) = annexb_start_code(bytes, pos) {
        let header = start + prefix;
        if header >= bytes.len() {
            return ValidationResult::invalid("H.264 empty NAL unit");
        }
        let nal = bytes[header];
        if nal & 0x80 != 0 {
            return ValidationResult::invalid("H.264 forbidden_zero_bit set");
        }
        let kind = nal & 0x1f;
        if kind == 0 || kind >= 24 {
            return ValidationResult::invalid("H.264 unsupported/invalid NAL type");
        }
        has_sps |= kind == 7;
        has_pps |= kind == 8;
        has_slice |= kind == 1 || kind == 5;
        nals += 1;
        pos = header + 1;
        if pos >= bytes.len() {
            break;
        }
        // Move to the next start code; if there is none, the remaining bytes
        // are simply the final NAL payload.
        if annexb_start_code(bytes, pos).is_none() {
            break;
        }
    }

    if nals < 3 || !has_sps || !has_pps || !has_slice {
        return ValidationResult::invalid("H.264 stream lacks SPS/PPS/slice structure");
    }
    ValidationResult::valid(90, "H.264 Annex-B NAL structure valid")
}

fn validate_psd(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 26
        || !bytes.starts_with(b"8BPS")
        || be_u16(&bytes[4..6]) != 1
        || &bytes[6..12] != &[0u8; 6]
    {
        return ValidationResult::invalid("PSD header invalid");
    }
    let channels = be_u16(&bytes[12..14]);
    let height = be_u32(&bytes[14..18]);
    let width = be_u32(&bytes[18..22]);
    let depth = be_u16(&bytes[22..24]);
    let color_mode = be_u16(&bytes[24..26]);
    if !(1..=56).contains(&channels)
        || width == 0
        || height == 0
        || !matches!(depth, 1 | 8 | 16 | 32)
        || color_mode > 9
    {
        return ValidationResult::invalid("PSD dimensions/channel/depth invalid");
    }
    let mut pos = 26usize;
    for _ in 0..3 {
        if pos + 4 > bytes.len() {
            return ValidationResult::invalid("PSD section length truncated");
        }
        let len = be_u32(&bytes[pos..pos + 4]) as usize;
        pos += 4;
        if pos.checked_add(len).is_none() || pos + len > bytes.len() {
            return ValidationResult::invalid("PSD section exceeds file");
        }
        pos += len;
    }
    if pos + 2 > bytes.len() || be_u16(&bytes[pos..pos + 2]) > 3 {
        return ValidationResult::invalid("PSD image compression field invalid");
    }
    ValidationResult::valid(90, "PSD header and length-delimited sections valid")
}

fn validate_tga(bytes: &[u8]) -> ValidationResult {
    const FOOTER_SIG: &[u8] = b"TRUEVISION-XFILE.\0";
    if bytes.len() < 18 + FOOTER_SIG.len() || !bytes.ends_with(FOOTER_SIG) {
        return ValidationResult::invalid("TGA 2.0 footer missing");
    }
    let image_type = bytes[2];
    if !matches!(image_type, 0 | 1 | 2 | 3 | 9 | 10 | 11) {
        return ValidationResult::invalid("TGA image type invalid");
    }
    let width = u16::from_le_bytes([bytes[12], bytes[13]]);
    let height = u16::from_le_bytes([bytes[14], bytes[15]]);
    let bpp = bytes[16];
    if width == 0 || height == 0 || !matches!(bpp, 8 | 15 | 16 | 24 | 32) {
        return ValidationResult::invalid("TGA dimensions/pixel depth invalid");
    }
    ValidationResult::valid(90, "TGA header and 2.0 footer valid")
}

const TLG0_MAGIC: &[u8] = b"TLG0.0\0sds\x1a";
const TLG5_MAGIC: &[u8] = b"TLG5.0\0raw\x1a";
const TLG6_MAGIC: &[u8] = b"TLG6.0\0raw\x1a";

fn validate_tlg_wrapper(bytes: &[u8], raw_offset: usize) -> std::result::Result<(), &'static str> {
    if raw_offset == 0 {
        return Ok(());
    }
    if bytes.len() < 15 || !bytes.starts_with(TLG0_MAGIC) {
        return Err("TLG0 wrapper signature invalid");
    }
    let raw_len = le_u32(&bytes[11..15]) as usize;
    if raw_len == 0
        || raw_offset.checked_add(raw_len).is_none()
        || raw_offset + raw_len > bytes.len()
    {
        return Err("TLG0 raw stream length invalid");
    }
    Ok(())
}

fn validate_tlg5(bytes: &[u8], raw_offset: usize) -> ValidationResult {
    if let Err(reason) = validate_tlg_wrapper(bytes, raw_offset) {
        return ValidationResult::invalid(reason);
    }
    if raw_offset + 24 > bytes.len() || &bytes[raw_offset..raw_offset + 11] != TLG5_MAGIC {
        return ValidationResult::invalid("TLG5 raw signature/header truncated");
    }
    let colors = bytes[raw_offset + 11] as usize;
    if colors != 3 && colors != 4 {
        return ValidationResult::invalid("TLG5 color count invalid");
    }
    let width = le_u32(&bytes[raw_offset + 12..raw_offset + 16]) as usize;
    let height = le_u32(&bytes[raw_offset + 16..raw_offset + 20]) as usize;
    let block_height = le_u32(&bytes[raw_offset + 20..raw_offset + 24]) as usize;
    if width == 0 || height == 0 || block_height == 0 || width > 1_000_000 || height > 1_000_000 {
        return ValidationResult::invalid("TLG5 dimensions/block height invalid");
    }
    let block_count = (height - 1) / block_height + 1;
    let table_start = raw_offset + 24;
    let Some(table_end) = table_start.checked_add(block_count.saturating_mul(4)) else {
        return ValidationResult::invalid("TLG5 block table overflow");
    };
    if table_end > bytes.len() {
        return ValidationResult::invalid("TLG5 block-size table truncated");
    }
    let block_sizes: Vec<usize> = (0..block_count)
        .map(|block| {
            let pos = table_start + block * 4;
            le_u32(&bytes[pos..pos + 4]) as usize
        })
        .collect();
    let mut position = table_end;

    for &declared_block_size in &block_sizes {
        let block_start = position;
        for _ in 0..colors {
            if position + 5 > bytes.len() {
                return ValidationResult::invalid("TLG5 channel block header truncated");
            }
            let method = bytes[position];
            if method > 1 {
                return ValidationResult::invalid("TLG5 channel compression method invalid");
            }
            let size = le_u32(&bytes[position + 1..position + 5]) as usize;
            position += 5;
            let Some(end) = position.checked_add(size) else {
                return ValidationResult::invalid("TLG5 channel block length overflow");
            };
            if end > bytes.len() {
                return ValidationResult::invalid("TLG5 channel block truncated");
            }
            position = end;
        }
        if position - block_start != declared_block_size {
            return ValidationResult::invalid("TLG5 declared block size mismatch");
        }
    }

    let raw_end = if raw_offset == 0 {
        bytes.len()
    } else {
        raw_offset + le_u32(&bytes[11..15]) as usize
    };
    if position != raw_end {
        return ValidationResult::invalid("TLG5 raw stream size mismatch");
    }
    ValidationResult::valid(95, "TLG5 header, block table, and channel blocks valid")
}

fn validate_tlg6(bytes: &[u8], raw_offset: usize) -> ValidationResult {
    if let Err(reason) = validate_tlg_wrapper(bytes, raw_offset) {
        return ValidationResult::invalid(reason);
    }
    if raw_offset + 31 > bytes.len() || &bytes[raw_offset..raw_offset + 11] != TLG6_MAGIC {
        return ValidationResult::invalid("TLG6 raw signature/header truncated");
    }
    let colors = bytes[raw_offset + 11] as usize;
    if !matches!(colors, 1 | 3 | 4) {
        return ValidationResult::invalid("TLG6 color count invalid");
    }
    if bytes[raw_offset + 12] != 0 || bytes[raw_offset + 13] != 0 || bytes[raw_offset + 14] != 0 {
        return ValidationResult::invalid("TLG6 control flags unsupported");
    }
    let width = le_u32(&bytes[raw_offset + 15..raw_offset + 19]) as usize;
    let height = le_u32(&bytes[raw_offset + 19..raw_offset + 23]) as usize;
    let max_bit_length = le_u32(&bytes[raw_offset + 23..raw_offset + 27]) as usize;
    let filter_length = le_u32(&bytes[raw_offset + 27..raw_offset + 31]) as usize;
    if width == 0 || height == 0 || max_bit_length == 0 || width > 1_000_000 || height > 1_000_000 {
        return ValidationResult::invalid("TLG6 dimensions/max bit length invalid");
    }
    let Some(mut position) = raw_offset
        .checked_add(31)
        .and_then(|x| x.checked_add(filter_length))
    else {
        return ValidationResult::invalid("TLG6 filter stream length overflow");
    };
    if position > bytes.len() {
        return ValidationResult::invalid("TLG6 filter stream truncated");
    }

    let y_blocks = (height - 1) / 8 + 1;
    for y_block in 0..y_blocks {
        let lines = (height - y_block * 8).min(8);
        let pixel_count = lines.saturating_mul(width);
        for _ in 0..colors {
            if position + 4 > bytes.len() {
                return ValidationResult::invalid("TLG6 bit-length field truncated");
            }
            let encoded = le_u32(&bytes[position..position + 4]);
            position += 4;
            let method = encoded >> 30;
            let bit_length = (encoded & 0x3fff_ffff) as usize;
            if method != 0
                || bit_length > max_bit_length
                || bit_length > pixel_count.saturating_mul(64)
            {
                return ValidationResult::invalid("TLG6 entropy block parameters invalid");
            }
            let byte_length = bit_length / 8 + if bit_length % 8 != 0 { 1 } else { 0 };
            let Some(end) = position.checked_add(byte_length) else {
                return ValidationResult::invalid("TLG6 entropy block length overflow");
            };
            if end > bytes.len() {
                return ValidationResult::invalid("TLG6 entropy block truncated");
            }
            position = end;
        }
    }

    let raw_end = if raw_offset == 0 {
        bytes.len()
    } else {
        raw_offset + le_u32(&bytes[11..15]) as usize
    };
    if position != raw_end {
        return ValidationResult::invalid("TLG6 raw stream size mismatch");
    }
    ValidationResult::valid(95, "TLG6 header, filter stream, and entropy blocks valid")
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Ogg's page CRC uses the non-reflected 0x04C11DB7 polynomial and an initial
/// value of zero.  The checksum field itself (bytes 22..26 of the page) is
/// treated as zero while computing the checksum.
pub fn ogg_crc32(page: &[u8]) -> u32 {
    let mut crc = 0u32;
    for (index, &original) in page.iter().enumerate() {
        let byte = if (22..26).contains(&index) {
            0
        } else {
            original
        };
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn riff_requires_real_form_chunks_not_just_header_and_size() {
        let fake = b"RIFF\x04\x00\x00\x00WAVE".to_vec();
        assert!(!validate_hypothesis("WAVE/RIFF", &fake).valid);

        let mut wave = b"RIFF\x00\x00\x00\x00WAVE".to_vec();
        wave.extend_from_slice(b"fmt ");
        wave.extend_from_slice(&16u32.to_le_bytes());
        wave.extend_from_slice(&[1, 0, 1, 0, 0x44, 0xac, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0]);
        wave.extend_from_slice(b"data");
        wave.extend_from_slice(&0u32.to_le_bytes());
        let riff_size = (wave.len() - 8) as u32;
        wave[4..8].copy_from_slice(&riff_size.to_le_bytes());
        assert!(validate_hypothesis("WAVE/RIFF", &wave).is_strong());
    }

    #[test]
    fn gif_rejects_signature_and_trailer_only_false_positive() {
        let mut fake = b"GIF89a".to_vec();
        fake.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0]);
        fake.push(0x55); // illegal first block introducer
        fake.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0x3b]);
        assert!(!validate_hypothesis("GIF89a", &fake).valid);
    }

    #[test]
    fn validates_utf16le_script_text() {
        let text = "// startup.tjs\r\nvar x = 1;\r\n";
        let mut bytes = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(validate_hypothesis("Text/UTF-16LE-BOM", &bytes).is_strong());
        assert!(validate_hypothesis("Text/UTF-16LE", &bytes).is_strong());
    }

    #[test]
    fn validates_utf8_and_cp932_text_without_bom() {
        let utf8 = "@layopt layer=message0 visible=true\r\n; 日本語テキスト\r\n".as_bytes();
        assert!(validate_hypothesis("Text/UTF-8", utf8).is_strong());

        // "@tag text=日本" encoded as CP932/Shift-JIS.
        let cp932 = b"@tag text=\x93\xfa\x96\x7b\r\n";
        assert!(validate_hypothesis("Text/CP932", cp932).is_strong());
    }

    #[test]
    fn rejects_unicode_gibberish_without_script_signal() {
        let text = "漢字仮名漢字仮名漢字仮名漢字仮名漢字仮名漢字仮名";
        assert!(!validate_decoded_text(text).valid);
    }

    #[test]
    fn decodes_kirikiri_mode1_wrapper() {
        let source = "// mode1.tjs\r\nvar value = 7;\r\n";
        let mut wrapped = vec![0xfe, 0xfe, 0x01, 0xff, 0xfe];
        for unit in source.encode_utf16() {
            let encoded = ((unit & 0xaaaa) >> 1) | ((unit & 0x5555) << 1);
            wrapped.extend_from_slice(&encoded.to_le_bytes());
        }
        assert!(validate_hypothesis("Kirikiri/Text-mode1", &wrapped).is_strong());
        let decoded = decode_kirikiri_text(&wrapped).unwrap();
        assert!(decoded.starts_with(&[0xff, 0xfe]));
        assert!(validate_hypothesis("Text/UTF-16LE-BOM", &decoded).is_strong());
    }

    #[test]
    fn validates_tjs2100_outer_and_data_pool_grammar() {
        // DATA has the seven empty constant-pool counts required by the loader.
        let data_payload = vec![0u8; 7 * 4];
        let data_size = 8 + data_payload.len();
        let objs_size = 16usize; // tag+size + toplevel(-1)+objcount(0)
        let file_size = 12 + data_size + objs_size;

        let mut bytes = Vec::with_capacity(file_size);
        bytes.extend_from_slice(b"TJS2100\0");
        bytes.extend_from_slice(&(file_size as u32).to_le_bytes());
        bytes.extend_from_slice(b"DATA");
        bytes.extend_from_slice(&(data_size as u32).to_le_bytes());
        bytes.extend_from_slice(&data_payload);
        bytes.extend_from_slice(b"OBJS");
        bytes.extend_from_slice(&(objs_size as u32).to_le_bytes());
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());

        assert_eq!(bytes.len(), file_size);
        assert!(validate_hypothesis("TJS2/Bytecode", &bytes).is_strong());
    }

    fn make_ogg_page(
        header_type: u8,
        granule: u64,
        serial: u32,
        sequence: u32,
        packet: &[u8],
    ) -> Vec<u8> {
        assert!(packet.len() < 255);
        let mut page = Vec::with_capacity(28 + packet.len());
        page.extend_from_slice(b"OggS");
        page.push(0); // stream-structure version
        page.push(header_type);
        page.extend_from_slice(&granule.to_le_bytes());
        page.extend_from_slice(&serial.to_le_bytes());
        page.extend_from_slice(&sequence.to_le_bytes());
        page.extend_from_slice(&[0u8; 4]); // CRC placeholder
        page.push(1); // page_segments
        page.push(packet.len() as u8);
        page.extend_from_slice(packet);
        let crc = ogg_crc32(&page);
        page[22..26].copy_from_slice(&crc.to_le_bytes());
        page
    }

    #[test]
    fn validates_two_page_opus_headers_and_ogg_crc() {
        let mut head = Vec::new();
        head.extend_from_slice(b"OpusHead");
        head.push(1); // version
        head.push(2); // stereo
        head.extend_from_slice(&312u16.to_le_bytes()); // pre-skip
        head.extend_from_slice(&48_000u32.to_le_bytes());
        head.extend_from_slice(&0i16.to_le_bytes()); // output gain
        head.push(0); // mapping family 0
        assert_eq!(head.len(), 19);

        let mut tags = Vec::new();
        tags.extend_from_slice(b"OpusTags");
        tags.extend_from_slice(&0u32.to_le_bytes()); // zero-length vendor string
        tags.extend_from_slice(&0u32.to_le_bytes()); // zero user comments
        assert_eq!(tags.len(), 16);

        let serial = 0x1234_5678;
        let mut stream = make_ogg_page(0x02, 0, serial, 0, &head);
        assert_eq!(stream.len(), 47);
        stream.extend_from_slice(&make_ogg_page(0x00, 0, serial, 1, &tags));
        assert_eq!(&stream[47..51], b"OggS");
        assert_eq!(&stream[75..83], b"OpusTags");

        assert!(validate_hypothesis("Ogg", &stream).is_strong());
        assert!(validate_hypothesis("Ogg/Opus", &stream).is_strong());

        // Any byte corruption must be caught independently by the page CRC.
        let mut corrupt = stream.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(!validate_hypothesis("Ogg/Opus", &corrupt).valid);
    }

    #[test]
    fn validates_kirikiri_prerendered_font_header_and_indexes() {
        let count = 2u32;
        let char_index = 36u32;
        let glyph_index = 40u32;
        let glyph_data = 80u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"TVP pre-rendered font\x1a");
        bytes.push(1);
        bytes.push(2);
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&char_index.to_le_bytes());
        bytes.extend_from_slice(&glyph_index.to_le_bytes());
        bytes.extend_from_slice(&0x20u16.to_le_bytes());
        bytes.extend_from_slice(&0x41u16.to_le_bytes());
        for offset in [glyph_data, glyph_data + 1] {
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&0i16.to_le_bytes());
            bytes.extend_from_slice(&0i16.to_le_bytes());
            bytes.extend_from_slice(&1i16.to_le_bytes());
            bytes.extend_from_slice(&0i16.to_le_bytes());
            bytes.extend_from_slice(&1i16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x20, 0x40]);

        assert!(validate_hypothesis("Kirikiri/PrerenderedFont-v1", &bytes).is_strong());
        assert!(!validate_hypothesis("Kirikiri/PrerenderedFont-v0", &bytes).valid);
    }

    #[test]
    fn validates_minimal_m2_psb_header_and_arrays() {
        let mut bytes = vec![0u8; 40];
        bytes[0..4].copy_from_slice(b"PSB\0");
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Three empty name-trie arrays.
        let names = 40u32;
        bytes.extend_from_slice(&[0x0d, 0, 0x0d]);
        bytes.extend_from_slice(&[0x0d, 0, 0x0d]);
        bytes.extend_from_slice(&[0x0d, 0, 0x0d]);
        let strings = bytes.len() as u32;
        bytes.extend_from_slice(&[0x0d, 0, 0x0d]);
        let strings_data = bytes.len() as u32;
        let chunk_offsets = bytes.len() as u32;
        bytes.extend_from_slice(&[0x0d, 0, 0x0d]);
        let chunk_lengths = bytes.len() as u32;
        bytes.extend_from_slice(&[0x0d, 0, 0x0d]);
        let chunk_data = bytes.len() as u32;
        let entries = bytes.len() as u32;
        bytes.push(0x21);

        bytes[8..12].copy_from_slice(&names.to_le_bytes());
        bytes[12..16].copy_from_slice(&names.to_le_bytes());
        bytes[16..20].copy_from_slice(&strings.to_le_bytes());
        bytes[20..24].copy_from_slice(&strings_data.to_le_bytes());
        bytes[24..28].copy_from_slice(&chunk_offsets.to_le_bytes());
        bytes[28..32].copy_from_slice(&chunk_lengths.to_le_bytes());
        bytes[32..36].copy_from_slice(&chunk_data.to_le_bytes());
        bytes[36..40].copy_from_slice(&entries.to_le_bytes());

        assert!(validate_hypothesis("PSB/M2-Emote", &bytes).is_strong());
    }

    #[test]
    fn tlg5_minimal_structure_is_checked() {
        let mut data = Vec::new();
        data.extend_from_slice(TLG5_MAGIC);
        data.push(3);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&18u32.to_le_bytes()); // 3 * (method + size + one raw byte)
        for _ in 0..3 {
            data.push(1); // raw
            data.extend_from_slice(&1u32.to_le_bytes());
            data.push(0);
        }
        assert!(validate_hypothesis("TLG5", &data).is_strong());
    }

    #[test]
    fn validates_mpeg1_video_sequence_structure() {
        let mut bytes = vec![
            0x00, 0x00, 0x01, 0xb3, 0x28, 0x01, 0xe0, 0x13, 0x00, 0x00, 0x20, 0x00,
        ];
        bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0xb8, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0, 0, 0, 0]);
        assert!(validate_mpeg1_video(&bytes).is_strong());
    }

    #[test]
    fn validates_h264_annexb_structure() {
        let bytes = [
            0, 0, 0, 1, 0x67, 0x42, 0, 0x1e, 0xaa, 0, 0, 0, 1, 0x68, 0xce, 0x06, 0xe2, 0, 0, 1,
            0x65, 0x88, 0x84, 0x00,
        ];
        assert!(validate_h264_annexb(&bytes).is_strong());
    }

    #[test]
    fn jpeg_validator_walks_frame_scan_and_entropy_markers() {
        let bytes = [
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11,
            0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x12, 0x34, 0xff,
            0x00, 0x56, 0xff, 0xd9,
        ];
        assert!(validate_jpeg(&bytes).is_strong());
    }
}
