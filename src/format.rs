use crate::brute::PlainByteConstraint;
use crate::repeating_xor::{Crib, PeriodCandidate};
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicModel {
    None,
    Png,
    Ogg,
    Opus,
    Tlg5,
    Tlg6,
}

#[derive(Clone, Debug)]
pub struct FormatHypothesis {
    pub name: &'static str,
    pub extensions: &'static [&'static str],
    pub cribs: Vec<Crib>,
    pub dynamic: DynamicModel,
}

impl FormatHypothesis {
    fn at_zero(
        name: &'static str,
        extensions: &'static [&'static str],
        bytes: &'static [u8],
    ) -> Self {
        Self {
            name,
            extensions,
            cribs: vec![Crib::new(0, bytes)],
            dynamic: DynamicModel::None,
        }
    }
}

const TLG0_MAGIC: &[u8] = b"TLG0.0\0sds\x1a";
const TLG5_MAGIC: &[u8] = b"TLG5.0\0raw\x1a";
const TLG6_MAGIC: &[u8] = b"TLG6.0\0raw\x1a";
const TVP_PRERENDERED_FONT_V0_MAGIC: &[u8] = b"TVP pre-rendered font\x1a\x00\x02";
const TVP_PRERENDERED_FONT_V1_MAGIC: &[u8] = b"TVP pre-rendered font\x1a\x01\x02";

const TEXT_EXTENSIONS: &[&str] = &[
    "tjs", "ks", "asd", "txt", "csv", "func", "stand", "ini", "ksd", "kdt", "json", "xml", "cfg",
    "conf", "js", "css", "html", "htm", "lua", "toml", "sli", "dic", "svg",
];

fn opus_base_cribs() -> Vec<Crib> {
    vec![
        Crib::new(0, b"OggS"),
        Crib::new(4, [0x00]),    // Ogg version 0
        Crib::new(5, [0x02]),    // BOS page; OpusHead is alone on page 0
        Crib::new(6, [0u8; 8]),  // ID-header granule position is zero
        Crib::new(18, [0u8; 4]), // first page sequence number is zero
    ]
}

fn opus_family0_cribs() -> Vec<Crib> {
    let mut cribs = opus_base_cribs();
    cribs.extend([
        Crib::new(26, [0x01]), // one lacing segment
        Crib::new(27, [0x13]), // 19-byte OpusHead packet
        Crib::new(28, b"OpusHead"),
        Crib::new(36, [0x01]), // OpusHead version 1
        Crib::new(46, [0x00]), // channel mapping family 0
        // 27-byte Ogg header + 1 lacing byte + 19-byte OpusHead = 47
        Crib::new(47, b"OggS"),
        Crib::new(51, [0x00]),                   // Ogg version 0
        Crib::new(65, [0x01, 0x00, 0x00, 0x00]), // page sequence number 1
    ]);
    cribs
}

/// Conservative built-in plaintext hypotheses.  Several hypotheses may exist
/// for the same extension: a strict/common layout is useful for key recovery,
/// while a conservative sibling prevents the strict model from becoming a
/// correctness requirement.
pub fn builtin_hypotheses() -> Vec<FormatHypothesis> {
    vec![
        FormatHypothesis {
            name: "PNG",
            extensions: &["png"],
            cribs: vec![
                Crib::new(0, &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
                Crib::new(8, [0x00, 0x00, 0x00, 0x0d]), // IHDR length
                Crib::new(12, b"IHDR"),
            ],
            dynamic: DynamicModel::Png,
        },
        FormatHypothesis::at_zero("JPEG", &["jpg", "jpeg"], &[0xff, 0xd8, 0xff]),
        // JPEG XR / HD Photo uses the little-endian TIFF-like WMP container
        // signature II BC 01.  The current validator treats this as structural
        // recognition only; it is useful key evidence but is not, by itself,
        // strong enough to declare a recovered file solved.
        FormatHypothesis::at_zero(
            "JPEG-XR/WMP",
            &["jxr", "wdp", "hdp"],
            &[0x49, 0x49, 0xbc, 0x01],
        ),
        // Generic Ogg: the BOS page always begins with OggS, version 0, and
        // sequence number 0.  The exact header-type byte is deliberately not
        // used because EOS may also be set for degenerate one-page streams.
        FormatHypothesis {
            name: "Ogg",
            extensions: &["ogg", "oga", "ogv"],
            cribs: vec![
                Crib::new(0, b"OggS"),
                Crib::new(4, [0x00]),
                Crib::new(18, [0u8; 4]),
            ],
            dynamic: DynamicModel::Ogg,
        },
        // Ogg Opus, conservative mapping-independent facts.
        FormatHypothesis {
            name: "Ogg/Opus",
            extensions: &["opus", "ogg", "oga"],
            cribs: opus_base_cribs(),
            dynamic: DynamicModel::Opus,
        },
        // Mapping family 0 is the normal mono/stereo representation.  The
        // identification packet is exactly 19 bytes and therefore fixes the
        // beginning of page 1 at offset 47.
        FormatHypothesis {
            name: "Ogg/Opus-family0",
            extensions: &["opus", "ogg", "oga"],
            cribs: opus_family0_cribs(),
            dynamic: DynamicModel::Opus,
        },
        // Very common small-tag case: the OpusTags packet fits into one Ogg
        // segment on page 1.  Keep this as a separate hypothesis; failure does
        // not reject the conservative Opus models above.
        FormatHypothesis {
            name: "Ogg/Opus-family0-smalltags",
            extensions: &["opus", "ogg", "oga"],
            cribs: {
                let mut cribs = opus_family0_cribs();
                cribs.extend([
                    Crib::new(52, [0x00]),   // ordinary non-BOS header page
                    Crib::new(53, [0u8; 8]), // comment header completes here
                    Crib::new(73, [0x01]),   // one lacing segment
                    Crib::new(75, b"OpusTags"),
                ]);
                cribs
            },
            dynamic: DynamicModel::Opus,
        },
        // Common Ogg Vorbis identification page.  A Vorbis ID packet is 30
        // bytes, so its single lacing byte and packet identifier are fixed.
        FormatHypothesis {
            name: "Ogg/Vorbis",
            extensions: &["ogg", "oga"],
            cribs: vec![
                Crib::new(0, b"OggS"),
                Crib::new(4, [0x00]),
                Crib::new(18, [0u8; 4]),
                Crib::new(26, [0x01]),
                Crib::new(27, [0x1e]),
                Crib::new(28, b"\x01vorbis"),
            ],
            dynamic: DynamicModel::Ogg,
        },
        FormatHypothesis {
            name: "WAVE/RIFF",
            extensions: &["wav"],
            cribs: vec![Crib::new(0, b"RIFF"), Crib::new(8, b"WAVE")],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "AVI/RIFF",
            extensions: &["avi"],
            cribs: vec![Crib::new(0, b"RIFF"), Crib::new(8, b"AVI ")],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "WebP/RIFF",
            extensions: &["webp"],
            cribs: vec![Crib::new(0, b"RIFF"), Crib::new(8, b"WEBP")],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis::at_zero("GIF87a", &["gif"], b"GIF87a"),
        FormatHypothesis::at_zero("GIF89a", &["gif"], b"GIF89a"),
        FormatHypothesis::at_zero("BMP", &["bmp"], b"BM"),
        FormatHypothesis::at_zero("ZIP/local", &["zip", "jar"], &[0x50, 0x4b, 0x03, 0x04]),
        FormatHypothesis::at_zero("ZIP/empty", &["zip", "jar"], &[0x50, 0x4b, 0x05, 0x06]),
        FormatHypothesis::at_zero("7-Zip", &["7z"], &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
        FormatHypothesis::at_zero("gzip", &["gz"], &[0x1f, 0x8b, 0x08]),
        // KiriKiri script/text resources.  These are deliberately kept in a
        // dedicated family so a known .tjs/.ks/.asd name can never silently
        // fall back to unrelated image/audio hypotheses.  Plain files without
        // a BOM (for example CP932/SJIS) require statistical text recovery and
        // stay unresolved until that model proves them.
        FormatHypothesis {
            name: "Text/UTF-16LE-BOM",
            extensions: TEXT_EXTENSIONS,
            cribs: vec![Crib::new(0, [0xff, 0xfe])],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "Text/UTF-16LE",
            extensions: TEXT_EXTENSIONS,
            cribs: Vec::new(),
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "Text/UTF-16BE-BOM",
            extensions: TEXT_EXTENSIONS,
            cribs: vec![Crib::new(0, [0xfe, 0xff])],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "Text/UTF-16BE",
            extensions: TEXT_EXTENSIONS,
            cribs: Vec::new(),
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "Text/UTF-8-BOM",
            extensions: TEXT_EXTENSIONS,
            cribs: vec![Crib::new(0, [0xef, 0xbb, 0xbf])],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "Text/UTF-8",
            extensions: TEXT_EXTENSIONS,
            cribs: Vec::new(),
            dynamic: DynamicModel::None,
        },
        FormatHypothesis {
            name: "Text/CP932",
            extensions: TEXT_EXTENSIONS,
            cribs: Vec::new(),
            dynamic: DynamicModel::None,
        },
        // KiriKiri's scrambled/compressed text signatures are five bytes:
        // FE FE <mode> FF FE.  The trailing UTF-16LE BOM bytes are free key
        // evidence and must not be thrown away.
        FormatHypothesis::at_zero(
            "Kirikiri/Text-mode0",
            TEXT_EXTENSIONS,
            &[0xfe, 0xfe, 0x00, 0xff, 0xfe],
        ),
        FormatHypothesis::at_zero(
            "Kirikiri/Text-mode1",
            TEXT_EXTENSIONS,
            &[0xfe, 0xfe, 0x01, 0xff, 0xfe],
        ),
        FormatHypothesis::at_zero(
            "Kirikiri/Text-mode2",
            TEXT_EXTENSIONS,
            &[0xfe, 0xfe, 0x02, 0xff, 0xfe],
        ),
        // KiriKiri TJS binary encoded scripts (.pbd). ns0 stores the typed
        // value stream directly with its seed checker; 4s0 wraps the same
        // logical value tree in optional PackinOne crypt + framed raw LZ4.
        FormatHypothesis::at_zero("KiriKiri/PBD-ns0", &["pbd"], b"TJS/ns0\0"),
        FormatHypothesis::at_zero("KiriKiri/PBD-4s0", &["pbd"], b"TJS/4s0\0"),
        // Compiled TJS2 bytecode.  The public bytecode loader uses
        // "TJS2100\0" + u32 file size followed by DATA and OBJS chunks.
        FormatHypothesis {
            name: "TJS2/Bytecode",
            extensions: &["tjs"],
            cribs: vec![Crib::new(0, b"TJS2100\0"), Crib::new(12, b"DATA")],
            dynamic: DynamicModel::None,
        },
        // M2 Packaged Struct Binary / E-mote resources.  The same PSB
        // container is commonly carried under several semantic extensions.
        FormatHypothesis::at_zero(
            "PSB/M2-Emote",
            &[
                "psb", "pimg", "scn", "mmo", "emtbytes", "mtn", "dpak", "psb.m",
            ],
            b"PSB\0",
        ),
        // PSZ/MDF are PSB-family shells. Their inner compression/encryption is
        // intentionally not guessed here; these signatures provide recovery
        // evidence and format recognition, but the validator remains weak
        // until the shell itself is decoded.
        FormatHypothesis::at_zero("PSZ/PSB-shell", &["psz", "psb.m"], b"PSZ"),
        FormatHypothesis::at_zero("MDF/PSB-shell", &["mdf", "psb.m"], b"mdf"),
        FormatHypothesis::at_zero("MFL/PSB-shell", &["mfl", "psb.m"], b"mfl"),
        // Fonts frequently live directly in XP3 archives.  These models are
        // useful for the small-font case where textual/statistical inference is
        // weak but sfnt table structure is very strong.
        FormatHypothesis::at_zero("TrueType/sfnt", &["ttf"], &[0x00, 0x01, 0x00, 0x00]),
        FormatHypothesis::at_zero("OpenType/CFF", &["otf"], b"OTTO"),
        FormatHypothesis::at_zero("TrueType/Collection", &["ttc"], b"ttcf"),
        FormatHypothesis::at_zero("WOFF", &["woff"], b"wOFF"),
        FormatHypothesis::at_zero("WOFF2", &["woff2"], b"wOF2"),
        // KiriKiri/TVP pre-rendered bitmap font.  The engine compares the
        // 22-byte signature literally, then accepts header version 0 or 1 and
        // requires the 16-bit-Unicode marker (2).  Keep one exact hypothesis
        // per version so recovery gets all 24 known header bytes.
        FormatHypothesis::at_zero(
            "Kirikiri/PrerenderedFont-v0",
            &["tft"],
            TVP_PRERENDERED_FONT_V0_MAGIC,
        ),
        FormatHypothesis::at_zero(
            "Kirikiri/PrerenderedFont-v1",
            &["tft"],
            TVP_PRERENDERED_FONT_V1_MAGIC,
        ),
        FormatHypothesis::at_zero("FLAC", &["flac"], b"fLaC"),
        FormatHypothesis {
            name: "MP4/ISO-BMFF",
            extensions: &["mp4", "m4a", "m4v", "mov"],
            cribs: vec![Crib::new(4, b"ftyp")],
            dynamic: DynamicModel::None,
        },
        FormatHypothesis::at_zero("MIDI", &["mid", "midi"], b"MThd"),
        FormatHypothesis::at_zero("DDS", &["dds"], b"DDS "),
        FormatHypothesis::at_zero("ICO", &["ico"], &[0x00, 0x00, 0x01, 0x00]),
        FormatHypothesis::at_zero("CUR", &["cur"], &[0x00, 0x00, 0x02, 0x00]),
        FormatHypothesis::at_zero("WebM/Matroska", &["webm", "mkv"], &[0x1a, 0x45, 0xdf, 0xa3]),
        FormatHypothesis::at_zero("MP3/ID3", &["mp3"], b"ID3"),
        // Native/plugin binaries are often shipped inside XP3 as .tpm/.dll.
        FormatHypothesis::at_zero("PE/COFF", &["exe", "dll", "tpm", "ax"], b"MZ"),
        FormatHypothesis::at_zero(
            "ASF/WMV-WMA",
            &["wmv", "wma", "asf"],
            &[
                0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62,
                0xce, 0x6c,
            ],
        ),
        FormatHypothesis::at_zero("MPEG-PS", &["mpg", "mpeg"], &[0x00, 0x00, 0x01, 0xba]),
        FormatHypothesis::at_zero(
            "MPEG-1/Video",
            &["m1v", "mpv", "mpg", "mpeg"],
            &[0x00, 0x00, 0x01, 0xb3],
        ),
        // Raw H.264/AVC Annex-B can use either four- or three-byte start codes.
        // Keep them as separate hypotheses rather than pretending one prefix is
        // mandatory for every stream.
        FormatHypothesis::at_zero(
            "H264/AnnexB-4",
            &["264", "h264", "avc"],
            &[0x00, 0x00, 0x00, 0x01],
        ),
        FormatHypothesis::at_zero(
            "H264/AnnexB-3",
            &["264", "h264", "avc"],
            &[0x00, 0x00, 0x01],
        ),
        FormatHypothesis::at_zero("Photoshop/PSD", &["psd"], b"8BPS"),
        FormatHypothesis {
            name: "TGA",
            extensions: &["tga"],
            cribs: Vec::new(),
            dynamic: DynamicModel::None,
        },
        // Raw TLG5.  KrkrExtract's decoder and the KiriKiri writer both use
        // the full 11-byte "TLG5.0\0raw\x1a" marker; using only "TLG5.0"
        // threw away five free key bytes.
        FormatHypothesis {
            name: "TLG5",
            extensions: &["tlg"],
            cribs: vec![Crib::new(0, TLG5_MAGIC)],
            dynamic: DynamicModel::Tlg5,
        },
        FormatHypothesis {
            name: "TLG5-rgb-block4",
            extensions: &["tlg"],
            cribs: vec![
                Crib::new(0, TLG5_MAGIC),
                Crib::new(11, [0x03]),
                Crib::new(20, [0x04, 0x00, 0x00, 0x00]),
            ],
            dynamic: DynamicModel::Tlg5,
        },
        FormatHypothesis {
            name: "TLG5-rgba-block4",
            extensions: &["tlg"],
            cribs: vec![
                Crib::new(0, TLG5_MAGIC),
                Crib::new(11, [0x04]),
                Crib::new(20, [0x04, 0x00, 0x00, 0x00]),
            ],
            dynamic: DynamicModel::Tlg5,
        },
        // TLG6 has three canonical zero control bytes immediately after the
        // color count.  Separate color-count variants convert the {1,3,4}
        // constraint into exact cribs without pretending only one is legal.
        FormatHypothesis {
            name: "TLG6-gray",
            extensions: &["tlg"],
            cribs: vec![Crib::new(0, TLG6_MAGIC), Crib::new(11, [0x01, 0, 0, 0])],
            dynamic: DynamicModel::Tlg6,
        },
        FormatHypothesis {
            name: "TLG6-rgb",
            extensions: &["tlg"],
            cribs: vec![Crib::new(0, TLG6_MAGIC), Crib::new(11, [0x03, 0, 0, 0])],
            dynamic: DynamicModel::Tlg6,
        },
        FormatHypothesis {
            name: "TLG6-rgba",
            extensions: &["tlg"],
            cribs: vec![Crib::new(0, TLG6_MAGIC), Crib::new(11, [0x04, 0, 0, 0])],
            dynamic: DynamicModel::Tlg6,
        },
        // TLG0 structured-data wrapper.  The raw TLG stream starts exactly at
        // offset 15 (11-byte marker + 4-byte raw length), which gives us a
        // second long known-plaintext region even before parsing the tags.
        FormatHypothesis {
            name: "TLG0/TLG5",
            extensions: &["tlg"],
            cribs: vec![Crib::new(0, TLG0_MAGIC), Crib::new(15, TLG5_MAGIC)],
            dynamic: DynamicModel::Tlg5,
        },
        FormatHypothesis {
            name: "TLG0/TLG6-gray",
            extensions: &["tlg"],
            cribs: vec![
                Crib::new(0, TLG0_MAGIC),
                Crib::new(15, TLG6_MAGIC),
                Crib::new(26, [0x01, 0, 0, 0]),
            ],
            dynamic: DynamicModel::Tlg6,
        },
        FormatHypothesis {
            name: "TLG0/TLG6-rgb",
            extensions: &["tlg"],
            cribs: vec![
                Crib::new(0, TLG0_MAGIC),
                Crib::new(15, TLG6_MAGIC),
                Crib::new(26, [0x03, 0, 0, 0]),
            ],
            dynamic: DynamicModel::Tlg6,
        },
        FormatHypothesis {
            name: "TLG0/TLG6-rgba",
            extensions: &["tlg"],
            cribs: vec![
                Crib::new(0, TLG0_MAGIC),
                Crib::new(15, TLG6_MAGIC),
                Crib::new(26, [0x04, 0, 0, 0]),
            ],
            dynamic: DynamicModel::Tlg6,
        },
    ]
}

/// Exact plaintext facts derivable from the physical plaintext length rather
/// than from a title-specific decoder. These are especially valuable because
/// they land at offsets far away from the file header and therefore cover new
/// repeating-key residues.
pub fn length_derived_cribs(hypothesis: &FormatHypothesis, len: usize) -> Vec<Crib> {
    let mut out = Vec::new();
    match hypothesis.name {
        "PNG" => {
            // The final PNG chunk is always a zero-length IEND with a fixed CRC.
            if len >= 12 {
                out.push(Crib::new(
                    (len - 12) as u64,
                    [
                        0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
                    ],
                ));
            }
            // IHDR compression and filter methods are both fixed to zero.
            if len >= 29 {
                out.push(Crib::new(26, [0x00, 0x00]));
            }
        }
        "JPEG" => {
            if len >= 2 {
                out.push(Crib::new((len - 2) as u64, [0xff, 0xd9]));
            }
        }
        "WAVE/RIFF" | "AVI/RIFF" | "WebP/RIFF" => {
            if len >= 8 && len - 8 <= u32::MAX as usize {
                out.push(Crib::new(4, ((len - 8) as u32).to_le_bytes()));
            }
        }
        "BMP" => {
            if len <= u32::MAX as usize {
                out.push(Crib::new(2, (len as u32).to_le_bytes()));
            }
        }
        "GIF87a" | "GIF89a" => {
            if len > 0 {
                out.push(Crib::new((len - 1) as u64, [0x3b]));
            }
        }
        "TGA" => {
            // TGA 2.0 footer ends with this fixed 18-byte signature. Older TGA
            // files without the footer remain unsupported rather than guessed.
            const FOOTER_SIG: &[u8] = b"TRUEVISION-XFILE.\0";
            if len >= FOOTER_SIG.len() {
                out.push(Crib::new((len - FOOTER_SIG.len()) as u64, FOOTER_SIG));
            }
        }
        "Kirikiri/Text-mode2" => {
            // FE FE 02 FF FE + compressed_size(u64) + uncompressed_size(u64)
            // + zlib. The physical wrapper length determines compressed_size
            // exactly, which contributes eight additional key observations.
            if len >= 21 {
                out.push(Crib::new(5, ((len - 21) as u64).to_le_bytes()));
            }
        }
        "TJS2/Bytecode" => {
            if len <= u32::MAX as usize && len >= 16 {
                out.push(Crib::new(8, (len as u32).to_le_bytes()));
            }
        }
        "PSB/M2-Emote" => {
            // Current supported PSB versions are encoded as a little-endian
            // u16, so the high byte is zero even though the low byte is a set.
            if len >= 6 {
                out.push(Crib::new(5, [0x00]));
            }
        }
        _ => {}
    }
    out
}

/// Non-singleton but exact format constraints. Unlike heuristic byte scoring,
/// these are safe to use for candidate elimination: the correct plaintext byte
/// must belong to the listed set for this hypothesis.
pub fn hard_plaintext_constraints(
    hypothesis: &FormatHypothesis,
    len: usize,
) -> Vec<PlainByteConstraint> {
    let mut out = Vec::new();
    match hypothesis.name {
        "PNG" if len >= 29 => {
            out.push(PlainByteConstraint::new(24, vec![1, 2, 4, 8, 16]));
            out.push(PlainByteConstraint::new(25, vec![0, 2, 3, 4, 6]));
            out.push(PlainByteConstraint::new(28, vec![0, 1]));
        }
        "Ogg" | "Ogg/Vorbis" if len >= 6 => {
            // First page must have BOS and cannot be a continuation. EOS may
            // additionally be present for a degenerate one-page logical stream.
            out.push(PlainByteConstraint::new(5, vec![0x02, 0x06]));
        }
        "Ogg/Opus-family0" | "Ogg/Opus-family0-smalltags" if len >= 38 => {
            out.push(PlainByteConstraint::new(37, vec![1, 2]));
        }
        "TLG5" if len >= 12 => {
            out.push(PlainByteConstraint::new(11, vec![3, 4]));
        }
        "PSB/M2-Emote" if len >= 5 => {
            out.push(PlainByteConstraint::new(4, vec![1, 2, 3, 4]));
        }
        _ => {}
    }
    out
}

/// Return only hypotheses supported by a recognized filename extension.
pub fn specific_hypotheses_for_name(name: &str) -> Vec<FormatHypothesis> {
    let ext = Path::new(name)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let lower_name = name.replace('\\', "/").to_ascii_lowercase();
    builtin_hypotheses()
        .into_iter()
        .filter(|hypothesis| {
            hypothesis.extensions.iter().any(|candidate| {
                *candidate == ext
                    || (candidate.contains('.') && lower_name.ends_with(&format!(".{candidate}")))
            })
        })
        .collect()
}

/// Return only plaintext facts shared by every extension-specific hypothesis.
/// This keeps shared-key probing conservative even when one extension has
/// several strict/common sub-models.
pub fn shared_cribs_for_name(name: &str) -> Vec<Crib> {
    let hypotheses = specific_hypotheses_for_name(name);
    let Some(first) = hypotheses.first() else {
        return Vec::new();
    };
    first
        .cribs
        .iter()
        .filter(|crib| {
            hypotheses.iter().all(|hypothesis| {
                hypothesis.cribs.iter().any(|candidate| {
                    candidate.offset == crib.offset && candidate.plaintext == crib.plaintext
                })
            })
        })
        .cloned()
        .collect()
}

/// Select extension-specific hypotheses when a usable extension exists. If the
/// filename is hidden or has an unknown extension, return all built-ins rather
/// than giving up on content identification.
pub fn hypotheses_for_name(name: &str) -> Vec<FormatHypothesis> {
    let selected = specific_hypotheses_for_name(name);
    if !selected.is_empty() {
        return selected;
    }

    let path = Path::new(name);
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Broad content sniffing is appropriate only when the archive has not
    // supplied a meaningful filename/extension.  A real `foo.tjs` is evidence
    // about the intended content family; treating it as GIF/WAVE merely because
    // the TJS model is incomplete creates false-positive plaintexts.
    let hidden_or_generic = ext.is_empty() || ext == "bin" || ext == "dat";
    if hidden_or_generic {
        builtin_hypotheses()
    } else {
        Vec::new()
    }
}

fn known_plain_byte(ciphertext: &[u8], candidate: &PeriodCandidate, offset: usize) -> Option<u8> {
    let cipher = *ciphertext.get(offset)?;
    let key = candidate.key.get(offset % candidate.period)?.as_ref()?;
    Some(cipher ^ *key)
}

fn known_plain_slice(
    ciphertext: &[u8],
    candidate: &PeriodCandidate,
    offset: usize,
    len: usize,
) -> Option<Vec<u8>> {
    (0..len)
        .map(|delta| known_plain_byte(ciphertext, candidate, offset + delta))
        .collect()
}

fn crib_key(crib: &Crib) -> (u64, Vec<u8>) {
    (crib.offset, crib.plaintext.clone())
}

fn push_unique(out: &mut Vec<Crib>, seen: &mut HashSet<(u64, Vec<u8>)>, crib: Crib) {
    if seen.insert(crib_key(&crib)) {
        out.push(crib);
    }
}

/// Discover additional exact plaintext fragments from a partially recovered
/// key.  This is intentionally conservative: dynamic evidence is emitted only
/// when the already-known key material makes the structural conclusion exact.
pub fn discover_dynamic_cribs(
    ciphertext: &[u8],
    hypothesis: &FormatHypothesis,
    candidate: &PeriodCandidate,
) -> Vec<Crib> {
    match hypothesis.dynamic {
        DynamicModel::Png => discover_png_cribs(ciphertext, candidate),
        DynamicModel::Ogg | DynamicModel::Opus => {
            discover_ogg_cribs(ciphertext, hypothesis.dynamic, candidate)
        }
        _ => Vec::new(),
    }
}

fn discover_png_cribs(ciphertext: &[u8], candidate: &PeriodCandidate) -> Vec<Crib> {
    const TYPES: [&[u8; 4]; 20] = [
        b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB",
        b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"eXIf", b"acTL",
    ];
    if candidate.period == 0 || ciphertext.len() < 20 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut position = 8usize; // first chunk length field
    let mut chunks = 0usize;

    while position + 12 <= ciphertext.len() && chunks < 1_000_000 {
        let Some(length_bytes) = known_plain_slice(ciphertext, candidate, position, 4) else {
            break;
        };
        let length = u32::from_be_bytes(length_bytes.as_slice().try_into().unwrap()) as usize;
        let type_offset = position + 4;
        let Some(end) = type_offset
            .checked_add(4)
            .and_then(|v| v.checked_add(length))
            .and_then(|v| v.checked_add(4))
        else {
            break;
        };
        if end > ciphertext.len() {
            break;
        }

        let mut matching = Vec::new();
        for tag in TYPES {
            let mut known = 0usize;
            let mut mismatch = false;
            for (delta, &plain) in tag.iter().enumerate() {
                let slot = (type_offset + delta) % candidate.period;
                if let Some(key) = candidate.key[slot] {
                    known += 1;
                    if ciphertext[type_offset + delta] ^ plain != key {
                        mismatch = true;
                        break;
                    }
                }
            }
            if !mismatch && known >= 2 {
                matching.push(tag);
            }
        }
        if matching.len() == 1 {
            push_unique(
                &mut out,
                &mut seen,
                Crib::new(type_offset as u64, matching[0]),
            );
        }

        position = end;
        chunks += 1;
        if position == ciphertext.len() {
            break;
        }
    }
    out
}

fn discover_ogg_cribs(
    ciphertext: &[u8],
    model: DynamicModel,
    candidate: &PeriodCandidate,
) -> Vec<Crib> {
    if candidate.period == 0 || ciphertext.len() < 27 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    // 1) Exact page walking.  Once page_segments and all lacing bytes for a
    // page are decryptable, the next page offset is determined by RFC 3533.
    // That immediately yields another "OggS\0" crib at an exact offset.
    let mut page = 0usize;
    let mut position = 0usize;
    let mut walked = 0usize;
    let mut opus_comment_active = matches!(model, DynamicModel::Opus);
    while position + 27 <= ciphertext.len() && walked < 1_000_000 {
        walked += 1;
        push_unique(&mut out, &mut seen, Crib::new(position as u64, b"OggS\0"));
        let Some(segment_count) = known_plain_byte(ciphertext, candidate, position + 26) else {
            break;
        };
        let segment_count = segment_count as usize;
        if position + 27 + segment_count > ciphertext.len() {
            break;
        }
        let Some(lacing) = known_plain_slice(ciphertext, candidate, position + 27, segment_count)
        else {
            break;
        };
        let body_size: usize = lacing.iter().map(|&x| x as usize).sum();
        let Some(next) = position
            .checked_add(27)
            .and_then(|x| x.checked_add(segment_count))
            .and_then(|x| x.checked_add(body_size))
        else {
            break;
        };
        if next <= position || next > ciphertext.len() {
            break;
        }
        if next == ciphertext.len() {
            break;
        }

        // Opus comment-header pages have deterministic granule semantics.
        // Page 0 is already covered by static cribs.  Starting at page 1, a
        // page whose packet does not complete has granule -1; the page where
        // the comment packet completes has granule 0.
        if opus_comment_active && page >= 1 && !lacing.is_empty() {
            let packet_completes = lacing.iter().any(|&x| x < 255);
            let granule = if packet_completes {
                [0u8; 8]
            } else {
                [0xffu8; 8]
            };
            push_unique(
                &mut out,
                &mut seen,
                Crib::new((position + 6) as u64, granule),
            );
            if packet_completes {
                opus_comment_active = false;
            }
        }

        page += 1;
        position = next;
    }

    // 2) Resynchronisation scan.  Ogg deliberately repeats the capture pattern
    // at every page.  If at least four of the five bytes "OggS\0" overlap key
    // slots we already know and all agree, accidental matches are negligible;
    // accept the location as a new exact crib.  A later iteration may then make
    // its lacing table decryptable and allow exact page walking to continue.
    const ANCHOR: &[u8] = b"OggS\0";
    if ciphertext.len() >= ANCHOR.len() {
        for offset in 1..=ciphertext.len() - ANCHOR.len() {
            let mut known = 0usize;
            let mut mismatch = false;
            for (delta, &plain) in ANCHOR.iter().enumerate() {
                let slot = (offset + delta) % candidate.period;
                if let Some(key) = candidate.key[slot] {
                    known += 1;
                    if ciphertext[offset + delta] ^ plain != key {
                        mismatch = true;
                        break;
                    }
                }
            }
            if !mismatch && known >= 4 {
                push_unique(&mut out, &mut seen, Crib::new(offset as u64, ANCHOR));
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave_has_disjoint_offset_features() {
        let h = hypotheses_for_name("voice/test.wav");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].cribs.len(), 2);
        assert_eq!(h[0].cribs[1].offset, 8);
    }

    #[test]
    fn generic_bin_name_falls_back_to_all_formats() {
        let h = hypotheses_for_name("font.bin");
        assert!(h.len() > 10);
        assert!(h.iter().any(|x| x.name == "PNG"));
        assert!(h.iter().any(|x| x.name == "TLG6-rgba"));
    }

    #[test]
    fn tjs_never_falls_back_to_image_or_audio_formats() {
        let h = hypotheses_for_name("scenario/startup.tjs");
        assert!(!h.is_empty());
        assert!(h.iter().all(|x| x.name.starts_with("Text/")
            || x.name.starts_with("Kirikiri/Text-")
            || x.name == "TJS2/Bytecode"));
        assert!(!h
            .iter()
            .any(|x| x.name.starts_with("GIF") || x.name.contains("RIFF")));
    }

    #[test]
    fn unknown_real_extension_does_not_silently_sniff_everything() {
        assert!(hypotheses_for_name("scenario/foo.customext").is_empty());
    }

    #[test]
    fn psb_family_extensions_route_to_m2_model() {
        for name in [
            "motion.psb",
            "image.pimg",
            "scene.scn",
            "model.mmo",
            "x.emtbytes",
            "a.psb.m",
        ] {
            let h = hypotheses_for_name(name);
            assert!(h.iter().any(|x| x.name == "PSB/M2-Emote"), "{name}");
        }
    }

    #[test]
    fn kirikiri_prerendered_font_has_exact_v0_v1_magic_models() {
        let h = hypotheses_for_name("font.tft");
        assert_eq!(h.len(), 2);
        assert!(h.iter().any(|x| {
            x.name == "Kirikiri/PrerenderedFont-v0"
                && x.cribs[0].plaintext == TVP_PRERENDERED_FONT_V0_MAGIC
        }));
        assert!(h.iter().any(|x| {
            x.name == "Kirikiri/PrerenderedFont-v1"
                && x.cribs[0].plaintext == TVP_PRERENDERED_FONT_V1_MAGIC
        }));
    }

    #[test]
    fn common_kirikiri_binary_formats_have_dedicated_models() {
        assert!(hypotheses_for_name("font.ttf")
            .iter()
            .any(|x| x.name == "TrueType/sfnt"));
        assert!(hypotheses_for_name("music.flac")
            .iter()
            .any(|x| x.name == "FLAC"));
        assert!(hypotheses_for_name("movie.mp4")
            .iter()
            .any(|x| x.name == "MP4/ISO-BMFF"));
        assert!(hypotheses_for_name("image.jxr")
            .iter()
            .any(|x| x.name == "JPEG-XR/WMP"));
        assert!(hypotheses_for_name("movie.m1v")
            .iter()
            .any(|x| x.name == "MPEG-1/Video"));
        assert!(hypotheses_for_name("movie.h264")
            .iter()
            .any(|x| x.name.starts_with("H264/AnnexB")));
        assert!(hypotheses_for_name("cursor.cur")
            .iter()
            .any(|x| x.name == "CUR"));
    }

    #[test]
    fn opus_has_multiple_models_and_shared_facts() {
        let h = specific_hypotheses_for_name("voice/vo9_0012.opus");
        assert!(h.len() >= 3);
        assert!(h.iter().any(|x| x.name == "Ogg/Opus"));
        assert!(h.iter().any(|x| x.name == "Ogg/Opus-family0"));
        let shared = shared_cribs_for_name("voice/vo9_0012.opus");
        assert!(shared
            .iter()
            .any(|x| x.offset == 0 && x.plaintext == b"OggS"));
        assert!(shared
            .iter()
            .any(|x| x.offset == 6 && x.plaintext == vec![0u8; 8]));
        assert!(!shared
            .iter()
            .any(|x| x.offset == 28 && x.plaintext == b"OpusHead"));
    }

    #[test]
    fn tlg_uses_full_raw_magic() {
        let h = specific_hypotheses_for_name("image/foo.tlg");
        assert!(h
            .iter()
            .any(|x| x.cribs.iter().any(|c| c.plaintext == TLG5_MAGIC)));
        assert!(h
            .iter()
            .any(|x| x.cribs.iter().any(|c| c.plaintext == TLG6_MAGIC)));
        assert!(h
            .iter()
            .any(|x| x.cribs.iter().any(|c| c.plaintext == TLG0_MAGIC)));
    }

    #[test]
    fn png_length_adds_far_end_crib() {
        let hypothesis = specific_hypotheses_for_name("image.png")
            .into_iter()
            .find(|h| h.name == "PNG")
            .unwrap();
        let cribs = length_derived_cribs(&hypothesis, 100);
        assert!(cribs.iter().any(|crib| {
            crib.offset == 88
                && crib.plaintext
                    == vec![
                        0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
                    ]
        }));
    }
}
