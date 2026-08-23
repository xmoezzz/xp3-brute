#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MagicGuess {
    pub message: String,
    pub mime_type: String,
    pub strength: u64,
    pub extensions: Vec<String>,
}

#[cfg(feature = "magic-sniff")]
mod imp {
    use super::MagicGuess;
    use magic_embed::magic_embed;
    use pure_magic::{Magic, MagicDb};
    use std::sync::OnceLock;

    // Project-private KiriKiri formats are expressed with the same rule language;
    // binary marker bytes are continuation rules so pure-magic and file(1)
    // agree on the printable parent string.
    // as libmagic/file(1), but compiled and evaluated entirely in Rust.
    #[magic_embed(include = ["../magic/krkr"])]
    struct KrkrMagicDb;

    static PROJECT_DB: OnceLock<Option<MagicDb>> = OnceLock::new();
    static STANDARD_DB: OnceLock<Option<MagicDb>> = OnceLock::new();

    pub(super) fn project_db() -> Option<&'static MagicDb> {
        PROJECT_DB.get_or_init(|| KrkrMagicDb::open().ok()).as_ref()
    }

    fn standard_db() -> Option<&'static MagicDb> {
        STANDARD_DB.get_or_init(|| magic_db::load().ok()).as_ref()
    }

    fn to_guess(magic: Magic<'_>) -> Option<MagicGuess> {
        if magic.is_default() {
            return None;
        }
        // Preserve libmagic rule order: the first extension is the rule's
        // canonical spelling and is used when a generic .bin/.dat output is
        // renamed after verified decryption. Sorting aliases (for example
        // jpg/jpeg or zip/jar) would destroy that preference.
        let extensions: Vec<String> = magic
            .extensions()
            .iter()
            .map(|value| value.as_ref().to_string())
            .collect();
        Some(MagicGuess {
            message: magic.message(),
            mime_type: magic.mime_type().to_string(),
            strength: magic.strength(),
            extensions,
        })
    }

    pub fn sniff_bytes(bytes: &[u8]) -> Option<MagicGuess> {
        // Project rules win over the generic database. This lets us extend
        // libmagic semantics for KiriKiri private formats without hard-coding
        // byte-prefix recognizers in Rust.
        if let Some(db) = project_db() {
            if let Ok(magic) = db.best_magic_slice(bytes) {
                if let Some(guess) = to_guess(magic) {
                    return Some(guess);
                }
            }
        }

        let magic = standard_db()?.best_magic_slice(bytes).ok()?;
        to_guess(magic)
    }
}

#[cfg(feature = "magic-sniff")]
pub use imp::sniff_bytes;

#[cfg(not(feature = "magic-sniff"))]
pub fn sniff_bytes(_bytes: &[u8]) -> Option<MagicGuess> {
    None
}


/// Bounded content-first PE recognition used by executable/module discovery.
/// `pure-magic` is consulted when enabled, then a strict MZ + PE signature
/// check is used as the feature-independent fallback.  This deliberately does
/// not add a project magic rule for the bare `MZ` prefix: doing so would make
/// the project database override more specific standard DOS/PE rules.
pub fn looks_like_pe_bytes(bytes: &[u8]) -> bool {
    if let Some(guess) = sniff_bytes(bytes) {
        let mime = guess.mime_type.to_ascii_lowercase();
        let message = guess.message.to_ascii_lowercase();
        let ext_match = guess.extensions.iter().any(|ext| {
            matches!(ext.to_ascii_lowercase().as_str(), "exe" | "dll" | "sys" | "scr")
        });
        if mime.contains("portable-executable")
            || mime.contains("x-dosexec")
            || message.contains("pe32 executable")
            || message.contains("portable executable")
            || ext_match
        {
            return true;
        }
    }
    structural_pe_signature(bytes)
}

/// Return true when `path` is a likely Windows PE module. Known KiriKiri
/// module extensions are a zero-I/O fast path; unknown extensions are sampled
/// and classified by magic/PE structure so renamed plugins are not missed.
pub fn path_looks_like_pe(path: &std::path::Path) -> bool {
    if path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "exe" | "dll" | "tpm"))
        .unwrap_or(false)
    {
        return true;
    }

    read_pe_prefix(path).is_some_and(|bytes| looks_like_pe_bytes(&bytes))
}

/// Strict content-first recognition for the *main game executable* discovery
/// path.  Unlike `path_looks_like_pe`, this does not trust the extension: the
/// candidate must be an i386 PE32 executable image and must not carry the DLL
/// characteristic.  `pure-magic`/the standard magic DB is still consulted as
/// the coarse content classifier before the PE header is validated.
pub fn path_looks_like_pe32_executable(path: &std::path::Path) -> bool {
    read_pe_prefix(path).is_some_and(|bytes| looks_like_pe32_executable_bytes(&bytes))
}

pub fn looks_like_pe32_executable_bytes(bytes: &[u8]) -> bool {
    if !looks_like_pe_bytes(bytes) {
        return false;
    }
    let Some(pe_offset) = pe_header_offset(bytes) else {
        return false;
    };
    // COFF header: machine, section count, timestamp, symbols, optional-size,
    // characteristics.  PE32 optional-header magic follows immediately.
    let Some(coff_end) = pe_offset.checked_add(24) else {
        return false;
    };
    if coff_end > bytes.len() {
        return false;
    }
    let machine = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);
    let optional_size =
        u16::from_le_bytes([bytes[pe_offset + 20], bytes[pe_offset + 21]]) as usize;
    let characteristics =
        u16::from_le_bytes([bytes[pe_offset + 22], bytes[pe_offset + 23]]);
    let optional = pe_offset + 24;
    if optional_size < 2 || optional + 2 > bytes.len() {
        return false;
    }
    let optional_magic = u16::from_le_bytes([bytes[optional], bytes[optional + 1]]);

    const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    const IMAGE_FILE_DLL: u16 = 0x2000;
    const PE32_MAGIC: u16 = 0x010b;
    machine == IMAGE_FILE_MACHINE_I386
        && optional_magic == PE32_MAGIC
        && characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0
        && characteristics & IMAGE_FILE_DLL == 0
}

fn read_pe_prefix(path: &std::path::Path) -> Option<Vec<u8>> {
    const MAX_PE_CANDIDATE_SIZE: u64 = 256 * 1024 * 1024;
    const SNIFF_PREFIX: usize = 256 * 1024;
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() < 0x40 || metadata.len() > MAX_PE_CANDIDATE_SIZE {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(SNIFF_PREFIX.min(metadata.len() as usize));
    let mut limited = std::io::Read::take(file, SNIFF_PREFIX as u64);
    std::io::Read::read_to_end(&mut limited, &mut bytes).ok()?;
    Some(bytes)
}

fn pe_header_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 0x40 || bytes.get(0..2) != Some(&b"MZ"[..]) {
        return None;
    }
    let pe_offset = u32::from_le_bytes([
        bytes[0x3c],
        bytes[0x3d],
        bytes[0x3e],
        bytes[0x3f],
    ]) as usize;
    let end = pe_offset.checked_add(4)?;
    (end <= bytes.len() && bytes.get(pe_offset..end) == Some(&b"PE\0\0"[..]))
        .then_some(pe_offset)
}

fn structural_pe_signature(bytes: &[u8]) -> bool {
    pe_header_offset(bytes).is_some()
}

#[cfg(all(test, feature = "magic-sniff"))]
mod tests {
    use super::*;

    #[test]
    fn tvp_prerendered_font_is_recognized_by_embedded_libmagic_rule() {
        let mut bytes = b"TVP pre-rendered font\x1a\x01\x02".to_vec();
        bytes.resize(36, 0);
        let raw = super::imp::project_db()
            .expect("embedded project magic database")
            .best_magic_slice(&bytes)
            .expect("evaluate project magic database");
        assert!(!raw.is_default(), "project magic result: {}", raw.message());
        let guess = sniff_bytes(&bytes).expect("TVP font magic");
        assert_eq!(guess.mime_type, "application/x-kirikiri-prerendered-font");
        assert_eq!(guess.extensions, vec!["tft"]);
        assert!(guess.message.contains("KiriKiri/TVP pre-rendered font"));
    }
}

#[cfg(test)]
mod pe_tests {
    use super::*;

    #[test]
    fn structural_pe_fallback_recognizes_extension_independent_pe() {
        let mut bytes = vec![0u8; 0x90];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(looks_like_pe_bytes(&bytes));
    }

    #[test]
    fn mz_without_pe_header_is_not_enough() {
        let mut bytes = vec![0u8; 0x90];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(!structural_pe_signature(&bytes));
    }

    fn synthetic_pe32(characteristics: u16, machine: u16, optional_magic: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&optional_magic.to_le_bytes());
        bytes
    }

    #[test]
    fn pe32_game_executable_rejects_dll_and_pe32_plus() {
        let exe = synthetic_pe32(0x0002, 0x014c, 0x010b);
        assert!(looks_like_pe32_executable_bytes(&exe));

        let dll = synthetic_pe32(0x2002, 0x014c, 0x010b);
        assert!(!looks_like_pe32_executable_bytes(&dll));

        let x64 = synthetic_pe32(0x0002, 0x8664, 0x020b);
        assert!(!looks_like_pe32_executable_bytes(&x64));
    }
}
