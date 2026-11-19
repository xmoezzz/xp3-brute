use std::collections::HashMap;
use std::path::{Path, PathBuf};

use xp3_brute::{adler32, Archive, Entry};

const STATE_MASK: u32 = 0x7fff_ffff;
const PERIOD: usize = 31;
const SAMPLE_SIZE_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const PROTECTED: u32 = 0x8000_0000;
const SIGNATURES: &[&[u8]] = &[
    b"TLG0.0\0sds\x1a",
    b"TLG5.0\0raw\x1a",
    b"TLG6.0\0raw\x1a",
    b"KBAD100\0",
];

/// The 31-bit state is a rotation of the archive checksum mixed with the seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MadoCrypt(u32);

impl MadoCrypt {
    fn key(self, adler: u32) -> [u8; PERIOD] {
        let mut state = (adler ^ self.0) & STATE_MASK;
        state |= (state & 1) << 31;
        std::array::from_fn(|_| {
            let byte = state as u8;
            state = ((state & !1) << 23) | (state >> 8);
            byte
        })
    }

    pub(crate) fn apply(self, adler: u32, offset: u64, bytes: &mut [u8]) {
        let mut key = self.key(adler);
        key.rotate_left((offset % PERIOD as u64) as usize);
        for block in bytes.chunks_mut(PERIOD) {
            for (byte, mask) in block.iter_mut().zip(key) {
                *byte ^= mask;
            }
        }
    }

    fn from_header(adler: u32, raw: &[u8], magic: &[u8]) -> Option<Self> {
        if raw.len() < magic.len() {
            return None;
        }
        // Four consecutive keystream bytes expose the 31 bits of state and
        // the repeated low bit. The rest of the signature checks the guess.
        let state = u32::from_le_bytes(std::array::from_fn(|i| raw[i] ^ magic[i]));
        if (state >> 31) != (state & 1) {
            return None;
        }
        let candidate = Self((state ^ adler) & STATE_MASK);
        raw.iter()
            .zip(candidate.key(adler))
            .zip(magic)
            .all(|((&byte, key), &expected)| byte ^ key == expected)
            .then_some(candidate)
    }

    pub(crate) fn recover(archive: &Archive) -> Option<Self> {
        if archive.is_hxv4() || !archive.indirect_special_roots().is_empty() {
            return None;
        }
        if let Some(filter) = Self::from_tlg_samples(archive) {
            return Some(filter);
        }
        // A title can span multiple XP3 files. A small archive with no usable
        // image headers can reuse a locally inferred seed after independent
        // checks on that archive's own protected entries.
        let path = archive.path.as_deref()?;
        if !archive
            .entries
            .iter()
            .any(|entry| protected(entry).is_some())
        {
            return None;
        }
        for sibling in foreground_archives(path) {
            if sibling == path {
                continue;
            }
            let Ok(reference) = Archive::open(sibling) else {
                continue;
            };
            if reference.is_hxv4() || !reference.indirect_special_roots().is_empty() {
                continue;
            }
            if let Some(filter) = Self::from_tlg_samples(&reference) {
                if filter.validates(archive) {
                    return Some(filter);
                }
            }
        }
        None
    }

    fn from_tlg_samples(archive: &Archive) -> Option<Self> {
        let mut candidates = HashMap::new();
        let entries = archive
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let adler = protected(entry)?;
                let name = entry.name.rsplit('.').next()?;
                (name.eq_ignore_ascii_case("tlg") && entry.original_size <= SAMPLE_SIZE_LIMIT)
                    .then_some((index, adler))
            });
        for (index, adler) in entries.take(32) {
            let Ok(raw) = archive.reconstruct_entry(index) else {
                continue;
            };
            for magic in SIGNATURES {
                if let Some(filter) = Self::from_header(adler, &raw, magic) {
                    let mut data = raw.clone();
                    filter.apply(adler, 0, &mut data);
                    if adler32(&data) == adler {
                        *candidates.entry(filter.0).or_insert(0) += 1;
                        break;
                    }
                }
            }
        }
        let mut candidates = candidates.into_iter().filter(|(_, count)| *count >= 2);
        let (seed, _) = candidates.next()?;
        (candidates.next().is_none() && Self(seed).validates(archive)).then_some(Self(seed))
    }

    fn validates(self, archive: &Archive) -> bool {
        let mut entries: Vec<_> = archive
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| Some((entry.original_size, index, protected(entry)?)))
            .collect();
        entries.sort_unstable();
        let mut matches = 0;
        for &(size, index, adler) in &entries {
            if matches >= 3 || (matches > 0 && size > SAMPLE_SIZE_LIMIT) {
                break;
            }
            let Ok(mut data) = archive.reconstruct_entry(index) else {
                return false;
            };
            if adler32(&data) == adler {
                continue;
            }
            self.apply(adler, 0, &mut data);
            if adler32(&data) != adler {
                return false;
            }
            matches += 1;
        }
        matches != 0
    }
}

fn protected(entry: &Entry) -> Option<u32> {
    if entry.flags & PROTECTED != 0 && entry.original_size != 0 {
        entry.adler
    } else {
        None
    }
}

fn foreground_archives(path: &Path) -> Vec<PathBuf> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    vec![
        parent.join("fgimage.xp3"),
        parent.join("arc").join("fgimage.xp3"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn madocrypt_recovers_seed_and_applies_file_relative_offsets() {
        let filter = MadoCrypt(0x1357_2468);
        let mut plain = SIGNATURES[0].to_vec();
        plain.extend(0..170);
        let adler = adler32(&plain);
        let mut cipher = plain.clone();
        filter.apply(adler, 0, &mut cipher);
        assert_eq!(
            MadoCrypt::from_header(adler, &cipher, SIGNATURES[0]),
            Some(filter)
        );
        assert!(MadoCrypt::from_header(adler, &cipher, SIGNATURES[1]).is_none());
        for (i, block) in cipher.chunks_mut(19).enumerate() {
            filter.apply(adler, (19 * i) as u64, block);
        }
        assert_eq!(cipher, plain);
    }
}
