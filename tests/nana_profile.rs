use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use xp3_brute::{
    adler32, cxdec_filename_md5_token, CxdecEngine, CxdecGeneratorKind, CxdecProfile,
    NanaDecryptor, YuzKey, XP3_MAGIC,
};

const KEY: [u32; 6] = [1, 12, 123, 1234, 12345, 123456];
const FILES: [(&str, &[u8]); 2] = [
    ("画像/表情.bin", b"first content sample"),
    ("scenario/second.bin", b"second content sample"),
];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "xp3-nana-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend((body.len() as u64).to_le_bytes());
    bytes.extend(body);
    bytes
}

fn file_chunk(name: &str, checksum: u32, data_offset: usize, size: usize) -> Vec<u8> {
    let mut info = 0x8000_0000u32.to_le_bytes().to_vec();
    info.extend((size as u64).to_le_bytes());
    info.extend((size as u64).to_le_bytes());
    info.extend((name.encode_utf16().count() as u16).to_le_bytes());
    info.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    let mut segment = 0u32.to_le_bytes().to_vec();
    segment.extend((data_offset as u64).to_le_bytes());
    segment.extend((size as u64).to_le_bytes());
    segment.extend((size as u64).to_le_bytes());
    let mut body = chunk(b"info", &info);
    body.extend(chunk(b"segm", &segment));
    body.extend(chunk(b"adlr", &checksum.to_le_bytes()));
    chunk(b"File", &body)
}

fn make_fixture(
    directory: &TestDirectory,
    bad_adler: bool,
    trailing_data: bool,
    direct_files: &[(&str, &[u8], u32)],
) {
    let content = CxdecProfile {
        mask: 0x0f,
        offset: 7,
        prolog_order: [0, 1, 2],
        even_branch_order: [0, 1, 2, 3, 4, 5, 6, 7],
        odd_branch_order: [0, 1, 2, 3, 4, 5],
        control_block: vec![0; 4096],
        generator: CxdecGeneratorKind::Cabbage { random_seed: 217 },
        wrappers: Vec::new(),
    };
    let engine = CxdecEngine::new(content.clone()).unwrap();
    fs::write(directory.join("control.bin"), &content.control_block).unwrap();

    let mut name_records = Vec::new();
    let mut archive = XP3_MAGIC.to_vec();
    archive.extend([0; 8]);
    let mut file_records = Vec::new();
    for (number, (name, plain)) in FILES.iter().enumerate() {
        let checksum = adler32(plain);
        let mut content = plain.to_vec();
        engine.apply(0, checksum, &mut content).unwrap();
        let token = cxdec_filename_md5_token("dls:", name);
        file_records.extend(file_chunk(&token, checksum, archive.len(), content.len()));
        archive.extend(content);

        let name_checksum = if bad_adler && number == 0 {
            checksum ^ 1
        } else {
            checksum
        };
        let mut record = name_checksum.to_le_bytes().to_vec();
        record.extend((name.encode_utf16().count() as u16).to_le_bytes());
        record.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        record.extend([0, 0]);
        let mut reversed = chunk(b"hnfn", &record);
        reversed.extend(name_records);
        name_records = reversed;
    }
    for &(name, plain, checksum) in direct_files {
        file_records.extend(file_chunk(name, checksum, archive.len(), plain.len()));
        archive.extend(plain);
    }
    let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
    compressed.write_all(&name_records).unwrap();
    let mut stored = compressed.finish().unwrap();
    if trailing_data {
        stored.push(0);
    }
    let prefix_len = stored.len().min(0x100);
    NanaDecryptor::new(YuzKey(KEY)).apply(&mut stored[..prefix_len]);

    let mut descriptor = (archive.len() as u64).to_le_bytes().to_vec();
    descriptor.extend((name_records.len() as u32).to_le_bytes());
    descriptor.extend((stored.len() as u32).to_le_bytes());
    archive.extend(stored);
    let mut index = chunk(b"dls:", &descriptor);
    index.extend(file_records);
    let index_offset = archive.len() as u64;
    archive[11..19].copy_from_slice(&index_offset.to_le_bytes());
    archive.push(0);
    archive.extend((index.len() as u64).to_le_bytes());
    archive.extend(index);
    fs::write(directory.join("input.xp3"), archive).unwrap();
}

fn write_profile(directory: &TestDirectory, key: [u32; 6], random_seed: u32) -> PathBuf {
    let profile = directory.join("profile.json");
    let data = json!({
        "name_state": key,
        "content": {
            "mask": 15, "offset": 7,
            "prolog_order": [0, 1, 2],
            "even_branch_order": [0, 1, 2, 3, 4, 5, 6, 7],
            "odd_branch_order": [0, 1, 2, 3, 4, 5],
            "random_seed": random_seed,
            "control_block_file": "control.bin",
        }
    });
    fs::write(&profile, serde_json::to_vec(&data).unwrap()).unwrap();
    profile
}

fn unpack(directory: &TestDirectory, profile: &Path, output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xp3brute"))
        .arg("unpack")
        .arg(directory.join("input.xp3"))
        .arg(output)
        .args(["--no-progress", "--compute", "cpu", "--nana-profile"])
        .arg(profile)
        .output()
        .unwrap()
}

#[test]
fn nana_profile_unpacks_files_under_verified_original_names() {
    let directory = TestDirectory::new();
    make_fixture(&directory, false, false, &[]);
    let profile = write_profile(&directory, KEY, 217);
    let output_path = directory.join("extracted");
    let result = unpack(&directory, &profile, &output_path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (name, data) in FILES {
        assert_eq!(fs::read(output_path.join(name)).unwrap(), data);
    }

    let inspection = Command::new(env!("CARGO_BIN_EXE_xp3brute"))
        .arg("inspect")
        .arg(directory.join("input.xp3"))
        .arg("--nana-profile")
        .arg(&profile)
        .output()
        .unwrap();
    assert!(inspection.status.success());
    let listing = String::from_utf8(inspection.stdout).unwrap();
    assert!(listing.contains("name=画像/表情.bin"));
    assert!(listing.contains("decoder=nana-profile"));
}

#[test]
fn nana_profile_keeps_both_direct_startup_entries() {
    let directory = TestDirectory::new();
    let bootstrap = b"bootstrap script";
    let literal = b"other startup script";
    let direct_files = [
        ("$", bootstrap.as_slice(), adler32(bootstrap)),
        ("startup.tjs", literal.as_slice(), adler32(literal)),
    ];
    make_fixture(&directory, false, false, &direct_files);
    let profile = write_profile(&directory, KEY, 217);
    let output = directory.join("extracted");
    let result = unpack(&directory, &profile, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (name, data) in FILES {
        assert_eq!(fs::read(output.join(name)).unwrap(), data);
    }
    for (name, data, _) in direct_files {
        assert_eq!(fs::read(output.join(name)).unwrap(), data);
    }
}

#[test]
fn nana_profile_rejects_unverified_mixed_entries_before_output() {
    let plain = b"direct content";
    let checksum = adler32(plain);
    let cases = [
        (
            "0123456789abcdef0123456789abcdef",
            checksum,
            "no filename token",
        ),
        ("startup.tjs", checksum ^ 1, "direct File"),
        ("SCENARIO\\SECOND.BIN", checksum, "duplicate output path"),
        ("scenario", checksum, "conflicting output path"),
        ("../outside", checksum, "invalid direct filename"),
    ];
    for (name, checksum, cause) in cases {
        let directory = TestDirectory::new();
        make_fixture(&directory, false, false, &[(name, plain, checksum)]);
        let profile = write_profile(&directory, KEY, 217);
        let output = directory.join("extracted");
        let result = unpack(&directory, &profile, &output);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success(), "unexpected success for {cause}");
        assert!(stderr.contains(cause), "expected {cause}: {stderr}");
        assert!(!output.exists());
    }
}

#[test]
fn nana_profile_rejects_invalid_names_or_content_before_output() {
    let cases = [
        (false, false, [0; 6], 217, "zlib"),
        (true, false, KEY, 217, "Adler-32 mismatch"),
        (false, true, KEY, 217, "decoded size"),
        (false, false, KEY, 218, "content profile did not validate"),
    ];
    for (bad_adler, trailing_data, key, seed, cause) in cases {
        let directory = TestDirectory::new();
        make_fixture(&directory, bad_adler, trailing_data, &[]);
        let profile = write_profile(&directory, key, seed);
        let output_path = directory.join("extracted");
        let result = unpack(&directory, &profile, &output_path);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success(), "unexpected success for {cause}");
        assert!(stderr.contains(cause), "expected {cause}: {stderr}");
        assert!(!output_path.exists());
    }
}
