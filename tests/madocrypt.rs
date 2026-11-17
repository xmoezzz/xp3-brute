use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use xp3_brute::{adler32, XP3_MAGIC};

const SEED: u32 = 0x0812_3456;
const SALT: &str = "example-test-salt";

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "xp3-mado-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("arc")).unwrap();
        Self(path)
    }

    fn join(&self, path: &str) -> PathBuf {
        self.0.join(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn xp3_chunk(tag: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend((value.len() as u64).to_le_bytes());
    bytes.extend(value);
    bytes
}

fn fixture_xp3(path: &Path, files: &[(String, Vec<u8>)]) {
    let mut archive = XP3_MAGIC.to_vec();
    archive.extend([0; 8]);
    let mut index = Vec::new();
    for (name, plain) in files {
        let size = (plain.len() as u64).to_le_bytes();
        let checksum = adler32(plain);
        let mut info = 0x8000_0000u32.to_le_bytes().to_vec();
        info.extend(size);
        info.extend(size);
        info.extend((name.encode_utf16().count() as u16).to_le_bytes());
        info.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        let mut segment = 0u32.to_le_bytes().to_vec();
        segment.extend((archive.len() as u64).to_le_bytes());
        segment.extend(size);
        segment.extend(size);
        let mut file = xp3_chunk(b"info", &info);
        file.extend(xp3_chunk(b"segm", &segment));
        file.extend(xp3_chunk(b"adlr", &checksum.to_le_bytes()));
        index.extend(xp3_chunk(b"File", &file));

        let state = (SEED ^ checksum) & 0x7fff_ffff;
        archive.extend(plain.iter().enumerate().map(|(i, byte)| {
            let shift = (i * 8) % 31;
            // Independent formulation using a rotation in the 31-bit ring.
            let mask = (state >> shift) | (state << (31 - shift));
            byte ^ mask as u8
        }));
    }
    let index_offset = (archive.len() as u64).to_le_bytes();
    archive[11..19].copy_from_slice(&index_offset);
    archive.push(0);
    archive.extend((index.len() as u64).to_le_bytes());
    archive.extend(index);
    fs::write(path, archive).unwrap();
}

fn tjs_chunk(tag: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend(((data.len() + 8) as u32).to_le_bytes());
    bytes.extend(data);
    bytes
}

fn tjs(strings: &[&str], has_function: bool) -> Vec<u8> {
    let mut data = vec![0; 20]; // empty byte, short, int, long and double pools
    data.extend((strings.len() as u32).to_le_bytes());
    for text in strings {
        let count = text.encode_utf16().count();
        data.extend((count as u32).to_le_bytes());
        data.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        if count % 2 == 1 {
            data.extend([0; 2]);
        }
    }
    data.extend([0; 4]); // octet count
    let mut objects = 0i32.to_le_bytes().to_vec();
    objects.extend((has_function as i32).to_le_bytes());
    if has_function {
        let mut function = vec![0; 14 * 4]; // object fields, source positions and code counts
        function.extend(4i32.to_le_bytes());
        for i in 1i16..=4 {
            function.extend(3i16.to_le_bytes()); // string constant type
            function.extend(i.to_le_bytes());
        }
        function.extend([0; 8]); // superclass and property counts
        objects.extend(tjs_chunk(b"TJS2", &function));
    }
    let mut result = b"TJS2100\0".to_vec();
    result.extend([0; 4]);
    result.extend(tjs_chunk(b"DATA", &data));
    result.extend(tjs_chunk(b"OBJS", &objects));
    let size = (result.len() as u32).to_le_bytes();
    result[8..12].copy_from_slice(&size);
    result
}

fn text(value: &str) -> Vec<u8> {
    let count = value.encode_utf16().count();
    assert!(count <= 31);
    let mut bytes = vec![0xa0 + count as u8];
    bytes.extend(value.encode_utf16().flat_map(u16::to_le_bytes));
    bytes
}

fn map(items: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = vec![0x80 + items.len() as u8];
    for (key, value) in items {
        bytes.extend(text(key));
        bytes.extend(value);
    }
    bytes
}

fn kbad(value: Vec<u8>) -> Vec<u8> {
    [b"KBAD100\0".as_slice(), &value].concat()
}

fn token(name: &str) -> String {
    let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut path: String = Sha256::digest(utf16)
        .iter()
        .map(|&byte| char::from_u32(0x4e00 + u32::from(byte)).unwrap())
        .collect();
    path.push_str(".tlg");
    path
}

fn unpack(archive: &Path, output: &Path, restore_names: bool) -> String {
    fs::create_dir(output).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_xp3brute"));
    command.arg("unpack").arg(archive).arg(output).args([
        "--no-exe-auto",
        "--no-progress",
        "--compute",
        "cpu",
        "--verbose",
    ]);
    if restore_names {
        command.arg("--restore-names");
    }
    let result = command.output().unwrap();
    let diagnostics = String::from_utf8(result.stderr).unwrap();
    assert!(result.status.success(), "{diagnostics}");
    assert!(diagnostics.contains("route=madocrypt archive-samples=verified"));
    diagnostics
}

#[test]
fn auto_madocrypt_restores_only_referenced_foreground_names_when_requested() {
    let dir = TestDir::new();
    let init_token = token("fixture-config-init");
    let levels_token = token("fixture-config-levels");
    let fgd_token = token("fg_sample_0");
    let first_token = token(&format!("fg_sample_0_7{SALT}"));
    let second_token = token(&format!("fg_sample_0_22{SALT}"));
    let orphan_token = token("orphan");
    let alphabet = (0x4e00..0x4f00)
        .map(|code| char::from_u32(code).unwrap())
        .collect::<String>();
    let utils = tjs(&[&alphabet], false);
    let layers = tjs(
        &["getLayerImageName", "_", SALT, "System", "getSHA256Name"],
        true,
    );
    let runner = tjs(&[&init_token, &levels_token], false);
    fixture_xp3(
        &dir.join("data.xp3"),
        &[
            ("utils.tjs".into(), utils.clone()),
            ("psdlayer.tjs".into(), layers),
            ("kagenvcharacterex.tjs".into(), runner),
        ],
    );

    let poses = map(&[("左向き", map(&[("filename", text("fg_sample"))]))]);
    let characters = map(&[("花", map(&[("map", poses)]))]);
    let init = kbad(map(&[("map", characters), ("list", vec![0x90])]));
    let levels = kbad(map(&[("花", map(&[("左向き", vec![0x91, 0x80])]))]));
    let mut pose = vec![0x93, 0x80]; // canvas and two image layers
    pose.extend(map(&[("layer_type", vec![0]), ("layer_id", vec![7])]));
    pose.extend(map(&[("layer_type", vec![0]), ("layer_id", vec![22])]));
    let first = b"TLG5.0\0raw\x1afixture first".to_vec();
    let second = b"TLG0.0\0sds\x1afixture second".to_vec();
    let orphan = b"TLG6.0\0raw\x1afixture orphan".to_vec();
    let fg = dir.join("arc/fgimage.xp3");
    fixture_xp3(
        &fg,
        &[
            (first_token.clone(), first.clone()),
            (second_token.clone(), second.clone()),
            (orphan_token.clone(), orphan.clone()),
            (init_token, init),
            (levels_token, levels),
            (fgd_token.clone(), kbad(pose)),
        ],
    );

    let data = dir.join("scripts");
    unpack(&dir.join("data.xp3"), &data, false);
    assert_eq!(fs::read(data.join("utils.tjs")).unwrap(), utils);

    let physical = dir.join("physical");
    unpack(&fg, &physical, false);
    assert_eq!(fs::read(physical.join(&first_token)).unwrap(), first);
    assert!(!physical.join("fg_sample_0_7.tlg").exists());

    let named = dir.join("named");
    let log = unpack(&fg, &named, true);
    assert!(log.contains("route=yakimochi-fgd mapped=2"));
    assert_eq!(fs::read(named.join("fg_sample_0_7.tlg")).unwrap(), first);
    assert_eq!(fs::read(named.join("fg_sample_0_22.tlg")).unwrap(), second);
    assert_eq!(fs::read(named.join(&orphan_token)).unwrap(), orphan);
    assert!(!named.join(&first_token).exists());
    assert!(!named.join(&second_token).exists());
    assert!(fs::read(named.join(fgd_token))
        .unwrap()
        .starts_with(b"KBAD100\0"));

    // An indexed path must not collide with a restored name on case-insensitive filesystems.
    let mut files = vec![
        (first_token, first),
        (second_token, second),
        (orphan_token, orphan),
        ("FG_SAMPLE_0_7.TLG".into(), b"existing file".to_vec()),
    ];
    let original = xp3_brute::Archive::open(&fg).unwrap();
    for (index, entry) in original.entries.iter().enumerate().skip(3) {
        let mut bytes = original.reconstruct_entry(index).unwrap();
        let checksum = entry.adler.unwrap();
        let state = (SEED ^ checksum) & 0x7fff_ffff;
        for (i, byte) in bytes.iter_mut().enumerate() {
            let shift = (i * 8) % 31;
            *byte ^= ((state >> shift) | (state << (31 - shift))) as u8;
        }
        files.push((entry.name.clone(), bytes));
    }
    fixture_xp3(&fg, &files);
    let collision_output = dir.join("collision-output");
    let result = Command::new(env!("CARGO_BIN_EXE_xp3brute"))
        .arg("unpack")
        .arg(&fg)
        .arg(&collision_output)
        .args([
            "--no-exe-auto",
            "--no-progress",
            "--compute",
            "cpu",
            "--restore-names",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("collides with an output path"));
    assert!(!collision_output.exists());
}

#[test]
fn auto_madocrypt_accepts_samples_larger_than_four_mib() {
    let dir = TestDir::new();
    let archive = dir.join("large.xp3");
    let mut first = b"TLG5.0\0raw\x1a".to_vec();
    first.resize(4 * 1024 * 1024 + 1, 0x42);
    let mut second = b"TLG6.0\0raw\x1a".to_vec();
    second.resize(4 * 1024 * 1024 + 2, 0x53);
    fixture_xp3(
        &archive,
        &[
            ("first.tlg".into(), first.clone()),
            ("second.tlg".into(), second.clone()),
        ],
    );
    let output = dir.join("large-output");
    unpack(&archive, &output, false);
    assert_eq!(fs::read(output.join("first.tlg")).unwrap(), first);
    assert_eq!(fs::read(output.join("second.tlg")).unwrap(), second);
}

fn const_tjs(text: &str) -> Vec<u8> {
    [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect()
}

#[test]
fn auto_madocrypt_restores_ev_definitions_and_layers_from_packaged_tjs() {
    let dir = TestDir::new();
    let alphabet = (0x4e00..0x4f00)
        .map(|code| char::from_u32(code).unwrap())
        .collect::<String>();
    let event_loader = tjs(
        &["loadInfo", "event_", "getSHA256Name", ".tlg", "evalStorage"],
        true,
    );
    let gallery = const_tjs(
        r#"(const) %[ "sample" => (const) [
        (const) %[ "thum" => "ev_not_cataloged", "events" => (const) [
            (const) %[ "name" => "ev_fixture" ], (const) %[ "name" => "ev_fixture" ]
        ] ]
    ] ]"#,
    );
    fixture_xp3(
        &dir.join("data.xp3"),
        &[
            ("utils.tjs".into(), tjs(&[&alphabet], false)),
            ("biscrat_kagenvevent.tjs".into(), event_loader),
            ("init_cg.tjs".into(), gallery),
        ],
    );

    let normal = token("event_ev_fixture");
    let large = token("event_ev_fixture_大");
    let uncataloged = token("event_ev_not_cataloged");
    let first_name = token("fixture-ev-image");
    let second_name = token("fixture-ev-image-large");
    let missing_name = token("fixture-missing-ev-image");
    let orphan = token("fixture-orphan-ev-image");
    let stem = |name: &str| name.trim_end_matches(".tlg").to_owned();
    let make_definition = |image: &str| {
        const_tjs(&format!(
            r#"(const) %[
          "keys" => (const) ["5", "10"],
          "info" => (const) %[
            "10" => (const) %[ "layerNumber" => 20, "filename" => "{}", "condition" => void ],
            "5" => (const) %[ "layerNumber" => 7, "filename" => "{}",
                             "condition" => "command(\"表情\")" ]
          ],
          "filename" => (const) %[ "表情" => (const) [5] ]
        ]"#,
            stem(&missing_name),
            stem(image)
        ))
    };
    let normal_definition = make_definition(&first_name);
    let large_definition = make_definition(&second_name);
    let png_name = format!("{}.png", stem(&first_name));
    let png = b"\x89PNG\r\n\x1a\nnative PNG".to_vec();
    let first = b"TLG0.0\0sds\x1afixture EV normal".to_vec();
    let second = b"TLG0.0\0sds\x1afixture EV large".to_vec();
    let orphan_image = b"TLG0.0\0sds\x1afixture unreferenced".to_vec();
    let archive = dir.join("arc/evimage.xp3");
    let entries = vec![
        (normal.clone(), normal_definition.clone()),
        (large.clone(), large_definition.clone()),
        (first_name.clone(), first.clone()),
        (second_name.clone(), second.clone()),
        (orphan.clone(), orphan_image.clone()),
        (png_name.clone(), png.clone()),
        (uncataloged.clone(), normal_definition.clone()),
    ];
    fixture_xp3(&archive, &entries);

    let physical = dir.join("physical");
    unpack(&archive, &physical, false);
    for (name, contents) in &entries {
        assert_eq!(&fs::read(physical.join(name)).unwrap(), contents);
    }
    assert!(!physical.join("event_ev_fixture.tlg").exists());

    let named = dir.join("named");
    let log = unpack(&archive, &named, true);
    assert!(log.contains("route=yakimochi-ev mapped=4"));
    for (name, contents) in [
        ("event_ev_fixture.tlg", &normal_definition),
        ("event_ev_fixture_大.tlg", &large_definition),
        ("ev_fixture_7.tlg", &first),
        ("ev_fixture_大_7.tlg", &second),
        (&orphan, &orphan_image),
        (&png_name, &png),
        (&uncataloged, &normal_definition),
    ] {
        assert_eq!(&fs::read(named.join(name)).unwrap(), contents);
    }
    for name in [
        normal.as_str(),
        &large,
        &first_name,
        &second_name,
        &missing_name,
        "ev_fixture_20.tlg",
    ] {
        assert!(!named.join(name).exists(), "{name}");
    }
}
