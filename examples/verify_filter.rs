use xp3_brute::{adler32, initialize_x86_filter_module, Archive, X86Xp3FilterRuntime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let archive_path = args
        .next()
        .ok_or("usage: verify_filter ARCHIVE MODULE [LIMIT]")?;
    let module_path = args
        .next()
        .ok_or("usage: verify_filter ARCHIVE MODULE [LIMIT]")?;
    let limit = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(8);
    let archive = Archive::open(&archive_path)?;
    let trace = std::env::var_os("XP3_FILTER_TRACE").is_some();
    if let Some(path) = std::env::var_os("XP3_FILTER_DUMP_INIT") {
        let initialized = initialize_x86_filter_module(&module_path, false)?;
        std::fs::write(path, initialized.initialized_file)?;
    }
    let mut runtime = X86Xp3FilterRuntime::open(&module_path, trace)?;
    let mut passed = 0usize;
    let mut checked = 0usize;
    let mut failures = 0usize;
    for (index, entry) in archive.entries.iter().enumerate() {
        let Some(expected) = entry.adler else {
            continue;
        };
        let mut data = archive.reconstruct_entry(index)?;
        let stored = adler32(&data);
        runtime.apply(0, expected, &mut data)?;
        let actual = adler32(&data);
        println!(
            "entry={index} name={:?} stored=0x{stored:08x} expected=0x{expected:08x} actual=0x{actual:08x} {}",
            entry.preferred_name(),
            if actual == expected { "PASS" } else { "FAIL" }
        );
        if actual == expected {
            passed += 1;
        } else {
            failures += 1;
        }
        checked += 1;
        if checked == limit {
            break;
        }
    }
    if passed == 0 {
        return Err(format!("{failures} checked entries failed source adlr").into());
    }
    if failures != 0 {
        return Err(format!("{failures} of {checked} checked entries failed source adlr").into());
    }
    Ok(())
}
