# Unicorn PE32 Win32 host layer

xp3-brute keeps Unicorn as the CPU backend. The Win32 guest state lives in
`src/win32_host.rs`, while `src/x86_filter.rs` maps typed API calls to Unicorn
guest memory/register operations. This separation follows retrowin32's useful
shim/system split without importing its CPU emulator.

## Audit result

Before this work, API addresses, TLS values, allocations, module handles, and
many API behaviors were local ad-hoc state in `x86_filter.rs`. `GetLastError`
always returned zero, `SetLastError` discarded its input, TLS indexes were not
validated, loader handles were placeholders, string conversion cast code units
instead of using a code page, and `GetProcAddress` stopped execution when an
export was absent.

The retrowin32 audit identified reusable host-layer boundaries: typed shims
independent of the selected CPU engine, explicit module/export tables,
per-thread TLS and last-error state, and heap ownership outside API dispatch.
The local implementation adapts those boundaries. Locale behavior itself is
implemented locally because the audited retrowin32 revision reports
`GetLocaleInfoA` as unimplemented and assumes code page 1252/ASCII in its NLS
path.

## Japanese guest profile

The default TPM guest is a Japanese Windows profile:

- user/system/thread LCID: `0x0411`
- ANSI and OEM code page: `932`
- CP932 conversion: `encoding_rs::SHIFT_JIS`

For `game-normal/plugin/kinglove.tpm`, process attach makes the exact request
`GetLocaleInfoA(0x0411, 0x1004, buffer, 6)` twice. `0x1004` is
`LOCALE_IDEFAULTANSICODEPAGE`; the host returns `"932\0"` with Win32-compatible
buffer-query and insufficient-buffer behavior.

## Repack recovery contract

When the generic x86 callback successfully decrypts an entry, `xp3-meta.yaml`
retains the exact PE32 module once (base64 plus SHA-256), the selected callback
address/source, the immutable original XP3 filter hash, and the guest profile.
Packing an edited entry reloads that retained module through the same host
layer and applies the symmetric callback. Module-integrity, callback, profile,
and filter-seed mismatches fail closed. XP3 `time`, `adlr`, identity hashes, and
other immutable index metadata remain sourced from the original manifest.

The complete real-sample run and hashes are recorded in
[`evidence/game-normal-roundtrip-2026-08-20.md`](evidence/game-normal-roundtrip-2026-08-20.md).
