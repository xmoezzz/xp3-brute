# Hxv4 notes

Hxv4 is a separate archive family, not an ordinary repeating-XOR Special variant.

## Main-archive startup anchor

`startup.tjs` is a bootstrap anchor of the main `data.xp3`, not an invariant of every HXV4 archive. Filesystem-backed parsing only canonicalizes the sole ordinary/non-fake entry to `startup.tjs` when the archive basename is actually `data.xp3`; voice/image/etc. XP3 files are never assigned a fabricated startup name. An explicitly stored `startup.tjs` remains usable regardless of archive basename.

When this anchor is available, its plaintext/bytecode is used only as an initial source of real resource-name candidates. The CLI also mines the validated EXE bres `STARTUP.TJS` and BOOTSTRAP DLL, so name recovery can start even while processing a sibling archive that does not itself contain `startup.tjs`.

## Native Special envelope

The Hxv4 root descriptor is:

```text
offset:u64 | stored_size:u32 | flags:u16
```

Descriptor bit 0 selects one of two nonce slots:

```text
nonce_slot = flags & 1
```

The out-of-line Special blob is:

```text
tag[16] || ciphertext
```

It is authenticated/decrypted with XChaCha20-Poly1305 using a 32-byte key and the selected 24-byte nonce. The plaintext is:

```text
uncompressed_size:u32 little-endian || zlib stream
```

The inflated stream is a big-endian TJS Variant object graph. Strings are UTF-16BE. Each native record contains a packed locator plus a per-record key. The locator is decoded as:

```text
synthetic_id = packed & 0xffffffff
native_meta   = packed >> 32
archive_slot  = (native_meta >> 16) & 0xffff
local_flag    = native_meta & 0xffff
open_flag     = local_flag & 1
```

For the current XP3, only `archive_slot == 0` records are mapped to synthetic resource ids. The Rust public field remains named `filter_flag` for compatibility and stores `local_flag`; its bit 0 is the native FilterImpl `open_flag`. Other archive slots remain represented in the decoded table but are not incorrectly attached to current-archive entries.

A candidate is accepted only if every layer validates:

1. Poly1305 authentication succeeds.
2. The decrypted size prefix is reasonable.
3. zlib decompression succeeds and produces exactly the prefixed size.
4. The entire TJS Variant stream parses with no trailing bytes.
5. The native Hx table shape yields valid records.

The first 16 bytes are an authentication tag, not plaintext or a repeating-XOR key fragment.

## What is intentionally skipped

The historical Special solver (direct wrappers, zero-frequency/structured M2 constraints, repeating-XOR period recovery, and period<=5 compatibility brute force) is **not** run on `RootKind::Hxv4SpecialIndex`. The real Hxv4 envelope is high-entropy authenticated stream-cipher ciphertext, so feeding it to M2/repeating-XOR recovery only wastes time and produces no cryptographically meaningful evidence.

Those historical attacks remain unchanged for ordinary Special variants.

## Automatic EXE/bootstrap recovery

HXV4 `unpack`, `inspect`, `decode-special`, and `hx-index` can recover the Special key material statically from the game executable. The executable is never launched. A supplied EXE is treated as a byte container rather than assuming the outer PE is the game itself: all valid embedded PE images are enumerated and a candidate is accepted only after its bres resources produce a valid `TJS2100\0` STARTUP and an embedded BOOTSTRAP PE. This handles launcher/wrapper executables that carry the real Kirikiri PE at a non-zero file offset.

The recovery chain is:

```text
outer EXE/container
  -> enumerate embedded PE images
  -> select PE by validated Kirikiri bres resources
  -> TEXT/127 + 0x2000-byte bres salt
  -> decrypt STARTUP.TJS
  -> locate/decrypt/inflate BOOTSTRAP PE
  -> PARAMS + UNIQUE + WARNING + archive seed
  -> bootstrap-prefix candidates from TJS2 constants
  -> Cx sponge + Argon2i + FNV/BLAKE2s FilterManager derivation
  -> derive key + nonce0/nonce1
  -> descriptor bit 0 selects nonce slot
  -> XChaCha20-Poly1305 authenticate/decrypt Special
  -> zlib + strict Hx object parse
```

No candidate key is accepted merely because bytes look plausible: the complete Special must authenticate and parse. `--hx-exe PATH` chooses an explicit executable. Without it, HXV4 scans the XP3 directory and one parent directory for `.exe` files. `--no-hx-exe-auto` disables discovery.

Explicit key material remains available and takes priority:

```text
--hx-key   <32-byte / 64-hex key>
--hx-nonce <24-byte / 48-hex selected nonce>
```

The older `--hx-key1` / `--hx-key2` spellings remain CLI aliases for compatibility. `exe-analyze <game.exe> --archive <data.xp3>` prints PE/bootstrap diagnostics and reports a key only after strict Special validation.

## Reconstructed native content filter (v0.3.7)

The entry-content filter is a different problem from Special-index AEAD decryption. The F5/disassembly of the title BOOTSTRAP DLL shows that the Special record's 64-bit `entry_key` is the native per-entry FilterManager input.

The static chain is:

```text
PARAMS + final bootstrap text
        -> Cx sponge salt
        -> Argon2i v0x13 (m=8 KiB, t=3, p=1), 64-byte material
        -> Cx sponge rate=136/domain=0x1f, squeeze 0x2000
        -> control mode 1: first 0x1000
           control mode 2: first 0x1000 XOR second 0x1000
        -> 1024 little-endian u32 control words

PARAMS + control words
        -> deterministic generator
        -> 128 DripValue lanes

Storages.archiveUniqueKey + archive seed
        -> 32-byte unique/modifier KDF block
        -> holder_low / holder_high (first 8 bytes)

entry_key + local_flag
        -> if !(local_flag & 1): XOR holder_low/high into entry_key
        -> DripValue(low32) / DripValue(high32)
        -> two boundary states
        -> split = offset + (mask & (effective_key >> 16))
        -> 16-byte prefix XOR
        -> reconstructed runtime stream filter
```

For this title the 22-byte `PARAMS` record selects xoroshiro128++ and control mode 2. The generator retains the old cxdec x86-emitter shape, including a 128-byte generated-code budget and retries at recursion depths 5, 4, 3, 2, 1 without rewinding the PRNG. HXV4 does not require executing those generated x86 instructions: each generated semantic handler sequence is represented as pure Rust and interpreted directly, which keeps recovery cross-platform.

`DripValue(u32)` uses the low seven input bits to select one of 128 lanes and the upper bits as the lane seed:

```text
lane = value & 0x7f
seed = value >> 7
lo = eval(lane, seed)
hi = eval(lane, ~seed)
return lo | (hi << 32)
```

Each 64-bit boundary result supplies two 16-bit sparse positions, a repeated body XOR byte, and two correction bytes. A zero body byte becomes `0xa5` in normal mode. The final state contains:

- an additional 16-byte XOR mask over logical offsets `0..16`;
- one split position;
- one repeated XOR byte before the split;
- one repeated XOR byte after the split;
- two sparse correction positions/bytes for each side.

The final transformation is XOR-only, so encryption and decryption are the same operation. It is applied **after** XP3 segment reconstruction/zlib decompression and supports arbitrary logical offsets.

XP3 Adler-32 is authoritative whenever present. Until broad Adler-32 validation succeeds, the implementation is described as **reconstructed**, not exact. If the reconstructed native manager plus authenticated `entry_key` does not reproduce the stored Adler-32, recovery fails closed and does not fall through to the expensive heuristic brute. The older known-format effective-filter solver and repeating-XOR solver remain compatibility fallback only when the native FilterManager cannot be reconstructed.

## Game-wide filename bootstrap

The native HXV4 Special table stores path hashes and filename hashes rather than plaintext filenames. `unpack` therefore has a second hard gate after Special authentication: ordinary entry reconstruction/solve is forbidden until the current archive's real filenames are resolved.

Before that gate, v0.3.2 runs a bounded game-wide bootstrap over the XP3 directory (or `--hx-game-dir DIR`):

```text
validated EXE STARTUP.TJS / BOOTSTRAP strings
        + loose game-file names/text
        + data.xp3 startup.tjs
        -> native pathHash/fileHash exact matching
        -> recover only entries whose real filename is now known
        -> mine TJS2 UTF-16LE/ASCII constants from validated plaintext
        -> hash new candidates against every sibling HXV4 Special index
        -> bounded numeric-neighbour expansion for numbered resource families
        -> repeat until no new exact matches appear
```

The bootstrap still runs exact hash-name recovery first. If that name work queue reaches a fixed point while records remain hash-only, v0.3.7 may then apply the **reconstructed native entry-key filter** without knowing a filename. Adler-verified plaintext is stored under `OUTPUT/_hxv4/bootstrap_hash_only/<archive>/` and mined for additional path/name candidates. Synthetic names and inferred extensions are inspection labels only; a real filename is accepted solely by exact HXV4 path/name-hash matching.

Matched names are written to `OUTPUT/_hxv4/HxNames.bootstrap.lst`; unresolved current-archive hashes are written to `OUTPUT/_hxv4/unresolved_names.tsv`. If any current-archive filename remains unresolved after the feedback loop, the ordinary final `[reconstruct]`/`[solve]`/output stage is still skipped, although Adler-verified native plaintext recovered during bootstrap remains available under `_hxv4/bootstrap_hash_only/`. Use `--no-hx-name-bootstrap` to disable the automatic pass or `--hx-game-dir DIR` to override the game-directory root.
