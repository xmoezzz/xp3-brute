# xp3-brute

`xp3-brute` is a cross-platform tool for extracting, recovering, converting, and rebuilding KiriKiri XP3 archives. It can automatically detect all information needed to unpack protected archives.

```bash
xp3brute unpack data.xp3 out
```

The tool will inspect the archive and write files to `out/`.

`unpack` keeps the normal console view intentionally compact: it emits stable
`status phase=...` progress records plus one final `summary`. The interactive
terminal view renders those same states as a single progress bar. Use
`--verbose` when you need per-probe recovery evidence; use `--no-progress` for
an even quieter embedding-friendly invocation.

Core Ideas:
This time we do not rely on the runtime to extract the archive.
- For complex CXDEC variants, the tool can recover the key parameters.
- For simple KiriKiri encryption filters, the tool can locate and execute the game's real extraction logic in an x86 emulator.
- Use brute-force only as a last fallback when the above methods fail. CPU host and GPU acceleration are supported for brute-force recovery.

---

## Quick start

### Workspace layout

This repository is a Cargo workspace:

```text
xp3-brute/                 # shared core library and xp3brute CLI
apps/xp3-desktop/          # native eframe/egui desktop app
packages/python/           # publishable PyPI SDK and wheel metadata
```

The CLI remains the default workspace member, so existing `cargo build` and
`cargo run -- ...` workflows are unchanged. Build the desktop application with:

```bash
cargo build -p xp3-brute --bin xp3brute
cargo run -p xp3-brute-desktop --bin xp3brute-gui
```

The desktop app provides archive browsing, search, raw selected-entry export,
file/folder pickers, and an asynchronous full-unpack view. Full unpack invokes
the same `xp3brute unpack` pipeline and streams its normalized status output
into the operation log. When the CLI is not on `PATH`, set `XP3BRUTE_BIN` to
its absolute path.

### Build

```bash
cargo build --release
```

The executable is:

```text
target/release/xp3brute
```

Tagged releases also publish prebuilt Linux x86_64, macOS arm64, and Windows x86_64 binaries. See [`docs/CI.md`](docs/CI.md) for the CI and release policy, including the Linux glibc compatibility baseline.

A CPU-only build without the optional GPU backend is also available:

```bash
cargo build --release --no-default-features --features magic-sniff
```

### Python / CPython bindings

The publishable SDK lives in [`packages/python`](packages/python). It ships a
Python API layer over a native CPython extension, and exposes archive
inspection/reconstruction, PBD/TLG/AMV conversion, manifest rebuild/pack,
round-trip verification, filter detection, and repeating-XOR recovery.

```bash
pip install xp3-brute
```

Source development:

```bash
cd packages/python
python -m pip install 'maturin>=1.12,<2'
maturin develop --release
```

Wheels target the CPython stable ABI (Python 3.9+) and are built in CI for
manylinux2014 x86_64, macOS arm64, and Windows x86_64. Structured reports are
returned as JSON strings, ready for `json.loads` or direct logging.

```python
from xp3_brute import Xp3

archive = Xp3.open_archive("data.xp3")
print(Xp3.inspect("data.xp3"))
for entry in archive.entries():
    print(entry.index, entry.name, entry.original_size)

storage_bytes = archive.reconstruct_entry(0)
report = Xp3.detect_filter("game.exe")
print(report["backend"], report["confidence"])
```

Release publishing uses PyPI trusted publishing and the wheel matrix in
[`python-publish.yml`](.github/workflows/python-publish.yml). Rust consumers
continue to use the same frontend-neutral public API directly.

---

## Unpack an XP3 archive

```bash
xp3brute unpack data.xp3 out
```

If the game executable is not beside the XP3 archive, specify it explicitly:

```bash
xp3brute unpack data.xp3 out --exe game.exe
```

`--exe` may point to the game executable. The tool can also inspect nearby DLL/TPM modules when looking for an extraction filter.

### HXV4 foreground filenames

For an HXV4 foreground archive, `--restore-names` uses the game executable's
native content filter and the archive's own standing definitions and layer
tables. It also reads CP932 stand metadata and can use the character list in a
sibling data.xp3 for additional stand aliases. It checks every proposed basename against the authenticated filename
hash and checks referenced TLG dimensions against the corresponding PBD or TXT
table. It also checks bounded layer numbers under known table names for TLGs
outside the active tables.

```bash
xp3brute unpack "game/fgimage.xp3" out --exe "game/game.exe" --restore-names
```

The option preserves known directory names and otherwise keeps the original
path hash as the directory group. Verified entries with unknown names use the
`_hxv4_hash` layout. `xp3-meta.yaml` records the archive identity and output path.

### Use a recovered Nana profile for a dls: archive

When the name state and Cabbage content parameters are already available for an
ordinary XP3 archive, supply them as a local JSON profile.

```bash
xp3brute inspect fgimage.xp3 --nana-profile profile.json
xp3brute unpack fgimage.xp3 out --nana-profile profile.json
```

The profile has two fields.

- `name_state` is an array of six unsigned 32-bit words in the order of the
  initialized Nana decoder state.
- `content` contains the unsigned 32-bit `mask`, `offset`, and `random_seed`,
  the `prolog_order`, `even_branch_order`, and `odd_branch_order` arrays
  (permutations of 0–2, 0–7, and 0–5), and `control_block_file`. This file
  contains the 4,096-byte table in the representation consumed by the
  content filter. A relative path is resolved against the profile's directory.

The CLI checks the name table against the archive's filename tokens and
Adler-32 values. Archives can also contain directly named files alongside
those tokens. The CLI verifies their plaintext Adler-32 and preserves their
literal paths. Before extracting, it verifies the supplied content profile
against the protected entries. Keep application-specific profile data local.

If you already have a Nana startup `.key` text file, pass it explicitly.
The first line derives the name state, control block, mask and offset. For
extraction, also supply the Cabbage generator settings as a JSON object with
`prolog_order`, `even_branch_order`, `odd_branch_order` and `random_seed`.

```bash
xp3brute inspect fgimage.xp3 --nana-key game.key
xp3brute unpack fgimage.xp3 out --nana-key game.key --nana-generator generator.json
```

The same archive name and content checks apply to values derived from the
key file.

### MadoCrypt archives and Yakimochi filenames

`unpack` can infer a MadoCrypt seed from protected TLG and KBAD100 headers
and verify it against complete entries. It can use a nearby `fgimage.xp3` to
learn the seed for a companion archive, then check the companion's own
Adler-32 values before enabling the filter. Keep the original game layout when
extracting companion archives.

Yakimochi Stream's foreground and event archives support logical filename recovery.

```bash
xp3brute unpack "game/arc/fgimage.xp3" out --restore-names
xp3brute unpack "game/arc/evimage.xp3" out-ev --restore-names
```

This option reads the game's `data.xp3` alongside the selected image archive.
For `fgimage.xp3`, it uses TJS2 constants and KBAD100 definitions to restore paths
of the form `<pose_base>_<level>_<layer_id>.tlg`. Foreground metadata keeps its
indexed paths.

For `evimage.xp3`, it uses the event loader, `init_cg.tjs`, and the archive's
serialized `(const)` definitions. Definitions use `event_<event>.tlg` and the
layers they reference use `<event>_<layerNumber>.tlg`. The Large variant keeps
the `_大` suffix in `<event>`. The definition files retain their original
extension and UTF-16LE data, including their internal layer references.

Unreferenced entries and native PNG files keep their indexed paths. Default
extraction uses indexed paths for every entry.

### What happens automatically

```mermaid
flowchart TD
    A[Open XP3 archive] --> B[Parse index and entries]
    B --> C{Protected / Special index?}
    C -- Yes --> D[Identify protection family]
    D --> E[Recover and validate names / protection state]
    C -- No --> F[Continue normally]
    E --> G[Recover content filter]
    F --> G
    G --> H{Known filter family?}
    H -- Yes --> I[Use recovered implementation/state]
    H -- No --> J[Search EXE / DLL / TPM for XP3 filter]
    J --> K{Filter callback validated?}
    K -- Yes --> L[Execute filter in x86 emulator]
    K -- No --> M[Shared-key recovery]
    M --> N[Per-file brute-force fallback]
    I --> O[Validate recovered files]
    L --> O
    N --> O
    O --> P[Write verified files]
```

Brute-force recovery is the **last fallback**. The tool first tries to identify and execute the game's real extraction/filter logic.

---

## Convert game resources while unpacking

By default, recovered files are kept in their original format.

Use `--unpacker-all` to enable the available resource converters:

```bash
xp3brute unpack data.xp3 out --unpacker-all
```

| Resource | Default | With `--unpacker-all` |
|---|---|---|
| Compiled TJS2 (`.tjs`) | keep bytecode | high-level decompile, same `.tjs` path |
| TLG5/TLG6 | keep TLG | convert to PNG |
| PSB / SCN / MTN / PIMG | keep original | JSON + decoded PNG/resources |
| PBD | keep original | typed JSON |
| Supported AMV/AJPM | keep original | PNG frames |
| KiriKiri wrapped text | decoded when verified | decoded when verified |

Individual decoders can be selected explicitly:

```bash
xp3brute unpack data.xp3 out --tjs decompile
xp3brute unpack data.xp3 out --tjs emit
xp3brute unpack data.xp3 out --tlg png
xp3brute unpack data.xp3 out --psb json
xp3brute unpack data.xp3 out --psb png
xp3brute unpack data.xp3 out --pbd json
xp3brute unpack data.xp3 out --amv png
```

Explicit options override the `--unpacker-all` preset. TJS2 conversion never changes the filename: `scenario.tjs` remains `scenario.tjs`. If loading/emission/decompilation fails, the original TJS2 bytes are preserved. Repacking treats an extracted text `.tjs` as source text and writes it back directly; `xp3brute` does not attempt to compile it back into TJS2 bytecode.

---

## Inspect an archive

```bash
xp3brute inspect data.xp3
```

Use this when you only want to inspect the XP3 structure, entries, or detected protection family without extracting everything.

---

## Automatic extraction-filter recovery

Older KiriKiri games often protect file contents with an XP3 extraction filter stored in the game EXE, a DLL, or a `.tpm` plugin.

`xp3-brute` can automatically search these modules and validate candidate filters against real XP3 entries.

```mermaid
flowchart LR
    A[data.xp3] --> D[Filter detection]
    B[game.exe] --> D
    C[DLL / TPM] --> D
    D --> E{Recognized family}
    E -- Known family --> F[Recovered implementation/state]
    E -- Unknown ordinary filter --> G[x86 callback emulation]
    F --> H[XP3 adlr + format validation]
    G --> H
    H --> I[Use validated filter for extraction]
```

A generic x86 filter is accepted only after it restores real archive samples and passes the available XP3 `adlr` and file-format checks.

You normally do not need to use the filter diagnostic commands manually.

For troubleshooting:

```bash
xp3brute filter-probe game.exe
xp3brute filter-probe plugin/filter.tpm --dynamic-v2link
```

---

## Protected archives

Protected XP3 variants are detected automatically.

The tool currently includes dedicated handling for:

- historical indirect Special-index variants;
- several CXDEC generations;
- HXV4 authenticated Special indices and their content-filter state;
- ordinary KiriKiri extraction filters that can be located and executed from PE32/i386 modules.

Protection names or four-byte chunk tags are not treated as authoritative identifiers. The tool uses archive structure, executable behavior/state, and validation against real XP3 data.

For normal use, the command remains:

```bash
xp3brute unpack data.xp3 out
```

or:

```bash
xp3brute unpack data.xp3 out --exe game.exe
```

---

## Rebuild an XP3 archive

During unpacking, `xp3-brute` writes:

```text
xp3-meta.yaml
```

This manifest stores the metadata needed to reconstruct the original archive and reapply its filter/protection state.

After editing extracted resources:

```bash
xp3brute pack out rebuilt.xp3
```

If the original archive is no longer at the path recorded during unpacking:

```bash
xp3brute pack out rebuilt.xp3 --source-archive /path/to/data.xp3
```

The default writer is source-template based. It tries to preserve the original XP3 representation rather than rebuilding the archive into a normalized layout.

The original XP3 `adlr` bytes are preserved and are never recomputed.

### Rebuild workflow

```mermaid
flowchart LR
    A[data.xp3] --> B[xp3brute unpack]
    B --> C[Editable files]
    B --> D[xp3-meta.yaml]
    C --> E[Edit PNG / JSON / text / resources]
    D --> F[xp3brute pack]
    E --> F
    A --> F
    F --> G[rebuilt.xp3]
```

---

## Verify a round trip

```bash
xp3brute verify-roundtrip out \
  --source-archive data.xp3 \
  --output rebuilt.xp3
```

For a machine-readable report:

```bash
xp3brute verify-roundtrip out \
  --source-archive data.xp3 \
  --output rebuilt.xp3 \
  --json
```

Verification checks the XP3 container separately from decoded resource formats.

---

## Standalone resource conversion

### TLG

```bash
xp3brute decode-tlg image.tlg image.png
xp3brute decode-tlg image.tlg image.jpg --jpeg-quality 92
xp3brute decode-tlg image.tlg image.bmp
```

Encode an image as TLG:

```bash
xp3brute encode-tlg image.png image.tlg
```

### PBD

```bash
xp3brute decode-pbd script.pbd script.pbd.json
xp3brute encode-pbd script.pbd.json rebuilt.pbd
```

### AMV/AJPM

```bash
xp3brute encode-amv frames/ movie.amv --fps 30 --quality 75
```

---

## GPU acceleration

The default build includes an optional `wgpu` compute backend.

Check available compute devices with:

```bash
xp3brute devices
```

`unpack` defaults to:

```text
--compute auto
```

Other modes are:

```bash
xp3brute unpack data.xp3 out --compute cpu
xp3brute unpack data.xp3 out --compute gpu
xp3brute unpack data.xp3 out --compute hybrid
```

GPU acceleration is used for suitable recovery workloads. Archive parsing, native-filter execution, decompression, and final validation remain CPU-side.

---

## Useful diagnostic commands

These commands are mainly intended for unsupported games or development/debugging:

```bash
# Probe archive recovery hypotheses
xp3brute probe data.xp3 --max-period 1024 --top 8

# Test whether several files share a repeating key
xp3brute shared-probe data.xp3 --max-period 1024 --top 20

# Reconstruct XP3 storage streams without applying a title-specific filter
xp3brute extract-raw data.xp3 out/

# Inspect historical Special-index data
xp3brute scan-special data.xp3

# Analyze an executable for HXV4 information
xp3brute exe-analyze game.exe --archive data.xp3
```

Most users should not need these commands.

---

## Supported areas

`xp3-brute` currently covers the following major areas:

- XP3 raw/zlib index parsing and reconstruction;
- standard / Krkr2 / KrkrZ-style archives;
- historical indirect Special-index variants;
- CXDEC-family content filters;
- generic PE32/i386 XP3 extraction-filter discovery and emulation;
- HXV4 Special and content-filter recovery;
- repeating-key recovery as a final fallback;
- TLG5/TLG6 decoding and TLG5 encoding;
- PSB / SCN / MTN / PIMG parsing and resource extraction;
- PBD decode/encode;
- supported AMV/AJPM resource extraction/rebuilding;
- KiriKiri text wrappers and common game-resource formats;
- source-template XP3 repacking and round-trip verification.

Not every vendor-specific protection can be recovered automatically. Unknown filters or archive variants may still require additional analysis.

---

## Memory usage

`Archive::open` is file-backed; opening a large XP3 does not load the complete archive into RAM.

The unpacker processes final entries in bounded batches. For low-memory environments:

```bash
KRKR_UNPACK_BATCH_SIZE=1 xp3brute unpack data.xp3 out
```

The batch byte budget can also be changed with:

```text
KRKR_UNPACK_BATCH_BYTES
```

---

## Project layout

The crate provides both:

- `xp3_brute`: reusable Rust library;
- `xp3brute`: command-line frontend.

Detailed implementation notes belong under `docs/`. This README intentionally focuses on normal installation, extraction, conversion, rebuilding, and troubleshooting workflows.
