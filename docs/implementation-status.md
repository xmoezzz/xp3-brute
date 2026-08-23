# Implementation and round-trip status

Status date: 2026-08-20. The crate/package name is **`xp3-brute`** (the Rust
library import remains `xp3_brute`; the CLI binary remains `xp3brute`).

`YES` means that the stated implementation path was exercised by a passing
test or real-sample run. `INCOMPLETE` means required implementation work is
still missing; it never means merely "no sample". `REAL-PENDING` is used only
in real-sample columns when the implementation has complete synthetic/file
tests but no matching real input is available. `UNSUPPORTED` is an explicit
fail-closed boundary. Merely having code is not a reason for `YES`.

The verifier keeps two independent result groups for every entry:

- **XP3**: reopen, exact physical-name length, immutable `adlr`/filter seed and
  identity hashes, byte-identical Special/HXV4 data, timestamp/flags/private
  metadata, segment structure, post-pack decrypt/filter comparison, and
  edited-sidecar consumption.
- **File format**: rebuild/reparse and format-specific semantic checks.

It also classifies each entry as `byte-exact`, `semantic-exact`, `lossy`,
`unsupported`, or `not-applicable`. Sidecar SHA-256 values are modification
bookkeeping only; original XP3 `adlr` values remain immutable filter/checksum
identity and are never reused as sidecar hashes.

## A. Content protection

| family | algorithm | recognition | parameter recovery | unpack | pack | real sample |
|---|---|---:|---:|---:|---:|---|
| Plain XP3 | none | YES | N/A | YES | YES | YES — Fate `data.xp3` |
| Generic PE32/TPM filter | constrained x86 callback + Japanese Win32 host | YES | YES — callback/module/profile/seed persisted | YES | YES | YES — `game-normal`, 5021/5021 round-trip checks pass after two real edits |
| Classic CXDEC | native 128-lane XOR/filter | YES | YES (tests/module analysis) | YES (tests) | YES (symmetric tests) | REAL-PENDING — Fate `cxdec.tpm` is real, supplied `data.xp3` entries are plain |
| Repeating-XOR fallback | bounded global/per-entry XOR | YES | YES (tests) | YES (tests) | YES (tests) | REAL-PENDING |
| HXV4 | native FilterManager, prefix/boundary XOR | YES | YES | YES | YES | YES — `uipsd.xp3`, 174/174 post-pack decrypt checks |
| Cabbage CXDEC | native Gen2/CxProgramNana | YES | INCOMPLETE — automatic `random_seed` recovery | YES with complete profile (tests) | YES (symmetric tests) | N/A — parameter recovery incomplete |
| Nana/dls | Cabbage content + Nana names | YES | INCOMPLETE — automatic content/name parameters | YES with complete profiles (tests) | YES (tests) | N/A — parameter recovery incomplete |
| Riddle/yuz | Cabbage content + Prefix8 | YES | INCOMPLETE — automatic content/name parameters | YES with complete profiles (tests) | YES (tests) | N/A — parameter recovery incomplete |
| Senren/sen | no separate content algorithm | N/A | N/A | N/A | N/A | REAL-PENDING |

## B. Special/name protection

| profile | decode | key recovery | name recovery | rebuild | real sample |
|---|---:|---:|---:|---:|---|
| No Special layer | YES | N/A | N/A | YES | YES — Fate/plain XP3 |
| Protected-dummy sentinel | YES | N/A | N/A | YES | YES — Fate, including historical `protectet` spelling |
| Ordinary M2/indirect Special | YES | INCOMPLETE | INCOMPLETE | YES when the decoded template/key is complete | N/A — recovery incomplete |
| HXV4 authenticated Special | YES | YES | INCOMPLETE — bounded logical-name bootstrap | YES | YES — `uipsd.xp3`; AEAD, stored blob, hashes and physical mapping complete; only five real PBD names were recovered in the bounded name run |
| Senren `sen:` | YES | N/A | YES (tests) | YES — stored section preserved | REAL-PENDING |
| Cabbage `cbg:` | YES | N/A | YES (tests) | YES — stored section preserved | REAL-PENDING |
| Nana `dls:` | YES | INCOMPLETE — automatic `YuzKey` recovery | YES with supplied/recovered key (vectors) | YES — stored section preserved | N/A — key recovery incomplete |
| Riddle `yuz:` | YES | INCOMPLETE — automatic control/key recovery | YES with supplied/recovered keys (vectors) | YES — stored section preserved | N/A — key recovery incomplete |
| Non-NUL UTF-16 name variant | YES (tests) | N/A | YES (tests) | YES (tests) | REAL-PENDING |

HXV4 no-name inventory is intentionally allowed to remain `pending`; the
authenticated per-record native filter state is bound to the physical entry
and is sufficient for decrypt verification. It does not invent a logical name.

## C. File formats

| format | decode | expand | rebuild | unchanged RT | modified RT | real sample |
|---|---:|---:|---:|---:|---:|---|
| TLG5/TLG6/TLG0 | YES | YES | YES (writer emits TLG5; TLG0 chunks restored) | YES (tests) | YES — encrypted-XP3 full-chain pixel/alpha test | FILE-LEVEL YES — 99 real encrypted TLG-derived PNGs decoded and one rebuilt/pixel-compared; real generic-TPM XP3 re-encryption is INCOMPLETE |
| Generic PSB | YES | YES | YES | YES (synthetic) | YES — encrypted-XP3 full-chain resource edit/reparse | REAL-PENDING |
| SCN | YES (shared PSB engine) | YES | YES (subtype path retained) | YES (synthetic) | YES — `.scn` resource edit in encrypted-XP3 full chain | REAL-PENDING |
| MTN | YES (shared PSB engine) | YES | YES (subtype/wrapper retained) | YES (synthetic) | YES — encrypted Emote texture/key/wrapper test | REAL-PENDING |
| PIMG | YES (shared PSB engine) | YES | YES (subtype/wrapper retained) | YES (synthetic) | YES (shared resource/texture writer) | REAL-PENDING |
| Emote PSB | YES | YES | YES — persisted key, protection state, wrapper and texture formats | YES (synthetic) | YES — root/animation metadata and RGBA edit reparsed | REAL-PENDING |
| AMV/AJPM Mode B | YES (independent decoder) | YES (PNG frames) | YES | YES — untouched packets/trailer | YES — replacement frame independently decoded | REAL-PENDING |
| AMV/AJPM Mode A | INCOMPLETE decode | INCOMPLETE | UNSUPPORTED (fails closed) | YES only with no expansion/stored-byte reuse | UNSUPPORTED | N/A — implementation incomplete |
| PBD `TJS/ns0` | YES | YES | YES | YES | YES — field edit reparsed | YES — HXV4 `chapter.pbd` |
| PBD `TJS/4s0` | YES | YES | YES | YES (synthetic) | YES (synthetic) | REAL-PENDING |
| KiriKiri compressed text | YES | YES | YES | YES | YES — wrapper/BOM/CRLF test | REAL-PENDING — Fate supplies ordinary scripts/text, not a proven wrapped-text entry |
| Raw/no expansion | YES | N/A | stored-byte reuse | YES | N/A | YES — Fate 981/981 and HXV4 174/174 |

Lossy rules are explicit. TLG-to-JPEG and edited AMV Mode B require
`--allow-lossy`; the verifier reports `lossy` rather than `match`. Mode A AMV
edits return an unsupported error instead of restoring hidden original bytes.

## D. Archive compatibility

| variant | parse | unpack | pack | reopen | byte/semantic RT |
|---|---:|---:|---:|---:|---|
| Plain XP3 | YES | YES | YES | YES | YES — byte exact |
| Legacy KRKR2/protected dummy | YES | YES | YES | YES | YES — Fate byte exact |
| Non-NUL UTF-16 names | YES (tests) | YES (tests) | YES (tests) | YES (tests) | YES synthetic; REAL-PENDING |
| Encrypted XP3, repeating XOR | YES | YES | YES | YES | YES — synthetic modified TLG and PSB full chains; identity metadata preserved |
| Encrypted XP3, generic TPM | YES | INCOMPLETE | INCOMPLETE | INCOMPLETE | N/A — execution incomplete |
| Ordinary Special names | YES | INCOMPLETE | INCOMPLETE | YES (tests) | N/A — recovery incomplete |
| HXV4 | YES | INCOMPLETE logical-name bootstrap | YES | YES | YES — 174/174 byte exact, decrypt exact, Special/hash/time metadata exact |

## Real-sample evidence

| game/sample | archive and entry | format/protection | result |
|---|---|---|---|
| Fate/stay night media | `Fate/data.xp3`, e.g. `etc/flaglistup.txt` | plain content, legacy protected dummy | 981 entries packed, reopened, decrypted/compared and classified byte-exact; whole archive `cmp` equal |
| 王様恋愛 trial | `game-normal/data.xp3`; `bgimage/anime/snow_4.png` and TLG6 `stimage/2/st2_s2_1_1.tlg` | generic x86 TPM filter, encrypted; direct PNG plus TLG0/TLG6 | Japanese host answers the observed `GetLocaleInfoA(0x0411, 0x1004, ..., 6)` request with CP932. Two pixel edits force two re-encodes; rebuilt XP3 reopens and 5021/5021 checks pass. The TLG edit is semantic-exact (602x639 RGBA, alpha, pixels, TLG0 container); `adlr`, filter seed, time, names, flags, unknown chunks, and segment structure remain unchanged. |
| limelight/HXV4 sample | `uipsd.xp3`, `94D4A97C61498621/chapter.pbd` | authenticated HXV4 Special + native entry filter; PBD ns0 | original PBD decode/encode is byte-identical; changed `packlist[0][2]` reparses as 373 |
| limelight/HXV4 sample | all 174 physical entries of `uipsd.xp3` | HXV4 no-name/no-expansion | packed archive reopens; 174/174 XP3 and source-byte checks pass; whole archive `cmp` equal |

## Current verifier command

```text
xp3brute verify-roundtrip UNPACK_DIR \
  --source-archive ORIGINAL.xp3 \
  --output rebuilt.xp3 \
  [--rebuilt-dir DIR] [--allow-lossy] [--compact-layout] [--json]
```

The source-format bytes are rebuilt before the persisted XP3 filter is applied.
After packing, the verifier reopens the XP3, reconstructs and decrypts the
entry, parses its embedded format again, and runs the appropriate semantic
comparison. It also fails if the original XP3 `adlr`/filter seed, alternate or
HXV4 identity, raw physical-name length, `time`, flags, unknown File chunks, or
stored Special/HXV4 blob changes. Only `info` sizes and `segm` physical
offset/sizes are normalized for this metadata comparison. A modified transform
that reports `stored-byte-reuse` is a failure.

## What remains unverified

- A complete edited encrypted-entry chain for the real generic TPM sample.
- Real PSB/SCN/MTN/PIMG/Emote semantic samples. `scn.xp3` is already present,
  but its full HXV4 name/bootstrap pass has not completed; this is currently an
  implementation/performance task rather than missing user data.
- Real AMV Mode B and Mode A containers.
- A real PBD `TJS/4s0` file.
- Real wrapped KiriKiri text covering modes 0, 1, and 2/CP932.
- Real Cabbage, Nana/dls, Riddle/yuz, Senren/sen, `cbg`, ordinary Special, and
  non-NUL UTF-16 archive profiles.

See [needed-test-games.md](needed-test-games.md) for the smallest requested
sample sets and priorities.
