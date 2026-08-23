# game-normal generic PE32/TPM round-trip evidence

Date: 2026-08-20 (Asia/Tokyo)

## Inputs

- Archive: `games/game-normal/data.xp3`
  - bytes: `803711809`
  - SHA-256: `e9860fd21cbae09373269fd40e39d0c8602c70194a5ba15b41225111cf248036`
- TPM: `games/game-normal/plugin/kinglove.tpm`
  - SHA-256: `359abbe24efb60a740f4cc4bd2447a4ac97ac5a348b95ae02fac8440aa01ee58`
  - selected callback: `0x10001000` (`static-registration`)
- Observed initialization request, twice:
  - `GetLocaleInfoA(0x00000411, 0x00001004, buffer, 6)`
  - returned Japanese Windows default ANSI code page string `"932\0"`

## Real edits

1. `bgimage/anime/snow_4.png`, pixel `(10,10)` changed from
   `srgba(254,254,254,0.858824)` to `srgba(0,255,0,1)`.
   - unpack SHA-256: `da084bbffff181244018ec743762b0637f393d26d7d9014f837baa7b2eb211a4`
   - edited SHA-256: `5faa24ee44180ff94a2ccbc5f6143131f8b6daa3c73c7f1927379ca395f83e66`
2. TLG0/TLG6 `stimage/2/st2_s2_1_1.tlg`, edited through its 602x639
   PNG sidecar at pixel `(10,10)`, from transparent black to opaque magenta.
   - unpack PNG SHA-256: `987ebff59b32a76c78147d474f4d1bf673044ae6dcfb6a23343ba16c3808df6e`
   - edited PNG SHA-256: `bd920c753ea4ea49d1b70516217e9cfada5343ef6f0a2d4ca018f094b7ed05d5`
   - rebuilt source-format SHA-256 after reopen+TPM decrypt:
     `e7ce5e3939f2cc4c7f2c892720b8108fbbb73d12c550334b0be9774a974b013f`

## Result

Command:

```text
xp3brute verify-roundtrip UNPACK_DIR \
  --source-archive games/game-normal/data.xp3 \
  --output rebuilt.xp3 --json
```

- Archive reopened: `true`
- Overall: `PASS` (`5021/5021`, failed `0`)
- Pack modes: `2` reencoded, `5019` exact stored-byte reuse
- File classifications: `4939` byte-exact, `1` semantic-exact, `81`
  not-applicable opaque/unexpanded entries preserved as exact encrypted bytes
- Rebuilt archive:
  - bytes: `803750886`
  - SHA-256: `766156888298df3eaff1a938d50053d556bc8bef4e0bc8c0200b2bf9a24fe4e0`
- Both edited entries passed reopen, physical name, original XP3 `adlr`/filter
  seed, timestamp/private metadata, segment structure, post-pack decrypt, and
  edited-asset consumption checks.
- The TLG entry additionally passed decode, dimensions, alpha, canonical RGBA
  pixels, and TLG0/SDS container checks.

The archive SHA/size is intentionally different because two assets were
edited. Immutable XP3 metadata was compared independently and remained exact.
