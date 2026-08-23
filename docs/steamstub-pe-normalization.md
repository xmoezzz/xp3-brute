# SteamStub PE normalization

`xp3-brute` treats executable packing as a PE-normalization layer, not as an
XP3 protection family.  This keeps outer executable wrappers separate from the
KiriKiri content-filter and Special/name classifiers.

Current support is intentionally narrow:

- SteamStub Variant 3.1.x, PE32/i386, 0xF0-byte DRM header.
- Encrypted code-section form (`Flags == 0`) only.
- Static restoration of the wrapped code section and original PE entry point.
- `.bind` is retained so RVAs and raw offsets remain stable for downstream
  static analysis and Unicorn initialization.

Recognition is structural.  The normalizer requires a valid PE32 image, a
`.bind` section containing the SteamStub v3 entry signature, a decodable
0xF0-byte header with the `0xC0DEC0DF` signature, and internally consistent
ImageBase/OEP/code-section/bind-section ranges.  Game names, Steam App IDs,
file hashes, and fixed RVAs are never used as detectors.

The public API is `normalize_pe_bytes` / `normalize_pe_file`; all current PE
analysis backends pass through this layer.  The CLI exposes the same operation
as:

```text
xp3brute pe-unpack packed.exe normalized.exe
```

This command produces an analysis-normalized PE.  It is not intended to remove
Steamworks API integration or to promise a standalone runnable game binary.

Implementation note: the format behavior was independently implemented for
interoperability.  Steamless was used as a public behavioral reference for the
SteamStub header/decryption format; no Steamless source code is incorporated.
