# Native CXDEC filter recovery

The CXDEC path is split into recognition, initialization, and archive-time execution.

## Recognition and key recovery

For each PE32/i386 EXE, DLL, or TPM candidate, the scanner looks for the CXDEC generator semantics (the xcode PRNG constants, the 1024-word table mask, adjacent-bit masks, and a plausible callback configuration). The callback configuration is the 32-bit structure:

```text
+0x00  const char *name
+0x04  key0
+0x08  key1
+0x0c  xcode_builder
```

`xcode_builder` must point into an executable section and the structure must be referenced by executable code. `key0` and `key1` are therefore recovered from the title module instead of being selected from a game-name table.

If the user supplies a game EXE to `filter-probe` or `unpack --filter-exe`, sibling EXE/DLL/TPM files are scanned as well.

## Earliest `.decc` profile

The oldest recognized `.decc` family keeps its generator semantics in the native Rust implementation. The 128 lane expressions are reconstructed from lane seeds 0..127; no generated machine code is needed. This static route is selected only when the recovered callback builder itself resides in the `.decc` section; merely having a `.decc` section is not enough to classify a module as the oldest profile.

## Intermediate generator profiles

Intermediate variants keep the same outer CXDEC archive transform but alter generator dispatch order. The tool does not hard-code a game list or permutation table. Instead it uses the recovered `xcode_builder` as an initialization oracle:

1. Create a 20-byte PE32 `cxdec_xcode_status` and a 128-byte output area.
2. Seed the status with the lane index (0..127).
3. Try generator depth 5 down to 1, resetting `curr` after a failed attempt but preserving the mutated PRNG seed.
4. Capture only the builder-emitted body bytes. The generated function is never called.
5. Parse the fixed CXDEC-emitted x86 grammar into a small Rust micro-op IR.
6. Require balanced saved-register pushes/pops and reject any unknown opcode.
7. Recover the control-block VA from emitted `MOV ESI, imm32` instructions when the canonical control-block header is absent.
8. Require all 128 lanes to initialize and agree on the control-block address before selecting the native backend.

After initialization, XP3 file processing uses only the Rust micro-op evaluator.

## Transition-era outer XOR wrappers

Some CXDEC-based titles add an extra XOR stream around the ordinary CXDEC core. The native initializer does not guess such a table from arbitrary PE bytes. When the original registered callback can be executed in the constrained x86 runtime, initialization compares that callback with the recovered native CXDEC core on zero buffers across multiple hashes and offsets. A residual is accepted only if it is independent of the file hash and repeats solely by absolute file offset with a period no larger than 4096 bytes. The recovered period is then applied natively for archive processing. If a non-core residual is observed but does not satisfy those invariants, native initialization is rejected and the generic x86 callback path remains authoritative.

This covers the known 512-byte `ExtraTable[offset % 512]` wrapper shape without hard-coding the table contents or the value 512.

## Archive transform

For an XP3 entry hash `h`, CXDEC selects lane `h & 0x7f`, evaluates it with `h >> 7` and its bitwise complement, derives the body XOR byte and two sparse correction positions, and applies the title-specific boundary `(h & key0) + key1`. Bytes after that boundary use `(h >> 16) ^ h` as the second hash. The transformation is XOR-only and is therefore symmetric for encryption and decryption.

## Fallback

A structural candidate is not enough to activate the native path for an intermediate profile. Its builder must initialize and translate all 128 lanes. If callback/core differential calibration observes an unsupported wrapper, native initialization is also rejected. In either case module selection continues with the generic XP3 filter discovery/Unicorn path.
