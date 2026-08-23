# Historical protection patterns extracted from the supplied KrkrExtract code

This file is a design input, not a compatibility matrix. The new implementation
should turn these historical cases into generic constraints rather than retain a
per-title decoder table.

## Protected-name sentinel entries

The old parser explicitly recognizes/skips a deliberately pathological
`$$$ This is a protected archive. $$$ ...` filename while identifying an XP3.
The lesson is that a storage name is untrusted evidence and must not control
structural parsing.

## M2/KrkrZ alternate identity records

The supplied `ReadXp3M2InfoChunk` layout is structurally:

```text
root magic       u32   (not stable)
chunk size       u64
hash             u32
filename length  u16
filename         UTF-16LE
```

`FindTheFirstUnknownMagic` demonstrates that the four-byte root magic was not a
stable semantic identifier. The Rust parser therefore recognizes this shape by
length/name consistency and treats the magic as an observation only.

## Indirect/moved indices

The supplied code contains three generations of special root descriptors that
point at a second index blob elsewhere in the physical archive. The layouts
changed over time:

```text
V1: offset:u64, original:u32, archive:u32, product_len:u16, product:UTF-16LE
V2: offset:u64, original:u32, archive:u32
V3: offset:u64, archive:u32, kind:u16
```

The current Rust parser records these as structural indirect-index candidates.
Following/transformation inference belongs to the next container-recovery stage.

## Prefix-only transformed compressed index

The historical `WalkSenrenBankaIndexBuffer` and V2 path read the indirect blob, call the captured `SpecialChunkDecoder` on exactly `min(0x100, compressed_size)` stored bytes, and only then call zlib `uncompress` on the complete blob. The compatible packer performs the same transform on the first `min(0x100, compressed_size)` bytes after `compress2(..., Z_BEST_COMPRESSION)`. Therefore a zlib failure does not imply whole-blob encryption.

The ordinary and special indices also leak a strong cross-check. The supplied packer writes:

```text
yuzu.Hash           = adlr.Hash
yuzu.FileNameLength = real filename UTF-16 length
info.FileNameLength = real filename UTF-16 length
```

while `info.FileName` may itself be replaced by a hash/synthetic lookup token. The Rust parser therefore preserves the raw `info.FileNameLength` and validates decrypted M2/Yuzu records in order using both the checksum/hash and the raw length before accepting any recovered name.

## Runtime decoder discovery and heap filename recovery

The supplied implementation did not assume that every special-index transform had a static XOR key. `XeReadFile`/the exception path captured a title-specific hidden `SpecialChunkDecoder` routine at runtime, and V1/V2 then invoked that routine before zlib decompression. The V3 static path was unfinished/disabled; the runtime `XeZLIB_uncompress` hook was used to capture already decoded/decompressed index data. Heap scanning was another fallback for archive/path strings.

The offline Rust core therefore treats bounded repeating XOR as one exhaustible decoder family, not as the definition of `CxFilterDecrypt`. A candidate is accepted only after decompression plus exact ordered-index validation; an arbitrary native decoder remains unresolved until its transform/key is actually recovered.

The architectural consequence is to separate:

1. payload recovery;
2. original filename recovery;
3. implementation/runtime recovery.

A one-way filename identifier may make (2) impossible from archive bytes alone
without preventing (1).
