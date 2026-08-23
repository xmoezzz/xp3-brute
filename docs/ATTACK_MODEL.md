# Attack model

## Final objective

The operational end condition is **100% entry payload recovery with validation**. If an entry is information-theoretically underdetermined under the independent-key model, the solver must not silently accept partial recovery; that entry becomes evidence that cross-file key derivation or another information source is required. Original filename recovery is tracked separately because a one-way name identifier may not contain enough information to reconstruct the original path.

## Layer 1: container recovery

Recover the XP3 physical structure, index chain, root records, entries, and raw/zlib segments. Unknown root magic is evidence, not identity. Structural constraints have priority over game-specific constants.

## Layer 2: storage stream reconstruction

Reassemble each entry after XP3 segment decoding. This stream is the boundary presented to the repeating-XOR analysis when an extraction filter is present.

## Layer 3: joint period/key/plaintext inference

For a candidate period `L`:

```text
C[i] = P[i] XOR K[i mod L]
```

A plaintext observation at offset `i` directly determines a candidate `K[i mod L]`. Multiple observations that land on the same residue either agree or contradict a period hypothesis.

The period is therefore a variable. Do not assume 256 or 1024; search from 1 upward and prefer the minimal consistent period only as a description-length prior when evidence cannot distinguish exact multiples.

Every recovered key slot decrypts a sparse sequence throughout the file:

```text
j, j + L, j + 2L, ...
```

Those sparse plaintext windows can expose new structural features and produce new key observations. The long-term solver should iterate until no new constraints are learned.

## Layer 4: cross-file constraint transfer

Independent per-file keys do not transfer key material. Solved plaintext still transfers *format knowledge*:

- fixed tags and magic;
- reserved/zero regions;
- offset/count/range relationships;
- alignment;
- repeated record grammar;
- checksums;
- string encodings;
- parser success.

This is useful even under the worst case where every entry key is statistically independent.

## Layer 5: optional key-derivation analysis

Only after intra-file analysis has recovered sparse or complete per-file keys should the program test whether keys share a derivation relation. Cross-file key inference is an accelerator, not an assumption required by the base attack.

## Parallelism

Natural parallel axes are:

- archive entries;
- period hypotheses;
- format hypotheses;
- key slots/candidate values;
- validators;
- optional cross-file derivation hypotheses.

The current implementation parallelizes period and format-hypothesis evaluation with Rayon. Later stages should preserve coarse-grained file parallelism rather than introducing async I/O into a CPU-bound solver.
