# Additional test games and samples needed

Status date: 2026-08-20. This list was produced after inspecting all files under
`../games`. It omits coverage already present: plain/legacy Fate XP3, a real
generic x86 TPM archive with encrypted TLG, HXV4 archives plus EXE, and real
PBD `TJS/ns0` files.

`P0` blocks an important end-to-end claim, `P1` covers an important generation,
`P2` adds compatibility/format breadth, and `P3` is an edge case.

## P0 — Real AMV/AJPM Mode B

**Why:** Mode B encode, template replacement, independent decode, timing and
alpha checks pass synthetically, but no AMV exists in the current games tree.

**Need:** the smallest XP3 containing one Mode B AMV, preferably 2–20 frames.
If the entry is filtered, include the exact game EXE and every TPM/DLL needed by
that filter. Include the XP3 because entry identity/encryption and repack must
also be tested; a loose AMV is useful but only proves the codec layer.

**Files to copy:**

```text
game.exe                    # required only when the XP3/filter needs it
plugin/*.tpm, relevant *.dll
movie-or-data.xp3           # required
```

**Desired formats:** one AMV Mode B with alpha and non-default frame timing if
possible.

## P0 — Small real PSB-family archive with resolvable names

**Why:** generic PSB/SCN resource edits pass synthetic tests, but no real
PSB-family plaintext has completed the whole decode -> expand -> rebuild ->
reparse path. The existing HXV4 `scn.xp3` may already contain this coverage, so
no new sample is necessary if its names can be resolved from the current data.
A small independently resolvable sample is the minimum useful fallback.

**Need:** one XP3 with at least one PSB plus, ideally, one of SCN/MTN/PIMG. For
Emote, include the executable/module from which the private key is recovered.
XP3 alone is insufficient when either XP3 content filtering or Emote protection
depends on the executable.

**Files to copy:**

```text
game.exe                    # required for CXDEC/HXV4/Emote key recovery
plugin/*.tpm, relevant *.dll
one small *.xp3             # required
```

**Desired formats:** typed root, strings, at least two resource indices, and one
embedded image; animation metadata is especially useful for SCN/MTN/Emote.

## P0 — Installed Classic CXDEC executable directory

**Why:** Fate supplies a real `cxdec.tpm` and installer media, but the directly
available `Fate/data.xp3` is plain and the installed main game EXE is not present
as a normal file. A real protected-entry chain is therefore unverified.

**Need:** an installed directory from a Classic CxEncryption title with its main
EXE, `cxdec.tpm`, related DLLs, and at least one XP3 whose content actually uses
the filter. XP3 alone is insufficient because callback keys/generator behavior
must be recovered from the executable/module.

**Files to copy:**

```text
game.exe
cxdec.tpm
all sibling *.tpm and relevant *.dll
one protected data*.xp3
```

Prefer a small archive containing TLG or wrapped text so codec reconstruction
and CXDEC re-encryption can be proven together.

## P1 — AMV/AJPM Mode A

**Why:** Mode A has an additional compressed plane and the writer intentionally
fails closed. A real corpus is needed to characterize that plane without data
loss.

**Need:** two or more Mode A AMVs with different dimensions/content, plus their
containing XP3. Include EXE/TPM/DLL only when required to decrypt the XP3.

**Files to copy:** the relevant XP3 and, if filtered, `game.exe`, `plugin/*.tpm`,
and relevant DLLs. Loose original AMVs are also useful for codec analysis.

## P1 — PBD `TJS/4s0`

**Why:** ns0 has a real HXV4 sample; 4s0 decode/crypt/framing/edit tests are only
synthetic.

**Need:** one XP3 containing a real `TJS/4s0` PBD. If the XP3 is unfiltered, only
the XP3 is required. Otherwise include the matching EXE/TPM/DLL set.

**Desired characteristics:** non-zero crypt mode, IV, multiple ordered records,
strings, and resource references.

## P1 — Historical content-filter generations

These families are absent from `../games`: **Cabbage CXDEC**, **Nana/dls**,
**Riddle/yuz**, and **Senren/sen**. One sample per distinct family is useful;
titles are irrelevant except as a way to obtain that binary profile.

**Why:** recognition constraints exist, but parameter recovery, unpack and
inverse packing cannot be marked supported without their real native decoder
and archive structures.

**Files to copy for each family:**

```text
game.exe
all TPM/DLL plugins, especially dls/yuz/sen/cxdec modules
one smallest protected *.xp3
```

Prefer an archive with a few known-format entries. EXE/plugins are required;
the XP3 alone cannot establish the native transform.

## P2 — Name/Special edge profiles

The following are absent and should be supplied only if readily available:

- a `cbg` name-section archive;
- a legacy KRKR2 archive whose UTF-16 filename is not NUL-terminated;
- an ordinary CXDEC archive that also uses a non-HXV4 Special real-name layer.

**Why:** these distinguish payload filtering from original-name recovery and
exercise template rebuilding of unusual name records.

**Files to copy:** the smallest affected XP3 is required. For CXDEC+Special or
keyed name transforms, also include the main EXE and all TPM/DLL plugins. For a
plain non-NUL-name archive, the XP3 alone is sufficient.

## P2 — Real wrapped KiriKiri text

**Why:** modes 0/1/2, BOM/encoding, CP932 and line-ending preservation pass
synthetic tests, while current real text is not proven to use all wrappers.

**Need:** a small unfiltered XP3 containing representative wrapped text. The XP3
alone is enough if unfiltered; otherwise include its EXE/TPM/DLL set.

## Smallest useful set to provide next

The highest-value minimum is:

1. one small **Mode B AMV XP3** (plus its EXE/plugins only if filtered);
2. one small, name-resolvable **PSB-family XP3** with an image resource, unless
   the current `scn.xp3` bootstrap is completed first;
3. an **installed Classic CXDEC directory** containing the actual main EXE,
   modules, and one genuinely filtered XP3.

After those, a single real `TJS/4s0` PBD and one Mode A AMV are the next most
useful additions. The historical families are best added one at a time rather
than as a large unprioritized game dump.
