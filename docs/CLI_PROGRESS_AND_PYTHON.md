# CLI progress and Python API architecture

This document defines the release-facing architecture for `xp3-brute`. It is
the implementation contract for modern terminal progress, non-interactive
automation, and the PyO3 package. The three surfaces must call the same Rust
operations and report the same events.

## Canonical names

| Surface | Canonical name | Compatibility policy |
| --- | --- | --- |
| Cargo package | `xp3-brute` | Authoritative immediately |
| Rust library import | `xp3_brute` | Authoritative immediately |
| CLI executable | `xp3brute` | Retained for existing scripts; a future alias may add `xp3-brute` |
| Python distribution | `xp3-brute` | Built with maturin |
| Python package | `xp3_brute` | Public user import |
| Python extension | `xp3_brute._native` | Private implementation detail |

The existing `krkr-xp3-brute/xp3-meta-v1`, PBD, and PSB schema identifiers
must not be renamed. They identify serialized protocols already written to
disk. New schema versions may use the new project prefix only when their data
contract actually changes.

## Architectural boundary

The dependency direction is fixed:

```text
format/recovery/encoder primitives
            |
            v
operation services + ProgressSink + CancellationToken
            |
       +----+------------------+
       |                       |
       v                       v
CLI renderer (indicatif)   PyO3 adapter (_native)
```

The library never prints progress and never imports `indicatif` or PyO3. The
CLI must not own archive/recovery algorithms. Python bindings must not invoke
CLI argument parsing or capture terminal output.

## Progress event contract

Long-running library operations accept an `OperationContext` containing:

- an `Arc<dyn ProgressSink>`;
- a cheap, cloneable `CancellationToken`;
- an operation ID and task-ID allocator.

The event model is flat and serialization-friendly. Every event carries an
operation ID, task ID, optional parent task ID, phase name, current value,
optional total, unit, and optional message. Event kinds are `started`,
`advanced`, `message`, and `finished`. Finish events distinguish `success`,
`failed`, and `cancelled`.

Phase names are stable kebab-case strings rather than a closed Rust enum. The
initial vocabulary is:

- `open-archive`, `read-index`, `special-index`;
- `bootstrap-names`, `reconstruct`, `solve`, `decode`, `write`;
- `rebuild-assets`, `encode-amv`, `pack-index`, `pack-archive`.

Units are a small enum: `items`, `bytes`, `candidates`, `frames`, and `steps`.
Unknown totals are supported. Parallel workers update atomic counters; the
sink, not each worker, controls redraw frequency.

Existing public functions remain as compatibility wrappers using a no-op
context. New context-aware functions use an `_with_context` suffix until the
next major API version.

## Modern CLI renderer

The CLI renderer will use `indicatif::MultiProgress` on stderr. stdout remains
reserved for command results and machine-readable output.

Global controls:

```text
--progress auto|always|never|json
--color auto|always|never
--quiet
--verbose
```

`auto` renders dynamic bars only when stderr is an attended terminal. Redirects,
`TERM=dumb`, and CI receive stable line output without escape sequences.
`json` emits newline-delimited progress events to stderr using the exact core
event schema. `never` installs the no-op sink. The existing command-local
`--no-progress` remains a deprecated alias for `--progress never` during the
transition.

Rendering rules:

- show at most one parent operation plus the active child phases;
- use a spinner for unknown totals and a bar for known totals;
- show phase, count, unit, rate, elapsed time, and ETA when meaningful;
- aggregate updates at no more than 20 redraws per second;
- route diagnostics through `MultiProgress::suspend` so messages never damage
  active bars;
- finish successful tasks with a concise persisted summary and remove obsolete
  child bars;
- Ctrl-C sets the cancellation token; workers stop at defined safe points and
  incomplete output is reported explicitly.

Snapshot tests use a fake terminal width and deterministic elapsed time. Other
tests cover redirected stderr, zero totals, unknown totals, concurrent task
updates, early success, errors, and cancellation.

## Operation-service extraction

Before broad Python exposure, the workflows currently embedded in `main.rs`
must move into library modules:

- `operations::inspect`;
- `operations::unpack`;
- `operations::rebuild`;
- `operations::pack`.

Each operation takes typed options and returns a typed report. No operation
returns preformatted console lines. CLI JSON, terminal summaries, and Python
objects are projections of the same report types.

The first migration target is `unpack`, because it currently owns the three
parallel `reconstruct`, `solve`, and `unpack` counters and therefore exercises
nested progress, cancellation, warnings, and bounded-memory behavior.

## PyO3 package

The binding is a separate workspace crate under `bindings/python`. This keeps
PyO3 and Python linker configuration out of the core Rust library. The mixed
Python package lives under `python/xp3_brute`, is built by maturin, includes a
`py.typed` marker and `.pyi` stubs, and re-exports the private `_native` module.

Minimum Python is 3.9. Release wheels target `abi3-py39`; exact-interpreter
development builds remain possible when profiling shows a material benefit.
The core Cargo package version is the single version source.

Initial public Python surface:

```python
xp3_brute.open_archive(path) -> Archive
Archive.entries -> Sequence[EntryInfo]
Archive.reconstruct(index) -> bytes
xp3_brute.inspect(path, *, progress=None, cancel=None) -> InspectReport
xp3_brute.unpack(path, output, *, options=None, progress=None, cancel=None) -> UnpackReport
xp3_brute.rebuild_assets(root, *, options=None, progress=None) -> RebuildReport
xp3_brute.pack(root, output, *, options=None, progress=None, cancel=None) -> PackReport
xp3_brute.encode_amv(frames, output, *, fps=30, quality=75, progress=None)
```

All native work detaches from the Python runtime. Python objects are converted
to owned Rust values before detaching. Progress callbacks are not called from
Rayon workers directly: events enter a bounded/coalescing queue and one Python
dispatcher invokes the callback in order. Callback exceptions cancel the
operation and are re-raised on the calling thread.

Rust errors map to a stable Python hierarchy rooted at `Xp3Error`, with
`FormatError`, `InvalidArgumentError`, `UnsupportedError`, `CancelledError`,
and `OSError` mappings where applicable. Panics never cross the FFI boundary.

## Delivery milestones

### M0 — canonical identity

- rename the Cargo package and Rust import;
- update examples, tests, README, lockfile, and producer metadata;
- preserve old serialized schema IDs.

Acceptance: `cargo test`, examples, and CLI compilation pass under the new
crate import, with no `krkr_xp3_brute` code references remaining.

### M1 — core event layer

- add `progress` and `operations` modules;
- implement no-op, channel, and test sinks plus cancellation;
- migrate `shared-probe` and AMV encoding as small end-to-end examples.

Acceptance: operations emit deterministic events without terminal dependencies.

### M2 — modern CLI

- add global output policy and indicatif renderer;
- migrate Special recovery and full unpack pipeline;
- centralize diagnostics so concurrent output cannot corrupt bars.

Acceptance: interactive, redirected, JSON, quiet, and cancelled runs all have
stable tested behavior.

### M3 — PyO3 foundation

- add workspace binding crate, maturin configuration, package, stubs, and
  exception hierarchy;
- expose archive inspection/reconstruction and AMV encoding first;
- test wheels on Python 3.9 and current CPython.

Acceptance: `pip install -e .`, import, typing smoke test, native error mapping,
and GIL-detachment concurrency test pass.

### M4 — complete operation parity

- expose unpack, rebuild, and pack reports/options;
- add queued progress callbacks and cancellation;
- publish platform wheels and CLI artifacts from one release tag.

Acceptance: equivalent Rust, CLI JSON, and Python calls produce equivalent
reports and manifest outputs on the sample corpus.
