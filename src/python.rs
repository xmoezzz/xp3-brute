//! CPython bindings for the stable, frontend-neutral XP3 API.
//!
//! The extension intentionally exposes data as Python primitives and JSON for
//! complex reports.  This keeps the ABI small and makes it equally convenient
//! to use from a script, a GUI, or a service without mirroring every internal
//! Rust type in Python.

use crate::{
    decode_amv, decode_pbd, decode_tlg_file, detect_filter, encode_pbd_json, encode_tlg_image_file,
    export_amv_frames, export_decoded_tlg, pack_xp3_from_manifest, rebuild_assets_from_manifest,
    recover_stream, verify_roundtrip, Archive, ArchiveOptions, ComputeMode, PbdJsonDocument,
    RebuildOptions, RecoveryConfig, TlgEncodeOptions, TlgExportFormat, TlgExportOptions,
    VerifyRoundtripOptions, Xp3PackOptions,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn runtime_error(error: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn export_format(value: &str) -> PyResult<TlgExportFormat> {
    match value.to_ascii_lowercase().as_str() {
        "png" => Ok(TlgExportFormat::Png),
        "jpg" | "jpeg" => Ok(TlgExportFormat::Jpeg),
        "bmp" => Ok(TlgExportFormat::Bmp),
        _ => Err(PyValueError::new_err(
            "format must be png, jpg/jpeg, or bmp",
        )),
    }
}

/// An XP3 entry. `name` is the archive name; for HXV4 it can be a synthetic
/// lookup token, in which case `hxv4_id` is populated.
#[pyclass(module = "xp3_brute", name = "Entry", frozen)]
#[derive(Clone)]
struct PyEntry {
    #[pyo3(get)]
    index: usize,
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    alternate_name: Option<String>,
    #[pyo3(get)]
    original_size: u64,
    #[pyo3(get)]
    archive_size: u64,
    #[pyo3(get)]
    adler: Option<u32>,
    #[pyo3(get)]
    hxv4_id: Option<u64>,
    #[pyo3(get)]
    protected_dummy: bool,
    #[pyo3(get)]
    segment_count: usize,
}

impl PyEntry {
    fn from_entry(index: usize, entry: &crate::Entry) -> Self {
        Self {
            index,
            name: entry.name.clone(),
            alternate_name: entry.alternate_name.clone(),
            original_size: entry.original_size,
            archive_size: entry.archive_size,
            adler: entry.adler,
            hxv4_id: entry.hxv4_id,
            protected_dummy: entry.is_protected_dummy(),
            segment_count: entry.segments.len(),
        }
    }
}

/// File-backed or in-memory XP3 container.
#[pyclass(module = "xp3_brute", name = "Archive")]
struct PyArchive {
    archive: Archive,
}

#[pymethods]
impl PyArchive {
    #[new]
    #[pyo3(signature = (path, tolerant = true))]
    fn new(path: PathBuf, tolerant: bool) -> PyResult<Self> {
        Archive::open_with_options(path, ArchiveOptions { tolerant })
            .map(|archive| Self { archive })
            .map_err(runtime_error)
    }

    #[staticmethod]
    #[pyo3(signature = (data, tolerant = true))]
    fn from_bytes(data: &[u8], tolerant: bool) -> PyResult<Self> {
        Archive::from_bytes_with_options(data.to_vec(), ArchiveOptions { tolerant })
            .map(|archive| Self { archive })
            .map_err(runtime_error)
    }

    #[getter]
    fn path(&self) -> Option<String> {
        self.archive
            .path
            .as_ref()
            .map(|path| path.display().to_string())
    }

    #[getter]
    fn xp3_offset(&self) -> u64 {
        self.archive.xp3_offset
    }

    #[getter]
    fn physical_size(&self) -> u64 {
        self.archive.physical_size()
    }

    #[getter]
    fn is_hxv4(&self) -> bool {
        self.archive.is_hxv4()
    }

    fn entries(&self) -> Vec<PyEntry> {
        self.archive
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| PyEntry::from_entry(index, entry))
            .collect()
    }

    /// Return a compact, stable JSON summary.  Use `entries()` for typed entry
    /// records and `reconstruct_entry()` for the reconstructed storage stream.
    fn summary_json(&self) -> String {
        json!({
            "path": self.archive.path.as_ref().map(|path| path.display().to_string()),
            "xp3_offset": self.archive.xp3_offset,
            "physical_size": self.archive.physical_size(),
            "file_backed": self.archive.is_file_backed(),
            "hxv4": self.archive.is_hxv4(),
            "entries": self.archive.entries.len(),
            "index_blocks": self.archive.index_blocks.len(),
            "root_chunks": self.archive.root_chunks.len(),
        })
        .to_string()
    }

    fn reconstruct_entry<'py>(
        &self,
        py: Python<'py>,
        index: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.archive
            .reconstruct_entry(index)
            .map(|bytes| PyBytes::new(py, &bytes))
            .map_err(runtime_error)
    }

    fn stored_entry_bytes<'py>(
        &self,
        py: Python<'py>,
        index: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.archive
            .stored_entry_bytes(index)
            .map(|bytes| PyBytes::new(py, &bytes))
            .map_err(runtime_error)
    }

    fn adler_matches(&self, index: usize, plaintext: &[u8]) -> PyResult<Option<bool>> {
        self.archive
            .adler_matches(index, plaintext)
            .map_err(runtime_error)
    }
}

#[pyfunction]
fn decode_pbd_json(data: &[u8], pretty: Option<bool>) -> PyResult<String> {
    let document = decode_pbd(data).map_err(runtime_error)?;
    let json = if pretty.unwrap_or(true) {
        serde_json::to_string_pretty(&document.to_json_document())
    } else {
        serde_json::to_string(&document.to_json_document())
    };
    json.map_err(runtime_error)
}

#[pyfunction]
fn encode_pbd_json_bytes(document_json: &str) -> PyResult<Vec<u8>> {
    let document: PbdJsonDocument = serde_json::from_str(document_json)
        .map_err(|error| PyValueError::new_err(format!("invalid PBD JSON: {error}")))?;
    encode_pbd_json(&document).map_err(runtime_error)
}

#[pyfunction]
fn decode_tlg_to_file(
    input: PathBuf,
    output: PathBuf,
    format: Option<&str>,
    jpeg_quality: Option<u8>,
) -> PyResult<String> {
    let decoded = decode_tlg_file(&input).map_err(runtime_error)?;
    let format = match format {
        Some(value) => export_format(value)?,
        None => TlgExportFormat::from_extension(&output).ok_or_else(|| {
            PyValueError::new_err("output extension must be png, jpg/jpeg, or bmp")
        })?,
    };
    let quality = jpeg_quality.unwrap_or(95);
    export_decoded_tlg(
        &decoded,
        &output,
        TlgExportOptions {
            format,
            jpeg_quality: quality,
        },
    )
    .map_err(runtime_error)?;
    Ok(json!({
        "input": input,
        "output": output,
        "width": decoded.info.width,
        "height": decoded.info.height,
        "components": decoded.info.components,
        "format": format.extension(),
    })
    .to_string())
}

#[pyfunction]
#[pyo3(signature = (input, output, components = 4, allow_lossy = false))]
fn encode_tlg_file(
    input: PathBuf,
    output: PathBuf,
    components: u8,
    allow_lossy: bool,
) -> PyResult<()> {
    encode_tlg_image_file(
        &input,
        &output,
        TlgEncodeOptions {
            components,
            allow_lossy,
        },
    )
    .map_err(runtime_error)
}

#[pyfunction]
fn export_amv(input: PathBuf, output_dir: PathBuf) -> PyResult<Vec<String>> {
    let bytes = fs::read(&input).map_err(runtime_error)?;
    let decoded = decode_amv(&bytes).map_err(runtime_error)?;
    export_amv_frames(&decoded, &output_dir)
        .map_err(runtime_error)
        .map(|paths| {
            paths
                .into_iter()
                .map(|path| path.display().to_string())
                .collect()
        })
}

#[pyfunction]
#[pyo3(signature = (unpack_root, output, source_archive = None, rebuilt_root = None, allow_lossy = false, preserve_physical_anchors = true))]
fn pack_xp3(
    unpack_root: PathBuf,
    output: PathBuf,
    source_archive: Option<PathBuf>,
    rebuilt_root: Option<PathBuf>,
    allow_lossy: bool,
    preserve_physical_anchors: bool,
) -> PyResult<String> {
    let report = pack_xp3_from_manifest(
        &unpack_root,
        &output,
        &Xp3PackOptions {
            source_archive,
            rebuild_assets: true,
            rebuilt_root,
            allow_lossy,
            preserve_physical_anchors,
        },
    )
    .map_err(runtime_error)?;
    Ok(json!({
        "output": report.output,
        "bytes_written": report.bytes_written,
        "reused_stored_entries": report.reused_stored_entries,
        "reencoded_entries": report.reencoded_entries,
        "index_blocks": report.index_blocks,
        "root_chunks": report.root_chunks,
        "special_blobs": report.special_blobs,
        "byte_identical_to_source": report.byte_identical_to_source,
    })
    .to_string())
}

#[pyfunction]
#[pyo3(signature = (unpack_root, output_root, allow_lossy = false, changed_only = false))]
fn rebuild_assets(
    unpack_root: PathBuf,
    output_root: PathBuf,
    allow_lossy: bool,
    changed_only: bool,
) -> PyResult<String> {
    let report = rebuild_assets_from_manifest(
        &unpack_root,
        &RebuildOptions {
            output_root,
            allow_lossy,
            changed_only,
        },
    )
    .map_err(runtime_error)?;
    Ok(json!({
        "records": report.records.into_iter().map(|record| json!({
            "kind": record.kind,
            "source_path": record.source_path,
            "output_path": record.output_path,
            "detail": record.detail,
        })).collect::<Vec<_>>(),
    })
    .to_string())
}

#[pyfunction]
#[pyo3(signature = (unpack_root, output, source_archive = None, rebuilt_root = None, allow_lossy = false, preserve_physical_anchors = true))]
fn verify_roundtrip_json(
    unpack_root: PathBuf,
    output: PathBuf,
    source_archive: Option<PathBuf>,
    rebuilt_root: Option<PathBuf>,
    allow_lossy: bool,
    preserve_physical_anchors: bool,
) -> PyResult<String> {
    let report = verify_roundtrip(
        &unpack_root,
        &VerifyRoundtripOptions {
            output_archive: output,
            rebuilt_root,
            source_archive,
            allow_lossy,
            preserve_physical_anchors,
        },
    )
    .map_err(runtime_error)?;
    crate::roundtrip_report_json(&report).map_err(runtime_error)
}

#[pyfunction]
#[pyo3(signature = (target = None))]
fn detect_filter_json(target: Option<PathBuf>) -> PyResult<String> {
    let report = detect_filter(target.as_deref()).map_err(runtime_error)?;
    Ok(json!({
        "source_module": report.source_module,
        "backend": format!("{:?}", report.backend),
        "content": format!("{:?}", report.content),
        "special_names": format!("{:?}", report.special_names),
        "confidence": format!("{:?}", report.confidence),
        "callback_va": report.callback_va,
        "callback_source": report.callback_source,
        "evidence": report.evidence.into_iter().map(|e| json!({"kind": e.kind, "detail": e.detail})).collect::<Vec<_>>(),
    }).to_string())
}

#[pyfunction]
#[pyo3(signature = (data, filename, min_period = 1, max_period = 1024, top_periods = 8, exhaustive_dynamic = false))]
fn recover_xor_json(
    data: &[u8],
    filename: &str,
    min_period: usize,
    max_period: usize,
    top_periods: usize,
    exhaustive_dynamic: bool,
) -> PyResult<String> {
    let report = recover_stream(
        data,
        &crate::hypotheses_for_name(filename),
        &RecoveryConfig {
            min_period,
            max_period,
            top_periods_per_hypothesis: top_periods,
            exhaustive_dynamic_periods: exhaustive_dynamic,
            compute_mode: ComputeMode::Auto,
            ..RecoveryConfig::default()
        },
    )
    .map_err(runtime_error)?;
    Ok(json!({
        "candidates": report.candidates.into_iter().map(|candidate| json!({
            "hypothesis": candidate.hypothesis,
            "period": candidate.period.period,
            "known_slots": candidate.period.known_slots,
            "conflicts": candidate.period.conflicts,
            "agreements": candidate.period.agreements,
            "coverage": candidate.period.coverage(),
            "key_hex": candidate.period.key.iter().map(|byte| byte.map(|v| format!("{v:02x}")).unwrap_or_else(|| "??".to_string())).collect::<String>(),
            "refinement_rounds": candidate.refinement_rounds,
        })).collect::<Vec<_>>(),
    }).to_string())
}

#[pymodule]
fn xp3_brute(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<PyArchive>()?;
    module.add_class::<PyEntry>()?;
    module.add_function(wrap_pyfunction!(decode_pbd_json, module)?)?;
    module.add_function(wrap_pyfunction!(encode_pbd_json_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(decode_tlg_to_file, module)?)?;
    module.add_function(wrap_pyfunction!(encode_tlg_file, module)?)?;
    module.add_function(wrap_pyfunction!(export_amv, module)?)?;
    module.add_function(wrap_pyfunction!(pack_xp3, module)?)?;
    module.add_function(wrap_pyfunction!(rebuild_assets, module)?)?;
    module.add_function(wrap_pyfunction!(verify_roundtrip_json, module)?)?;
    module.add_function(wrap_pyfunction!(detect_filter_json, module)?)?;
    module.add_function(wrap_pyfunction!(recover_xor_json, module)?)?;
    Ok(())
}
