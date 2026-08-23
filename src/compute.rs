//! Optional cross-platform GPU acceleration for the data-parallel recovery kernels.
//!
//! The CPU remains authoritative for XP3 parsing, dynamic format propagation,
//! MITM joins, and final validation. wgpu accelerates batched text-period
//! coincidence ranking, 256-way key-slot likelihood scoring, and bounded
//! mixed-radix Adler search. All GPU-derived candidates are independently
//! validated on the CPU before they can become recovered plaintext.

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Debug, Default)]
pub struct ComputeTelemetry {
    pub gpu_period_jobs: u64,
    pub gpu_period_candidates: u64,
    pub gpu_slot_jobs: u64,
    pub gpu_slot_candidates: u64,
    pub gpu_adler_jobs: u64,
    pub gpu_adler_candidates: u64,
    pub gpu_busy_fallbacks: u64,
    pub gpu_error_fallbacks: u64,
    pub gpu_time_ms: u64,
    pub cpu_period_jobs: u64,
    pub cpu_slot_jobs: u64,
}

static GPU_PERIOD_JOBS: AtomicU64 = AtomicU64::new(0);
static GPU_PERIOD_CANDIDATES: AtomicU64 = AtomicU64::new(0);
static GPU_SLOT_JOBS: AtomicU64 = AtomicU64::new(0);
static GPU_SLOT_CANDIDATES: AtomicU64 = AtomicU64::new(0);
static GPU_ADLER_JOBS: AtomicU64 = AtomicU64::new(0);
static GPU_ADLER_CANDIDATES: AtomicU64 = AtomicU64::new(0);
static GPU_BUSY_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static GPU_ERROR_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static GPU_TIME_MS: AtomicU64 = AtomicU64::new(0);
static CPU_PERIOD_JOBS: AtomicU64 = AtomicU64::new(0);
static CPU_SLOT_JOBS: AtomicU64 = AtomicU64::new(0);
static AUTO_GPU_QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
const AUTO_GPU_QUEUE_LIMIT: u64 = 2;

pub fn compute_telemetry() -> ComputeTelemetry {
    ComputeTelemetry {
        gpu_period_jobs: GPU_PERIOD_JOBS.load(Ordering::Relaxed),
        gpu_period_candidates: GPU_PERIOD_CANDIDATES.load(Ordering::Relaxed),
        gpu_slot_jobs: GPU_SLOT_JOBS.load(Ordering::Relaxed),
        gpu_slot_candidates: GPU_SLOT_CANDIDATES.load(Ordering::Relaxed),
        gpu_adler_jobs: GPU_ADLER_JOBS.load(Ordering::Relaxed),
        gpu_adler_candidates: GPU_ADLER_CANDIDATES.load(Ordering::Relaxed),
        gpu_busy_fallbacks: GPU_BUSY_FALLBACKS.load(Ordering::Relaxed),
        gpu_error_fallbacks: GPU_ERROR_FALLBACKS.load(Ordering::Relaxed),
        gpu_time_ms: GPU_TIME_MS.load(Ordering::Relaxed),
        cpu_period_jobs: CPU_PERIOD_JOBS.load(Ordering::Relaxed),
        cpu_slot_jobs: CPU_SLOT_JOBS.load(Ordering::Relaxed),
    }
}

pub fn reset_compute_telemetry() {
    for counter in [
        &GPU_PERIOD_JOBS,
        &GPU_PERIOD_CANDIDATES,
        &GPU_SLOT_JOBS,
        &GPU_SLOT_CANDIDATES,
        &GPU_ADLER_JOBS,
        &GPU_ADLER_CANDIDATES,
        &GPU_BUSY_FALLBACKS,
        &GPU_ERROR_FALLBACKS,
        &GPU_TIME_MS,
        &CPU_PERIOD_JOBS,
        &CPU_SLOT_JOBS,
        &AUTO_GPU_QUEUE_DEPTH,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
}

pub(crate) fn note_cpu_period_job() {
    CPU_PERIOD_JOBS.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn note_cpu_slot_job() {
    CPU_SLOT_JOBS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ComputeMode {
    /// Use the GPU for sufficiently large supported jobs when an adapter is
    /// available; otherwise use the Rayon/CPU implementation.
    #[default]
    Auto,
    Cpu,
    /// Prefer the GPU even for small supported jobs. If initialization or a
    /// dispatch fails, the caller receives an error rather than silently
    /// pretending the GPU was used.
    Gpu,
    /// CPU structural work and GPU brute-force work are both enabled. GPU
    /// submissions are serialized, but a busy accelerator never stalls other
    /// Rayon jobs: those jobs immediately continue through the CPU fallback.
    Hybrid,
}

impl fmt::Display for ComputeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Hybrid => "hybrid",
        })
    }
}

impl FromStr for ComputeMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "cpu" => Ok(Self::Cpu),
            "gpu" => Ok(Self::Gpu),
            "hybrid" => Ok(Self::Hybrid),
            _ => Err(format!(
                "invalid compute mode {value:?}; expected auto|cpu|gpu|hybrid"
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GpuInfo {
    pub name: String,
    pub backend: String,
    pub device_type: String,
    pub driver: String,
    pub driver_info: String,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AdlerGpuChoice {
    pub value: u8,
    pub a: u32,
    pub b: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct AdlerGpuSlot {
    pub key_slot: usize,
    pub choices: Vec<AdlerGpuChoice>,
}

#[derive(Clone, Debug)]
pub(crate) struct AdlerGpuProblem {
    pub total_combinations: u32,
    pub need_a: u32,
    pub need_b: u32,
    pub slots: Vec<AdlerGpuSlot>,
}

#[derive(Clone, Debug)]
pub(crate) struct AdlerGpuResult {
    pub hit_indices: Vec<u32>,
    pub adapter_name: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PeriodGpuResult {
    pub counts: Vec<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub(crate) struct SlotScoreGpuResult {
    pub scores: Vec<[f64; 256]>,
}

#[cfg(feature = "gpu")]
mod native {
    use super::{
        AdlerGpuProblem, AdlerGpuResult, GpuInfo, PeriodGpuResult, SlotScoreGpuResult,
        GPU_ADLER_CANDIDATES, GPU_ADLER_JOBS, GPU_PERIOD_CANDIDATES, GPU_PERIOD_JOBS,
        GPU_SLOT_CANDIDATES, GPU_SLOT_JOBS, GPU_TIME_MS,
    };
    use std::borrow::Cow;
    use std::sync::atomic::Ordering;
    use std::sync::{mpsc, Mutex, OnceLock};
    use std::time::Instant;
    use wgpu::util::DeviceExt;

    const WORKGROUP_SIZE: u32 = 256;
    // Adler is only a 32-bit filter and collisions are possible. Keep enough
    // checksum hits for CPU grammar validation; overflow falls back to CPU so
    // correctness never depends on this cap.
    const MAX_HITS: u32 = 4096;

    const SHADER: &str = r#"
const ADLER_MOD: u32 = 65521u;

struct Slot {
    first: u32,
    count: u32,
    key_slot: u32,
    _pad: u32,
};

struct Choice {
    value: u32,
    a: u32,
    b: u32,
    _pad: u32,
};

struct Params {
    total: u32,
    slot_count: u32,
    need_a: u32,
    need_b: u32,
    row_width: u32,
    max_hits: u32,
    _pad0: u32,
    _pad1: u32,
};

struct Hits {
    count: atomic<u32>,
    overflow: atomic<u32>,
    indices: array<u32>,
};

@group(0) @binding(0) var<storage, read> slots: array<Slot>;
@group(0) @binding(1) var<storage, read> choices: array<Choice>;
@group(0) @binding(2) var<uniform> params: Params;
@group(0) @binding(3) var<storage, read_write> hits: Hits;

@compute @workgroup_size(256, 1, 1)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let assignment_index = gid.x + gid.y * params.row_width;
    if (assignment_index >= params.total) {
        return;
    }

    var mixed = assignment_index;
    var sum_a = 0u;
    var sum_b = 0u;
    var s = 0u;
    loop {
        if (s >= params.slot_count) { break; }
        let slot = slots[s];
        let digit = mixed % slot.count;
        mixed = mixed / slot.count;
        let choice = choices[slot.first + digit];
        sum_a = (sum_a + choice.a) % ADLER_MOD;
        sum_b = (sum_b + choice.b) % ADLER_MOD;
        s = s + 1u;
    }

    if (sum_a == params.need_a && sum_b == params.need_b) {
        let out_index = atomicAdd(&hits.count, 1u);
        if (out_index < params.max_hits) {
            hits.indices[out_index] = assignment_index;
        } else {
            atomicStore(&hits.overflow, 1u);
        }
    }
}
"#;

    const PERIOD_SHADER: &str = r#"
struct Params {
    byte_len: u32,
    min_period: u32,
    period_count: u32,
    parity_sensitive: u32,
    max_comparisons: u32,
    _pad0: u32,
    _pad1: u32,
    _pad2: u32,
};

struct CountPair {
    equal: u32,
    total: u32,
};

@group(0) @binding(0) var<storage, read> packed_bytes: array<u32>;
@group(0) @binding(1) var<uniform> params: Params;
@group(0) @binding(2) var<storage, read_write> output: array<CountPair>;

var<workgroup> wg_equal: atomic<u32>;
var<workgroup> wg_total: atomic<u32>;

fn get_byte(index: u32) -> u32 {
    let word = packed_bytes[index >> 2u];
    let shift = (index & 3u) * 8u;
    return (word >> shift) & 255u;
}

@compute @workgroup_size(256, 1, 1)
fn main(
    @builtin(workgroup_id) wid: vec3<u32>,
    @builtin(local_invocation_index) lid: u32
) {
    let pi = wid.x;
    if (pi >= params.period_count) { return; }
    if (lid == 0u) {
        atomicStore(&wg_equal, 0u);
        atomicStore(&wg_total, 0u);
    }
    workgroupBarrier();

    let period = params.min_period + pi;
    var lag = period;
    if (params.parity_sensitive != 0u && (period & 1u) != 0u) {
        lag = period * 2u;
    }
    if (lag < params.byte_len) {
        let available = params.byte_len - lag;
        let step = max(1u, (available + params.max_comparisons - 1u) / params.max_comparisons);
        let sample_count = (available + step - 1u) / step;
        var sample = lid;
        var local_equal = 0u;
        var local_total = 0u;
        loop {
            if (sample >= sample_count) { break; }
            let i = sample * step;
            if (i < available) {
                if (get_byte(i) == get_byte(i + lag)) { local_equal = local_equal + 1u; }
                local_total = local_total + 1u;
            }
            sample = sample + 256u;
        }
        if (local_equal != 0u) { atomicAdd(&wg_equal, local_equal); }
        if (local_total != 0u) { atomicAdd(&wg_total, local_total); }
    }
    workgroupBarrier();
    if (lid == 0u) {
        output[pi].equal = atomicLoad(&wg_equal);
        output[pi].total = atomicLoad(&wg_total);
    }
}
"#;

    const SLOT_SHADER: &str = r#"
struct Params {
    slot_count: u32,
    _pad0: u32,
    _pad1: u32,
    _pad2: u32,
};

@group(0) @binding(0) var<storage, read> histograms: array<u32>;
@group(0) @binding(1) var<storage, read> log_probability: array<f32>;
@group(0) @binding(2) var<uniform> params: Params;
@group(0) @binding(3) var<storage, read_write> scores: array<f32>;

@compute @workgroup_size(256, 1, 1)
fn main(
    @builtin(workgroup_id) wid: vec3<u32>,
    @builtin(local_invocation_index) key: u32
) {
    let slot = wid.x;
    if (slot >= params.slot_count) { return; }
    var score = 0.0;
    var cipher = 0u;
    loop {
        if (cipher >= 256u) { break; }
        let count = histograms[slot * 256u + cipher];
        if (count != 0u) {
            score = score + f32(count) * log_probability[cipher ^ key];
        }
        cipher = cipher + 1u;
    }
    scores[slot * 256u + key] = score;
}
"#;

    struct GpuContext {
        device: wgpu::Device,
        queue: wgpu::Queue,
        pipeline: wgpu::ComputePipeline,
        bind_group_layout: wgpu::BindGroupLayout,
        period_pipeline: wgpu::ComputePipeline,
        period_bind_group_layout: wgpu::BindGroupLayout,
        slot_pipeline: wgpu::ComputePipeline,
        slot_bind_group_layout: wgpu::BindGroupLayout,
        info: GpuInfo,
    }

    static GPU: OnceLock<Result<Mutex<GpuContext>, String>> = OnceLock::new();

    fn words_to_bytes(words: &[u32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 4);
        for &word in words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn backend_name(value: wgpu::Backend) -> String {
        format!("{value:?}")
    }

    fn device_type_name(value: wgpu::DeviceType) -> String {
        format!("{value:?}")
    }

    fn init() -> Result<Mutex<GpuContext>, String> {
        let instance = wgpu::Instance::default();
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .ok_or_else(|| "wgpu found no compatible high-performance adapter".to_string())?;

        let adapter_info = adapter.get_info();
        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("xp3brute compute device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
            },
            None,
        ))
        .map_err(|error| format!("wgpu request_device failed: {error}"))?;

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("xp3brute adler bind group layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("xp3brute adler pipeline layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("xp3brute adler brute shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(SHADER)),
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("xp3brute adler brute pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: "main",
        });

        let period_bind_group_layout =
            device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some("xp3brute period bind group layout"),
                entries: &[
                    wgpu::BindGroupLayoutEntry {
                        binding: 0,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 1,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Uniform,
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 2,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                ],
            });
        let period_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("xp3brute period pipeline layout"),
            bind_group_layouts: &[&period_bind_group_layout],
            push_constant_ranges: &[],
        });
        let period_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("xp3brute period score shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(PERIOD_SHADER)),
        });
        let period_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("xp3brute period score pipeline"),
            layout: Some(&period_layout),
            module: &period_shader,
            entry_point: "main",
        });

        let slot_bind_group_layout =
            device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some("xp3brute slot-score bind group layout"),
                entries: &[
                    wgpu::BindGroupLayoutEntry {
                        binding: 0,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 1,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 2,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Uniform,
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 3,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                ],
            });
        let slot_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("xp3brute slot-score pipeline layout"),
            bind_group_layouts: &[&slot_bind_group_layout],
            push_constant_ranges: &[],
        });
        let slot_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("xp3brute slot-score shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(SLOT_SHADER)),
        });
        let slot_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("xp3brute slot-score pipeline"),
            layout: Some(&slot_layout),
            module: &slot_shader,
            entry_point: "main",
        });

        Ok(Mutex::new(GpuContext {
            device,
            queue,
            pipeline,
            bind_group_layout,
            period_pipeline,
            period_bind_group_layout,
            slot_pipeline,
            slot_bind_group_layout,
            info: GpuInfo {
                name: adapter_info.name,
                backend: backend_name(adapter_info.backend),
                device_type: device_type_name(adapter_info.device_type),
                driver: adapter_info.driver,
                driver_info: adapter_info.driver_info,
            },
        }))
    }

    fn global() -> Result<&'static Mutex<GpuContext>, String> {
        match GPU.get_or_init(init) {
            Ok(context) => Ok(context),
            Err(error) => Err(error.clone()),
        }
    }

    pub(super) fn info() -> Result<GpuInfo, String> {
        let guard = global()?
            .lock()
            .map_err(|_| "wgpu context mutex poisoned".to_string())?;
        Ok(guard.info.clone())
    }

    pub(super) fn search(
        problem: &AdlerGpuProblem,
        wait_for_gpu: bool,
    ) -> Result<AdlerGpuResult, String> {
        if problem.slots.is_empty() {
            return Err("GPU Adler search received no ambiguous slots".to_string());
        }
        if problem.total_combinations == 0 {
            return Err("GPU Adler search received an empty key space".to_string());
        }

        let context = global()?;
        let guard = if wait_for_gpu {
            context
                .lock()
                .map_err(|_| "wgpu context mutex poisoned".to_string())?
        } else {
            context
                .try_lock()
                .map_err(|_| "wgpu accelerator busy".to_string())?
        };
        let device = &guard.device;
        let queue = &guard.queue;
        let started = Instant::now();

        let mut slot_words = Vec::with_capacity(problem.slots.len() * 4);
        let mut choice_words = Vec::new();
        let mut first = 0u32;
        for slot in &problem.slots {
            let count = u32::try_from(slot.choices.len())
                .map_err(|_| "too many GPU choices in one key slot".to_string())?;
            if count == 0 {
                return Err("GPU Adler key slot has no choices".to_string());
            }
            slot_words.extend_from_slice(&[
                first,
                count,
                u32::try_from(slot.key_slot).map_err(|_| "key slot exceeds u32".to_string())?,
                0,
            ]);
            for choice in &slot.choices {
                choice_words.extend_from_slice(&[choice.value as u32, choice.a, choice.b, 0]);
            }
            first = first
                .checked_add(count)
                .ok_or_else(|| "GPU choice table exceeds u32".to_string())?;
        }

        let total_workgroups = problem
            .total_combinations
            .saturating_add(WORKGROUP_SIZE - 1)
            / WORKGROUP_SIZE;
        let max_groups = device.limits().max_compute_workgroups_per_dimension.max(1);
        let groups_x = total_workgroups.min(max_groups).max(1);
        let groups_y = total_workgroups.saturating_add(groups_x - 1) / groups_x;
        if groups_y > max_groups {
            return Err(format!(
                "GPU dispatch requires {groups_y} Y workgroups but adapter limit is {max_groups}"
            ));
        }
        let row_width = groups_x
            .checked_mul(WORKGROUP_SIZE)
            .ok_or_else(|| "GPU row width overflow".to_string())?;

        let params_words = [
            problem.total_combinations,
            u32::try_from(problem.slots.len())
                .map_err(|_| "GPU slot count exceeds u32".to_string())?,
            problem.need_a,
            problem.need_b,
            row_width,
            MAX_HITS,
            0,
            0,
        ];
        let output_words = 2usize + MAX_HITS as usize;
        let output_bytes_len = (output_words * 4) as u64;

        let slot_bytes = words_to_bytes(&slot_words);
        let choice_bytes = words_to_bytes(&choice_words);
        let params_bytes = words_to_bytes(&params_words);
        let zero_output = vec![0u8; output_bytes_len as usize];

        let slot_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute GPU slots"),
            contents: &slot_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });
        let choice_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute GPU choices"),
            contents: &choice_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });
        let params_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute GPU params"),
            contents: &params_bytes,
            usage: wgpu::BufferUsages::UNIFORM,
        });
        let hit_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute GPU hits"),
            contents: &zero_output,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });
        let readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("xp3brute GPU readback"),
            size: output_bytes_len,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("xp3brute adler bind group"),
            layout: &guard.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: slot_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: choice_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: hit_buffer.as_entire_binding(),
                },
            ],
        });

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("xp3brute adler command encoder"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("xp3brute adler brute pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&guard.pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(groups_x, groups_y.max(1), 1);
        }
        encoder.copy_buffer_to_buffer(&hit_buffer, 0, &readback, 0, output_bytes_len);
        queue.submit(Some(encoder.finish()));

        let slice = readback.slice(..);
        let (sender, receiver) = mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        device.poll(wgpu::Maintain::Wait);
        receiver
            .recv()
            .map_err(|_| "wgpu readback callback channel closed".to_string())?
            .map_err(|error| format!("wgpu map_async failed: {error:?}"))?;

        let mapped = slice.get_mapped_range();
        if mapped.len() < 8 {
            return Err("wgpu returned a truncated hit buffer".to_string());
        }
        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes([
                mapped[offset],
                mapped[offset + 1],
                mapped[offset + 2],
                mapped[offset + 3],
            ])
        };
        let hit_count = read_u32(0);
        let overflow = read_u32(4);
        if overflow != 0 || hit_count > MAX_HITS {
            drop(mapped);
            readback.unmap();
            return Err(format!(
                "GPU Adler hit buffer overflowed ({}+ hits); retrying on CPU preserves completeness",
                MAX_HITS
            ));
        }
        let mut hit_indices = Vec::with_capacity(hit_count as usize);
        for i in 0..hit_count as usize {
            hit_indices.push(read_u32(8 + i * 4));
        }
        drop(mapped);
        readback.unmap();

        GPU_ADLER_JOBS.fetch_add(1, Ordering::Relaxed);
        GPU_ADLER_CANDIDATES.fetch_add(problem.total_combinations as u64, Ordering::Relaxed);
        GPU_TIME_MS.fetch_add(
            started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        Ok(AdlerGpuResult {
            hit_indices,
            adapter_name: guard.info.name.clone(),
        })
    }

    fn lock_context(
        wait_for_gpu: bool,
    ) -> Result<std::sync::MutexGuard<'static, GpuContext>, String> {
        let context = global()?;
        if wait_for_gpu {
            context
                .lock()
                .map_err(|_| "wgpu context mutex poisoned".to_string())
        } else {
            context
                .try_lock()
                .map_err(|_| "wgpu accelerator busy".to_string())
        }
    }

    fn pack_bytes(bytes: &[u8]) -> Vec<u8> {
        let words = (bytes.len() + 3) / 4;
        let mut out = vec![0u8; words * 4];
        out[..bytes.len()].copy_from_slice(bytes);
        out
    }

    pub(super) fn period_scores(
        bytes: &[u8],
        min_period: usize,
        max_period: usize,
        parity_sensitive: bool,
        wait_for_gpu: bool,
    ) -> Result<PeriodGpuResult, String> {
        if bytes.is_empty() || min_period == 0 || max_period < min_period {
            return Err("invalid GPU period-score problem".to_string());
        }
        let guard = lock_context(wait_for_gpu)?;
        let device = &guard.device;
        let queue = &guard.queue;
        let period_count = max_period - min_period + 1;
        if period_count as u32 > device.limits().max_compute_workgroups_per_dimension {
            return Err("period range exceeds GPU workgroup dimension".to_string());
        }
        let started = Instant::now();
        let packed = pack_bytes(bytes);
        let params_words = [
            u32::try_from(bytes.len())
                .map_err(|_| "ciphertext too large for GPU period scorer".to_string())?,
            u32::try_from(min_period).map_err(|_| "min period exceeds u32".to_string())?,
            u32::try_from(period_count).map_err(|_| "period count exceeds u32".to_string())?,
            parity_sensitive as u32,
            32_768u32,
            0,
            0,
            0,
        ];
        let params_bytes = words_to_bytes(&params_words);
        let output_len = period_count * 8;
        let zero_output = vec![0u8; output_len];
        let input_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute period bytes"),
            contents: &packed,
            usage: wgpu::BufferUsages::STORAGE,
        });
        let params_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute period params"),
            contents: &params_bytes,
            usage: wgpu::BufferUsages::UNIFORM,
        });
        let output_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute period output"),
            contents: &zero_output,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });
        let readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("xp3brute period readback"),
            size: output_len as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("xp3brute period bind group"),
            layout: &guard.period_bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: input_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: output_buffer.as_entire_binding(),
                },
            ],
        });
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("xp3brute period encoder"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("xp3brute period pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&guard.period_pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(period_count as u32, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&output_buffer, 0, &readback, 0, output_len as u64);
        queue.submit(Some(encoder.finish()));
        let slice = readback.slice(..);
        let (sender, receiver) = mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        device.poll(wgpu::Maintain::Wait);
        receiver
            .recv()
            .map_err(|_| "wgpu period readback channel closed".to_string())?
            .map_err(|e| format!("wgpu period map failed: {e:?}"))?;
        let mapped = slice.get_mapped_range();
        if mapped.len() != output_len {
            return Err("wgpu period output length mismatch".to_string());
        }
        let mut counts = Vec::with_capacity(period_count);
        for i in 0..period_count {
            let o = i * 8;
            let equal = u32::from_le_bytes(mapped[o..o + 4].try_into().unwrap());
            let total = u32::from_le_bytes(mapped[o + 4..o + 8].try_into().unwrap());
            counts.push((equal, total));
        }
        drop(mapped);
        readback.unmap();
        GPU_PERIOD_JOBS.fetch_add(1, Ordering::Relaxed);
        GPU_PERIOD_CANDIDATES.fetch_add(period_count as u64, Ordering::Relaxed);
        GPU_TIME_MS.fetch_add(
            started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        Ok(PeriodGpuResult { counts })
    }

    pub(super) fn slot_scores(
        histograms: &[[u32; 256]],
        log_probability: &[f64; 256],
        wait_for_gpu: bool,
    ) -> Result<SlotScoreGpuResult, String> {
        if histograms.is_empty() {
            return Err("GPU slot scorer received no slots".to_string());
        }
        let guard = lock_context(wait_for_gpu)?;
        let device = &guard.device;
        let queue = &guard.queue;
        if histograms.len() as u32 > device.limits().max_compute_workgroups_per_dimension {
            return Err("slot count exceeds GPU workgroup dimension".to_string());
        }
        let started = Instant::now();
        let mut hist_words = Vec::with_capacity(histograms.len() * 256);
        for hist in histograms {
            hist_words.extend_from_slice(hist);
        }
        let hist_bytes = words_to_bytes(&hist_words);
        let mut prob_bytes = Vec::with_capacity(256 * 4);
        for &v in log_probability {
            prob_bytes.extend_from_slice(&(v as f32).to_le_bytes());
        }
        let params_bytes = words_to_bytes(&[histograms.len() as u32, 0, 0, 0]);
        let output_len = histograms.len() * 256 * 4;
        let zero_output = vec![0u8; output_len];
        let hist_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute slot histograms"),
            contents: &hist_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });
        let prob_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute slot logp"),
            contents: &prob_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });
        let params_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute slot params"),
            contents: &params_bytes,
            usage: wgpu::BufferUsages::UNIFORM,
        });
        let output_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("xp3brute slot output"),
            contents: &zero_output,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });
        let readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("xp3brute slot readback"),
            size: output_len as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("xp3brute slot bind group"),
            layout: &guard.slot_bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: hist_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: prob_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: output_buffer.as_entire_binding(),
                },
            ],
        });
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("xp3brute slot encoder"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("xp3brute slot-score pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&guard.slot_pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(histograms.len() as u32, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&output_buffer, 0, &readback, 0, output_len as u64);
        queue.submit(Some(encoder.finish()));
        let slice = readback.slice(..);
        let (sender, receiver) = mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        device.poll(wgpu::Maintain::Wait);
        receiver
            .recv()
            .map_err(|_| "wgpu slot readback channel closed".to_string())?
            .map_err(|e| format!("wgpu slot map failed: {e:?}"))?;
        let mapped = slice.get_mapped_range();
        if mapped.len() != output_len {
            return Err("wgpu slot output length mismatch".to_string());
        }
        let mut scores = Vec::with_capacity(histograms.len());
        for slot in 0..histograms.len() {
            let mut row = [0.0f64; 256];
            for key in 0..256 {
                let o = (slot * 256 + key) * 4;
                row[key] = f32::from_le_bytes(mapped[o..o + 4].try_into().unwrap()) as f64;
            }
            scores.push(row);
        }
        drop(mapped);
        readback.unmap();
        GPU_SLOT_JOBS.fetch_add(1, Ordering::Relaxed);
        GPU_SLOT_CANDIDATES.fetch_add((histograms.len() * 256) as u64, Ordering::Relaxed);
        GPU_TIME_MS.fetch_add(
            started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        Ok(SlotScoreGpuResult { scores })
    }
}

fn try_enter_auto_gpu_queue() -> bool {
    let mut current = AUTO_GPU_QUEUE_DEPTH.load(Ordering::Relaxed);
    loop {
        if current >= AUTO_GPU_QUEUE_LIMIT {
            return false;
        }
        match AUTO_GPU_QUEUE_DEPTH.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(next) => current = next,
        }
    }
}

fn leave_auto_gpu_queue() {
    AUTO_GPU_QUEUE_DEPTH.fetch_sub(1, Ordering::AcqRel);
}

pub(crate) fn gpu_period_scores(
    mode: ComputeMode,
    bytes: &[u8],
    min_period: usize,
    max_period: usize,
    parity_sensitive: bool,
    min_bytes: usize,
) -> Result<Option<PeriodGpuResult>, String> {
    if mode == ComputeMode::Cpu || (mode != ComputeMode::Gpu && bytes.len() < min_bytes) {
        return Ok(None);
    }
    #[cfg(feature = "gpu")]
    {
        let (wait, queued) = match mode {
            ComputeMode::Gpu => (true, false),
            ComputeMode::Auto => {
                if !try_enter_auto_gpu_queue() {
                    GPU_BUSY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                (true, true)
            }
            ComputeMode::Hybrid => (false, false),
            ComputeMode::Cpu => unreachable!(),
        };
        let result = native::period_scores(bytes, min_period, max_period, parity_sensitive, wait);
        if queued {
            leave_auto_gpu_queue();
        }
        match result {
            Ok(result) => Ok(Some(result)),
            Err(error) if mode != ComputeMode::Gpu => {
                if error.contains("busy") {
                    GPU_BUSY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                } else {
                    GPU_ERROR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(feature = "gpu"))]
    {
        if mode == ComputeMode::Gpu {
            Err("this build was compiled without the `gpu` feature".to_string())
        } else {
            Ok(None)
        }
    }
}

pub(crate) fn gpu_slot_scores(
    mode: ComputeMode,
    histograms: &[[u32; 256]],
    log_probability: &[f64; 256],
    min_candidates: usize,
) -> Result<Option<SlotScoreGpuResult>, String> {
    let candidates = histograms.len().saturating_mul(256);
    if mode == ComputeMode::Cpu || (mode != ComputeMode::Gpu && candidates < min_candidates) {
        return Ok(None);
    }
    #[cfg(feature = "gpu")]
    {
        let (wait, queued) = match mode {
            ComputeMode::Gpu => (true, false),
            ComputeMode::Auto => {
                if !try_enter_auto_gpu_queue() {
                    GPU_BUSY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                (true, true)
            }
            ComputeMode::Hybrid => (false, false),
            ComputeMode::Cpu => unreachable!(),
        };
        let result = native::slot_scores(histograms, log_probability, wait);
        if queued {
            leave_auto_gpu_queue();
        }
        match result {
            Ok(result) => Ok(Some(result)),
            Err(error) if mode != ComputeMode::Gpu => {
                if error.contains("busy") {
                    GPU_BUSY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                } else {
                    GPU_ERROR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(feature = "gpu"))]
    {
        if mode == ComputeMode::Gpu {
            Err("this build was compiled without the `gpu` feature".to_string())
        } else {
            Ok(None)
        }
    }
}

pub fn gpu_info() -> Result<Option<GpuInfo>, String> {
    #[cfg(feature = "gpu")]
    {
        native::info().map(Some)
    }
    #[cfg(not(feature = "gpu"))]
    {
        Ok(None)
    }
}

pub(crate) fn gpu_adler_search(
    mode: ComputeMode,
    problem: &AdlerGpuProblem,
    min_combinations: u128,
) -> Result<Option<AdlerGpuResult>, String> {
    if mode == ComputeMode::Cpu {
        return Ok(None);
    }
    if mode != ComputeMode::Gpu && (problem.total_combinations as u128) < min_combinations {
        return Ok(None);
    }

    #[cfg(feature = "gpu")]
    {
        let (wait, queued) = match mode {
            ComputeMode::Gpu => (true, false),
            ComputeMode::Auto => {
                if !try_enter_auto_gpu_queue() {
                    GPU_BUSY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                (true, true)
            }
            ComputeMode::Hybrid => (false, false),
            ComputeMode::Cpu => unreachable!(),
        };
        let result = native::search(problem, wait);
        if queued {
            leave_auto_gpu_queue();
        }
        match result {
            Ok(result) => Ok(Some(result)),
            Err(error) if mode != ComputeMode::Gpu => {
                if error.contains("busy") {
                    GPU_BUSY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                } else {
                    GPU_ERROR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(feature = "gpu"))]
    {
        if mode == ComputeMode::Gpu {
            Err("this build was compiled without the `gpu` feature".to_string())
        } else {
            Ok(None)
        }
    }
}
