//! Frontend-neutral operation progress and cancellation.
//!
//! Core code emits structured events through [`ProgressSink`]. Terminal and
//! Python frontends are responsible for rendering or dispatching those events;
//! this module deliberately has no dependency on either frontend runtime.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressEventKind {
    Started,
    Advanced,
    Message,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressUnit {
    Items,
    Bytes,
    Candidates,
    Frames,
    Steps,
}

impl ProgressUnit {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Bytes => "bytes",
            Self::Candidates => "candidates",
            Self::Frames => "frames",
            Self::Steps => "steps",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressLevel {
    Info,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressOutcome {
    Success,
    Failed,
    Cancelled,
}

/// Stable, flat event representation suitable for terminal, JSON, and FFI use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub sequence: u64,
    pub operation_id: u64,
    pub task_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<u64>,
    pub kind: ProgressEventKind,
    /// Stable kebab-case phase name, such as `reconstruct` or `encode-amv`.
    pub phase: String,
    pub current: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    pub unit: ProgressUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<ProgressLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ProgressOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub trait ProgressSink: Send + Sync + 'static {
    fn emit(&self, event: ProgressEvent);
}

impl<F> ProgressSink for F
where
    F: Fn(ProgressEvent) + Send + Sync + 'static,
{
    fn emit(&self, event: ProgressEvent) {
        self(event);
    }
}

#[derive(Debug, Default)]
pub struct NoopProgressSink;

impl ProgressSink for NoopProgressSink {
    fn emit(&self, _event: ProgressEvent) {}
}

/// Cheap cooperative cancellation shared by operations and worker threads.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

struct OperationInner {
    operation_id: u64,
    next_task_id: AtomicU64,
    next_sequence: AtomicU64,
    sink: Arc<dyn ProgressSink>,
    cancellation: CancellationToken,
}

/// Shared context passed to context-aware long-running library operations.
#[derive(Clone)]
pub struct OperationContext {
    inner: Arc<OperationInner>,
}

impl Default for OperationContext {
    fn default() -> Self {
        Self::silent()
    }
}

impl OperationContext {
    pub fn silent() -> Self {
        Self::new(Arc::new(NoopProgressSink))
    }

    pub fn new(sink: Arc<dyn ProgressSink>) -> Self {
        Self::with_cancellation(sink, CancellationToken::default())
    }

    pub fn with_cancellation(sink: Arc<dyn ProgressSink>, cancellation: CancellationToken) -> Self {
        Self {
            inner: Arc::new(OperationInner {
                operation_id: NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed),
                next_task_id: AtomicU64::new(1),
                next_sequence: AtomicU64::new(1),
                sink,
                cancellation,
            }),
        }
    }

    pub fn operation_id(&self) -> u64 {
        self.inner.operation_id
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.inner.cancellation
    }

    pub fn start_task(
        &self,
        phase: impl Into<String>,
        total: Option<u64>,
        unit: ProgressUnit,
    ) -> ProgressTask {
        self.start_child_task(None, phase, total, unit)
    }

    pub fn start_child_task(
        &self,
        parent_task_id: Option<u64>,
        phase: impl Into<String>,
        total: Option<u64>,
        unit: ProgressUnit,
    ) -> ProgressTask {
        let task = ProgressTask {
            context: self.clone(),
            task_id: self.inner.next_task_id.fetch_add(1, Ordering::Relaxed),
            parent_task_id,
            phase: phase.into(),
            total,
            unit,
            current: Arc::new(AtomicU64::new(0)),
            finished: Arc::new(AtomicBool::new(false)),
        };
        task.emit(ProgressEventKind::Started, None, None, None);
        task
    }

    fn emit(&self, event: ProgressEvent) {
        self.inner.sink.emit(event);
    }

    fn next_sequence(&self) -> u64 {
        self.inner.next_sequence.fetch_add(1, Ordering::Relaxed)
    }
}

/// Thread-safe handle for one phase within an operation.
#[derive(Clone)]
pub struct ProgressTask {
    context: OperationContext,
    task_id: u64,
    parent_task_id: Option<u64>,
    phase: String,
    total: Option<u64>,
    unit: ProgressUnit,
    current: Arc<AtomicU64>,
    finished: Arc<AtomicBool>,
}

impl ProgressTask {
    pub fn id(&self) -> u64 {
        self.task_id
    }

    pub fn is_cancelled(&self) -> bool {
        self.context.cancellation().is_cancelled()
    }

    pub fn position(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }

    pub fn advance(&self, delta: u64) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        self.current.fetch_add(delta, Ordering::Relaxed);
        self.emit(ProgressEventKind::Advanced, None, None, None);
    }

    pub fn set_position(&self, current: u64) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        self.current.store(current, Ordering::Relaxed);
        self.emit(ProgressEventKind::Advanced, None, None, None);
    }

    pub fn message(&self, level: ProgressLevel, message: impl Into<String>) {
        self.emit(
            ProgressEventKind::Message,
            Some(level),
            None,
            Some(message.into()),
        );
    }

    /// Finish the task once. Calls from racing workers after the first are ignored.
    pub fn finish(&self, outcome: ProgressOutcome, message: Option<String>) {
        if self
            .finished
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.emit(ProgressEventKind::Finished, None, Some(outcome), message);
    }

    fn emit(
        &self,
        kind: ProgressEventKind,
        level: Option<ProgressLevel>,
        outcome: Option<ProgressOutcome>,
        message: Option<String>,
    ) {
        self.context.emit(ProgressEvent {
            sequence: self.context.next_sequence(),
            operation_id: self.context.operation_id(),
            task_id: self.task_id,
            parent_task_id: self.parent_task_id,
            kind,
            phase: self.phase.clone(),
            current: self.position(),
            total: self.total,
            unit: self.unit,
            level,
            outcome,
            message,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn task_events_are_ordered_and_finish_once() {
        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let captured = events.clone();
        let context = OperationContext::new(Arc::new(move |event| {
            captured.lock().unwrap().push(event);
        }));
        let task = context.start_task("encode-amv", Some(2), ProgressUnit::Frames);
        task.advance(1);
        task.advance(1);
        task.finish(ProgressOutcome::Success, None);
        task.finish(ProgressOutcome::Failed, Some("late".to_string()));

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].kind, ProgressEventKind::Started);
        assert_eq!(events[1].current, 1);
        assert_eq!(events[2].current, 2);
        assert_eq!(events[3].outcome, Some(ProgressOutcome::Success));
        assert!(events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        assert!(events
            .iter()
            .all(|event| event.operation_id == context.operation_id()));
    }

    #[test]
    fn child_tasks_and_cancellation_are_shared() {
        let token = CancellationToken::default();
        let context =
            OperationContext::with_cancellation(Arc::new(NoopProgressSink), token.clone());
        let parent = context.start_task("unpack", Some(3), ProgressUnit::Steps);
        let child = context.start_child_task(
            Some(parent.id()),
            "reconstruct",
            Some(20),
            ProgressUnit::Items,
        );
        assert!(!child.is_cancelled());
        token.cancel();
        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
    }

    #[test]
    fn events_serialize_with_stable_kebab_case_values() {
        let event = ProgressEvent {
            sequence: 1,
            operation_id: 2,
            task_id: 3,
            parent_task_id: None,
            kind: ProgressEventKind::Finished,
            phase: "pack-archive".to_string(),
            current: 9,
            total: Some(9),
            unit: ProgressUnit::Items,
            level: None,
            outcome: Some(ProgressOutcome::Cancelled),
            message: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"finished\""));
        assert!(json.contains("\"outcome\":\"cancelled\""));
        assert!(json.contains("\"unit\":\"items\""));
    }
}
