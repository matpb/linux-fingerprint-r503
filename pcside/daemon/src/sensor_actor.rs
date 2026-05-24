//! Actor that owns the blocking R503 sensor on a dedicated OS thread and
//! exposes async methods over tokio channels.
//!
//! The sensor is a single physical device on a single serial port; only one
//! operation can be in flight at a time. We serialize via an mpsc queue and
//! run the actual I/O inside `tokio::task::spawn_blocking`.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, OnceCell};

use crate::sensor::{MatchResult, R503, SensorError, SensorInfo};

/// Progress channel for a single in-flight operation. The sensor actor writes
/// each PROGRESS line; the caller (D-Bus interface) reads them and translates
/// to fprintd signals.
pub type ProgressTx = mpsc::UnboundedSender<String>;
pub type ProgressRx = mpsc::UnboundedReceiver<String>;

enum SensorRequest {
    Info(oneshot::Sender<Result<SensorInfo, SensorError>>),
    Enroll {
        slot: u8,
        progress: Option<ProgressTx>,
        done: oneshot::Sender<Result<u8, SensorError>>,
    },
    Verify {
        progress: Option<ProgressTx>,
        done: oneshot::Sender<Result<MatchResult, SensorError>>,
    },
    Identify {
        progress: Option<ProgressTx>,
        done: oneshot::Sender<Result<MatchResult, SensorError>>,
    },
    Delete {
        slot: u8,
        done: oneshot::Sender<Result<u8, SensorError>>,
    },
    Clear(oneshot::Sender<Result<(), SensorError>>),
    Wake(oneshot::Sender<Result<bool, SensorError>>),
    Ping(oneshot::Sender<Result<bool, SensorError>>),
    LedOff(oneshot::Sender<Result<(), SensorError>>),
}

/// Outcome of running one request against the sensor.
/// - `Done`: result was sent to the caller (success or non-IO error).
/// - `NeedsReopen(req)`: the operation hit a fatal I/O error before sending
///   a result; the worker should drop the sensor, reopen, and retry the
///   returned request so the caller still sees a single response.
enum HandleOutcome {
    Done,
    NeedsReopen(SensorRequest),
}

/// An I/O error that means the underlying serial port is no longer usable —
/// distinguishes "the sensor said no to that operation" from "the device is
/// physically gone." On a USB unplug we see `BrokenPipe` (read after device
/// removal) or `NotFound` (open after path went away). serialport-rs sometimes
/// surfaces the kernel-side disconnect as `Other` (the TIOCMGET / termios ioctl
/// just returns ENXIO/ENODEV with no clean ErrorKind mapping), so that bucket
/// has to be treated as fatal too — otherwise an unplug looks like a transient
/// I/O blip and the worker never reopens.
///
/// Exposed pub(crate) so the D-Bus interface can map post-reopen-failure
/// errors to `verify-disconnected` / `enroll-disconnected` status signals.
pub(crate) fn is_fatal_io(err: &SensorError) -> bool {
    use std::io::ErrorKind::*;
    if let SensorError::Io(e) = err {
        matches!(
            e.kind(),
            BrokenPipe | NotFound | NotConnected | UnexpectedEof | PermissionDenied | Other
        )
    } else {
        false
    }
}

#[derive(Clone)]
pub struct SensorActor {
    tx: mpsc::UnboundedSender<SensorRequest>,
    initial_info: Arc<OnceCell<SensorInfo>>,
}

impl SensorActor {
    /// Open the sensor on the given port (or auto-detect), spawn the worker,
    /// probe `info()` once for capacity caching. Returns once the sensor is
    /// fully open and responsive. The worker thread survives subsequent USB
    /// unplug/replug cycles by lazily re-opening on the next request after an
    /// I/O failure.
    pub async fn spawn(port: Option<String>) -> anyhow::Result<Self> {
        let (req_tx, mut req_rx) = mpsc::unbounded_channel::<SensorRequest>();
        let (open_tx, open_rx) = oneshot::channel::<Result<(), SensorError>>();

        std::thread::Builder::new()
            .name("r503-worker".into())
            .spawn(move || {
                // Initial open — must succeed or the daemon won't start.
                let mut sensor: Option<R503> = match R503::open(port.as_deref(), Duration::from_secs(8)) {
                    Ok(s) => {
                        let _ = open_tx.send(Ok(()));
                        Some(s)
                    }
                    Err(e) => {
                        let _ = open_tx.send(Err(e));
                        return;
                    }
                };
                tracing::info!(
                    port = sensor.as_ref().map(|s| s.port_path()).unwrap_or("?"),
                    "R503 sensor open"
                );

                while let Some(initial_req) = req_rx.blocking_recv() {
                    // Inner loop: serve this request, with up to one transparent
                    // reopen+retry on fatal I/O. The caller sees a single
                    // response regardless of how many reopen attempts happened.
                    let mut req = initial_req;
                    let mut already_retried = false;
                    loop {
                        // Ensure the sensor is open. The reopen path races udev:
                        // after an unplug+replug the kernel creates /dev/ttyACM*
                        // before our 70-r503.rules has finished applying, so
                        // /dev/r503 may not exist for ~100-300ms. Retry a few
                        // times with exponential backoff before giving up.
                        if sensor.is_none() {
                            const REOPEN_ATTEMPTS: u32 = 4;
                            let mut last_err: Option<SensorError> = None;
                            for attempt in 0..REOPEN_ATTEMPTS {
                                if attempt > 0 {
                                    let delay_ms = 150u64 << (attempt - 1).min(3);
                                    std::thread::sleep(Duration::from_millis(delay_ms));
                                }
                                match R503::open(port.as_deref(), Duration::from_secs(8)) {
                                    Ok(s) => {
                                        tracing::info!(
                                            port = s.port_path(),
                                            attempt,
                                            "R503 sensor RECONNECTED"
                                        );
                                        sensor = Some(s);
                                        break;
                                    }
                                    Err(e) => {
                                        tracing::warn!(attempt, "reopen failed: {}", e);
                                        last_err = Some(e);
                                    }
                                }
                            }
                            if sensor.is_none() {
                                let err = last_err.unwrap_or_else(|| {
                                    SensorError::Io(std::io::Error::new(
                                        std::io::ErrorKind::NotConnected,
                                        "sensor reopen failed after retries",
                                    ))
                                });
                                Self::respond_with_error(req, err);
                                break;
                            }
                        }
                        let s = sensor.as_mut().unwrap();
                        match Self::handle_request(s, req) {
                            HandleOutcome::Done => break,
                            HandleOutcome::NeedsReopen(returned_req) => {
                                tracing::warn!(
                                    "sensor I/O error — will reopen and retry the request"
                                );
                                sensor = None;
                                if already_retried {
                                    Self::respond_with_error(
                                        returned_req,
                                        SensorError::Io(std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "sensor failed twice in a row",
                                        )),
                                    );
                                    break;
                                }
                                already_retried = true;
                                req = returned_req;
                                // loop back to reopen + retry
                            }
                        }
                    }
                }
                tracing::info!("R503 sensor worker exiting");
            })
            .map_err(|e| anyhow::anyhow!("failed to spawn worker thread: {}", e))?;

        // Wait for open() to complete.
        match open_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(anyhow::anyhow!("sensor open failed: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("sensor worker dropped before signalling open")),
        }

        let actor = SensorActor {
            tx: req_tx,
            initial_info: Arc::new(OnceCell::new()),
        };
        // Probe info once for capacity etc.
        let info = actor.info().await.map_err(|e| anyhow::anyhow!("initial info failed: {}", e))?;
        actor.initial_info.set(info).ok();
        Ok(actor)
    }

    fn handle_request(sensor: &mut R503, req: SensorRequest) -> HandleOutcome {
        // Reset the progress callback to a no-op default; per-op overrides
        // happen just below for the multi-step ops.
        sensor.set_progress(|msg: &str| tracing::trace!(progress = msg));

        // Install a progress callback derived from a clone of the per-request
        // sender, so that on retry (after re-open) we can install a fresh one.
        fn install_progress(sensor: &mut R503, progress: &Option<ProgressTx>) {
            if let Some(tx) = progress {
                let tx = tx.clone();
                sensor.set_progress(move |msg: &str| {
                    let _ = tx.send(msg.to_string());
                });
            }
        }

        match req {
            SensorRequest::Info(done) => {
                let result = sensor.info();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Info(done));
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Enroll { slot, progress, done } => {
                install_progress(sensor, &progress);
                let result = sensor.enroll(slot);
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Enroll {
                        slot,
                        progress,
                        done,
                    });
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Verify { progress, done } => {
                install_progress(sensor, &progress);
                let result = sensor.verify();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Verify {
                        progress,
                        done,
                    });
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Identify { progress, done } => {
                install_progress(sensor, &progress);
                let result = sensor.identify();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Identify {
                        progress,
                        done,
                    });
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Delete { slot, done } => {
                let result = sensor.delete(slot);
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Delete { slot, done });
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Clear(done) => {
                let result = sensor.clear();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Clear(done));
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Wake(done) => {
                let result = sensor.wake();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Wake(done));
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::Ping(done) => {
                let result = sensor.ping();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::Ping(done));
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
            SensorRequest::LedOff(done) => {
                let result = sensor.led_off();
                if matches!(&result, Err(e) if is_fatal_io(e)) {
                    return HandleOutcome::NeedsReopen(SensorRequest::LedOff(done));
                }
                let _ = done.send(result);
                HandleOutcome::Done
            }
        }
    }

    /// Fan a single error out to whichever oneshot is in the variant. Used when
    /// the sensor is unavailable and we need to reject an incoming request
    /// without serving it.
    fn respond_with_error(req: SensorRequest, err: SensorError) {
        // SensorError isn't Clone, so we need to construct a fresh error per
        // variant. We forward the original via `to_string()` wrapped in a
        // synthetic Io error so the client sees a consistent shape.
        fn dup(e: &SensorError) -> SensorError {
            SensorError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                e.to_string(),
            ))
        }
        match req {
            SensorRequest::Info(done) => {
                let _ = done.send(Err(err));
            }
            SensorRequest::Enroll { done, .. } => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::Verify { done, .. } => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::Identify { done, .. } => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::Delete { done, .. } => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::Clear(done) => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::Wake(done) => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::Ping(done) => {
                let _ = done.send(Err(dup(&err)));
            }
            SensorRequest::LedOff(done) => {
                let _ = done.send(Err(dup(&err)));
            }
        }
    }

    fn send(&self, req: SensorRequest) -> Result<(), SensorError> {
        self.tx.send(req).map_err(|_| {
            SensorError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "sensor worker is gone",
            ))
        })
    }

    pub fn cached_info(&self) -> Option<&SensorInfo> {
        self.initial_info.get()
    }

    pub async fn info(&self) -> Result<SensorInfo, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Info(tx))?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    pub async fn enroll(&self, slot: u8, progress: Option<ProgressTx>) -> Result<u8, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Enroll { slot, progress, done: tx })?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    pub async fn verify(&self, progress: Option<ProgressTx>) -> Result<MatchResult, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Verify { progress, done: tx })?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    #[allow(dead_code)]
    pub async fn identify(&self, progress: Option<ProgressTx>) -> Result<MatchResult, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Identify { progress, done: tx })?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    pub async fn delete(&self, slot: u8) -> Result<u8, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Delete { slot, done: tx })?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    #[allow(dead_code)]
    pub async fn clear(&self) -> Result<(), SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Clear(tx))?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    #[allow(dead_code)]
    pub async fn wake(&self) -> Result<bool, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Wake(tx))?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    #[allow(dead_code)]
    pub async fn ping(&self) -> Result<bool, SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::Ping(tx))?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }

    #[allow(dead_code)]
    pub async fn led_off(&self) -> Result<(), SensorError> {
        let (tx, rx) = oneshot::channel();
        self.send(SensorRequest::LedOff(tx))?;
        rx.await.map_err(|_| SensorError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sensor worker gone")))?
    }
}
