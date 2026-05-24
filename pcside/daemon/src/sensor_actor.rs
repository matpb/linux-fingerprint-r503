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

#[derive(Clone)]
pub struct SensorActor {
    tx: mpsc::UnboundedSender<SensorRequest>,
    initial_info: Arc<OnceCell<SensorInfo>>,
}

impl SensorActor {
    /// Open the sensor on the given port (or auto-detect), spawn the worker,
    /// probe `info()` once for capacity caching. Returns once the sensor is
    /// fully open and responsive.
    pub async fn spawn(port: Option<String>) -> anyhow::Result<Self> {
        let (req_tx, mut req_rx) = mpsc::unbounded_channel::<SensorRequest>();
        let (open_tx, open_rx) = oneshot::channel::<Result<(), SensorError>>();

        // Worker thread — owns the R503 forever.
        std::thread::Builder::new()
            .name("r503-worker".into())
            .spawn(move || {
                let sensor_result = R503::open(port.as_deref(), Duration::from_secs(8));
                let mut sensor = match sensor_result {
                    Ok(s) => {
                        let _ = open_tx.send(Ok(()));
                        s
                    }
                    Err(e) => {
                        let _ = open_tx.send(Err(e));
                        return;
                    }
                };
                tracing::info!(port = sensor.port_path(), "R503 sensor open");

                while let Some(req) = req_rx.blocking_recv() {
                    Self::handle_request(&mut sensor, req);
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

    fn handle_request(sensor: &mut R503, req: SensorRequest) {
        // Reset the progress callback to a no-op default; per-op overrides
        // happen just below for the multi-step ops.
        sensor.set_progress(|msg: &str| tracing::trace!(progress = msg));
        match req {
            SensorRequest::Info(done) => {
                let _ = done.send(sensor.info());
            }
            SensorRequest::Enroll { slot, progress, done } => {
                if let Some(tx) = progress {
                    sensor.set_progress(move |msg: &str| {
                        let _ = tx.send(msg.to_string());
                    });
                }
                let _ = done.send(sensor.enroll(slot));
            }
            SensorRequest::Verify { progress, done } => {
                if let Some(tx) = progress {
                    sensor.set_progress(move |msg: &str| {
                        let _ = tx.send(msg.to_string());
                    });
                }
                let _ = done.send(sensor.verify());
            }
            SensorRequest::Identify { progress, done } => {
                if let Some(tx) = progress {
                    sensor.set_progress(move |msg: &str| {
                        let _ = tx.send(msg.to_string());
                    });
                }
                let _ = done.send(sensor.identify());
            }
            SensorRequest::Delete { slot, done } => {
                let _ = done.send(sensor.delete(slot));
            }
            SensorRequest::Clear(done) => {
                let _ = done.send(sensor.clear());
            }
            SensorRequest::Wake(done) => {
                let _ = done.send(sensor.wake());
            }
            SensorRequest::Ping(done) => {
                let _ = done.send(sensor.ping());
            }
            SensorRequest::LedOff(done) => {
                let _ = done.send(sensor.led_off());
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
