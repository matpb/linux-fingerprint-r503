//! r503d — fprintd-replacement daemon for the R503 fingerprint reader over
//! USB-serial. Owns `net.reactivated.Fprint` on the system bus (or session bus
//! when `--session` is passed for dev). PAM, fprintd-{enroll,verify}, KDE and
//! SDDM see this daemon as if it were upstream fprintd.

mod auth;
mod crypto;
mod dbus_iface;
mod error;
mod framing;
mod keystore;
mod pairing;
mod sensor;
mod sensor_actor;
mod state;
mod storage;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

use crate::dbus_iface::{Device, Manager, DEVICE_PATH, MANAGER_PATH};
use crate::sensor_actor::SensorActor;
use crate::storage::Storage;

const BUS_NAME: &str = "net.reactivated.Fprint";

const DEFAULT_CONFIDENCE_THRESHOLD: u16 = 50;

#[derive(Parser, Debug)]
#[command(name = "r503d", about = "R503 fprintd-replacement daemon")]
struct Args {
    /// Own the bus name on the SESSION bus (dev / testing). Default is system bus.
    #[arg(long)]
    session: bool,

    /// Serial port for the R503. Auto-detects /dev/ttyACM* | /dev/ttyUSB* if omitted.
    #[arg(long)]
    port: Option<String>,

    /// Path to the per-user slot mapping file.
    /// Default: /var/lib/r503d/users.json (system) or
    /// $XDG_STATE_HOME/r503d/users.json (session).
    #[arg(long)]
    storage: Option<PathBuf>,

    /// Minimum match confidence to accept (R503 returns 0-1000-ish).
    #[arg(long, default_value_t = DEFAULT_CONFIDENCE_THRESHOLD)]
    confidence: u16,

    /// One-shot: pair an unpaired Nano. Requires /etc/r503d/allow-pair (SPEC §13.5).
    /// Stop the daemon first: `systemctl stop r503d && r503d --pair`.
    #[arg(long, conflicts_with_all = ["unpair", "status"])]
    pair: bool,

    /// One-shot: wipe pairing from the Nano + host (key rotation / decommission).
    #[arg(long, conflicts_with_all = ["pair", "status"])]
    unpair: bool,

    /// One-shot: print pairing state from both sides without mutating.
    #[arg(long, conflicts_with_all = ["pair", "unpair"])]
    status: bool,
}

fn default_storage_path(session: bool) -> PathBuf {
    if session {
        let xdg_state = std::env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                PathBuf::from(home).join(".local").join("state")
            });
        xdg_state.join("r503d").join("users.json")
    } else {
        PathBuf::from("/var/lib/r503d/users.json")
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,r503d=debug")),
        )
        .init();

    // One-shot pairing flows exit before any daemon setup.
    if args.status {
        return pairing::run_status(args.port.as_deref());
    }
    if args.pair {
        return pairing::run_pair(args.port.as_deref());
    }
    if args.unpair {
        return pairing::run_unpair(args.port.as_deref());
    }

    let storage_path = args
        .storage
        .clone()
        .unwrap_or_else(|| default_storage_path(args.session));

    tracing::info!(
        port = ?args.port,
        storage = %storage_path.display(),
        bus = if args.session { "session" } else { "system" },
        "r503d starting"
    );

    // Load host-side key (if paired). Mismatch (key without paired Nano, or
    // vice versa) is surfaced after the sensor opens and we can compare states.
    let auth_key = keystore::load_key();
    if auth_key.is_some() {
        tracing::info!(
            key_path = keystore::KEY_PATH,
            "v2 auth key loaded — sensor will use authenticated channel"
        );
    } else {
        tracing::info!("no v2 auth key found — sensor will use plain v1 protocol");
    }

    // Open the sensor first — fail fast if the Uno isn't plugged in.
    let sensor = SensorActor::spawn(args.port.clone(), auth_key)
        .await
        .context("opening R503 sensor")?;

    let info = sensor
        .cached_info()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("sensor info unavailable after open"))?;
    tracing::info!(
        fw = %info.fw,
        capacity = info.capacity,
        enrolled = info.enrolled,
        "sensor ready"
    );

    // Open storage, sized for actual sensor capacity.
    let storage = Storage::open(storage_path.clone(), info.capacity)
        .await
        .context("opening storage")?;

    let device = Device::new(sensor, storage, args.confidence);

    let builder = if args.session {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    let conn = builder
        .name(BUS_NAME)?
        .serve_at(MANAGER_PATH, Manager)?
        .serve_at(DEVICE_PATH, device)?
        .build()
        .await
        .context("connecting to D-Bus and registering objects")?;

    spawn_disconnect_watcher(conn.clone()).await?;

    tracing::info!(
        bus = if args.session { "session" } else { "system" },
        name = BUS_NAME,
        manager = MANAGER_PATH,
        device = DEVICE_PATH,
        "r503d ready"
    );

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received, shutting down"),
        _ = sigint.recv() => tracing::info!("SIGINT received, shutting down"),
    }
    Ok(())
}

/// Watch for clients disconnecting from the bus and auto-release their claim
/// on the device if they were holding one. Without this, a crashed pam_fprintd
/// or fprintd-verify leaves the device permanently AlreadyInUse.
async fn spawn_disconnect_watcher(conn: zbus::Connection) -> anyhow::Result<()> {
    use futures_util::StreamExt;

    let dbus_proxy = zbus::fdo::DBusProxy::new(&conn)
        .await
        .context("creating DBusProxy for NameOwnerChanged watcher")?;
    let mut stream = dbus_proxy
        .receive_name_owner_changed()
        .await
        .context("subscribing to NameOwnerChanged")?;

    tokio::spawn(async move {
        while let Some(signal) = stream.next().await {
            let args = match signal.args() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!("NameOwnerChanged unpack failed: {}", e);
                    continue;
                }
            };
            // A client disconnecting = old_owner populated, new_owner empty.
            // Also only unique names (start with ':') — well-known name changes
            // aren't claims we care about.
            let name = args.name.as_str();
            if !name.starts_with(':') {
                continue;
            }
            let old_owner = args
                .old_owner
                .as_ref()
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("");
            let new_owner = args
                .new_owner
                .as_ref()
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("");
            if old_owner.is_empty() || !new_owner.is_empty() {
                continue;
            }
            // Someone dropped — look up the Device and offer them a chance
            // to release their claim.
            let object_server = conn.object_server();
            if let Ok(iface_ref) = object_server
                .interface::<_, crate::dbus_iface::Device>(DEVICE_PATH)
                .await
            {
                iface_ref.get().await.handle_client_disconnect(name).await;
            }
        }
    });

    Ok(())
}
