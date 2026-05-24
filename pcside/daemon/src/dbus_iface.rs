//! zbus interfaces for net.reactivated.Fprint.{Manager,Device}.
//!
//! Implements the same wire surface as upstream fprintd; pam_fprintd can't
//! tell the difference. See /tmp/fprintd/src/net.reactivated.Fprint.*.xml
//! for the canonical interface descriptions.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

use crate::error::FprintError;
use crate::sensor::{MatchResult, SensorError};
use crate::sensor_actor::SensorActor;
use crate::storage::Storage;

pub const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
pub const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

pub const MANAGER_INTERFACE: &str = "net.reactivated.Fprint.Manager";
pub const DEVICE_INTERFACE: &str = "net.reactivated.Fprint.Device";

/// All valid fingerprint names per the fprintd spec.
const FINGER_NAMES: &[&str] = &[
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];

fn validate_finger(name: &str, allow_any: bool) -> Result<(), FprintError> {
    if allow_any && name == "any" {
        return Ok(());
    }
    if FINGER_NAMES.contains(&name) {
        Ok(())
    } else {
        Err(FprintError::InvalidFingername(name.to_string()))
    }
}

fn effective_user() -> String {
    // Fall back to the current uid's name. With polkit later we'll resolve the
    // caller's uid instead.
    let uid = unsafe { libc::getuid() };
    pwd_lookup(uid).unwrap_or_else(|| uid.to_string())
}

/// Cheap getpwuid_r without pulling in the `nix` crate. Returns the username
/// for the given uid, or None on failure.
fn pwd_lookup(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;
    use std::ptr;
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = ptr::null_mut();
        let mut buf = MaybeUninit::<[libc::c_char; 1024]>::uninit();
        let rc = libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            1024,
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return None;
        }
        let name = CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned();
        Some(name)
    }
}

// ============================================================================
// Manager
// ============================================================================

pub struct Manager;

#[zbus::interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    /// Enumerate the fingerprint readers attached to the system. We always
    /// expose exactly one (the R503).
    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![OwnedObjectPath::try_from(DEVICE_PATH).unwrap()]
    }

    /// The default reader is our only reader.
    async fn get_default_device(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from(DEVICE_PATH).unwrap()
    }
}

// ============================================================================
// Device
// ============================================================================

#[derive(Debug, Default)]
struct DeviceState {
    /// Effective username that currently owns the device, or None when free.
    claimed_by: Option<String>,
    /// D-Bus unique name of the claimer so Release/VerifyStart can verify it.
    claim_sender: Option<String>,
    /// "enroll" | "verify" | None.
    action_in_progress: Option<&'static str>,
    finger_present: bool,
    finger_needed: bool,
}

pub struct Device {
    pub sensor: SensorActor,
    pub storage: Storage,
    pub confidence_threshold: u16,
    state: Arc<Mutex<DeviceState>>,
}

impl Device {
    pub fn new(sensor: SensorActor, storage: Storage, confidence_threshold: u16) -> Self {
        Device {
            sensor,
            storage,
            confidence_threshold,
            state: Arc::new(Mutex::new(DeviceState::default())),
        }
    }

    async fn ensure_claim(&self, sender: Option<&str>) -> Result<String, FprintError> {
        let state = self.state.lock().await;
        let user = state
            .claimed_by
            .as_ref()
            .ok_or_else(|| FprintError::ClaimDevice("device not claimed".into()))?;
        if let (Some(s), Some(claim_s)) = (sender, state.claim_sender.as_deref()) {
            if s != claim_s {
                return Err(FprintError::ClaimDevice(
                    "device claimed by a different sender".into(),
                ));
            }
        }
        Ok(user.clone())
    }

    /// Called by the NameOwnerChanged watcher when a bus client disappears.
    /// If they were holding the claim, release it so the next client can claim.
    /// Mirrors fprintd's behavior — without this, a crashed pam_fprintd or
    /// fprintd-verify leaves the device wedged until daemon restart.
    pub async fn handle_client_disconnect(&self, unique_name: &str) {
        let mut state = self.state.lock().await;
        if state.claim_sender.as_deref() == Some(unique_name) {
            tracing::info!(
                user = ?state.claimed_by,
                sender = unique_name,
                "claimer disconnected — auto-releasing device"
            );
            state.claimed_by = None;
            state.claim_sender = None;
            state.action_in_progress = None;
        }
    }
}

#[zbus::interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    // ----- Properties -----

    #[zbus(property, name = "name")]
    async fn name(&self) -> String {
        "R503 fingerprint reader".to_string()
    }

    #[zbus(property, name = "num-enroll-stages")]
    async fn num_enroll_stages(&self) -> i32 {
        // R503 firmware takes exactly two finger placements per template
        // (capture + verify-and-merge). See firmware/r503fp/r503fp.ino enroll().
        2
    }

    #[zbus(property, name = "scan-type")]
    async fn scan_type(&self) -> String {
        "press".to_string()
    }

    #[zbus(property, name = "finger-present")]
    async fn finger_present(&self) -> bool {
        self.state.lock().await.finger_present
    }

    #[zbus(property, name = "finger-needed")]
    async fn finger_needed(&self) -> bool {
        self.state.lock().await.finger_needed
    }

    // ----- Methods -----

    async fn list_enrolled_fingers(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        username: String,
    ) -> Result<Vec<String>, FprintError> {
        // Empty username = "the caller themselves". Fall back to the currently
        // claimed user, otherwise to the daemon process owner (which is mat on
        // the session bus / root on the system bus). pam_fprintd always passes
        // an explicit username, so this only matters for fprintd-list and
        // direct gdbus testing.
        let user = if username.is_empty() {
            self.state
                .lock()
                .await
                .claimed_by
                .clone()
                .unwrap_or_else(effective_user)
        } else {
            username
        };
        let fingers = self.storage.list_fingers(&user).await;
        if fingers.is_empty() {
            return Err(FprintError::NoEnrolledPrints(format!(
                "no enrolled prints for {}",
                user
            )));
        }
        Ok(fingers)
    }

    async fn delete_enrolled_fingers(&self, username: String) -> Result<(), FprintError> {
        let slots = self.storage.remove_user(&username).await?;
        for s in slots {
            if let Err(e) = self.sensor.delete(s).await {
                tracing::warn!("sensor delete slot {} failed: {}", s, e);
            }
        }
        Ok(())
    }

    #[zbus(name = "DeleteEnrolledFingers2")]
    async fn delete_enrolled_fingers2(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = header.sender().map(|s| s.to_string());
        let user = self.ensure_claim(sender.as_deref()).await?;
        let slots = self.storage.remove_user(&user).await?;
        for s in slots {
            if let Err(e) = self.sensor.delete(s).await {
                tracing::warn!("sensor delete slot {} failed: {}", s, e);
            }
        }
        Ok(())
    }

    async fn delete_enrolled_finger(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        finger_name: String,
    ) -> Result<(), FprintError> {
        validate_finger(&finger_name, false)?;
        let sender = header.sender().map(|s| s.to_string());
        let user = self.ensure_claim(sender.as_deref()).await?;
        let slot = self
            .storage
            .remove_finger(&user, &finger_name)
            .await?
            .ok_or_else(|| {
                FprintError::NoEnrolledPrints(format!(
                    "{} not enrolled for {}",
                    finger_name, user
                ))
            })?;
        if let Err(e) = self.sensor.delete(slot).await {
            tracing::warn!("sensor delete slot {} failed: {}", slot, e);
        }
        Ok(())
    }

    async fn claim(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        username: String,
    ) -> Result<(), FprintError> {
        let mut state = self.state.lock().await;
        if let Some(existing) = &state.claimed_by {
            return Err(FprintError::AlreadyInUse(format!(
                "already claimed by {}",
                existing
            )));
        }
        let sender = header.sender().map(|s| s.to_string());
        let user = if username.is_empty() {
            sender.clone().unwrap_or_else(effective_user)
        } else {
            username
        };
        tracing::info!(user = %user, sender = ?sender, "Device claimed");
        state.claimed_by = Some(user);
        state.claim_sender = sender;
        Ok(())
    }

    async fn release(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = header.sender().map(|s| s.to_string());
        let mut state = self.state.lock().await;
        if state.claimed_by.is_none() {
            return Err(FprintError::ClaimDevice("device not claimed".into()));
        }
        if let (Some(s), Some(claim_s)) = (sender.as_deref(), state.claim_sender.as_deref()) {
            if s != claim_s {
                return Err(FprintError::ClaimDevice(
                    "claimed by a different sender".into(),
                ));
            }
        }
        tracing::info!(user = ?state.claimed_by, "Device released");
        state.claimed_by = None;
        state.claim_sender = None;
        state.action_in_progress = None;
        Ok(())
    }

    async fn verify_start(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: String,
    ) -> Result<(), FprintError> {
        validate_finger(&finger_name, true)?;
        let sender = header.sender().map(|s| s.to_string());
        let user = self.ensure_claim(sender.as_deref()).await?;

        {
            let mut state = self.state.lock().await;
            if let Some(action) = state.action_in_progress {
                return Err(FprintError::AlreadyInUse(format!(
                    "{} already in progress",
                    action
                )));
            }
            state.action_in_progress = Some("verify");
        }

        let user_slots = self.storage.get_user_slots(&user).await;
        if user_slots.is_empty() {
            self.state.lock().await.action_in_progress = None;
            return Err(FprintError::NoEnrolledPrints(format!(
                "no enrolled prints for {}",
                user
            )));
        }

        let (selected, expected_slots): (String, HashSet<u8>) = if finger_name == "any" {
            let first = user_slots.keys().next().cloned().unwrap_or_default();
            (first, user_slots.values().copied().collect())
        } else {
            let slot = match user_slots.get(&finger_name) {
                Some(s) => *s,
                None => {
                    self.state.lock().await.action_in_progress = None;
                    return Err(FprintError::NoEnrolledPrints(format!(
                        "{} not enrolled for {}",
                        finger_name, user
                    )));
                }
            };
            let mut set = HashSet::new();
            set.insert(slot);
            (finger_name.clone(), set)
        };

        tracing::info!(user = %user, selected = %selected, expected = ?expected_slots, "VerifyStart");
        Device::verify_finger_selected(&emitter, &selected).await.ok();
        {
            let mut state = self.state.lock().await;
            state.finger_needed = true;
        }
        let owned_emitter = emitter.to_owned();

        let sensor = self.sensor.clone();
        let state = self.state.clone();
        let threshold = self.confidence_threshold;

        // Verify keeps capturing until match / no-match / external stop / hard
        // error. Firmware-side "ERR timeout" / "ERR poor_quality" / capture
        // failures become verify-retry-scan signals (done=false) and the worker
        // loops back to call sensor.verify() again.
        tokio::spawn(async move {
            let final_status: &'static str = loop {
                // Bail if VerifyStop was called externally.
                if state.lock().await.action_in_progress != Some("verify") {
                    break "verify-disconnected";
                }
                let result = sensor.verify(None).await;
                match result {
                    Ok(MatchResult { slot, confidence }) => {
                        let accepted = expected_slots.contains(&slot)
                            && confidence >= threshold;
                        let status = if accepted { "verify-match" } else { "verify-no-match" };
                        tracing::info!(slot, confidence, accepted, "verify done");
                        break status;
                    }
                    Err(SensorError::Command { code, detail }) => {
                        let code_low = code.to_lowercase();
                        // Firmware vocab: no_match (final), timeout / poor_quality /
                        // capture_failed=N / image2tz_failed=N (retry).
                        if code_low == "no_match" {
                            break "verify-no-match";
                        }
                        if code_low == "timeout"
                            || code_low == "poor_quality"
                            || code_low.starts_with("capture_failed")
                            || code_low.starts_with("image2tz_failed")
                        {
                            tracing::debug!("verify retry (firmware {} {:?})", code, detail);
                            Device::verify_status(&owned_emitter, "verify-retry-scan", false)
                                .await
                                .ok();
                            // Small backoff so we don't busy-loop on sensor_unreachable etc.
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                        tracing::warn!("verify err: {} {:?}", code, detail);
                        break "verify-unknown-error";
                    }
                    Err(SensorError::Timeout(_)) => {
                        // Rust-side timeout (shouldn't normally fire — the firmware's
                        // 10s capture timeout is < our 15s execute timeout).
                        Device::verify_status(&owned_emitter, "verify-retry-scan", false)
                            .await
                            .ok();
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("verify unexpected error: {}", e);
                        break "verify-unknown-error";
                    }
                }
            };
            {
                let mut s = state.lock().await;
                s.finger_needed = false;
                s.finger_present = false;
                s.action_in_progress = None;
            }
            if let Err(e) = Device::verify_status(&owned_emitter, final_status, true).await {
                tracing::warn!("emit final VerifyStatus failed: {}", e);
            }
        });

        Ok(())
    }

    async fn verify_stop(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = header.sender().map(|s| s.to_string());
        let _user = self.ensure_claim(sender.as_deref()).await?;
        let mut state = self.state.lock().await;
        if state.action_in_progress != Some("verify") {
            return Err(FprintError::NoActionInProgress("no verify in progress".into()));
        }
        state.action_in_progress = None;
        Ok(())
    }

    async fn enroll_start(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: String,
    ) -> Result<(), FprintError> {
        validate_finger(&finger_name, false)?;
        let sender = header.sender().map(|s| s.to_string());
        let user = self.ensure_claim(sender.as_deref()).await?;
        {
            let mut state = self.state.lock().await;
            if let Some(action) = state.action_in_progress {
                return Err(FprintError::AlreadyInUse(format!(
                    "{} already in progress",
                    action
                )));
            }
            state.action_in_progress = Some("enroll");
        }

        // If already enrolled, free the old slot first.
        if let Some(existing) = self.storage.get_slot(&user, &finger_name).await {
            tracing::info!(user = %user, finger = %finger_name, slot = existing, "re-enrolling, freeing old slot");
            if let Err(e) = self.sensor.delete(existing).await {
                tracing::warn!("delete old slot failed: {}", e);
            }
            self.storage.remove_finger(&user, &finger_name).await?;
        }

        let slot = self.storage.allocate_slot().await?;
        tracing::info!(user = %user, finger = %finger_name, slot, "EnrollStart");
        {
            let mut state = self.state.lock().await;
            state.finger_needed = true;
        }
        let owned_emitter = emitter.to_owned();

        // Channel for progress lines from the sensor worker.
        let (prog_tx, mut prog_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let progress_emitter = owned_emitter.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(msg) = prog_rx.recv().await {
                tracing::debug!(progress = %msg, "enroll progress");
                let low = msg.to_lowercase();
                // Firmware emits: "place_finger", "remove_finger", "place_again".
                // fprintd consumers expect enroll-stage-passed between captures.
                if low.contains("remove_finger") || low.contains("remove finger") {
                    Device::enroll_status(&progress_emitter, "enroll-stage-passed", false)
                        .await
                        .ok();
                }
            }
        });

        let sensor = self.sensor.clone();
        let storage = self.storage.clone();
        let state = self.state.clone();
        let user_for_task = user.clone();
        let finger_for_task = finger_name.clone();
        tokio::spawn(async move {
            let result = sensor.enroll(slot, Some(prog_tx)).await;
            progress_handle.abort();
            {
                let mut s = state.lock().await;
                s.finger_needed = false;
                s.finger_present = false;
                s.action_in_progress = None;
            }
            match result {
                Ok(_actual_slot) => {
                    if let Err(e) = storage
                        .set_slot(&user_for_task, &finger_for_task, slot)
                        .await
                    {
                        tracing::warn!("storage write failed: {}", e);
                        Device::enroll_status(&owned_emitter, "enroll-failed", true)
                            .await
                            .ok();
                        return;
                    }
                    tracing::info!(user = %user_for_task, finger = %finger_for_task, slot, "enroll COMPLETE");
                    Device::enroll_status(&owned_emitter, "enroll-completed", true)
                        .await
                        .ok();
                }
                Err(e) => {
                    tracing::warn!("enroll error: {}", e);
                    Device::enroll_status(&owned_emitter, "enroll-failed", true)
                        .await
                        .ok();
                }
            }
        });

        Ok(())
    }

    async fn enroll_stop(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = header.sender().map(|s| s.to_string());
        let _user = self.ensure_claim(sender.as_deref()).await?;
        let mut state = self.state.lock().await;
        if state.action_in_progress != Some("enroll") {
            return Err(FprintError::NoActionInProgress("no enroll in progress".into()));
        }
        state.action_in_progress = None;
        Ok(())
    }

    // ----- Signals -----

    #[zbus(signal)]
    async fn verify_finger_selected(
        emitter: &SignalEmitter<'_>,
        finger_name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn enroll_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;
}

// NOTE: We currently do NOT emit PropertiesChanged for finger-present /
// finger-needed. pam_fprintd drives off the VerifyStatus / EnrollStatus
// signals (and the GUI fprintd consumers that watch finger-present mostly
// just animate a UI hint). If a frontend turns out to need it, hook the
// zbus-generated `<name>_changed(&self, emitter)` helpers here.
