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
use crate::storage::{Storage, StorageError};

pub const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
pub const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

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

/// Update the polled `finger-present` / `finger-needed` properties from a
/// firmware PROGRESS line. Best-effort hint for GUI clients that poll those
/// properties — we don't emit PropertiesChanged, so transient state is only
/// observable to actively-polling consumers.
///
/// Firmware vocabulary (`firmware/r503fp/r503fp.ino`):
///   - "place_finger" / "place_again": sensor is waiting for a touch.
///   - "remove_finger": a capture just succeeded, sensor is waiting for the
///     finger to be lifted before the next stage (enroll only).
async fn update_finger_state_from_progress(
    state: &std::sync::Arc<tokio::sync::Mutex<DeviceState>>,
    msg: &str,
) {
    let low = msg.to_lowercase();
    let mut s = state.lock().await;
    if low.contains("place_finger") || low.contains("place_again") {
        s.finger_needed = true;
        s.finger_present = false;
    } else if low.contains("remove_finger") || low.contains("remove finger") {
        // Capture just finished; finger is still on the sensor until lifted.
        s.finger_needed = false;
        s.finger_present = true;
    }
}

/// Wipe every (finger, slot) pair for a user. Deletes from sensor flash FIRST,
/// then removes from the registry — and only the (finger, slot) pairs whose
/// sensor delete actually succeeded. Partial-success returns a PrintsNotDeleted
/// listing every slot that still lives in flash, so a caller can retry and the
/// surviving registry rows still authenticate against their templates.
async fn delete_user_fingers(
    sensor: &crate::sensor_actor::SensorActor,
    storage: &crate::storage::Storage,
    user: &str,
) -> Result<(), FprintError> {
    let entries = storage.get_user_slots(user).await;
    if entries.is_empty() {
        return Ok(());
    }
    let mut errors: Vec<String> = Vec::new();
    let mut succeeded: Vec<String> = Vec::new();
    for (finger, slot) in entries {
        match sensor.delete(slot).await {
            Ok(_) => succeeded.push(finger),
            Err(e) => {
                tracing::warn!("sensor delete slot {} ({}) failed: {}", slot, finger, e);
                errors.push(format!("{} (slot {}): {}", finger, slot, e));
            }
        }
    }
    for finger in &succeeded {
        if let Err(e) = storage.remove_finger(user, finger).await {
            tracing::warn!(
                "registry remove {} failed after sensor delete: {}",
                finger,
                e
            );
            errors.push(format!("{} (registry write): {}", finger, e));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(FprintError::PrintsNotDeleted(format!(
            "partial delete: {}",
            errors.join("; ")
        )))
    }
}

/// Cheap getpwuid_r without pulling in the `nix` crate. Returns the username
/// for the given uid, or None on failure. Crate-visible so `auth.rs` can
/// resolve the caller without a second helper.
pub(crate) fn pwd_lookup(uid: u32) -> Option<String> {
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
    /// Current in-flight action, if any. `epoch` distinguishes successive
    /// enroll/verify operations of the SAME kind so an abandoned task can't
    /// stomp the successor's state at cleanup time.
    action: Option<ActionToken>,
    /// Monotonic counter to mint fresh epoch ids.
    next_epoch: u64,
    finger_present: bool,
    finger_needed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActionToken {
    kind: ActionKind,
    epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    Enroll,
    Verify,
}

impl ActionKind {
    fn as_str(self) -> &'static str {
        match self {
            ActionKind::Enroll => "enroll",
            ActionKind::Verify => "verify",
        }
    }
}

impl DeviceState {
    /// Mint a fresh ActionToken for a new operation and install it. Caller is
    /// responsible for having already verified `self.action.is_none()`.
    fn start_action(&mut self, kind: ActionKind) -> ActionToken {
        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let token = ActionToken { kind, epoch };
        self.action = Some(token);
        token
    }

    /// Clear the action slot AND finger-* hints, but ONLY if `expected` still
    /// owns the slot. Returns whether the clear happened — task cleanup uses
    /// this to decide whether to emit a terminal status signal.
    fn end_action_if_owner(&mut self, expected: ActionToken) -> bool {
        if self.action == Some(expected) {
            self.action = None;
            self.finger_needed = false;
            self.finger_present = false;
            true
        } else {
            false
        }
    }
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
        if let (Some(s), Some(claim_s)) = (sender, state.claim_sender.as_deref())
            && s != claim_s
        {
            return Err(FprintError::ClaimDevice(
                "device claimed by a different sender".into(),
            ));
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
            state.action = None;
            state.finger_needed = false;
            state.finger_present = false;
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
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: String,
    ) -> Result<Vec<String>, FprintError> {
        // `auth::authorize_username` handles the fprintd empty-string
        // convention, the self-request fast path, the uid-0 (PAM) fast path,
        // and falls through to polkit for cross-user requests. Without this
        // gate, any local user could enumerate any other user's fingers
        // (see SECURITY_HARDENING_PLAN.md §P0-3).
        let sender = header.sender().map(|s| s.to_string());
        let user = crate::auth::authorize_username(conn, sender.as_deref(), &username).await?;
        let fingers = self.storage.list_fingers(&user).await;
        if fingers.is_empty() {
            return Err(FprintError::NoEnrolledPrints(format!(
                "no enrolled prints for {}",
                user
            )));
        }
        Ok(fingers)
    }

    async fn delete_enrolled_fingers(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: String,
    ) -> Result<(), FprintError> {
        // Authorize before nuking anything. Pre-fix, any local user could
        // wipe `root`'s enrollment without a claim (SECURITY_HARDENING_PLAN.md
        // §P0-2). The `DeleteEnrolledFingers2` variant below is claim-gated,
        // but this legacy entry point is still exposed for upstream parity.
        let sender = header.sender().map(|s| s.to_string());
        let user = crate::auth::authorize_username(conn, sender.as_deref(), &username).await?;
        delete_user_fingers(&self.sensor, &self.storage, &user).await
    }

    #[zbus(name = "DeleteEnrolledFingers2")]
    async fn delete_enrolled_fingers2(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = header.sender().map(|s| s.to_string());
        let user = self.ensure_claim(sender.as_deref()).await?;
        delete_user_fingers(&self.sensor, &self.storage, &user).await
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
            .get_slot(&user, &finger_name)
            .await
            .ok_or_else(|| {
                FprintError::NoEnrolledPrints(format!("{} not enrolled for {}", finger_name, user))
            })?;
        if let Err(e) = self.sensor.delete(slot).await {
            tracing::warn!("sensor delete slot {} failed: {}", slot, e);
            return Err(FprintError::PrintsNotDeleted(format!(
                "sensor delete failed for slot {}: {}",
                slot, e
            )));
        }
        // Sensor template gone; registry remove is the bookkeeping tail.
        self.storage.remove_finger(&user, &finger_name).await?;
        Ok(())
    }

    async fn claim(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: String,
    ) -> Result<(), FprintError> {
        let sender = header.sender().map(|s| s.to_string());
        // The claim is the gate that everything else hangs off — once it's
        // uid-bound, `enroll_start` / `verify_start` / `delete_*2` inherit
        // the binding for free via `ensure_claim`. Pre-fix, a local user
        // could `Claim "root"` and then enroll their own finger under root's
        // identity (SECURITY_HARDENING_PLAN.md §P0-1).
        let user = crate::auth::authorize_username(conn, sender.as_deref(), &username).await?;
        let mut state = self.state.lock().await;
        // Single-user pragma: if the device is already claimed for the SAME
        // user and no operation is in flight, allow the new caller to take
        // over. Without this, opening KDE Settings (which claims and holds
        // the device for the lifetime of the dialog) blocks every CLI
        // fprintd-verify/sudo finger-auth from the same desktop session
        // until the dialog is closed. A different-user claim, or an
        // in-flight enroll/verify, still fails AlreadyInUse.
        if let Some(existing) = &state.claimed_by {
            if existing != &user {
                return Err(FprintError::AlreadyInUse(format!(
                    "already claimed by {}",
                    existing
                )));
            }
            if let Some(action) = state.action {
                return Err(FprintError::AlreadyInUse(format!(
                    "{} in progress for {}",
                    action.kind.as_str(),
                    existing
                )));
            }
            tracing::info!(user = %user, sender = ?sender, "Device re-claimed (same user, no op in flight)");
        } else {
            tracing::info!(user = %user, sender = ?sender, "Device claimed");
        }
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
        if let (Some(s), Some(claim_s)) = (sender.as_deref(), state.claim_sender.as_deref())
            && s != claim_s
        {
            return Err(FprintError::ClaimDevice(
                "claimed by a different sender".into(),
            ));
        }
        tracing::info!(user = ?state.claimed_by, "Device released");
        state.claimed_by = None;
        state.claim_sender = None;
        state.action = None;
        state.finger_needed = false;
        state.finger_present = false;
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

        // Mint the action token AND snapshot the user's slots while holding the
        // SAME state-lock acquisition. Previously the token was minted under the
        // lock, the lock dropped, and get_user_slots() read afterwards — leaving
        // a window in which a same-sender DeleteEnrolledFinger (which is not
        // action-gated) could mutate the slot set between mint and read. The
        // race was bounded by ensure_claim (no cross-user privesc; worst case a
        // verify that naturally fails), but reading the slots under the lock
        // closes it outright. get_user_slots only touches the independent
        // storage RwLock, so holding the state mutex across it is deadlock-free
        // (nothing acquires storage-then-state). (Audit 2026-05-28 / L1.)
        let (my_token, user_slots) = {
            let mut state = self.state.lock().await;
            if let Some(t) = state.action {
                return Err(FprintError::AlreadyInUse(format!(
                    "{} already in progress",
                    t.kind.as_str()
                )));
            }
            let slots = self.storage.get_user_slots(&user).await;
            (state.start_action(ActionKind::Verify), slots)
        };

        // Build expected_slots + the name we'll advertise via VerifyFingerSelected.
        // For "any", we emit the literal "any" so the UI doesn't lie about which
        // finger the user must place. expected_slots is the union of every
        // enrolled slot, so a match on any of them succeeds.
        if user_slots.is_empty() {
            self.state.lock().await.end_action_if_owner(my_token);
            return Err(FprintError::NoEnrolledPrints(format!(
                "no enrolled prints for {}",
                user
            )));
        }
        let (selected, expected_slots): (String, HashSet<u8>) = if finger_name == "any" {
            ("any".to_string(), user_slots.values().copied().collect())
        } else {
            let slot = match user_slots.get(&finger_name) {
                Some(s) => *s,
                None => {
                    self.state.lock().await.end_action_if_owner(my_token);
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
        Device::verify_finger_selected(&emitter, &selected)
            .await
            .ok();
        {
            let mut state = self.state.lock().await;
            state.finger_needed = true;
            state.finger_present = false;
        }
        let owned_emitter = emitter.to_owned();

        let sensor = self.sensor.clone();
        let state = self.state.clone();
        let threshold = self.confidence_threshold;

        // Single task: drives the verify retry-loop AND processes PROGRESS
        // lines inline via select!, so there's no second receiver task to
        // leak and no abort-races-queued-message footgun.
        tokio::spawn(async move {
            let (prog_tx, mut prog_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

            // Retry budget (audit §P1-7 / §S4.2): the firmware-asks-retry
            // branch used to spin forever, letting an attacker hammer verify
            // with arbitrary finger pressure / coverage until they got a
            // match. Bound to 5 retries OR 30s, whichever comes first. A
            // real `no_match` from the firmware (the wrong-finger terminal
            // status) is not affected — it already breaks the loop below.
            const MAX_RETRIES: u32 = 5;
            const RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
            let started_at = std::time::Instant::now();
            let mut retries: u32 = 0;

            let final_status: Option<&'static str> = 'outer: loop {
                if state.lock().await.action != Some(my_token) {
                    tracing::info!("verify externally stopped");
                    break 'outer None;
                }
                let verify_fut = sensor.verify(Some(prog_tx.clone()));
                tokio::pin!(verify_fut);
                let result = loop {
                    tokio::select! {
                        biased;
                        Some(msg) = prog_rx.recv() => {
                            update_finger_state_from_progress(&state, &msg).await;
                        }
                        result = &mut verify_fut => break result,
                    }
                };
                match result {
                    Ok(MatchResult { slot, confidence }) => {
                        let accepted = expected_slots.contains(&slot) && confidence >= threshold;
                        let status = if accepted {
                            "verify-match"
                        } else {
                            "verify-no-match"
                        };
                        tracing::info!(slot, confidence, accepted, "verify done");
                        break 'outer Some(status);
                    }
                    Err(SensorError::Command { code, detail }) => {
                        let code_low = code.to_lowercase();
                        // Firmware vocab: no_match (final), timeout / poor_quality /
                        // capture_failed=N / image2tz_failed=N (retry).
                        if code_low == "no_match" {
                            break 'outer Some("verify-no-match");
                        }
                        if code_low == "timeout"
                            || code_low == "poor_quality"
                            || code_low.starts_with("capture_failed")
                            || code_low.starts_with("image2tz_failed")
                        {
                            if retries >= MAX_RETRIES || started_at.elapsed() > RETRY_BUDGET {
                                tracing::info!(
                                    retries,
                                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                                    "verify retry budget exhausted ({} {:?}); forcing no-match",
                                    code,
                                    detail
                                );
                                break 'outer Some("verify-no-match");
                            }
                            retries += 1;
                            tracing::debug!(
                                "verify retry {}/{} (firmware {} {:?})",
                                retries,
                                MAX_RETRIES,
                                code,
                                detail
                            );
                            Device::verify_status(&owned_emitter, "verify-retry-scan", false)
                                .await
                                .ok();
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                        tracing::warn!("verify err: {} {:?}", code, detail);
                        break 'outer Some("verify-unknown-error");
                    }
                    Err(SensorError::Timeout(_)) => {
                        // Rust-side timeout (shouldn't normally fire — the firmware's
                        // 10s capture timeout is < our 15s execute timeout). Counted
                        // against the same retry budget as firmware-retryables.
                        if retries >= MAX_RETRIES || started_at.elapsed() > RETRY_BUDGET {
                            tracing::info!(
                                retries,
                                elapsed_ms = started_at.elapsed().as_millis() as u64,
                                "verify retry budget exhausted (rust-side timeout); forcing no-match"
                            );
                            break 'outer Some("verify-no-match");
                        }
                        retries += 1;
                        Device::verify_status(&owned_emitter, "verify-retry-scan", false)
                            .await
                            .ok();
                        continue;
                    }
                    Err(e) => {
                        if crate::sensor_actor::is_fatal_io(&e) {
                            tracing::warn!("verify disconnected: {}", e);
                            break 'outer Some("verify-disconnected");
                        }
                        tracing::warn!("verify unexpected error: {}", e);
                        break 'outer Some("verify-unknown-error");
                    }
                }
            };

            // Drain any trailing PROGRESS lines so finger-* properties don't
            // settle on a stale value. Bounded by a short window because the
            // sensor actor's progress closure keeps our prog_tx clone alive
            // until the next sensor command replaces it.
            drop(prog_tx);
            let drain_deadline = tokio::time::sleep(std::time::Duration::from_millis(50));
            tokio::pin!(drain_deadline);
            loop {
                tokio::select! {
                    _ = &mut drain_deadline => break,
                    msg = prog_rx.recv() => match msg {
                        Some(m) => update_finger_state_from_progress(&state, &m).await,
                        None => break,
                    }
                }
            }

            // Epoch-guarded cleanup + emit: if a successor (or VerifyStop)
            // has replaced our action token, drop both the state reset and
            // the final-status emit silently — the original caller is gone
            // and the new owner mustn't see a stale signal.
            let still_ours = state.lock().await.end_action_if_owner(my_token);
            if still_ours {
                if let Some(status) = final_status
                    && let Err(e) = Device::verify_status(&owned_emitter, status, true).await
                {
                    tracing::warn!("emit final VerifyStatus failed: {}", e);
                }
            } else {
                tracing::debug!("verify task: token no longer owns action, dropping final status");
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
        match state.action {
            Some(ActionToken {
                kind: ActionKind::Verify,
                ..
            }) => {
                state.action = None;
                state.finger_needed = false;
                state.finger_present = false;
                Ok(())
            }
            _ => Err(FprintError::NoActionInProgress(
                "no verify in progress".into(),
            )),
        }
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

        let my_token = {
            let mut state = self.state.lock().await;
            if let Some(t) = state.action {
                return Err(FprintError::AlreadyInUse(format!(
                    "{} already in progress",
                    t.kind.as_str()
                )));
            }
            state.start_action(ActionKind::Enroll)
        };

        // Re-enroll strategy: if the user already has THIS finger enrolled,
        // reuse the same slot. The R503's storeModel() unconditionally
        // overwrites the slot at the END of enroll, only after createModel
        // succeeds — so a failed re-enroll leaves the previous good template
        // intact, and a successful re-enroll cleanly replaces it. This avoids
        // the "wipe old enrollment before knowing the new one works" foot-gun
        // and removes the ghost-template window we'd open by pre-deleting.
        let slot = match self.storage.get_slot(&user, &finger_name).await {
            Some(existing) => {
                tracing::info!(user = %user, finger = %finger_name, slot = existing, "re-enrolling (reusing existing slot)");
                existing
            }
            None => match self.storage.allocate_slot().await {
                Ok(s) => s,
                Err(StorageError::NoFreeSlot(_)) => {
                    // Upstream FP_DEVICE_ERROR_DATA_FULL → status signal.
                    // Emit synchronously BEFORE clearing the action slot so a
                    // racing EnrollStart can't pre-empt and have our orphan
                    // signal land against its session.
                    tracing::warn!(user = %user, finger = %finger_name, "sensor flash full — emitting enroll-data-full");
                    Device::enroll_status(&emitter, "enroll-data-full", true)
                        .await
                        .ok();
                    self.state.lock().await.end_action_if_owner(my_token);
                    return Ok(());
                }
                Err(e) => {
                    self.state.lock().await.end_action_if_owner(my_token);
                    return Err(e.into());
                }
            },
        };
        tracing::info!(user = %user, finger = %finger_name, slot, "EnrollStart");
        {
            let mut state = self.state.lock().await;
            state.finger_needed = true;
            state.finger_present = false;
        }
        let owned_emitter = emitter.to_owned();

        let sensor = self.sensor.clone();
        let storage = self.storage.clone();
        let state = self.state.clone();
        let user_for_task = user.clone();
        let finger_for_task = finger_name.clone();
        tokio::spawn(async move {
            let (prog_tx, mut prog_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let enroll_fut = sensor.enroll(slot, Some(prog_tx.clone()));
            tokio::pin!(enroll_fut);

            // Drive the enroll + interleave progress in one task. select! means
            // there's no separate receiver task to leak and no abort-races-
            // queued-message: each PROGRESS line is consumed before we hand
            // control to the next branch.
            let result = loop {
                tokio::select! {
                    biased;
                    Some(msg) = prog_rx.recv() => {
                        tracing::debug!(progress = %msg, "enroll progress");
                        update_finger_state_from_progress(&state, &msg).await;
                        let low = msg.to_lowercase();
                        if low.contains("remove_finger") || low.contains("remove finger") {
                            Device::enroll_status(&owned_emitter, "enroll-stage-passed", false)
                                .await
                                .ok();
                        }
                    }
                    result = &mut enroll_fut => break result,
                }
            };
            // Drain any trailing PROGRESS lines that landed after enroll done.
            drop(prog_tx);
            let drain_deadline = tokio::time::sleep(std::time::Duration::from_millis(50));
            tokio::pin!(drain_deadline);
            loop {
                tokio::select! {
                    _ = &mut drain_deadline => break,
                    msg = prog_rx.recv() => match msg {
                        Some(m) => update_finger_state_from_progress(&state, &m).await,
                        None => break,
                    }
                }
            }

            // Epoch-guarded cleanup. If a successor (or EnrollStop / claimer
            // disconnect) replaced our token, drop the result silently — the
            // original caller is no longer listening and we mustn't stomp the
            // successor's state or emit a stale terminal signal.
            let still_ours = state.lock().await.end_action_if_owner(my_token);
            if !still_ours {
                tracing::debug!("enroll task: token no longer owns action, dropping final status");
                return;
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
                    let status = if crate::sensor_actor::is_fatal_io(&e) {
                        tracing::warn!("enroll disconnected: {}", e);
                        "enroll-disconnected"
                    } else {
                        tracing::warn!("enroll error: {}", e);
                        "enroll-failed"
                    };
                    Device::enroll_status(&owned_emitter, status, true)
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
        match state.action {
            Some(ActionToken {
                kind: ActionKind::Enroll,
                ..
            }) => {
                state.action = None;
                state.finger_needed = false;
                state.finger_present = false;
                Ok(())
            }
            _ => Err(FprintError::NoActionInProgress(
                "no enroll in progress".into(),
            )),
        }
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
