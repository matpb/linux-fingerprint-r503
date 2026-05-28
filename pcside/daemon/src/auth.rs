//! Caller-identity gating for D-Bus methods that take a `username` parameter.
//!
//! Before this module existed, every method that accepted a `username: String`
//! trusted it blindly — so a local user could `Claim "root"`, `EnrollStart ...`,
//! place their own finger, and harvest a working fingerprint for root's PAM
//! session on the next `sudo`. See `docs/SECURITY_HARDENING_PLAN.md` §P0-1.
//!
//! Authorization model (stricter than upstream fprintd — see
//! SECURITY_HARDENING_PLAN.md §S1):
//!   - Empty `requested_username` → resolve to the caller themselves.
//!   - Self request (`requested_username == caller`) → allowed, no prompt.
//!   - Caller is uid 0 (root, e.g. `sudo`/`pam_fprintd`) → allowed for any user;
//!     PAM is the legitimate cross-user case and must not block.
//!   - Otherwise → polkit `check_authorization` WITHOUT `AllowUserInteraction`
//!     against `net.reactivated.fprint.device.setusername`. Default policy is
//!     `no` for every session class, so cross-user ops from non-root callers
//!     are denied silently — no dialog can be triggered on the active session
//!     by an SSH attacker or low-privilege local user. To enroll for another
//!     user, become root: `sudo fprintd-enroll target-user`.
//!
//! Why polkit at all if we never prompt? It's the documented Linux escape
//! hatch: an admin who wants kiosk / multi-user-lab behavior can drop a JS
//! rule into `/etc/polkit-1/rules.d/` that grants specific subjects without
//! us shipping a config knob ourselves.
//!
//! All three outcomes of `authorize_username`:
//!   - `Ok(resolved_user)` — caller is authorized; act on `resolved_user`.
//!   - `Err(FprintError::PermissionDenied)` — explicit denial (cross-user
//!     without polkit clearance, or polkit said no).
//!   - `Err(FprintError::Internal)` — couldn't even resolve the caller (no
//!     sender header, uid not in passwd, polkit unreachable, etc).

use std::collections::HashMap;

use zbus::Connection;
// `BitFlag::empty()` is the no-flags constructor for polkit's CheckAuthorization
// flag set. Pulled in directly because zbus_polkit's flag type is enumflags2-
// backed and the trait provides `empty()` without us having to depend on
// enumflags2 in Cargo.toml.
use enumflags2::BitFlag;
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

use crate::error::FprintError;

/// fprintd-compatible action ID for cross-user fingerprint management.
/// Keeping the name identical means an admin's existing polkit rules for
/// upstream fprintd Just Work against r503d too.
pub const ACTION_SETUSERNAME: &str = "net.reactivated.fprint.device.setusername";

/// Resolve `requested_username` (with the fprintd empty-string convention) and
/// verify the calling D-Bus client is allowed to act as that user. Returns the
/// resolved username on success.
///
/// This is the single chokepoint every `username`-accepting D-Bus method must
/// route through; the old `resolve_caller` helper has been retired.
pub async fn authorize_username(
    conn: &Connection,
    sender: Option<&str>,
    requested_username: &str,
) -> Result<String, FprintError> {
    let (caller_uid, caller_pid, caller_user) = resolve_caller(conn, sender).await?;

    // Fast paths — no polkit round-trip.
    if requested_username.is_empty() || requested_username == caller_user {
        return Ok(caller_user);
    }
    if caller_uid == 0 {
        // PAM/sudo invokes us as root and passes the target user verbatim.
        // Treating uid 0 as universally trusted matches the upstream fprintd
        // policy and keeps `pam_fprintd` working without prompts.
        return Ok(requested_username.to_string());
    }

    // Cross-user request from a non-root caller — defer to polkit. We
    // deliberately do NOT pass `AllowUserInteraction`: an SSH attacker
    // calling `Claim "mat"` must not be able to pop a polkit dialog on the
    // active session that an unattentive admin might click through. With no
    // interaction, polkit can only return `is_authorized=true` if an admin
    // has explicitly written a polkit rule granting the subject — the
    // intended escape hatch for kiosks / multi-user labs.
    let proxy = AuthorityProxy::new(conn)
        .await
        .map_err(|e| FprintError::Internal(format!("polkit proxy: {}", e)))?;
    // `unix-process` subject. Polkit looks up start-time + uid from /proc;
    // the (pid, start-time) tuple is stable against pid reuse so this is safe
    // even though pid alone would be racy. Alternative: `new_for_message_header`
    // ("system-bus-name" subject_kind) — same security properties, different
    // bookkeeping.
    let subject = Subject::new_for_owner(caller_pid, None, None)
        .map_err(|e| FprintError::Internal(format!("polkit subject: {}", e)))?;
    let details: HashMap<&str, &str> = HashMap::new();
    let result = proxy
        .check_authorization(
            &subject,
            ACTION_SETUSERNAME,
            &details,
            CheckAuthorizationFlags::empty().into(),
            "",
        )
        .await
        .map_err(|e| FprintError::Internal(format!("polkit check: {}", e)))?;

    if result.is_authorized {
        Ok(requested_username.to_string())
    } else {
        Err(FprintError::PermissionDenied(format!(
            "uid {} not authorized to act as user {}",
            caller_uid, requested_username
        )))
    }
}

/// Look up the calling D-Bus client's (uid, pid, username) tuple. Identical
/// resolution path to the previous `dbus_iface::resolve_caller`, just split
/// out so this module owns the policy.
async fn resolve_caller(
    conn: &Connection,
    sender: Option<&str>,
) -> Result<(u32, u32, String), FprintError> {
    let sender = sender.ok_or_else(|| FprintError::Internal("missing sender".into()))?;
    let bus_name = zbus::names::BusName::try_from(sender)
        .map_err(|e| FprintError::Internal(format!("invalid sender {}: {}", sender, e)))?;
    let dbus = zbus::fdo::DBusProxy::new(conn).await?;
    let uid = dbus
        .get_connection_unix_user(bus_name.clone())
        .await
        .map_err(|e| FprintError::Internal(format!("GetConnectionUnixUser: {}", e)))?;
    let pid = dbus
        .get_connection_unix_process_id(bus_name)
        .await
        .map_err(|e| FprintError::Internal(format!("GetConnectionUnixProcessID: {}", e)))?;
    let user = crate::dbus_iface::pwd_lookup(uid)
        .ok_or_else(|| FprintError::Internal(format!("uid {} not in passwd", uid)))?;
    validate_username(&user)?;
    Ok((uid, pid, user))
}

#[cfg(test)]
mod tests {
    use super::validate_username;

    #[test]
    fn accepts_real_usernames() {
        for ok in ["mat", "root", "john.doe", "svc-r503", "_systemd", "user1", "a"] {
            assert!(validate_username(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn rejects_unsafe_usernames() {
        for bad in ["", ".", "..", "../etc/shadow", "a/b", "a\\b", "a\nb", "a\0b", "\x07evil"] {
            assert!(validate_username(bad).is_err(), "should reject {bad:?}");
        }
    }
}

/// Reject a username that could be dangerous if a future code path ever
/// interpolated it into a file path (it becomes a HashMap key in users.json
/// today, but path-shaped names are a footgun waiting to happen). No current
/// exploit exists — this is a boundary guard (audit 2026-05-28 / L5).
///
/// Deliberately NOT a tight allow-list: we reject only the genuinely unsafe
/// shapes (empty, `.`/`..`, path separators, NUL and control bytes) so that
/// any real account a working `getpwuid_r` returns — including locale or
/// site-specific names a strict `^[a-z_]...$` regex would wrongly bounce —
/// keeps authenticating. useradd already forbids these characters, so a name
/// carrying one is anomalous, not legitimate.
fn validate_username(user: &str) -> Result<(), FprintError> {
    let bad = user.is_empty()
        || user == "."
        || user == ".."
        || user.contains('/')
        || user.contains('\\')
        || user.bytes().any(|b| b == 0 || b.is_ascii_control());
    if bad {
        tracing::warn!(user = %user.escape_default().to_string(), "rejecting unsafe username from getpwuid_r");
        return Err(FprintError::Internal("unsafe username".into()));
    }
    Ok(())
}
