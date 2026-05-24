//! D-Bus error type. Variant names map 1:1 to the fprintd-compatible error
//! names under `net.reactivated.Fprint.Error.*`. `zbus::DBusError` provides
//! both `Display` and `std::error::Error` for us, so we don't also derive
//! `thiserror::Error`.

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
pub enum FprintError {
    /// Catch-all for unexpected internal failures (sensor I/O, storage,
    /// anything else that bubbles up). String payload is shown to the caller.
    Internal(String),

    /// The caller hasn't claimed the device (or claim was lost).
    ClaimDevice(String),

    /// The device is already in use by another claimer or operation.
    AlreadyInUse(String),

    /// No prints enrolled for the requested user / finger.
    NoEnrolledPrints(String),

    /// VerifyStop / EnrollStop with no matching active operation.
    NoActionInProgress(String),

    /// Finger name string not in the fprintd-defined set.
    InvalidFingername(String),

    /// Print deletion failed (sensor flash or storage layer rejected).
    PrintsNotDeleted(String),
}

impl From<zbus::Error> for FprintError {
    fn from(e: zbus::Error) -> Self {
        FprintError::Internal(format!("zbus: {}", e))
    }
}

impl From<crate::sensor::SensorError> for FprintError {
    fn from(e: crate::sensor::SensorError) -> Self {
        FprintError::Internal(e.to_string())
    }
}

impl From<crate::storage::StorageError> for FprintError {
    fn from(e: crate::storage::StorageError) -> Self {
        FprintError::Internal(e.to_string())
    }
}
