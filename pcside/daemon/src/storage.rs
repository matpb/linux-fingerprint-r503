//! JSON-backed per-user fingerprint slot registry.
//!
//! The R503 holds the actual biometric templates in its on-sensor flash; this
//! file is just a label that says "user X's right-thumb lives in slot N." Atomic
//! writes via temp-file rename.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Default, Serialize, Deserialize)]
struct StorageFile {
    /// username -> (finger-name -> slot index in sensor flash)
    users: HashMap<String, HashMap<String, u8>>,
}

#[derive(Debug, Clone)]
pub struct Storage {
    inner: Arc<RwLock<StorageInner>>,
}

#[derive(Debug)]
struct StorageInner {
    path: PathBuf,
    capacity: u16,
    data: StorageFile,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage parse: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("no free slots (capacity={0})")]
    NoFreeSlot(u16),
}

impl Storage {
    pub async fn open(path: PathBuf, capacity: u16) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let data: StorageFile = if path.exists() {
            let raw = tokio::fs::read(&path).await?;
            serde_json::from_slice(&raw)?
        } else {
            StorageFile::default()
        };
        let storage = Storage {
            inner: Arc::new(RwLock::new(StorageInner {
                path,
                capacity,
                data,
            })),
        };
        storage.save().await?;
        Ok(storage)
    }

    pub async fn list_fingers(&self, username: &str) -> Vec<String> {
        let guard = self.inner.read().await;
        let mut v: Vec<String> = guard
            .data
            .users
            .get(username)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    pub async fn get_slot(&self, username: &str, finger: &str) -> Option<u8> {
        self.inner
            .read()
            .await
            .data
            .users
            .get(username)
            .and_then(|m| m.get(finger).copied())
    }

    pub async fn get_user_slots(&self, username: &str) -> HashMap<String, u8> {
        self.inner
            .read()
            .await
            .data
            .users
            .get(username)
            .cloned()
            .unwrap_or_default()
    }

    /// Lowest unused slot in [0, capacity).
    pub async fn allocate_slot(&self) -> Result<u8, StorageError> {
        let guard = self.inner.read().await;
        let used: HashSet<u8> = guard
            .data
            .users
            .values()
            .flat_map(|m| m.values().copied())
            .collect();
        let cap = guard.capacity.min(u8::MAX as u16 + 1);
        for s in 0..cap {
            let slot = s as u8;
            if !used.contains(&slot) {
                return Ok(slot);
            }
        }
        Err(StorageError::NoFreeSlot(guard.capacity))
    }

    pub async fn set_slot(
        &self,
        username: &str,
        finger: &str,
        slot: u8,
    ) -> Result<(), StorageError> {
        {
            let mut guard = self.inner.write().await;
            guard
                .data
                .users
                .entry(username.to_string())
                .or_default()
                .insert(finger.to_string(), slot);
        }
        self.save().await
    }

    pub async fn remove_finger(
        &self,
        username: &str,
        finger: &str,
    ) -> Result<Option<u8>, StorageError> {
        let slot = {
            let mut guard = self.inner.write().await;
            let removed = guard
                .data
                .users
                .get_mut(username)
                .and_then(|m| m.remove(finger));
            if guard
                .data
                .users
                .get(username)
                .map(|m| m.is_empty())
                .unwrap_or(false)
            {
                guard.data.users.remove(username);
            }
            removed
        };
        self.save().await?;
        Ok(slot)
    }

    async fn save(&self) -> Result<(), StorageError> {
        let guard = self.inner.read().await;
        let bytes = serde_json::to_vec_pretty(&guard.data)?;
        let tmp = guard.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &guard.path).await?;
        Ok(())
    }
}
