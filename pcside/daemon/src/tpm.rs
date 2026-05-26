//! TPM2-sealed host key (SPEC §13.12).
//!
//! Seals the 16-byte SipHash key (the v2 authenticated wire-protocol shared
//! secret, SPEC §13) to PCR7 on the local TPM2. The sealed blob lives at
//! `/var/lib/r503d/key.tpm` and only unwraps on the same machine in the same
//! Secure Boot policy state.
//!
//! Threat closed (vs. plaintext `key` file):
//!   - Offline-disk attacker (`dd` of unmounted partition, SSD swap into a
//!     hostile box) gets ciphertext only.
//!   - Bootloader / kernel substitution that changes PCR7 fails `TPM2_Unseal`.
//!
//! Failure mode on PCR7 mismatch: refuse to operate, instruct the operator to
//! run the reseal ceremony (`sudo dist/reseal-tpm.sh`). No plaintext fallback —
//! that would defeat the point.

#![allow(dead_code)] // sealed_blob_exists / current_pcr7_hex / hex_encode are
                     // wired in via follow-up tooling (--tpm-info CLI etc.);
                     // keeping them here saves a churn pass when those land.

use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;

use std::str::FromStr;

use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::SessionHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Private,
        Public, PublicBuilder, PublicKeyedHashParameters, RsaExponent, SensitiveData,
        SymmetricDefinition,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::{Marshall, UnMarshall},
    utils::create_restricted_decryption_rsa_public,
    Context as TpmContext,
};

pub const TPM_DEVICE: &str = "/dev/tpmrm0";

/// On-disk magic + format version. Bump the trailing byte if the serialization
/// format changes incompatibly. The canonical on-disk path lives in
/// `keystore::KEY_TPM_PATH` — kept there so the rest of the daemon doesn't
/// import this module just to read a path.
const FILE_MAGIC: &[u8; 8] = b"R503TPM\x01";

/// PCRs we bind the seal to. PCR7 = Secure Boot policy + keys.
const PCR_SLOTS: &[PcrSlot] = &[PcrSlot::Slot7];

/// Cheap probe — `true` if the TPM2 character device exists. Doesn't open it
/// (avoids spurious "Permission denied" noise when called from a non-root
/// preflight). Production code paths run as root via the systemd unit.
pub fn device_present() -> bool {
    Path::new(TPM_DEVICE).exists()
}

/// Seal the 16-byte key to PCR7 (SHA256). Returns the on-disk blob bytes
/// (the caller is responsible for writing them atomically).
pub fn seal_key(key: &[u8; 16]) -> Result<Vec<u8>> {
    let mut ctx = open_context()?;

    let pcr_sel = pcr_selection()?;
    let policy_digest = trial_policy_pcr_digest(&mut ctx, pcr_sel.clone())?;

    let hmac = start_hmac_session(&mut ctx)?;
    let attempt: Result<(Vec<u8>, Vec<u8>)> = (|| {
        ctx.set_sessions((Some(hmac), None, None));
        let primary = ctx
            .create_primary(
                Hierarchy::Owner,
                srk_template()?,
                None,
                None,
                None,
                None,
            )
            .context("creating primary key on Owner hierarchy")?;

        let sealed_pub = sealed_object_template(policy_digest.clone())?;

        let sensitive = SensitiveData::try_from(key.to_vec())
            .map_err(|e| anyhow!("wrapping 16 bytes into SensitiveData: {:?}", e))?;

        let created = ctx
            .create(primary.key_handle, sealed_pub, None, Some(sensitive), None, None)
            .context("creating sealed object under primary")?;

        let pub_bytes: Vec<u8> = created
            .out_public
            .marshall()
            .context("marshalling out_public")?;
        // `Private` is a thin TPM2B byte buffer (zeroizing). Its raw bytes
        // are the on-disk form — no separate marshall step.
        let priv_bytes: Vec<u8> = created.out_private.value().to_vec();

        ctx.flush_context(primary.key_handle.into()).ok();
        Ok((pub_bytes, priv_bytes))
    })();

    ctx.flush_context(SessionHandle::from(hmac).into()).ok();
    let (pub_bytes, priv_bytes) = attempt?;

    Ok(serialize_blob(&pub_bytes, &priv_bytes))
}

/// Unseal the key from a previously-sealed blob, against the current PCR7
/// value. Returns an error if PCR7 has changed since sealing (the underlying
/// TPM error is `TPM_RC_POLICY_FAIL`; we wrap it with the reseal hint).
pub fn unseal_key(blob: &[u8]) -> Result<[u8; 16]> {
    let (pub_bytes, priv_bytes) = deserialize_blob(blob)?;
    let sealed_public =
        Public::unmarshall(&pub_bytes).context("unmarshalling stored sealed Public")?;
    let sealed_private = Private::try_from(priv_bytes)
        .map_err(|e| anyhow!("rebuilding Private from blob bytes: {:?}", e))?;

    let mut ctx = open_context()?;
    let pcr_sel = pcr_selection()?;

    let hmac = start_hmac_session(&mut ctx)?;
    let policy = start_policy_session(&mut ctx)?;

    let attempt: Result<[u8; 16]> = (|| {
        ctx.set_sessions((Some(hmac), None, None));
        let primary = ctx
            .create_primary(
                Hierarchy::Owner,
                srk_template()?,
                None,
                None,
                None,
                None,
            )
            .context("re-creating primary key (TPM owner seed mismatch?)")?;

        let loaded = ctx
            .load(primary.key_handle, sealed_private, sealed_public)
            .context("loading sealed object under primary")?;

        // Build the policy on the policy session: PolicyPCR with empty digest =
        // TPM uses *current* PCR values, then the unseal succeeds iff the
        // resulting session digest matches the auth_policy baked into the
        // sealed object at seal time.
        let policy_session = PolicySession::try_from(policy)
            .map_err(|e| anyhow!("auth → policy session: {:?}", e))?;
        ctx.policy_pcr(
            policy_session,
            Digest::try_from(Vec::<u8>::new()).unwrap(),
            pcr_sel.clone(),
        )
        .context("PolicyPCR — TPM_RC_POLICY_FAIL means PCR7 changed since sealing")?;

        ctx.set_sessions((Some(policy), None, None));
        let unsealed = ctx.unseal(loaded.into()).context(
            "Unseal — PCR policy mismatch; \
                 boot state changed since sealing. \
                 Run `sudo dist/reseal-tpm.sh` to recover.",
        )?;

        ctx.set_sessions((Some(hmac), None, None));
        ctx.flush_context(loaded.into()).ok();
        ctx.flush_context(primary.key_handle.into()).ok();

        let bytes = unsealed.value();
        if bytes.len() != 16 {
            bail!("unsealed payload is {} bytes, expected 16", bytes.len());
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Ok(out)
    })();

    ctx.flush_context(SessionHandle::from(policy).into()).ok();
    ctx.flush_context(SessionHandle::from(hmac).into()).ok();

    attempt
}

/// Read the current PCR7 (SHA256) value as a hex string. Diagnostic helper
/// for the `--tpm-info` CLI; not used in the seal/unseal hot path.
pub fn current_pcr7_hex() -> Result<String> {
    let mut ctx = open_context()?;
    let pcr_sel = pcr_selection()?;
    let (_count, _sel, digests) = ctx
        .pcr_read(pcr_sel)
        .context("pcr_read on PCR7")?;
    let d = digests
        .value()
        .first()
        .ok_or_else(|| anyhow!("pcr_read returned no digests"))?;
    Ok(hex_encode(d.value()))
}

fn open_context() -> Result<TpmContext> {
    // Pin to `/dev/tpmrm0` — the kernel's resource-managed TPM device. The
    // tss-esapi default points at `/dev/tpm0`, the raw device, which on
    // Fedora is owned `tss:root 0660` and is unavailable to a hardened
    // systemd unit even when running as root (DevicePolicy=closed plus the
    // group-only DAC means cgroup denies the open). `/dev/tpmrm0` is
    // `root:tss 0660` and works with the systemd `DeviceAllow` we ship.
    let config = DeviceConfig::from_str(TPM_DEVICE)
        .with_context(|| format!("parsing TCTI device path {}", TPM_DEVICE))?;
    TpmContext::new(TctiNameConf::Device(config))
        .with_context(|| format!("opening TPM2 device at {}", TPM_DEVICE))
}

fn pcr_selection() -> Result<PcrSelectionList> {
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, PCR_SLOTS)
        .build()
        .context("building PCR selection (sha256:7)")
}

fn start_hmac_session(ctx: &mut TpmContext) -> Result<AuthSession> {
    let s = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("starting HMAC session")?
        .ok_or_else(|| anyhow!("start_auth_session returned None for HMAC"))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(s, attrs, mask)
        .context("setting HMAC session attributes")?;
    Ok(s)
}

fn start_policy_session(ctx: &mut TpmContext) -> Result<AuthSession> {
    let s = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("starting policy session")?
        .ok_or_else(|| anyhow!("start_auth_session returned None for Policy"))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(s, attrs, mask)
        .context("setting policy session attributes")?;
    Ok(s)
}

/// Run PolicyPCR on a trial session to compute the policy digest we'll bake
/// into the sealed object's `auth_policy` field.
fn trial_policy_pcr_digest(
    ctx: &mut TpmContext,
    pcr_sel: PcrSelectionList,
) -> Result<Digest> {
    let old = ctx.sessions();
    ctx.clear_sessions();

    let trial = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("starting trial session")?
        .ok_or_else(|| anyhow!("trial start_auth_session returned None"))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(trial, attrs, mask)
        .context("trial session attrs")?;

    let policy_session = PolicySession::try_from(trial)
        .map_err(|e| anyhow!("trial auth → policy session: {:?}", e))?;
    ctx.policy_pcr(
        policy_session,
        Digest::try_from(Vec::<u8>::new()).unwrap(),
        pcr_sel,
    )
    .context("trial policy_pcr")?;
    let digest = ctx
        .policy_get_digest(policy_session)
        .context("policy_get_digest on trial session")?;

    ctx.flush_context(SessionHandle::from(trial).into()).ok();
    ctx.set_sessions(old);
    Ok(digest)
}

fn srk_template() -> Result<Public> {
    // Standard restricted-decryption RSA-2048 primary on the Owner hierarchy.
    // Deterministic across reboots: the Owner Primary Seed (OPS) doesn't
    // change unless the TPM is cleared (TPM2_Clear). Means we don't need to
    // persist the primary handle — recreate it each time, get the same key.
    create_restricted_decryption_rsa_public(
        tss_esapi::abstraction::cipher::Cipher::aes_128_cfb()
            .try_into()
            .context("symmetric for SRK template")?,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .context("building SRK-like primary template")
}

fn sealed_object_template(policy_digest: Digest) -> Result<Public> {
    // KeyedHash sealed object. `admin_with_policy = true` and `user_with_auth
    // = false` means there's no fallback password — the only way to authorize
    // the unseal is to satisfy the PCR policy. That's the entire security
    // story.
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true)
        .with_user_with_auth(false)
        .build()
        .context("sealed object attributes")?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .context("building sealed-object Public")
}

fn serialize_blob(pub_bytes: &[u8], priv_bytes: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(FILE_MAGIC.len() + 8 + pub_bytes.len() + priv_bytes.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(pub_bytes);
    out.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(priv_bytes);
    out
}

fn deserialize_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if blob.len() < FILE_MAGIC.len() + 8 {
        bail!("sealed blob too short ({} bytes)", blob.len());
    }
    if &blob[..FILE_MAGIC.len()] != FILE_MAGIC {
        bail!("sealed blob magic/version mismatch — file isn't a key.tpm produced by this daemon");
    }
    let mut off = FILE_MAGIC.len();
    let pub_len =
        u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if off + pub_len + 4 > blob.len() {
        bail!("sealed blob truncated (pub field)");
    }
    let pub_bytes = blob[off..off + pub_len].to_vec();
    off += pub_len;
    let priv_len =
        u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if off + priv_len != blob.len() {
        bail!(
            "sealed blob length mismatch (priv field): expected {} more bytes, blob has {}",
            priv_len,
            blob.len() - off
        );
    }
    let priv_bytes = blob[off..off + priv_len].to_vec();
    Ok((pub_bytes, priv_bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_roundtrip() {
        let pub_bytes = vec![1, 2, 3, 4, 5];
        let priv_bytes = vec![9, 8, 7];
        let blob = serialize_blob(&pub_bytes, &priv_bytes);
        let (p, q) = deserialize_blob(&blob).unwrap();
        assert_eq!(p, pub_bytes);
        assert_eq!(q, priv_bytes);
    }

    #[test]
    fn blob_rejects_wrong_magic() {
        let mut blob = serialize_blob(&[1, 2, 3], &[4, 5, 6]);
        blob[0] = b'X';
        assert!(deserialize_blob(&blob).is_err());
    }

    #[test]
    fn blob_rejects_truncated_pub() {
        let blob = serialize_blob(&[1, 2, 3, 4], &[5, 6]);
        let truncated = &blob[..blob.len() - 5];
        assert!(deserialize_blob(truncated).is_err());
    }

    #[test]
    fn blob_rejects_trailing_garbage() {
        let mut blob = serialize_blob(&[1, 2, 3], &[4, 5]);
        blob.push(0xff);
        assert!(deserialize_blob(&blob).is_err());
    }
}
