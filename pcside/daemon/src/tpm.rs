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
use zeroize::Zeroizing;

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

/// On-disk magic + format version.
///   - `\x01`: original format — pub_len/pub/priv_len/priv. PCR7-only,
///     implicit. Still readable.
///   - `\x02`: extends `\x01` with `[pcr_count: u8, pcr_list: u8 × N]`
///     between magic and pub_len. Caller chooses which PCRs to bind.
const FILE_MAGIC_V1: &[u8; 8] = b"R503TPM\x01";
const FILE_MAGIC_V2: &[u8; 8] = b"R503TPM\x02";

/// Default PCR binding for legacy v1 blobs and the no-flag pair path.
/// PCR7 = Secure Boot policy + keys (SPEC §13.12).
const DEFAULT_PCRS: &[u8] = &[7];

/// Cheap probe — `true` if the TPM2 character device exists. Doesn't open it
/// (avoids spurious "Permission denied" noise when called from a non-root
/// preflight). Production code paths run as root via the systemd unit.
pub fn device_present() -> bool {
    Path::new(TPM_DEVICE).exists()
}

/// Seal the 16-byte key to the default PCR set (PCR7 only — SPEC §13.12
/// recommended path). Returns the on-disk blob bytes (caller writes them
/// atomically). Equivalent to `seal_key_with_pcrs(key, &[7])`.
pub fn seal_key(key: &[u8; 16]) -> Result<Vec<u8>> {
    seal_key_with_pcrs(key, DEFAULT_PCRS)
}

/// Seal the 16-byte key to an arbitrary PCR set (SHA256 bank). The PCR list
/// is encoded into the on-disk blob (FILE_MAGIC_V2) so `unseal_key` reads it
/// back and constructs the matching policy automatically. PCR7-only callers
/// get the v1 magic via `seal_key`.
///
/// Recommended additional PCRs (operator's choice, kept off by default to
/// avoid kernel-update pain):
///   - PCR7: Secure Boot policy + keys (already the default)
///   - PCR11: systemd-stub UKI measurement — binds kernel+initrd hash
///   - PCR4: bootloader / shim measurement
///   - PCR0: UEFI firmware (CRTM)
///
/// Each additional PCR tightens the seal and invalidates it on the
/// corresponding update event (kernel bump → PCR11 changes → reseal needed).
/// `dist/reseal-tpm.sh` carries `--pcrs <list>` to the reseal flow.
pub fn seal_key_with_pcrs(key: &[u8; 16], pcrs: &[u8]) -> Result<Vec<u8>> {
    validate_pcrs(pcrs)?;
    let mut ctx = open_context()?;

    let pcr_sel = pcr_selection_for(pcrs)?;
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

    Ok(serialize_blob(pcrs, &pub_bytes, &priv_bytes))
}

/// Unseal the key from a previously-sealed blob, against the current PCR7
/// value. Returns an error if PCR7 has changed since sealing (the underlying
/// TPM error is `TPM_RC_POLICY_FAIL`; we wrap it with the reseal hint).
///
/// The returned `Zeroizing<[u8; 16]>` scrubs the unwrapped key on drop —
/// it must not be unwrapped into a bare `[u8; 16]` by callers (crypto-
/// posture review item #2).
pub fn unseal_key(blob: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
    let (pcrs, pub_bytes, priv_bytes) = deserialize_blob(blob)?;
    let sealed_public =
        Public::unmarshall(&pub_bytes).context("unmarshalling stored sealed Public")?;
    let sealed_private = Private::try_from(priv_bytes)
        .map_err(|e| anyhow!("rebuilding Private from blob bytes: {:?}", e))?;

    let mut ctx = open_context()?;
    let pcr_sel = pcr_selection_for(&pcrs)?;

    let hmac = start_hmac_session(&mut ctx)?;
    let policy = start_policy_session(&mut ctx)?;

    let attempt: Result<Zeroizing<[u8; 16]>> = (|| {
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
        let mut out = Zeroizing::new([0u8; 16]);
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
    let pcr_sel = pcr_selection_for(DEFAULT_PCRS)?;
    let (_count, _sel, digests) = ctx
        .pcr_read(pcr_sel)
        .context("pcr_read on PCR7")?;
    let d = digests
        .value()
        .first()
        .ok_or_else(|| anyhow!("pcr_read returned no digests"))?;
    Ok(hex_encode(d.value()))
}

/// Parse a comma-separated PCR list (`"7"`, `"7,11"`, `"0,4,7,11"`).
/// Caller-facing helper so the CLI doesn't have to know about tss-esapi types.
pub fn parse_pcr_list(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() { continue; }
        let n: u8 = tok.parse()
            .with_context(|| format!("PCR index {:?} is not a u8", tok))?;
        out.push(n);
    }
    if out.is_empty() {
        bail!("PCR list is empty — must specify at least one (e.g. \"7\")");
    }
    validate_pcrs(&out)?;
    Ok(out)
}

fn validate_pcrs(pcrs: &[u8]) -> Result<()> {
    if pcrs.is_empty() {
        bail!("PCR list cannot be empty");
    }
    if pcrs.len() > 24 {
        bail!("PCR list too long ({} > 24 slots in the SHA256 bank)", pcrs.len());
    }
    for &p in pcrs {
        if p > 23 {
            bail!("PCR index {} out of range (0..=23 in the SHA256 bank)", p);
        }
    }
    // Reject duplicates.
    let mut sorted = pcrs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != pcrs.len() {
        bail!("PCR list contains duplicates: {:?}", pcrs);
    }
    Ok(())
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

fn pcr_selection_for(pcrs: &[u8]) -> Result<PcrSelectionList> {
    let slots: Vec<PcrSlot> = pcrs.iter().map(|&p| u8_to_pcr_slot(p)).collect();
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .with_context(|| format!("building PCR selection (sha256:{:?})", pcrs))
}

fn u8_to_pcr_slot(p: u8) -> PcrSlot {
    match p {
        0 => PcrSlot::Slot0,    1 => PcrSlot::Slot1,
        2 => PcrSlot::Slot2,    3 => PcrSlot::Slot3,
        4 => PcrSlot::Slot4,    5 => PcrSlot::Slot5,
        6 => PcrSlot::Slot6,    7 => PcrSlot::Slot7,
        8 => PcrSlot::Slot8,    9 => PcrSlot::Slot9,
        10 => PcrSlot::Slot10, 11 => PcrSlot::Slot11,
        12 => PcrSlot::Slot12, 13 => PcrSlot::Slot13,
        14 => PcrSlot::Slot14, 15 => PcrSlot::Slot15,
        16 => PcrSlot::Slot16, 17 => PcrSlot::Slot17,
        18 => PcrSlot::Slot18, 19 => PcrSlot::Slot19,
        20 => PcrSlot::Slot20, 21 => PcrSlot::Slot21,
        22 => PcrSlot::Slot22, 23 => PcrSlot::Slot23,
        // validate_pcrs() screens this out before we get here.
        _ => unreachable!("PCR {} > 23 should have been rejected", p),
    }
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

fn serialize_blob(pcrs: &[u8], pub_bytes: &[u8], priv_bytes: &[u8]) -> Vec<u8> {
    // PCR7-only seals stay on the v1 magic so existing key.tpm files keep
    // round-tripping. Anything else gets the v2 magic + explicit PCR list.
    let use_v2 = pcrs != DEFAULT_PCRS;
    let mut out = Vec::with_capacity(
        FILE_MAGIC_V1.len() + 8 + pub_bytes.len() + priv_bytes.len()
            + if use_v2 { 1 + pcrs.len() } else { 0 }
    );
    out.extend_from_slice(if use_v2 { FILE_MAGIC_V2 } else { FILE_MAGIC_V1 });
    if use_v2 {
        out.push(pcrs.len() as u8);
        out.extend_from_slice(pcrs);
    }
    out.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(pub_bytes);
    out.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(priv_bytes);
    out
}

fn deserialize_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Defensive cap. Real TPM-marshalled fields here are ~150 B (Public) and
    // ~100 B (Private); a 64 KB cap is generous and bounds any attempt to
    // make us preallocate a multi-GB buffer from a hostile file. Crypto-
    // posture review item #7.
    const MAX_FIELD: usize = 65_536;

    if blob.len() < FILE_MAGIC_V1.len() + 8 {
        bail!("sealed blob too short ({} bytes)", blob.len());
    }
    let (pcrs, mut off) = if &blob[..FILE_MAGIC_V1.len()] == FILE_MAGIC_V1 {
        (DEFAULT_PCRS.to_vec(), FILE_MAGIC_V1.len())
    } else if &blob[..FILE_MAGIC_V2.len()] == FILE_MAGIC_V2 {
        let mut off = FILE_MAGIC_V2.len();
        if off >= blob.len() { bail!("v2 sealed blob truncated before pcr_count"); }
        let pcr_count = blob[off] as usize;
        off += 1;
        if pcr_count == 0 || pcr_count > 24 {
            bail!("v2 sealed blob has invalid pcr_count={}", pcr_count);
        }
        if off + pcr_count > blob.len() {
            bail!("v2 sealed blob truncated in pcr_list");
        }
        let pcrs = blob[off..off + pcr_count].to_vec();
        off += pcr_count;
        validate_pcrs(&pcrs)?;
        (pcrs, off)
    } else {
        bail!("sealed blob magic mismatch — file isn't a key.tpm produced by this daemon");
    };

    let pub_len =
        u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    if pub_len > MAX_FIELD {
        bail!("sealed blob pub field too large ({} > {})", pub_len, MAX_FIELD);
    }
    off += 4;
    let pub_end = off
        .checked_add(pub_len)
        .and_then(|e| e.checked_add(4))
        .ok_or_else(|| anyhow!("sealed blob length arithmetic overflow (pub field)"))?;
    if pub_end > blob.len() {
        bail!("sealed blob truncated (pub field)");
    }
    let pub_bytes = blob[off..off + pub_len].to_vec();
    off += pub_len;
    let priv_len =
        u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    if priv_len > MAX_FIELD {
        bail!("sealed blob priv field too large ({} > {})", priv_len, MAX_FIELD);
    }
    off += 4;
    let blob_end = off
        .checked_add(priv_len)
        .ok_or_else(|| anyhow!("sealed blob length arithmetic overflow (priv field)"))?;
    if blob_end != blob.len() {
        bail!(
            "sealed blob length mismatch (priv field): expected {} more bytes, blob has {}",
            priv_len,
            blob.len() - off
        );
    }
    let priv_bytes = blob[off..off + priv_len].to_vec();
    Ok((pcrs, pub_bytes, priv_bytes))
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
    fn blob_roundtrip_v1_default_pcrs() {
        let pub_bytes = vec![1, 2, 3, 4, 5];
        let priv_bytes = vec![9, 8, 7];
        let blob = serialize_blob(DEFAULT_PCRS, &pub_bytes, &priv_bytes);
        assert_eq!(&blob[..FILE_MAGIC_V1.len()], FILE_MAGIC_V1,
            "default PCRs should still use v1 magic for backward compat");
        let (pcrs, p, q) = deserialize_blob(&blob).unwrap();
        assert_eq!(pcrs, DEFAULT_PCRS);
        assert_eq!(p, pub_bytes);
        assert_eq!(q, priv_bytes);
    }

    #[test]
    fn blob_roundtrip_v2_multi_pcrs() {
        let pcrs = vec![0u8, 4, 7, 11];
        let pub_bytes = vec![1, 2, 3, 4, 5];
        let priv_bytes = vec![9, 8, 7];
        let blob = serialize_blob(&pcrs, &pub_bytes, &priv_bytes);
        assert_eq!(&blob[..FILE_MAGIC_V2.len()], FILE_MAGIC_V2,
            "non-default PCRs should use v2 magic");
        let (got_pcrs, p, q) = deserialize_blob(&blob).unwrap();
        assert_eq!(got_pcrs, pcrs);
        assert_eq!(p, pub_bytes);
        assert_eq!(q, priv_bytes);
    }

    #[test]
    fn blob_rejects_wrong_magic() {
        let mut blob = serialize_blob(DEFAULT_PCRS, &[1, 2, 3], &[4, 5, 6]);
        blob[0] = b'X';
        assert!(deserialize_blob(&blob).is_err());
    }

    #[test]
    fn blob_rejects_truncated_pub() {
        let blob = serialize_blob(DEFAULT_PCRS, &[1, 2, 3, 4], &[5, 6]);
        let truncated = &blob[..blob.len() - 5];
        assert!(deserialize_blob(truncated).is_err());
    }

    #[test]
    fn blob_rejects_trailing_garbage() {
        let mut blob = serialize_blob(DEFAULT_PCRS, &[1, 2, 3], &[4, 5]);
        blob.push(0xff);
        assert!(deserialize_blob(&blob).is_err());
    }

    #[test]
    fn blob_rejects_oversized_pub_len() {
        let mut blob = Vec::new();
        blob.extend_from_slice(FILE_MAGIC_V1);
        blob.extend_from_slice(&(100_000u32).to_le_bytes());
        blob.extend_from_slice(&[0u8; 8]);
        let err = deserialize_blob(&blob).unwrap_err().to_string();
        assert!(err.contains("pub field too large"), "got: {err}");
    }

    #[test]
    fn blob_rejects_oversized_priv_len() {
        let mut blob = Vec::new();
        blob.extend_from_slice(FILE_MAGIC_V1);
        blob.extend_from_slice(&(0u32).to_le_bytes());
        blob.extend_from_slice(&(100_000u32).to_le_bytes());
        let err = deserialize_blob(&blob).unwrap_err().to_string();
        assert!(err.contains("priv field too large"), "got: {err}");
    }

    #[test]
    fn parse_pcr_list_accepts_canonical_forms() {
        assert_eq!(parse_pcr_list("7").unwrap(), vec![7u8]);
        assert_eq!(parse_pcr_list("7,11").unwrap(), vec![7u8, 11]);
        assert_eq!(parse_pcr_list("0,4,7,11").unwrap(), vec![0u8, 4, 7, 11]);
        assert_eq!(parse_pcr_list(" 7 , 11 ").unwrap(), vec![7u8, 11]);
    }

    #[test]
    fn parse_pcr_list_rejects_invalid() {
        assert!(parse_pcr_list("").is_err());
        assert!(parse_pcr_list("24").is_err());      // out of range
        assert!(parse_pcr_list("7,7").is_err());     // duplicate
        assert!(parse_pcr_list("seven").is_err());   // non-numeric
        assert!(parse_pcr_list("-1").is_err());      // negative
    }
}
