#![forbid(unsafe_code)]

//! Detached signatures verify a Capsule against a separately trusted key.
//! The record is not a directory, certificate, identity proof or replay cache.

use e2ee_capsule::{Capsule, CapsuleLimits};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

pub mod local;

pub const SIGNATURE_ALGORITHM: &str = "ALG-ED25519";
pub const RECORD_VERSION: u16 = 1;
const MAGIC: &[u8; 4] = b"E2CS";
const MAX_CONTEXT: usize = 256;
const MAX_RECORD: usize = 4 + 2 + 2 + 32 + 32 + 2 + MAX_CONTEXT + 64;

pub struct CapsuleSigningKey(SigningKey);

impl CapsuleSigningKey {
    pub fn generate() -> Result<Self, ProvenanceError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *seed).map_err(|_| ProvenanceError::Randomness)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// For encrypted endpoint-state restoration. Never use a password as a seed.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl fmt::Debug for CapsuleSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapsuleSigningKey([REDACTED])")
    }
}

/// The caller pins this key through independent verification or a trusted
/// account/device authorization chain. No key is accepted from the signature.
#[derive(Clone)]
pub struct TrustedSigner(VerifyingKey);

impl TrustedSigner {
    pub fn from_public_key(bytes: [u8; 32]) -> Result<Self, ProvenanceError> {
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| ProvenanceError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(ProvenanceError::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    pub fn key_id(&self) -> [u8; 32] {
        key_id(self.0.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    pub version: u16,
    pub algorithm: String,
    pub signer_key_id: [u8; 32],
    pub capsule_digest: [u8; 32],
    pub context: String,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProvenance {
    pub signer_key_id: [u8; 32],
    pub capsule_digest: [u8; 32],
    pub context: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    Randomness,
    InvalidPublicKey,
    InvalidContext,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    MalformedRecord,
    SignerMismatch,
    ContextMismatch,
    CapsuleDigestMismatch,
    InvalidSignature,
    Capsule,
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Randomness => "secure randomness failed",
            Self::InvalidPublicKey => "signer public key is invalid or weak",
            Self::InvalidContext => "signature context is invalid",
            Self::UnsupportedVersion => "signature record version is unsupported",
            Self::UnsupportedAlgorithm => "signature algorithm is unsupported",
            Self::MalformedRecord => "signature record is malformed",
            Self::SignerMismatch => "signature does not match the independently trusted signer",
            Self::ContextMismatch => "signature context does not match the expected application",
            Self::CapsuleDigestMismatch => "signed Capsule digest does not match",
            Self::InvalidSignature => "Capsule signature verification failed",
            Self::Capsule => "Capsule framing or resource policy failed",
        })
    }
}

impl std::error::Error for ProvenanceError {}

pub fn sign_capsule(
    key: &CapsuleSigningKey,
    capsule: &Capsule,
    context: &str,
    limits: CapsuleLimits,
) -> Result<DetachedSignature, ProvenanceError> {
    validate_context(context)?;
    let mut record = DetachedSignature {
        version: RECORD_VERSION,
        algorithm: SIGNATURE_ALGORITHM.into(),
        signer_key_id: key_id(&key.public_key()),
        capsule_digest: capsule_digest(capsule, limits)?,
        context: context.into(),
        signature: [0; 64],
    };
    record.signature = key.0.sign(&signing_message(&record)).to_bytes();
    Ok(record)
}

pub fn verify_capsule_signature(
    trusted_signer: &TrustedSigner,
    capsule: &Capsule,
    record: &DetachedSignature,
    expected_context: &str,
    limits: CapsuleLimits,
) -> Result<VerifiedProvenance, ProvenanceError> {
    record.validate()?;
    validate_context(expected_context)?;
    if record.signer_key_id != trusted_signer.key_id() {
        return Err(ProvenanceError::SignerMismatch);
    }
    if record.context != expected_context {
        return Err(ProvenanceError::ContextMismatch);
    }
    if record.capsule_digest != capsule_digest(capsule, limits)? {
        return Err(ProvenanceError::CapsuleDigestMismatch);
    }
    trusted_signer
        .0
        .verify_strict(
            &signing_message(record),
            &Signature::from_bytes(&record.signature),
        )
        .map_err(|_| ProvenanceError::InvalidSignature)?;
    Ok(VerifiedProvenance {
        signer_key_id: record.signer_key_id,
        capsule_digest: record.capsule_digest,
        context: record.context.clone(),
    })
}

impl DetachedSignature {
    fn validate(&self) -> Result<(), ProvenanceError> {
        if self.version != RECORD_VERSION {
            return Err(ProvenanceError::UnsupportedVersion);
        }
        if self.algorithm != SIGNATURE_ALGORITHM {
            return Err(ProvenanceError::UnsupportedAlgorithm);
        }
        validate_context(&self.context)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceError> {
        self.validate()?;
        let mut out = Vec::with_capacity(MAX_RECORD);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes()); // ALG-ED25519
        out.extend_from_slice(&self.signer_key_id);
        out.extend_from_slice(&self.capsule_digest);
        out.extend_from_slice(&(self.context.len() as u16).to_be_bytes());
        out.extend_from_slice(self.context.as_bytes());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProvenanceError> {
        const PREFIX: usize = 4 + 2 + 2 + 32 + 32 + 2;
        if bytes.len() < PREFIX + 64 || bytes.len() > MAX_RECORD || &bytes[..4] != MAGIC {
            return Err(ProvenanceError::MalformedRecord);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != RECORD_VERSION {
            return Err(ProvenanceError::UnsupportedVersion);
        }
        if bytes[6..8] != 1_u16.to_be_bytes() {
            return Err(ProvenanceError::UnsupportedAlgorithm);
        }
        let context_len = usize::from(u16::from_be_bytes([bytes[72], bytes[73]]));
        if context_len > MAX_CONTEXT || bytes.len() != PREFIX + context_len + 64 {
            return Err(ProvenanceError::MalformedRecord);
        }
        let record = Self {
            version,
            algorithm: SIGNATURE_ALGORITHM.into(),
            signer_key_id: bytes[8..40]
                .try_into()
                .map_err(|_| ProvenanceError::MalformedRecord)?,
            capsule_digest: bytes[40..72]
                .try_into()
                .map_err(|_| ProvenanceError::MalformedRecord)?,
            context: std::str::from_utf8(&bytes[PREFIX..PREFIX + context_len])
                .map_err(|_| ProvenanceError::InvalidContext)?
                .into(),
            signature: bytes[PREFIX + context_len..]
                .try_into()
                .map_err(|_| ProvenanceError::MalformedRecord)?,
        };
        record.validate()?;
        Ok(record)
    }
}

fn validate_context(context: &str) -> Result<(), ProvenanceError> {
    if context.is_empty()
        || context.len() > MAX_CONTEXT
        || !context.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ProvenanceError::InvalidContext);
    }
    Ok(())
}

fn key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"E2EC-SIGNER-KEY-ID-V1");
    hash.update(public_key);
    hash.finalize().into()
}

fn capsule_digest(capsule: &Capsule, limits: CapsuleLimits) -> Result<[u8; 32], ProvenanceError> {
    let encoded = capsule
        .encode(limits)
        .map_err(|_| ProvenanceError::Capsule)?;
    Ok(Sha256::digest(encoded).into())
}

fn signing_message(record: &DetachedSignature) -> Vec<u8> {
    let mut out = b"End-To-End Everywhere Capsule detached signature v1".to_vec();
    out.extend_from_slice(&record.version.to_be_bytes());
    out.extend_from_slice(&(record.algorithm.len() as u16).to_be_bytes());
    out.extend_from_slice(record.algorithm.as_bytes());
    out.extend_from_slice(&record.signer_key_id);
    out.extend_from_slice(&(record.context.len() as u16).to_be_bytes());
    out.extend_from_slice(record.context.as_bytes());
    out.extend_from_slice(&record.capsule_digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2ee_message::{encrypt_text, generate_recipient_keypair, RecipientPublicKey};

    fn capsule() -> Capsule {
        let pair = generate_recipient_keypair();
        encrypt_text(
            &RecipientPublicKey {
                recipient_hint: vec![1; 16],
                encoded_public_key: pair.public_key,
            },
            "signed",
            None,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_verifies_against_separately_pinned_key() {
        let key = CapsuleSigningKey::generate().unwrap();
        let capsule = capsule();
        let signature =
            sign_capsule(&key, &capsule, "email/message", CapsuleLimits::default()).unwrap();
        let decoded = DetachedSignature::decode(&signature.encode().unwrap()).unwrap();
        assert_eq!(signature, decoded);
        let trusted = TrustedSigner::from_public_key(key.public_key()).unwrap();
        let verified = verify_capsule_signature(
            &trusted,
            &capsule,
            &decoded,
            "email/message",
            CapsuleLimits::default(),
        )
        .unwrap();
        assert_eq!(verified.signer_key_id, trusted.key_id());
        assert_eq!(format!("{key:?}"), "CapsuleSigningKey([REDACTED])");
    }

    #[test]
    fn attacker_cannot_substitute_a_new_self_signed_key() {
        let trusted_key = CapsuleSigningKey::generate().unwrap();
        let attacker = CapsuleSigningKey::generate().unwrap();
        let trusted = TrustedSigner::from_public_key(trusted_key.public_key()).unwrap();
        let capsule = capsule();
        let mut signature =
            sign_capsule(&attacker, &capsule, "app/v1", CapsuleLimits::default()).unwrap();
        assert_eq!(
            verify_capsule_signature(
                &trusted,
                &capsule,
                &signature,
                "app/v1",
                CapsuleLimits::default()
            ),
            Err(ProvenanceError::SignerMismatch)
        );
        signature.signer_key_id = trusted.key_id();
        assert_eq!(
            verify_capsule_signature(
                &trusted,
                &capsule,
                &signature,
                "app/v1",
                CapsuleLimits::default()
            ),
            Err(ProvenanceError::InvalidSignature)
        );
    }

    #[test]
    fn signature_binds_every_capsule_field_and_application_context() {
        let key = CapsuleSigningKey::generate().unwrap();
        let trusted = TrustedSigner::from_public_key(key.public_key()).unwrap();
        let original = capsule();
        let signature = sign_capsule(&key, &original, "app/v1", CapsuleLimits::default()).unwrap();
        let mut mutations = vec![original.clone(); 5];
        mutations[0].payload_ciphertext[0] ^= 1;
        mutations[1].protected_header_ciphertext[0] ^= 1;
        mutations[2].recipients[0].wrapped_content_key[0] ^= 1;
        mutations[3].recipients[0].recipient_hint[0] ^= 1;
        mutations[4].suite_id.push('X');
        for altered in mutations {
            assert_eq!(
                verify_capsule_signature(
                    &trusted,
                    &altered,
                    &signature,
                    "app/v1",
                    CapsuleLimits::default()
                ),
                Err(ProvenanceError::CapsuleDigestMismatch)
            );
        }
        assert_eq!(
            verify_capsule_signature(
                &trusted,
                &original,
                &signature,
                "other/v1",
                CapsuleLimits::default()
            ),
            Err(ProvenanceError::ContextMismatch)
        );
        let mut forged_context = signature.clone();
        forged_context.context = "other/v1".into();
        assert_eq!(
            verify_capsule_signature(
                &trusted,
                &original,
                &forged_context,
                "other/v1",
                CapsuleLimits::default()
            ),
            Err(ProvenanceError::InvalidSignature)
        );
        let mut modified_signature = signature;
        modified_signature.signature[0] ^= 1;
        assert_eq!(
            verify_capsule_signature(
                &trusted,
                &original,
                &modified_signature,
                "app/v1",
                CapsuleLimits::default()
            ),
            Err(ProvenanceError::InvalidSignature)
        );
    }

    #[test]
    fn parser_rejects_all_truncations_trailing_data_and_unknown_versions() {
        let key = CapsuleSigningKey::generate().unwrap();
        let record = sign_capsule(&key, &capsule(), "app/v1", CapsuleLimits::default()).unwrap();
        let bytes = record.encode().unwrap();
        for n in 0..bytes.len() {
            assert!(DetachedSignature::decode(&bytes[..n]).is_err());
        }
        let mut appended = bytes.clone();
        appended.push(0);
        assert!(DetachedSignature::decode(&appended).is_err());
        let mut version = bytes.clone();
        version[5] = 2;
        assert_eq!(
            DetachedSignature::decode(&version),
            Err(ProvenanceError::UnsupportedVersion)
        );
        let mut algorithm = bytes;
        algorithm[7] = 2;
        assert_eq!(
            DetachedSignature::decode(&algorithm),
            Err(ProvenanceError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn weak_keys_and_empty_or_overlong_contexts_are_rejected() {
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(matches!(
            TrustedSigner::from_public_key(identity),
            Err(ProvenanceError::InvalidPublicKey)
        ));
        let key = CapsuleSigningKey::generate().unwrap();
        for invalid in ["", "line\nbreak", &"x".repeat(MAX_CONTEXT + 1)] {
            assert_eq!(
                sign_capsule(&key, &capsule(), invalid, CapsuleLimits::default()),
                Err(ProvenanceError::InvalidContext)
            );
        }
    }

    #[test]
    fn rfc8032_section_7_1_test_vector_one_verifies_strictly() {
        fn hex<const N: usize>(input: &str) -> [u8; N] {
            let mut result = [0; N];
            for (i, byte) in result.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&input[i * 2..i * 2 + 2], 16).unwrap();
            }
            result
        }
        let seed = hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected = hex::<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(key.verifying_key().to_bytes(), public);
        assert_eq!(key.sign(b"").to_bytes(), expected);
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify_strict(b"", &Signature::from_bytes(&expected))
            .unwrap();
    }
}
