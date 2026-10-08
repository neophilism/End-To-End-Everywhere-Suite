//! Shared recipient-roster authentication for multi-recipient Capsules.

use crate::{MessageError, RecipientPublicKey, E2EESA_MESSAGE_SUITE};
use e2ee_capsule::{CapsuleLimits, RecipientStanza};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Reject invalid or duplicate endpoints before generating content keys.
pub fn validate_recipient_keys(recipients: &[RecipientPublicKey]) -> Result<(), MessageError> {
    let hints: Vec<_> = recipients
        .iter()
        .map(|r| r.recipient_hint.as_slice())
        .collect();
    multi_recipient_context(b"validation", &hints)?;
    let mut keys = BTreeSet::new();
    for recipient in recipients {
        use hpke::{Deserializable, Kem};
        <hpke::kem::X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recipient.encoded_public_key)
            .map_err(|_| MessageError::InvalidPublicKey)?;
        if !keys.insert(recipient.encoded_public_key.as_slice()) {
            return Err(MessageError::DuplicateRecipientKey);
        }
    }
    Ok(())
}

/// Length-framed ordered roster, bound to an application-specific domain.
/// This is an application composition over RFC 9180, not a group protocol.
pub fn multi_recipient_context(domain: &[u8], hints: &[&[u8]]) -> Result<Vec<u8>, MessageError> {
    if hints.is_empty() || hints.len() > CapsuleLimits::default().max_recipients {
        return Err(MessageError::RecipientCount);
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    put_bytes(&mut out, domain);
    put_bytes(&mut out, E2EESA_MESSAGE_SUITE.as_bytes());
    out.extend_from_slice(&(hints.len() as u32).to_be_bytes());
    for hint in hints {
        super::validate_recipient_hint(hint)?;
        if !seen.insert(*hint) {
            return Err(MessageError::DuplicateRecipientHint);
        }
        put_bytes(&mut out, hint);
    }
    Ok(out)
}

/// Authenticate every stanza, including stanzas for other recipients, in the
/// content AEAD. A carrier cannot replace someone else's wrap undetected.
pub fn bind_recipient_stanzas(base: &[u8], stanzas: &[RecipientStanza]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"E2EC-RECIPIENT-STANZAS-V1");
    hash.update((stanzas.len() as u32).to_be_bytes());
    for stanza in stanzas {
        for field in [
            &stanza.recipient_hint,
            &stanza.encapsulated_key,
            &stanza.wrapped_content_key,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
    }
    let mut out = base.to_vec();
    out.extend_from_slice(&hash.finalize());
    out
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}
