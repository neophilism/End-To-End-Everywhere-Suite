#![forbid(unsafe_code)]

//! E2E Capsule universal encrypted-envelope format.
//!
//! The wire format is deliberately transport-agnostic. Email, chat, browsers,
//! files, databases, and arbitrary applications can carry the same opaque
//! capsule bytes without becoming plaintext endpoints.

use std::collections::BTreeSet;
use std::fmt;

const MAGIC: [u8; 4] = *b"E2EC";
pub const FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientStanza {
    /// Opaque routing/decryption hint. It must not contain a human-readable
    /// recipient identity unless a higher-level profile explicitly permits it.
    pub recipient_hint: Vec<u8>,
    /// KEM or protocol-specific encapsulated key material.
    pub encapsulated_key: Vec<u8>,
    /// Content-encryption key wrapped for this recipient.
    pub wrapped_content_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    /// Exact registered cryptographic suite identifier selected by the caller.
    pub suite_id: String,
    pub recipients: Vec<RecipientStanza>,
    /// Encrypted application metadata such as content type, filename, message
    /// ID, timestamps, or application context.
    pub protected_header_ciphertext: Vec<u8>,
    /// Authenticated encrypted application payload.
    pub payload_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleLimits {
    pub max_recipients: usize,
    pub max_recipient_hint_bytes: usize,
    pub max_encapsulated_key_bytes: usize,
    pub max_wrapped_key_bytes: usize,
    pub max_protected_header_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for CapsuleLimits {
    fn default() -> Self {
        Self {
            max_recipients: 4096,
            max_recipient_hint_bytes: 128,
            max_encapsulated_key_bytes: 8192,
            max_wrapped_key_bytes: 8192,
            max_protected_header_bytes: 1024 * 1024,
            max_payload_bytes: 64 * 1024 * 1024,
            max_total_bytes: 72 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFlags,
    InvalidSuite,
    NoRecipients,
    TooManyRecipients,
    EmptyRecipientHint,
    DuplicateRecipientHint,
    EmptyEncapsulatedKey,
    EmptyWrappedKey,
    LimitExceeded,
    IntegerOverflow,
    Truncated,
    TrailingData,
    InvalidUtf8,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidMagic => "capsule magic is invalid",
            Self::UnsupportedVersion => "capsule format version is unsupported",
            Self::UnsupportedFlags => "capsule uses unsupported mandatory flags",
            Self::InvalidSuite => "capsule suite identifier is invalid",
            Self::NoRecipients => "capsule has no recipients",
            Self::TooManyRecipients => "capsule recipient count exceeds policy",
            Self::EmptyRecipientHint => "recipient hint must not be empty",
            Self::DuplicateRecipientHint => "recipient hints must be unique",
            Self::EmptyEncapsulatedKey => "recipient encapsulated key must not be empty",
            Self::EmptyWrappedKey => "recipient wrapped content key must not be empty",
            Self::LimitExceeded => "capsule exceeds configured resource limits",
            Self::IntegerOverflow => "capsule length cannot be represented safely",
            Self::Truncated => "capsule is truncated",
            Self::TrailingData => "capsule contains unexpected trailing data",
            Self::InvalidUtf8 => "capsule suite identifier is not valid UTF-8",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CapsuleError {}

impl Capsule {
    pub fn validate(&self, limits: CapsuleLimits) -> Result<(), CapsuleError> {
        if self.suite_id.is_empty()
            || !self
                .suite_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(CapsuleError::InvalidSuite);
        }
        if self.recipients.is_empty() {
            return Err(CapsuleError::NoRecipients);
        }
        if self.recipients.len() > limits.max_recipients {
            return Err(CapsuleError::TooManyRecipients);
        }
        if self.protected_header_ciphertext.len() > limits.max_protected_header_bytes
            || self.payload_ciphertext.len() > limits.max_payload_bytes
        {
            return Err(CapsuleError::LimitExceeded);
        }

        let mut hints = BTreeSet::new();
        for stanza in &self.recipients {
            if stanza.recipient_hint.is_empty() {
                return Err(CapsuleError::EmptyRecipientHint);
            }
            if stanza.recipient_hint.len() > limits.max_recipient_hint_bytes
                || stanza.encapsulated_key.len() > limits.max_encapsulated_key_bytes
                || stanza.wrapped_content_key.len() > limits.max_wrapped_key_bytes
            {
                return Err(CapsuleError::LimitExceeded);
            }
            if stanza.encapsulated_key.is_empty() {
                return Err(CapsuleError::EmptyEncapsulatedKey);
            }
            if stanza.wrapped_content_key.is_empty() {
                return Err(CapsuleError::EmptyWrappedKey);
            }
            if !hints.insert(stanza.recipient_hint.as_slice()) {
                return Err(CapsuleError::DuplicateRecipientHint);
            }
        }

        Ok(())
    }

    pub fn encode(&self, limits: CapsuleLimits) -> Result<Vec<u8>, CapsuleError> {
        self.validate(limits)?;

        let suite_len =
            u16::try_from(self.suite_id.len()).map_err(|_| CapsuleError::IntegerOverflow)?;
        let recipient_count =
            u32::try_from(self.recipients.len()).map_err(|_| CapsuleError::IntegerOverflow)?;
        let protected_len = u32::try_from(self.protected_header_ciphertext.len())
            .map_err(|_| CapsuleError::IntegerOverflow)?;
        let payload_len = u64::try_from(self.payload_ciphertext.len())
            .map_err(|_| CapsuleError::IntegerOverflow)?;

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        put_u16(&mut out, FORMAT_VERSION);
        put_u16(&mut out, 0);
        put_u16(&mut out, suite_len);
        out.extend_from_slice(self.suite_id.as_bytes());
        put_u32(&mut out, recipient_count);

        for stanza in &self.recipients {
            put_len_prefixed_u16(&mut out, &stanza.recipient_hint)?;
            put_len_prefixed_u32(&mut out, &stanza.encapsulated_key)?;
            put_len_prefixed_u32(&mut out, &stanza.wrapped_content_key)?;
        }

        put_u32(&mut out, protected_len);
        out.extend_from_slice(&self.protected_header_ciphertext);
        put_u64(&mut out, payload_len);
        out.extend_from_slice(&self.payload_ciphertext);

        if out.len() > limits.max_total_bytes {
            return Err(CapsuleError::LimitExceeded);
        }
        Ok(out)
    }

    pub fn decode(input: &[u8], limits: CapsuleLimits) -> Result<Self, CapsuleError> {
        if input.len() > limits.max_total_bytes {
            return Err(CapsuleError::LimitExceeded);
        }

        let mut cursor = Cursor::new(input);
        if cursor.take(4)? != MAGIC {
            return Err(CapsuleError::InvalidMagic);
        }

        if cursor.u16()? != FORMAT_VERSION {
            return Err(CapsuleError::UnsupportedVersion);
        }
        if cursor.u16()? != 0 {
            return Err(CapsuleError::UnsupportedFlags);
        }

        let suite_len = usize::from(cursor.u16()?);
        let suite_bytes = cursor.take(suite_len)?;
        let suite_id = std::str::from_utf8(suite_bytes)
            .map_err(|_| CapsuleError::InvalidUtf8)?
            .to_owned();

        let recipient_count =
            usize::try_from(cursor.u32()?).map_err(|_| CapsuleError::IntegerOverflow)?;
        if recipient_count == 0 {
            return Err(CapsuleError::NoRecipients);
        }
        if recipient_count > limits.max_recipients {
            return Err(CapsuleError::TooManyRecipients);
        }

        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipients.push(RecipientStanza {
                recipient_hint: cursor.len_prefixed_u16(limits.max_recipient_hint_bytes)?,
                encapsulated_key: cursor.len_prefixed_u32(limits.max_encapsulated_key_bytes)?,
                wrapped_content_key: cursor.len_prefixed_u32(limits.max_wrapped_key_bytes)?,
            });
        }

        let protected_len =
            usize::try_from(cursor.u32()?).map_err(|_| CapsuleError::IntegerOverflow)?;
        if protected_len > limits.max_protected_header_bytes {
            return Err(CapsuleError::LimitExceeded);
        }
        let protected_header_ciphertext = cursor.take(protected_len)?.to_vec();

        let payload_len =
            usize::try_from(cursor.u64()?).map_err(|_| CapsuleError::IntegerOverflow)?;
        if payload_len > limits.max_payload_bytes {
            return Err(CapsuleError::LimitExceeded);
        }
        let payload_ciphertext = cursor.take(payload_len)?.to_vec();

        if !cursor.is_finished() {
            return Err(CapsuleError::TrailingData);
        }

        let capsule = Self {
            suite_id,
            recipients,
            protected_header_ciphertext,
            payload_ciphertext,
        };
        capsule.validate(limits)?;
        Ok(capsule)
    }
}

fn put_len_prefixed_u16(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CapsuleError> {
    let len = u16::try_from(bytes.len()).map_err(|_| CapsuleError::IntegerOverflow)?;
    put_u16(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_len_prefixed_u32(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CapsuleError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CapsuleError::IntegerOverflow)?;
    put_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CapsuleError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CapsuleError::IntegerOverflow)?;
        if end > self.input.len() {
            return Err(CapsuleError::Truncated);
        }
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CapsuleError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| CapsuleError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, CapsuleError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CapsuleError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, CapsuleError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| CapsuleError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn len_prefixed_u16(&mut self, max: usize) -> Result<Vec<u8>, CapsuleError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(CapsuleError::LimitExceeded);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn len_prefixed_u32(&mut self, max: usize) -> Result<Vec<u8>, CapsuleError> {
        let len = usize::try_from(self.u32()?).map_err(|_| CapsuleError::IntegerOverflow)?;
        if len > max {
            return Err(CapsuleError::LimitExceeded);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule() -> Capsule {
        Capsule {
            suite_id: "HPKE-SUITE-1".into(),
            recipients: vec![
                RecipientStanza {
                    recipient_hint: vec![1; 16],
                    encapsulated_key: vec![2; 32],
                    wrapped_content_key: vec![3; 48],
                },
                RecipientStanza {
                    recipient_hint: vec![4; 16],
                    encapsulated_key: vec![5; 32],
                    wrapped_content_key: vec![6; 48],
                },
            ],
            protected_header_ciphertext: vec![7; 64],
            payload_ciphertext: vec![8; 512],
        }
    }

    #[test]
    fn deterministic_round_trip() {
        let limits = CapsuleLimits::default();
        let original = capsule();
        let encoded = original.encode(limits).unwrap();
        let decoded = Capsule::decode(&encoded, limits).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.encode(limits).unwrap(), encoded);
    }

    #[test]
    fn rejects_truncated_capsule() {
        let limits = CapsuleLimits::default();
        let mut encoded = capsule().encode(limits).unwrap();
        encoded.pop();
        assert_eq!(
            Capsule::decode(&encoded, limits),
            Err(CapsuleError::Truncated)
        );
    }

    #[test]
    fn rejects_trailing_data() {
        let limits = CapsuleLimits::default();
        let mut encoded = capsule().encode(limits).unwrap();
        encoded.push(0);
        assert_eq!(
            Capsule::decode(&encoded, limits),
            Err(CapsuleError::TrailingData)
        );
    }

    #[test]
    fn rejects_duplicate_recipient_hints() {
        let limits = CapsuleLimits::default();
        let mut candidate = capsule();
        candidate.recipients[1].recipient_hint = candidate.recipients[0].recipient_hint.clone();
        assert_eq!(
            candidate.validate(limits),
            Err(CapsuleError::DuplicateRecipientHint)
        );
    }

    #[test]
    fn rejects_payload_over_configured_limit_before_allocation() {
        let limits = CapsuleLimits {
            max_payload_bytes: 64,
            ..CapsuleLimits::default()
        };
        assert_eq!(
            capsule().validate(limits),
            Err(CapsuleError::LimitExceeded)
        );
    }

    #[test]
    fn rejects_unknown_version() {
        let limits = CapsuleLimits::default();
        let mut encoded = capsule().encode(limits).unwrap();
        encoded[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            Capsule::decode(&encoded, limits),
            Err(CapsuleError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_unknown_mandatory_flags() {
        let limits = CapsuleLimits::default();
        let mut encoded = capsule().encode(limits).unwrap();
        encoded[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            Capsule::decode(&encoded, limits),
            Err(CapsuleError::UnsupportedFlags)
        );
    }
}
