#![forbid(unsafe_code)]

//! Device enrollment and verification contracts.
//!
//! A newly enrolled device is not an authorized E2EE endpoint until both sides
//! of a pairing ceremony confirm the same verification transcript.

use e2ee_core::{DeviceId, EndpointId, UserId};
use e2ee_keystore::SecretHandle;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnrollmentId(String);

impl EnrollmentId {
    pub fn parse(value: &str) -> Result<Self, EnrollmentError> {
        validate_token(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_token(value: &str) -> Result<(), EnrollmentError> {
    if value.is_empty() {
        return Err(EnrollmentError::InvalidIdentifier);
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(EnrollmentError::InvalidIdentifier);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethod {
    QrScan,
    ShortAuthenticationString,
    OutOfBand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationSide {
    ExistingEndpoint,
    NewEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationDigest([u8; 32]);

impl VerificationDigest {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    pub enrollment_id: EnrollmentId,
    pub user_id: UserId,
    pub existing_endpoint_id: EndpointId,
    pub new_device_id: DeviceId,
    pub new_endpoint_id: EndpointId,
    pub new_endpoint_root: SecretHandle,
    pub challenge: [u8; 32],
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub verification_method: VerificationMethod,
}

impl PairingOffer {
    pub fn validate(&self) -> Result<(), EnrollmentError> {
        if self.expires_at_unix_seconds <= self.created_at_unix_seconds {
            return Err(EnrollmentError::InvalidExpiry);
        }
        if self.existing_endpoint_id == self.new_endpoint_id {
            return Err(EnrollmentError::EndpointReuse);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    Offered,
    Accepted,
    Verified,
    Finalized,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentError {
    InvalidIdentifier,
    InvalidExpiry,
    Expired,
    EndpointReuse,
    InvalidState,
    TranscriptMismatch,
    AlreadySubmitted,
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentifier => "enrollment identifier is invalid",
            Self::InvalidExpiry => "pairing expiry is invalid",
            Self::Expired => "pairing offer has expired",
            Self::EndpointReuse => "new endpoint must differ from existing endpoint",
            Self::InvalidState => "operation is not valid in the current pairing state",
            Self::TranscriptMismatch => "pairing verification transcripts do not match",
            Self::AlreadySubmitted => "verification was already submitted by this side",
        };
        f.write_str(message)
    }
}

impl std::error::Error for EnrollmentError {}

#[derive(Debug, Clone)]
pub struct PairingSession {
    offer: PairingOffer,
    state: PairingState,
    existing_digest: Option<VerificationDigest>,
    new_digest: Option<VerificationDigest>,
}

impl PairingSession {
    pub fn new(offer: PairingOffer, now_unix_seconds: u64) -> Result<Self, EnrollmentError> {
        offer.validate()?;
        if now_unix_seconds >= offer.expires_at_unix_seconds {
            return Err(EnrollmentError::Expired);
        }
        Ok(Self {
            offer,
            state: PairingState::Offered,
            existing_digest: None,
            new_digest: None,
        })
    }

    pub fn offer(&self) -> &PairingOffer {
        &self.offer
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn accept(&mut self, now_unix_seconds: u64) -> Result<(), EnrollmentError> {
        self.ensure_live(now_unix_seconds)?;
        if self.state != PairingState::Offered {
            return Err(EnrollmentError::InvalidState);
        }
        self.state = PairingState::Accepted;
        Ok(())
    }

    pub fn submit_verification(
        &mut self,
        side: VerificationSide,
        digest: VerificationDigest,
        now_unix_seconds: u64,
    ) -> Result<(), EnrollmentError> {
        self.ensure_live(now_unix_seconds)?;
        if self.state != PairingState::Accepted {
            return Err(EnrollmentError::InvalidState);
        }

        let slot = match side {
            VerificationSide::ExistingEndpoint => &mut self.existing_digest,
            VerificationSide::NewEndpoint => &mut self.new_digest,
        };
        if slot.is_some() {
            return Err(EnrollmentError::AlreadySubmitted);
        }
        *slot = Some(digest);

        if let (Some(existing), Some(new)) = (self.existing_digest, self.new_digest) {
            if existing != new {
                self.state = PairingState::Aborted;
                return Err(EnrollmentError::TranscriptMismatch);
            }
            self.state = PairingState::Verified;
        }

        Ok(())
    }

    pub fn finalize(&mut self, now_unix_seconds: u64) -> Result<(), EnrollmentError> {
        self.ensure_live(now_unix_seconds)?;
        if self.state != PairingState::Verified {
            return Err(EnrollmentError::InvalidState);
        }
        self.state = PairingState::Finalized;
        Ok(())
    }

    pub fn is_endpoint_authorized(&self) -> bool {
        self.state == PairingState::Finalized
    }

    fn ensure_live(&self, now_unix_seconds: u64) -> Result<(), EnrollmentError> {
        if now_unix_seconds >= self.offer.expires_at_unix_seconds {
            return Err(EnrollmentError::Expired);
        }
        if self.state == PairingState::Aborted || self.state == PairingState::Finalized {
            return Err(EnrollmentError::InvalidState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> PairingOffer {
        PairingOffer {
            enrollment_id: EnrollmentId::parse("enroll-1").unwrap(),
            user_id: UserId::parse("user-1").unwrap(),
            existing_endpoint_id: EndpointId::parse("endpoint-old").unwrap(),
            new_device_id: DeviceId::parse("device-new").unwrap(),
            new_endpoint_id: EndpointId::parse("endpoint-new").unwrap(),
            new_endpoint_root: SecretHandle::parse("device/root/new").unwrap(),
            challenge: [7; 32],
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            verification_method: VerificationMethod::QrScan,
        }
    }

    #[test]
    fn endpoint_is_not_authorized_before_completed_verification() {
        let mut session = PairingSession::new(offer(), 110).unwrap();
        assert!(!session.is_endpoint_authorized());

        session.accept(111).unwrap();
        let digest = VerificationDigest::new([9; 32]);
        session
            .submit_verification(VerificationSide::ExistingEndpoint, digest, 112)
            .unwrap();
        assert!(!session.is_endpoint_authorized());

        session
            .submit_verification(VerificationSide::NewEndpoint, digest, 113)
            .unwrap();
        assert_eq!(session.state(), PairingState::Verified);
        assert!(!session.is_endpoint_authorized());

        session.finalize(114).unwrap();
        assert!(session.is_endpoint_authorized());
    }

    #[test]
    fn mismatched_verification_aborts_pairing() {
        let mut session = PairingSession::new(offer(), 110).unwrap();
        session.accept(111).unwrap();
        session
            .submit_verification(
                VerificationSide::ExistingEndpoint,
                VerificationDigest::new([1; 32]),
                112,
            )
            .unwrap();

        assert_eq!(
            session.submit_verification(
                VerificationSide::NewEndpoint,
                VerificationDigest::new([2; 32]),
                113,
            ),
            Err(EnrollmentError::TranscriptMismatch)
        );
        assert_eq!(session.state(), PairingState::Aborted);
    }

    #[test]
    fn expired_offer_fails_closed() {
        assert!(matches!(
            PairingSession::new(offer(), 200),
            Err(EnrollmentError::Expired)
        ));
    }

    #[test]
    fn new_endpoint_must_be_distinct() {
        let mut invalid = offer();
        invalid.new_endpoint_id = invalid.existing_endpoint_id.clone();
        assert!(matches!(
            PairingSession::new(invalid, 110),
            Err(EnrollmentError::EndpointReuse)
        ));
    }
}
