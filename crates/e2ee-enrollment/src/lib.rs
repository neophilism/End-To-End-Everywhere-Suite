#![forbid(unsafe_code)]

//! Device enrollment and verification contracts.
//!
//! A newly enrolled device is not an authorized E2EE endpoint until both sides
//! of a pairing ceremony confirm the same verification transcript.

use e2ee_core::{DeviceId, EndpointId, UserId};
use e2ee_keystore::SecretHandle;
use std::{collections::BTreeMap, fmt};

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
    finalized_at_unix_seconds: Option<u64>,
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
            finalized_at_unix_seconds: None,
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
        self.finalized_at_unix_seconds = Some(now_unix_seconds);
        Ok(())
    }

    pub fn authorization(&self) -> Result<DeviceAuthorization, EnrollmentError> {
        if self.state != PairingState::Finalized {
            return Err(EnrollmentError::InvalidState);
        }
        Ok(DeviceAuthorization {
            user_id: self.offer.user_id.clone(),
            device_id: self.offer.new_device_id.clone(),
            endpoint_id: self.offer.new_endpoint_id.clone(),
            authorized_at_unix_seconds: self
                .finalized_at_unix_seconds
                .ok_or(EnrollmentError::InvalidState)?,
            source: AuthorizationSource::Pairing {
                enrollment_id: self.offer.enrollment_id.clone(),
                authorized_by: self.offer.existing_endpoint_id.clone(),
                verification_digest: self
                    .existing_digest
                    .ok_or(EnrollmentError::InvalidState)?,
            },
        })
    }

    pub fn is_endpoint_authorized(&self) -> bool {
        self.authorization().is_ok()
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


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationSource {
    TrustedBootstrap,
    Pairing {
        enrollment_id: EnrollmentId,
        authorized_by: EndpointId,
        verification_digest: VerificationDigest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub endpoint_id: EndpointId,
    pub authorized_at_unix_seconds: u64,
    pub source: AuthorizationSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    pub endpoint_id: EndpointId,
    pub revoked_by: EndpointId,
    pub revoked_at_unix_seconds: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRosterError {
    UserMismatch,
    EndpointAlreadyKnown,
    EndpointNotAuthorized,
    AuthorizerNotAuthorized,
    InvalidAuthorizationSource,
    SelfRevocation,
    ClockRegression,
    RevisionExhausted,
}

impl fmt::Display for DeviceRosterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UserMismatch => "device authorization belongs to a different user",
            Self::EndpointAlreadyKnown => "endpoint was already authorized or revoked",
            Self::EndpointNotAuthorized => "target endpoint is not currently authorized",
            Self::AuthorizerNotAuthorized => "authorizing endpoint is not currently authorized",
            Self::InvalidAuthorizationSource => {
                "paired device must carry a finalized pairing authorization"
            }
            Self::SelfRevocation => "an endpoint cannot revoke itself",
            Self::ClockRegression => "device lifecycle timestamp moved backwards",
            Self::RevisionExhausted => "device roster revision is exhausted",
        };
        f.write_str(message)
    }
}

impl std::error::Error for DeviceRosterError {}

#[derive(Debug, Clone)]
pub struct DeviceRoster {
    user_id: UserId,
    revision: u64,
    authorizations: BTreeMap<EndpointId, DeviceAuthorization>,
    revocations: BTreeMap<EndpointId, DeviceRevocation>,
}

impl DeviceRoster {
    /// Creates a roster from an endpoint established by a separate trusted
    /// account bootstrap. Restoring this anchor requires host-level integrity
    /// and rollback protection outside this portable state machine.
    pub fn from_trusted_bootstrap(
        user_id: UserId,
        device_id: DeviceId,
        endpoint_id: EndpointId,
        authorized_at_unix_seconds: u64,
    ) -> Self {
        let authorization = DeviceAuthorization {
            user_id: user_id.clone(),
            device_id,
            endpoint_id: endpoint_id.clone(),
            authorized_at_unix_seconds,
            source: AuthorizationSource::TrustedBootstrap,
        };
        Self {
            user_id,
            revision: 1,
            authorizations: BTreeMap::from([(endpoint_id, authorization)]),
            revocations: BTreeMap::new(),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn authorization(&self, endpoint_id: &EndpointId) -> Option<&DeviceAuthorization> {
        self.is_authorized(endpoint_id)
            .then(|| self.authorizations.get(endpoint_id))
            .flatten()
    }

    pub fn revocation(&self, endpoint_id: &EndpointId) -> Option<&DeviceRevocation> {
        self.revocations.get(endpoint_id)
    }

    pub fn is_authorized(&self, endpoint_id: &EndpointId) -> bool {
        self.authorizations.contains_key(endpoint_id)
            && !self.revocations.contains_key(endpoint_id)
    }

    pub fn register_paired(
        &mut self,
        authorization: DeviceAuthorization,
    ) -> Result<u64, DeviceRosterError> {
        if authorization.user_id != self.user_id {
            return Err(DeviceRosterError::UserMismatch);
        }
        if self.authorizations.contains_key(&authorization.endpoint_id)
            || self.revocations.contains_key(&authorization.endpoint_id)
        {
            return Err(DeviceRosterError::EndpointAlreadyKnown);
        }

        let authorized_by = match &authorization.source {
            AuthorizationSource::Pairing { authorized_by, .. } => authorized_by,
            AuthorizationSource::TrustedBootstrap => {
                return Err(DeviceRosterError::InvalidAuthorizationSource)
            }
        };
        let parent = self
            .authorization(authorized_by)
            .ok_or(DeviceRosterError::AuthorizerNotAuthorized)?;
        if authorization.authorized_at_unix_seconds < parent.authorized_at_unix_seconds {
            return Err(DeviceRosterError::ClockRegression);
        }

        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DeviceRosterError::RevisionExhausted)?;
        self.authorizations
            .insert(authorization.endpoint_id.clone(), authorization);
        Ok(self.revision)
    }

    pub fn revoke(
        &mut self,
        endpoint_id: &EndpointId,
        revoked_by: &EndpointId,
        revoked_at_unix_seconds: u64,
    ) -> Result<DeviceRevocation, DeviceRosterError> {
        if endpoint_id == revoked_by {
            return Err(DeviceRosterError::SelfRevocation);
        }
        let target = self
            .authorization(endpoint_id)
            .ok_or(DeviceRosterError::EndpointNotAuthorized)?;
        let authorizer = self
            .authorization(revoked_by)
            .ok_or(DeviceRosterError::AuthorizerNotAuthorized)?;
        if revoked_at_unix_seconds < target.authorized_at_unix_seconds
            || revoked_at_unix_seconds < authorizer.authorized_at_unix_seconds
        {
            return Err(DeviceRosterError::ClockRegression);
        }

        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DeviceRosterError::RevisionExhausted)?;
        let revocation = DeviceRevocation {
            endpoint_id: endpoint_id.clone(),
            revoked_by: revoked_by.clone(),
            revoked_at_unix_seconds,
            revision,
        };
        self.revision = revision;
        self.revocations
            .insert(endpoint_id.clone(), revocation.clone());
        Ok(revocation)
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
    fn finalized_session(mut pairing_offer: PairingOffer) -> PairingSession {
        let mut session = PairingSession::new(pairing_offer.clone(), 110).unwrap();
        session.accept(111).unwrap();
        let digest = VerificationDigest::new([9; 32]);
        session
            .submit_verification(VerificationSide::ExistingEndpoint, digest, 112)
            .unwrap();
        session
            .submit_verification(VerificationSide::NewEndpoint, digest, 113)
            .unwrap();
        session.finalize(114).unwrap();
        pairing_offer.challenge.fill(0);
        session
    }

    #[test]
    fn finalized_pairing_registers_only_under_its_active_authorizer() {
        let session = finalized_session(offer());
        let authorization = session.authorization().unwrap();
        let existing = session.offer().existing_endpoint_id.clone();
        let mut roster = DeviceRoster::from_trusted_bootstrap(
            session.offer().user_id.clone(),
            DeviceId::parse("device-old").unwrap(),
            existing,
            100,
        );

        assert_eq!(roster.register_paired(authorization).unwrap(), 2);
        assert!(roster.is_authorized(&session.offer().new_endpoint_id));
    }

    #[test]
    fn unfinished_or_cross_user_pairing_never_authorizes() {
        let session = PairingSession::new(offer(), 110).unwrap();
        assert_eq!(session.authorization(), Err(EnrollmentError::InvalidState));

        let completed = finalized_session(offer());
        let mut roster = DeviceRoster::from_trusted_bootstrap(
            UserId::parse("different-user").unwrap(),
            DeviceId::parse("device-old").unwrap(),
            completed.offer().existing_endpoint_id.clone(),
            100,
        );
        assert_eq!(
            roster.register_paired(completed.authorization().unwrap()),
            Err(DeviceRosterError::UserMismatch)
        );
    }

    #[test]
    fn revocation_is_immediate_irreversible_and_replay_safe() {
        let session = finalized_session(offer());
        let authorization = session.authorization().unwrap();
        let existing = session.offer().existing_endpoint_id.clone();
        let target = session.offer().new_endpoint_id.clone();
        let mut roster = DeviceRoster::from_trusted_bootstrap(
            session.offer().user_id.clone(),
            DeviceId::parse("device-old").unwrap(),
            existing.clone(),
            100,
        );
        roster.register_paired(authorization.clone()).unwrap();

        let revocation = roster.revoke(&target, &existing, 120).unwrap();
        assert_eq!(revocation.revision, 3);
        assert!(!roster.is_authorized(&target));
        assert!(roster.revocation(&target).is_some());
        assert_eq!(
            roster.register_paired(authorization),
            Err(DeviceRosterError::EndpointAlreadyKnown)
        );
    }

    #[test]
    fn revoked_endpoint_cannot_authorize_another_device() {
        let first = finalized_session(offer());
        let existing = first.offer().existing_endpoint_id.clone();
        let revoked = first.offer().new_endpoint_id.clone();
        let mut roster = DeviceRoster::from_trusted_bootstrap(
            first.offer().user_id.clone(),
            DeviceId::parse("device-old").unwrap(),
            existing.clone(),
            100,
        );
        roster.register_paired(first.authorization().unwrap()).unwrap();
        roster.revoke(&revoked, &existing, 120).unwrap();

        let mut next_offer = offer();
        next_offer.enrollment_id = EnrollmentId::parse("enroll-2").unwrap();
        next_offer.existing_endpoint_id = revoked;
        next_offer.new_device_id = DeviceId::parse("device-third").unwrap();
        next_offer.new_endpoint_id = EndpointId::parse("endpoint-third").unwrap();
        let next = finalized_session(next_offer);
        assert_eq!(
            roster.register_paired(next.authorization().unwrap()),
            Err(DeviceRosterError::AuthorizerNotAuthorized)
        );
    }


}
