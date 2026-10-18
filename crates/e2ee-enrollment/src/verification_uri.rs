//! Strict non-secret QR transport for out-of-band verification digests.
//! The host must compare the scanned digest with the locally computed transcript.
//! Parsing alone does not authorize a new device or verify the other endpoint.

use super::{EnrollmentId, EnrollmentError, VerificationDigest};

const PREFIX: &str = "e2ee-verify-v1:";
const HEX: &[u8; 16] = b"0123456789abcdef";
const MAX_PAYLOAD_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationQrCode {
    pub enrollment_id: EnrollmentId,
    pub digest: VerificationDigest,
}

impl VerificationQrCode {
    pub fn encode(&self) -> String {
        let mut encoded = String::from(PREFIX);
        encoded.push_str(self.enrollment_id.as_str());
        encoded.push(':');
        for byte in self.digest.as_bytes() {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0xf) as usize] as char);
        }
        encoded
    }

    pub fn parse(text: &str) -> Result<Self, EnrollmentError> {
        if text.len() > MAX_PAYLOAD_BYTES || text.trim() != text {
            return Err(EnrollmentError::InvalidIdentifier);
        }
        let body = text.strip_prefix(PREFIX).ok_or(EnrollmentError::InvalidIdentifier)?;
        let (id, encoded) = body.rsplit_once(':').ok_or(EnrollmentError::InvalidIdentifier)?;
        let enrollment_id = EnrollmentId::parse(id)?;
        if encoded.len() != 64 || !encoded.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(EnrollmentError::InvalidIdentifier);
        }
        let mut digest = [0u8; 32];
        for (index, out) in digest.iter_mut().enumerate() {
            let part = encoded.get(index * 2..index * 2 + 2).ok_or(EnrollmentError::InvalidIdentifier)?;
            *out = u8::from_str_radix(part, 16).map_err(|_| EnrollmentError::InvalidIdentifier)?;
        }
        Ok(Self { enrollment_id, digest: VerificationDigest::new(digest) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_qr_roundtrip_binds_enrollment_to_transcript() {
        let source = VerificationQrCode {
            enrollment_id: EnrollmentId::parse("enroll:desktop-1").unwrap(),
            digest: VerificationDigest::new([0xab; 32]),
        };
        let parsed = VerificationQrCode::parse(&source.encode()).unwrap();
        assert_eq!(parsed, source);
        assert!(source.encode().ends_with(&"ab".repeat(32)));
    }

    #[test]
    fn noncanonical_and_malicious_qr_payloads_are_rejected() {
        let good = VerificationQrCode {
            enrollment_id: EnrollmentId::parse("id").unwrap(),
            digest: VerificationDigest::new([1; 32]),
        }.encode();
        for invalid in [
            good.to_uppercase(),
            format!("{} ", good),
            format!("{}?admin=1", good),
            good.replace("e2ee-verify-v1:", "https://example.org/"),
            good.replace("id:", "../id:"),
            "e2ee-verify-v1:id:123".to_string(),
        ] {
            assert!(VerificationQrCode::parse(&invalid).is_err());
        }
    }
}
