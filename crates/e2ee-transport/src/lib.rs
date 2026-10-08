#![forbid(unsafe_code)]

//! Transport encodings carry ciphertext and optional provenance together.
//! Parsing never implies signature verification or recipient decryption.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use e2ee_capsule::{Capsule, CapsuleLimits};
use e2ee_provenance::{
    verify_capsule_signature, DetachedSignature, TrustedSigner, VerifiedProvenance,
};
use std::fmt;

pub const DELIVERY_VERSION: u16 = 1;
/// Experimental vendor media type; this repository does not claim IANA registration.
pub const DELIVERY_MEDIA_TYPE: &str = "application/vnd.e2ee.delivery;version=1";
pub const DELIVERY_EXTENSION: &str = "e2ed";
pub const DEFAULT_MAX_URI_BYTES: usize = 8192;
const BEGIN: &str = "-----BEGIN E2E DELIVERY-----";
const END: &str = "-----END E2E DELIVERY-----";
const URI_PREFIX: &str = "e2ed:v1:";
const MAX_SIGNATURE: usize = 512;
const FIXED_BYTES: usize = 4 + 2 + 2 + 8 + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub capsule: Capsule,
    pub signature: Option<DetachedSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    LimitExceeded,
    Malformed,
    UnsupportedVersion,
    UnsupportedFlags,
    InvalidEncoding,
    UnsupportedMediaType,
    Capsule,
    Signature,
    MissingSignature,
    UnverifiedSignature,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LimitExceeded => "delivery exceeds the configured resource limit",
            Self::Malformed => "delivery framing is malformed",
            Self::UnsupportedVersion => "delivery version is unsupported",
            Self::UnsupportedFlags => "delivery flags are unsupported",
            Self::InvalidEncoding => "delivery text encoding is invalid",
            Self::UnsupportedMediaType => "delivery media type is unsupported",
            Self::Capsule => "Capsule framing is invalid",
            Self::Signature => "signature record framing is invalid",
            Self::MissingSignature => "required Capsule signature is missing",
            Self::UnverifiedSignature => "required Capsule signature did not verify",
        })
    }
}

impl std::error::Error for TransportError {}

impl Delivery {
    pub fn encode(&self, limits: CapsuleLimits) -> Result<Vec<u8>, TransportError> {
        let capsule = self
            .capsule
            .encode(limits)
            .map_err(|_| TransportError::Capsule)?;
        let signature = match &self.signature {
            Some(record) => record.encode().map_err(|_| TransportError::Signature)?,
            None => Vec::new(),
        };
        let mut out = Vec::with_capacity(capsule.len() + signature.len() + FIXED_BYTES);
        out.extend_from_slice(b"E2ED");
        out.extend_from_slice(&DELIVERY_VERSION.to_be_bytes());
        out.extend_from_slice(&u16::from(self.signature.is_some()).to_be_bytes());
        out.extend_from_slice(&(capsule.len() as u64).to_be_bytes());
        out.extend_from_slice(&capsule);
        out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], limits: CapsuleLimits) -> Result<Self, TransportError> {
        if bytes.len() > delivery_limit(limits)? {
            return Err(TransportError::LimitExceeded);
        }
        if bytes.len() < FIXED_BYTES || &bytes[..4] != b"E2ED" {
            return Err(TransportError::Malformed);
        }
        if bytes[4..6] != DELIVERY_VERSION.to_be_bytes() {
            return Err(TransportError::UnsupportedVersion);
        }
        let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
        if flags > 1 {
            return Err(TransportError::UnsupportedFlags);
        }
        let capsule_len = usize::try_from(u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| TransportError::Malformed)?,
        ))
        .map_err(|_| TransportError::LimitExceeded)?;
        if capsule_len > limits.max_total_bytes {
            return Err(TransportError::LimitExceeded);
        }
        let signature_offset = 16_usize
            .checked_add(capsule_len)
            .ok_or(TransportError::LimitExceeded)?;
        let signature_start = signature_offset
            .checked_add(2)
            .ok_or(TransportError::LimitExceeded)?;
        if signature_start > bytes.len() {
            return Err(TransportError::Malformed);
        }
        let signature_len = usize::from(u16::from_be_bytes([
            bytes[signature_offset],
            bytes[signature_offset + 1],
        ]));
        if signature_len > MAX_SIGNATURE
            || signature_start.checked_add(signature_len) != Some(bytes.len())
        {
            return Err(TransportError::Malformed);
        }
        if (flags == 0 && signature_len != 0) || (flags == 1 && signature_len == 0) {
            return Err(TransportError::Malformed);
        }
        let capsule = Capsule::decode(&bytes[16..signature_offset], limits)
            .map_err(|_| TransportError::Capsule)?;
        let signature = if flags == 1 {
            Some(
                DetachedSignature::decode(&bytes[signature_start..])
                    .map_err(|_| TransportError::Signature)?,
            )
        } else {
            None
        };
        Ok(Self { capsule, signature })
    }

    /// Applications requiring provenance call this before decrypting/displaying.
    /// An unsigned delivery never silently satisfies the required-signature policy.
    pub fn verify_required_signature(
        &self,
        signer: &TrustedSigner,
        expected_context: &str,
        limits: CapsuleLimits,
    ) -> Result<VerifiedProvenance, TransportError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or(TransportError::MissingSignature)?;
        verify_capsule_signature(signer, &self.capsule, signature, expected_context, limits)
            .map_err(|_| TransportError::UnverifiedSignature)
    }
}

/// ASCII armor uses padded RFC 4648 Base64 with 76-character lines.
pub fn encode_armored(
    delivery: &Delivery,
    limits: CapsuleLimits,
) -> Result<String, TransportError> {
    let body = STANDARD.encode(delivery.encode(limits)?);
    let mut out = format!("{BEGIN}\n");
    for line in body.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).map_err(|_| TransportError::InvalidEncoding)?);
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    Ok(out)
}

pub fn decode_armored(input: &str, limits: CapsuleLimits) -> Result<Delivery, TransportError> {
    let max_encoded = encoded_limit(limits)?;
    let max_text = max_encoded
        .checked_add(max_encoded.div_ceil(76).saturating_mul(2))
        .and_then(|n| n.checked_add(BEGIN.len() + END.len() + 4))
        .ok_or(TransportError::LimitExceeded)?;
    if input.len() > max_text {
        return Err(TransportError::LimitExceeded);
    }
    let input = input.strip_suffix('\n').unwrap_or(input);
    let mut lines = input
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    if lines.next() != Some(BEGIN) {
        return Err(TransportError::InvalidEncoding);
    }
    let mut body = String::new();
    let mut ended = false;
    for line in lines.by_ref() {
        if line == END {
            ended = true;
            break;
        }
        if line.is_empty()
            || line.len() > 76
            || !line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err(TransportError::InvalidEncoding);
        }
        if body
            .len()
            .checked_add(line.len())
            .filter(|n| *n <= max_encoded)
            .is_none()
        {
            return Err(TransportError::LimitExceeded);
        }
        body.push_str(line);
    }
    if !ended || lines.next().is_some() || body.is_empty() {
        return Err(TransportError::InvalidEncoding);
    }
    let bytes = STANDARD
        .decode(body)
        .map_err(|_| TransportError::InvalidEncoding)?;
    Delivery::decode(&bytes, limits)
}

/// Local application handoff only: never places data in an HTTP query string.
pub fn encode_uri(
    delivery: &Delivery,
    limits: CapsuleLimits,
    max_uri_bytes: usize,
) -> Result<String, TransportError> {
    let bytes = delivery.encode(limits)?;
    let encoded_len = bytes
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .map(|n| n / 3)
        .and_then(|n| n.checked_add(URI_PREFIX.len()))
        .ok_or(TransportError::LimitExceeded)?;
    if encoded_len > max_uri_bytes {
        return Err(TransportError::LimitExceeded);
    }
    Ok(format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

pub fn decode_uri(
    input: &str,
    limits: CapsuleLimits,
    max_uri_bytes: usize,
) -> Result<Delivery, TransportError> {
    if input.len() > max_uri_bytes
        || input.len() > encoded_limit(limits)?.saturating_add(URI_PREFIX.len())
    {
        return Err(TransportError::LimitExceeded);
    }
    let body = input
        .strip_prefix(URI_PREFIX)
        .ok_or(TransportError::InvalidEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| TransportError::InvalidEncoding)?;
    Delivery::decode(&bytes, limits)
}

pub fn decode_attachment(
    media_type: &str,
    bytes: &[u8],
    limits: CapsuleLimits,
) -> Result<Delivery, TransportError> {
    if media_type != DELIVERY_MEDIA_TYPE {
        return Err(TransportError::UnsupportedMediaType);
    }
    Delivery::decode(bytes, limits)
}

fn delivery_limit(limits: CapsuleLimits) -> Result<usize, TransportError> {
    limits
        .max_total_bytes
        .checked_add(FIXED_BYTES + MAX_SIGNATURE)
        .ok_or(TransportError::LimitExceeded)
}

fn encoded_limit(limits: CapsuleLimits) -> Result<usize, TransportError> {
    delivery_limit(limits)?
        .checked_add(2)
        .map(|n| n / 3)
        .and_then(|n| n.checked_mul(4))
        .ok_or(TransportError::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2ee_message::{encrypt_text, generate_recipient_keypair, RecipientPublicKey};
    use e2ee_provenance::{sign_capsule, CapsuleSigningKey};

    fn signed() -> (Delivery, TrustedSigner) {
        let pair = generate_recipient_keypair();
        let capsule = encrypt_text(
            &RecipientPublicKey {
                recipient_hint: vec![1; 16],
                encoded_public_key: pair.public_key,
            },
            "private message",
            None,
        )
        .unwrap();
        let key = CapsuleSigningKey::generate().unwrap();
        let signer = TrustedSigner::from_public_key(key.public_key()).unwrap();
        let signature =
            sign_capsule(&key, &capsule, "delivery/v1", CapsuleLimits::default()).unwrap();
        (
            Delivery {
                capsule,
                signature: Some(signature),
            },
            signer,
        )
    }

    #[test]
    fn signed_deliveries_preserve_provenance_in_every_encoding() {
        let (delivery, signer) = signed();
        let limits = CapsuleLimits::default();
        let armor = encode_armored(&delivery, limits).unwrap();
        assert!(!armor.contains("private message"));
        let uri = encode_uri(&delivery, limits, DEFAULT_MAX_URI_BYTES).unwrap();
        for decoded in [
            Delivery::decode(&delivery.encode(limits).unwrap(), limits).unwrap(),
            decode_armored(&armor, limits).unwrap(),
            decode_uri(&uri, limits, DEFAULT_MAX_URI_BYTES).unwrap(),
            decode_attachment(
                DELIVERY_MEDIA_TYPE,
                &delivery.encode(limits).unwrap(),
                limits,
            )
            .unwrap(),
        ] {
            assert_eq!(decoded, delivery);
            decoded
                .verify_required_signature(&signer, "delivery/v1", limits)
                .unwrap();
        }
    }

    #[test]
    fn unsigned_delivery_cannot_satisfy_provenance_policy() {
        let (mut delivery, signer) = signed();
        delivery.signature = None;
        let bytes = delivery.encode(CapsuleLimits::default()).unwrap();
        let parsed = Delivery::decode(&bytes, CapsuleLimits::default()).unwrap();
        assert_eq!(
            parsed.verify_required_signature(&signer, "delivery/v1", CapsuleLimits::default()),
            Err(TransportError::MissingSignature)
        );
    }

    #[test]
    fn armor_accepts_lf_and_crlf_but_rejects_junk_or_extra_records() {
        let (delivery, _) = signed();
        let limits = CapsuleLimits::default();
        let armor = encode_armored(&delivery, limits).unwrap();
        assert_eq!(
            decode_armored(&armor.replace('\n', "\r\n"), limits).unwrap(),
            delivery
        );
        assert_eq!(
            decode_armored(armor.trim_end_matches('\n'), limits).unwrap(),
            delivery
        );
        for junk in [
            format!("prefix{armor}"),
            format!("{armor}junk"),
            format!("{armor}{armor}"),
            armor.replacen('\n', "\n ", 1),
        ] {
            assert!(decode_armored(&junk, limits).is_err());
        }
    }

    #[test]
    fn uri_rejects_http_queries_percent_escapes_padding_and_unknown_versions() {
        let (delivery, _) = signed();
        let limits = CapsuleLimits::default();
        let uri = encode_uri(&delivery, limits, DEFAULT_MAX_URI_BYTES).unwrap();
        for bad in [
            format!("{uri}?token=x"),
            format!("{uri}%20"),
            format!("{uri}="),
            uri.replace("e2ed:v1:", "e2ed:v2:"),
            format!("https://example.invalid/{uri}"),
        ] {
            assert!(decode_uri(&bad, limits, DEFAULT_MAX_URI_BYTES).is_err());
        }
        assert_eq!(
            encode_uri(&delivery, limits, 8),
            Err(TransportError::LimitExceeded)
        );
        assert_eq!(
            decode_uri(&uri, limits, 8),
            Err(TransportError::LimitExceeded)
        );
    }

    #[test]
    fn truncated_binary_trailing_data_and_unknown_flags_fail_closed() {
        let (delivery, _) = signed();
        let limits = CapsuleLimits::default();
        let bytes = delivery.encode(limits).unwrap();
        for n in 0..bytes.len() {
            assert!(Delivery::decode(&bytes[..n], limits).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Delivery::decode(&trailing, limits).is_err());
        let mut flags = bytes.clone();
        flags[7] = 2;
        assert_eq!(
            Delivery::decode(&flags, limits),
            Err(TransportError::UnsupportedFlags)
        );
        let mut length = bytes;
        length[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            Delivery::decode(&length, limits),
            Err(TransportError::LimitExceeded)
        );
    }

    #[test]
    fn configured_limits_are_enforced_before_base64_decode() {
        let (delivery, _) = signed();
        let ordinary = CapsuleLimits::default();
        let limits = CapsuleLimits {
            max_total_bytes: 1,
            ..ordinary
        };
        assert!(decode_armored(&encode_armored(&delivery, ordinary).unwrap(), limits).is_err());
        assert!(decode_uri(
            &encode_uri(&delivery, ordinary, DEFAULT_MAX_URI_BYTES).unwrap(),
            limits,
            DEFAULT_MAX_URI_BYTES
        )
        .is_err());
        let overflow = CapsuleLimits {
            max_total_bytes: usize::MAX,
            ..ordinary
        };
        assert_eq!(
            decode_armored("", overflow),
            Err(TransportError::LimitExceeded)
        );
    }
}
