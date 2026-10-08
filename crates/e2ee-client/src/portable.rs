//! Bounded, versioned public contact cards and encrypted endpoint-state records.

use crate::{ClientError, EncryptedEndpointKeys, EndpointCard};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use e2ee_core::EndpointId;

pub const CONTACT_URI_PREFIX: &str = "e2ec:v1:";
const MAX_CONTACT: usize = 8 + 128 + 64;

impl EndpointCard {
    pub fn encode(&self) -> Result<Vec<u8>, ClientError> {
        self.validate()?;
        let id = self.endpoint_id.as_str().as_bytes();
        let mut bytes = b"E2PC\0\x01".to_vec();
        bytes.extend_from_slice(&(id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&self.recipient_public_key);
        bytes.extend_from_slice(&self.signer_public_key);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() < 8 + 1 + 64 || bytes.len() > MAX_CONTACT || bytes[..6] != *b"E2PC\0\x01" {
            return Err(ClientError::InvalidState);
        }
        let len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        if len == 0 || len > 128 || bytes.len() != 8 + len + 64 {
            return Err(ClientError::InvalidState);
        }
        let endpoint_id = EndpointId::parse(
            std::str::from_utf8(&bytes[8..8 + len]).map_err(|_| ClientError::InvalidEndpoint)?,
        )
        .map_err(|_| ClientError::InvalidEndpoint)?;
        let card = Self {
            endpoint_id,
            recipient_public_key: bytes[8 + len..40 + len]
                .try_into()
                .map_err(|_| ClientError::InvalidState)?,
            signer_public_key: bytes[40 + len..]
                .try_into()
                .map_err(|_| ClientError::InvalidState)?,
        };
        card.validate()?;
        Ok(card)
    }

    /// Public data only; suitable for a locally handled contact QR code.
    pub fn to_uri(&self) -> Result<String, ClientError> {
        Ok(format!(
            "{CONTACT_URI_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.encode()?)
        ))
    }

    pub fn from_uri(value: &str) -> Result<Self, ClientError> {
        if value.len() > 512 {
            return Err(ClientError::InvalidState);
        }
        let encoded = value
            .strip_prefix(CONTACT_URI_PREFIX)
            .ok_or(ClientError::InvalidState)?;
        if encoded.is_empty()
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(ClientError::InvalidState);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ClientError::InvalidState)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(ClientError::InvalidState);
        }
        Self::decode(&bytes)
    }

    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl EncryptedEndpointKeys {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"E2CK\0\x01".to_vec();
        bytes.extend_from_slice(&86_u16.to_be_bytes());
        bytes.extend_from_slice(&86_u16.to_be_bytes());
        bytes.extend_from_slice(&self.recipient);
        bytes.extend_from_slice(&self.signer);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != 182 || bytes[..10] != *b"E2CK\0\x01\0\x56\0\x56" {
            return Err(ClientError::InvalidState);
        }
        Self::from_ciphertexts(bytes[10..96].to_vec(), bytes[96..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EndpointSession, SessionPolicy, VerifiedContact};

    fn card() -> EndpointCard {
        EndpointSession::create_local(
            EndpointId::parse("endpoint-1").unwrap(),
            SessionPolicy::default(),
            0,
        )
        .unwrap()
        .card()
        .clone()
    }

    #[test]
    fn contact_card_round_trip_preserves_fingerprint_without_granting_trust() {
        let original = card();
        let bytes = original.encode().unwrap();
        let parsed = EndpointCard::decode(&bytes).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(
            EndpointCard::from_uri(&original.to_uri().unwrap()).unwrap(),
            original
        );
        assert_eq!(original.fingerprint_hex().len(), 64);
        assert!(VerifiedContact::confirm(parsed, [0; 32]).is_err());
        for i in 0..bytes.len() {
            assert!(EndpointCard::decode(&bytes[..i]).is_err());
        }
        assert!(EndpointCard::decode(&[bytes, vec![0]].concat()).is_err());
    }

    #[test]
    fn contact_uri_rejects_queries_escapes_padding_and_other_versions() {
        let uri = card().to_uri().unwrap();
        for invalid in [
            format!("{uri}?x=1"),
            format!("{uri}#secret"),
            format!("{uri}="),
            uri.replacen("v1", "v2", 1),
            uri.replacen(":", "%3A", 1),
            format!("https://example.org/{uri}"),
        ] {
            assert!(EndpointCard::from_uri(&invalid).is_err());
        }
        assert!(EndpointCard::from_uri(&"a".repeat(513)).is_err());
    }

    #[test]
    fn encrypted_keys_parser_rejects_all_truncations_bad_lengths_and_trailing_data() {
        let record = EncryptedEndpointKeys::from_ciphertexts(vec![1; 86], vec![2; 86]).unwrap();
        let bytes = record.encode();
        assert_eq!(EncryptedEndpointKeys::decode(&bytes).unwrap(), record);
        for i in 0..bytes.len() {
            assert!(EncryptedEndpointKeys::decode(&bytes[..i]).is_err());
        }
        for i in 0..10 {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            assert!(EncryptedEndpointKeys::decode(&changed).is_err());
        }
        assert!(EncryptedEndpointKeys::decode(&[bytes, vec![0]].concat()).is_err());
    }
}
