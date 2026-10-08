#![forbid(unsafe_code)]

//! Single- and multi-recipient text/message encryption for E2E Capsules.
//!
//! This module uses the exact E2EESA-recommended RFC 9180 HPKE suite for
//! recipient key wrapping, plus a fresh random content-encryption key for the
//! protected header and message payload.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use e2ee_capsule::{Capsule, CapsuleLimits, RecipientStanza};
use hpke::{
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
    single_shot_open, single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS,
    Serializable,
};
use std::fmt;
use zeroize::Zeroizing;

pub mod recipients;
use recipients::{bind_recipient_stanzas, multi_recipient_context, validate_recipient_keys};

type Kem = X25519HkdfSha256;
type HpkeAead = HpkeChaCha20Poly1305;
type HpkeKdf = HkdfSha256;

pub const E2EESA_MESSAGE_SUITE: &str = "SUITE-HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305";
pub const DEFAULT_CONTENT_TYPE: &str = "text/plain;charset=utf-8";

const HPKE_INFO: &[u8] = b"End-To-End Everywhere Capsule key wrap v1";
const HEADER_MAGIC: [u8; 4] = *b"E2MH";
const HEADER_VERSION: u16 = 1;
const NONCE_LEN: usize = 12;
const CONTENT_KEY_LEN: usize = 32;
const MESSAGE_ID_LEN: usize = 16;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct RecipientPublicKey {
    pub recipient_hint: Vec<u8>,
    pub encoded_public_key: Vec<u8>,
}

impl fmt::Debug for RecipientPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipientPublicKey")
            .field("recipient_hint_len", &self.recipient_hint.len())
            .field("public_key_len", &self.encoded_public_key.len())
            .finish()
    }
}

/// Ephemeral in-memory representation of an endpoint HPKE private key.
///
/// Production clients should persist endpoint protocol keys only inside the
/// encrypted local state protected by the selected e2ee-keystore profile.
/// Dropping this object overwrites its serialized key bytes.
pub struct RecipientPrivateKey {
    encoded_private_key: Zeroizing<Vec<u8>>,
}

impl RecipientPrivateKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, MessageError> {
        let bytes = Zeroizing::new(bytes);
        let _ = <Kem as KemTrait>::PrivateKey::from_bytes(&bytes)
            .map_err(|_| MessageError::InvalidPrivateKey)?;
        Ok(Self {
            encoded_private_key: bytes,
        })
    }

    fn parse(&self) -> Result<<Kem as KemTrait>::PrivateKey, MessageError> {
        <Kem as KemTrait>::PrivateKey::from_bytes(&self.encoded_private_key)
            .map_err(|_| MessageError::InvalidPrivateKey)
    }
}

impl fmt::Debug for RecipientPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientPrivateKey([REDACTED])")
    }
}

pub struct RecipientKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: RecipientPrivateKey,
}

impl fmt::Debug for RecipientKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipientKeyPair")
            .field("public_key_len", &self.public_key.len())
            .field("private_key", &self.private_key)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedText {
    pub message_id: [u8; MESSAGE_ID_LEN],
    pub content_type: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    RandomnessFailure,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidRecipientHint,
    UnsupportedSuite,
    RecipientCount,
    DuplicateRecipientHint,
    DuplicateRecipientKey,
    RecipientHintMismatch,
    HpkeSeal,
    HpkeOpen,
    InvalidContentKey,
    EncryptFailed,
    AuthenticationFailed,
    InvalidProtectedHeader,
    UnsupportedHeaderVersion,
    InvalidContentType,
    InvalidUtf8,
    TextTooLarge,
    Capsule(String),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RandomnessFailure => "secure randomness failed",
            Self::InvalidPublicKey => "recipient HPKE public key is invalid",
            Self::InvalidPrivateKey => "recipient HPKE private key is invalid",
            Self::InvalidRecipientHint => "recipient hint is invalid",
            Self::UnsupportedSuite => "capsule uses an unsupported cryptographic suite",
            Self::RecipientCount => "recipient count is outside the supported range",
            Self::DuplicateRecipientHint => "recipient hints must be unique",
            Self::DuplicateRecipientKey => "recipient endpoint keys must be unique",
            Self::RecipientHintMismatch => {
                "capsule recipient hint does not match expected recipient"
            }
            Self::HpkeSeal => "HPKE content-key wrapping failed",
            Self::HpkeOpen => "HPKE content-key unwrapping failed",
            Self::InvalidContentKey => "unwrapped content key has an invalid length",
            Self::EncryptFailed => "message encryption failed",
            Self::AuthenticationFailed => "message authentication/decryption failed",
            Self::InvalidProtectedHeader => "protected message header is invalid",
            Self::UnsupportedHeaderVersion => "protected message header version is unsupported",
            Self::InvalidContentType => "message content type is invalid",
            Self::InvalidUtf8 => "decrypted text is not valid UTF-8",
            Self::TextTooLarge => "text payload exceeds profile limit",
            Self::Capsule(_) => "capsule validation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for MessageError {}

pub fn generate_recipient_keypair() -> RecipientKeyPair {
    let (private_key, public_key) = Kem::gen_keypair();
    RecipientKeyPair {
        public_key: public_key.to_bytes().as_slice().to_vec(),
        private_key: RecipientPrivateKey {
            encoded_private_key: Zeroizing::new(private_key.to_bytes().as_slice().to_vec()),
        },
    }
}

/// Wrap arbitrary endpoint content-key material to one recipient using the
/// exact E2EESA HPKE suite. The caller supplies a domain-separated HPKE info
/// string and authenticated context appropriate to its application profile.
pub fn wrap_key_for_recipient(
    recipient: &RecipientPublicKey,
    key_material: &[u8],
    hpke_info: &[u8],
    aad: &[u8],
) -> Result<RecipientStanza, MessageError> {
    validate_recipient_hint(&recipient.recipient_hint)?;
    let recipient_public = <Kem as KemTrait>::PublicKey::from_bytes(&recipient.encoded_public_key)
        .map_err(|_| MessageError::InvalidPublicKey)?;
    let (encapped_key, wrapped_content_key) = single_shot_seal::<HpkeAead, HpkeKdf, Kem>(
        &OpModeS::Base,
        &recipient_public,
        hpke_info,
        key_material,
        aad,
    )
    .map_err(|_| MessageError::HpkeSeal)?;

    Ok(RecipientStanza {
        recipient_hint: recipient.recipient_hint.clone(),
        encapsulated_key: encapped_key.to_bytes().as_slice().to_vec(),
        wrapped_content_key,
    })
}

/// Unwrap endpoint content-key material from one recipient stanza.
pub fn unwrap_key_for_recipient(
    expected_recipient_hint: &[u8],
    recipient_private_key: &RecipientPrivateKey,
    stanza: &RecipientStanza,
    hpke_info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MessageError> {
    validate_recipient_hint(expected_recipient_hint)?;
    if stanza.recipient_hint != expected_recipient_hint {
        return Err(MessageError::RecipientHintMismatch);
    }

    let private_key = recipient_private_key.parse()?;
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&stanza.encapsulated_key)
        .map_err(|_| MessageError::HpkeOpen)?;

    single_shot_open::<HpkeAead, HpkeKdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapped_key,
        hpke_info,
        &stanza.wrapped_content_key,
        aad,
    )
    .map_err(|_| MessageError::HpkeOpen)
}

pub fn encrypt_text(
    recipient: &RecipientPublicKey,
    text: &str,
    content_type: Option<&str>,
) -> Result<Capsule, MessageError> {
    encrypt_text_for_recipients(std::slice::from_ref(recipient), text, content_type)
}

/// Encrypt once and independently wrap the fresh content key for each endpoint.
/// The recipient roster is immutable after encryption and is not an MLS group.
pub fn encrypt_text_for_recipients(
    recipients: &[RecipientPublicKey],
    text: &str,
    content_type: Option<&str>,
) -> Result<Capsule, MessageError> {
    let text_bytes = text.as_bytes();
    if text_bytes.len() > MAX_TEXT_BYTES {
        return Err(MessageError::TextTooLarge);
    }
    validate_recipient_keys(recipients)?;

    let content_type = content_type.unwrap_or(DEFAULT_CONTENT_TYPE);
    validate_content_type(content_type)?;

    let mut content_key = Zeroizing::new([0_u8; CONTENT_KEY_LEN]);
    fill_random(&mut *content_key)?;

    let mut message_id = [0_u8; MESSAGE_ID_LEN];
    fill_random(&mut message_id)?;

    let protected_header_plaintext = encode_header(message_id, content_type)?;

    let mut header_nonce = [0_u8; NONCE_LEN];
    let mut payload_nonce = [0_u8; NONCE_LEN];
    fill_random(&mut header_nonce)?;
    loop {
        fill_random(&mut payload_nonce)?;
        if payload_nonce != header_nonce {
            break;
        }
    }

    let hints: Vec<_> = recipients
        .iter()
        .map(|r| r.recipient_hint.as_slice())
        .collect();
    let wrap_context = message_context(&hints)?;
    let wrap_aad = domain_aad(&wrap_context, b"content-key-wrap", None);
    let stanzas = recipients
        .iter()
        .map(|recipient| wrap_key_for_recipient(recipient, &*content_key, HPKE_INFO, &wrap_aad))
        .collect::<Result<Vec<_>, _>>()?;
    let base_aad = content_context(&wrap_context, &stanzas);
    let header_aad = domain_aad(&base_aad, b"protected-header", None);
    let payload_aad = domain_aad(&base_aad, b"message-payload", Some(&message_id));

    let protected_header_ciphertext = seal_content(
        &content_key,
        &header_nonce,
        &protected_header_plaintext,
        &header_aad,
    )?;
    let payload_ciphertext = seal_content(&content_key, &payload_nonce, text_bytes, &payload_aad)?;

    let capsule = Capsule {
        suite_id: E2EESA_MESSAGE_SUITE.to_owned(),
        recipients: stanzas,
        protected_header_ciphertext: prefix_nonce(header_nonce, protected_header_ciphertext),
        payload_ciphertext: prefix_nonce(payload_nonce, payload_ciphertext),
    };

    capsule
        .validate(CapsuleLimits::default())
        .map_err(|error| MessageError::Capsule(error.to_string()))?;
    Ok(capsule)
}

pub fn decrypt_text(
    expected_recipient_hint: &[u8],
    recipient_private_key: &RecipientPrivateKey,
    capsule: &Capsule,
) -> Result<DecryptedText, MessageError> {
    capsule
        .validate(CapsuleLimits::default())
        .map_err(|error| MessageError::Capsule(error.to_string()))?;

    if capsule.suite_id != E2EESA_MESSAGE_SUITE {
        return Err(MessageError::UnsupportedSuite);
    }
    validate_recipient_hint(expected_recipient_hint)?;
    let stanza = capsule
        .recipients
        .iter()
        .find(|s| s.recipient_hint == expected_recipient_hint)
        .ok_or(MessageError::RecipientHintMismatch)?;
    let hints: Vec<_> = capsule
        .recipients
        .iter()
        .map(|s| s.recipient_hint.as_slice())
        .collect();
    let wrap_context = message_context(&hints)?;
    let base_aad = content_context(&wrap_context, &capsule.recipients);
    let wrap_aad = domain_aad(&wrap_context, b"content-key-wrap", None);
    let content_key = Zeroizing::new(unwrap_key_for_recipient(
        expected_recipient_hint,
        recipient_private_key,
        stanza,
        HPKE_INFO,
        &wrap_aad,
    )?);

    if content_key.len() != CONTENT_KEY_LEN {
        return Err(MessageError::InvalidContentKey);
    }

    decrypt_with_content_key(&content_key, capsule, &base_aad)
}

fn message_context(hints: &[&[u8]]) -> Result<Vec<u8>, MessageError> {
    if hints.len() == 1 {
        validate_recipient_hint(hints[0])?;
        Ok(base_context(hints[0]))
    } else {
        multi_recipient_context(b"E2EC-MSG-MULTI-V1", hints)
    }
}

fn content_context(base: &[u8], stanzas: &[RecipientStanza]) -> Vec<u8> {
    if stanzas.len() == 1 {
        base.to_vec()
    } else {
        bind_recipient_stanzas(base, stanzas)
    }
}

fn decrypt_with_content_key(
    content_key: &[u8],
    capsule: &Capsule,
    base_aad: &[u8],
) -> Result<DecryptedText, MessageError> {
    let (header_nonce, header_ciphertext) = split_nonce(&capsule.protected_header_ciphertext)?;
    let header_aad = domain_aad(base_aad, b"protected-header", None);
    let header_plaintext = open_content(content_key, header_nonce, header_ciphertext, &header_aad)?;
    let header = decode_header(&header_plaintext)?;

    let (payload_nonce, payload_ciphertext) = split_nonce(&capsule.payload_ciphertext)?;
    if payload_nonce == header_nonce {
        return Err(MessageError::AuthenticationFailed);
    }
    let payload_aad = domain_aad(base_aad, b"message-payload", Some(&header.message_id));
    let plaintext = open_content(content_key, payload_nonce, payload_ciphertext, &payload_aad)?;
    if plaintext.len() > MAX_TEXT_BYTES {
        return Err(MessageError::TextTooLarge);
    }
    let text = String::from_utf8(plaintext).map_err(|_| MessageError::InvalidUtf8)?;

    Ok(DecryptedText {
        message_id: header.message_id,
        content_type: header.content_type,
        text,
    })
}

fn validate_recipient_hint(hint: &[u8]) -> Result<(), MessageError> {
    if hint.is_empty() || hint.len() > 128 {
        return Err(MessageError::InvalidRecipientHint);
    }
    Ok(())
}

fn validate_content_type(content_type: &str) -> Result<(), MessageError> {
    if content_type.is_empty()
        || content_type.len() > MAX_CONTENT_TYPE_BYTES
        || content_type
            .bytes()
            .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(MessageError::InvalidContentType);
    }
    Ok(())
}

fn fill_random(output: &mut [u8]) -> Result<(), MessageError> {
    getrandom::fill(output).map_err(|_| MessageError::RandomnessFailure)
}

fn base_context(recipient_hint: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + recipient_hint.len());
    out.extend_from_slice(b"E2EC-MSG-V1");
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&(E2EESA_MESSAGE_SUITE.len() as u16).to_be_bytes());
    out.extend_from_slice(E2EESA_MESSAGE_SUITE.as_bytes());
    out.extend_from_slice(&(recipient_hint.len() as u16).to_be_bytes());
    out.extend_from_slice(recipient_hint);
    out
}

fn domain_aad(base: &[u8], domain: &[u8], message_id: Option<&[u8; MESSAGE_ID_LEN]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + domain.len() + MESSAGE_ID_LEN + 4);
    out.extend_from_slice(base);
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    if let Some(id) = message_id {
        out.extend_from_slice(id);
    }
    out
}

fn seal_content(
    content_key: &[u8; CONTENT_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MessageError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(content_key).map_err(|_| MessageError::EncryptFailed)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| MessageError::EncryptFailed)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| MessageError::EncryptFailed)
}

fn open_content(
    content_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MessageError> {
    if content_key.len() != CONTENT_KEY_LEN || nonce.len() != NONCE_LEN {
        return Err(MessageError::AuthenticationFailed);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| MessageError::AuthenticationFailed)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| MessageError::AuthenticationFailed)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| MessageError::AuthenticationFailed)
}

fn prefix_nonce(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

fn split_nonce(value: &[u8]) -> Result<(&[u8], &[u8]), MessageError> {
    if value.len() <= NONCE_LEN {
        return Err(MessageError::AuthenticationFailed);
    }
    Ok(value.split_at(NONCE_LEN))
}

struct ProtectedHeader {
    message_id: [u8; MESSAGE_ID_LEN],
    content_type: String,
}

fn encode_header(
    message_id: [u8; MESSAGE_ID_LEN],
    content_type: &str,
) -> Result<Vec<u8>, MessageError> {
    validate_content_type(content_type)?;
    let content_type_len =
        u16::try_from(content_type.len()).map_err(|_| MessageError::InvalidContentType)?;

    let mut out = Vec::with_capacity(24 + content_type.len());
    out.extend_from_slice(&HEADER_MAGIC);
    out.extend_from_slice(&HEADER_VERSION.to_be_bytes());
    out.extend_from_slice(&message_id);
    out.extend_from_slice(&content_type_len.to_be_bytes());
    out.extend_from_slice(content_type.as_bytes());
    Ok(out)
}

fn decode_header(value: &[u8]) -> Result<ProtectedHeader, MessageError> {
    const FIXED_LEN: usize = 4 + 2 + MESSAGE_ID_LEN + 2;
    if value.len() < FIXED_LEN || value[..4] != HEADER_MAGIC {
        return Err(MessageError::InvalidProtectedHeader);
    }

    let version = u16::from_be_bytes(
        value[4..6]
            .try_into()
            .map_err(|_| MessageError::InvalidProtectedHeader)?,
    );
    if version != HEADER_VERSION {
        return Err(MessageError::UnsupportedHeaderVersion);
    }

    let mut message_id = [0_u8; MESSAGE_ID_LEN];
    message_id.copy_from_slice(&value[6..6 + MESSAGE_ID_LEN]);

    let length_offset = 6 + MESSAGE_ID_LEN;
    let content_type_len = usize::from(u16::from_be_bytes(
        value[length_offset..length_offset + 2]
            .try_into()
            .map_err(|_| MessageError::InvalidProtectedHeader)?,
    ));
    let content_type_start = length_offset + 2;
    let content_type_end = content_type_start
        .checked_add(content_type_len)
        .ok_or(MessageError::InvalidProtectedHeader)?;
    if content_type_end != value.len() {
        return Err(MessageError::InvalidProtectedHeader);
    }

    let content_type = std::str::from_utf8(&value[content_type_start..content_type_end])
        .map_err(|_| MessageError::InvalidProtectedHeader)?
        .to_owned();
    validate_content_type(&content_type)?;

    Ok(ProtectedHeader {
        message_id,
        content_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient() -> (RecipientPublicKey, RecipientPrivateKey) {
        let pair = generate_recipient_keypair();
        (
            RecipientPublicKey {
                recipient_hint: vec![0x11; 16],
                encoded_public_key: pair.public_key,
            },
            pair.private_key,
        )
    }

    #[test]
    fn text_round_trip() {
        let (public, private) = recipient();
        let capsule = encrypt_text(&public, "Meet me at four.", None).unwrap();
        let opened = decrypt_text(&public.recipient_hint, &private, &capsule).unwrap();

        assert_eq!(opened.text, "Meet me at four.");
        assert_eq!(opened.content_type, DEFAULT_CONTENT_TYPE);
        assert_eq!(capsule.suite_id, E2EESA_MESSAGE_SUITE);
        assert_ne!(capsule.payload_ciphertext, b"Meet me at four.");
    }

    #[test]
    fn wrong_recipient_key_cannot_open_message() {
        let (public, _) = recipient();
        let (_, wrong_private) = recipient();
        let capsule = encrypt_text(&public, "classified", None).unwrap();

        assert_eq!(
            decrypt_text(&public.recipient_hint, &wrong_private, &capsule),
            Err(MessageError::HpkeOpen)
        );
    }

    #[test]
    fn tampered_payload_fails_authentication() {
        let (public, private) = recipient();
        let mut capsule = encrypt_text(&public, "authentic", None).unwrap();
        let last = capsule.payload_ciphertext.len() - 1;
        capsule.payload_ciphertext[last] ^= 1;

        assert_eq!(
            decrypt_text(&public.recipient_hint, &private, &capsule),
            Err(MessageError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampered_protected_header_fails_authentication() {
        let (public, private) = recipient();
        let mut capsule = encrypt_text(&public, "authentic", None).unwrap();
        let last = capsule.protected_header_ciphertext.len() - 1;
        capsule.protected_header_ciphertext[last] ^= 1;

        assert_eq!(
            decrypt_text(&public.recipient_hint, &private, &capsule),
            Err(MessageError::AuthenticationFailed)
        );
    }

    #[test]
    fn recipient_hint_is_bound_into_key_wrap() {
        let (public, private) = recipient();
        let mut capsule = encrypt_text(&public, "bound", None).unwrap();
        capsule.recipients[0].recipient_hint[0] ^= 1;

        assert_eq!(
            decrypt_text(&capsule.recipients[0].recipient_hint, &private, &capsule),
            Err(MessageError::HpkeOpen)
        );
    }

    #[test]
    fn requires_exact_supported_suite() {
        let (public, private) = recipient();
        let mut capsule = encrypt_text(&public, "suite", None).unwrap();
        capsule.suite_id = "unknown-suite".into();

        assert_eq!(
            decrypt_text(&public.recipient_hint, &private, &capsule),
            Err(MessageError::UnsupportedSuite)
        );
    }

    #[test]
    fn message_ids_are_fresh() {
        let (public, private) = recipient();
        let first = encrypt_text(&public, "same", None).unwrap();
        let second = encrypt_text(&public, "same", None).unwrap();

        let first_open = decrypt_text(&public.recipient_hint, &private, &first).unwrap();
        let second_open = decrypt_text(&public.recipient_hint, &private, &second).unwrap();
        assert_ne!(first_open.message_id, second_open.message_id);
        assert_ne!(first.payload_ciphertext, second.payload_ciphertext);
    }

    fn multiple_recipients() -> (Vec<RecipientPublicKey>, Vec<RecipientPrivateKey>) {
        (1..=3)
            .map(|i| {
                let (mut public, private) = recipient();
                public.recipient_hint = vec![i; 16];
                (public, private)
            })
            .unzip()
    }

    #[test]
    fn every_endpoint_decrypts_the_same_payload_and_message_id() {
        let (public, private) = multiple_recipients();
        let capsule = encrypt_text_for_recipients(&public, "all devices: 🌍", None).unwrap();
        let opened: Vec<_> = public
            .iter()
            .zip(&private)
            .map(|(p, k)| decrypt_text(&p.recipient_hint, k, &capsule).unwrap())
            .collect();
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[0].text, "all devices: 🌍");
        assert_ne!(
            capsule.recipients[0].wrapped_content_key,
            capsule.recipients[1].wrapped_content_key
        );
    }

    #[test]
    fn removal_reordering_and_addition_of_recipients_fail_closed() {
        let (public, private) = multiple_recipients();
        let original = encrypt_text_for_recipients(&public, "immutable roster", None).unwrap();
        let mut removed = original.clone();
        removed.recipients.pop();
        let mut reordered = original.clone();
        reordered.recipients.swap(1, 2);
        let (mut outsider, _) = recipient();
        outsider.recipient_hint = vec![4; 16];
        let other = encrypt_text(&outsider, "another message", None).unwrap();
        let mut added = original.clone();
        added.recipients.push(other.recipients[0].clone());
        let mut reduced_to_single = original.clone();
        reduced_to_single.recipients.truncate(1);
        for altered in [removed, reordered, added, reduced_to_single] {
            assert!(decrypt_text(&public[0].recipient_hint, &private[0], &altered).is_err());
        }
    }

    #[test]
    fn other_recipients_wrap_is_authenticated() {
        let (public, private) = multiple_recipients();
        let mut capsule = encrypt_text_for_recipients(&public, "bound wrappers", None).unwrap();
        capsule.recipients[1].wrapped_content_key[0] ^= 1;
        assert_eq!(
            decrypt_text(&public[0].recipient_hint, &private[0], &capsule),
            Err(MessageError::AuthenticationFailed)
        );
    }

    #[test]
    fn duplicate_and_invalid_endpoints_are_rejected() {
        let (public, _) = multiple_recipients();
        assert_eq!(
            encrypt_text_for_recipients(&[], "x", None),
            Err(MessageError::RecipientCount)
        );
        let mut duplicate_hint = public.clone();
        duplicate_hint[1].recipient_hint = duplicate_hint[0].recipient_hint.clone();
        assert_eq!(
            encrypt_text_for_recipients(&duplicate_hint, "x", None),
            Err(MessageError::DuplicateRecipientHint)
        );
        let mut duplicate_key = public.clone();
        duplicate_key[1].encoded_public_key = duplicate_key[0].encoded_public_key.clone();
        assert_eq!(
            encrypt_text_for_recipients(&duplicate_key, "x", None),
            Err(MessageError::DuplicateRecipientKey)
        );
        let mut invalid = public;
        invalid[1].encoded_public_key = vec![1];
        assert_eq!(
            encrypt_text_for_recipients(&invalid, "x", None),
            Err(MessageError::InvalidPublicKey)
        );
        invalid[1].encoded_public_key = vec![0; 32];
        assert_eq!(
            encrypt_text_for_recipients(&invalid, "x", None),
            Err(MessageError::HpkeSeal)
        );
    }
}
