#![forbid(unsafe_code)]

//! Chunked attachment/file encryption mapped to
//! attachment-chunked-aead@0.1.0.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use e2ee_capsule::{Capsule, CapsuleLimits};
use e2ee_message::{
    unwrap_key_for_recipient, wrap_key_for_recipient, RecipientPrivateKey, RecipientPublicKey,
    E2EESA_MESSAGE_SUITE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const ATTACHMENT_PROFILE: &str = "attachment-chunked-aead@0.1.0";
pub const CONTENT_AEAD: &str = "ALG-CHACHA20-POLY1305";
pub const HASH_ALGORITHM: &str = "ALG-SHA256";

const HPKE_INFO: &[u8] = b"End-To-End Everywhere attachment key wrap v1";
const MANIFEST_DOMAIN: &str = "E2EESA-ATTACHMENT-MANIFEST-v1";
const MANIFEST_NONCE: [u8; 12] = [0xff; 12];
const PAYLOAD_MAGIC: [u8; 4] = *b"E2AF";
const PAYLOAD_VERSION: u16 = 1;
const KEY_LEN: usize = 32;
const MIN_CHUNK_SIZE: usize = 64 * 1024;
const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_CHUNK_COUNT: usize = 1_000_000;
const MAX_FILENAME_BYTES: usize = 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 256;
const INLINE_MAX_PAYLOAD_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOptions {
    pub filename: String,
    pub media_type: String,
    pub chunk_size_bytes: usize,
}

impl FileOptions {
    pub fn new(filename: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            filename: filename.into(),
            media_type: media_type.into(),
            chunk_size_bytes: DEFAULT_CHUNK_SIZE,
        }
    }

    pub fn validate(&self) -> Result<(), FileError> {
        validate_filename(&self.filename)?;
        validate_media_type(&self.media_type)?;
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size_bytes) {
            return Err(FileError::InvalidChunkSize);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedFile {
    pub attachment_id: String,
    pub parent_message_id: String,
    pub filename: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    RandomnessFailure,
    InvalidFilename,
    InvalidMediaType,
    InvalidChunkSize,
    TooManyChunks,
    FileTooLargeForInlineCapsule,
    EncryptFailed,
    AuthenticationFailed,
    InvalidManifest,
    ManifestDigestMismatch,
    InvalidPayload,
    ChunkCountMismatch,
    ChunkLengthMismatch,
    WholeFileHashMismatch,
    UnsupportedProfile,
    UnsupportedAlgorithms,
    UnsupportedSuite,
    Recipient(String),
    Capsule(String),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RandomnessFailure => "secure randomness failed",
            Self::InvalidFilename => "filename is invalid",
            Self::InvalidMediaType => "media type is invalid",
            Self::InvalidChunkSize => "chunk size must be between 64 KiB and 8 MiB",
            Self::TooManyChunks => "attachment has too many chunks",
            Self::FileTooLargeForInlineCapsule => {
                "file exceeds the inline Capsule implementation limit"
            }
            Self::EncryptFailed => "attachment encryption failed",
            Self::AuthenticationFailed => "attachment authentication failed",
            Self::InvalidManifest => "private attachment manifest is invalid",
            Self::ManifestDigestMismatch => "private manifest context digest does not match",
            Self::InvalidPayload => "encrypted attachment payload framing is invalid",
            Self::ChunkCountMismatch => "encrypted chunk count does not match private manifest",
            Self::ChunkLengthMismatch => "decrypted chunk length does not match private manifest",
            Self::WholeFileHashMismatch => "whole-file plaintext hash verification failed",
            Self::UnsupportedProfile => "attachment profile is unsupported",
            Self::UnsupportedAlgorithms => "attachment algorithms are unsupported",
            Self::UnsupportedSuite => "Capsule cryptographic suite is unsupported",
            Self::Recipient(_) => "recipient key operation failed",
            Self::Capsule(_) => "Capsule validation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FileError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Manifest {
    attachment_id: String,
    parent_message_id: String,
    attachment_key_id: String,
    nonce_prefix: [u8; 4],
    chunk_size_bytes: usize,
    chunk_count: usize,
    plaintext_size_bytes: usize,
    filename: String,
    media_type: String,
    whole_plaintext_hash: [u8; 32],
    storage_object_id: String,
    manifest_context_digest: [u8; 32],
}

pub fn encrypt_file(
    recipient: &RecipientPublicKey,
    options: &FileOptions,
    plaintext: &[u8],
) -> Result<Capsule, FileError> {
    options.validate()?;
    if plaintext.len() > INLINE_MAX_PAYLOAD_BYTES {
        return Err(FileError::FileTooLargeForInlineCapsule);
    }

    let chunk_count = chunk_count(plaintext.len(), options.chunk_size_bytes)?;
    let mut attachment_key = [0_u8; KEY_LEN];
    fill_random(&mut attachment_key)?;

    let attachment_id = random_hex_id()?;
    let parent_message_id = random_hex_id()?;
    let attachment_key_id = random_hex_id()?;
    let storage_object_id = random_hex_id()?;
    let mut nonce_prefix = [0_u8; 4];
    fill_random(&mut nonce_prefix)?;
    let whole_plaintext_hash = sha256(plaintext);

    let mut manifest = Manifest {
        attachment_id,
        parent_message_id,
        attachment_key_id,
        nonce_prefix,
        chunk_size_bytes: options.chunk_size_bytes,
        chunk_count,
        plaintext_size_bytes: plaintext.len(),
        filename: options.filename.clone(),
        media_type: options.media_type.clone(),
        whole_plaintext_hash,
        storage_object_id,
        manifest_context_digest: [0; 32],
    };
    manifest.manifest_context_digest = sha256(&manifest_context_json(&manifest)?);
    let manifest_plaintext = manifest_json(&manifest)?;

    let base_context = file_base_context(&recipient.recipient_hint);
    let manifest_aad = domain_aad(&base_context, b"private-manifest");
    let protected_header_ciphertext = seal(
        &attachment_key,
        &MANIFEST_NONCE,
        &manifest_plaintext,
        &manifest_aad,
    )?;

    let payload_ciphertext = encrypt_chunks(&attachment_key, &manifest, plaintext)?;
    let wrap_aad = domain_aad(&base_context, b"attachment-key-wrap");
    let stanza = wrap_key_for_recipient(recipient, &attachment_key, HPKE_INFO, &wrap_aad)
        .map_err(|error| FileError::Recipient(error.to_string()))?;
    attachment_key.fill(0);

    let capsule = Capsule {
        suite_id: E2EESA_MESSAGE_SUITE.to_owned(),
        recipients: vec![stanza],
        protected_header_ciphertext,
        payload_ciphertext,
    };
    capsule
        .validate(file_capsule_limits())
        .map_err(|error| FileError::Capsule(error.to_string()))?;
    Ok(capsule)
}

pub fn decrypt_file(
    expected_recipient_hint: &[u8],
    recipient_private_key: &RecipientPrivateKey,
    capsule: &Capsule,
) -> Result<DecryptedFile, FileError> {
    capsule
        .validate(file_capsule_limits())
        .map_err(|error| FileError::Capsule(error.to_string()))?;
    if capsule.suite_id != E2EESA_MESSAGE_SUITE {
        return Err(FileError::UnsupportedSuite);
    }
    if capsule.recipients.len() != 1 {
        return Err(FileError::InvalidPayload);
    }

    let base_context = file_base_context(expected_recipient_hint);
    let wrap_aad = domain_aad(&base_context, b"attachment-key-wrap");
    let mut attachment_key = unwrap_key_for_recipient(
        expected_recipient_hint,
        recipient_private_key,
        &capsule.recipients[0],
        HPKE_INFO,
        &wrap_aad,
    )
    .map_err(|error| FileError::Recipient(error.to_string()))?;
    if attachment_key.len() != KEY_LEN {
        attachment_key.fill(0);
        return Err(FileError::AuthenticationFailed);
    }

    let result = decrypt_with_key(&attachment_key, capsule, &base_context);
    attachment_key.fill(0);
    result
}

fn decrypt_with_key(
    attachment_key: &[u8],
    capsule: &Capsule,
    base_context: &[u8],
) -> Result<DecryptedFile, FileError> {
    let manifest_aad = domain_aad(base_context, b"private-manifest");
    let manifest_plaintext = open(
        attachment_key,
        &MANIFEST_NONCE,
        &capsule.protected_header_ciphertext,
        &manifest_aad,
    )?;
    let manifest = parse_manifest(&manifest_plaintext)?;

    let expected_digest = sha256(&manifest_context_json(&manifest)?);
    if expected_digest != manifest.manifest_context_digest {
        return Err(FileError::ManifestDigestMismatch);
    }

    let bytes = decrypt_chunks(attachment_key, &manifest, &capsule.payload_ciphertext)?;
    if sha256(&bytes) != manifest.whole_plaintext_hash {
        return Err(FileError::WholeFileHashMismatch);
    }

    Ok(DecryptedFile {
        attachment_id: manifest.attachment_id,
        parent_message_id: manifest.parent_message_id,
        filename: manifest.filename,
        media_type: manifest.media_type,
        bytes,
    })
}

fn encrypt_chunks(
    key: &[u8; KEY_LEN],
    manifest: &Manifest,
    plaintext: &[u8],
) -> Result<Vec<u8>, FileError> {
    let mut output = Vec::new();
    output.extend_from_slice(&PAYLOAD_MAGIC);
    output.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
    output.extend_from_slice(&(manifest.chunk_count as u64).to_be_bytes());

    for index in 0..manifest.chunk_count {
        let start = index
            .checked_mul(manifest.chunk_size_bytes)
            .ok_or(FileError::InvalidPayload)?;
        let end = start
            .saturating_add(manifest.chunk_size_bytes)
            .min(plaintext.len());
        let chunk = if plaintext.is_empty() {
            &[][..]
        } else {
            &plaintext[start..end]
        };
        let nonce = chunk_nonce(manifest.nonce_prefix, index)?;
        let aad = chunk_aad(manifest, index, chunk.len());
        let encrypted = seal(key, &nonce, chunk, &aad)?;
        let encrypted_len =
            u32::try_from(encrypted.len()).map_err(|_| FileError::InvalidPayload)?;
        output.extend_from_slice(&encrypted_len.to_be_bytes());
        output.extend_from_slice(&encrypted);
    }
    Ok(output)
}

fn decrypt_chunks(key: &[u8], manifest: &Manifest, payload: &[u8]) -> Result<Vec<u8>, FileError> {
    let mut cursor = ByteCursor::new(payload);
    if cursor.take(4)? != PAYLOAD_MAGIC {
        return Err(FileError::InvalidPayload);
    }
    if cursor.u16()? != PAYLOAD_VERSION {
        return Err(FileError::InvalidPayload);
    }
    let encoded_count = usize::try_from(cursor.u64()?).map_err(|_| FileError::InvalidPayload)?;
    if encoded_count != manifest.chunk_count {
        return Err(FileError::ChunkCountMismatch);
    }

    let mut output = Vec::with_capacity(manifest.plaintext_size_bytes);
    for index in 0..manifest.chunk_count {
        let encrypted_len =
            usize::try_from(cursor.u32()?).map_err(|_| FileError::InvalidPayload)?;
        if encrypted_len > MAX_CHUNK_SIZE + 16 {
            return Err(FileError::InvalidPayload);
        }
        let ciphertext = cursor.take(encrypted_len)?;
        let expected_plaintext_len = expected_chunk_len(manifest, index)?;
        let nonce = chunk_nonce(manifest.nonce_prefix, index)?;
        let aad = chunk_aad(manifest, index, expected_plaintext_len);
        let chunk = open(key, &nonce, ciphertext, &aad)?;
        if chunk.len() != expected_plaintext_len {
            return Err(FileError::ChunkLengthMismatch);
        }
        // Plaintext is appended only after this chunk's AEAD authentication.
        output.extend_from_slice(&chunk);
    }

    if !cursor.finished() || output.len() != manifest.plaintext_size_bytes {
        return Err(FileError::InvalidPayload);
    }
    Ok(output)
}

fn expected_chunk_len(manifest: &Manifest, index: usize) -> Result<usize, FileError> {
    if index >= manifest.chunk_count {
        return Err(FileError::InvalidPayload);
    }
    if manifest.plaintext_size_bytes == 0 {
        return Ok(0);
    }
    if index + 1 < manifest.chunk_count {
        return Ok(manifest.chunk_size_bytes);
    }
    let consumed = manifest
        .chunk_size_bytes
        .checked_mul(manifest.chunk_count - 1)
        .ok_or(FileError::InvalidManifest)?;
    manifest
        .plaintext_size_bytes
        .checked_sub(consumed)
        .ok_or(FileError::InvalidManifest)
}

fn chunk_count(size: usize, chunk_size: usize) -> Result<usize, FileError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(FileError::InvalidChunkSize);
    }
    let count = if size == 0 {
        1
    } else {
        size.checked_add(chunk_size - 1)
            .ok_or(FileError::TooManyChunks)?
            / chunk_size
    };
    if count > MAX_CHUNK_COUNT {
        return Err(FileError::TooManyChunks);
    }
    Ok(count)
}

fn chunk_nonce(prefix: [u8; 4], index: usize) -> Result<[u8; 12], FileError> {
    let index = u64::try_from(index).map_err(|_| FileError::InvalidPayload)?;
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    Ok(nonce)
}

fn chunk_aad(manifest: &Manifest, index: usize, plaintext_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(b"E2EESA-ATTACHMENT-CHUNK-v1");
    put_bytes(&mut aad, manifest.attachment_id.as_bytes());
    aad.extend_from_slice(&manifest.manifest_context_digest);
    aad.extend_from_slice(&(index as u64).to_be_bytes());
    aad.extend_from_slice(&(manifest.chunk_count as u64).to_be_bytes());
    aad.extend_from_slice(&(plaintext_len as u64).to_be_bytes());
    aad
}

fn manifest_context_json(manifest: &Manifest) -> Result<Vec<u8>, FileError> {
    let value = json!({
        "attachment_id": manifest.attachment_id,
        "attachment_key_id": manifest.attachment_key_id,
        "chunk_count": manifest.chunk_count,
        "chunk_size_bytes": manifest.chunk_size_bytes,
        "content_aead_algorithm_id": CONTENT_AEAD,
        "domain": MANIFEST_DOMAIN,
        "filename": manifest.filename,
        "format_version": "attachment-v1",
        "hash_algorithm_id": HASH_ALGORITHM,
        "media_type": manifest.media_type,
        "nonce_prefix_hex": hex(&manifest.nonce_prefix),
        "parent_message_id": manifest.parent_message_id,
        "plaintext_size_bytes": manifest.plaintext_size_bytes,
        "profile_ref": ATTACHMENT_PROFILE,
        "storage_object_id": manifest.storage_object_id,
        "whole_plaintext_hash_hex": hex(&manifest.whole_plaintext_hash)
    });
    serde_json::to_vec(&value).map_err(|_| FileError::InvalidManifest)
}

fn manifest_json(manifest: &Manifest) -> Result<Vec<u8>, FileError> {
    let value = json!({
        "attachment_id": manifest.attachment_id,
        "attachment_key_id": manifest.attachment_key_id,
        "chunk_count": manifest.chunk_count,
        "chunk_size_bytes": manifest.chunk_size_bytes,
        "content_aead_algorithm_id": CONTENT_AEAD,
        "filename": manifest.filename,
        "format_version": "attachment-v1",
        "hash_algorithm_id": HASH_ALGORITHM,
        "manifest_context_digest_hex": hex(&manifest.manifest_context_digest),
        "media_type": manifest.media_type,
        "nonce_prefix_hex": hex(&manifest.nonce_prefix),
        "parent_message_id": manifest.parent_message_id,
        "plaintext_size_bytes": manifest.plaintext_size_bytes,
        "profile_ref": ATTACHMENT_PROFILE,
        "storage_object_id": manifest.storage_object_id,
        "whole_plaintext_hash_hex": hex(&manifest.whole_plaintext_hash)
    });
    serde_json::to_vec(&value).map_err(|_| FileError::InvalidManifest)
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest, FileError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FileError::InvalidManifest)?;
    let object = value.as_object().ok_or(FileError::InvalidManifest)?;

    let allowed = [
        "attachment_id",
        "attachment_key_id",
        "chunk_count",
        "chunk_size_bytes",
        "content_aead_algorithm_id",
        "filename",
        "format_version",
        "hash_algorithm_id",
        "manifest_context_digest_hex",
        "media_type",
        "nonce_prefix_hex",
        "parent_message_id",
        "plaintext_size_bytes",
        "profile_ref",
        "storage_object_id",
        "whole_plaintext_hash_hex",
    ];
    if object.len() != allowed.len() || object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(FileError::InvalidManifest);
    }

    if string_field(object, "profile_ref")? != ATTACHMENT_PROFILE {
        return Err(FileError::UnsupportedProfile);
    }
    if string_field(object, "format_version")? != "attachment-v1" {
        return Err(FileError::InvalidManifest);
    }
    if string_field(object, "content_aead_algorithm_id")? != CONTENT_AEAD
        || string_field(object, "hash_algorithm_id")? != HASH_ALGORITHM
    {
        return Err(FileError::UnsupportedAlgorithms);
    }

    let manifest = Manifest {
        attachment_id: bounded_string(object, "attachment_id", 64)?,
        parent_message_id: bounded_string(object, "parent_message_id", 64)?,
        attachment_key_id: bounded_string(object, "attachment_key_id", 64)?,
        nonce_prefix: decode_hex_fixed::<4>(string_field(object, "nonce_prefix_hex")?)?,
        chunk_size_bytes: usize_field(object, "chunk_size_bytes")?,
        chunk_count: usize_field(object, "chunk_count")?,
        plaintext_size_bytes: usize_field(object, "plaintext_size_bytes")?,
        filename: bounded_string(object, "filename", MAX_FILENAME_BYTES)?,
        media_type: bounded_string(object, "media_type", MAX_MEDIA_TYPE_BYTES)?,
        whole_plaintext_hash: decode_hex_fixed::<32>(string_field(
            object,
            "whole_plaintext_hash_hex",
        )?)?,
        storage_object_id: bounded_string(object, "storage_object_id", 64)?,
        manifest_context_digest: decode_hex_fixed::<32>(string_field(
            object,
            "manifest_context_digest_hex",
        )?)?,
    };
    validate_filename(&manifest.filename)?;
    validate_media_type(&manifest.media_type)?;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&manifest.chunk_size_bytes)
        || manifest.chunk_count == 0
        || manifest.chunk_count > MAX_CHUNK_COUNT
        || chunk_count(manifest.plaintext_size_bytes, manifest.chunk_size_bytes)?
            != manifest.chunk_count
    {
        return Err(FileError::InvalidManifest);
    }
    Ok(manifest)
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, FileError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(FileError::InvalidManifest)
}

fn bounded_string(
    object: &serde_json::Map<String, Value>,
    name: &str,
    max_bytes: usize,
) -> Result<String, FileError> {
    let value = string_field(object, name)?;
    if value.is_empty() || value.len() > max_bytes {
        return Err(FileError::InvalidManifest);
    }
    Ok(value.to_owned())
}

fn usize_field(object: &serde_json::Map<String, Value>, name: &str) -> Result<usize, FileError> {
    let value = object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(FileError::InvalidManifest)?;
    usize::try_from(value).map_err(|_| FileError::InvalidManifest)
}

fn validate_filename(value: &str) -> Result<(), FileError> {
    if value.is_empty()
        || value.len() > MAX_FILENAME_BYTES
        || value == "."
        || value == ".."
        || value.chars().any(|c| c == '\0' || c == '/' || c == '\\')
    {
        return Err(FileError::InvalidFilename);
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), FileError> {
    if value.is_empty()
        || value.len() > MAX_MEDIA_TYPE_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(FileError::InvalidMediaType);
    }
    Ok(())
}

fn file_base_context(recipient_hint: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + recipient_hint.len());
    out.extend_from_slice(b"E2EC-FILE-V1");
    put_bytes(&mut out, E2EESA_MESSAGE_SUITE.as_bytes());
    put_bytes(&mut out, ATTACHMENT_PROFILE.as_bytes());
    put_bytes(&mut out, recipient_hint);
    out
}

fn domain_aad(base: &[u8], domain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + domain.len() + 4);
    out.extend_from_slice(base);
    put_bytes(&mut out, domain);
    out
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn seal(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FileError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| FileError::EncryptFailed)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| FileError::EncryptFailed)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| FileError::EncryptFailed)
}

fn open(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, FileError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| FileError::AuthenticationFailed)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| FileError::AuthenticationFailed)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| FileError::AuthenticationFailed)
}

fn fill_random(output: &mut [u8]) -> Result<(), FileError> {
    getrandom::fill(output).map_err(|_| FileError::RandomnessFailure)
}

fn random_hex_id() -> Result<String, FileError> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes)?;
    Ok(hex(&bytes))
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for &byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex_fixed<const N: usize>(value: &str) -> Result<[u8; N], FileError> {
    if value.len() != N * 2 {
        return Err(FileError::InvalidManifest);
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        let high = decode_nibble(value.as_bytes()[offset])?;
        let low = decode_nibble(value.as_bytes()[offset + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, FileError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(FileError::InvalidManifest),
    }
}

fn file_capsule_limits() -> CapsuleLimits {
    CapsuleLimits {
        max_payload_bytes: INLINE_MAX_PAYLOAD_BYTES + 32 * 1024,
        max_total_bytes: INLINE_MAX_PAYLOAD_BYTES + 2 * 1024 * 1024,
        ..CapsuleLimits::default()
    }
}

struct ByteCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FileError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FileError::InvalidPayload)?;
        if end > self.input.len() {
            return Err(FileError::InvalidPayload);
        }
        let result = &self.input[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, FileError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| FileError::InvalidPayload)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, FileError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| FileError::InvalidPayload)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, FileError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| FileError::InvalidPayload)?,
        ))
    }

    fn finished(&self) -> bool {
        self.offset == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2ee_message::generate_recipient_keypair;

    fn recipient() -> (RecipientPublicKey, RecipientPrivateKey) {
        let pair = generate_recipient_keypair();
        (
            RecipientPublicKey {
                recipient_hint: vec![0x41; 16],
                encoded_public_key: pair.public_key,
            },
            pair.private_key,
        )
    }

    #[test]
    fn multi_chunk_file_round_trip() {
        let (public, private) = recipient();
        let mut options = FileOptions::new("report.bin", "application/octet-stream");
        options.chunk_size_bytes = MIN_CHUNK_SIZE;
        let plaintext = vec![0x5a; MIN_CHUNK_SIZE * 2 + 123];

        let capsule = encrypt_file(&public, &options, &plaintext).unwrap();
        let opened = decrypt_file(&public.recipient_hint, &private, &capsule).unwrap();

        assert_eq!(opened.filename, "report.bin");
        assert_eq!(opened.media_type, "application/octet-stream");
        assert_eq!(opened.bytes, plaintext);
        assert!(!capsule
            .protected_header_ciphertext
            .windows(b"report.bin".len())
            .any(|window| window == b"report.bin"));
    }

    #[test]
    fn empty_file_is_one_authenticated_chunk() {
        let (public, private) = recipient();
        let options = FileOptions::new("empty.txt", "text/plain");
        let capsule = encrypt_file(&public, &options, b"").unwrap();
        let opened = decrypt_file(&public.recipient_hint, &private, &capsule).unwrap();
        assert!(opened.bytes.is_empty());
        assert!(capsule.payload_ciphertext.len() > 14);
    }

    #[test]
    fn chunk_reordering_fails() {
        let (public, private) = recipient();
        let mut options = FileOptions::new("two.bin", "application/octet-stream");
        options.chunk_size_bytes = MIN_CHUNK_SIZE;
        let plaintext = vec![7; MIN_CHUNK_SIZE + 5];
        let mut capsule = encrypt_file(&public, &options, &plaintext).unwrap();

        let mut cursor = ByteCursor::new(&capsule.payload_ciphertext);
        let prefix = cursor.take(14).unwrap().to_vec();
        let first_len = cursor.u32().unwrap() as usize;
        let first = cursor.take(first_len).unwrap().to_vec();
        let second_len = cursor.u32().unwrap() as usize;
        let second = cursor.take(second_len).unwrap().to_vec();

        let mut reordered = prefix;
        reordered.extend_from_slice(&(second.len() as u32).to_be_bytes());
        reordered.extend_from_slice(&second);
        reordered.extend_from_slice(&(first.len() as u32).to_be_bytes());
        reordered.extend_from_slice(&first);
        capsule.payload_ciphertext = reordered;

        assert_eq!(
            decrypt_file(&public.recipient_hint, &private, &capsule),
            Err(FileError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampered_manifest_fails_authentication() {
        let (public, private) = recipient();
        let options = FileOptions::new("a.txt", "text/plain");
        let mut capsule = encrypt_file(&public, &options, b"hello").unwrap();
        capsule.protected_header_ciphertext[0] ^= 1;

        assert_eq!(
            decrypt_file(&public.recipient_hint, &private, &capsule),
            Err(FileError::AuthenticationFailed)
        );
    }

    #[test]
    fn wrong_recipient_cannot_decrypt_file() {
        let (public, _) = recipient();
        let (_, wrong_private) = recipient();
        let options = FileOptions::new("a.txt", "text/plain");
        let capsule = encrypt_file(&public, &options, b"hello").unwrap();

        assert!(matches!(
            decrypt_file(&public.recipient_hint, &wrong_private, &capsule),
            Err(FileError::Recipient(_))
        ));
    }

    #[test]
    fn unsafe_filename_is_rejected() {
        let (public, _) = recipient();
        let options = FileOptions::new("../secret.txt", "text/plain");
        assert_eq!(
            encrypt_file(&public, &options, b"x"),
            Err(FileError::InvalidFilename)
        );
    }
}
