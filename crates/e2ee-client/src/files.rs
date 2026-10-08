//! Files use the same contact, signature and lock policy as client text.

use crate::{ClientError, EndpointSession, SenderPolicy, SignatureMode, VerifiedContact};
use e2ee_capsule::CapsuleLimits;
use e2ee_file::{decrypt_file, encrypt_file_for_recipients, FileOptions};
use e2ee_provenance::{sign_capsule, TrustedSigner, VerifiedProvenance};
use e2ee_transport::Delivery;
use std::fmt;
use zeroize::Zeroizing;

pub struct OpenedFile {
    pub provenance: Option<VerifiedProvenance>,
    filename: Zeroizing<String>,
    media_type: Zeroizing<String>,
    bytes: Zeroizing<Vec<u8>>,
}

impl OpenedFile {
    pub fn filename(&self) -> &str {
        &self.filename
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OpenedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedFile")
            .field("provenance", &self.provenance)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

impl EndpointSession {
    pub fn encrypt_file(
        &mut self,
        recipients: &[VerifiedContact],
        options: &FileOptions,
        bytes: &[u8],
        signature: SignatureMode<'_>,
        now_ms: u64,
    ) -> Result<Delivery, ClientError> {
        self.require_unlocked(now_ms)?;
        // Keep the controller's bounded inline file path within the transport
        // parser budget. Larger streaming attachments require another API.
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(e2ee_file::FileError::FileTooLargeForInlineCapsule.into());
        }
        let recipients: Vec<_> = recipients.iter().map(|r| r.0.recipient()).collect();
        let capsule = encrypt_file_for_recipients(&recipients, options, bytes)?;
        let signature = match signature {
            SignatureMode::Unsigned => None,
            SignatureMode::Signed { context } => Some(sign_capsule(
                &self.keys.as_ref().ok_or(ClientError::Locked)?.signer,
                &capsule,
                context,
                CapsuleLimits::default(),
            )?),
        };
        self.last_activity_ms = now_ms;
        Ok(Delivery { capsule, signature })
    }

    /// Opening returns bytes only. Hosts must never automatically execute or
    /// render active file content, nor concatenate the filename into a path.
    pub fn open_file(
        &mut self,
        delivery: &Delivery,
        sender: SenderPolicy<'_>,
        now_ms: u64,
    ) -> Result<OpenedFile, ClientError> {
        self.require_unlocked(now_ms)?;
        let provenance = match sender {
            SenderPolicy::RequireSignature { sender, context } => {
                Some(delivery.verify_required_signature(
                    &TrustedSigner::from_public_key(sender.0.signer_public_key)?,
                    context,
                    CapsuleLimits::default(),
                )?)
            }
            SenderPolicy::PermitUnsigned => {
                if delivery.signature.is_some() {
                    return Err(ClientError::UnexpectedSignature);
                }
                None
            }
        };
        let file = decrypt_file(
            self.card.endpoint_id.as_str().as_bytes(),
            &self.keys.as_ref().ok_or(ClientError::Locked)?.recipient,
            &delivery.capsule,
        )?;
        self.last_activity_ms = now_ms;
        Ok(OpenedFile {
            provenance,
            filename: Zeroizing::new(file.filename),
            media_type: Zeroizing::new(file.media_type),
            bytes: Zeroizing::new(file.bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SessionPolicy, VerifiedContact};
    use e2ee_core::EndpointId;
    use e2ee_transport::{decode_armored, encode_armored};

    fn session(id: &str) -> EndpointSession {
        EndpointSession::create_local(EndpointId::parse(id).unwrap(), SessionPolicy::default(), 0)
            .unwrap()
    }

    fn pin(s: &EndpointSession) -> VerifiedContact {
        VerifiedContact::confirm(s.card().clone(), s.card().fingerprint()).unwrap()
    }

    #[test]
    fn signed_chunked_file_survives_transport_and_obeys_sender_and_lock_policy() {
        let mut alice = session("alice");
        let mut bob = session("bob");
        let mut eve = session("eve");
        let alice_pin = pin(&alice);
        let mut options = FileOptions::new("private-report.txt", "text/plain");
        options.chunk_size_bytes = 64 * 1024;
        let bytes = vec![7; 2 * 64 * 1024 + 17];
        let delivery = alice
            .encrypt_file(
                &[pin(&bob), pin(&eve)],
                &options,
                &bytes,
                SignatureMode::Signed {
                    context: "file-share-1",
                },
                1,
            )
            .unwrap();
        let transported = decode_armored(
            &encode_armored(&delivery, CapsuleLimits::default()).unwrap(),
            CapsuleLimits::default(),
        )
        .unwrap();
        for receiver in [&mut bob, &mut eve] {
            let file = receiver
                .open_file(
                    &transported,
                    SenderPolicy::RequireSignature {
                        sender: &alice_pin,
                        context: "file-share-1",
                    },
                    2,
                )
                .unwrap();
            assert_eq!(file.filename(), "private-report.txt");
            assert_eq!(file.bytes(), bytes);
            assert!(file.provenance.is_some());
            assert!(!format!("{file:?}").contains("private-report"));
        }
        assert!(bob
            .open_file(
                &transported,
                SenderPolicy::RequireSignature {
                    sender: &pin(&eve),
                    context: "file-share-1"
                },
                3
            )
            .is_err());
        assert!(matches!(
            bob.open_file(&transported, SenderPolicy::PermitUnsigned, 3),
            Err(ClientError::UnexpectedSignature)
        ));
        bob.lock();
        assert!(matches!(
            bob.open_file(
                &transported,
                SenderPolicy::RequireSignature {
                    sender: &alice_pin,
                    context: "file-share-1"
                },
                4
            ),
            Err(ClientError::Locked)
        ));
    }

    #[test]
    fn empty_unsigned_files_are_valid_and_unsafe_names_fail_before_encryption() {
        let mut alice = session("alice");
        let mut bob = session("bob");
        let pin = pin(&bob);
        let file = alice
            .encrypt_file(
                std::slice::from_ref(&pin),
                &FileOptions::new("empty.bin", "application/octet-stream"),
                &[],
                SignatureMode::Unsigned,
                1,
            )
            .unwrap();
        assert!(bob
            .open_file(&file, SenderPolicy::PermitUnsigned, 1)
            .unwrap()
            .bytes()
            .is_empty());
        assert!(alice
            .encrypt_file(
                &[pin],
                &FileOptions::new("../escape", "text/plain"),
                b"x",
                SignatureMode::Unsigned,
                2
            )
            .is_err());
    }
}
