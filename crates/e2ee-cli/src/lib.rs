#![forbid(unsafe_code)]

//! A short-lived local client. Each invocation unlocks only for its operation.

use e2ee_capsule::CapsuleLimits;
use e2ee_client::{
    archive::{ArchiveAnchor, ArchiveError, LocalClient, RestorePolicy},
    contacts::ContactStatus,
    ClientError, EndpointCard, SenderPolicy, SessionPolicy, SignatureMode,
};
use e2ee_core::{EndpointId, ProfileId};
use e2ee_file::FileOptions;
use e2ee_keystore::{
    software::{KdfBudget, VaultKdf},
    SOFTWARE_VAULT_PROFILE,
};
use e2ee_storage::{PrivateStateStore, StorageError};
use e2ee_transport::{decode_armored, encode_armored, Delivery};
use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DELIVERY_BYTES: usize = 40 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ARMORED_DELIVERY_BYTES: usize = 56 * 1024 * 1024;

pub const HELP: &str = "End-To-End Everywhere CLI (pre-alpha)\n\
Usage: e2ee --state DIR --software-vault (--password-only | --anchor HEX) [--password-stdin] [--armor] COMMAND\n\n\
Commands:\n\
  init ENDPOINT                 Create a new local encrypted identity\n\
  identity                      Show endpoint and complete fingerprint\n\
  card                          Export the public contact URI\n\
  contacts                      List current contact fingerprints/status\n\
  import CONTACT_URI            Observe a contact without granting trust\n\
  verify ENDPOINT FINGERPRINT    Confirm a fingerprint from an independent channel\n\
  revoke ENDPOINT                Block new operations with that contact\n\
  reactivate ENDPOINT FINGERPRINT Explicitly reactivate and verify a contact\n\
  passwd                        Change the local unlock passphrase\n\
  seal-text IDS CONTEXT INPUT OUTPUT  Encrypt/sign UTF-8 text for verified contacts\n\
  open-text SENDER CONTEXT INPUT OUTPUT Open signed text from a verified sender\n\
  seal-file IDS CONTEXT INPUT OUTPUT  Encrypt/sign an attachment for verified contacts\n\
  open-file SENDER CONTEXT INPUT OUTPUT Open signed attachment to a private file\n\n\
Passphrases are prompted without terminal echo. --password-stdin explicitly reads\n\
one line (old/new lines for passwd) from a non-terminal stream ending at EOF.\n\
No passphrases are accepted as arguments or environment variables.\n\
Password-only mode has no independent identity pin or rollback protection.\n\
Anchored mode requires a separately trusted 140-character hexadecimal anchor.\n\
Successful state saves print the new public ANCHOR token to stderr; retain it\n\
independently only after the save. Native Windows file storage is not yet supported.\n\
Text INPUT is a local file. OUTPUT must not exist and is created private (0600)\n\
on Unix. Neither passphrases nor plaintext are printed to stdout. CONTEXT\n\
is a shared ASCII application purpose; both peers must use the same value.\n\
--armor explicitly selects ASCII-armored E2E deliveries on seal/open commands;\n\
binary .e2ed remains the default. Do not paste unencrypted files into email.\n";

enum Command {
    Init(EndpointId),
    Identity,
    Card,
    Contacts,
    Import(EndpointCard),
    Verify(EndpointId, [u8; 32]),
    Revoke(EndpointId),
    Reactivate(EndpointId, [u8; 32]),
    Passwd,
    SealText(Vec<EndpointId>, String, PathBuf, PathBuf),
    OpenText(EndpointId, String, PathBuf, PathBuf),
    SealFile(Vec<EndpointId>, String, PathBuf, PathBuf),
    OpenFile(EndpointId, String, PathBuf, PathBuf),
}

#[derive(Clone, Copy)]
enum DeliveryFormat {
    Binary,
    Armored,
}

struct Options {
    state: PathBuf,
    anchor: Option<ArchiveAnchor>,
    password_stdin: bool,
    delivery_format: DeliveryFormat,
    command: Command,
}

#[derive(Debug)]
pub enum CliError {
    Usage,
    InvalidFingerprint,
    InvalidAnchor,
    InvalidPassphrase,
    InvalidContext,
    InvalidText,
    InvalidInput,
    FileTooLarge,
    ConfirmationMismatch,
    TerminalInput,
    ExtraCredentialInput,
    MissingState,
    AlreadyExists,
    Interrupted,
    SignalHandler,
    Io(io::Error),
    Storage(StorageError),
    Archive(ArchiveError),
    Client(ClientError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str("invalid arguments; run e2ee --help"),
            Self::InvalidFingerprint => f.write_str("supply the complete 64-character fingerprint"),
            Self::InvalidAnchor => {
                f.write_str("trusted anchor must be a valid 140-character hexadecimal token")
            }
            Self::InvalidPassphrase => f.write_str("passphrase must contain 12 to 1024 bytes"),
            Self::InvalidContext => f.write_str("context must be 1-256 printable ASCII bytes"),
            Self::InvalidText => f.write_str("text input must be valid UTF-8"),
            Self::InvalidInput => f.write_str("input must be a regular file"),
            Self::FileTooLarge => f.write_str("local input exceeds the supported size limit"),
            Self::ConfirmationMismatch => f.write_str("passphrase confirmation did not match"),
            Self::TerminalInput => {
                f.write_str("--password-stdin requires a non-terminal credential stream")
            }
            Self::ExtraCredentialInput => {
                f.write_str("credential stream has extra data; expected EOF")
            }
            Self::MissingState => {
                f.write_str("no local client archive exists; initialize a new directory")
            }
            Self::AlreadyExists => f.write_str("initialization requires a new state directory"),
            Self::Interrupted => f.write_str("operation interrupted"),
            Self::SignalHandler => f.write_str("could not install console cancellation handling"),
            Self::Io(_) => f.write_str("local client I/O or hidden passphrase input failed"),
            Self::Storage(error) => error.fmt(f),
            Self::Archive(error) => error.fmt(f),
            Self::Client(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CliError {}

macro_rules! error_from {
    ($type:ty, $variant:ident) => {
        impl From<$type> for CliError {
            fn from(value: $type) -> Self {
                Self::$variant(value)
            }
        }
    };
}
error_from!(io::Error, Io);
error_from!(StorageError, Storage);
error_from!(ArchiveError, Archive);
error_from!(ClientError, Client);

pub fn entry(arguments: Vec<OsString>) -> i32 {
    let result = (|| -> Result<(), CliError> {
        let arguments: Vec<_> = arguments
            .into_iter()
            .map(|arg| arg.into_string().map_err(|_| CliError::Usage))
            .collect::<Result<_, _>>()?;
        if arguments.is_empty() || arguments == ["--help"] {
            io::stdout().lock().write_all(HELP.as_bytes())?;
            return Ok(());
        }
        if arguments == ["--version"] {
            writeln!(
                io::stdout().lock(),
                "e2ee {} (pre-alpha)",
                env!("CARGO_PKG_VERSION")
            )?;
            return Ok(());
        }
        let options = parse(&arguments)?;
        // Let the password reader return and restore terminal settings after
        // its Ctrl-C event instead of terminating in the middle of raw mode.
        ctrlc::try_set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst))
            .map_err(|_| CliError::SignalHandler)?;
        run(options, &mut io::stdout().lock(), &mut io::stderr().lock())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "e2ee: {error}");
            if matches!(error, CliError::Interrupted) {
                return 130;
            }
            if matches!(
                error,
                CliError::Usage
                    | CliError::InvalidFingerprint
                    | CliError::InvalidAnchor
                    | CliError::InvalidContext
            ) {
                2
            } else {
                1
            }
        }
    }
}

fn parse(arguments: &[String]) -> Result<Options, CliError> {
    if arguments.len() > 32 || arguments.iter().any(|arg| arg.len() > 4096) {
        return Err(CliError::Usage);
    }
    let mut state = None;
    let mut software = false;
    let mut password_only = false;
    let mut anchor = None;
    let mut password_stdin = false;
    let mut armor = false;
    let mut offset = 0;
    while let Some(flag) = arguments.get(offset).filter(|arg| arg.starts_with("--")) {
        offset += 1;
        match flag.as_str() {
            "--state" if state.is_none() => {
                let value = arguments.get(offset).ok_or(CliError::Usage)?;
                if value.is_empty() || value.starts_with("--") {
                    return Err(CliError::Usage);
                }
                state = Some(PathBuf::from(value));
                offset += 1;
            }
            "--software-vault" if !software => software = true,
            "--password-only" if !password_only && anchor.is_none() => password_only = true,
            "--anchor" if anchor.is_none() && !password_only => {
                let value = arguments.get(offset).ok_or(CliError::Usage)?;
                let bytes = decode_hex::<70>(value).map_err(|_| CliError::InvalidAnchor)?;
                anchor = Some(ArchiveAnchor::decode(&bytes).map_err(|_| CliError::InvalidAnchor)?);
                offset += 1;
            }
            "--password-stdin" if !password_stdin => password_stdin = true,
            "--armor" if !armor => armor = true,
            _ => return Err(CliError::Usage),
        }
    }
    if !software || (!password_only && anchor.is_none()) {
        return Err(CliError::Usage);
    }
    let state = state.ok_or(CliError::Usage)?;
    let args: Vec<_> = arguments[offset..].iter().map(String::as_str).collect();
    let command = match args.as_slice() {
        ["init", id] if anchor.is_none() => Command::Init(endpoint(id)?),
        ["identity"] => Command::Identity,
        ["card"] => Command::Card,
        ["contacts"] => Command::Contacts,
        ["import", uri] => Command::Import(EndpointCard::from_uri(uri)?),
        ["verify", id, fingerprint] => Command::Verify(
            endpoint(id)?,
            decode_hex(fingerprint).map_err(|_| CliError::InvalidFingerprint)?,
        ),
        ["revoke", id] => Command::Revoke(endpoint(id)?),
        ["reactivate", id, fingerprint] => Command::Reactivate(
            endpoint(id)?,
            decode_hex(fingerprint).map_err(|_| CliError::InvalidFingerprint)?,
        ),
        ["passwd"] => Command::Passwd,
        ["seal-text", ids, context, input, output] => Command::SealText(
            recipients(ids)?,
            application_context(context)?.to_owned(),
            PathBuf::from(input),
            PathBuf::from(output),
        ),
        ["open-text", sender, context, input, output] => Command::OpenText(
            endpoint(sender)?,
            application_context(context)?.to_owned(),
            PathBuf::from(input),
            PathBuf::from(output),
        ),
        ["seal-file", ids, context, input, output] => Command::SealFile(
            recipients(ids)?,
            application_context(context)?.to_owned(),
            PathBuf::from(input),
            PathBuf::from(output),
        ),
        ["open-file", sender, context, input, output] => Command::OpenFile(
            endpoint(sender)?,
            application_context(context)?.to_owned(),
            PathBuf::from(input),
            PathBuf::from(output),
        ),
        _ => return Err(CliError::Usage),
    };
    if armor
        && !matches!(
            &command,
            Command::SealText(..)
                | Command::OpenText(..)
                | Command::SealFile(..)
                | Command::OpenFile(..)
        )
    {
        return Err(CliError::Usage);
    }
    Ok(Options {
        state,
        anchor,
        password_stdin,
        delivery_format: if armor {
            DeliveryFormat::Armored
        } else {
            DeliveryFormat::Binary
        },
        command,
    })
}

fn endpoint(value: &str) -> Result<EndpointId, CliError> {
    if value.len() > 128 {
        return Err(CliError::Usage);
    }
    EndpointId::parse(value).map_err(|_| CliError::Usage)
}

fn application_context(value: &str) -> Result<&str, CliError> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CliError::InvalidContext);
    }
    Ok(value)
}

fn recipients(value: &str) -> Result<Vec<EndpointId>, CliError> {
    if value.is_empty() {
        return Err(CliError::Usage);
    }
    let ids: Vec<_> = value.split(',').map(endpoint).collect::<Result<_, _>>()?;
    if ids.is_empty() || ids.len() > 1024 {
        return Err(CliError::Usage);
    }
    Ok(ids)
}

fn run(
    options: Options,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<(), CliError> {
    let clock = Instant::now();
    let now = || u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut passwords = Passwords::new(options.password_stdin)?;
    if let Command::Init(endpoint) = options.command {
        if options.state.try_exists()? {
            return Err(CliError::AlreadyExists);
        }
        let passphrase = passwords.read("New vault passphrase: ", true)?;
        passwords.finish()?;
        let mut client = LocalClient::create(
            endpoint,
            &ProfileId::parse(SOFTWARE_VAULT_PROFILE).map_err(|_| CliError::Usage)?,
            passphrase,
            VaultKdf::default(),
            KdfBudget::default(),
            SessionPolicy::default(),
            now(),
        )?;
        check_interrupted()?;
        let mut store = PrivateStateStore::create(&options.state)?;
        let anchor = client.save(&mut store, None, now())?;
        emit_anchor(&anchor, diagnostics)?;
        writeln!(output, "Created local encrypted identity.")?;
        return emit_identity(client.card(), output);
    }
    let mut store = PrivateStateStore::open(&options.state)?;
    let loaded = store.read()?.ok_or(CliError::MissingState)?;
    let passphrase = passwords.read("Vault passphrase: ", false)?;
    if !matches!(options.command, Command::Passwd) {
        passwords.finish()?;
    }
    let policy = options
        .anchor
        .as_ref()
        .map_or(RestorePolicy::PasswordOnly, RestorePolicy::Anchored);
    let mut client = LocalClient::open(
        &loaded.bytes,
        passphrase,
        policy,
        KdfBudget::default(),
        SessionPolicy::default(),
        now(),
    )?;
    check_interrupted()?;
    if options.anchor.is_none() {
        writeln!(
            diagnostics,
            "Password-only local protection; no independent identity pin or rollback protection."
        )?;
    }
    let changed = match options.command {
        Command::Identity => {
            emit_identity(client.card(), output)?;
            false
        }
        Command::Card => {
            writeln!(output, "{}", client.card().to_uri()?)?;
            false
        }
        Command::Contacts => {
            for (card, status) in client.session_and_contacts(now())?.1.contacts() {
                writeln!(
                    output,
                    "{}\t{}\t{}",
                    card.endpoint_id.as_str(),
                    status_label(status),
                    card.fingerprint_hex()
                )?;
            }
            false
        }
        Command::Import(card) => {
            client
                .session_and_contacts(now())?
                .1
                .observe(card)
                .map_err(ArchiveError::from)?;
            true
        }
        Command::Verify(id, fingerprint) => {
            client
                .session_and_contacts(now())?
                .1
                .verify(&id, fingerprint)
                .map_err(ArchiveError::from)?;
            true
        }
        Command::Revoke(id) => {
            client
                .session_and_contacts(now())?
                .1
                .revoke(&id)
                .map_err(ArchiveError::from)?;
            true
        }
        Command::Reactivate(id, fingerprint) => {
            client
                .session_and_contacts(now())?
                .1
                .reactivate(&id, fingerprint)
                .map_err(ArchiveError::from)?;
            true
        }
        Command::Passwd => {
            let new_passphrase = passwords.read("New vault passphrase: ", true)?;
            passwords.finish()?;
            client.change_passphrase(
                new_passphrase,
                VaultKdf::default(),
                KdfBudget::default(),
                now(),
            )?;
            true
        }
        Command::SealText(ids, context, source, destination) => {
            let plaintext = read_bounded_file(&source, MAX_TEXT_BYTES)?;
            let text = std::str::from_utf8(&plaintext).map_err(|_| CliError::InvalidText)?;
            let (session, contacts) = client.session_and_contacts(now())?;
            let delivery = session.encrypt_text_to_contacts(
                contacts,
                &ids,
                text,
                SignatureMode::Signed { context: &context },
                now(),
            )?;
            let encoded = encode_delivery(&delivery, options.delivery_format)?;
            check_interrupted()?;
            write_new_private(&destination, &encoded)?;
            writeln!(
                output,
                "Signed encrypted delivery saved to a new private file."
            )?;
            false
        }
        Command::OpenText(sender, context, source, destination) => {
            // Do not publish a plaintext file until both sender provenance and
            // recipient authentication succeed under the current contact book.
            let delivery = decode_delivery(&source, options.delivery_format)?;
            let (session, contacts) = client.session_and_contacts(now())?;
            let opened =
                session.open_text_from_contact(contacts, &sender, &context, &delivery, now())?;
            check_interrupted()?;
            write_new_private(&destination, opened.text().as_bytes())?;
            writeln!(output, "Verified text saved to a new private file.")?;
            false
        }
        Command::SealFile(ids, context, source, destination) => {
            let payload = read_bounded_file(&source, MAX_FILE_BYTES)?;
            let filename = source
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(CliError::InvalidInput)?;
            let file_options = FileOptions::new(filename, "application/octet-stream");
            let (session, contacts) = client.session_and_contacts(now())?;
            let delivery = session.encrypt_file_to_contacts(
                contacts,
                &ids,
                &file_options,
                &payload,
                SignatureMode::Signed { context: &context },
                now(),
            )?;
            let encoded = encode_delivery(&delivery, options.delivery_format)?;
            check_interrupted()?;
            write_new_private(&destination, &encoded)?;
            writeln!(output, "Signed encrypted file saved to a private delivery.")?;
            false
        }
        Command::OpenFile(sender, context, source, destination) => {
            let delivery = decode_delivery(&source, options.delivery_format)?;
            let (session, contacts) = client.session_and_contacts(now())?;
            let pinned = contacts
                .verified_contact(&sender)
                .map_err(ClientError::from)?;
            let opened = session.open_file(
                &delivery,
                SenderPolicy::RequireSignature {
                    sender: &pinned,
                    context: &context,
                },
                now(),
            )?;
            // Never use the sender's embedded filename as a destination path.
            // The user selects an explicit new local output path.
            check_interrupted()?;
            write_new_private(&destination, opened.bytes())?;
            writeln!(output, "Verified attachment saved to a new private file.")?;
            false
        }
        Command::Init(_) => return Err(CliError::Usage),
    };
    if changed {
        check_interrupted()?;
        let anchor = client.save(&mut store, Some(loaded.digest), now())?;
        emit_anchor(&anchor, diagnostics)?;
        writeln!(output, "Saved encrypted local state.")?;
    }
    client.lock();
    Ok(())
}

/// Read exactly one regular local file and fail on oversized content. Secret
/// buffers are zeroized when they leave scope, including on validation errors.
fn encode_delivery(delivery: &Delivery, format: DeliveryFormat) -> Result<Vec<u8>, CliError> {
    let limits = CapsuleLimits::default();
    match format {
        DeliveryFormat::Binary => delivery.encode(limits),
        DeliveryFormat::Armored => encode_armored(delivery, limits).map(String::into_bytes),
    }
    .map_err(|error| CliError::Client(ClientError::Transport(error)))
}

fn decode_delivery(path: &Path, format: DeliveryFormat) -> Result<Delivery, CliError> {
    let maximum = match format {
        DeliveryFormat::Binary => MAX_DELIVERY_BYTES,
        DeliveryFormat::Armored => MAX_ARMORED_DELIVERY_BYTES,
    };
    let encoded = read_bounded_file(path, maximum)?;
    let limits = CapsuleLimits::default();
    match format {
        DeliveryFormat::Binary => Delivery::decode(&encoded, limits),
        DeliveryFormat::Armored => {
            let text = std::str::from_utf8(&encoded).map_err(|_| {
                CliError::Client(ClientError::Transport(
                    e2ee_transport::TransportError::InvalidEncoding,
                ))
            })?;
            decode_armored(text, limits)
        }
    }
    .map_err(|error| CliError::Client(ClientError::Transport(error)))
}

fn read_bounded_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(CliError::InvalidInput);
    }
    let mut contents = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut contents)?;
    if contents.len() > limit {
        return Err(CliError::FileTooLarge);
    }
    Ok(contents)
}

/// Refuse any existing destination (including symlinks) and never expose
/// plaintext through stdout or a default-readable output file.
#[cfg(unix)]
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::{fs, fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CliError::Io(error));
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_new_private(_path: &Path, _bytes: &[u8]) -> Result<(), CliError> {
    Err(CliError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "private output requires a Unix host",
    )))
}

fn emit_identity(card: &EndpointCard, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "Endpoint: {}", card.endpoint_id.as_str())?;
    writeln!(output, "Fingerprint: {}", card.fingerprint_hex())?;
    Ok(())
}

fn emit_anchor(anchor: &ArchiveAnchor, diagnostics: &mut impl Write) -> Result<(), CliError> {
    writeln!(diagnostics, "ANCHOR {}", encode_hex(&anchor.encode()?))?;
    Ok(())
}

fn status_label(status: ContactStatus) -> &'static str {
    match status {
        ContactStatus::Unverified => "unverified",
        ContactStatus::Verified => "verified",
        ContactStatus::KeyChanged => "key-changed",
        ContactStatus::Revoked => "revoked",
    }
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != 2 * N || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or(())?;
        let low = (pair[1] as char).to_digit(16).ok_or(())?;
        bytes[index] = (high * 16 + low) as u8;
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Passwords {
    from_stdin: bool,
}

impl Passwords {
    fn new(from_stdin: bool) -> Result<Self, CliError> {
        if from_stdin && io::stdin().is_terminal() {
            return Err(CliError::TerminalInput);
        }
        Ok(Self { from_stdin })
    }

    fn read(&mut self, prompt: &str, confirm: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
        check_interrupted()?;
        let passphrase = if self.from_stdin {
            read_credential_line(&mut io::stdin().lock())?
        } else {
            // Move the library's String allocation directly into a zeroizing
            // buffer rather than making a second password copy.
            Zeroizing::new(hidden_password(prompt)?.into_bytes())
        };
        if !(12..=1024).contains(&passphrase.len()) {
            return Err(CliError::InvalidPassphrase);
        }
        if confirm && !self.from_stdin {
            let confirmation =
                Zeroizing::new(hidden_password("Confirm new passphrase: ")?.into_bytes());
            if *confirmation != *passphrase {
                return Err(CliError::ConfirmationMismatch);
            }
        }
        Ok(passphrase)
    }

    fn finish(&mut self) -> Result<(), CliError> {
        if self.from_stdin {
            let mut extra = Zeroizing::new([0; 1]);
            if io::stdin().lock().read(&mut *extra)? != 0 {
                return Err(CliError::ExtraCredentialInput);
            }
        }
        Ok(())
    }
}

fn check_interrupted() -> Result<(), CliError> {
    if INTERRUPTED.load(Ordering::SeqCst) {
        Err(CliError::Interrupted)
    } else {
        Ok(())
    }
}

fn hidden_password(prompt: &str) -> Result<String, CliError> {
    let result = rpassword::prompt_password(prompt).map_err(|error| {
        if error.kind() == io::ErrorKind::Interrupted {
            CliError::Interrupted
        } else {
            CliError::Io(error)
        }
    })?;
    let mut password = Zeroizing::new(result);
    check_interrupted()?;
    // Move the allocation into the caller's zeroizing byte buffer.
    Ok(std::mem::take(&mut *password))
}

fn read_credential_line(input: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut password = Zeroizing::new(Vec::with_capacity(1025));
    let mut byte = Zeroizing::new([0; 1]);
    loop {
        if input.read(&mut *byte)? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            if password.last() == Some(&b'\r') {
                password.pop();
            }
            break;
        }
        if password.len() == 1025 {
            return Err(CliError::InvalidPassphrase);
        }
        password.push(byte[0]);
    }
    if !(12..=1024).contains(&password.len()) {
        return Err(CliError::InvalidPassphrase);
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn explicit_profile_trust_mode_and_canonical_arguments_are_required() {
        let args = |tail: &[&str]| tail.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        for invalid in [
            args(&["--state", "private", "identity"]),
            args(&["--state", "private", "--software-vault", "identity"]),
            args(&[
                "--state",
                "private",
                "--hardware-vault",
                "--password-only",
                "identity",
            ]),
            args(&[
                "--state",
                "private",
                "--software-vault",
                "--software-vault",
                "--password-only",
                "identity",
            ]),
            args(&[
                "--state",
                "private",
                "--software-vault",
                "--password-only",
                "identity",
                "extra",
            ]),
        ] {
            assert!(parse(&invalid).is_err());
        }
        assert!(parse(&args(&[
            "--state",
            "private",
            "--software-vault",
            "--password-only",
            "identity"
        ]))
        .is_ok());
    }

    #[test]
    fn bounded_credential_lines_preserve_spaces_reject_overflow_and_support_crlf() {
        let expected = b"  strong local secret  ";
        assert_eq!(
            &*read_credential_line(&mut Cursor::new([expected.as_slice(), b"\r\n"].concat()))
                .unwrap(),
            expected
        );
        assert!(read_credential_line(&mut Cursor::new(vec![b'x'; 1026])).is_err());
        assert!(read_credential_line(&mut Cursor::new(b"short\n")).is_err());
        assert_eq!(
            read_credential_line(&mut Cursor::new(vec![b'x'; 1024]))
                .unwrap()
                .len(),
            1024
        );
    }
}
