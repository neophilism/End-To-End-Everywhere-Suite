#![forbid(unsafe_code)]

//! One private local record, written atomically under an exclusive process lock.
//! Callers supply ciphertext; this adapter does not itself encrypt arbitrary bytes.
//! The directory and its ancestors must be controlled by the local user. Files
//! on a network filesystem and adversarial processes running as the same user
//! are outside this adapter's locking and durability guarantees.

use std::{fmt, io};

pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub type StateDigest = [u8; 32];

pub struct StoredState {
    pub bytes: Vec<u8>,
    /// An optimistic concurrency token, never an independent rollback anchor.
    pub digest: StateDigest,
}

impl fmt::Debug for StoredState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredState")
            .field("byte_count", &self.bytes.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub enum StorageError {
    UnsupportedPlatform,
    InvalidDirectory,
    InsecurePermissions,
    UnsafeFile,
    Busy,
    Conflict,
    LimitExceeded,
    RandomnessFailure,
    Io(io::Error),
    /// Rename succeeded, but the directory sync failed. Reload before retrying;
    /// the new record may be visible without being power-loss durable.
    DurabilityUnknown(io::Error),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => "private state storage needs a supported platform adapter",
            Self::InvalidDirectory => "state directory is invalid",
            Self::InsecurePermissions => "state directory or file permissions are not private",
            Self::UnsafeFile => "state storage refuses symlinks, hard links and non-regular files",
            Self::Busy => "another process is using this state directory",
            Self::Conflict => "local state changed; reload before saving",
            Self::LimitExceeded => "local state record exceeds its size limit",
            Self::RandomnessFailure => "secure temporary-file randomness failed",
            Self::Io(_) => "local state I/O failed",
            Self::DurabilityUnknown(_) => {
                "new state is visible but its durability is uncertain; reload before retrying"
            }
        })
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) | Self::DurabilityUnknown(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    const RECORD: &str = "state.e2es";
    const LOCK: &str = "writer.lock";

    /// Holds the writer lock until dropped. Keep this guard through the entire
    /// load/mutate/save transaction. Do not delete or replace its lock file.
    pub struct PrivateStateStore {
        path: PathBuf,
        directory: File,
        _lock: File,
    }

    impl fmt::Debug for PrivateStateStore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateStateStore")
                .field("directory", &"[REDACTED]")
                .finish()
        }
    }

    impl PrivateStateStore {
        /// Creates one 0700 directory. Its parent must already exist. Refuses
        /// an existing directory rather than adopting an unknown installation.
        pub fn create(path: impl AsRef<Path>) -> Result<Self, StorageError> {
            let path = std::path::absolute(path)?;
            if path.file_name().is_none() {
                return Err(StorageError::InvalidDirectory);
            }
            DirBuilder::new().mode(0o700).create(&path)?;
            let store = Self::open(&path)?;
            store.directory.sync_all()?;
            let parent = path.parent().ok_or(StorageError::InvalidDirectory)?;
            open_directory(parent)?.sync_all()?;
            Ok(store)
        }

        /// Opens only a private directory and takes a nonblocking exclusive
        /// lock. No automatic permission repair or creation of missing parents.
        pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
            let path = std::path::absolute(path)?;
            let directory = open_directory(&path)?;
            let metadata = directory.metadata()?;
            if !metadata.is_dir() {
                return Err(StorageError::InvalidDirectory);
            }
            if metadata.mode() & 0o7777 != 0o700 {
                return Err(StorageError::InsecurePermissions);
            }
            let lock = private_options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path.join(LOCK))
                .map_err(open_error)?;
            validate_file(&lock.metadata()?, metadata.uid())?;
            lock.try_lock().map_err(|error| match error {
                TryLockError::WouldBlock => StorageError::Busy,
                TryLockError::Error(error) => StorageError::Io(error),
            })?;
            Ok(Self {
                path,
                directory,
                _lock: lock,
            })
        }

        pub fn read(&self) -> Result<Option<StoredState>, StorageError> {
            let file = match private_options().read(true).open(self.path.join(RECORD)) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(open_error(error)),
            };
            let metadata = file.metadata()?;
            validate_file(&metadata, self.directory.metadata()?.uid())?;
            if metadata.len() > MAX_RECORD_BYTES as u64 {
                return Err(StorageError::LimitExceeded);
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(MAX_RECORD_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_RECORD_BYTES {
                return Err(StorageError::LimitExceeded);
            }
            Ok(Some(StoredState {
                digest: digest(&bytes),
                bytes,
            }))
        }

        /// Replace a complete ciphertext record. `None` means no record may
        /// already exist; a digest must match the last loaded bytes otherwise.
        /// The temporary file is synced, renamed, then its directory is synced.
        /// Publish independent rollback floors only after this returns success.
        pub fn commit(
            &mut self,
            expected: Option<StateDigest>,
            ciphertext: &[u8],
        ) -> Result<StateDigest, StorageError> {
            if ciphertext.is_empty() || ciphertext.len() > MAX_RECORD_BYTES {
                return Err(StorageError::LimitExceeded);
            }
            if self.read()?.map(|state| state.digest) != expected {
                return Err(StorageError::Conflict);
            }
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|_| StorageError::RandomnessFailure)?;
            let mut name = String::from("pending-");
            for byte in random {
                use std::fmt::Write;
                write!(&mut name, "{byte:02x}").expect("writing to a String cannot fail");
            }
            let temporary = self.path.join(name);
            let mut file = private_options()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            let prepared = (|| -> io::Result<()> {
                file.write_all(ciphertext)?;
                file.sync_all()?;
                fs::rename(&temporary, self.path.join(RECORD))
            })();
            if let Err(error) = prepared {
                let _ = fs::remove_file(&temporary);
                return Err(StorageError::Io(error));
            }
            self.directory
                .sync_all()
                .map_err(StorageError::DurabilityUnknown)?;
            Ok(digest(ciphertext))
        }
    }

    fn private_options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options
    }

    fn open_directory(path: &Path) -> Result<File, StorageError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(open_error)
    }

    fn open_error(error: io::Error) -> StorageError {
        if error.raw_os_error() == Some(libc::ELOOP) {
            StorageError::UnsafeFile
        } else {
            StorageError::Io(error)
        }
    }

    fn validate_file(metadata: &Metadata, directory_owner: u32) -> Result<(), StorageError> {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(StorageError::UnsafeFile);
        }
        if metadata.uid() != directory_owner || metadata.mode() & 0o7777 != 0o600 {
            return Err(StorageError::InsecurePermissions);
        }
        Ok(())
    }

    fn digest(bytes: &[u8]) -> StateDigest {
        Sha256::digest(bytes).into()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        struct TempDirectory(PathBuf);
        impl TempDirectory {
            fn new() -> Self {
                let mut random = [0; 16];
                getrandom::fill(&mut random).unwrap();
                let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
                let path = std::env::temp_dir().join(format!("e2ee-storage-{name}"));
                DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }
            fn state(&self) -> PathBuf {
                self.0.join("private")
            }
        }
        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn durable_restart_and_compare_exchange_preserve_complete_records() {
            let temp = TempDirectory::new();
            let mut store = PrivateStateStore::create(temp.state()).unwrap();
            assert!(store.read().unwrap().is_none());
            let old = store.commit(None, b"encrypted record one").unwrap();
            assert!(matches!(
                store.commit(None, b"must not replace initialized state"),
                Err(StorageError::Conflict)
            ));
            assert!(matches!(
                store.commit(Some([0; 32]), b"stale write"),
                Err(StorageError::Conflict)
            ));
            assert_eq!(store.read().unwrap().unwrap().digest, old);
            let new = store.commit(Some(old), b"encrypted record two").unwrap();
            drop(store);
            let restarted = PrivateStateStore::open(temp.state()).unwrap();
            let loaded = restarted.read().unwrap().unwrap();
            assert_eq!(loaded.bytes, b"encrypted record two");
            assert_eq!(loaded.digest, new);
            assert!(!format!("{loaded:?}").contains("record two"));
            assert_eq!(fs::read_dir(temp.state()).unwrap().count(), 2);
        }

        #[test]
        fn lock_rejects_concurrent_writer_and_is_released_on_drop() {
            let temp = TempDirectory::new();
            let store = PrivateStateStore::create(temp.state()).unwrap();
            assert!(matches!(
                PrivateStateStore::open(temp.state()),
                Err(StorageError::Busy)
            ));
            drop(store);
            assert!(PrivateStateStore::open(temp.state()).is_ok());
            assert!(PrivateStateStore::create(temp.state()).is_err());
        }

        #[test]
        fn private_permissions_and_file_types_are_enforced() {
            let temp = TempDirectory::new();
            let mut store = PrivateStateStore::create(temp.state()).unwrap();
            store.commit(None, b"ciphertext").unwrap();
            let record = temp.state().join(RECORD);
            fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                store.read(),
                Err(StorageError::InsecurePermissions)
            ));
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
            let alias = temp.0.join("hard-link");
            fs::hard_link(&record, &alias).unwrap();
            assert!(matches!(store.read(), Err(StorageError::UnsafeFile)));
            fs::remove_file(alias).unwrap();
            drop(store);
            fs::set_permissions(temp.state(), fs::Permissions::from_mode(0o755)).unwrap();
            assert!(matches!(
                PrivateStateStore::open(temp.state()),
                Err(StorageError::InsecurePermissions)
            ));
        }

        #[test]
        fn symlinks_are_rejected_without_reading_or_overwriting_the_target() {
            let temp = TempDirectory::new();
            let mut store = PrivateStateStore::create(temp.state()).unwrap();
            let outside = temp.0.join("outside");
            fs::write(&outside, b"outside bytes").unwrap();
            symlink(&outside, temp.state().join(RECORD)).unwrap();
            assert!(matches!(store.read(), Err(StorageError::UnsafeFile)));
            assert!(store.commit(None, b"replacement").is_err());
            assert_eq!(fs::read(&outside).unwrap(), b"outside bytes");
            drop(store);
            fs::remove_file(temp.state().join(LOCK)).unwrap();
            symlink(&outside, temp.state().join(LOCK)).unwrap();
            assert!(PrivateStateStore::open(temp.state()).is_err());
            let alias = temp.0.join("directory-link");
            symlink(temp.state(), &alias).unwrap();
            assert!(PrivateStateStore::open(alias).is_err());
        }

        #[test]
        fn size_limits_reject_sparse_files_and_do_not_destroy_previous_state() {
            let temp = TempDirectory::new();
            let mut store = PrivateStateStore::create(temp.state()).unwrap();
            let old = store.commit(None, b"previous ciphertext").unwrap();
            assert!(matches!(
                store.commit(Some(old), &[]),
                Err(StorageError::LimitExceeded)
            ));
            assert!(matches!(
                store.commit(Some(old), &vec![0; MAX_RECORD_BYTES + 1]),
                Err(StorageError::LimitExceeded)
            ));
            assert_eq!(store.read().unwrap().unwrap().digest, old);
            OpenOptions::new()
                .write(true)
                .open(temp.state().join(RECORD))
                .unwrap()
                .set_len(MAX_RECORD_BYTES as u64 + 1)
                .unwrap();
            assert!(matches!(store.read(), Err(StorageError::LimitExceeded)));
        }
    }
}

#[cfg(unix)]
pub use platform::PrivateStateStore;

#[cfg(not(unix))]
mod platform {
    use super::*;
    use std::path::Path;

    #[derive(Debug)]
    pub struct PrivateStateStore;

    impl PrivateStateStore {
        pub fn create(_path: impl AsRef<Path>) -> Result<Self, StorageError> {
            Err(StorageError::UnsupportedPlatform)
        }
        pub fn open(_path: impl AsRef<Path>) -> Result<Self, StorageError> {
            Err(StorageError::UnsupportedPlatform)
        }
        pub fn read(&self) -> Result<Option<StoredState>, StorageError> {
            Err(StorageError::UnsupportedPlatform)
        }
        pub fn commit(
            &mut self,
            _expected: Option<StateDigest>,
            _ciphertext: &[u8],
        ) -> Result<StateDigest, StorageError> {
            Err(StorageError::UnsupportedPlatform)
        }
    }
}

#[cfg(not(unix))]
pub use platform::PrivateStateStore;
