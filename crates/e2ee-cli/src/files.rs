//! Local file boundaries for user-selected imports and private new exports.
use super::{check_interrupted, CliError};
use std::{
    fs,
    fs::File,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

pub(super) fn require_new_destination(path: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CliError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn read_bounded_file(
    path: &Path,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    read_regular(path, maximum, false)
}
pub(super) fn read_backup_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    read_regular(path, e2ee_client::archive::MAX_ARCHIVE_BYTES, true)
}
fn read_regular(
    path: &Path,
    maximum: usize,
    no_follow: bool,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let metadata = if no_follow {
        fs::symlink_metadata(path)?
    } else {
        fs::metadata(path)?
    };
    if !metadata.is_file() {
        return Err(CliError::InvalidInput);
    }
    #[cfg(unix)]
    let file = {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
        let flags = libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | libc::O_NOCTTY
            | if no_follow { libc::O_NOFOLLOW } else { 0 };
        OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CliError::InvalidInput);
    }
    if metadata.len() > maximum as u64 {
        return Err(CliError::FileTooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(CliError::FileTooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    publish_private(path, bytes, check_interrupted, File::sync_all)
}
#[cfg(not(unix))]
pub(super) fn write_new_private(_path: &Path, _bytes: &[u8]) -> Result<(), CliError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private output requires a Unix host",
    )
    .into())
}

#[cfg(unix)]
fn publish_private(
    path: &Path,
    bytes: &[u8],
    before_publish: impl FnOnce() -> Result<(), CliError>,
    sync_directory: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), CliError> {
    use std::{
        fs::OpenOptions,
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    require_new_destination(path)?;
    if path.file_name().is_none() {
        return Err(CliError::InvalidInput);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    let (temporary, mut file) = (0..4)
        .find_map(|_| {
            let mut random = [0; 16];
            if getrandom::fill(&mut random).is_err() {
                return Some(Err(io::Error::other("private export randomness failed")));
            }
            let temporary = parent.join(format!(
                "pending-e2ee-export-{}.tmp",
                super::encode_hex(&random)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
            {
                Ok(file) => Some(Ok((temporary, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "temporary export collision",
            ))
        })?;
    let prepared = (|| {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(CliError::UnsafeOutput);
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        before_publish()
    })();
    drop(file);
    if let Err(error) = prepared {
        remove_pending(&temporary, &directory)?;
        return Err(error);
    }
    // link creates the destination only if absent, and exposes an already
    // complete, synced inode. rename would silently overwrite another export.
    if let Err(error) = fs::hard_link(&temporary, path) {
        remove_pending(&temporary, &directory)?;
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            CliError::DestinationExists
        } else {
            CliError::AtomicOutputUnavailable
        });
    }
    // Publication already happened. Never remove the selected destination to
    // compensate for a cleanup/sync failure; callers must inspect before retrying.
    fs::remove_file(&temporary).map_err(|_| CliError::OutputCommitUncertain)?;
    sync_directory(&directory).map_err(|_| CliError::OutputCommitUncertain)
}

#[cfg(unix)]
fn remove_pending(path: &Path, directory: &File) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(CliError::OutputCleanupUncertain),
    }
    directory
        .sync_all()
        .map_err(|_| CliError::OutputCleanupUncertain)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        path::PathBuf,
        process::Command,
    };

    struct Sandbox(PathBuf);
    impl Sandbox {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir()
                .join(format!("e2ee-atomic-{}", super::super::encode_hex(&nonce)));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn entries(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect()
        }
    }
    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn selected_name_is_absent_until_complete_private_inode_is_published() {
        let root = Sandbox::new();
        let path = root.0.join("selected.bin");
        let bytes = vec![0xa5; 1024 * 1024];
        publish_private(
            &path,
            &bytes,
            || {
                assert!(!path.exists());
                let pending = root.entries();
                assert_eq!(pending.len(), 1);
                let metadata = fs::metadata(&pending[0]).unwrap();
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                assert_eq!(metadata.nlink(), 1);
                assert_eq!(fs::read(&pending[0]).unwrap(), bytes);
                Ok(())
            },
            File::sync_all,
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(root.entries(), [path]);
    }
    #[test]
    fn cancellation_before_publication_cleans_private_temporary_without_publishing() {
        let root = Sandbox::new();
        let path = root.0.join("cancelled.txt");
        assert!(matches!(
            publish_private(
                &path,
                b"never publish",
                || Err(CliError::Interrupted),
                File::sync_all
            ),
            Err(CliError::Interrupted)
        ));
        assert!(!path.exists());
        assert!(root.entries().is_empty());
    }
    #[test]
    fn destination_created_during_preparation_is_preserved_and_pending_file_removed() {
        let root = Sandbox::new();
        let path = root.0.join("raced.txt");
        let result = publish_private(
            &path,
            b"new plaintext",
            || {
                fs::write(&path, b"keep the other export")?;
                Ok(())
            },
            File::sync_all,
        );
        assert!(matches!(result, Err(CliError::DestinationExists)));
        assert_eq!(fs::read(&path).unwrap(), b"keep the other export");
        assert_eq!(root.entries(), [path]);
    }
    #[test]
    fn failure_after_publication_reports_uncertainty_and_keeps_complete_output() {
        let root = Sandbox::new();
        let path = root.0.join("published.txt");
        let result = publish_private(
            &path,
            b"already committed output",
            || Ok(()),
            |_| Err(io::Error::other("injected directory-sync failure")),
        );
        assert!(matches!(result, Err(CliError::OutputCommitUncertain)));
        assert_eq!(fs::read(&path).unwrap(), b"already committed output");
        assert_eq!(root.entries(), [path]);
    }
    #[test]
    fn bounded_regular_imports_reject_pipes_and_directories_but_preserve_explicit_file_links() {
        let root = Sandbox::new();
        let fifo = root.0.join("pipe");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(matches!(
            read_bounded_file(&fifo, 128),
            Err(CliError::InvalidInput)
        ));
        assert!(matches!(
            read_bounded_file(&root.0, 128),
            Err(CliError::InvalidInput)
        ));
        let file = root.0.join("input");
        fs::write(&file, b"bounded bytes").unwrap();
        let link = root.0.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(&**read_bounded_file(&link, 128).unwrap(), b"bounded bytes");
        assert!(matches!(
            read_backup_file(&link),
            Err(CliError::InvalidInput)
        ));
        assert!(matches!(
            read_bounded_file(&file, 2),
            Err(CliError::FileTooLarge)
        ));
    }
    #[test]
    fn dangling_destination_link_is_rejected_without_creating_pending_plaintext() {
        let root = Sandbox::new();
        let path = root.0.join("selected");
        std::os::unix::fs::symlink(root.0.join("missing-target"), &path).unwrap();
        assert!(write_new_private(&path, b"must not be written").is_err());
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(root.entries(), [path]);
    }
}
