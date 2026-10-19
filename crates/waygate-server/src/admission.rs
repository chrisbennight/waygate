//! Optional operator-owned HTTP admission, checked before either router.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;

use axum::http::{Method, Uri};

#[derive(Clone, Default)]
pub(crate) struct AdmissionGate {
    #[cfg(target_os = "linux")]
    file: Option<Arc<linux::GateFile>>,
}

impl AdmissionGate {
    pub(crate) fn new(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        anyhow::ensure!(
            path.is_absolute() && path.file_name().is_some(),
            "GATEWAY_ADMISSION_FILE must be an absolute file path"
        );
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                file: Some(Arc::new(linux::GateFile::open(path, 0)?)),
            })
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("GATEWAY_ADMISSION_FILE requires Linux")
    }

    pub(crate) async fn admits(&self, method: &Method, uri: &Uri) -> bool {
        if matches!(*method, Method::GET | Method::HEAD)
            && matches!(
                uri.path(),
                "/.well-known/jwks.json" | "/healthz" | "/readyz"
            )
        {
            return true;
        }
        #[cfg(target_os = "linux")]
        if let Some(file) = self.file.as_ref() {
            // The blocking task owns the permit through cancellation, so a
            // cancelled request cannot submit replacement work while it runs.
            let Ok(permit) = file.checks.clone().try_acquire_owned() else {
                return false;
            };
            let file = file.clone();
            return tokio::task::spawn_blocking(move || {
                let _permit = permit;
                file.is_open()
            })
            .await
            .unwrap_or_else(|_| {
                tracing::warn!("admission file check did not complete");
                false
            });
        }
        true
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::sync::Arc;

    use anyhow::Context;
    use tokio::sync::Semaphore;

    pub(super) struct GateFile {
        directory: File,
        name: CString,
        owner: u32,
        pub(super) checks: Arc<Semaphore>,
    }

    impl GateFile {
        pub(super) fn open(path: &Path, owner: u32) -> anyhow::Result<Self> {
            let parent = path.parent().context("admission file needs a directory")?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(parent)
                .context("open admission directory")?;
            let metadata = directory.metadata().context("stat admission directory")?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
                "admission directory must be root-owned and not group/world writable"
            );
            let name = CString::new(path.file_name().context("admission filename")?.as_bytes())
                .context("admission filename contains NUL")?;
            Ok(Self {
                directory,
                name,
                owner,
                checks: Arc::new(Semaphore::new(8)),
            })
        }

        pub(super) fn is_open(&self) -> bool {
            // The directory descriptor pins the reviewed mount. The worker
            // replaces only this basename, never the directory itself.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return false;
            }
            // openat returned a fresh descriptor owned only by this File.
            let mut file = unsafe { File::from_raw_fd(fd) };
            let Ok(metadata) = file.metadata() else {
                return false;
            };
            if !metadata.is_file()
                || metadata.uid() != self.owner
                || metadata.mode() & 0o022 != 0
                || metadata.len() != 5
            {
                return false;
            }
            let mut content = [0; 6];
            matches!(file.read(&mut content), Ok(5)) && &content[..5] == b"open\n"
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(path: &Path) -> super::AdmissionGate {
        let owner = std::fs::metadata(path.parent().unwrap()).unwrap().uid();
        super::AdmissionGate {
            file: Some(Arc::new(GateFile::open(path, owner).unwrap())),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        #[test]
        fn only_a_protected_regular_file_with_exact_open_bytes_admits() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("admission");
            let owner = std::fs::metadata(root.path()).unwrap().uid();
            let mut gate = GateFile::open(&path, owner).unwrap();
            assert!(!gate.is_open(), "missing file closes admission");
            for content in [b"closed\n".as_slice(), b"open", b"open\nextra", b"OPEN\n"] {
                std::fs::write(&path, content).unwrap();
                assert!(!gate.is_open());
            }
            std::fs::write(&path, b"open\n").unwrap();
            assert!(gate.is_open());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert!(
                !gate.is_open(),
                "untrusted writer cannot authorize admission"
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            if owner != 0 {
                assert!(!gate.is_open(), "unreadable file closes admission");
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            gate.owner = owner.wrapping_add(1);
            assert!(!gate.is_open());
            gate.owner = owner;
            std::fs::remove_file(&path).unwrap();
            let other = root.path().join("other");
            std::fs::write(&other, b"open\n").unwrap();
            symlink(&other, &path).unwrap();
            assert!(!gate.is_open(), "symlink is never followed");
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            assert!(!gate.is_open());
            std::fs::remove_dir(&path).unwrap();
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            assert!(!gate.is_open(), "FIFO cannot block the reader");
        }

        #[test]
        fn unsafe_or_symlinked_directories_are_refused() {
            let root = tempfile::tempdir().unwrap();
            let owner = std::fs::metadata(root.path()).unwrap().uid();
            let path = root.path().join("admission");
            assert!(GateFile::open(&path, owner.wrapping_add(1)).is_err());
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(GateFile::open(&path, owner).is_err());
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let alias = root.path().join("alias");
            symlink(root.path(), &alias).unwrap();
            assert!(GateFile::open(&alias.join("admission"), owner).is_err());
        }

        #[tokio::test]
        async fn saturation_fails_closed_without_queuing() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("admission");
            std::fs::write(&path, b"open\n").unwrap();
            let gate = fixture(&path);
            let file = gate.file.as_ref().unwrap();
            let permits = file.checks.clone().acquire_many_owned(8).await.unwrap();
            assert!(
                !gate
                    .admits(&axum::http::Method::POST, &"/mcp".parse().unwrap())
                    .await
            );
            drop(permits);
            assert!(
                gate.admits(&axum::http::Method::POST, &"/mcp".parse().unwrap())
                    .await
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) use linux::fixture;
