//! Durable small files: written to a temporary file, fsynced, renamed into
//! place, and the directory fsynced (daemons bug 7: the Python's TOTP state,
//! lockdown flag and spool survived a crash but not a power loss).

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

/// `mkdir -p` with mode `mode` for what it creates.
pub fn private_dir(dir: &Path, mode: u32) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(mode).create(dir)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Replace `path` with `data`, durably. The file gets `mode`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp"));
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(dir)
}

/// Remove `path` durably; `Ok(false)` if it was not there.
pub fn remove_durably(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                sync_dir(dir)?;
            }
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Does `path` exist? An error other than "not found" counts as yes, so a
/// lockdown flag that cannot be checked holds (fail closed).
#[must_use]
pub fn exists_or_unknown(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
pub(crate) mod testdir {
    use std::path::PathBuf;

    /// A fresh directory under the system temp dir, removed on drop.
    #[derive(Debug)]
    pub struct TestDir(pub PathBuf);

    impl TestDir {
        pub fn new(tag: &str) -> TestDir {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir =
                std::env::temp_dir().join(format!("aa-hostd-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            TestDir(dir)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdir::TestDir;
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn atomic_writes() {
        let d = TestDir::new("fs");
        let p = d.path().join("a").join("f.json");
        private_dir(p.parent().unwrap(), 0o700).unwrap();
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(exists_or_unknown(&p));
        assert!(remove_durably(&p).unwrap());
        assert!(!remove_durably(&p).unwrap());
        assert!(!exists_or_unknown(&p));
        // No temp files left.
        assert_eq!(fs::read_dir(p.parent().unwrap()).unwrap().count(), 0);
    }
}
