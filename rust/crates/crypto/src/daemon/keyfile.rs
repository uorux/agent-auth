//! A daemon's identity key on disk (Python `load_or_create_key`).

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use crate::rng::{RandomError, array};

use super::keys::{KeyParseError, SigningKey};

/// The key file could not be created or is not safe to use.
#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{0} is not a regular file")]
    NotRegular(PathBuf),
    #[error("{path} is owned by uid {uid}, not this user")]
    WrongOwner { path: PathBuf, uid: u32 },
    #[error("{path} is accessible by other users (mode {mode:o}); fix it to 0400")]
    TooOpen { path: PathBuf, mode: u32 },
    #[error("{path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: KeyParseError,
    },
    #[error(transparent)]
    Random(#[from] RandomError),
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> KeyFileError + '_ {
    move |source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    }
}

/// The daemon's identity key: created 0400 on first start, then reused.
///
/// The key is written to a temporary file and hard-linked into place, so a
/// crash mid-write never leaves a truncated key, and two racing first
/// starts agree on one key. A key file that is a symlink, not a regular
/// file, not owned by the effective uid, or readable by anyone else is
/// refused rather than used.
pub fn load_or_create_key(path: &Path) -> Result<SigningKey, KeyFileError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(io_err(parent))?;
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => create(path, parent)?,
        Err(e) => return Err(io_err(path)(e)),
    }
    load(path, parent)
}

fn create(path: &Path, parent: &Path) -> Result<(), KeyFileError> {
    let key = SigningKey::generate()?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{name}.{}", hex::encode(array::<8>()?)));
    let written = write_new(&tmp, key.to_text().expose());
    let linked = written.and_then(|()| match fs::hard_link(&tmp, path) {
        Ok(()) => File::open(parent).and_then(|d| d.sync_all()),
        // Another process won the race; use its key.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    });
    let removed = fs::remove_file(&tmp);
    linked.map_err(io_err(path))?;
    match removed {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err(&tmp)(e)),
        _ => Ok(()),
    }
}

fn write_new(tmp: &Path, text: &str) -> io::Result<()> {
    // create_new is O_CREAT|O_EXCL, which never follows a symlink.
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(tmp)?;
    f.write_all(text.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()
}

/// `open(2)` flags std has no names for (values from each OS's headers;
/// no libc). `O_NOFOLLOW` refuses a symlink at the last component;
/// `O_NONBLOCK` keeps a FIFO swapped in for the key from hanging the open.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "s390x"
    )
))]
mod oflags {
    pub const O_NOFOLLOW: i32 = 0o400_000;
    pub const O_NONBLOCK: i32 = 0o4_000;
}
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64",
        target_arch = "powerpc"
    )
))]
mod oflags {
    pub const O_NOFOLLOW: i32 = 0o100_000;
    pub const O_NONBLOCK: i32 = 0o4_000;
}
#[cfg(target_os = "macos")]
mod oflags {
    pub const O_NOFOLLOW: i32 = 0x0100;
    pub const O_NONBLOCK: i32 = 0x0004;
}

fn load(path: &Path, parent: &Path) -> Result<SigningKey, KeyFileError> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(oflags::O_NOFOLLOW | oflags::O_NONBLOCK)
        .open(path);
    let mut file = match opened {
        Ok(f) => f,
        // ELOOP from O_NOFOLLOW: say what it means.
        Err(_) if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
            return Err(KeyFileError::NotRegular(path.to_owned()));
        }
        Err(e) => return Err(io_err(path)(e)),
    };
    // Everything is decided on the opened file, not the path.
    let meta = file.metadata().map_err(io_err(path))?;
    if !meta.file_type().is_file() {
        return Err(KeyFileError::NotRegular(path.to_owned()));
    }
    let euid = effective_uid(parent)?;
    if meta.uid() != euid {
        return Err(KeyFileError::WrongOwner {
            path: path.to_owned(),
            uid: meta.uid(),
        });
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyFileError::TooOpen {
            path: path.to_owned(),
            mode,
        });
    }
    let mut text = String::new();
    io::Read::by_ref(&mut file)
        .take(4096)
        .read_to_string(&mut text)
        .map_err(io_err(path))?;
    let key = SigningKey::from_text(&text).map_err(|source| KeyFileError::Parse {
        path: path.to_owned(),
        source,
    });
    zeroize::Zeroize::zeroize(&mut text);
    key
}

/// This process's effective uid, without libc: on Linux from
/// `/proc/self/status`; elsewhere the owner of a file it creates in `dir`.
fn effective_uid(dir: &Path) -> Result<u32, KeyFileError> {
    #[cfg(target_os = "linux")]
    {
        let _ = dir;
        let status = Path::new("/proc/self/status");
        let text = fs::read_to_string(status).map_err(io_err(status))?;
        text.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|e| e.parse().ok())
            .ok_or_else(|| {
                io_err(status)(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no effective uid in /proc/self/status",
                ))
            })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let probe = dir.join(format!(".uid-probe.{}", hex::encode(array::<8>()?)));
        let made = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
            .and_then(|f| f.metadata());
        let _ = fs::remove_file(&probe);
        made.map(|m| m.uid()).map_err(io_err(&probe))
    }
}

#[cfg(test)]
#[cfg(not(miri))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aa-keyfile-{tag}-{}",
            hex::encode(array::<6>().unwrap())
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn create_then_reuse() {
        let dir = tmpdir("reuse");
        let path = dir.join("sub").join("key");
        let a = load_or_create_key(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o400);
        assert_eq!(fs::metadata(dir.join("sub")).unwrap().mode() & 0o777, 0o700);
        let b = load_or_create_key(&path).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        assert_eq!(text.trim(), a.to_text().expose());
        // No temporary files left behind.
        let names: Vec<_> = fs::read_dir(dir.join("sub")).unwrap().collect();
        assert_eq!(names.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_open_modes_and_symlinks() {
        let dir = tmpdir("modes");
        let path = dir.join("key");
        load_or_create_key(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_or_create_key(&path),
            Err(KeyFileError::TooOpen { mode: 0o644, .. })
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_create_key(&path).is_ok());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            load_or_create_key(&link),
            Err(KeyFileError::NotRegular(_))
        ));
        // A dangling symlink is refused too, not written through.
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        assert!(load_or_create_key(&dangling).is_err());
        assert!(!dir.join("nowhere").exists());
        // A FIFO in place of the key is refused at once (no hang on open).
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_or_create_key(&fifo),
            Err(KeyFileError::NotRegular(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_garbage() {
        let dir = tmpdir("garbage");
        let path = dir.join("key");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .unwrap()
            .write_all(b"not a key")
            .unwrap();
        assert!(matches!(
            load_or_create_key(&path),
            Err(KeyFileError::Parse { .. })
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
