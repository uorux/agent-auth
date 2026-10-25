//! Root's file operations on directories agents control (sandboxd spec
//! B-11, B-12, B-13).
//!
//! sandboxd runs as root and works inside trees whose owners (project
//! users) can rename, replace and symlink anything at any moment. Nothing
//! here follows a path an agent controls:
//!
//! - A directory is reached from a trusted root (a path from sandboxd's
//!   own config) one component at a time, each opened `O_PATH |
//!   O_DIRECTORY | O_NOFOLLOW` relative to the handle of its parent
//!   (through `/proc/self/fd/<parent>/<name>`: std has no `openat`, and the
//!   kernel resolves the parent's magic link to exactly the directory we
//!   opened, then the one name in it, without following it).
//! - Every entry of a tree is opened `O_PATH | O_NOFOLLOW` and `fstat`ed
//!   through that descriptor; what is done to it is done through
//!   `/proc/self/fd/<fd>`, which names that inode and nothing else, however
//!   the tree changes meanwhile. Symlinks are never followed nor changed.
//! - Files are created `O_CREAT | O_EXCL | O_NOFOLLOW` under a random name
//!   in a directory handle and renamed over the target in the same
//!   directory: a planted FIFO, symlink or file at the temporary name only
//!   makes the write fail (B-11c).
//! - Reads open `O_NOFOLLOW | O_NONBLOCK` and accept only regular files of
//!   a bounded size.
//!
//! ACLs are still set by `setfacl` (std has no xattr calls and this
//! workspace allows no `unsafe`), but only on paths of the form
//! `/proc/<sandboxd>/fd/<n>` for inodes verified as above, passed on stdin
//! in batches. Ownership changes use `chown(2)` through the same magic
//! links, without a subprocess.
//!
//! Residual risk (documented in DEVIATIONS.md): a project can hard-link
//! into its tree any file it could already write elsewhere (Linux's
//! `protected_hardlinks`); such a file looks like its own. Grants are
//! therefore applied only to entries owned by the tree's project and with
//! one link, ownership is changed only from the expected previous owners
//! and never for a multiply-linked file, and removing an entry for a uid
//! is applied to every entry (removing access is harmless). `setfacl`
//! itself is a separate root process trusted to parse its stdin; and the
//! `X` permission is evaluated when it runs (an agent can still chmod +x a
//! file of its own project first, which gives the reader nothing new).

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

/// Deeper directories are left alone (and logged): each level holds a
/// descriptor while its subtree is walked.
pub const MAX_DEPTH: usize = 128;
/// Paths per `setfacl` run.
pub const ACL_BATCH: usize = 128;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// One name inside a directory: not empty, no `/`, not `.` or `..`, no NUL.
pub fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(invalid(format!("not a file name: {name:?}")));
    }
    Ok(())
}

fn magic(fd: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// The path another process (root) reaches this descriptor's inode by.
fn magic_for_child(fd: &File) -> String {
    format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd())
}

fn open_path(path: &Path, extra: i32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | extra)
        .open(path)
}

/// A directory, held by an `O_PATH` descriptor.
#[derive(Debug)]
pub struct Dir {
    fd: File,
}

impl Dir {
    /// A directory sandboxd's own config names (its ancestors are root's):
    /// symlinks along it are followed.
    pub fn open_trusted(path: &Path) -> io::Result<Dir> {
        Ok(Dir {
            fd: open_path(path, libc::O_DIRECTORY)?,
        })
    }

    /// `root` (trusted), then each of `names` without following anything.
    pub fn open_beneath(root: &Path, names: &[&str]) -> io::Result<Dir> {
        let mut dir = Dir::open_trusted(root)?;
        for name in names {
            dir = dir.child(name)?;
        }
        Ok(dir)
    }

    /// The subdirectory `name`; a symlink or anything else fails.
    pub fn child(&self, name: &str) -> io::Result<Dir> {
        check_name(name)?;
        Ok(Dir {
            fd: open_path(&self.entry_path(name), libc::O_DIRECTORY | libc::O_NOFOLLOW)?,
        })
    }

    /// `/proc/self/fd/<this>/<name>`: `name` in exactly this directory.
    fn entry_path(&self, name: &str) -> PathBuf {
        magic(&self.fd).join(name)
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        self.fd.metadata()
    }

    /// `mkdir name` (mode `mode`) if it is missing, then the directory.
    pub fn ensure_child(&self, name: &str, mode: u32) -> io::Result<Dir> {
        check_name(name)?;
        match fs::DirBuilder::new()
            .mode(mode)
            .create(self.entry_path(name))
        {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        self.child(name)
    }

    /// Owner `uid:uid` and mode `mode` for this directory itself.
    pub fn set_owner_mode(&self, uid: Option<u32>, mode: u32) -> io::Result<()> {
        let p = magic(&self.fd);
        if let Some(uid) = uid {
            std::os::unix::fs::chown(&p, Some(uid), Some(uid))?;
        }
        fs::set_permissions(&p, fs::Permissions::from_mode(mode))
    }

    /// A regular file's contents (at most `max` bytes; larger fails), or
    /// `None` if there is nothing by that name. Anything but a regular
    /// file (a symlink, a FIFO, a directory) is an error.
    pub fn read_file(&self, name: &str, max: u64) -> io::Result<Option<(Vec<u8>, Metadata)>> {
        check_name(name)?;
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(self.entry_path(name))
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = f.metadata()?;
        if !meta.is_file() {
            return Err(invalid(format!("{name} is not a regular file")));
        }
        if meta.len() > max {
            return Err(invalid(format!("{name} is larger than {max} bytes")));
        }
        let mut buf = Vec::new();
        f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
        if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
            return Err(invalid(format!("{name} is larger than {max} bytes")));
        }
        Ok(Some((buf, meta)))
    }

    /// Replace `name` with `data`: a new file under a random name (created
    /// exclusively, never following), written, fsynced, given `uid:uid` and
    /// `mode`, renamed over `name`.
    pub fn write_file(
        &self,
        name: &str,
        data: &[u8],
        uid: Option<u32>,
        mode: u32,
    ) -> io::Result<()> {
        check_name(name)?;
        let tmp = format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple());
        let tmp_path = self.entry_path(&tmp);
        let done = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp_path)?;
            f.write_all(data)?;
            f.sync_all()?;
            if let Some(uid) = uid {
                std::os::unix::fs::fchown(&f, Some(uid), Some(uid))?;
            }
            f.set_permissions(fs::Permissions::from_mode(mode))?;
            fs::rename(&tmp_path, self.entry_path(name))?;
            Ok(())
        })();
        if done.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        done
    }

    /// Remove the entry `name` (not following it); missing is fine.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        match fs::remove_file(self.entry_path(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// What `name` is, without following it (`None`: nothing there).
    pub fn entry(&self, name: &str) -> io::Result<Option<Entry>> {
        check_name(name)?;
        match open_path(&self.entry_path(name), libc::O_NOFOLLOW) {
            Ok(fd) => {
                let meta = fd.metadata()?;
                Ok(Some(Entry { fd, meta }))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The target of the symlink `name` (`None`: not a symlink, or gone).
    pub fn read_link(&self, name: &str) -> io::Result<Option<PathBuf>> {
        check_name(name)?;
        match fs::read_link(self.entry_path(name)) {
            Ok(t) => Ok(Some(t)),
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::InvalidInput =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// The names in this directory.
    fn names(&self) -> io::Result<Vec<OsString>> {
        let mut out = Vec::new();
        for e in fs::read_dir(magic(&self.fd))? {
            out.push(e?.file_name());
        }
        Ok(out)
    }

    /// The path a unix socket in this directory is connected by.
    #[must_use]
    pub fn socket_path(&self, entry: &Entry) -> PathBuf {
        let _ = self;
        magic(&entry.fd)
    }
}

/// An entry opened without following it.
#[derive(Debug)]
pub struct Entry {
    fd: File,
    pub meta: Metadata,
}

impl Entry {
    #[must_use]
    pub fn is_socket(&self) -> bool {
        use std::os::unix::fs::FileTypeExt as _;
        self.meta.file_type().is_socket()
    }

    /// `/proc/self/fd/<n>`: this inode, for `connect(2)` and the like.
    #[must_use]
    pub fn magic_path(&self) -> PathBuf {
        magic(&self.fd)
    }
}

/// Walk `top` and every directory below it (not following symlinks), at
/// most [`MAX_DEPTH`] deep, calling `visit` for `top` and every entry.
fn walk(top: &Dir, visit: &mut dyn FnMut(Entry) -> io::Result<()>) -> io::Result<()> {
    let first = Entry {
        fd: top.fd.try_clone()?,
        meta: top.metadata()?,
    };
    visit(first)?;
    walk_dir(top, 0, visit)
}

fn walk_dir(
    dir: &Dir,
    depth: usize,
    visit: &mut dyn FnMut(Entry) -> io::Result<()>,
) -> io::Result<()> {
    for name in dir.names()? {
        let path = magic(&dir.fd).join(&name);
        let fd = match open_path(&path, libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            // Gone meanwhile: nothing to do.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let meta = fd.metadata()?;
        let sub = if meta.is_dir() {
            if depth >= MAX_DEPTH {
                tracing::warn!(
                    name = %String::from_utf8_lossy(name.as_bytes()),
                    "directory deeper than {MAX_DEPTH} levels left as it is"
                );
                None
            } else {
                Some(Dir {
                    fd: fd.try_clone()?,
                })
            }
        } else {
            None
        };
        visit(Entry { fd, meta })?;
        if let Some(sub) = sub {
            walk_dir(&sub, depth.saturating_add(1), visit)?;
        }
    }
    Ok(())
}

/// What a tree operation did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeReport {
    pub changed: u64,
    pub skipped: u64,
}

/// `chown -R --no-dereference uid:uid`, for entries now owned by one of
/// `from` (and, for regular files, linked once). Symlinks are left as they
/// are (their owner grants nothing).
pub fn chown_tree(top: &Dir, uid: u32, from: &[u32]) -> io::Result<TreeReport> {
    let mut report = TreeReport::default();
    walk(top, &mut |e| {
        let ft = e.meta.file_type();
        let eligible = chown_eligible(
            ft.is_symlink(),
            ft.is_file(),
            e.meta.uid(),
            e.meta.nlink(),
            from,
        );
        if !eligible {
            if e.meta.uid() != uid || e.meta.gid() != uid {
                report.skipped = report.skipped.saturating_add(1);
            }
            return Ok(());
        }
        if e.meta.uid() == uid && e.meta.gid() == uid {
            return Ok(());
        }
        std::os::unix::fs::chown(magic(&e.fd), Some(uid), Some(uid))?;
        report.changed = report.changed.saturating_add(1);
        Ok(())
    })?;
    Ok(report)
}

/// Whether `chown_tree` changes an entry: not a symlink, owned by one of
/// `from`, and (a regular file) linked once.
#[must_use]
pub fn chown_eligible(symlink: bool, file: bool, owner: u32, nlink: u64, from: &[u32]) -> bool {
    !symlink && from.contains(&owner) && (!file || nlink == 1)
}

/// A named user's ACL entry: give `perms` (`rX` or `rwX`, also as the
/// directories' default), or remove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclChange {
    Grant { uid: u32, write: bool },
    Revoke { uid: u32 },
}

impl AclChange {
    fn args(self, dir: bool) -> [String; 2] {
        match self {
            AclChange::Grant { uid, write } => {
                let p = if write { "rwX" } else { "rX" };
                let spec = if dir {
                    format!("u:{uid}:{p},d:u:{uid}:{p}")
                } else {
                    format!("u:{uid}:{p}")
                };
                ["-m".to_owned(), spec]
            }
            AclChange::Revoke { uid } => {
                let spec = if dir {
                    format!("u:{uid},d:u:{uid}")
                } else {
                    format!("u:{uid}")
                };
                ["-x".to_owned(), spec]
            }
        }
    }
}

fn run_setfacl(setfacl: &str, change: AclChange, dir: bool, batch: &[File]) -> io::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut list = String::new();
    for f in batch {
        list.push_str(&magic_for_child(f));
        list.push('\n');
    }
    let mut child = Command::new(setfacl)
        .args(change.args(dir))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/run/current-system/sw/bin:/usr/bin:/bin")
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(list.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stdout));
        Err(io::Error::other(format!(
            "setfacl failed ({}): {}",
            out.status.code().unwrap_or(-1),
            text.trim().chars().take(300).collect::<String>()
        )))
    }
}

/// Apply `change` to `top` and everything below it: regular files and
/// directories only (directories also get it as their default, so files
/// created later inherit it). A grant applies only to entries owned by
/// `owner` (the tree's project) and, for files, linked once.
pub fn acl_tree(top: &Dir, setfacl: &str, change: AclChange, owner: u32) -> io::Result<TreeReport> {
    let mut report = TreeReport::default();
    let mut dirs: Vec<File> = Vec::new();
    let mut files: Vec<File> = Vec::new();
    walk(top, &mut |e| {
        let ft = e.meta.file_type();
        if !(ft.is_dir() || ft.is_file()) {
            return Ok(());
        }
        if matches!(change, AclChange::Grant { .. })
            && (e.meta.uid() != owner || (ft.is_file() && e.meta.nlink() != 1))
        {
            report.skipped = report.skipped.saturating_add(1);
            return Ok(());
        }
        report.changed = report.changed.saturating_add(1);
        if ft.is_dir() {
            dirs.push(e.fd);
            if dirs.len() >= ACL_BATCH {
                run_setfacl(setfacl, change, true, &dirs)?;
                dirs.clear();
            }
        } else {
            files.push(e.fd);
            if files.len() >= ACL_BATCH {
                run_setfacl(setfacl, change, false, &files)?;
                files.clear();
            }
        }
        Ok(())
    })?;
    run_setfacl(setfacl, change, true, &dirs)?;
    run_setfacl(setfacl, change, false, &files)?;
    Ok(report)
}

/// `path` as names below `root` (`None` if it is not below it, or has
/// `.`/`..` components).
#[must_use]
pub fn names_below<'a>(root: &Path, path: &'a Path) -> Option<Vec<&'a str>> {
    let rest = path.strip_prefix(root).ok()?;
    let mut out = Vec::new();
    for c in rest.components() {
        match c {
            Component::Normal(n) => out.push(n.to_str()?),
            _ => return None,
        }
    }
    Some(out)
}

/// Where the codex app-server's socket is, reached without following
/// anything the project controls (B-13). codex leaves a symlink at the
/// path it was given (`/tmp/<name>` inside its unit) to the real socket
/// under the unit's `/tmp`, which is `tmp` here: the link's target is
/// read, never followed, and must be `/tmp/<plain names>`; each directory
/// on the way is opened without following, and the final entry must be a
/// socket. What is returned names that socket's inode only.
pub fn codex_socket(tmp: &Dir, name: &str) -> io::Result<Option<Entry>> {
    let Some(first) = tmp.entry(name)? else {
        return Ok(None);
    };
    if first.is_socket() {
        return Ok(Some(first));
    }
    if !first.meta.file_type().is_symlink() {
        return Ok(None);
    }
    let Some(target) = tmp.read_link(name)? else {
        return Ok(None);
    };
    let Some(parts) = names_below(Path::new("/tmp"), &target) else {
        return Ok(None);
    };
    if !target.is_absolute() || parts.is_empty() {
        return Ok(None);
    }
    let (last, dirs) = match parts.split_last() {
        Some(x) => x,
        None => return Ok(None),
    };
    let mut dir = Dir {
        fd: tmp.fd.try_clone()?,
    };
    for d in dirs {
        dir = match dir.child(d) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
    }
    match dir.entry(last)? {
        Some(e) if e.is_socket() => Ok(Some(e)),
        _ => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::os::unix::fs::symlink;

    fn me() -> u32 {
        fs::metadata("/proc/self").unwrap().uid()
    }

    #[test]
    fn names_are_single_components() {
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            assert!(check_name(bad).is_err());
        }
        assert!(check_name(".codex").is_ok());
        assert_eq!(
            names_below(Path::new("/tmp"), Path::new("/tmp/a/b")),
            Some(vec!["a", "b"])
        );
        assert_eq!(
            names_below(Path::new("/tmp"), Path::new("/tmp/../run/x")),
            None
        );
        assert_eq!(names_below(Path::new("/tmp"), Path::new("/run/x")), None);
    }

    #[test]
    fn a_symlinked_directory_is_never_entered() {
        let d = TestDir::new("fs-sym");
        fs::create_dir_all(d.path().join("homes/p/real")).unwrap();
        fs::create_dir_all(d.path().join("secret")).unwrap();
        fs::write(d.path().join("secret/token"), b"root only").unwrap();
        symlink(d.path().join("secret"), d.path().join("homes/p/.codex")).unwrap();
        let home = Dir::open_beneath(d.path(), &["homes", "p"]).unwrap();
        assert!(home.child(".codex").is_err());
        assert!(home.ensure_child(".codex", 0o700).is_err());
        assert!(Dir::open_beneath(d.path(), &["homes", "p", ".codex"]).is_err());
        // A symlinked file is not read through.
        symlink(
            d.path().join("secret/token"),
            d.path().join("homes/p/real/auth.json"),
        )
        .unwrap();
        let real = home.child("real").unwrap();
        assert!(real.read_file("auth.json", 1024).is_err());
        // Writing replaces the link itself; the target is untouched.
        real.write_file("auth.json", b"new", None, 0o600).unwrap();
        assert_eq!(
            fs::read(d.path().join("secret/token")).unwrap(),
            b"root only"
        );
        assert_eq!(
            real.read_file("auth.json", 1024).unwrap().unwrap().0,
            b"new"
        );
    }

    #[test]
    fn a_planted_fifo_or_temp_name_does_not_block_a_write() {
        let d = TestDir::new("fs-fifo");
        let dir = Dir::open_trusted(d.path()).unwrap();
        let status = Command::new("mkfifo")
            .arg(d.path().join("auth.json"))
            .status();
        if status.is_ok_and(|s| s.success()) {
            // Reading a FIFO fails at once (never blocks).
            assert!(dir.read_file("auth.json", 1024).is_err());
            dir.write_file("auth.json", b"x", None, 0o600).unwrap();
            assert_eq!(fs::read(d.path().join("auth.json")).unwrap(), b"x");
        }
        let meta = fs::metadata(d.path().join("auth.json")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // Oversized files are refused.
        fs::write(d.path().join("big"), vec![b'a'; 2048]).unwrap();
        assert!(dir.read_file("big", 1024).is_err());
        assert!(dir.read_file("missing", 1024).unwrap().is_none());
    }

    #[test]
    fn chown_walks_without_following_and_only_from_expected_owners() {
        let d = TestDir::new("fs-chown");
        fs::create_dir_all(d.path().join("p/sub")).unwrap();
        fs::write(d.path().join("p/sub/f"), b"x").unwrap();
        fs::write(d.path().join("outside"), b"x").unwrap();
        symlink(d.path().join("outside"), d.path().join("p/link")).unwrap();
        fs::hard_link(d.path().join("outside"), d.path().join("p/hard")).unwrap();
        let top = Dir::open_beneath(d.path(), &["p"]).unwrap();
        let uid = me();
        // Nothing is owned by an expected previous owner: nothing changes
        // (as a non-root test, no other change can be made).
        let r = chown_tree(&top, uid.wrapping_add(7), &[uid.wrapping_add(9)]).unwrap();
        assert_eq!(r.changed, 0);
        assert_eq!(r.skipped, 5, "p, sub, f, link, hard");
        assert!(chown_eligible(false, true, 5, 1, &[5]));
        assert!(!chown_eligible(false, true, 5, 2, &[5]), "hard-linked");
        assert!(!chown_eligible(true, false, 5, 1, &[5]), "symlink");
        assert!(!chown_eligible(false, false, 6, 1, &[5]), "another owner");
        assert!(chown_eligible(false, false, 5, 3, &[5]), "a directory");
    }

    #[test]
    fn acls_reach_only_the_tree_and_files_it_owns() {
        let d = TestDir::new("fs-acl");
        fs::create_dir_all(d.path().join("p/sub")).unwrap();
        fs::write(d.path().join("p/sub/f"), b"x").unwrap();
        fs::write(d.path().join("outside"), b"x").unwrap();
        symlink(d.path().join("outside"), d.path().join("p/link")).unwrap();
        fs::hard_link(d.path().join("outside"), d.path().join("p/hard")).unwrap();
        let top = Dir::open_beneath(d.path(), &["p"]).unwrap();
        let uid = me();
        let grant = AclChange::Grant { uid, write: false };
        let setfacl = "setfacl";
        match acl_tree(&top, setfacl, grant, uid) {
            Ok(r) => {
                // p, p/sub, p/sub/f (the hard link is skipped).
                assert_eq!(r.changed, 3);
                assert_eq!(r.skipped, 1);
                let show = |p: &str| {
                    String::from_utf8(
                        Command::new("getfacl")
                            .args(["-p", "-c"])
                            .arg(d.path().join(p))
                            .output()
                            .unwrap()
                            .stdout,
                    )
                    .unwrap()
                };
                let entry = format!("user:{uid}:r");
                assert!(show("p/sub/f").contains(&entry));
                assert!(show("p/sub").contains(&format!("default:user:{uid}:r-x")));
                assert!(!show("outside").contains(&entry));
                acl_tree(&top, setfacl, AclChange::Revoke { uid }, uid).unwrap();
                assert!(!show("p/sub/f").contains(&entry));
                assert!(!show("p/sub").contains(&format!("default:user:{uid}")));
            }
            // No setfacl, or a filesystem without ACLs: nothing to check.
            Err(e) => eprintln!("skipped: {e}"),
        }
    }

    #[test]
    fn codex_socket_resolution() {
        let d = TestDir::new("fs-codex");
        let tmp = Dir::open_trusted(d.path()).unwrap();
        assert!(codex_socket(&tmp, "codex-a.sock").unwrap().is_none());
        fs::create_dir_all(d.path().join("codex-daemon-40001")).unwrap();
        let real = d.path().join("codex-daemon-40001").join("c376b6");
        let _l = std::os::unix::net::UnixListener::bind(&real).unwrap();
        symlink(
            "/tmp/codex-daemon-40001/c376b6",
            d.path().join("codex-a.sock"),
        )
        .unwrap();
        let e = codex_socket(&tmp, "codex-a.sock").unwrap().unwrap();
        assert!(e.is_socket());
        assert!(std::os::unix::net::UnixStream::connect(e.magic_path()).is_ok());
        for (i, elsewhere) in [
            "/run/sandboxd/ctl.sock",
            "/tmp/../run/x",
            "relative",
            "/tmp",
        ]
        .iter()
        .enumerate()
        {
            let name = format!("codex-{i}.sock");
            symlink(elsewhere, d.path().join(&name)).unwrap();
            assert!(codex_socket(&tmp, &name).unwrap().is_none(), "{elsewhere}");
        }
        // A symlinked directory on the way is not followed.
        symlink(d.path().join("codex-daemon-40001"), d.path().join("sneaky")).unwrap();
        symlink("/tmp/sneaky/c376b6", d.path().join("codex-s.sock")).unwrap();
        assert!(codex_socket(&tmp, "codex-s.sock").unwrap().is_none());
        // The final entry must be a socket, not a link to one.
        symlink(&real, d.path().join("codex-daemon-40001").join("hop")).unwrap();
        symlink("/tmp/codex-daemon-40001/hop", d.path().join("codex-h.sock")).unwrap();
        assert!(codex_socket(&tmp, "codex-h.sock").unwrap().is_none());
    }

    #[test]
    fn a_socket_path_longer_than_a_unix_address_connects() {
        let d = TestDir::new("fs-long");
        let deep = d.path().join("d".repeat(60)).join("codex-daemon-40001");
        fs::create_dir_all(&deep).unwrap();
        let tmp = Dir::open_trusted(d.path()).unwrap();
        let dir = tmp
            .child(&"d".repeat(60))
            .unwrap()
            .child("codex-daemon-40001")
            .unwrap();
        let name = "c".repeat(64);
        assert!(deep.join(&name).as_os_str().len() > 108);
        let listener = std::os::unix::net::UnixListener::bind(dir.entry_path(&name)).unwrap();
        let e = dir.entry(&name).unwrap().unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(e.magic_path()).unwrap();
        let (mut conn, _) = listener.accept().unwrap();
        conn.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
    }
}
