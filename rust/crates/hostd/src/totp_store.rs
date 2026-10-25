//! A host's four TOTP secrets and their state files (daemons-hostd §7).
//!
//! `{state_dir}/totp/{name}`: the base32 secret (0400, created exclusively).
//! `{state_dir}/totp/{name}.state`: the [`TotpState`] (0600, replaced
//! durably). Verification of one secret is serialized (a mutex per secret),
//! and an accepted code's state is on disk before the caller acts on it.
//! An unreadable state file hard-locks its secret rather than forgetting
//! the last used step (which would make a code replayable).

use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use agent_auth_core::hostd::totp::{
    self as guard, AcceptedCode, SecretName, TotpRefusal, TotpState,
};
use agent_auth_crypto::Secret;
use agent_auth_crypto::totp::{TotpError as CodeError, TotpSecret, verify as check_code};

use crate::fsutil;

/// Why a code was not accepted (or the store failed). The text goes to the
/// broker and the human.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    #[error("no {0} secret on this host (run totp-enroll)")]
    NotEnrolled(SecretName),
    #[error("{0} is already enrolled (rotate it to replace it)")]
    AlreadyEnrolled(SecretName),
    #[error(transparent)]
    Refused(#[from] TotpRefusal),
    #[error("TOTP store: {0}")]
    Io(String),
}

#[derive(Debug)]
pub struct TotpStore {
    dir: PathBuf,
    locks: [Mutex<()>; 4],
}

fn index(name: SecretName) -> usize {
    SecretName::ALL.iter().position(|n| *n == name).unwrap_or(0)
}

fn io_err(e: &io::Error) -> TotpError {
    TotpError::Io(e.to_string())
}

impl TotpStore {
    #[must_use]
    pub fn new(dir: PathBuf) -> TotpStore {
        TotpStore {
            dir,
            locks: Default::default(),
        }
    }

    fn secret_path(&self, name: SecretName) -> PathBuf {
        self.dir.join(name.as_str())
    }

    fn state_path(&self, name: SecretName) -> PathBuf {
        self.dir.join(format!("{}.state", name.as_str()))
    }

    #[must_use]
    pub fn enrolled(&self, name: SecretName) -> bool {
        fs::symlink_metadata(self.secret_path(name)).is_ok()
    }

    /// Create one secret and return it (shown once, by the caller).
    pub fn enroll(&self, name: SecretName, replace: bool) -> Result<TotpSecret, TotpError> {
        let _guard = self.lock(name);
        fsutil::private_dir(&self.dir, 0o700).map_err(|e| io_err(&e))?;
        let path = self.secret_path(name);
        if self.enrolled(name) {
            if !replace {
                return Err(TotpError::AlreadyEnrolled(name));
            }
            fs::remove_file(&path).map_err(|e| io_err(&e))?;
        }
        let secret = TotpSecret::generate().map_err(|e| TotpError::Io(e.to_string()))?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .map_err(|e| io_err(&e))?;
        let text = secret.to_base32();
        f.write_all(text.expose().as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .and_then(|()| f.sync_all())
            .map_err(|e| io_err(&e))?;
        fsutil::remove_durably(&self.state_path(name)).map_err(|e| io_err(&e))?;
        Ok(secret)
    }

    fn lock(&self, name: SecretName) -> std::sync::MutexGuard<'_, ()> {
        self.locks
            .get(index(name))
            .unwrap_or(&self.locks[0])
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn read_secret(&self, name: SecretName) -> Result<TotpSecret, TotpError> {
        let path = self.secret_path(name);
        let meta = fs::symlink_metadata(&path).map_err(|_| TotpError::NotEnrolled(name))?;
        if !meta.file_type().is_file() {
            return Err(TotpError::Io(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let mut f = fs::File::open(&path).map_err(|_| TotpError::NotEnrolled(name))?;
        let mut buf = String::new();
        let read = f.read_to_string(&mut buf);
        let text = Secret::new(buf);
        read.map_err(|e| io_err(&e))?;
        TotpSecret::from_base32(text.expose())
            .map_err(|e| TotpError::Io(format!("{}: {e}", path.display())))
    }

    /// The state; `None` when present but unreadable.
    fn read_state(&self, name: SecretName) -> Option<TotpState> {
        match fs::read(self.state_path(name)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Some(TotpState::default()),
            Err(_) => None,
            Ok(bytes) => serde_json::from_slice(&bytes)
                .ok()
                .and_then(|v| TotpState::from_json(&v)),
        }
    }

    fn write_state(&self, name: SecretName, state: &TotpState) -> Result<(), TotpError> {
        fsutil::private_dir(&self.dir, 0o700).map_err(|e| io_err(&e))?;
        fsutil::write_atomic(
            &self.state_path(name),
            state.to_json().to_string().as_bytes(),
            0o600,
        )
        .map_err(|e| io_err(&e))
    }

    /// Accept `code` for `name` once, at `now_secs`, or say why not. The
    /// state is persisted before this returns an accepted code.
    pub fn verify(
        &self,
        name: SecretName,
        code: &str,
        now_secs: u64,
    ) -> Result<AcceptedCode, TotpError> {
        let _guard = self.lock(name);
        let secret = self.read_secret(name)?;
        let Some(mut state) = self.read_state(name) else {
            return Err(TotpRefusal::HardLocked { name }.into());
        };
        let attempt = guard::begin(&state, name, now_secs)?;
        let matched = match check_code(&secret, code, now_secs, None) {
            Ok(step) => Some(step.0),
            Err(CodeError::WrongCode | CodeError::AlreadyUsed) => None,
        };
        let result = attempt.conclude(&mut state, matched);
        if !matches!(result, Err(TotpRefusal::AlreadyUsed)) {
            self.write_state(name, &state)?;
        }
        Ok(result?)
    }

    /// Root on the host clears a (hard) lock. The last used step is kept;
    /// if the state was unreadable, codes up to the next step are refused.
    pub fn clear_lock(&self, name: SecretName, now_secs: u64) -> Result<(), TotpError> {
        let _guard = self.lock(name);
        let mut state = self.read_state(name).unwrap_or_else(|| TotpState {
            last_step: Some((now_secs / guard::STEP_SECS).saturating_add(guard::WINDOW_STEPS)),
            ..TotpState::default()
        });
        state.clear_lock();
        self.write_state(name, &state)
    }

    /// Is the secret refusing every code now (for the status)?
    #[must_use]
    pub fn locked(&self, name: SecretName, now_secs: u64) -> bool {
        match self.read_state(name) {
            None => true,
            Some(s) => s.lock_reason(name, now_secs).is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use agent_auth_core::Tier;
    use agent_auth_core::hostd::totp::Purpose;
    use std::os::unix::fs::PermissionsExt as _;

    const UD: SecretName = SecretName::new(Tier::User, Purpose::Direct);
    const RA: SecretName = SecretName::new(Tier::Root, Purpose::Arm);

    #[test]
    fn totp_codes_are_single_use_and_wrong_ones_lock_the_secret() {
        let d = TestDir::new("totp");
        let store = TotpStore::new(d.path().join("totp"));
        let secret = store.enroll(UD, false).unwrap();
        let mode = fs::metadata(d.path().join("totp/user-direct"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);
        let now = 1_700_000_000u64;
        let step = now / 30;
        let code = |s: u64| secret.code_at(s).expose().clone();
        assert_eq!(store.verify(UD, &code(step), now).unwrap().step(), step);
        let again = store.verify(UD, &code(step), now).unwrap_err();
        assert!(again.to_string().contains("already used"));
        assert!(
            store
                .verify(UD, &code(step - 1), now)
                .unwrap_err()
                .to_string()
                .contains("already used")
        );
        assert!(store.verify(UD, &code(step + 1), now).is_ok());
        assert_eq!(
            store.verify(RA, "000000", now).unwrap_err().to_string(),
            "no root-arm secret on this host (run totp-enroll)"
        );
        assert!(
            store
                .enroll(UD, false)
                .unwrap_err()
                .to_string()
                .contains("already enrolled")
        );
        let later = now + 600;
        for _ in 0..5 {
            assert_eq!(
                store.verify(UD, "000000", later).unwrap_err().to_string(),
                "wrong code"
            );
        }
        let locked = store.verify(UD, &code(later / 30), later).unwrap_err();
        assert!(locked.to_string().contains("locked"), "{locked}");
        assert!(store.locked(UD, later));
        assert!(
            store
                .verify(UD, &code((later + 400) / 30), later + 400)
                .is_ok()
        );
        // Non-digits are ignored (what was typed with a space).
        let c = code((later + 460) / 30);
        let spaced = format!("{} {}", &c[..3], &c[3..]);
        assert!(store.verify(UD, &spaced, later + 460).is_ok());
    }

    #[test]
    fn an_unreadable_state_locks_until_root_clears_it() {
        let d = TestDir::new("totp2");
        let store = TotpStore::new(d.path().join("totp"));
        let secret = store.enroll(UD, false).unwrap();
        fs::write(d.path().join("totp/user-direct.state"), b"{not json").unwrap();
        let now = 1_700_000_000u64;
        let code = secret.code_at(now / 30).expose().clone();
        assert!(matches!(
            store.verify(UD, &code, now),
            Err(TotpError::Refused(TotpRefusal::HardLocked { .. }))
        ));
        store.clear_lock(UD, now).unwrap();
        // The current window stays spent after clearing an unknown state.
        assert!(store.verify(UD, &code, now).is_err());
        let later = now + 90;
        assert!(
            store
                .verify(UD, secret.code_at(later / 30).expose(), later)
                .is_ok()
        );
    }
}
