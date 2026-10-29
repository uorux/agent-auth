//! A fresh directory under the system temp dir, removed on drop (tests).

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct TestDir(pub PathBuf);

impl TestDir {
    #[allow(clippy::unwrap_used)]
    pub fn new(tag: &str) -> TestDir {
        let dir = std::env::temp_dir().join(format!(
            "aa-sbx-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TestDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
