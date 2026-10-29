//! A running job's output, capped to its end (daemons-hostd spec §9.1).
//!
//! The end is kept because that is where a failure explains itself. The
//! Python's drop loop could leave up to one chunk beyond the cap and then
//! slice it off without setting `truncated` (bug 1): here `truncated` is
//! true exactly when more was produced than is kept.

use std::collections::VecDeque;

/// Collects output chunks, keeping the last `cap` bytes.
#[derive(Debug, Clone)]
pub struct OutputTail {
    cap: usize,
    chunks: VecDeque<Vec<u8>>,
    /// Bytes held in `chunks` (at most `cap` plus one chunk).
    held: usize,
    /// Bytes produced in all.
    produced: u64,
}

/// The kept output and whether anything was cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptOutput {
    /// The last `min(cap, produced)` bytes.
    pub bytes: Vec<u8>,
    pub truncated: bool,
    /// Everything the job wrote.
    pub produced: u64,
}

impl OutputTail {
    #[must_use]
    pub fn new(cap: usize) -> OutputTail {
        OutputTail {
            cap,
            chunks: VecDeque::new(),
            held: 0,
            produced: 0,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.produced = self
            .produced
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        self.chunks.push_back(chunk.to_vec());
        self.held = self.held.saturating_add(chunk.len());
        // Drop whole chunks while what remains still covers the cap.
        while let Some(first) = self.chunks.front() {
            if self.held.saturating_sub(first.len()) >= self.cap {
                self.held = self.held.saturating_sub(first.len());
                self.chunks.pop_front();
            } else {
                break;
            }
        }
    }

    #[must_use]
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// The kept output: the last `cap` bytes, and `truncated` iff more was
    /// produced.
    #[must_use]
    pub fn finish(self) -> KeptOutput {
        let mut all: Vec<u8> = Vec::with_capacity(self.held);
        for chunk in &self.chunks {
            all.extend_from_slice(chunk);
        }
        let cut = all.len().saturating_sub(self.cap);
        let bytes = all.split_off(cut);
        let kept = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        KeptOutput {
            truncated: self.produced > kept,
            bytes,
            produced: self.produced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_python_counterexample_is_truncated() {
        // Bug 1: with a cap of 100, chunks of 60 + 60 dropped nothing and
        // the final slice cut 20 bytes without saying so.
        let mut tail = OutputTail::new(100);
        tail.push(&[1; 60]);
        tail.push(&[2; 60]);
        let out = tail.finish();
        assert_eq!(out.bytes.len(), 100);
        assert!(out.truncated);
        assert_eq!(out.produced, 120);
        assert_eq!(&out.bytes[..40], &[1; 40]);
    }

    #[test]
    fn exactly_the_cap_is_not_truncated() {
        let mut tail = OutputTail::new(10);
        tail.push(b"0123456789");
        let out = tail.finish();
        assert_eq!(out.bytes, b"0123456789");
        assert!(!out.truncated);
        let empty = OutputTail::new(10).finish();
        assert!(empty.bytes.is_empty() && !empty.truncated);
    }

    proptest! {
        /// The kept output is the end of everything written, at most `cap`
        /// bytes, and `truncated` says whether anything was cut.
        #[test]
        fn keeps_the_end(cap in 0usize..64, chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..12)) {
            let mut tail = OutputTail::new(cap);
            let mut all = Vec::new();
            for c in &chunks {
                tail.push(c);
                all.extend_from_slice(c);
            }
            let out = tail.finish();
            let start = all.len().saturating_sub(cap);
            prop_assert_eq!(&out.bytes[..], &all[start..]);
            prop_assert_eq!(out.truncated, all.len() > cap);
            prop_assert_eq!(out.produced, u64::try_from(all.len()).unwrap());
        }
    }
}
