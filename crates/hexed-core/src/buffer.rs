//! In-memory byte buffer with a simple overwrite-undo stack.
//!
//! P0 keeps the whole file in a `Vec<u8>`; that is fine for the malware
//! samples this tool targets (typically well under RAM). A piece-table /
//! mmap backend can later replace the storage behind this same API without
//! touching the UI or the template engine.

use std::io;
use std::path::{Path, PathBuf};

/// A reversible edit. Each history entry, when [`Buffer::apply`]-ed, mutates
/// the buffer and returns the inverse edit to push onto the opposite stack, so
/// undo and redo share one code path across overwrite/insert/delete.
#[derive(Clone)]
enum Edit {
    /// Write `bytes` at `offset` (length-preserving).
    Overwrite { offset: usize, bytes: Vec<u8> },
    /// Insert `bytes` at `offset` (grows the buffer).
    Insert { offset: usize, bytes: Vec<u8> },
    /// Remove `len` bytes at `offset` (shrinks the buffer).
    Delete { offset: usize, len: usize },
    /// Replace the entire buffer with `bytes` (used by the text editor).
    Replace { bytes: Vec<u8> },
}

pub struct Buffer {
    data: Vec<u8>,
    path: Option<PathBuf>,
    undo: Vec<Edit>,
    redo: Vec<Edit>,
    dirty: bool,
}

impl Buffer {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Buffer { data, path: None, undo: Vec::new(), redo: Vec::new(), dirty: false }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let p = path.as_ref();
        let data = std::fs::read(p)?;
        Ok(Buffer { data, path: Some(p.to_path_buf()), undo: Vec::new(), redo: Vec::new(), dirty: false })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clamped byte slice `[start, end)`.
    pub fn slice(&self, start: usize, end: usize) -> &[u8] {
        let s = start.min(self.data.len());
        let e = end.min(self.data.len());
        if s >= e {
            &[]
        } else {
            &self.data[s..e]
        }
    }

    /// Overwrite bytes at `offset` with `new` (clamped to buffer length),
    /// recording an undo entry. Does not change the buffer size.
    pub fn overwrite(&mut self, offset: usize, new: &[u8]) {
        if offset >= self.data.len() || new.is_empty() {
            return;
        }
        let end = (offset + new.len()).min(self.data.len());
        let n = end - offset;
        let old = self.data[offset..end].to_vec();
        self.data[offset..end].copy_from_slice(&new[..n]);
        self.undo.push(Edit::Overwrite { offset, bytes: old });
        self.redo.clear();
        self.dirty = true;
    }

    /// Insert `bytes` at `offset` (0..=len), growing the buffer. Undoable.
    pub fn insert(&mut self, offset: usize, bytes: &[u8]) {
        if bytes.is_empty() || offset > self.data.len() {
            return;
        }
        self.data.splice(offset..offset, bytes.iter().copied());
        self.undo.push(Edit::Delete { offset, len: bytes.len() });
        self.redo.clear();
        self.dirty = true;
    }

    /// Delete `len` bytes at `offset` (clamped), shrinking the buffer. Undoable.
    pub fn delete(&mut self, offset: usize, len: usize) {
        if len == 0 || offset >= self.data.len() {
            return;
        }
        let end = (offset + len).min(self.data.len());
        let removed: Vec<u8> = self.data.splice(offset..end, std::iter::empty()).collect();
        self.undo.push(Edit::Insert { offset, bytes: removed });
        self.redo.clear();
        self.dirty = true;
    }

    /// Apply a history edit to the data, returning the inverse edit.
    fn apply(&mut self, edit: Edit) -> Edit {
        match edit {
            Edit::Overwrite { offset, bytes } => {
                let end = offset + bytes.len();
                let cur = self.data[offset..end].to_vec();
                self.data[offset..end].copy_from_slice(&bytes);
                Edit::Overwrite { offset, bytes: cur }
            }
            Edit::Insert { offset, bytes } => {
                let len = bytes.len();
                self.data.splice(offset..offset, bytes);
                Edit::Delete { offset, len }
            }
            Edit::Delete { offset, len } => {
                let end = (offset + len).min(self.data.len());
                let removed: Vec<u8> =
                    self.data.splice(offset..end, std::iter::empty()).collect();
                Edit::Insert { offset, bytes: removed }
            }
            Edit::Replace { bytes } => {
                let old = std::mem::replace(&mut self.data, bytes);
                Edit::Replace { bytes: old }
            }
        }
    }

    /// Replace the entire buffer contents (used by the text editor), recording a
    /// single undo entry for the whole change.
    pub fn replace_all(&mut self, new: Vec<u8>) {
        if new == self.data {
            return;
        }
        let old = std::mem::replace(&mut self.data, new);
        self.undo.push(Edit::Replace { bytes: old });
        self.redo.clear();
        self.dirty = true;
    }

    pub fn undo(&mut self) -> bool {
        if let Some(edit) = self.undo.pop() {
            let inverse = self.apply(edit);
            self.redo.push(inverse);
            self.dirty = true;
            true
        } else {
            false
        }
    }

    pub fn redo(&mut self) -> bool {
        if let Some(edit) = self.redo.pop() {
            let inverse = self.apply(edit);
            self.undo.push(inverse);
            self.dirty = true;
            true
        } else {
            false
        }
    }

    pub fn save(&mut self) -> io::Result<()> {
        match &self.path {
            Some(p) => {
                std::fs::write(p, &self.data)?;
                self.dirty = false;
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "buffer has no path; use save_as")),
        }
    }

    pub fn save_as<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let p = path.as_ref();
        std::fs::write(p, &self.data)?;
        self.path = Some(p.to_path_buf());
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_and_undo_redo() {
        let mut b = Buffer::from_bytes(vec![0, 1, 2, 3, 4]);
        b.overwrite(1, &[0xAA, 0xBB]);
        assert_eq!(b.data(), &[0, 0xAA, 0xBB, 3, 4]);
        assert!(b.is_dirty());

        assert!(b.undo());
        assert_eq!(b.data(), &[0, 1, 2, 3, 4]);

        assert!(b.redo());
        assert_eq!(b.data(), &[0, 0xAA, 0xBB, 3, 4]);

        assert!(!b.redo());
    }

    #[test]
    fn replace_all_undo_redo() {
        let mut b = Buffer::from_bytes(vec![1, 2, 3]);
        b.replace_all(b"hello world".to_vec());
        assert_eq!(b.data(), b"hello world");
        assert!(b.is_dirty());
        assert!(b.undo());
        assert_eq!(b.data(), &[1, 2, 3]);
        assert!(b.redo());
        assert_eq!(b.data(), b"hello world");
        // no-op when unchanged: nothing recorded
        let mut b2 = Buffer::from_bytes(b"same".to_vec());
        b2.replace_all(b"same".to_vec());
        assert!(!b2.undo());
    }

    #[test]
    fn overwrite_clamps_to_length() {
        let mut b = Buffer::from_bytes(vec![1, 2, 3]);
        b.overwrite(2, &[9, 9, 9, 9]); // would run past the end
        assert_eq!(b.data(), &[1, 2, 9]);
    }

    #[test]
    fn insert_undo_redo() {
        let mut b = Buffer::from_bytes(vec![1, 2, 3]);
        b.insert(1, &[0xAA, 0xBB]);
        assert_eq!(b.data(), &[1, 0xAA, 0xBB, 2, 3]);
        assert!(b.undo());
        assert_eq!(b.data(), &[1, 2, 3]);
        assert!(b.redo());
        assert_eq!(b.data(), &[1, 0xAA, 0xBB, 2, 3]);
    }

    #[test]
    fn insert_at_end_and_start() {
        let mut b = Buffer::from_bytes(vec![1, 2]);
        b.insert(2, &[9]); // append
        assert_eq!(b.data(), &[1, 2, 9]);
        b.insert(0, &[0]); // prepend
        assert_eq!(b.data(), &[0, 1, 2, 9]);
        b.insert(99, &[7]); // out of range: no-op
        assert_eq!(b.data(), &[0, 1, 2, 9]);
    }

    #[test]
    fn delete_undo_redo() {
        let mut b = Buffer::from_bytes(vec![1, 2, 3, 4, 5]);
        b.delete(1, 2); // remove 2,3
        assert_eq!(b.data(), &[1, 4, 5]);
        assert!(b.undo());
        assert_eq!(b.data(), &[1, 2, 3, 4, 5]);
        assert!(b.redo());
        assert_eq!(b.data(), &[1, 4, 5]);
    }

    #[test]
    fn delete_clamps_and_mixed_history() {
        let mut b = Buffer::from_bytes(vec![1, 2, 3]);
        b.delete(2, 10); // clamp to end: remove just [3]
        assert_eq!(b.data(), &[1, 2]);
        // interleave overwrite + insert + delete, then unwind fully
        b.overwrite(0, &[9]);
        b.insert(1, &[7, 7]);
        assert_eq!(b.data(), &[9, 7, 7, 2]);
        assert!(b.undo()); // undo insert
        assert_eq!(b.data(), &[9, 2]);
        assert!(b.undo()); // undo overwrite
        assert_eq!(b.data(), &[1, 2]);
        assert!(b.undo()); // undo delete
        assert_eq!(b.data(), &[1, 2, 3]);
        assert!(!b.undo());
    }

    #[test]
    fn slice_is_clamped() {
        let b = Buffer::from_bytes(vec![1, 2, 3]);
        assert_eq!(b.slice(1, 100), &[2, 3]);
        assert_eq!(b.slice(5, 9), &[] as &[u8]);
    }
}
