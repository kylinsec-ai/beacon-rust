//! A safe way to format and append arbitrary text (bformat.cpp).

use std::fmt::Write as _;

/// Formatted text buffer (formatp).
pub struct FormatP {
    /// The original buffer.
    buf: Vec<u8>,
    /// Number of bytes in our string.
    length: usize,
}

impl FormatP {
    /// Initialize a formatted buffer with `maxsz` capacity.
    pub fn init(maxsz: usize) -> FormatP {
        FormatP {
            buf: vec![0u8; maxsz],
            length: 0,
        }
    }

    /// Reset back to our original parameters to make re-use possible.
    pub fn reset(&mut self) {
        self.length = 0;
    }

    /// Add an integer (network order) to our data.
    pub fn bformat_int(&mut self, value: i32) {
        let be = value.to_be_bytes();
        self.bformat_copy(&be);
    }

    /// Copy some value into our buffer.
    pub fn bformat_copy(&mut self, src: &[u8]) {
        if src.is_empty() {
            return;
        }
        if src.len() >= (self.buf.len() - self.length) {
            return;
        }
        self.buf[self.length..self.length + src.len()].copy_from_slice(src);
        self.length += src.len();
    }

    /// Format some text into our buffer and append it (bformat_printf).
    pub fn bformat_printf(&mut self, fmt: std::fmt::Arguments<'_>) {
        let mut s = String::new();
        if s.write_fmt(fmt).is_err() {
            return;
        }
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() >= (self.buf.len() - self.length) {
            return;
        }
        self.buf[self.length..self.length + bytes.len()].copy_from_slice(bytes);
        self.length += bytes.len();
    }

    /// Free this buffer (drop it; the struct does that).
    pub fn free(&mut self) {
        self.length = 0;
        self.buf.clear();
    }

    /// Return a pointer to the string managed by this buffer.
    pub fn bformat_string(&self) -> &[u8] {
        &self.buf[..self.length]
    }

    /// Return the length of the string in this buffer.
    pub fn bformat_length(&self) -> usize {
        self.length
    }

    /// Return the string and its size.
    pub fn bformat_tostring(&mut self) -> (&[u8], usize) {
        let len = self.length;
        (&self.buf[..len], len)
    }
}

/// Initialize a formatted text buffer.
pub fn bformat_init(maxsz: usize) -> FormatP {
    FormatP::init(maxsz)
}
