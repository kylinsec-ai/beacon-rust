//! 一种安全的方式来格式化并追加任意文本（bformat.cpp）。
//! A safe way to format and append arbitrary text (bformat.cpp).

use std::fmt::Write as _;

/// 格式化文本缓冲区（formatp）。
/// Formatted text buffer (formatp).
pub struct FormatP {
    /// 原始缓冲区。
    /// The original buffer.
    buf: Vec<u8>,
    /// 我们字符串中的字节数。
    /// Number of bytes in our string.
    length: usize,
}

impl FormatP {
    /// 以 `maxsz` 容量初始化格式化缓冲区。
    /// Initialize a formatted buffer with `maxsz` capacity.
    pub fn init(maxsz: usize) -> FormatP {
        FormatP {
            buf: vec![0u8; maxsz],
            length: 0,
        }
    }

    /// 重置回我们的原始参数以便可以重用。
    /// Reset back to our original parameters to make re-use possible.
    pub fn reset(&mut self) {
        self.length = 0;
    }

    /// 向我们的数据中添加一个整数（网络字节序）。
    /// Add an integer (network order) to our data.
    pub fn bformat_int(&mut self, value: i32) {
        let be = value.to_be_bytes();
        self.bformat_copy(&be);
    }

    /// 将某个值复制到我们的缓冲区中。
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

    /// 将格式化文本写入我们的缓冲区并追加（bformat_printf）。
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

    /// 释放此缓冲区（丢弃它；结构体会自动完成）。
    /// Free this buffer (drop it; the struct does that).
    pub fn free(&mut self) {
        self.length = 0;
        self.buf.clear();
    }

    /// 返回此缓冲区管理的字符串指针。
    /// Return a pointer to the string managed by this buffer.
    pub fn bformat_string(&self) -> &[u8] {
        &self.buf[..self.length]
    }

    /// 返回此缓冲区中字符串的长度。
    /// Return the length of the string in this buffer.
    pub fn bformat_length(&self) -> usize {
        self.length
    }

    /// 返回字符串及其大小。
    /// Return the string and its size.
    pub fn bformat_tostring(&mut self) -> (&[u8], usize) {
        let len = self.length;
        (&self.buf[..len], len)
    }
}

/// 初始化一个格式化文本缓冲区。
/// Initialize a formatted text buffer.
pub fn bformat_init(maxsz: usize) -> FormatP {
    FormatP::init(maxsz)
}
