//! 一种更干净的方式解析来自 Cobalt Strike 的数据（parse.cpp）。
//! A cleaner way to parse data from Cobalt Strike (parse.cpp).
//!
//! C 代码基于 `char*`/长度对与内部指针工作；我们改用自有的 `Vec<u8>` 游标——提取语义相同，但没有裸指针。`data_alloc` 返回一个清零的自有缓冲区。
//! The C code works on `char*`/length pairs with interior pointers. We use
//! an owning `Vec<u8>` cursor instead — same extraction semantics, no raw
//! pointers. `data_alloc` returns a zeroed owned buffer.

/// 数据解析器（datap）。
/// Data parser (datap).
#[derive(Clone)]
pub struct DataP {
    /// 原始缓冲区［以便我们将其清零］。
    /// The original buffer [so we can zero it].
    original: Vec<u8>,
    /// 当前在缓冲区中的位置。
    /// Current position into the buffer.
    pos: usize,
}

/// 从 `DataP` 中提取的借用缓冲区。
/// A borrowed buffer extracted from a `DataP`.
#[derive(Clone)]
pub struct DataPBuffer {
    pub buffer: Vec<u8>,
    pub length: usize,
}

impl DataP {
    /// 分配一个自有且清零的解析器缓冲区。
    /// Allocate an owned, zeroed parser buffer.
    pub fn alloc(size: usize) -> DataP {
        DataP {
            original: vec![0u8; size],
            pos: 0,
        }
    }

    /// 在既有缓冲区上初始化解析器（复制它；解析期间解析器持有数据）。
    /// Initialize a parser over an existing buffer (copies it; the parser
    /// owns the data for the duration of parsing).
    pub fn init(buffer: &[u8]) -> DataP {
        DataP {
            original: buffer.to_vec(),
            pos: 0,
        }
    }

    /// 将整个原始缓冲区清零。
    /// Zero the entire original buffer.
    pub fn cleanup(&mut self) {
        for b in self.original.iter_mut() {
            *b = 0;
        }
    }

    /// 提取一个整数（网络字节序）。
    /// Extract an integer (network order).
    pub fn data_int(&mut self) -> u32 {
        if self.remaining() < 4 {
            return 0;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.original[self.pos..self.pos + 4]);
        self.pos += 4;
        u32::from_be_bytes(b)
    }

    /// 提取单个字节。
    /// Extract a single byte.
    pub fn data_byte(&mut self) -> u32 {
        if self.remaining() == 0 {
            return 0;
        }
        let v = self.original[self.pos] as u32;
        self.pos += 1;
        v
    }

    /// 提取一个无符号短整数（网络字节序）。
    /// Extract an unsigned short (network order).
    pub fn data_short(&mut self) -> u16 {
        if self.remaining() < 2 {
            return 0;
        }
        let mut b = [0u8; 2];
        b.copy_from_slice(&self.original[self.pos..self.pos + 2]);
        self.pos += 2;
        u16::from_be_bytes(b)
    }

    /// 提取长度为 `length` 的字节切片。
    /// Extract a slice of `length` bytes.
    pub fn data_ptr(&mut self, length: usize) -> Option<&[u8]> {
        if self.remaining() < length {
            return None;
        }
        let s = &self.original[self.pos..self.pos + length];
        self.pos += length;
        Some(s)
    }

    /// 提取长度前缀块：［4 字节长度］［数据］。
    /// Extract a length-prefixed block: [4b length][data].
    pub fn data_extract(&mut self) -> Option<DataPBuffer> {
        let length = self.data_int() as usize;
        let buffer = self.data_ptr(length)?;
        Some(DataPBuffer {
            buffer: buffer.to_vec(),
            length,
        })
    }

    /// 提取字符串：将其复制到 `buffer` 并以 NUL 结尾。
    /// Extract a string, copying it into `buffer` and NUL-terminating.
    /// 返回字符串长度 + 1（含 NUL），失败时返回 0。
    /// Returns the length of the string + 1 (including NUL), or 0 on failure.
    pub fn data_string(&mut self, buffer: &mut [u8], max: usize) -> usize {
        let slen = self.data_int() as usize;
        if slen == 0 || (slen + 1) >= max {
            return 0;
        }
        match self.data_ptr(slen) {
            Some(ptr) => {
                buffer[..slen].copy_from_slice(ptr);
                buffer[slen] = 0;
                slen + 1
            }
            None => 0,
        }
    }

    /// 将 NUL 结尾的长度+字符串提取为借用切片。
    /// Extract a NUL-terminated length+string as a borrowed slice.
    /// `[4b length][data]`.
    pub fn data_string_asciiz(&mut self) -> Option<&[u8]> {
        let slen = self.data_int() as usize;
        if slen == 0 {
            return None;
        }
        self.data_ptr(slen)
    }

    /// 提取指针和长度对（data_ptr_extract）。
    /// Extract a pointer and length pair (data_ptr_extract).
    pub fn data_ptr_extract(&mut self) -> Option<DataPBuffer> {
        self.data_extract()
    }

    /// 剩余数据的长度。
    /// Length of remaining data.
    pub fn data_length(&self) -> usize {
        self.remaining()
    }

    /// 返回指向当前位置的指针。
    /// Return a pointer to the current position.
    pub fn data_buffer(&self) -> &[u8] {
        &self.original[self.pos..]
    }

    /// 剩余字节数。
    /// Remaining bytes.
    fn remaining(&self) -> usize {
        self.original.len().saturating_sub(self.pos)
    }
}

/// 分配内存并返回指向它的解析器（data_alloc）。
/// Allocate memory and return a parser that points to it (data_alloc).
pub fn data_alloc(size: usize) -> DataP {
    DataP::alloc(size)
}
