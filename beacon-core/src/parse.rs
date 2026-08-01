//! A cleaner way to parse data from Cobalt Strike (parse.cpp).
//!
//! The C code works on `char*`/length pairs with interior pointers. We use
//! an owning `Vec<u8>` cursor instead — same extraction semantics, no raw
//! pointers. `data_alloc` returns a zeroed owned buffer.

/// Data parser (datap).
#[derive(Clone)]
pub struct DataP {
    /// The original buffer [so we can zero it].
    original: Vec<u8>,
    /// Current position into the buffer.
    pos: usize,
}

/// A borrowed buffer extracted from a `DataP`.
#[derive(Clone)]
pub struct DataPBuffer {
    pub buffer: Vec<u8>,
    pub length: usize,
}

impl DataP {
    /// Allocate an owned, zeroed parser buffer.
    pub fn alloc(size: usize) -> DataP {
        DataP {
            original: vec![0u8; size],
            pos: 0,
        }
    }

    /// Initialize a parser over an existing buffer (copies it; the parser
    /// owns the data for the duration of parsing).
    pub fn init(buffer: &[u8]) -> DataP {
        DataP {
            original: buffer.to_vec(),
            pos: 0,
        }
    }

    /// Zero the entire original buffer.
    pub fn cleanup(&mut self) {
        for b in self.original.iter_mut() {
            *b = 0;
        }
    }

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

    /// Extract a single byte.
    pub fn data_byte(&mut self) -> u32 {
        if self.remaining() == 0 {
            return 0;
        }
        let v = self.original[self.pos] as u32;
        self.pos += 1;
        v
    }

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

    /// Extract a slice of `length` bytes.
    pub fn data_ptr(&mut self, length: usize) -> Option<&[u8]> {
        if self.remaining() < length {
            return None;
        }
        let s = &self.original[self.pos..self.pos + length];
        self.pos += length;
        Some(s)
    }

    /// Extract a length-prefixed block: [4b length][data].
    pub fn data_extract(&mut self) -> Option<DataPBuffer> {
        let length = self.data_int() as usize;
        let buffer = self.data_ptr(length)?;
        Some(DataPBuffer {
            buffer: buffer.to_vec(),
            length,
        })
    }

    /// Extract a string, copying it into `buffer` and NUL-terminating.
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

    /// Extract a NUL-terminated length+string as a borrowed slice.
    /// `[4b length][data]`.
    pub fn data_string_asciiz(&mut self) -> Option<&[u8]> {
        let slen = self.data_int() as usize;
        if slen == 0 {
            return None;
        }
        self.data_ptr(slen)
    }

    /// Extract a pointer and length pair (data_ptr_extract).
    pub fn data_ptr_extract(&mut self) -> Option<DataPBuffer> {
        self.data_extract()
    }

    /// Length of remaining data.
    pub fn data_length(&self) -> usize {
        self.remaining()
    }

    /// Return a pointer to the current position.
    pub fn data_buffer(&self) -> &[u8] {
        &self.original[self.pos..]
    }

    /// Remaining bytes.
    fn remaining(&self) -> usize {
        self.original.len().saturating_sub(self.pos)
    }
}

/// Allocate memory and return a parser that points to it (data_alloc).
pub fn data_alloc(size: usize) -> DataP {
    DataP::alloc(size)
}
