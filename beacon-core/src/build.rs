//! API to build a buffer into a ready-to-encrypt frame (build.cpp).
//!
//! Frame layout:
//!   [0..4)  nonce (network order)
//!   [4..8)  length of the payload (network order, excludes the 8-byte header)
//!   [8..)   payload

use crate::state::NONCE;
use std::sync::atomic::Ordering;

/// Buffer builder (builder).
pub struct Builder {
    /// Our destination buffer.
    dest: Vec<u8>,
    /// Maximum size.
    max: usize,
    /// Current length (including the 8-byte header).
    len: usize,
}

impl Builder {
    /// Initialize a builder with a maximum size. Allocates `max` bytes.
    pub fn init(max: usize) -> Builder {
        let mut b = Builder {
            dest: vec![0u8; max],
            max,
            len: 0,
        };

        // setup our data header: nonce + length(0)
        let nonce = NONCE.load(Ordering::SeqCst);
        let temp = nonce.to_be_bytes();
        b.dest[..4].copy_from_slice(&temp);
        b.dest[4..8].copy_from_slice(&0u32.to_be_bytes());
        b.len = 8;

        // increment counter
        NONCE.store(nonce.wrapping_add(1), Ordering::SeqCst);
        b
    }

    /// Add an integer (network order).
    pub fn add_int(&mut self, number: u32) {
        self.add_data(&number.to_be_bytes());
    }

    /// Add a short (network order).
    pub fn add_short(&mut self, number: u16) {
        self.add_data(&number.to_be_bytes());
    }

    /// Add a byte.
    pub fn add_byte(&mut self, number: u8) {
        self.add_data(&[number]);
    }

    /// Add raw data.
    pub fn add_data(&mut self, data: &[u8]) {
        // if we're going to go over, bail!
        if (self.len + data.len()) > self.max {
            return;
        }

        // copy our data over
        self.dest[self.len..self.len + data.len()].copy_from_slice(data);

        // increment our total length
        self.len += data.len();

        // update the length part of our buffer; subtract 8 bytes for the header
        let changeme = (self.len - 8) as u32;
        self.dest[4..8].copy_from_slice(&changeme.to_be_bytes());
    }

    /// Total length of our buffer.
    pub fn length(&self) -> usize {
        self.len + 4
    }

    /// Slightly different finishing function for RSA encrypted packages.
    pub fn length_rsa(&mut self) -> usize {
        // put our magic number first
        self.dest[..4].copy_from_slice(&0x0000BEEFu32.to_be_bytes());

        // return the len without the magic number added to the end
        self.len
    }

    /// Consume the builder, returning the raw bytes (zero-padded to `max`).
    pub fn into_bytes(self) -> Vec<u8> {
        self.dest
    }

    /// Access the destination buffer.
    pub fn dest(&self) -> &[u8] {
        &self.dest
    }

    /// Current payload length (bytes written after the header).
    pub fn payload_len(&self) -> usize {
        self.len.saturating_sub(8)
    }
}
