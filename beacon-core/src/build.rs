//! 将缓冲区构建为可加密帧的 API（build.cpp）。
//! API to build a buffer into a ready-to-encrypt frame (build.cpp).
//!
//! 帧布局：
//! Frame layout:
//!   [0..4)  nonce（网络字节序）
//!   [0..4)  nonce (network order)
//!   [4..8)  载荷长度（网络字节序，不含 8 字节头）
//!   [4..8)  length of the payload (network order, excludes the 8-byte header)
//!   [8..)   载荷
//!   [8..)   payload

use crate::state::NONCE;
use std::sync::atomic::Ordering;

/// 缓冲区构建器（builder）。
/// Buffer builder (builder).
pub struct Builder {
    /// 我们的目标缓冲区。
    /// Our destination buffer.
    dest: Vec<u8>,
    /// 最大大小。
    /// Maximum size.
    max: usize,
    /// 当前长度（含 8 字节头）。
    /// Current length (including the 8-byte header).
    len: usize,
}

impl Builder {
    /// 以最大大小初始化构建器。分配 `max` 字节。
    /// Initialize a builder with a maximum size. Allocates `max` bytes.
    pub fn init(max: usize) -> Builder {
        let mut b = Builder {
            dest: vec![0u8; max],
            max,
            len: 0,
        };

        // 设置我们的数据头：nonce + length(0)
        // setup our data header: nonce + length(0)
        let nonce = NONCE.load(Ordering::SeqCst);
        let temp = nonce.to_be_bytes();
        b.dest[..4].copy_from_slice(&temp);
        b.dest[4..8].copy_from_slice(&0u32.to_be_bytes());
        b.len = 8;

        // 递增计数器
        // increment counter
        NONCE.store(nonce.wrapping_add(1), Ordering::SeqCst);
        b
    }

    /// 添加一个整数（网络字节序）。
    /// Add an integer (network order).
    pub fn add_int(&mut self, number: u32) {
        self.add_data(&number.to_be_bytes());
    }

    /// 添加一个短整数（网络字节序）。
    /// Add a short (network order).
    pub fn add_short(&mut self, number: u16) {
        self.add_data(&number.to_be_bytes());
    }

    /// 添加一个字节。
    /// Add a byte.
    pub fn add_byte(&mut self, number: u8) {
        self.add_data(&[number]);
    }

    /// 添加原始数据。
    /// Add raw data.
    pub fn add_data(&mut self, data: &[u8]) {
        // 如果要超限，直接放弃！
        // if we're going to go over, bail!
        if (self.len + data.len()) > self.max {
            return;
        }

        // 复制我们的数据
        // copy our data over
        self.dest[self.len..self.len + data.len()].copy_from_slice(data);

        // 递增我们的总长度
        // increment our total length
        self.len += data.len();

        // 更新我们缓冲区的长度部分；为头减去 8 字节
        // update the length part of our buffer; subtract 8 bytes for the header
        let changeme = (self.len - 8) as u32;
        self.dest[4..8].copy_from_slice(&changeme.to_be_bytes());
    }

    /// 我们缓冲区的总长度。
    /// Total length of our buffer.
    pub fn length(&self) -> usize {
        self.len + 4
    }

    /// RSA 加密包的略有不同的收尾函数。
    /// Slightly different finishing function for RSA encrypted packages.
    pub fn length_rsa(&mut self) -> usize {
        // 先把我们的魔数放进去
        // put our magic number first
        self.dest[..4].copy_from_slice(&0x0000BEEFu32.to_be_bytes());

        // 返回末尾未加魔数的长度
        // return the len without the magic number added to the end
        self.len
    }

    /// 消费构建器，返回原始字节（零填充到 `max`）。
    /// Consume the builder, returning the raw bytes (zero-padded to `max`).
    pub fn into_bytes(self) -> Vec<u8> {
        self.dest
    }

    /// 访问目标缓冲区。
    /// Access the destination buffer.
    pub fn dest(&self) -> &[u8] {
        &self.dest
    }

    /// 当前载荷长度（头之后写入的字节数）。
    /// Current payload length (bytes written after the header).
    pub fn payload_len(&self) -> usize {
        self.len.saturating_sub(8)
    }
}
