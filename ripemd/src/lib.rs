//! An implementation of the [RIPEMD] cryptographic hash.
//!
//! This crate implements only the modified 1996 versions, not the original
//! one from 1992.
//!
//! Note that RIPEMD-256 provides only the same security as RIPEMD-128,
//! and RIPEMD-320 provides only the same security as RIPEMD-160.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use ripemd::{Ripemd160, Ripemd320, Digest};
//!
//! // create a RIPEMD-160 hasher instance
//! let mut hasher = Ripemd160::new();
//!
//! // process input message
//! hasher.update(b"Hello world!");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 20]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("7f772647d88750add82d8e1a7a3e5c0902a346a3"));
//!
//! // same for RIPEMD-320
//! let mut hasher = Ripemd320::new();
//! hasher.update(b"Hello world!");
//! let result = hasher.finalize();
//! assert_eq!(&result[..], &hex!("
//!     f1c1c231d301abcf2d7daae0269ff3e7bc68e623
//!     ad723aa068d316b056d26b7d1bb6f0cc0f28336d
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes] readme.
//!
//! [RIPEMD]: https://en.wikipedia.org/wiki/RIPEMD
//! [RustCrypto/hashes]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    generic_array::typenum::{Unsigned, U20, U32, U40, U64},
    HashMarker, Output,
};

mod c160;
mod c256;
mod c320;

/// Core RIPEMD-160 hasher state.
#[derive(Clone)]
pub struct Ripemd160Core {
    h: [u32; c160::DIGEST_BUF_LEN],
    block_len: u64,
}

impl HashMarker for Ripemd160Core {}

impl BlockSizeUser for Ripemd160Core {
    type BlockSize = U64;
}

impl BufferKindUser for Ripemd160Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Ripemd160Core {
    type OutputSize = U20;
}

impl UpdateCore for Ripemd160Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // Assumes that `block_len` does not overflow
        self.block_len += blocks.len() as u64;
        for block in blocks {
            c160::compress(&mut self.h, block);
        }
    }
}

impl FixedOutputCore for Ripemd160Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        let mut h = self.h;
        buffer.len64_padding_le(bit_len, |block| c160::compress(&mut h, block));

        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Ripemd160Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: c160::H0,
            block_len: 0,
        }
    }
}

impl Reset for Ripemd160Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Ripemd160Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd160")
    }
}

impl fmt::Debug for Ripemd160Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd160Core { ... }")
    }
}

/// RIPEMD-160 hasher state.
pub type Ripemd160 = CoreWrapper<Ripemd160Core>;

/// Core RIPEMD-256 hasher state.
#[derive(Clone)]
pub struct Ripemd256Core {
    h: [u32; c256::DIGEST_BUF_LEN],
    block_len: u64,
}

impl HashMarker for Ripemd256Core {}

impl BlockSizeUser for Ripemd256Core {
    type BlockSize = U64;
}

impl BufferKindUser for Ripemd256Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Ripemd256Core {
    type OutputSize = U32;
}

impl UpdateCore for Ripemd256Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // Assumes that `block_len` does not overflow
        self.block_len += blocks.len() as u64;
        for block in blocks {
            c256::compress(&mut self.h, block);
        }
    }
}

impl FixedOutputCore for Ripemd256Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        let mut h = self.h;
        buffer.len64_padding_le(bit_len, |block| c256::compress(&mut h, block));

        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Ripemd256Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: c256::H0,
            block_len: 0,
        }
    }
}

impl Reset for Ripemd256Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Ripemd256Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd256")
    }
}

impl fmt::Debug for Ripemd256Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd256Core { ... }")
    }
}

/// RIPEMD-160 hasher state.
pub type Ripemd256 = CoreWrapper<Ripemd256Core>;

/// Core RIPEMD-320 hasher state.
#[derive(Clone)]
pub struct Ripemd320Core {
    h: [u32; c320::DIGEST_BUF_LEN],
    block_len: u64,
}

impl HashMarker for Ripemd320Core {}

impl BlockSizeUser for Ripemd320Core {
    type BlockSize = U64;
}

impl BufferKindUser for Ripemd320Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Ripemd320Core {
    type OutputSize = U40;
}

impl UpdateCore for Ripemd320Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // Assumes that `block_len` does not overflow
        self.block_len += blocks.len() as u64;
        for block in blocks {
            c320::compress(&mut self.h, block);
        }
    }
}

impl FixedOutputCore for Ripemd320Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        let mut h = self.h;
        buffer.len64_padding_le(bit_len, |block| c320::compress(&mut h, block));

        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Ripemd320Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: c320::H0,
            block_len: 0,
        }
    }
}

impl Reset for Ripemd320Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Ripemd320Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd320")
    }
}

impl fmt::Debug for Ripemd320Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd320Core { ... }")
    }
}

/// RIPEMD-320 hasher state.
pub type Ripemd320 = CoreWrapper<Ripemd320Core>;
