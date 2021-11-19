use core::fmt;
use digest::{
    block_buffer::Eager,
    consts::U64,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    HashMarker, Output,
};

use crate::streebog::StreebogState;

/// Core Streebog512 hasher state.
#[derive(Clone)]
pub struct Streebog512Core {
    state: StreebogState,
}

impl HashMarker for Streebog512Core {}

impl BlockSizeUser for Streebog512Core {
    type BlockSize = U64;
}

impl BufferKindUser for Streebog512Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Streebog512Core {
    type OutputSize = U64;
}

impl UpdateCore for Streebog512Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.state.update_blocks(blocks);
    }
}

impl FixedOutputCore for Streebog512Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        self.state.finalize(buffer);
        out.copy_from_slice(&self.state.h)
    }
}

impl Default for Streebog512Core {
    #[inline]
    fn default() -> Self {
        let state = StreebogState {
            h: [0u8; 64],
            n: Default::default(),
            sigma: Default::default(),
        };
        Self { state }
    }
}

impl Reset for Streebog512Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Streebog512Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog512")
    }
}

impl fmt::Debug for Streebog512Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog512Core { ... }")
    }
}

/// Streebog512 hasher state.
pub type Streebog512 = CoreWrapper<Streebog512Core>;
