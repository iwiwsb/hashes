//#![no_std]
#![warn(rust_2018_idioms)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::max;
use core::fmt::Debug;
use digest::{InvalidBufferSize, InvalidOutputSize, Update, VariableOutput};
use std::ops::BitXor;

/// MD6 hasher
#[derive(Debug)]
pub struct MD6 {
    output_size: usize,
    rounds: u16,
    levels: u8,
    key: [u8; 64],
    keylen: u8,
}

impl MD6 {
    const DEFAULT_LEVEL_NUMBER: u8 = 64;
    const MAX_ROUND_NUMBER: u16 = 4096;

    const VECTOR_Q: [u64; 15] = [
        0x7311_C281_2425_CFA0,
        0x6432_2864_34AA_C8E7,
        0xB604_50E9_EF68_B7C1,
        0xE8FB_2390_8D9F_06F1,
        0xDD2E_76CB_A691_E5BF,
        0x0CD0_D63B_2C30_BC41,
        0x1F8C_CF68_2305_8F8A,
        0x54E5_ED5B_88E3_775D,
        0x4AD1_2AAE_0A6D_6031,
        0x3E7F_16BB_8822_2E0D,
        0x8AF8_671D_3FB5_0C2C,
        0x995A_D117_8BD2_5C31,
        0xC878_C1DD_04C4_B633,
        0x3B72_066C_7A15_52AC,
        0x0D6F_3522_631E_FFCB,
    ];

    pub fn with_levels(self, levels: u8) -> Self {
        Self { levels, ..self }
    }

    pub fn with_rounds(self, rounds: u16) -> Option<Self> {
        if !(1..=Self::MAX_ROUND_NUMBER).contains(&rounds) {
            return None;
        }

        Some(Self { rounds, ..self })
    }

    pub fn with_key(self, key: [u8; 64]) -> Self {
        Self { key, ..self }
    }

    fn control_word(
        &self,
        is_final_compression: bool,
        num_of_padding_data_bits: u16,
    ) -> ControlWord {
        ControlWord {
            rounds: self.rounds,
            mode: self.levels,
            is_final_compression,
            num_of_padding_data_bits,
            keylen: self.keylen,
            desired_digest_length: self.output_size as u16,
        }
    }

    pub fn compression(
        &self,
        node_id: u64,
        control_word: ControlWord,
        data: [u64; 64],
    ) -> [u64; 16] {
        let mut input = [0u64; 89];
        input[0..=14].copy_from_slice(&Self::VECTOR_Q);
        input[15..=22].copy_from_slice(
            self.key
                .chunks(8)
                .map(|bytes: &[u8]| -> u64 {
                    u64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ])
                })
                .collect::<Vec<u64>>()
                .as_slice(),
        );
        input[23] = node_id;
        input[24] = control_word.into();
        input[25..].copy_from_slice(&data);
        Self::compression_internal(input)
    }

    fn compression_internal(input: [u64; 89]) -> [u64; 16] {
        const T0: usize = 17;
        const T1: usize = 18;
        const T2: usize = 21;
        const T3: usize = 31;
        const T4: usize = 67;

        const R_I_N: [u64; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
        const L_I_N: [u64; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];

        const INPUT_LEN: usize = 89;
        const STEPS_PER_ROUND: usize = 16;

        const S_: u64 = 0x7311_C281_2425_CFA0;
        let mut output_vec = Vec::new();
        output_vec.resize(89, 0);
        output_vec.copy_from_slice(&input);
        let mut round_const = 0x0123_4567_89AB_CDEF;

        let rounds = ControlWord::from(input[24]).rounds as usize;

        for round in 0..rounds {
            for step in round * STEPS_PER_ROUND..STEPS_PER_ROUND * (round + 1) {
                let mut x = round_const;
                x ^= output_vec[step] ^ output_vec[INPUT_LEN + step - T0];
                x ^= (output_vec[INPUT_LEN + step - T1] & output_vec[INPUT_LEN + step - T2])
                    ^ (output_vec[INPUT_LEN + step - T3] & output_vec[INPUT_LEN + step - T4]);
                x ^= x >> R_I_N[step % 16];
                x ^= x << L_I_N[step % 16];
                output_vec.push(x);
            }
            round_const = round_const.rotate_left(1).bitxor(round_const & S_);
        }

        [
            output_vec[output_vec.len() - 16],
            output_vec[output_vec.len() - 15],
            output_vec[output_vec.len() - 14],
            output_vec[output_vec.len() - 13],
            output_vec[output_vec.len() - 12],
            output_vec[output_vec.len() - 11],
            output_vec[output_vec.len() - 10],
            output_vec[output_vec.len() - 9],
            output_vec[output_vec.len() - 8],
            output_vec[output_vec.len() - 7],
            output_vec[output_vec.len() - 6],
            output_vec[output_vec.len() - 5],
            output_vec[output_vec.len() - 4],
            output_vec[output_vec.len() - 3],
            output_vec[output_vec.len() - 2],
            output_vec[output_vec.len() - 1],
        ]
    }

    fn calc_default_rounds(output_size: u16, keyed: bool) -> u16 {
        let default_r: u16 = 40 + output_size / 4;
        if keyed {
            max(80, default_r)
        } else {
            default_r
        }
    }
}

impl VariableOutput for MD6 {
    const MAX_OUTPUT_SIZE: usize = 64;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        if !(1..=Self::MAX_OUTPUT_SIZE).contains(&output_size) {
            return Err(InvalidOutputSize);
        }

        let rounds: u16 = Self::calc_default_rounds(output_size as u16, false);
        let key = [0u8; 64];
        let levels: u8 = Self::DEFAULT_LEVEL_NUMBER;
        let keylen: u8 = 0;
        Ok(Self {
            output_size,
            rounds,
            levels,
            key,
            keylen,
        })
    }

    fn output_size(&self) -> usize {
        self.output_size
    }

    fn finalize_variable(self, _out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        todo!();
    }
}

impl Update for MD6 {
    fn update(&mut self, _data: &[u8]) {
        todo!()
    }
}

#[derive(Debug, PartialEq)]
pub struct ControlWord {
    pub rounds: u16,
    pub mode: u8,
    pub is_final_compression: bool,
    pub num_of_padding_data_bits: u16,
    pub keylen: u8,
    pub desired_digest_length: u16,
}

impl From<ControlWord> for u64 {
    fn from(value: ControlWord) -> Self {
        (value.rounds as u64) << 48
            | (value.mode as u64) << 40
            | (value.is_final_compression as u64) << 36
            | (value.num_of_padding_data_bits as u64) << 20
            | (value.keylen as u64) << 12
            | (value.desired_digest_length as u64)
    }
}

impl From<u64> for ControlWord {
    fn from(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        let _reserved = bytes[0] >> 4;
        let rounds = u16::from_be_bytes([bytes[0] & 0b0000_1111, bytes[1]]);
        let mode = bytes[2];
        let is_final_compression = bytes[3] & 0b1111_0000 != 0;
        let num_of_padding_data_bits = u16::from_be_bytes([
            (bytes[3] << 4) | (bytes[4] >> 4),
            (bytes[4] << 4) | (bytes[5] >> 4),
        ]);
        let keylen = (bytes[5] << 4) | (bytes[6] >> 4);
        let desired_digest_length = u16::from_be_bytes([bytes[6] & 0b0000_1111, bytes[7]]);

        Self {
            rounds,
            mode,
            is_final_compression,
            num_of_padding_data_bits,
            keylen,
            desired_digest_length,
        }
    }
}

struct Input {
    key: [u64; 8],
    node_id: u64,
    control_word: ControlWord,
    data: [u64; 64],
}

impl Input {
    fn compress(&self) {
        todo!()
    }
}

impl From<Input> for [u64; 89] {
    fn from(value: Input) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_word_from_u64_1() {
        let left = ControlWord {
            rounds: 5,
            mode: 64,
            is_final_compression: true,
            num_of_padding_data_bits: 4072,
            keylen: 0,
            desired_digest_length: 256,
        };

        let right = ControlWord::from(0x0005_4010_FE80_0100);

        assert_eq!(left, right);
    }

    #[test]
    fn test_control_word_from_u64_2() {
        let left = ControlWord {
            rounds: 5,
            mode: 64,
            is_final_compression: false,
            num_of_padding_data_bits: 0,
            keylen: 10,
            desired_digest_length: 224,
        };

        let right = ControlWord::from(0x0005_4000_0000_A0E0);

        assert_eq!(left, right);
    }

    #[test]
    fn test_control_word_from_u64_3() {
        let left = ControlWord {
            rounds: 104,
            mode: 0,
            is_final_compression: false,
            num_of_padding_data_bits: 0,
            keylen: 0,
            desired_digest_length: 256,
        };

        let right = ControlWord::from(0x0068_0000_0000_0100);

        assert_eq!(left, right);
    }

    #[test]
    fn test_control_word_as_u64_1() {
        let left = u64::from(ControlWord {
            rounds: 5,
            mode: 64,
            is_final_compression: true,
            num_of_padding_data_bits: 4072,
            keylen: 0,
            desired_digest_length: 256,
        });

        let right = 0x0005_4010_FE80_0100;

        assert_eq!(left, right);
    }

    #[test]
    fn test_control_word_as_u64_2() {
        let left = u64::from(ControlWord {
            rounds: 5,
            mode: 64,
            is_final_compression: false,
            num_of_padding_data_bits: 0,
            keylen: 10,
            desired_digest_length: 224,
        });

        let right = 0x0005_4000_0000_A0E0;

        assert_eq!(left, right)
    }

    #[test]
    fn test_control_word_as_u64_3() {
        let left = u64::from(ControlWord {
            rounds: 104,
            mode: 0,
            is_final_compression: false,
            num_of_padding_data_bits: 0,
            keylen: 0,
            desired_digest_length: 256,
        });

        let right = 0x0068_0000_0000_0100;

        assert_eq!(left, right);
    }

    #[test]
    fn test_compression_function_1() {
        let expected_result: [u64; 16] = [
            0x2D1A_BE06_01B2_E6B0,
            0x61D5_9FD2_B731_0353,
            0xEA7D_A28D_EC70_8EC7,
            0xA63A_99A5_74E4_0155,
            0x290B_4FAB_E801_04C4,
            0x8C6A_3503_CF88_1A99,
            0xE370_E23D_1B70_0CC5,
            0x4492_E78E_3FE4_2F13,
            0xDF6C_91B7_EAF3_F088,
            0xAAB3_E19A_8F63_B80A,
            0xD987_BDCB_DA2E_934F,
            0xAEAE_805D_E12B_0D24,
            0x8854_C14D_C284_F840,
            0xED71_AD7B_A542_855C,
            0xE189_633E_48C7_97A5,
            0x5121_A746_BE48_CEC8,
        ];

        let result = MD6::compression_internal([
            0x7311_C281_2425_CFA0, // Q[ 0]
            0x6432_2864_34AA_C8E7, // Q[ 1]
            0xB604_50E9_EF68_B7C1, // Q[ 2]
            0xE8FB_2390_8D9F_06F1, // Q[ 3]
            0xDD2E_76CB_A691_E5BF, // Q[ 4]
            0x0CD0_D63B_2C30_BC41, // Q[ 5]
            0x1F8C_CF68_2305_8F8A, // Q[ 6]
            0x54E5_ED5B_88E3_775D, // Q[ 7]
            0x4AD1_2AAE_0A6D_6031, // Q[ 8]
            0x3E7F_16BB_8822_2E0D, // Q[ 9]
            0x8AF8_671D_3FB5_0C2C, // Q[10]
            0x995A_D117_8BD2_5C31, // Q[11]
            0xC878_C1DD_04C4_B633, // Q[12]
            0x3B72_066C_7A15_52AC, // Q[13]
            0x0D6F_3522_631E_FFCB, // Q[14]
            0x0000_0000_0000_0000, // key K[0]
            0x0000_0000_0000_0000, // key K[1]
            0x0000_0000_0000_0000, // key K[2]
            0x0000_0000_0000_0000, // key K[3]
            0x0000_0000_0000_0000, // key K[4]
            0x0000_0000_0000_0000, // key K[5]
            0x0000_0000_0000_0000, // key K[6]
            0x0000_0000_0000_0000, // key K[7]
            0x0100_0000_0000_0000, // nodeID U = (ell,i) = (1,0)
            0x0005_4010_FE80_0100, // control word V = (r,L,z,p,keylen,d) = (5,64,1,4072,10,256)
            0x6162_6300_0000_0000, // data B[ 0] input message word
            0x0000_0000_0000_0000, // data B[ 1] padding
            0x0000_0000_0000_0000, // data B[ 2] padding
            0x0000_0000_0000_0000, // data B[ 3] padding
            0x0000_0000_0000_0000, // data B[ 4] padding
            0x0000_0000_0000_0000, // data B[ 5] padding
            0x0000_0000_0000_0000, // data B[ 6] padding
            0x0000_0000_0000_0000, // data B[ 7] padding
            0x0000_0000_0000_0000, // data B[ 8] padding
            0x0000_0000_0000_0000, // data B[ 9] padding
            0x0000_0000_0000_0000, // data B[10] padding
            0x0000_0000_0000_0000, // data B[11] padding
            0x0000_0000_0000_0000, // data B[12] padding
            0x0000_0000_0000_0000, // data B[13] padding
            0x0000_0000_0000_0000, // data B[14] padding
            0x0000_0000_0000_0000, // data B[15] padding
            0x0000_0000_0000_0000, // data B[16] padding
            0x0000_0000_0000_0000, // data B[17] padding
            0x0000_0000_0000_0000, // data B[18] padding
            0x0000_0000_0000_0000, // data B[19] padding
            0x0000_0000_0000_0000, // data B[20] padding
            0x0000_0000_0000_0000, // data B[21] padding
            0x0000_0000_0000_0000, // data B[22] padding
            0x0000_0000_0000_0000, // data B[23] padding
            0x0000_0000_0000_0000, // data B[24] padding
            0x0000_0000_0000_0000, // data B[25] padding
            0x0000_0000_0000_0000, // data B[26] padding
            0x0000_0000_0000_0000, // data B[27] padding
            0x0000_0000_0000_0000, // data B[28] padding
            0x0000_0000_0000_0000, // data B[29] padding
            0x0000_0000_0000_0000, // data B[30] padding
            0x0000_0000_0000_0000, // data B[31] padding
            0x0000_0000_0000_0000, // data B[32] padding
            0x0000_0000_0000_0000, // data B[33] padding
            0x0000_0000_0000_0000, // data B[34] padding
            0x0000_0000_0000_0000, // data B[35] padding
            0x0000_0000_0000_0000, // data B[36] padding
            0x0000_0000_0000_0000, // data B[37] padding
            0x0000_0000_0000_0000, // data B[38] padding
            0x0000_0000_0000_0000, // data B[39] padding
            0x0000_0000_0000_0000, // data B[40] padding
            0x0000_0000_0000_0000, // data B[41] padding
            0x0000_0000_0000_0000, // data B[42] padding
            0x0000_0000_0000_0000, // data B[43] padding
            0x0000_0000_0000_0000, // data B[44] padding
            0x0000_0000_0000_0000, // data B[45] padding
            0x0000_0000_0000_0000, // data B[46] padding
            0x0000_0000_0000_0000, // data B[47] padding
            0x0000_0000_0000_0000, // data B[48] padding
            0x0000_0000_0000_0000, // data B[49] padding
            0x0000_0000_0000_0000, // data B[50] padding
            0x0000_0000_0000_0000, // data B[51] padding
            0x0000_0000_0000_0000, // data B[52] padding
            0x0000_0000_0000_0000, // data B[53] padding
            0x0000_0000_0000_0000, // data B[54] padding
            0x0000_0000_0000_0000, // data B[55] padding
            0x0000_0000_0000_0000, // data B[56] padding
            0x0000_0000_0000_0000, // data B[57] padding
            0x0000_0000_0000_0000, // data B[58] padding
            0x0000_0000_0000_0000, // data B[59] padding
            0x0000_0000_0000_0000, // data B[60] padding
            0x0000_0000_0000_0000, // data B[61] padding
            0x0000_0000_0000_0000, // data B[62] padding
            0x0000_0000_0000_0000, // data B[63] padding
        ]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_compression_function_2() {
        let expected_result: [u64; 16] = [
            0xE86A_6F80_5FB8_10CA,
            0x991D_E071_2998_31A9,
            0xC595_17FB_7F5C_5E74,
            0x0E2B_5F69_481C_68E6,
            0x8DDB_33A8_B069_B4C2,
            0x558B_3513_A004_6DBD,
            0xE1DF_B672_6949_AB7E,
            0xF48B_AE51_5E89_EE94,
            0xD31D_1F87_D97D_A302,
            0x5D34_9E9B_0D69_B270,
            0xB409_D2EE_2C3E_5577,
            0x9976_21D4_03CD_954E,
            0x7A35_3E0E_F294_90A3,
            0x716D_1239_DFFF_51DC,
            0x5974_4BE8_98CF_7C0A,
            0x0795_1A90_E19D_A429,
        ];

        let result = MD6::compression_internal([
            0x7311_C281_2425_CFA0, // Q[ 0]
            0x6432_2864_34AA_C8E7, // Q[ 1]
            0xB604_50E9_EF68_B7C1, // Q[ 2]
            0xE8FB_2390_8D9F_06F1, // Q[ 3]
            0xDD2E_76CB_A691_E5BF, // Q[ 4]
            0x0CD0_D63B_2C30_BC41, // Q[ 5]
            0x1F8C_CF68_2305_8F8A, // Q[ 6]
            0x54E5_ED5B_88E3_775D, // Q[ 7]
            0x4AD1_2AAE_0A6D_6031, // Q[ 8]
            0x3E7F_16BB_8822_2E0D, // Q[ 9]
            0x8AF8_671D_3FB5_0C2C, // Q[10]
            0x995A_D117_8BD2_5C31, // Q[11]
            0xC878_C1DD_04C4_B633, // Q[12]
            0x3B72_066C_7A15_52AC, // Q[13]
            0x0D6F_3522_631E_FFCB, // Q[14]
            0x6162_6364_6531_3233, // key K[0]
            0x3435_0000_0000_0000, // key K[1]
            0x0000_0000_0000_0000, // key K[2]
            0x0000_0000_0000_0000, // key K[3]
            0x0000_0000_0000_0000, // key K[4]
            0x0000_0000_0000_0000, // key K[5]
            0x0000_0000_0000_0000, // key K[6]
            0x0000_0000_0000_0000, // key K[7]
            0x0100_0000_0000_0000, // nodeID U = (ell,i) = (1,0)
            0x0005_4000_0000_A0E0, // control word V = (r,L,z,p,keylen,d) = (5,64,0,0,10,224)
            0x1122_3344_5566_7711, // data B[ 0] input message word 0
            0x2233_4455_6677_1122, // data B[ 1] input message word 1
            0x3344_5566_7711_2233, // data B[ 2] input message word 2
            0x4455_6677_1122_3344, // data B[ 3] input message word 3
            0x5566_7711_2233_4455, // data B[ 4] input message word 4
            0x6677_1122_3344_5566, // data B[ 5] input message word 5
            0x7711_2233_4455_6677, // data B[ 6] input message word 6
            0x1122_3344_5566_7711, // data B[ 7] input message word 7
            0x2233_4455_6677_1122, // data B[ 8] input message word 8
            0x3344_5566_7711_2233, // data B[ 9] input message word 9
            0x4455_6677_1122_3344, // data B[10] input message word 10
            0x5566_7711_2233_4455, // data B[11] input message word 11
            0x6677_1122_3344_5566, // data B[12] input message word 12
            0x7711_2233_4455_6677, // data B[13] input message word 13
            0x1122_3344_5566_7711, // data B[14] input message word 14
            0x2233_4455_6677_1122, // data B[15] input message word 15
            0x3344_5566_7711_2233, // data B[16] input message word 16
            0x4455_6677_1122_3344, // data B[17] input message word 17
            0x5566_7711_2233_4455, // data B[18] input message word 18
            0x6677_1122_3344_5566, // data B[19] input message word 19
            0x7711_2233_4455_6677, // data B[20] input message word 20
            0x1122_3344_5566_7711, // data B[21] input message word 21
            0x2233_4455_6677_1122, // data B[22] input message word 22
            0x3344_5566_7711_2233, // data B[23] input message word 23
            0x4455_6677_1122_3344, // data B[24] input message word 24
            0x5566_7711_2233_4455, // data B[25] input message word 25
            0x6677_1122_3344_5566, // data B[26] input message word 26
            0x7711_2233_4455_6677, // data B[27] input message word 27
            0x1122_3344_5566_7711, // data B[28] input message word 28
            0x2233_4455_6677_1122, // data B[29] input message word 29
            0x3344_5566_7711_2233, // data B[30] input message word 30
            0x4455_6677_1122_3344, // data B[31] input message word 31
            0x5566_7711_2233_4455, // data B[32] input message word 32
            0x6677_1122_3344_5566, // data B[33] input message word 33
            0x7711_2233_4455_6677, // data B[34] input message word 34
            0x1122_3344_5566_7711, // data B[35] input message word 35
            0x2233_4455_6677_1122, // data B[36] input message word 36
            0x3344_5566_7711_2233, // data B[37] input message word 37
            0x4455_6677_1122_3344, // data B[38] input message word 38
            0x5566_7711_2233_4455, // data B[39] input message word 39
            0x6677_1122_3344_5566, // data B[40] input message word 40
            0x7711_2233_4455_6677, // data B[41] input message word 41
            0x1122_3344_5566_7711, // data B[42] input message word 42
            0x2233_4455_6677_1122, // data B[43] input message word 43
            0x3344_5566_7711_2233, // data B[44] input message word 44
            0x4455_6677_1122_3344, // data B[45] input message word 45
            0x5566_7711_2233_4455, // data B[46] input message word 46
            0x6677_1122_3344_5566, // data B[47] input message word 47
            0x7711_2233_4455_6677, // data B[48] input message word 48
            0x1122_3344_5566_7711, // data B[49] input message word 49
            0x2233_4455_6677_1122, // data B[50] input message word 50
            0x3344_5566_7711_2233, // data B[51] input message word 51
            0x4455_6677_1122_3344, // data B[52] input message word 52
            0x5566_7711_2233_4455, // data B[53] input message word 53
            0x6677_1122_3344_5566, // data B[54] input message word 54
            0x7711_2233_4455_6677, // data B[55] input message word 55
            0x1122_3344_5566_7711, // data B[56] input message word 56
            0x2233_4455_6677_1122, // data B[57] input message word 57
            0x3344_5566_7711_2233, // data B[58] input message word 58
            0x4455_6677_1122_3344, // data B[59] input message word 59
            0x5566_7711_2233_4455, // data B[60] input message word 60
            0x6677_1122_3344_5566, // data B[61] input message word 61
            0x7711_2233_4455_6677, // data B[62] input message word 62
            0x1122_3344_5566_7711, // data B[63] input message word 63
        ]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_compression_function_3() {
        let expected_result: [u64; 16] = [
            0x34E0_6CF8_E7E3_80B8,
            0xF873_6F43_57F9_9CB8,
            0xA3E1_187D_A8FB_D4E8,
            0x6C11_DA3B_93AC_A37A,
            0x5FDB_88A9_8301_B016,
            0x5D2A_34CC_C621_594D,
            0xD105_21D7_588C_E414,
            0x5040_286F_E773_A8C0,
            0xFE03_0F55_9C8A_0F0B,
            0xCA28_9A3C_963D_D24B,
            0xACDC_CF24_C7A7_0E53,
            0x1F45_1B9A_0209_F583,
            0xDA56_F65E_3205_064D,
            0xA00E_879E_AE6D_8241,
            0x2A2A_15BC_29DC_56A4,
            0x5D8E_6779_0565_7F39,
        ];

        let result = MD6::compression_internal([
            0x7311_C281_2425_CFA0, // Q[0]
            0x6432_2864_34AA_C8E7, // Q[1]
            0xB604_50E9_EF68_B7C1, // Q[2]
            0xE8FB_2390_8D9F_06F1, // Q[3]
            0xDD2E_76CB_A691_E5BF, // Q[4]
            0x0CD0_D63B_2C30_BC41, // Q[5]
            0x1F8C_CF68_2305_8F8A, // Q[6]
            0x54E5_ED5B_88E3_775D, // Q[7]
            0x4AD1_2AAE_0A6D_6031, // Q[8]
            0x3E7F_16BB_8822_2E0D, // Q[9]
            0x8AF8_671D_3FB5_0C2C, // Q[10]
            0x995A_D117_8BD2_5C31, // Q[11]
            0xC878_C1DD_04C4_B633, // Q[12]
            0x3B72_066C_7A15_52AC, // Q[13]
            0x0D6F_3522_631E_FFCB, // Q[14]
            0x6162_6364_6531_3233, // key K[0]
            0x3435_0000_0000_0000, // key K[1]
            0x0000_0000_0000_0000, // key K[2]
            0x0000_0000_0000_0000, // key K[3]
            0x0000_0000_0000_0000, // key K[4]
            0x0000_0000_0000_0000, // key K[5]
            0x0000_0000_0000_0000, // key K[6]
            0x0000_0000_0000_0000, // key K[7]
            0x0100_0000_0000_0001, // nodeID U = (ell,i) = (1,1)
            0x0005_4000_D400_A0E0, // control word V = (r,L,z,p,keylen,d) = (5,64,0,3392,10,224)
            0x2233_4455_6677_1122, // data B[ 0] input message word
            0x3344_5566_7711_2233, // data B[ 1] input message word
            0x4455_6677_1122_3344, // data B[ 2] input message word
            0x5566_7711_2233_4455, // data B[ 3] input message word
            0x6677_1122_3344_5566, // data B[ 4] input message word
            0x7711_2233_4455_6677, // data B[ 5] input message word
            0x1122_3344_5566_7711, // data B[ 6] input message word
            0x2233_4455_6677_1122, // data B[ 7] input message word
            0x3344_5566_7711_2233, // data B[ 8] input message word
            0x4455_6677_1122_3344, // data B[ 9] input message word
            0x5566_7711_2233_4455, // data B[10] input message word
            0x0000_0000_0000_0000, // data B[11] padding
            0x0000_0000_0000_0000, // data B[12] padding
            0x0000_0000_0000_0000, // data B[13] padding
            0x0000_0000_0000_0000, // data B[14] padding
            0x0000_0000_0000_0000, // data B[15] padding
            0x0000_0000_0000_0000, // data B[16] padding
            0x0000_0000_0000_0000, // data B[17] padding
            0x0000_0000_0000_0000, // data B[18] padding
            0x0000_0000_0000_0000, // data B[19] padding
            0x0000_0000_0000_0000, // data B[20] padding
            0x0000_0000_0000_0000, // data B[21] padding
            0x0000_0000_0000_0000, // data B[22] padding
            0x0000_0000_0000_0000, // data B[23] padding
            0x0000_0000_0000_0000, // data B[24] padding
            0x0000_0000_0000_0000, // data B[25] padding
            0x0000_0000_0000_0000, // data B[26] padding
            0x0000_0000_0000_0000, // data B[27] padding
            0x0000_0000_0000_0000, // data B[28] padding
            0x0000_0000_0000_0000, // data B[29] padding
            0x0000_0000_0000_0000, // data B[30] padding
            0x0000_0000_0000_0000, // data B[31] padding
            0x0000_0000_0000_0000, // data B[32] padding
            0x0000_0000_0000_0000, // data B[33] padding
            0x0000_0000_0000_0000, // data B[34] padding
            0x0000_0000_0000_0000, // data B[35] padding
            0x0000_0000_0000_0000, // data B[36] padding
            0x0000_0000_0000_0000, // data B[37] padding
            0x0000_0000_0000_0000, // data B[38] padding
            0x0000_0000_0000_0000, // data B[39] padding
            0x0000_0000_0000_0000, // data B[40] padding
            0x0000_0000_0000_0000, // data B[41] padding
            0x0000_0000_0000_0000, // data B[42] padding
            0x0000_0000_0000_0000, // data B[43] padding
            0x0000_0000_0000_0000, // data B[44] padding
            0x0000_0000_0000_0000, // data B[45] padding
            0x0000_0000_0000_0000, // data B[46] padding
            0x0000_0000_0000_0000, // data B[47] padding
            0x0000_0000_0000_0000, // data B[48] padding
            0x0000_0000_0000_0000, // data B[49] padding
            0x0000_0000_0000_0000, // data B[50] padding
            0x0000_0000_0000_0000, // data B[51] padding
            0x0000_0000_0000_0000, // data B[52] padding
            0x0000_0000_0000_0000, // data B[53] padding
            0x0000_0000_0000_0000, // data B[54] padding
            0x0000_0000_0000_0000, // data B[55] padding
            0x0000_0000_0000_0000, // data B[56] padding
            0x0000_0000_0000_0000, // data B[57] padding
            0x0000_0000_0000_0000, // data B[58] padding
            0x0000_0000_0000_0000, // data B[59] padding
            0x0000_0000_0000_0000, // data B[60] padding
            0x0000_0000_0000_0000, // data B[61] padding
            0x0000_0000_0000_0000, // data B[62] padding
            0x0000_0000_0000_0000, // data B[63] padding
        ]);

        assert_eq!(result, expected_result);
    }
}
