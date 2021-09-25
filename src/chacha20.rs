use std::convert::TryInto;

type Quarter = (usize, usize, usize, usize);
const QUARTERS: [Quarter; 8] = [
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
];

const SIZE: usize = 16;
const K: &str = "expand 32-byte k";

#[derive(PartialEq, Clone, Debug)]
struct Chacha20 {
    words: [u32; SIZE],
}

impl Chacha20 {
    pub fn new(secret: [u8; 32], nonce: [u8; 12]) -> Chacha20 {
        let mut words = [0u32; SIZE];
        let mut index = 0;

        // Chacha constant
        let mut k = K.as_bytes();
        while k.len() > 0 {
            words[index] = Self::read_le_u32(&mut k);
            index += 1;
        }

        // secret key
        let mut secret: &[u8] = &secret[..];
        while secret.len() > 0 {
            words[index] = Self::read_le_u32(&mut secret);
            index += 1;
        }

        // init block number
        words[index] = 0;
        index += 1;

        // nonce
        let mut nonce: &[u8] = &nonce[..];
        while nonce.len() > 0 {
            words[index] = Self::read_le_u32(&mut nonce);
            index += 1;
        }

        Chacha20 { words }
    }

    fn read_le_u32(input: &mut &[u8]) -> u32 {
        let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
        *input = rest;
        u32::from_le_bytes(int_bytes.try_into().unwrap())
    }

    pub fn key(&mut self, block: u32) -> [u8; 64] {
        self.words[12] = block;
        let mut state: Chacha20 = self.clone();

        for _ in 0..10 {
            for quarter in QUARTERS {
                state.quarter_round(quarter);
            }
        }
        state.add(self);
        state.serialize()
    }

    fn quarter_round(&mut self, quarter: Quarter) {
        let (a, b, c, d) = quarter;
        let w = &mut self.words;

        w[a] = w[a].wrapping_add(w[b]);
        w[d] ^= w[a];
        w[d] = w[d].rotate_left(16);
        w[c] = w[c].wrapping_add(w[d]);
        w[b] ^= w[c];
        w[b] = w[b].rotate_left(12);
        w[a] = w[a].wrapping_add(w[b]);
        w[d] ^= w[a];
        w[d] = w[d].rotate_left(8);
        w[c] = w[c].wrapping_add(w[d]);
        w[b] ^= w[c];
        w[b] = w[b].rotate_left(7);
    }

    fn add(&mut self, start: &mut Chacha20) {
        for index in 0..SIZE {
            self.words[index] = self.words[index].wrapping_add(start.words[index]);
        }
    }

    fn serialize(&self) -> [u8; 64] {
        self.words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }
}

pub fn encrypt(plainBytes: &Vec<u8>) -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // rfc8349
    #[test]
    fn test_quarter_round() {
        const EXPECT: Chacha20 = Chacha20 {
            words: [
                0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
                0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
                0x2098d9d6, 0x91dbd320,
            ],
        };

        let mut state: Chacha20 = Chacha20 {
            words: [
                0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
                0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
                0x2098d9d6, 0x91dbd320,
            ],
        };

        state.quarter_round(QUARTERS[6]);
        assert_eq!(state, EXPECT);
    }

    #[test]
    fn test_new() {
        const EXPECT: Chacha20 = Chacha20 {
            words: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
                0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000000, 0x09000000,
                0x4a000000, 0x00000000,
            ],
        };

        const SECRET: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        const NONCE: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let setup = Chacha20::new(SECRET, NONCE);
        assert_eq!(setup, EXPECT);
    }

    #[test]
    fn test_key() {
        const EXPECT: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        const SECRET: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        const NONCE: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        const BLOCK: u32 = 1;

        let mut setup = Chacha20::new(SECRET, NONCE);
        let key = setup.key(BLOCK);
        assert_eq!(key, EXPECT);
    }

    #[test]
    fn test_encrypt() {}
}
