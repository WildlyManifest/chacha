const K: [u32; 4] = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];
const COL0: [usize; 4] = [0, 4, 8, 12];
const COL1: [usize; 4] = [1, 5, 9, 13];
const COL2: [usize; 4] = [2, 6, 10, 14];
const COL3: [usize; 4] = [3, 7, 11, 15];
const DIAG0: [usize; 4] = [0, 5, 10, 15];
const DIAG1: [usize; 4] = [1, 6, 11, 12];
const DIAG2: [usize; 4] = [2, 7, 8, 13];
const DIAG3: [usize; 4] = [3, 4, 9, 14];

#[derive(Clone)]
struct Chacha {
    words: [i32; 16],
}

impl Chacha {
    pub fn key(secret: [u8; 32], block: u32, nonce: [u8; 12]) -> [u8; 64] {
        let mut state: Chacha = Chacha::setup(secret, block, nonce);
        let start: Chacha = state.clone();

        for _ in 0..10 {
            state.quarter_round(COL0);
            state.quarter_round(COL1);
            state.quarter_round(COL2);
            state.quarter_round(COL3);
            state.quarter_round(DIAG0);
            state.quarter_round(DIAG1);
            state.quarter_round(DIAG2);
            state.quarter_round(DIAG3);
        }
        state.sum(start);
        state.serialize()
    }

    fn setup(secret: [u8; 32], block: u32, nonce: [u8; 12]) -> Chacha {}

    fn quarter_round(&mut self, indices: [usize; 4]) {}

    fn sum(&mut self, start: Chacha) -> Chacha {}

    fn serialize(&self) -> [u8; 64] {}
}
