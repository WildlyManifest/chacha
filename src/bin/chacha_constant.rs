use std::convert::TryInto;
static CONSTANT: &str = "expand 32-byte k";

fn main() {
    let mut bytes = CONSTANT.as_bytes();

    while bytes.len() >= 4 {
        let block = read_le_u32(&mut bytes);
        println!("{:#X}", block);
    }
}

fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}
