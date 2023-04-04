pub fn two_bytes_to_u16(bytes: &[u8]) -> u16 {
    assert!(bytes.len() == 2);
    (256u16 * bytes[0] as u16) + bytes[1] as u16
}

pub fn four_bytes_to_u32(bytes: &[u8]) -> u32 {
    assert!(bytes.len() == 4);
    ((bytes[0] as u32) << 24)
        + ((bytes[1] as u32) << 16)
        + ((bytes[2] as u32) << 8)
        + (bytes[3] as u32)
}
