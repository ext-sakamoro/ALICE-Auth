//! hex.

// Hex (fully unrolled, no loop, no branch)
// ============================================================================

const H: [u8; 16] = *b"0123456789abcdef";

#[cfg(debug_assertions)]
#[inline(always)]
pub(crate) fn hex4(s: &[u8], d: &mut [u8; 8]) {
    d[0] = H[(s[0] >> 4) as usize];
    d[1] = H[(s[0] & 0xf) as usize];
    d[2] = H[(s[1] >> 4) as usize];
    d[3] = H[(s[1] & 0xf) as usize];
    d[4] = H[(s[2] >> 4) as usize];
    d[5] = H[(s[2] & 0xf) as usize];
    d[6] = H[(s[3] >> 4) as usize];
    d[7] = H[(s[3] & 0xf) as usize];
}

#[cfg(debug_assertions)]
#[inline(always)]
pub(crate) fn hex8(s: &[u8], d: &mut [u8; 16]) {
    d[0] = H[(s[0] >> 4) as usize];
    d[1] = H[(s[0] & 0xf) as usize];
    d[2] = H[(s[1] >> 4) as usize];
    d[3] = H[(s[1] & 0xf) as usize];
    d[4] = H[(s[2] >> 4) as usize];
    d[5] = H[(s[2] & 0xf) as usize];
    d[6] = H[(s[3] >> 4) as usize];
    d[7] = H[(s[3] & 0xf) as usize];
    d[8] = H[(s[4] >> 4) as usize];
    d[9] = H[(s[4] & 0xf) as usize];
    d[10] = H[(s[5] >> 4) as usize];
    d[11] = H[(s[5] & 0xf) as usize];
    d[12] = H[(s[6] >> 4) as usize];
    d[13] = H[(s[6] & 0xf) as usize];
    d[14] = H[(s[7] >> 4) as usize];
    d[15] = H[(s[7] & 0xf) as usize];
}

#[inline(always)]
pub(crate) const fn hex32(s: &[u8; 32], d: &mut [u8; 64]) {
    d[0] = H[(s[0] >> 4) as usize];
    d[1] = H[(s[0] & 0xf) as usize];
    d[2] = H[(s[1] >> 4) as usize];
    d[3] = H[(s[1] & 0xf) as usize];
    d[4] = H[(s[2] >> 4) as usize];
    d[5] = H[(s[2] & 0xf) as usize];
    d[6] = H[(s[3] >> 4) as usize];
    d[7] = H[(s[3] & 0xf) as usize];
    d[8] = H[(s[4] >> 4) as usize];
    d[9] = H[(s[4] & 0xf) as usize];
    d[10] = H[(s[5] >> 4) as usize];
    d[11] = H[(s[5] & 0xf) as usize];
    d[12] = H[(s[6] >> 4) as usize];
    d[13] = H[(s[6] & 0xf) as usize];
    d[14] = H[(s[7] >> 4) as usize];
    d[15] = H[(s[7] & 0xf) as usize];
    d[16] = H[(s[8] >> 4) as usize];
    d[17] = H[(s[8] & 0xf) as usize];
    d[18] = H[(s[9] >> 4) as usize];
    d[19] = H[(s[9] & 0xf) as usize];
    d[20] = H[(s[10] >> 4) as usize];
    d[21] = H[(s[10] & 0xf) as usize];
    d[22] = H[(s[11] >> 4) as usize];
    d[23] = H[(s[11] & 0xf) as usize];
    d[24] = H[(s[12] >> 4) as usize];
    d[25] = H[(s[12] & 0xf) as usize];
    d[26] = H[(s[13] >> 4) as usize];
    d[27] = H[(s[13] & 0xf) as usize];
    d[28] = H[(s[14] >> 4) as usize];
    d[29] = H[(s[14] & 0xf) as usize];
    d[30] = H[(s[15] >> 4) as usize];
    d[31] = H[(s[15] & 0xf) as usize];
    d[32] = H[(s[16] >> 4) as usize];
    d[33] = H[(s[16] & 0xf) as usize];
    d[34] = H[(s[17] >> 4) as usize];
    d[35] = H[(s[17] & 0xf) as usize];
    d[36] = H[(s[18] >> 4) as usize];
    d[37] = H[(s[18] & 0xf) as usize];
    d[38] = H[(s[19] >> 4) as usize];
    d[39] = H[(s[19] & 0xf) as usize];
    d[40] = H[(s[20] >> 4) as usize];
    d[41] = H[(s[20] & 0xf) as usize];
    d[42] = H[(s[21] >> 4) as usize];
    d[43] = H[(s[21] & 0xf) as usize];
    d[44] = H[(s[22] >> 4) as usize];
    d[45] = H[(s[22] & 0xf) as usize];
    d[46] = H[(s[23] >> 4) as usize];
    d[47] = H[(s[23] & 0xf) as usize];
    d[48] = H[(s[24] >> 4) as usize];
    d[49] = H[(s[24] & 0xf) as usize];
    d[50] = H[(s[25] >> 4) as usize];
    d[51] = H[(s[25] & 0xf) as usize];
    d[52] = H[(s[26] >> 4) as usize];
    d[53] = H[(s[26] & 0xf) as usize];
    d[54] = H[(s[27] >> 4) as usize];
    d[55] = H[(s[27] & 0xf) as usize];
    d[56] = H[(s[28] >> 4) as usize];
    d[57] = H[(s[28] & 0xf) as usize];
    d[58] = H[(s[29] >> 4) as usize];
    d[59] = H[(s[29] & 0xf) as usize];
    d[60] = H[(s[30] >> 4) as usize];
    d[61] = H[(s[30] & 0xf) as usize];
    d[62] = H[(s[31] >> 4) as usize];
    d[63] = H[(s[31] & 0xf) as usize];
}
