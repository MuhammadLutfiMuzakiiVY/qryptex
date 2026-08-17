use subtle::{Choice, ConstantTimeEq};

/// Constant-time byte array comparison.
/// Returns Choice(1) if `a` and `b` are equal, Choice(0) otherwise.
#[inline]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        Choice::from(0)
    } else {
        a.ct_eq(b)
    }
}

/// Constant-time conditional copy: if `choice == 1`, copy `src` to `dst`.
#[inline]
pub fn ct_conditional_copy(choice: Choice, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    let mask = choice.unwrap_u8().wrapping_neg();
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= mask & (*d ^ s);
    }
}

/// Constant-time conditional select: returns `a` if `choice == 1`, else `b`.
#[inline]
pub fn ct_select_u32(choice: Choice, a: u32, b: u32) -> u32 {
    let mask = (choice.unwrap_u8() as u32).wrapping_neg();
    b ^ (mask & (a ^ b))
}

/// Constant-time conditional select for i16.
#[inline]
pub fn ct_select_i16(choice: Choice, a: i16, b: i16) -> i16 {
    let mask = (choice.unwrap_u8() as i16).wrapping_neg();
    b ^ (mask & (a ^ b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_bytes() {
        let b1 = [1u8, 2, 3, 4];
        let b2 = [1u8, 2, 3, 4];
        let b3 = [1u8, 2, 3, 5];
        assert_eq!(ct_eq_bytes(&b1, &b2).unwrap_u8(), 1);
        assert_eq!(ct_eq_bytes(&b1, &b3).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_conditional_copy() {
        let mut dst = [0u8; 4];
        let src = [10u8, 20, 30, 40];
        ct_conditional_copy(Choice::from(0), &mut dst, &src);
        assert_eq!(dst, [0, 0, 0, 0]);
        ct_conditional_copy(Choice::from(1), &mut dst, &src);
        assert_eq!(dst, [10, 20, 30, 40]);
    }
}
