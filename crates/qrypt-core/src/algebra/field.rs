/// Modulus Q = 3329 for Lattice polynomial arithmetic
pub const Q: i16 = 3329;
pub const Q_I32: i32 = 3329;

/// QINV = -q^{-1} mod 2^16 = 62209 = -3327
pub const QINV: i32 = -3327;

/// Montgomery reduction: computes (a * R^{-1}) mod q where R = 2^16.
#[inline(always)]
pub fn montgomery_reduce(a: i32) -> i16 {
    let u = ((a as i16).wrapping_mul(QINV as i16)) as i32;
    let t = (a - u * Q_I32) >> 16;
    t as i16
}

/// Barrett reduction: computes a mod q for a in [-32768, 32767], mapping result to [-q/2, q/2].
#[inline(always)]
pub fn barrett_reduce(a: i16) -> i16 {
    let v = ((1i32 << 26) + (Q_I32 / 2)) / Q_I32;
    let mut t = ((v * a as i32 + (1 << 25)) >> 26) as i16;
    t = t.wrapping_mul(Q);
    a.wrapping_sub(t)
}

/// Center reduction: maps value to range [-(Q-1)/2, (Q-1)/2]
#[inline(always)]
pub fn csubq(a: i16) -> i16 {
    let mut a = a - Q;
    a += (a >> 15) & Q;
    a
}

/// Map element to canonical range [0, Q-1]
#[inline(always)]
pub fn freeze(mut a: i16) -> i16 {
    a = barrett_reduce(a);
    a += (a >> 15) & Q;
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce() {
        let _r_mod_q = 65536 % 3329; // 2285
                                     // montgomery_reduce(x * R) should be x mod q
        for x in 0..100 {
            let xr = x * 65536;
            let res = freeze(montgomery_reduce(xr));
            assert_eq!(res, (x % Q_I32) as i16);
        }
    }

    #[test]
    fn test_freeze_range() {
        for x in -10000..10000 {
            let f = freeze(x as i16);
            assert!((0..Q).contains(&f));
        }
    }
}
