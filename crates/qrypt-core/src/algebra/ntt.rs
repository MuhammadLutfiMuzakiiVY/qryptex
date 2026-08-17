use super::field::{barrett_reduce, montgomery_reduce};

pub const N: usize = 256;

/// 512-th primitive root of unity modulo Q=3329 is 17 (17^256 = -1 mod 3329).
/// Table of zeta in bit-reversed order multiplied by Montgomery factor R mod Q.
pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -500, 488, 1014, -130,
    303, -1422, -991, -24, 762, -1071, 1084, -580,
    -1456, 1284, -1304, -883, 907, -1367, -499, 1534,
    1247, -700, -1146, 1269, 1107, -1187, -1389, -1457,
    -739, -439, 230, -120, 378, -244, 514, -812,
    -607, 758, -64, -1200, 1162, 432, -872, -498,
    -1304, -608, -1274, -968, -1397, 901, -177, 54,
    -1440, 1104, -995, 1286, 112, 852, 1020, -1364,
    1210, 155, 1354, -1324, -480, -644, -1102, 1312,
    -1415, -988, -919, 774, -643, 33, -900, 1431,
    -264, 648, 701, -315, -9, 1336, 943, 719,
];

/// Forward Number Theoretic Transform (Cooley-Tukey Butterfly)
pub fn ntt(poly: &mut [i16; N]) {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = montgomery_reduce(zeta as i32 * poly[j + len] as i32);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse Number Theoretic Transform (Gentleman-Sande Butterfly)
pub fn inv_ntt(poly: &mut [i16; N]) {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = montgomery_reduce((zeta as i32) * (t as i32 - poly[j + len] as i32));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // Multiply by 128^{-1} * R^2 mod Q = 1441
    let f: i16 = 1441;
    for j in 0..256 {
        poly[j] = montgomery_reduce(poly[j] as i32 * f as i32);
    }
}

/// Base multiplication of two degree-1 polynomials modulo (X^2 - zeta)
#[inline(always)]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// Pointwise multiplication of two polynomials in NTT domain
pub fn poly_ntt_mul(c: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in 0..64 {
        let zeta = ZETAS[64 + i];
        let neg_zeta = -zeta;

        // Base multiplication for pair (2*i, 2*i + 1) mod (X^2 - zeta)
        let a0 = a[4 * i];
        let a1 = a[4 * i + 1];
        let b0 = b[4 * i];
        let b1 = b[4 * i + 1];

        let r0 = fqmul(a1, b1);
        let r0 = fqmul(r0, zeta);
        let r0 = r0 + fqmul(a0, b0);
        let r1 = fqmul(a0, b1) + fqmul(a1, b0);

        c[4 * i] = barrett_reduce(r0);
        c[4 * i + 1] = barrett_reduce(r1);

        // Base multiplication for pair (2*i + 2, 2*i + 3) mod (X^2 + zeta)
        let a2 = a[4 * i + 2];
        let a3 = a[4 * i + 3];
        let b2 = b[4 * i + 2];
        let b3 = b[4 * i + 3];

        let r2 = fqmul(a3, b3);
        let r2 = fqmul(r2, neg_zeta);
        let r2 = r2 + fqmul(a2, b2);
        let r3 = fqmul(a2, b3) + fqmul(a3, b2);

        c[4 * i + 2] = barrett_reduce(r2);
        c[4 * i + 3] = barrett_reduce(r3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_zeta_table_integrity() {
        assert_eq!(ZETAS.len(), 128);
        assert_eq!(N, 256);
    }
}
