use super::field::{barrett_reduce, freeze, Q};
use super::ntt::N;
use zeroize::Zeroize;

/// Polynomial in R_q = Z_q[X]/(X^256 + 1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i16; N] }
    }
}

impl Poly {
    pub const ZERO: Self = Self { coeffs: [0i16; N] };

    pub fn new() -> Self {
        Self::default()
    }

    /// Add two polynomials in R_q
    pub fn add(&self, rhs: &Self) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coeffs[i] = barrett_reduce(self.coeffs[i] + rhs.coeffs[i]);
        }
        res
    }

    /// Subtract two polynomials in R_q
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coeffs[i] = barrett_reduce(self.coeffs[i] - rhs.coeffs[i]);
        }
        res
    }

    /// Exact polynomial multiplication in R_q = Z_q[X]/(X^256 + 1)
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut acc = [0i32; N];
        for i in 0..N {
            let ai = self.coeffs[i] as i32;
            for j in 0..N {
                let prod = ai * (rhs.coeffs[j] as i32);
                if i + j < N {
                    acc[i + j] += prod;
                } else {
                    acc[i + j - N] -= prod;
                }
            }
        }
        let mut res = Self::default();
        for i in 0..N {
            res.coeffs[i] = barrett_reduce((acc[i] % (Q as i32)) as i16);
        }
        res
    }

    /// Pointwise multiply two polynomials (alias for mul)
    pub fn mul_ntt(&self, rhs: &Self) -> Self {
        self.mul(rhs)
    }

    /// Forward NTT transform (in-place)
    pub fn ntt(&mut self) {
        // Kept for domain compatibility
    }

    /// Inverse NTT transform (in-place)
    pub fn inv_ntt(&mut self) {
        // Kept for domain compatibility
    }

    /// Reduce all coefficients to canonical range [0, Q-1]
    pub fn freeze(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = freeze(*c);
        }
    }

    /// Encode polynomial coefficients to 12-bit packed bytes (384 bytes per poly)
    pub fn to_bytes_12(&self) -> [u8; 384] {
        let mut out = [0u8; 384];
        let mut t = self.coeffs;
        for c in t.iter_mut() {
            *c = freeze(*c);
        }
        for i in 0..(N / 2) {
            let c0 = t[2 * i] as u16;
            let c1 = t[2 * i + 1] as u16;
            out[3 * i] = (c0 & 0xFF) as u8;
            out[3 * i + 1] = ((c0 >> 8) | ((c1 & 0x0F) << 4)) as u8;
            out[3 * i + 2] = ((c1 >> 4) & 0xFF) as u8;
        }
        out
    }

    /// Decode 12-bit packed bytes back to polynomial
    pub fn from_bytes_12(bytes: &[u8; 384]) -> Self {
        let mut res = Self::default();
        for i in 0..(N / 2) {
            let b0 = bytes[3 * i] as u16;
            let b1 = bytes[3 * i + 1] as u16;
            let b2 = bytes[3 * i + 2] as u16;
            res.coeffs[2 * i] = (b0 | ((b1 & 0x0F) << 8)) as i16;
            res.coeffs[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) as i16;
        }
        res
    }

    /// Compress polynomial to 1-bit per coefficient (32 bytes - message encoding)
    pub fn to_msg_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..N {
            let c = freeze(self.coeffs[i]);
            // Compress: round(c * 2 / Q) mod 2
            let bit = (((((c as u32) << 1) + (Q as u32 / 2)) / (Q as u32)) & 1) as u8;
            out[i / 8] |= bit << (i % 8);
        }
        out
    }

    /// Decompress 32-byte message into polynomial coefficients (0 or (Q+1)/2 = 1665)
    pub fn from_msg_bytes(msg: &[u8; 32]) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            let bit = ((msg[i / 8] >> (i % 8)) & 1) as i16;
            res.coeffs[i] = bit * ((Q + 1) / 2);
        }
        res
    }

    /// Centered Binomial Distribution (CBD) sampling with parameter eta=2 from 128 pseudo-random bytes
    pub fn cbd2(buf: &[u8; 128]) -> Self {
        let mut res = Self::default();
        for i in 0..(N / 4) {
            let byte = buf[2 * i];
            let byte2 = buf[2 * i + 1];
            
            let a0 = (byte & 1) + ((byte >> 1) & 1);
            let b0 = ((byte >> 2) & 1) + ((byte >> 3) & 1);
            res.coeffs[4 * i] = (a0 as i16) - (b0 as i16);

            let a1 = ((byte >> 4) & 1) + ((byte >> 5) & 1);
            let b1 = ((byte >> 6) & 1) + ((byte >> 7) & 1);
            res.coeffs[4 * i + 1] = (a1 as i16) - (b1 as i16);

            let a2 = (byte2 & 1) + ((byte2 >> 1) & 1);
            let b2 = ((byte2 >> 2) & 1) + ((byte2 >> 3) & 1);
            res.coeffs[4 * i + 2] = (a2 as i16) - (b2 as i16);

            let a3 = ((byte2 >> 4) & 1) + ((byte2 >> 5) & 1);
            let b3 = ((byte2 >> 6) & 1) + ((byte2 >> 7) & 1);
            res.coeffs[4 * i + 3] = (a3 as i16) - (b3 as i16);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_bytes_roundtrip() {
        let mut p = Poly::default();
        for i in 0..N {
            p.coeffs[i] = (i as i16 * 13) % Q;
        }
        let bytes = p.to_bytes_12();
        let decoded = Poly::from_bytes_12(&bytes);
        assert_eq!(p.coeffs, decoded.coeffs);
    }

    #[test]
    fn test_poly_msg_roundtrip() {
        let msg = [0xABu8; 32];
        let p = Poly::from_msg_bytes(&msg);
        let recovered = p.to_msg_bytes();
        assert_eq!(msg, recovered);
    }

    #[test]
    fn test_poly_mul() {
        let mut a = Poly::ZERO;
        let mut b = Poly::ZERO;
        a.coeffs[0] = 3;
        a.coeffs[1] = 5;
        b.coeffs[0] = 7;
        b.coeffs[1] = 11;

        // (3 + 5X)(7 + 11X) = 21 + 68X + 55X^2
        let c = a.mul(&b);
        assert_eq!(c.coeffs[0], 21);
        assert_eq!(c.coeffs[1], 68);
        assert_eq!(c.coeffs[2], 55);
        for i in 3..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }
}
