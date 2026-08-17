use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Polynomial in GF(2)[X]/(X^R - 1) for Quasi-Cyclic Code Cryptography
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QcPoly {
    pub r: usize,
    pub words: Vec<u64>,
}

impl Zeroize for QcPoly {
    fn zeroize(&mut self) {
        self.words.zeroize();
    }
}

impl Drop for QcPoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl QcPoly {
    /// Create a zero polynomial of size `r`
    pub fn zero(r: usize) -> Self {
        let num_words = (r + 63) / 64;
        Self {
            r,
            words: vec![0u64; num_words],
        }
    }

    /// Set bit at index `idx` (0-indexed modulo r)
    #[inline]
    pub fn set_bit(&mut self, idx: usize) {
        let bit_pos = idx % self.r;
        let word_idx = bit_pos / 64;
        let offset = bit_pos % 64;
        self.words[word_idx] |= 1u64 << offset;
    }

    /// Get bit at index `idx`
    #[inline]
    pub fn get_bit(&self, idx: usize) -> u8 {
        let bit_pos = idx % self.r;
        let word_idx = bit_pos / 64;
        let offset = bit_pos % 64;
        ((self.words[word_idx] >> offset) & 1) as u8
    }

    /// Flip bit at index `idx`
    #[inline]
    pub fn flip_bit(&mut self, idx: usize) {
        let bit_pos = idx % self.r;
        let word_idx = bit_pos / 64;
        let offset = bit_pos % 64;
        self.words[word_idx] ^= 1u64 << offset;
    }

    /// Hamming weight (number of 1 bits)
    pub fn weight(&self) -> usize {
        let mut count = 0;
        let full_words = self.r / 64;
        for i in 0..full_words {
            count += self.words[i].count_ones() as usize;
        }
        let remainder = self.r % 64;
        if remainder > 0 {
            let mask = (1u64 << remainder) - 1;
            count += (self.words[full_words] & mask).count_ones() as usize;
        }
        count
    }

    /// Polynomial addition in GF(2)[X]/(X^r - 1) is bitwise XOR
    pub fn add(&self, rhs: &Self) -> Self {
        assert_eq!(self.r, rhs.r);
        let mut res = Self::zero(self.r);
        for i in 0..self.words.len() {
            res.words[i] = self.words[i] ^ rhs.words[i];
        }
        res
    }

    /// Cyclic multiplication in GF(2)[X]/(X^r - 1)
    pub fn mul(&self, rhs: &Self) -> Self {
        assert_eq!(self.r, rhs.r);
        let mut res = Self::zero(self.r);
        for i in 0..self.r {
            if self.get_bit(i) == 1 {
                for j in 0..rhs.r {
                    if rhs.get_bit(j) == 1 {
                        let k = (i + j) % self.r;
                        res.flip_bit(k);
                    }
                }
            }
        }
        res
    }

    /// Sample a random sparse polynomial with exactly `w` non-zero coefficients
    pub fn sample_sparse<R: RngCore + CryptoRng>(r: usize, w: usize, rng: &mut R) -> Self {
        assert!(w <= r);
        let mut poly = Self::zero(r);
        let mut set_count = 0;

        while set_count < w {
            let rand_val = rng.next_u32() as usize % r;
            if poly.get_bit(rand_val) == 0 {
                poly.set_bit(rand_val);
                set_count += 1;
            }
        }
        poly
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let byte_len = (self.r + 7) / 8;
        let mut bytes = vec![0u8; byte_len];
        for i in 0..self.r {
            if self.get_bit(i) == 1 {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], r: usize) -> Self {
        let mut poly = Self::zero(r);
        for i in 0..r {
            if (bytes[i / 8] >> (i % 8)) & 1 == 1 {
                poly.set_bit(i);
            }
        }
        poly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_qc_poly_weight_and_serialization() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let poly = QcPoly::sample_sparse(257, 16, &mut rng);
        assert_eq!(poly.weight(), 16);

        let bytes = poly.to_bytes();
        let decoded = QcPoly::from_bytes(&bytes, 257);
        assert_eq!(poly.words, decoded.words);
    }

    #[test]
    fn test_qc_poly_multiplication() {
        let mut a = QcPoly::zero(7);
        let mut b = QcPoly::zero(7);

        // a = X^1 + X^3
        a.set_bit(1);
        a.set_bit(3);

        // b = X^2 + X^5
        b.set_bit(2);
        b.set_bit(5);

        // a * b = (X^1 + X^3)(X^2 + X^5) = X^3 + X^6 + X^5 + X^8
        // X^8 mod (X^7 - 1) = X^1
        // Expected bits set: 1, 3, 5, 6
        let c = a.mul(&b);
        assert_eq!(c.get_bit(1), 1);
        assert_eq!(c.get_bit(3), 1);
        assert_eq!(c.get_bit(5), 1);
        assert_eq!(c.get_bit(6), 1);
        assert_eq!(c.weight(), 4);
    }
}
