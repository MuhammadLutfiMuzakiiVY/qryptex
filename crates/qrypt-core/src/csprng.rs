use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, Error, RngCore};

/// Secure entropy source wrapping OS cryptographically secure random number generator (getrandom).
pub struct SecureOsRng;

impl RngCore for SecureOsRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::OsRng.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        rand_core::OsRng.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureOsRng {}

/// Deterministic DRBG for reproducible research, KAT vectors, and fuzzing benchmarks only.
/// DO NOT USE IN PRODUCTION ENVIRONMENTS.
#[derive(Clone)]
pub struct DeterministicDrbg {
    inner: ChaCha20Rng,
}

impl DeterministicDrbg {
    /// Instantiate a DRBG from a known 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl RngCore for DeterministicDrbg {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl CryptoRng for DeterministicDrbg {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_drbg_reproducibility() {
        let seed = [42u8; 32];
        let mut drbg1 = DeterministicDrbg::from_seed(seed);
        let mut drbg2 = DeterministicDrbg::from_seed(seed);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        drbg1.fill_bytes(&mut buf1);
        drbg2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_os_rng() {
        let mut rng = SecureOsRng;
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng.fill_bytes(&mut buf1);
        rng.fill_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }
}
