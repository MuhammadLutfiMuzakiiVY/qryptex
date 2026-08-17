use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QryptError {
    DecapsulationFailed,
    VerificationFailed,
    InvalidEncoding,
    InvalidKeyLength,
    InvalidCiphertextLength,
    InvalidSignatureLength,
    RngFailure,
    DecryptionFailure,
    IncompatibleParameters,
    ThresholdExceeded,
}

impl fmt::Display for QryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecapsulationFailed => write!(f, "Decapsulation failed (invalid ciphertext or shared secret verification)"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::InvalidEncoding => write!(f, "Data encoding is invalid or corrupted"),
            Self::InvalidKeyLength => write!(f, "Key buffer length is invalid"),
            Self::InvalidCiphertextLength => write!(f, "Ciphertext buffer length is invalid"),
            Self::InvalidSignatureLength => write!(f, "Signature buffer length is invalid"),
            Self::RngFailure => write!(f, "Cryptographic random number generation failed"),
            Self::DecryptionFailure => write!(f, "Decryption/decoding failure in underlying code/lattice primitive"),
            Self::IncompatibleParameters => write!(f, "Parameters mismatch between interacting cryptographic primitives"),
            Self::ThresholdExceeded => write!(f, "Error correction threshold exceeded during decoding"),
        }
    }
}

impl std::error::Error for QryptError {}
