use crate::traits::SignatureScheme;
use qrypt_core::constant_time::ct_eq_bytes;
use qrypt_core::error::QryptError;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

pub const TREE_HEIGHT: usize = 4;
pub const NUM_LEAVES: usize = 1 << TREE_HEIGHT; // 16 leaves
pub const WOTS_W: usize = 16; // Base 16 (4 bits per digit)
pub const WOTS_LEN1: usize = 64; // 256 bits / 4 = 64 digits
pub const WOTS_LEN2: usize = 3; // Checksum digits
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // 67 chains
pub const HASH_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashPublicKey {
    pub root: [u8; HASH_LEN],
    pub pub_seed: [u8; HASH_LEN],
}

#[derive(Clone)]
pub struct HashSecretKey {
    pub sec_seed: [u8; HASH_LEN],
    pub pk: HashPublicKey,
}

impl Zeroize for HashSecretKey {
    fn zeroize(&mut self) {
        self.sec_seed.zeroize();
    }
}

impl Drop for HashSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashSignature {
    pub leaf_idx: u32,
    pub wots_sig: Vec<[u8; HASH_LEN]>,
    pub auth_path: Vec<[u8; HASH_LEN]>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HashTreeSignature;

fn prf(seed: &[u8; HASH_LEN], addr: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(addr);
    let mut out = [0u8; HASH_LEN];
    hasher.finalize_xof().read(&mut out);
    out
}

fn hash_node(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN], pub_seed: &[u8; HASH_LEN], level: u8, index: u32) -> [u8; HASH_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(pub_seed);
    hasher.update(&[level]);
    hasher.update(&index.to_be_bytes());
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; HASH_LEN];
    hasher.finalize_xof().read(&mut out);
    out
}

fn chain(input: &[u8; HASH_LEN], start: usize, steps: usize, pub_seed: &[u8; HASH_LEN], chain_idx: usize) -> [u8; HASH_LEN] {
    let mut out = *input;
    for step in start..(start + steps) {
        let mut hasher = Shake256::default();
        hasher.update(pub_seed);
        hasher.update(&(chain_idx as u32).to_be_bytes());
        hasher.update(&(step as u8).to_be_bytes());
        hasher.update(&out);
        hasher.finalize_xof().read(&mut out);
    }
    out
}

/// Compute WOTS+ leaf public key from secret seed and leaf index
fn compute_wots_pk(sec_seed: &[u8; HASH_LEN], pub_seed: &[u8; HASH_LEN], leaf_idx: u32) -> [u8; HASH_LEN] {
    let mut wots_pk_hasher = Shake256::default();
    wots_pk_hasher.update(pub_seed);
    wots_pk_hasher.update(&leaf_idx.to_be_bytes());

    for i in 0..WOTS_LEN {
        let mut addr = [0u8; 8];
        addr[0..4].copy_from_slice(&leaf_idx.to_be_bytes());
        addr[4..8].copy_from_slice(&(i as u32).to_be_bytes());
        let sk_i = prf(sec_seed, &addr);
        let pk_i = chain(&sk_i, 0, WOTS_W - 1, pub_seed, i);
        wots_pk_hasher.update(&pk_i);
    }

    let mut leaf = [0u8; HASH_LEN];
    wots_pk_hasher.finalize_xof().read(&mut leaf);
    leaf
}

/// Build Merkle tree from secret seed and compute all nodes
fn build_merkle_tree(sec_seed: &[u8; HASH_LEN], pub_seed: &[u8; HASH_LEN]) -> (Vec<Vec<[u8; HASH_LEN]>>, [u8; HASH_LEN]) {
    let mut tree: Vec<Vec<[u8; HASH_LEN]>> = Vec::with_capacity(TREE_HEIGHT + 1);

    // Leaves (Level 0)
    let mut leaves = Vec::with_capacity(NUM_LEAVES);
    for i in 0..NUM_LEAVES {
        leaves.push(compute_wots_pk(sec_seed, pub_seed, i as u32));
    }
    tree.push(leaves);

    // Internal nodes
    for h in 0..TREE_HEIGHT {
        let prev_level = &tree[h];
        let mut curr_level = Vec::with_capacity(prev_level.len() / 2);
        for i in 0..(prev_level.len() / 2) {
            let parent = hash_node(&prev_level[2 * i], &prev_level[2 * i + 1], pub_seed, (h + 1) as u8, i as u32);
            curr_level.push(parent);
        }
        tree.push(curr_level);
    }

    let root = tree[TREE_HEIGHT][0];
    (tree, root)
}

fn message_to_wots_digits(msg_digest: &[u8; 32]) -> [usize; WOTS_LEN] {
    let mut digits = [0usize; WOTS_LEN];
    let mut checksum = 0usize;

    for i in 0..WOTS_LEN1 {
        let byte = msg_digest[i / 2];
        let val = if i % 2 == 0 {
            (byte >> 4) as usize
        } else {
            (byte & 0x0F) as usize
        };
        digits[i] = val;
        checksum += (WOTS_W - 1) - val;
    }

    // Append base-16 checksum
    for i in 0..WOTS_LEN2 {
        digits[WOTS_LEN1 + i] = (checksum >> (4 * (WOTS_LEN2 - 1 - i))) & 0x0F;
    }

    digits
}

impl SignatureScheme for HashTreeSignature {
    type PublicKey = HashPublicKey;
    type SecretKey = HashSecretKey;
    type Signature = HashSignature;

    fn algorithm_name() -> &'static str {
        "QRYPTEX-Hash-MerkleWOTS-Level1"
    }

    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError> {
        let mut sec_seed = [0u8; HASH_LEN];
        let mut pub_seed = [0u8; HASH_LEN];
        rng.fill_bytes(&mut sec_seed);
        rng.fill_bytes(&mut pub_seed);

        let (_, root) = build_merkle_tree(&sec_seed, &pub_seed);

        let pk = HashPublicKey { root, pub_seed };
        let sk = HashSecretKey {
            sec_seed,
            pk: pk.clone(),
        };

        Ok((pk, sk))
    }

    fn sign<R: RngCore + CryptoRng>(
        sk: &Self::SecretKey,
        msg: &[u8],
        _rng: &mut R,
    ) -> Result<Self::Signature, QryptError> {
        // Compute message digest = SHAKE256(pub_seed || msg)
        let mut hasher = Shake256::default();
        hasher.update(&sk.pk.pub_seed);
        hasher.update(msg);
        let mut msg_digest = [0u8; 32];
        hasher.finalize_xof().read(&mut msg_digest);

        // Pseudo-random leaf index derived from msg_digest
        let leaf_idx = u32::from_be_bytes(msg_digest[0..4].try_into().unwrap()) % (NUM_LEAVES as u32);

        let digits = message_to_wots_digits(&msg_digest);

        // Compute WOTS+ signature
        let mut wots_sig = Vec::with_capacity(WOTS_LEN);
        for i in 0..WOTS_LEN {
            let mut addr = [0u8; 8];
            addr[0..4].copy_from_slice(&leaf_idx.to_be_bytes());
            addr[4..8].copy_from_slice(&(i as u32).to_be_bytes());
            let sk_i = prf(&sk.sec_seed, &addr);
            let sig_i = chain(&sk_i, 0, digits[i], &sk.pk.pub_seed, i);
            wots_sig.push(sig_i);
        }

        // Compute Merkle authentication path
        let (tree, _) = build_merkle_tree(&sk.sec_seed, &sk.pk.pub_seed);
        let mut auth_path = Vec::with_capacity(TREE_HEIGHT);
        let mut idx = leaf_idx as usize;

        for h in 0..TREE_HEIGHT {
            let sibling_idx = idx ^ 1;
            auth_path.push(tree[h][sibling_idx]);
            idx >>= 1;
        }

        Ok(HashSignature {
            leaf_idx,
            wots_sig,
            auth_path,
        })
    }

    fn verify(
        pk: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, QryptError> {
        if sig.wots_sig.len() != WOTS_LEN || sig.auth_path.len() != TREE_HEIGHT {
            return Ok(false);
        }

        let mut hasher = Shake256::default();
        hasher.update(&pk.pub_seed);
        hasher.update(msg);
        let mut msg_digest = [0u8; 32];
        hasher.finalize_xof().read(&mut msg_digest);

        let digits = message_to_wots_digits(&msg_digest);

        // Recover WOTS+ public key
        let mut wots_pk_hasher = Shake256::default();
        wots_pk_hasher.update(&pk.pub_seed);
        wots_pk_hasher.update(&sig.leaf_idx.to_be_bytes());

        for i in 0..WOTS_LEN {
            let steps = (WOTS_W - 1) - digits[i];
            let pk_i = chain(&sig.wots_sig[i], digits[i], steps, &pk.pub_seed, i);
            wots_pk_hasher.update(&pk_i);
        }

        let mut current_node = [0u8; HASH_LEN];
        wots_pk_hasher.finalize_xof().read(&mut current_node);

        // Climb Merkle tree to root
        let mut idx = sig.leaf_idx;
        for h in 0..TREE_HEIGHT {
            let sibling = &sig.auth_path[h];
            current_node = if idx % 2 == 0 {
                hash_node(&current_node, sibling, &pk.pub_seed, (h + 1) as u8, idx / 2)
            } else {
                hash_node(sibling, &current_node, &pk.pub_seed, (h + 1) as u8, idx / 2)
            };
            idx /= 2;
        }

        let is_valid = ct_eq_bytes(&current_node, &pk.root).unwrap_u8() == 1;
        Ok(is_valid)
    }

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&pk.root);
        bytes.extend_from_slice(&pk.pub_seed);
        bytes
    }

    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError> {
        if bytes.len() != 64 {
            return Err(QryptError::InvalidKeyLength);
        }
        let mut root = [0u8; HASH_LEN];
        let mut pub_seed = [0u8; HASH_LEN];
        root.copy_from_slice(&bytes[0..32]);
        pub_seed.copy_from_slice(&bytes[32..64]);
        Ok(HashPublicKey { root, pub_seed })
    }

    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96);
        bytes.extend_from_slice(&sk.sec_seed);
        bytes.extend_from_slice(&Self::serialize_public_key(&sk.pk));
        bytes
    }

    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError> {
        if bytes.len() != 96 {
            return Err(QryptError::InvalidKeyLength);
        }
        let mut sec_seed = [0u8; HASH_LEN];
        sec_seed.copy_from_slice(&bytes[0..32]);
        let pk = Self::deserialize_public_key(&bytes[32..96])?;
        Ok(HashSecretKey { sec_seed, pk })
    }

    fn serialize_signature(sig: &Self::Signature) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&sig.leaf_idx.to_be_bytes());
        for s in &sig.wots_sig {
            bytes.extend_from_slice(s);
        }
        for a in &sig.auth_path {
            bytes.extend_from_slice(a);
        }
        bytes
    }

    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, QryptError> {
        let expected = 4 + WOTS_LEN * HASH_LEN + TREE_HEIGHT * HASH_LEN;
        if bytes.len() != expected {
            return Err(QryptError::InvalidSignatureLength);
        }
        let leaf_idx = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let mut wots_sig = Vec::with_capacity(WOTS_LEN);
        let mut offset = 4;
        for _ in 0..WOTS_LEN {
            let mut s = [0u8; HASH_LEN];
            s.copy_from_slice(&bytes[offset..offset + HASH_LEN]);
            wots_sig.push(s);
            offset += HASH_LEN;
        }
        let mut auth_path = Vec::with_capacity(TREE_HEIGHT);
        for _ in 0..TREE_HEIGHT {
            let mut a = [0u8; HASH_LEN];
            a.copy_from_slice(&bytes[offset..offset + HASH_LEN]);
            auth_path.push(a);
            offset += HASH_LEN;
        }
        Ok(HashSignature {
            leaf_idx,
            wots_sig,
            auth_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrypt_core::csprng::DeterministicDrbg;

    #[test]
    fn test_hash_sig_roundtrip() {
        let mut rng = DeterministicDrbg::from_seed([31u8; 32]);
        let (pk, sk) = HashTreeSignature::keygen(&mut rng).unwrap();

        let msg = b"QRYPTEX Research Framework Hash Signature Test";
        let sig = HashTreeSignature::sign(&sk, msg, &mut rng).unwrap();
        let valid = HashTreeSignature::verify(&pk, msg, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_hash_sig_rejection_on_modified_msg() {
        let mut rng = DeterministicDrbg::from_seed([32u8; 32]);
        let (pk, sk) = HashTreeSignature::keygen(&mut rng).unwrap();

        let msg = b"Original Message";
        let sig = HashTreeSignature::sign(&sk, msg, &mut rng).unwrap();
        let valid = HashTreeSignature::verify(&pk, b"Tampered Message", &sig).unwrap();
        assert!(!valid);
    }
}
