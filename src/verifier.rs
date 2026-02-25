use sha2::{Sha256, Digest};

pub fn generate_commitment(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.finalize().to_vec()
}

pub fn verify_commitment(commitment: &[u8], public_key: &[u8]) -> bool {
    let expected_commitment = generate_commitment(public_key);
    commitment == expected_commitment
}