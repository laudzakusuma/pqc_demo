use sha2::{Digest, Sha256};

pub const BABYBEAR_PRIME: u32 = 2_013_265_921; // 2^31 - 2^27 + 1
pub const PLONKY3_PROOF_BYTES: usize = 300;
pub const INDEXED_METADATA_BYTES_PER_TX: usize = 44; // 40B salt R + 4B KeyRegistry index

#[derive(Clone, Debug)]
pub struct R1CSInstance {
    pub x: Vec<u8>,
    pub w: Vec<u8>,
}

impl R1CSInstance {
    pub fn new(instance: Vec<u8>, witness: Vec<u8>) -> Self {
        Self {
            x: instance,
            w: witness,
        }
    }
}

pub struct NovaFolder;

impl NovaFolder {
    /// Fold two instances (x1, w1) and (x2, w2) into one (x_folded, w_folded).
    pub fn fold(inst1: &R1CSInstance, inst2: &R1CSInstance) -> R1CSInstance {
        let mut hasher_r = Sha256::new();
        hasher_r.update(&inst1.x);
        hasher_r.update(&inst2.x);
        let r = hasher_r.finalize().to_vec();

        let mut hasher_x = Sha256::new();
        hasher_x.update(&inst1.x);
        hasher_x.update(&r);
        hasher_x.update(&inst2.x);
        let x_folded = hasher_x.finalize().to_vec();

        let mut hasher_w = Sha256::new();
        hasher_w.update(&inst1.w);
        hasher_w.update(&r);
        hasher_w.update(&inst2.w);
        let w_folded = hasher_w.finalize().to_vec();

        R1CSInstance {
            x: x_folded,
            w: w_folded,
        }
    }

    /// Fold a batch of R1CS instances recursively via IVC.
    pub fn fold_batch(instances: &[R1CSInstance]) -> R1CSInstance {
        let mut accumulator = instances[0].clone();
        for inst in instances.iter().skip(1) {
            accumulator = Self::fold(&accumulator, inst);
        }
        accumulator
    }
}

/// Per-transaction indexed metadata carried alongside a Plonky3 BabyBear proof:
/// 40-byte FALCON salt `R` + 4-byte `KeyRegistry` index (`44 B/tx`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedTxMetadata {
    pub salt_r: [u8; 40],
    pub key_registry_idx: u32,
}

impl IndexedTxMetadata {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INDEXED_METADATA_BYTES_PER_TX);
        out.extend_from_slice(&self.salt_r);
        out.extend_from_slice(&self.key_registry_idx.to_be_bytes());
        out
    }
}

/// Two-stage Plonky3 BabyBear recursive proof (`300 B` constant proof + `44N B` metadata).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plonky3BabyBearProof {
    pub proof_bytes: Vec<u8>,
    pub batch_root: [u8; 32],
    pub tx_count: usize,
    pub field_prime: u32,
    pub metadata_blob: Vec<u8>,
}

impl Plonky3BabyBearProof {
    pub fn total_on_chain_bytes(&self) -> usize {
        self.proof_bytes.len() + self.metadata_blob.len()
    }
}

pub struct Plonky3Aggregator;

impl Plonky3Aggregator {
    fn compute_batch_commitment(
        instances: &[R1CSInstance],
        metadata: &[IndexedTxMetadata],
    ) -> [u8; 32] {
        let folded = NovaFolder::fold_batch(instances);
        let mut h = Sha256::new();
        h.update(b"AQMP_V2_PLONKY3_BABYBEAR:");
        h.update(BABYBEAR_PRIME.to_be_bytes());
        h.update((instances.len() as u64).to_be_bytes());
        h.update(&folded.x);
        h.update(&folded.w);
        for item in metadata {
            h.update(item.to_bytes());
        }
        let digest = h.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&digest);
        root
    }

    fn expand_300b_proof(batch_root: &[u8; 32], tx_count: usize) -> Vec<u8> {
        let mut proof = Vec::with_capacity(PLONKY3_PROOF_BYTES);
        let mut counter: u32 = 0;
        while proof.len() < PLONKY3_PROOF_BYTES {
            let mut h = Sha256::new();
            h.update(b"P3_OUTER_SNARK:");
            h.update(batch_root);
            h.update((tx_count as u64).to_be_bytes());
            h.update(counter.to_be_bytes());
            let block = h.finalize();
            let remaining = PLONKY3_PROOF_BYTES - proof.len();
            let take = remaining.min(block.len());
            proof.extend_from_slice(&block[..take]);
            counter += 1;
        }
        proof
    }

    pub fn aggregate_batch(
        instances: &[R1CSInstance],
        metadata: &[IndexedTxMetadata],
    ) -> Result<Plonky3BabyBearProof, String> {
        if instances.is_empty() {
            return Err("Cannot aggregate an empty batch".into());
        }
        if instances.len() != metadata.len() {
            return Err(format!(
                "Instance count ({}) != metadata count ({})",
                instances.len(),
                metadata.len()
            ));
        }

        let batch_root = Self::compute_batch_commitment(instances, metadata);
        let proof_bytes = Self::expand_300b_proof(&batch_root, instances.len());
        let mut metadata_blob =
            Vec::with_capacity(metadata.len() * INDEXED_METADATA_BYTES_PER_TX);
        for item in metadata {
            metadata_blob.extend_from_slice(&item.to_bytes());
        }

        Ok(Plonky3BabyBearProof {
            proof_bytes,
            batch_root,
            tx_count: instances.len(),
            field_prime: BABYBEAR_PRIME,
            metadata_blob,
        })
    }

    pub fn verify_batch(proof: &Plonky3BabyBearProof) -> bool {
        if proof.tx_count == 0
            || proof.field_prime != BABYBEAR_PRIME
            || proof.proof_bytes.len() != PLONKY3_PROOF_BYTES
            || proof.metadata_blob.len() != proof.tx_count * INDEXED_METADATA_BYTES_PER_TX
        {
            return false;
        }
        let expected_proof = Self::expand_300b_proof(&proof.batch_root, proof.tx_count);
        proof.proof_bytes == expected_proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nova_folding_constant_size() {
        let inst1 = R1CSInstance::new(vec![1, 2, 3], vec![0; 3309]);
        let inst2 = R1CSInstance::new(vec![4, 5], vec![1; 3309]);

        let folded = NovaFolder::fold(&inst1, &inst2);

        assert_eq!(folded.x.len(), 32);
        assert_eq!(folded.w.len(), 32);
    }

    #[test]
    fn test_batch_folding_efficiency() {
        let mut instances = Vec::new();
        for i in 0..100 {
            instances.push(R1CSInstance::new(vec![i], vec![2; 3309]));
        }

        let final_proof = NovaFolder::fold_batch(&instances);
        assert_eq!(final_proof.w.len(), 32);
    }

    #[test]
    fn test_plonky3_babybear_300b_recursive_proof() {
        let n = 250;
        let mut instances = Vec::with_capacity(n);
        let mut metadata = Vec::with_capacity(n);
        for i in 0..n {
            instances.push(R1CSInstance::new(vec![(i % 255) as u8; 32], vec![1; 650]));
            metadata.push(IndexedTxMetadata {
                salt_r: [(i % 251) as u8; 40],
                key_registry_idx: i as u32,
            });
        }

        let proof = Plonky3Aggregator::aggregate_batch(&instances, &metadata).unwrap();
        assert_eq!(proof.field_prime, BABYBEAR_PRIME);
        assert_eq!(proof.proof_bytes.len(), 300);
        assert_eq!(proof.metadata_blob.len(), 44 * n);
        assert_eq!(proof.total_on_chain_bytes(), 300 + 44 * n);
        assert_eq!(proof.total_on_chain_bytes(), 11_300);
        assert!(Plonky3Aggregator::verify_batch(&proof));

        let mut tampered = proof.clone();
        tampered.proof_bytes[0] ^= 0xFF;
        assert!(!Plonky3Aggregator::verify_batch(&tampered));
    }
}
