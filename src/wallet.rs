use k256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SmartWallet {
    pub address: String,
    pub ecdsa_pub: VerifyingKey,
    pub pqc_pub: Vec<u8>,
    pub key_registry_index: u32,
    pub initial_anchor: [u8; 32],
}

impl SmartWallet {
    pub fn new(ecdsa_pub: VerifyingKey, pqc_pub: Vec<u8>) -> Self {
        Self::new_with_index(ecdsa_pub, pqc_pub, 0, [0u8; 32])
    }

    /// Create an AQMP v2.0 hybrid smart wallet bound to a 4-byte `KeyRegistry` index
    /// and an initial 32-byte Dual-Commit XOR anchor `y_0`.
    pub fn new_with_index(
        ecdsa_pub: VerifyingKey,
        pqc_pub: Vec<u8>,
        key_registry_index: u32,
        initial_anchor: [u8; 32],
    ) -> Self {
        // P2QRH (Pay-to-Quantum-Resistant-Hash) composite wallet address
        let mut hasher = Sha256::new();
        hasher.update(ecdsa_pub.to_sec1_bytes());
        hasher.update(&pqc_pub);

        let address = format!("0x{}", hex::encode(hasher.finalize()));

        Self {
            address: address[..42].to_string(),
            ecdsa_pub,
            pqc_pub,
            key_registry_index,
            initial_anchor,
        }
    }

    /// Big-endian 4-byte `KeyRegistry` index used in AQMP v2.0 indexed aggregation
    /// (`40B salt R + 4B idx = 44B/tx`).
    pub fn key_registry_bytes(&self) -> [u8; 4] {
        self.key_registry_index.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_downgrade_attack_prevention() {
        let ecdsa_sec = SigningKey::random(&mut OsRng);
        let pqc_pub_valid = vec![9; 1952];

        let wallet = SmartWallet::new(*ecdsa_sec.verifying_key(), pqc_pub_valid);

        let pqc_pub_malicious = vec![0; 1952];
        let downgraded_wallet = SmartWallet::new(*ecdsa_sec.verifying_key(), pqc_pub_malicious);

        assert_ne!(
            wallet.address, downgraded_wallet.address,
            "FATAL: Dompet rentan terhadap Downgrade Attack!"
        );
    }

    #[test]
    fn test_key_registry_4byte_index_encoding() {
        let ecdsa_sec = SigningKey::random(&mut OsRng);
        let pqc_pub = vec![7u8; 897];
        let anchor = [0xABu8; 32];
        let wallet = SmartWallet::new_with_index(
            *ecdsa_sec.verifying_key(),
            pqc_pub,
            0x0102_0304,
            anchor,
        );

        assert_eq!(wallet.key_registry_bytes(), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(wallet.key_registry_bytes().len(), 4);
        assert_eq!(wallet.initial_anchor, anchor);
    }
}
