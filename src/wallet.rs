use k256::ecdsa::VerifyingKey;
use sha2::{Sha256, Digest};

#[allow(dead_code)]
pub struct SmartWallet {
    pub address: String,
    pub ecdsa_pub: VerifyingKey,
    pub pqc_pub: Vec<u8>,
}

impl SmartWallet {
    pub fn new(ecdsa_pub: VerifyingKey, pqc_pub: Vec<u8>) -> Self {
        //alamat dompet P2QRH (Pay-to-Quantum-Resistant-Hash)
        let mut hasher = Sha256::new();
        hasher.update(&ecdsa_pub.to_sec1_bytes());
        hasher.update(&pqc_pub);
        
        //menghasilkan alamat layaknya EVM (0x...) dari hash komposit
        let address = format!("0x{}", hex::encode(hasher.finalize()));
        
        Self {
            address: address[..42].to_string(), //ambil 40 karakter hex + 0x
            ecdsa_pub,
            pqc_pub,
        }
    }
}