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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_downgrade_attack_prevention() {
        let ecdsa_sec = SigningKey::random(&mut OsRng);
        let pqc_pub_valid = vec![9; 1952]; //kunci publik ML-DSA simulasi
        
        //dompet asli
        let wallet = SmartWallet::new(*ecdsa_sec.verifying_key(), pqc_pub_valid.clone());

        //simulasi serangan: Penyerang mencoba menurunkan versi ke kunci publik PQC yang kosong/berbeda
        let pqc_pub_malicious = vec![0; 1952];
        let downgraded_wallet = SmartWallet::new(*ecdsa_sec.verifying_key(), pqc_pub_malicious);

        //membuktikan bahwa alamat hash akan rusak/berbeda jika salah satu komponen diubah
        assert_ne!(
            wallet.address, downgraded_wallet.address,
            "FATAL: Dompet rentan terhadap Downgrade Attack!"
        );
    }
}