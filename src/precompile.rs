// Simulasi precompile Falcon-512 sesuai EIP-7619 & AQMP v2.0
use pqcrypto_falcon::falcon512::*;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

pub const FALCON512_PK_BYTES: usize = 897;
pub const FALCON512_SALT_BYTES: usize = 40;
pub const FALCON512_SIG_STD_BYTES: usize = 626;
pub const FALCON512_SIG_KR_BYTES: usize = 650;
pub const FALCON512_MAX_DETACHED_SIG_BYTES: usize = 666;
pub const KEY_REGISTRY_IDX_BYTES: usize = 4;

/// AQMP v2.0 unaggregated FALCON-512 standard payload per tx: `p (897 B) + S (626 B) + R (40 B) = 1563 B`.
pub fn falcon_standard_tx_bytes() -> usize {
    FALCON512_PK_BYTES + FALCON512_SIG_STD_BYTES + FALCON512_SALT_BYTES
}

/// AQMP v2.0 unaggregated FALCON-512 key-recovery payload per tx: `S_tilde (650 B) + R (40 B) = 690 B`.
pub fn falcon_key_recovery_tx_bytes() -> usize {
    FALCON512_SIG_KR_BYTES + FALCON512_SALT_BYTES
}

/// AQMP v2.0 indexed FALCON-512 on-chain metadata per tx: `R (40 B) + KeyRegistry idx (4 B) = 44 B`.
pub fn falcon_indexed_tx_bytes() -> usize {
    FALCON512_SALT_BYTES + KEY_REGISTRY_IDX_BYTES
}

/// Menghitung biaya gas untuk verifikasi Falcon-512 berdasarkan EIP-7619.
pub fn falcon_verify_gas(message: &[u8]) -> u64 {
    const BASE_COST: u64 = 1465;
    let message_words = (message.len() + 31) / 32;
    let memory_cost = (message_words as u64) * 6;
    BASE_COST + memory_cost
}

/// Memverifikasi detached signature Falcon-512.
pub fn verify_falcon(pubkey_bytes: &[u8], sig_bytes: &[u8], message: &[u8]) -> bool {
    if pubkey_bytes.len() != FALCON512_PK_BYTES
        || sig_bytes.is_empty()
        || sig_bytes.len() > FALCON512_MAX_DETACHED_SIG_BYTES
    {
        return false;
    }

    let Ok(pubkey) = PublicKey::from_bytes(pubkey_bytes) else {
        return false;
    };
    let Ok(sig) = DetachedSignature::from_bytes(sig_bytes) else {
        return false;
    };

    verify_detached_signature(&sig, message, &pubkey).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_falcon::falcon512::{detached_sign, keypair};

    #[test]
    fn test_falcon_verify() {
        let (pk, sk) = keypair();
        let message = b"Hello, AQMP v2.0!";
        let signature = detached_sign(message, &sk);

        let pk_bytes = pk.as_bytes();
        let sig_bytes = signature.as_bytes();

        assert_eq!(pk_bytes.len(), FALCON512_PK_BYTES);
        assert!(verify_falcon(pk_bytes, sig_bytes, message));

        let wrong_message = b"Wrong message!";
        assert!(!verify_falcon(pk_bytes, sig_bytes, wrong_message));
    }

    #[test]
    fn test_falcon_gas_and_aqmp_v2_footprints() {
        let message = b"Test message for gas calculation.";
        let gas = falcon_verify_gas(message);
        assert_eq!(gas, 1465 + ((message.len() + 31) / 32 * 6) as u64);
        assert_eq!(falcon_standard_tx_bytes(), 1563);
        assert_eq!(falcon_key_recovery_tx_bytes(), 690);
        assert_eq!(falcon_indexed_tx_bytes(), 44);
    }
}
