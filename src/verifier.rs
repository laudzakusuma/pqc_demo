use sha2::{Digest, Sha256, Sha384};
use std::collections::HashSet;

pub const DUAL_COMMIT_TX1_BYTES_256: usize = 32;
pub const DUAL_COMMIT_TX2_BYTES_256: usize = 64;
pub const DUAL_COMMIT_CYCLE_BYTES_256: usize =
    DUAL_COMMIT_TX1_BYTES_256 + DUAL_COMMIT_TX2_BYTES_256; // 96 B/tx (ECDSA parity)

pub const DUAL_COMMIT_TX1_BYTES_384: usize = 48;
pub const DUAL_COMMIT_TX2_BYTES_384: usize = 96;
pub const DUAL_COMMIT_CYCLE_BYTES_384: usize =
    DUAL_COMMIT_TX1_BYTES_384 + DUAL_COMMIT_TX2_BYTES_384; // 144 B/tx (QROM >= 187b @ q_F=2^64)

pub const DOMAIN_PREIMAGE: &[u8] = b"PRE:";
pub const DOMAIN_MESSAGE: &[u8] = b"MSG:";

/// Legacy Commit-and-Reveal helper preserved for backwards compatibility.
pub fn generate_commitment(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.finalize().to_vec()
}

/// Legacy Commit-and-Reveal verifier preserved for backwards compatibility.
pub fn verify_commitment(commitment: &[u8], public_key: &[u8]) -> bool {
    let expected_commitment = generate_commitment(public_key);
    commitment == expected_commitment
}

/// Domain-separated sponge/hash digest width for AQMP v2.0 Dual-Commit XOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpongeWidth {
    /// 256-bit digest (32 B Tx1 + 64 B Tx2 = 96 B/tx; >= 128-bit QROM up to q_F = 2^41).
    Bits256,
    /// 384-bit domain-separated digest (48 B Tx1 + 96 B Tx2 = 144 B/tx; >= 187-bit QROM at q_F = 2^64).
    Bits384,
}

impl SpongeWidth {
    pub fn digest_len(self) -> usize {
        match self {
            Self::Bits256 => 32,
            Self::Bits384 => 48,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Self::Bits256 => 256,
            Self::Bits384 => 384,
        }
    }

    pub fn cycle_bytes(self) -> usize {
        self.digest_len() * 3
    }

    pub fn domain_hash(self, domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Bits256 => {
                let mut h = Sha256::new();
                h.update(domain);
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
            Self::Bits384 => {
                let mut h = Sha384::new();
                h.update(domain);
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
        }
    }
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len() != b.len() {
        return Err(format!(
            "XOR operand length mismatch: {} != {}",
            a.len(),
            b.len()
        ));
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Tx1 Commit payload: `C = F_PRE(x) XOR F_MSG(x || m)` (32 B for 256-bit, 48 B for 384-bit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualCommitTx1 {
    pub commitment: Vec<u8>,
    pub width: SpongeWidth,
}

impl DualCommitTx1 {
    pub fn size_bytes(&self) -> usize {
        self.commitment.len()
    }
}

/// Tx2 Reveal & Ephemeral Rotation payload: `(x, y' = F_PRE(x'))` (64 B for 256-bit, 96 B for 384-bit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualCommitRevealTx2 {
    pub revealed_secret_x: Vec<u8>,
    pub next_anchor_y_prime: Vec<u8>,
    pub width: SpongeWidth,
}

impl DualCommitRevealTx2 {
    pub fn size_bytes(&self) -> usize {
        self.revealed_secret_x.len() + self.next_anchor_y_prime.len()
    }
}

/// Outcome of verifying a Dual-Commit XOR commit-reveal-rotate cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualCommitVerification {
    pub rotated_anchor: Vec<u8>,
    pub total_cycle_bytes: usize,
    pub delta_star_blocks: Option<u64>,
}

/// Stateful AQMP v2.0 Dual-Commit XOR verifier with replay & rotation enforcement.
pub struct DualCommitXorVerifier {
    width: SpongeWidth,
    spent_secrets: HashSet<Vec<u8>>,
}

impl DualCommitXorVerifier {
    pub fn new(width: SpongeWidth) -> Self {
        Self {
            width,
            spent_secrets: HashSet::new(),
        }
    }

    pub fn width(&self) -> SpongeWidth {
        self.width
    }

    pub fn create_anchor(&self, secret_x: &[u8]) -> Result<Vec<u8>, String> {
        let expected = self.width.digest_len();
        if secret_x.len() != expected {
            return Err(format!(
                "secret_x must be {expected} bytes, got {}",
                secret_x.len()
            ));
        }
        Ok(self.width.domain_hash(DOMAIN_PREIMAGE, &[secret_x]))
    }

    pub fn create_commit(&self, secret_x: &[u8], message: &[u8]) -> Result<DualCommitTx1, String> {
        let expected = self.width.digest_len();
        if secret_x.len() != expected {
            return Err(format!(
                "secret_x must be {expected} bytes, got {}",
                secret_x.len()
            ));
        }
        let fx = self.width.domain_hash(DOMAIN_PREIMAGE, &[secret_x]);
        let fxm = self.width.domain_hash(DOMAIN_MESSAGE, &[secret_x, message]);
        let commitment = xor_bytes(&fx, &fxm)?;
        Ok(DualCommitTx1 {
            commitment,
            width: self.width,
        })
    }

    pub fn create_reveal(
        &self,
        secret_x: &[u8],
        next_secret_x_prime: &[u8],
    ) -> Result<DualCommitRevealTx2, String> {
        let expected = self.width.digest_len();
        if secret_x.len() != expected || next_secret_x_prime.len() != expected {
            return Err(format!(
                "Both secret_x and next_secret_x_prime must be {expected} bytes"
            ));
        }
        if constant_time_eq(secret_x, next_secret_x_prime) {
            return Err("next_secret_x_prime must differ from secret_x for forward secrecy".into());
        }
        let y_prime = self
            .width
            .domain_hash(DOMAIN_PREIMAGE, &[next_secret_x_prime]);
        Ok(DualCommitRevealTx2 {
            revealed_secret_x: secret_x.to_vec(),
            next_anchor_y_prime: y_prime,
            width: self.width,
        })
    }

    pub fn verify_and_rotate(
        &mut self,
        anchor_y: &[u8],
        tx1: &DualCommitTx1,
        tx2: &DualCommitRevealTx2,
        message: &[u8],
        fukuda_window: Option<(u64, f64)>,
    ) -> Result<DualCommitVerification, String> {
        let expected_len = self.width.digest_len();
        if anchor_y.len() != expected_len {
            return Err(format!(
                "Invalid anchor length: expected {expected_len} B, got {} B",
                anchor_y.len()
            ));
        }
        if tx1.width != self.width || tx2.width != self.width {
            return Err("Sponge width mismatch between verifier and tx payloads".into());
        }
        if tx1.commitment.len() != expected_len
            || tx2.revealed_secret_x.len() != expected_len
            || tx2.next_anchor_y_prime.len() != expected_len
        {
            return Err("Malformed Dual-Commit XOR payload byte lengths".into());
        }

        let delta_star_blocks = match fukuda_window {
            Some((delta_eff, epsilon)) => Some(enforce_fukuda_window(delta_eff, epsilon)?),
            None => None,
        };

        if self.spent_secrets.contains(&tx2.revealed_secret_x) {
            return Err("Replay detected: ephemeral preimage x already consumed".into());
        }
        if constant_time_eq(&tx2.next_anchor_y_prime, anchor_y) {
            return Err("Key rotation failed: next anchor y' cannot reuse current anchor y".into());
        }

        let fx = self
            .width
            .domain_hash(DOMAIN_PREIMAGE, &[&tx2.revealed_secret_x]);
        if !constant_time_eq(&fx, anchor_y) {
            return Err("Anchor preimage mismatch: F_PRE(x) != y".into());
        }

        let fxm = self
            .width
            .domain_hash(DOMAIN_MESSAGE, &[&tx2.revealed_secret_x, message]);
        let expected_c = xor_bytes(&fx, &fxm)?;
        if !constant_time_eq(&expected_c, &tx1.commitment) {
            return Err("Dual-Commit XOR mismatch: F_PRE(x) XOR F_MSG(x || m) != C".into());
        }

        self.spent_secrets.insert(tx2.revealed_secret_x.clone());

        Ok(DualCommitVerification {
            rotated_anchor: tx2.next_anchor_y_prime.clone(),
            total_cycle_bytes: tx1.size_bytes() + tx2.size_bytes(),
            delta_star_blocks,
        })
    }
}

/// Evaluate exact concrete QROM security bits:
/// `Adv^{EUF-CMA-QROM}(A) <= (8 * (q_F + 1)^2 + 32 * q_F^3) / 2^n`.
pub fn qrom_security_bits(log2_q_f: u32, n_bits: u32) -> f64 {
    let ln2 = std::f64::consts::LN_2;
    let log2_qf_plus_1 = (log2_q_f as f64) + (2.0_f64.powi(-(log2_q_f as i32))).ln_1p() / ln2;
    let term1_exp = 3.0 + 2.0 * log2_qf_plus_1; // log2(8 * (q_F + 1)^2)
    let term2_exp = 5.0 + 3.0 * (log2_q_f as f64); // log2(32 * q_F^3)
    let max_exp = term1_exp.max(term2_exp);
    let log2_num =
        max_exp + (2.0_f64.powf(term1_exp - max_exp) + 2.0_f64.powf(term2_exp - max_exp)).log2();
    (n_bits as f64) - log2_num
}

/// Exact integer Fukuda deadline `Delta* = ceil(4 / (1 - epsilon))` where `epsilon = epsilon_bps / 10_000`.
pub fn fukuda_deadline_bps(epsilon_bps: u32) -> Result<u64, String> {
    if epsilon_bps == 0 || epsilon_bps >= 10_000 {
        return Err(format!(
            "epsilon_bps must lie strictly in (0, 10000), got {epsilon_bps}"
        ));
    }
    let denom = u64::from(10_000 - epsilon_bps);
    Ok((40_000 + denom - 1) / denom)
}

/// Compute Fukuda migration deadline `Delta* = ceil(4 / (1 - epsilon))` in blocks.
pub fn fukuda_deadline(epsilon: f64) -> Result<u64, String> {
    if !epsilon.is_finite() || epsilon <= 0.0 || epsilon >= 1.0 {
        return Err(format!("epsilon must lie strictly in (0, 1), got {epsilon}"));
    }
    let bps = (epsilon * 10_000.0).round() as u32;
    fukuda_deadline_bps(bps)
}

/// Enforce Fukuda consensus finality deadline `Delta_eff >= Delta* = ceil(4 / (1 - epsilon))`.
pub fn enforce_fukuda_window(delta_eff: u64, epsilon: f64) -> Result<u64, String> {
    let delta_star = fukuda_deadline(epsilon)?;
    if delta_eff < delta_star {
        return Err(format!(
            "Fukuda finality violation: Delta_eff={delta_eff} < Delta*={delta_star} at epsilon={epsilon:.2}"
        ));
    }
    Ok(delta_star)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_commit_xor_256_and_384_cycle() {
        for (width, expected_tx1, expected_tx2, expected_total) in [
            (
                SpongeWidth::Bits256,
                DUAL_COMMIT_TX1_BYTES_256,
                DUAL_COMMIT_TX2_BYTES_256,
                DUAL_COMMIT_CYCLE_BYTES_256,
            ),
            (
                SpongeWidth::Bits384,
                DUAL_COMMIT_TX1_BYTES_384,
                DUAL_COMMIT_TX2_BYTES_384,
                DUAL_COMMIT_CYCLE_BYTES_384,
            ),
        ] {
            let len = width.digest_len();
            let mut verifier = DualCommitXorVerifier::new(width);
            let x0 = vec![0x11u8; len];
            let x1 = vec![0x22u8; len];
            let msg = b"AQMP v2.0 Dual-Commit XOR payload";

            let y0 = verifier.create_anchor(&x0).unwrap();
            let tx1 = verifier.create_commit(&x0, msg).unwrap();
            let tx2 = verifier.create_reveal(&x0, &x1).unwrap();

            assert_eq!(tx1.size_bytes(), expected_tx1);
            assert_eq!(tx2.size_bytes(), expected_tx2);
            assert_eq!(tx1.size_bytes() + tx2.size_bytes(), expected_total);

            // Tampered message must fail XOR commitment check
            let tampered = verifier.verify_and_rotate(&y0, &tx1, &tx2, b"forged", Some((8, 0.50)));
            assert!(tampered.is_err());

            // Valid verify & rotate succeeds
            let ok = verifier
                .verify_and_rotate(&y0, &tx1, &tx2, msg, Some((8, 0.50)))
                .unwrap();
            assert_eq!(ok.total_cycle_bytes, expected_total);
            assert_eq!(ok.delta_star_blocks, Some(8));
            assert_eq!(ok.rotated_anchor, verifier.create_anchor(&x1).unwrap());

            // Replay of spent x0 must fail
            let replay = verifier.verify_and_rotate(&y0, &tx1, &tx2, msg, Some((8, 0.50)));
            assert!(replay.is_err());
        }
    }

    #[test]
    fn test_qrom_security_bounds_256_and_384() {
        let sec_256_at_40 = qrom_security_bits(40, 256);
        let sec_256_at_41 = qrom_security_bits(41, 256);
        let sec_384_at_64 = qrom_security_bits(64, 384);

        assert!(
            sec_256_at_40 >= 128.0,
            "Expected >= 128-bit QROM at q_F=2^40 for 256-bit sponge, got {sec_256_at_40:.4}"
        );
        assert!(
            sec_256_at_41 >= 127.99,
            "Expected ~128-bit QROM at q_F=2^41 for 256-bit sponge, got {sec_256_at_41:.4}"
        );
        assert!(
            sec_384_at_64 >= 187.0,
            "Expected >= 187-bit QROM at q_F=2^64 for 384-bit sponge, got {sec_384_at_64:.4}"
        );
    }

    #[test]
    fn test_fukuda_migration_deadlines() {
        let expected = [
            (0.10, 5_u64),
            (0.25, 6_u64),
            (0.50, 8_u64),
            (0.75, 16_u64),
            (0.80, 20_u64),
            (0.90, 40_u64),
            (0.95, 80_u64),
        ];
        for (eps, delta_star) in expected {
            assert_eq!(fukuda_deadline(eps).unwrap(), delta_star);
            assert_eq!(enforce_fukuda_window(delta_star, eps).unwrap(), delta_star);
            assert!(enforce_fukuda_window(delta_star - 1, eps).is_err());
        }
    }
}
