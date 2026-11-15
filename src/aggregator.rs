use sha2::{Digest, Sha256};

pub const ECDSA_PK_BYTES: usize = 32;
pub const ECDSA_SIG_BYTES: usize = 64;
pub const ECDSA_TOTAL_BYTES: usize = ECDSA_PK_BYTES + ECDSA_SIG_BYTES; // 96 B

pub const MLDSA65_PK_BYTES: usize = 1952;
pub const MLDSA65_SIG_BYTES: usize = 3309;
pub const MLDSA65_TOTAL_BYTES: usize = MLDSA65_PK_BYTES + MLDSA65_SIG_BYTES; // 5261 B

pub const FALCON_PK_BYTES: usize = 897;
pub const FALCON_SALT_BYTES: usize = 40;
pub const FALCON_SIG_STD_BYTES: usize = 626;
pub const FALCON_SIG_KR_BYTES: usize = 650;
pub const KEY_REGISTRY_INDEX_BYTES: usize = 4;

pub const LABRADOR_EL_BASE_BYTES: usize = 51_200; // 50 KiB base proof
pub const LABRADOR_EL_LOG_COEFF: usize = 128;
pub const LABRADOR_CL_FIXED_BYTES: usize = 71_680; // 70 KiB fixed overhead
pub const PLONKY3_PROOF_BYTES: usize = 300; // BabyBear recursive proof

pub const PROVING_BUDGET_MS: f64 = 810.0;

pub const N_STAR_PLONKY3: usize = 1;
pub const N_STAR_ECDSA: usize = 6;
pub const N_STAR_EL: usize = 81;
pub const N_STAR_CL: usize = 111;

/// Build a SHA-256 Merkle root from raw PQC signatures.
pub fn build_merkle_root(signatures: &[Vec<u8>]) -> Vec<u8> {
    if signatures.is_empty() {
        return vec![];
    }

    let mut leaves: Vec<Vec<u8>> = signatures
        .iter()
        .map(|sig| {
            let mut hasher = Sha256::new();
            hasher.update(sig);
            hasher.finalize().to_vec()
        })
        .collect();

    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in leaves.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);

            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]);
            }
            next_level.push(hasher.finalize().to_vec());
        }
        leaves = next_level;
    }

    leaves[0].clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApseLayer {
    ExecutionLayer,
    ConsensusLayer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApseAggregationMode {
    Plonky3IndexedAggregation,
    FalconKeyRecoveryUnaggregated,
    LabradorIndexedAggregation,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApseSelection {
    pub mode: ApseAggregationMode,
    pub layer: ApseLayer,
    pub n_tx: usize,
    pub payload_bytes: usize,
    pub ecdsa_baseline_bytes: usize,
    pub mldsa65_baseline_bytes: usize,
    pub falcon_kr_bytes: usize,
    pub breakeven_threshold_n: usize,
    pub proving_time_ms: f64,
    pub proving_budget_ms: f64,
    pub fallback_triggered: bool,
    pub rationale: String,
}

pub fn ecdsa_bytes(n_tx: usize) -> usize {
    n_tx * ECDSA_TOTAL_BYTES
}

pub fn mldsa65_bytes(n_tx: usize) -> usize {
    n_tx * MLDSA65_TOTAL_BYTES
}

/// EL Case 1 (FALCON Key-Recovery, No Aggregation): `N * (650 + 40) = 690N`.
pub fn falcon_kr_unaggregated_bytes(n_tx: usize) -> usize {
    n_tx * (FALCON_SIG_KR_BYTES + FALCON_SALT_BYTES)
}

/// EL Case 2 (FALCON Standard, No Aggregation): `N * (897 + 626 + 40) = 1563N`.
pub fn falcon_std_unaggregated_bytes(n_tx: usize) -> usize {
    n_tx * (FALCON_PK_BYTES + FALCON_SIG_STD_BYTES + FALCON_SALT_BYTES)
}

/// `a_{N,EL} = 51200 + floor(128 * log2(max(N, 2)))`.
pub fn labrador_el_overhead_bytes(n_tx: usize) -> usize {
    let m = n_tx.max(2);
    let log2_term = if m.is_power_of_two() {
        LABRADOR_EL_LOG_COEFF * (m.trailing_zeros() as usize)
    } else {
        (LABRADOR_EL_LOG_COEFF as f64 * (m as f64).log2()).floor() as usize
    };
    LABRADOR_EL_BASE_BYTES + log2_term
}

/// EL Case 3a (LaBRADOR ZK-Aggregation, Unindexed Full PK): `a_{N,EL} + N * (897 + 40)`.
pub fn labrador_el_unindexed_bytes(n_tx: usize) -> usize {
    labrador_el_overhead_bytes(n_tx) + n_tx * (FALCON_PK_BYTES + FALCON_SALT_BYTES)
}

/// EL Case 3b (LaBRADOR ZK-Aggregation + `KeyRegistry` 4B Index): `a_{N,EL} + N * (40 + 4)`.
pub fn labrador_el_indexed_bytes(n_tx: usize) -> usize {
    labrador_el_overhead_bytes(n_tx) + n_tx * (FALCON_SALT_BYTES + KEY_REGISTRY_INDEX_BYTES)
}

/// CL Case 3 (Consensus Layer LaBRADOR Aggregation, 70 KiB fixed): `71680 + N * (40 + 4)`.
pub fn labrador_cl_indexed_bytes(n_tx: usize) -> usize {
    LABRADOR_CL_FIXED_BYTES + n_tx * (FALCON_SALT_BYTES + KEY_REGISTRY_INDEX_BYTES)
}

/// AQMP v2.0 Plonky3 BabyBear 300B Recursive Proof + `KeyRegistry` 4B Index: `300 + 44N`.
pub fn plonky3_indexed_bytes(n_tx: usize) -> usize {
    PLONKY3_PROOF_BYTES + n_tx * (FALCON_SALT_BYTES + KEY_REGISTRY_INDEX_BYTES)
}

/// AQMP v2.0 Adaptive Threshold: `min(690N, 300 + 44N)`.
pub fn aqmp_v2_adaptive_bytes(n_tx: usize) -> usize {
    falcon_kr_unaggregated_bytes(n_tx).min(plonky3_indexed_bytes(n_tx))
}

/// APSE v2.0 deterministic break-even routing engine.
pub fn select_apse_mode(
    n_tx: usize,
    layer: ApseLayer,
    plonky3_active: bool,
    proving_time_ms: f64,
) -> Result<ApseSelection, String> {
    if n_tx == 0 {
        return Err("n_tx must be >= 1".into());
    }
    if !proving_time_ms.is_finite() || proving_time_ms < 0.0 {
        return Err(format!("Invalid proving_time_ms: {proving_time_ms}"));
    }

    let ecdsa_b = ecdsa_bytes(n_tx);
    let mldsa_b = mldsa65_bytes(n_tx);
    let falcon_kr_b = falcon_kr_unaggregated_bytes(n_tx);
    let budget_ok = proving_time_ms <= PROVING_BUDGET_MS;

    if plonky3_active && budget_ok && n_tx >= N_STAR_PLONKY3 {
        let payload_b = plonky3_indexed_bytes(n_tx);
        return Ok(ApseSelection {
            mode: ApseAggregationMode::Plonky3IndexedAggregation,
            layer,
            n_tx,
            payload_bytes: payload_b,
            ecdsa_baseline_bytes: ecdsa_b,
            mldsa65_baseline_bytes: mldsa_b,
            falcon_kr_bytes: falcon_kr_b,
            breakeven_threshold_n: N_STAR_PLONKY3,
            proving_time_ms,
            proving_budget_ms: PROVING_BUDGET_MS,
            fallback_triggered: false,
            rationale: format!(
                "Plonky3 BabyBear 300B proof active within {PROVING_BUDGET_MS:.0} ms budget ({proving_time_ms:.1} ms): 300 + 44*{n_tx} = {payload_b} B"
            ),
        });
    }

    let threshold_n = match layer {
        ApseLayer::ExecutionLayer => N_STAR_EL,
        ApseLayer::ConsensusLayer => N_STAR_CL,
    };
    let reason_prefix = if !plonky3_active {
        "Plonky3 disabled".to_string()
    } else {
        format!("Proving time {proving_time_ms:.1} ms exceeded {PROVING_BUDGET_MS:.0} ms budget")
    };

    if n_tx < threshold_n {
        Ok(ApseSelection {
            mode: ApseAggregationMode::FalconKeyRecoveryUnaggregated,
            layer,
            n_tx,
            payload_bytes: falcon_kr_b,
            ecdsa_baseline_bytes: ecdsa_b,
            mldsa65_baseline_bytes: mldsa_b,
            falcon_kr_bytes: falcon_kr_b,
            breakeven_threshold_n: threshold_n,
            proving_time_ms,
            proving_budget_ms: PROVING_BUDGET_MS,
            fallback_triggered: true,
            rationale: format!(
                "{reason_prefix}; N={n_tx} < N*={threshold_n} -> FALCON key-recovery unaggregated ({falcon_kr_b} B)"
            ),
        })
    } else {
        let payload_b = match layer {
            ApseLayer::ExecutionLayer => labrador_el_indexed_bytes(n_tx),
            ApseLayer::ConsensusLayer => labrador_cl_indexed_bytes(n_tx),
        };
        Ok(ApseSelection {
            mode: ApseAggregationMode::LabradorIndexedAggregation,
            layer,
            n_tx,
            payload_bytes: payload_b,
            ecdsa_baseline_bytes: ecdsa_b,
            mldsa65_baseline_bytes: mldsa_b,
            falcon_kr_bytes: falcon_kr_b,
            breakeven_threshold_n: threshold_n,
            proving_time_ms,
            proving_budget_ms: PROVING_BUDGET_MS,
            fallback_triggered: true,
            rationale: format!(
                "{reason_prefix}; N={n_tx} >= N*={threshold_n} -> LaBRADOR + KeyRegistry indexed aggregation ({payload_b} B)"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apse_v2_exact_breakeven_thresholds() {
        let first_el = (1..=1000)
            .find(|&n| labrador_el_indexed_bytes(n) < falcon_kr_unaggregated_bytes(n))
            .unwrap();
        let first_cl = (1..=1000)
            .find(|&n| labrador_cl_indexed_bytes(n) < falcon_kr_unaggregated_bytes(n))
            .unwrap();
        let first_ecdsa = (1..=1000)
            .find(|&n| plonky3_indexed_bytes(n) < ecdsa_bytes(n))
            .unwrap();
        let first_plonky3 = (1..=1000)
            .find(|&n| plonky3_indexed_bytes(n) < falcon_kr_unaggregated_bytes(n))
            .unwrap();

        assert_eq!(first_el, N_STAR_EL);
        assert_eq!(first_cl, N_STAR_CL);
        assert_eq!(first_ecdsa, N_STAR_ECDSA);
        assert_eq!(first_plonky3, N_STAR_PLONKY3);
    }

    #[test]
    fn test_apse_v2_payloads_at_n250() {
        assert_eq!(ecdsa_bytes(250), 24_000);
        assert_eq!(mldsa65_bytes(250), 1_315_250);
        assert_eq!(falcon_kr_unaggregated_bytes(250), 172_500);
        assert_eq!(falcon_std_unaggregated_bytes(250), 390_750);
        assert_eq!(labrador_el_unindexed_bytes(250), 286_469);
        assert_eq!(labrador_el_indexed_bytes(250), 63_219);
        assert_eq!(labrador_cl_indexed_bytes(250), 82_680);
        assert_eq!(plonky3_indexed_bytes(250), 11_300);
        assert_eq!(aqmp_v2_adaptive_bytes(250), 11_300);
    }

    #[test]
    fn test_apse_v2_budget_fallback_routing() {
        // Within 810 ms budget -> Plonky3 BabyBear 300B + 44N
        let p3 = select_apse_mode(250, ApseLayer::ExecutionLayer, true, 420.0).unwrap();
        assert_eq!(p3.mode, ApseAggregationMode::Plonky3IndexedAggregation);
        assert!(!p3.fallback_triggered);
        assert_eq!(p3.payload_bytes, 11_300);

        // Over 810 ms budget, EL N=80 < 81 -> FALCON key-recovery unaggregated
        let el_pre = select_apse_mode(80, ApseLayer::ExecutionLayer, true, 900.0).unwrap();
        assert_eq!(
            el_pre.mode,
            ApseAggregationMode::FalconKeyRecoveryUnaggregated
        );
        assert!(el_pre.fallback_triggered);
        assert_eq!(el_pre.payload_bytes, 55_200);

        // Over 810 ms budget, EL N=81 >= 81 -> LaBRADOR EL + KeyRegistry
        let el_post = select_apse_mode(81, ApseLayer::ExecutionLayer, true, 900.0).unwrap();
        assert_eq!(el_post.mode, ApseAggregationMode::LabradorIndexedAggregation);
        assert_eq!(el_post.payload_bytes, 55_575);

        // Over 810 ms budget, CL N=110 < 111 vs N=111 >= 111
        let cl_pre = select_apse_mode(110, ApseLayer::ConsensusLayer, true, 900.0).unwrap();
        assert_eq!(
            cl_pre.mode,
            ApseAggregationMode::FalconKeyRecoveryUnaggregated
        );
        let cl_post = select_apse_mode(111, ApseLayer::ConsensusLayer, true, 900.0).unwrap();
        assert_eq!(cl_post.mode, ApseAggregationMode::LabradorIndexedAggregation);
        assert_eq!(cl_post.payload_bytes, 76_564);
    }
}
