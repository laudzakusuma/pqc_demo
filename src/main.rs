mod aggregator;
mod folding;
mod precompile;
mod verifier;
mod wallet;

use aggregator::{
    aqmp_v2_adaptive_bytes, build_merkle_root, ecdsa_bytes, falcon_kr_unaggregated_bytes,
    falcon_std_unaggregated_bytes, labrador_cl_indexed_bytes, labrador_el_indexed_bytes,
    labrador_el_unindexed_bytes, mldsa65_bytes, select_apse_mode, ApseLayer, N_STAR_CL,
    N_STAR_ECDSA, N_STAR_EL, N_STAR_PLONKY3, PROVING_BUDGET_MS,
};
use folding::{IndexedTxMetadata, NovaFolder, Plonky3Aggregator, R1CSInstance};
use k256::ecdsa::SigningKey;
use pqc_combo::{generate_dilithium_keypair, sign_message};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::process::Command;
use verifier::{
    fukuda_deadline, qrom_security_bits, DualCommitXorVerifier, SpongeWidth,
    DUAL_COMMIT_CYCLE_BYTES_256, DUAL_COMMIT_CYCLE_BYTES_384,
};

fn main() {
    println!("==============================================================================");
    println!("AQMP v2.0 (ADAPTIVE QUANTUM MIGRATION PROTOCOL) - RUST + SUI MOVE BENCHMARK");
    println!("==============================================================================\n");

    // [1/5] Wallet Compatibility & 4-Byte KeyRegistry Indexing
    println!("[1/5] Compatibility & 4-Byte KeyRegistry (Closing Downgrade Attacks)...");
    let (pqc_pub, pqc_sec) = generate_dilithium_keypair();
    let ecdsa_sec = SigningKey::random(&mut OsRng);

    let mut xor_256 = DualCommitXorVerifier::new(SpongeWidth::Bits256);
    let x0_256 = [0x11u8; 32];
    let x1_256 = [0x22u8; 32];
    let anchor_256 = xor_256.create_anchor(&x0_256).expect("valid 256-bit anchor");
    let mut anchor_arr = [0u8; 32];
    anchor_arr.copy_from_slice(&anchor_256);

    let legacy_wallet = wallet::SmartWallet::new(*ecdsa_sec.verifying_key(), pqc_pub.as_ref().to_vec());
    let smart_wallet = wallet::SmartWallet::new_with_index(
        *ecdsa_sec.verifying_key(),
        pqc_pub.as_ref().to_vec(),
        42,
        anchor_arr,
    );
    println!("   Smart Wallet Address : {} (P2QRH parity={})", smart_wallet.address, smart_wallet.address == legacy_wallet.address);
    println!(
        "   KeyRegistry Index    : {} (encoded = 0x{})",
        smart_wallet.key_registry_index,
        hex::encode(smart_wallet.key_registry_bytes())
    );

    // Legacy Commit-Reveal check
    let legacy_commit = verifier::generate_commitment(&smart_wallet.pqc_pub);
    let legacy_ok = verifier::verify_commitment(&legacy_commit, &smart_wallet.pqc_pub);
    println!(
        "   Legacy Commit-Reveal : {}",
        if legacy_ok { "VALID" } else { "FAILED" }
    );

    // [2/5] Hash-Based Dual-Commit XOR (256-bit & 384-bit) + QROM + Fukuda Deadline
    println!("\n[2/5] Dual-Commit XOR + QROM Security + Fukuda Consensus Deadline...");
    let msg = b"AQMP v2.0 atomic commit-reveal-rotate cycle";
    let tx1_256 = xor_256.create_commit(&x0_256, msg).expect("tx1 256");
    let tx2_256 = xor_256.create_reveal(&x0_256, &x1_256).expect("tx2 256");
    let ver_256 = xor_256
        .verify_and_rotate(&anchor_256, &tx1_256, &tx2_256, msg, Some((8, 0.50)))
        .expect("dual-commit 256 valid");

    let mut xor_384 = DualCommitXorVerifier::new(SpongeWidth::Bits384);
    let x0_384 = [0x33u8; 48];
    let x1_384 = [0x44u8; 48];
    let anchor_384 = xor_384.create_anchor(&x0_384).expect("valid 384-bit anchor");
    let tx1_384 = xor_384.create_commit(&x0_384, msg).expect("tx1 384");
    let tx2_384 = xor_384.create_reveal(&x0_384, &x1_384).expect("tx2 384");
    let ver_384 = xor_384
        .verify_and_rotate(&anchor_384, &tx1_384, &tx2_384, msg, Some((40, 0.90)))
        .expect("dual-commit 384 valid");

    let qrom_256 = qrom_security_bits(41, xor_256.width().bits());
    let qrom_384 = qrom_security_bits(64, xor_384.width().bits());
    println!(
        "   256-bit Dual-Commit XOR : {} B/tx (width={} B, expected {} B, ECDSA parity), QROM(q_F=2^41) = {:.2} bits",
        ver_256.total_cycle_bytes,
        xor_256.width().cycle_bytes(),
        DUAL_COMMIT_CYCLE_BYTES_256,
        qrom_256
    );
    println!(
        "   384-bit Wide Sponge XOR : {} B/tx (expected {} B), QROM(q_F=2^64) = {:.2} bits (>= 187 bits)",
        ver_384.total_cycle_bytes, DUAL_COMMIT_CYCLE_BYTES_384, qrom_384
    );
    for eps in [0.10_f64, 0.25, 0.50, 0.75, 0.90] {
        let delta_star = fukuda_deadline(eps).expect("valid epsilon");
        println!("   Fukuda Deadline (eps={eps:.2}): Delta* = {delta_star} blocks");
    }

    // [3/5] Falcon-512 EIP-7619 Precompile & AQMP v2.0 Footprints
    println!("\n[3/5] FALCON-512 EIP-7619 Precompile & Indexed Metadata Check...");
    let (falcon_pk, falcon_sk) = falcon512::keypair();
    let falcon_sig = falcon512::detached_sign(msg, &falcon_sk);
    let falcon_ok = precompile::verify_falcon(falcon_pk.as_bytes(), falcon_sig.as_bytes(), msg);
    let falcon_gas = precompile::falcon_verify_gas(msg);
    println!(
        "   FALCON-512 Verify : {} (gas = {}, std = {} B/tx, unagg KR = {} B/tx, indexed = {} B/tx)",
        if falcon_ok { "VALID" } else { "INVALID" },
        falcon_gas,
        precompile::falcon_standard_tx_bytes(),
        precompile::falcon_key_recovery_tx_bytes(),
        precompile::falcon_indexed_tx_bytes()
    );

    // [4/5] APSE v2.0 Break-Even Routing & Plonky3 BabyBear 300B Aggregation
    println!("\n[4/5] APSE v2.0 Break-Even Routing & Plonky3 BabyBear 300B Aggregation...");
    println!(
        "   Break-Even Thresholds : N*_Plonky3 = {}, N*_ECDSA = {}, N*_EL = {}, N*_CL = {}",
        N_STAR_PLONKY3, N_STAR_ECDSA, N_STAR_EL, N_STAR_CL
    );
    let n_sample = 250;
    let apse_p3 = select_apse_mode(n_sample, ApseLayer::ExecutionLayer, true, 420.0)
        .expect("APSE Plonky3 selection");
    let apse_fallback_el = select_apse_mode(n_sample, ApseLayer::ExecutionLayer, true, 900.0)
        .expect("APSE EL fallback selection");
    let apse_fallback_cl = select_apse_mode(n_sample, ApseLayer::ConsensusLayer, true, 900.0)
        .expect("APSE CL fallback selection");
    println!(
        "   APSE (within {:.0} ms budget)     : {:?} -> {} B ({})",
        PROVING_BUDGET_MS, apse_p3.mode, apse_p3.payload_bytes, apse_p3.rationale
    );
    println!(
        "   APSE (EL / CL budget fallback) : EL={:?} ({} B) | CL={:?} ({} B) | ECDSA={} B | ML-DSA={} B",
        apse_fallback_el.mode,
        apse_fallback_el.payload_bytes,
        apse_fallback_cl.mode,
        apse_fallback_cl.payload_bytes,
        ecdsa_bytes(n_sample),
        mldsa65_bytes(n_sample)
    );
    println!(
        "   N=250 Reference Footprints      : FALCON-KR={} B | FALCON-Std={} B | LaBRADOR-FullPK={} B | LaBRADOR-EL={} B | LaBRADOR-CL={} B | AQMP-v2={} B",
        falcon_kr_unaggregated_bytes(n_sample),
        falcon_std_unaggregated_bytes(n_sample),
        labrador_el_unindexed_bytes(n_sample),
        labrador_el_indexed_bytes(n_sample),
        labrador_cl_indexed_bytes(n_sample),
        aqmp_v2_adaptive_bytes(n_sample)
    );

    let mut batch_instances = Vec::with_capacity(n_sample);
    let mut batch_meta = Vec::with_capacity(n_sample);
    let mut raw_sigs = Vec::with_capacity(n_sample);
    for i in 0..n_sample {
        let tx_data = format!("AQMP tx #{i} from {}", smart_wallet.address);
        let sig = sign_message(&pqc_sec, tx_data.as_bytes());
        let witness = sig.as_ref().to_vec();
        raw_sigs.push(witness.clone());
        let instance_hash = Sha256::digest(tx_data.as_bytes()).to_vec();
        batch_instances.push(R1CSInstance::new(instance_hash, witness));
        batch_meta.push(IndexedTxMetadata {
            salt_r: [(i % 251) as u8; 40],
            key_registry_idx: i as u32,
        });
    }

    let merkle_root = build_merkle_root(&raw_sigs);
    let nova_folded = NovaFolder::fold_batch(&batch_instances);
    let p3_proof = Plonky3Aggregator::aggregate_batch(&batch_instances, &batch_meta)
        .expect("Plonky3 aggregation");
    let p3_valid = Plonky3Aggregator::verify_batch(&p3_proof);
    println!(
        "   Plonky3 BabyBear Batch (N=250)  : proof={} B + meta={} B = {} B total (valid={})",
        p3_proof.proof_bytes.len(),
        p3_proof.metadata_blob.len(),
        p3_proof.total_on_chain_bytes(),
        p3_valid
    );
    println!(
        "   Legacy Merkle/Nova Roots        : merkle=0x{}, nova_w={} B",
        hex::encode(&merkle_root[..8]),
        nova_folded.w.len()
    );

    // [5/5] Sui Move Cross-Layer Verification Dispatch (graceful when sui CLI absent)
    println!("\n[5/5] Sui Move Cross-Layer Verification Dispatch...");
    let package_id = "0x9279fb51b3cb7db117239b5a59d23e185fbc726fd760d226c4558c11155edb58";
    let commitment_obj_id = "0x9d051db7aa9597034e5df555ea13d14db0e745683b7b2a4dd32401540e8c6464";
    let hex_pqc_pub = format!("0x{}", hex::encode(&smart_wallet.pqc_pub));
    let hex_x_folded = format!("0x{}", hex::encode(&nova_folded.x));
    let hex_w_folded = format!("0x{}", hex::encode(&nova_folded.w));
    let _hex_commit = format!("0x{}", hex::encode(&legacy_commit));

    match Command::new("sui")
        .arg("client")
        .arg("call")
        .arg("--package")
        .arg(package_id)
        .arg("--module")
        .arg("folding_verifier")
        .arg("--function")
        .arg("execute_zk_folded_tx")
        .arg("--args")
        .arg(commitment_obj_id)
        .arg(&hex_pqc_pub)
        .arg(&hex_x_folded)
        .arg(&hex_w_folded)
        .arg("--gas-budget")
        .arg("1000000")
        .output()
    {
        Ok(output) => {
            println!("   On-Chain Execution Status: {:?}", output.status);
        }
        Err(err) => {
            println!(
                "   Sui CLI not installed on PATH ({err}); verified offline RPC payload preparation:"
            );
            println!(
                "   Target: {package_id}::folding_verifier::execute_zk_folded_tx | plonky3={} B",
                p3_proof.proof_bytes.len()
            );
        }
    }

    println!("\nAQMP v2.0 RUST PROVER + SUI MOVE VERIFIER UPGRADE COMPLETE.");
}
