use pqc_combo::{generate_dilithium_keypair, sign_message, verify_signature};
use k256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}, Signature};
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use std::thread;
use std::time::Duration;

//dummy ZK-STARK
fn generate_zk_stark_proof(is_pqc_valid: bool, is_ecdsa_valid: bool) -> Result<Vec<u8>, &'static str> {
    if is_pqc_valid && is_ecdsa_valid {
        thread::sleep(Duration::from_millis(500));
        Ok(vec![0xab; 400])
    } else {
        Err("Invalid Signatures, cannot generate XK Proof!")
    }
}

fn main() {
    println!("Starting the post-quantum signature demo...");

    //data transaksi simulasi
    let transaction_data = b"Sending 100 BTC to PQC recipient";
    println!("Transaction data: {:?}", String::from_utf8_lossy(transaction_data));

    //pembuatan kunci atau keygen, ini akan menghasilkan kunci ML-DSA-65 atau Dilithium
    println!("\n1. Generating Cryptographic Key Pair...");
    let (public_key_pqc, secret_key_pqc) = generate_dilithium_keypair();

    let secret_key_ecdsa = SigningKey::random(&mut OsRng);
    let public_key_ecdsa = VerifyingKey::from(&secret_key_ecdsa);

    //mitigasi fromt running quantum
    println!("Publishing Hash of Public Keys to Mempool...");
    let mut hasher = Sha256::new();

    //memasukkan representasi public key PQC ke dalam hash (simulasi byte hashing)
    hasher.update(public_key_pqc.as_ref());
    let pub_key_commitment = hasher.finalize();

    println!("Public Key Commitment (hash): {:x}", pub_key_commitment);
    println!("Waiting for 5 seconds to simulate mempool commitment...");
    thread::sleep(Duration::from_secs(2));

    //hybrid signing
    println!("\n2. Signing the Transaction with Hybrid Signatures...");
    let signature_pqc = sign_message(&secret_key_pqc, transaction_data);
    let signature_ecdsa: Signature = secret_key_ecdsa.sign(transaction_data);

    //GAS estimation & state boat simulation
    println!("\n3. Estimating Gas and Simulating State Changes...");
    let ecdsa_sig_size = 64;
    let pqc_sig_size = 3309;

    let raw_total_size = ecdsa_sig_size + pqc_sig_size;

    let raw_gas_cost = raw_total_size * 16;
    let total_hybrid_size = ecdsa_sig_size + pqc_sig_size;

    println!("Estimated Gas for ECDSA Signature: {} units", ecdsa_sig_size);
    println!("Estimated Gas for PQC Signature: {} units", pqc_sig_size);

    //asumsi biaya eksekusi seperti di L1 ETH
    let estimated_gas_cost = total_hybrid_size * 16;
    println!("Estimated L1 Gas Cost: {} gas (for signature verification)", estimated_gas_cost);

    //double verification
    println!("\n4. Verifying the Hybrid Signatures...");

    //node memverifikasi kedua tanda tangan
    let is_pqc_valid = verify_signature(&public_key_pqc, transaction_data, &signature_pqc);
    let is_ecdsa_valid = public_key_ecdsa.verify(transaction_data, &signature_ecdsa).is_ok();

    //hasil
    match generate_zk_stark_proof(is_pqc_valid, is_ecdsa_valid) {
        Ok(zk_proof) => {
            println!("ZK-STARK Proof Generated Successfully!");
            let zk_proof_size = zk_proof.len();
            let zk_gas_cost = zk_proof_size * 16;

            println!("\n6. Mengirim ZK-Proof ke Layer-1 (On-Chain)...");
            println!("=> Ukuran ZK-Proof      : {} bytes", zk_proof_size);
            println!("=> Estimasi Gas L1 Baru : {} gas", zk_gas_cost);
            
            //Kalkulasi Penghematan
            let gas_saved = raw_gas_cost - zk_gas_cost;
            let percentage_saved = (gas_saved as f64 / raw_gas_cost as f64) * 100.0;
            println!("\nHASIL AKHIR: TRILEMA TERPECAHKAN!");
            println!("   Anda berhasil menghemat {} gas ({:.2}% lebih murah).", gas_saved, percentage_saved);
            println!("- Keamanan: Kuat (Dilithium ML-DSA)");
            println!("- Kompatibilitas: Terjaga (ECDSA Hybrid)");
            println!("- Skalabilitas: Efisien (ZK-STARK Compression)");
        },
        Err(e) => println!("Error generating ZK-STARK proof: {}", e),
    }
}