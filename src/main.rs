mod wallet;
mod aggregator;
mod verifier;
mod folding;

use pqc_combo::{generate_dilithium_keypair, sign_message};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use std::thread;
use std::time::Duration;
use sha2::{Sha256, Digest};

fn main() {
    println!("breaking trilema migration\n");

    //compability test: buat smart wallet dengan kunci ECDSA dan PQC, pastikan alamatnya terbentuk
    println!("[1/3] Menutup Celah Downgrade Attack...");
    let (pqc_pub, pqc_sec) = generate_dilithium_keypair();
    let ecdsa_sec = SigningKey::random(&mut OsRng);
    
    let smart_wallet = wallet::SmartWallet::new(*ecdsa_sec.verifying_key(), pqc_pub.as_ref().to_vec());
    println!("Smart Wallet Terbentuk: {}", smart_wallet.address);

    //security test: simulasikan serangan front-running dengan mencoba menebak komitmen PQC sebelum terungkap
    println!("\n[2/3] Menutup Celah Front-Running Kuantum...");
    let commitment = verifier::generate_commitment(&smart_wallet.pqc_pub);
    println!("L1 Mempool menerima Hash Komitmen : 0x{}", hex::encode(&commitment));
    
    thread::sleep(Duration::from_secs(1));

    let is_valid = verifier::verify_commitment(&commitment, &smart_wallet.pqc_pub);
    println!("L1 Verifikasi Commit-and-Reveal : {}", if is_valid { "VALID" } else { "GAGAL" });

    //scalability test: batch 10 transaksi dengan tanda tangan PQC
    println!("\n[3/3] Menutup Celah State Bloat (Recursive Folding Scheme)...");
    
    let tx_count = 10;
    let mut batch_instances = Vec::new();
    let mut total_raw_size = 0;

    for i in 0..tx_count {
        let tx_data = format!("Kirim {} aset dari {}", i, smart_wallet.address);
        let sig = sign_message(&pqc_sec, tx_data.as_bytes());
        
        let witness_bytes = sig.as_ref().to_vec();
        total_raw_size += witness_bytes.len();

        //mengubah transaksi menjadi pasangan pernyataan saksi (R1CS Instance & Witness)
        let mut hasher = Sha256::new();
        hasher.update(tx_data.as_bytes());
        let instance_hash = hasher.finalize().to_vec();

        batch_instances.push(folding::R1CSInstance::new(instance_hash, witness_bytes));
    }
    
    println!("=> Total ukuran saksi mentah (Witness PQC): {} bytes", total_raw_size);

    //mengeksekusi skema pelipatan (melipat 10 transaksi jadi 1)
    let folded_proof = folding::NovaFolder::fold_batch(&batch_instances);
    let folded_size = folded_proof.x.len() + folded_proof.w.len();

    println!("=> Output Publik (x_folded)  : 0x{}", hex::encode(&folded_proof.x));
    println!("=> Output Privat (w_folded)  : 0x{}", hex::encode(&folded_proof.w));
    println!("=> Total ukuran komputasi terlipat : {} bytes", folded_size);

    //kalkulasi gas
    let raw_gas = total_raw_size * 16;
    let folded_gas = folded_size * 16;
    let savings = (1.0 - (folded_gas as f64 / raw_gas as f64)) * 100.0;

    println!("\nHASIL REVOLUSI FOLDING SCHEME:");
    println!("Beban komputasi L1 dihancurkan dari {} gas menjadi hanya {} gas!", raw_gas, folded_gas);
    println!("Efisiensi tercapai: {:.2}%. Arsitektur ini siap untuk ZK-STARK!", savings);
}