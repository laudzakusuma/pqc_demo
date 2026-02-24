use pqc_combo::{generate_dilithium_keypair, sign_message, verify_signature};
fn main() {
    println!("Starting the post-quantum signature demo...");

    //data transaksi simulasi
    let transaction_data = b"Sending 100 BTC to PQC recipient";
    println!("Transaction data: {:?}", String::from_utf8_lossy(transaction_data));

    //pembuatan kunci atau keygen, ini akan menghasilkan kunci ML-DSA-65 atau Dilithium
    println!("\n1. Generating Cryptographic Key Pair...");
    let (public_key, secret_key) = generate_dilithium_keypair();

    //melihat ukuran public key dilithium
    println!("Public key size: 1952 bytes");

    //penandatanganan transaksi, menggunakan secret key untuk menandatangani data transaksi
    println!("2. Signing the Transaction...");
    let signature = sign_message(&secret_key, transaction_data);

    //disini node blockchain akan memverifikasi transaksi menggunakan public key pengguna
    println!("3. Verifying the Signature...");
    let is_valid = verify_signature(&public_key, transaction_data, &signature);

    //hasil akhir
    if is_valid {
        println!("\n Signature is valid! Transaction is authenticated.");
    } else {
        println!("\n Signature is invalid! Transaction authentication failed.");
    }
}