use sha2::{Sha256, Digest};

//membangun Merkle Root sejati dari sekumpulan tanda tangan mentah
pub fn build_merkle_root(signatures: &[Vec<u8>]) -> Vec<u8> {
    if signatures.is_empty() {
        return vec![];
    }

    //hash tingkat daun (leaf nodes)
    let mut leaves: Vec<Vec<u8>> = signatures.iter().map(|sig| {
        let mut hasher = Sha256::new();
        hasher.update(sig);
        hasher.finalize().to_vec()
    }).collect();

    //komputasi pohon ke atas hingga tersisa 1 Root (32 bytes)
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in leaves.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]); //duplikat jika ganjil
            }
            next_level.push(hasher.finalize().to_vec());
        }
        leaves = next_level;
    }

    leaves[0].clone() //merkle root
}