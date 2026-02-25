use sha2::{Sha256, Digest};

//representasi struktur Rank-1 Constraint System (R1CS)
#[derive(Clone, Debug)]
pub struct R1CSInstance {
    pub x: Vec<u8>,
    pub w: Vec<u8>,
}

impl R1CSInstance {
    pub fn new(instance: Vec<u8>, witness: Vec<u8>) -> Self {
        Self { x: instance, w: witness }
    }
}

//melipat mesin skema pelipatan
pub struct NovaFolder;

impl NovaFolder {
    //melipat dua instance (x1, w1) dan (x2, w2) menjadi satu (x_folded, w_folded)
    pub fn fold(inst1: &R1CSInstance, inst2: &R1CSInstance) -> R1CSInstance {
        //menghasilkan faktor pelipat acak 'r' (menggunakan Fiat-Shamir heuristic)
        let mut hasher_r = Sha256::new();
        hasher_r.update(&inst1.x);
        hasher_r.update(&inst2.x);
        let r = hasher_r.finalize().to_vec();
        
        //secara kriptografis disimulasikan melalui state hashing yang terikat
        let mut hasher_x = Sha256::new();
        hasher_x.update(&inst1.x);
        hasher_x.update(&r);
        hasher_x.update(&inst2.x);
        let x_folded = hasher_x.finalize().to_vec();

        let mut hasher_w = Sha256::new();
        hasher_w.update(&inst1.w);
        hasher_w.update(&r);
        hasher_w.update(&inst2.w);
        let w_folded = hasher_w.finalize().to_vec();

        R1CSInstance {
            x: x_folded,
            w: w_folded,
        }
    }

    //melipat sekumpulan besar instance secara rekursif menjadi 1 pasangan (Incremental Verifiable Computation / IVC)
    pub fn fold_batch(instances: &[R1CSInstance]) -> R1CSInstance {
        let mut accumulator = instances[0].clone();
        for i in 1..instances.len() {
            accumulator = Self::fold(&accumulator, &instances[i]);
        }
        accumulator
    }
}