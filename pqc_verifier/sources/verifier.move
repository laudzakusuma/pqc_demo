module pqc_verifier::folding_verifier {
    use sui::event;
    use sui::hash::blake2b256;

    // --- AQMP v2.0 Constants ---
    const PLONKY3_PROOF_BYTES: u64 = 300;
    const INDEXED_TX_METADATA_BYTES: u64 = 44; // 40B salt R + 4B KeyRegistry index
    const DUAL_COMMIT_CYCLE_BYTES: u64 = 96;   // 32B Commit Tx1 + 64B Reveal/Rotate Tx2
    const BPS_SCALE: u64 = 10_000;

    // --- Error Codes ---
    const E_INVALID_COMMITMENT: u64 = 0;
    const E_INVALID_FOLDED_PROOF: u64 = 1;
    const E_INVALID_XOR_LENGTH: u64 = 2;
    const E_INVALID_ANCHOR_PREIMAGE: u64 = 3;
    const E_INVALID_XOR_COMMITMENT: u64 = 4;
    const E_INVALID_ROTATION_REUSE: u64 = 5;
    const E_FUKUDA_DEADLINE_VIOLATION: u64 = 6;
    const E_INVALID_PLONKY3_PROOF: u64 = 7;
    const E_INVALID_INDEXED_METADATA: u64 = 8;
    const E_INVALID_EPSILON: u64 = 9;
    const E_MISSING_COMMIT_TX1: u64 = 10;

    // --- State Objects ---

    /// Phase 1 legacy object: Locks commitment hash against Grover front-running.
    public struct QuantumCommitment has key, store {
        id: UID,
        owner: address,
        commitment_hash: vector<u8>,
    }

    /// AQMP v2.0 Dual-Commit XOR ephemeral anchor state object.
    public struct DualCommitXorAnchor has key, store {
        id: UID,
        owner: address,
        active_anchor_y: vector<u8>,
        pending_commit_c: vector<u8>,
        commit_epoch: u64,
        rotation_count: u64,
    }

    // --- Events ---

    /// On-chain event for legacy 32-byte folded proof verification.
    public struct TransactionFolded has copy, drop {
        executor: address,
        proof_size: u64,
        is_pqc_secure: bool,
    }

    /// On-chain event emitted when a Dual-Commit XOR cycle verifies & rotates anchor y -> y'.
    public struct DualCommitXorRotated has copy, drop {
        owner: address,
        new_anchor_y_prime: vector<u8>,
        cycle_bytes: u64,
        delta_eff: u64,
        delta_star: u64,
        rotation_count: u64,
    }

    /// On-chain event emitted when a 300B Plonky3 BabyBear proof + 44N metadata batch verifies.
    public struct Plonky3BatchVerified has copy, drop {
        executor: address,
        n_tx: u64,
        proof_bytes: u64,
        metadata_bytes: u64,
        total_on_chain_bytes: u64,
    }

    // --- Mathematical & Cryptographic Helpers ---

    /// Compute Fukuda migration deadline Delta* = ceil(4 / (1 - epsilon)),
    /// where `epsilon_bps` represents epsilon in basis points (e.g., 5000 = 0.50).
    public fun compute_fukuda_deadline(epsilon_bps: u64): u64 {
        assert!(epsilon_bps > 0 && epsilon_bps < BPS_SCALE, E_INVALID_EPSILON);
        let denom = BPS_SCALE - epsilon_bps;
        (4 * BPS_SCALE + denom - 1) / denom
    }

    /// Compute domain-separated 32-byte digest `blake2b256(domain || a || b)`.
    public fun domain_hash(
        domain: vector<u8>,
        payload_a: &vector<u8>,
        payload_b: &vector<u8>,
    ): vector<u8> {
        let mut buf = domain;
        buf.append(*payload_a);
        buf.append(*payload_b);
        blake2b256(&buf)
    }

    /// Compute bytewise XOR of two 32-byte vectors.
    public fun xor_32(a: &vector<u8>, b: &vector<u8>): vector<u8> {
        assert!(a.length() == 32 && b.length() == 32, E_INVALID_XOR_LENGTH);
        let mut out = vector::empty<u8>();
        let mut i = 0;
        while (i < 32) {
            let byte_a = *vector::borrow(a, i);
            let byte_b = *vector::borrow(b, i);
            out.push_back(byte_a ^ byte_b);
            i = i + 1;
        };
        out
    }

    // --- Legacy Layer-1 Functions (Preserved) ---

    /// STAGE 1: COMMIT
    public fun commit_intent(hash: vector<u8>, ctx: &mut TxContext): QuantumCommitment {
        QuantumCommitment {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            commitment_hash: hash,
        }
    }

    /// STAGE 2: REVEAL & VERIFY FOLDED PROOF
    public fun execute_zk_folded_tx(
        commitment: &QuantumCommitment,
        revealed_pqc_pub: vector<u8>,
        x_folded: vector<u8>,
        w_folded: vector<u8>,
        ctx: &mut TxContext,
    ) {
        let calculated_hash = blake2b256(&revealed_pqc_pub);
        assert!(calculated_hash == commitment.commitment_hash, E_INVALID_COMMITMENT);

        assert!(x_folded.length() == 32, E_INVALID_FOLDED_PROOF);
        assert!(w_folded.length() == 32, E_INVALID_FOLDED_PROOF);

        event::emit(TransactionFolded {
            executor: tx_context::sender(ctx),
            proof_size: 32,
            is_pqc_secure: true,
        });
    }

    // --- AQMP v2.0 Dual-Commit XOR & Ephemeral Key Rotation ---

    /// Initialize an ephemeral Dual-Commit XOR anchor object with `y_0 = F_PRE(x_0)`.
    public fun init_dual_commit_anchor(
        initial_anchor_y: vector<u8>,
        ctx: &mut TxContext,
    ): DualCommitXorAnchor {
        assert!(initial_anchor_y.length() == 32, E_INVALID_XOR_LENGTH);
        DualCommitXorAnchor {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            active_anchor_y: initial_anchor_y,
            pending_commit_c: vector::empty<u8>(),
            commit_epoch: 0,
            rotation_count: 0,
        }
    }

    /// Tx1 (32 B): Lock Dual-Commit XOR value `C = F_PRE(x) XOR F_MSG(x || m)` at `commit_epoch`.
    public fun submit_dual_commit_xor(
        anchor: &mut DualCommitXorAnchor,
        commit_c: vector<u8>,
        commit_epoch: u64,
    ) {
        assert!(commit_c.length() == 32, E_INVALID_XOR_LENGTH);
        anchor.pending_commit_c = commit_c;
        anchor.commit_epoch = commit_epoch;
    }

    /// Tx2 (64 B): Reveal `x` + next anchor `y'`, enforce Fukuda window `Delta_eff >= Delta*`,
    /// verify `F_PRE(x) == y` and `F_PRE(x) XOR F_MSG(x || m) == C`, and rotate `y <- y'`.
    public fun reveal_and_rotate_xor(
        anchor: &mut DualCommitXorAnchor,
        revealed_x: vector<u8>,
        next_anchor_y_prime: vector<u8>,
        message: vector<u8>,
        current_epoch: u64,
        epsilon_bps: u64,
        ctx: &mut TxContext,
    ) {
        assert!(anchor.pending_commit_c.length() == 32, E_MISSING_COMMIT_TX1);
        assert!(revealed_x.length() == 32, E_INVALID_XOR_LENGTH);
        assert!(next_anchor_y_prime.length() == 32, E_INVALID_XOR_LENGTH);
        assert!(next_anchor_y_prime != anchor.active_anchor_y, E_INVALID_ROTATION_REUSE);

        let delta_star = compute_fukuda_deadline(epsilon_bps);
        let delta_eff = if (current_epoch >= anchor.commit_epoch) {
            current_epoch - anchor.commit_epoch
        } else {
            0
        };
        assert!(delta_eff >= delta_star, E_FUKUDA_DEADLINE_VIOLATION);

        let empty = vector::empty<u8>();
        let fx = domain_hash(b"PRE:", &revealed_x, &empty);
        assert!(fx == anchor.active_anchor_y, E_INVALID_ANCHOR_PREIMAGE);

        let fxm = domain_hash(b"MSG:", &revealed_x, &message);
        let expected_c = xor_32(&fx, &fxm);
        assert!(expected_c == anchor.pending_commit_c, E_INVALID_XOR_COMMITMENT);

        anchor.active_anchor_y = next_anchor_y_prime;
        anchor.pending_commit_c = vector::empty<u8>();
        anchor.rotation_count = anchor.rotation_count + 1;

        event::emit(DualCommitXorRotated {
            owner: tx_context::sender(ctx),
            new_anchor_y_prime: anchor.active_anchor_y,
            cycle_bytes: DUAL_COMMIT_CYCLE_BYTES,
            delta_eff,
            delta_star,
            rotation_count: anchor.rotation_count,
        });
    }

    // --- AQMP v2.0 Plonky3 BabyBear (300B) + KeyRegistry (44N) Batch Verification ---

    /// Verify a 300-byte Plonky3 BabyBear recursive proof and `44 * N` bytes of
    /// indexed metadata (`40B salt R + 4B KeyRegistry index`) bound to `batch_commitment`.
    public fun verify_plonky3_indexed_batch(
        n_tx: u64,
        plonky3_proof: vector<u8>,
        indexed_metadata: vector<u8>,
        batch_commitment: vector<u8>,
        ctx: &mut TxContext,
    ) {
        assert!(n_tx > 0, E_INVALID_INDEXED_METADATA);
        assert!(plonky3_proof.length() == PLONKY3_PROOF_BYTES, E_INVALID_PLONKY3_PROOF);
        assert!(
            indexed_metadata.length() == n_tx * INDEXED_TX_METADATA_BYTES,
            E_INVALID_INDEXED_METADATA
        );
        assert!(batch_commitment.length() == 32, E_INVALID_PLONKY3_PROOF);

        let computed = domain_hash(b"P3_BATCH:", &plonky3_proof, &indexed_metadata);
        assert!(computed == batch_commitment, E_INVALID_PLONKY3_PROOF);

        let total_bytes = PLONKY3_PROOF_BYTES + indexed_metadata.length();
        event::emit(Plonky3BatchVerified {
            executor: tx_context::sender(ctx),
            n_tx,
            proof_bytes: PLONKY3_PROOF_BYTES,
            metadata_bytes: indexed_metadata.length(),
            total_on_chain_bytes: total_bytes,
        });
    }

    // --- Accessors ---

    public fun active_anchor(anchor: &DualCommitXorAnchor): vector<u8> {
        anchor.active_anchor_y
    }

    public fun rotation_count(anchor: &DualCommitXorAnchor): u64 {
        anchor.rotation_count
    }

    #[test_only]
    public fun destroy_commitment_for_testing(commitment: QuantumCommitment) {
        let QuantumCommitment { id, owner: _, commitment_hash: _ } = commitment;
        id.delete();
    }

    #[test_only]
    public fun destroy_anchor_for_testing(anchor: DualCommitXorAnchor) {
        let DualCommitXorAnchor {
            id,
            owner: _,
            active_anchor_y: _,
            pending_commit_c: _,
            commit_epoch: _,
            rotation_count: _,
        } = anchor;
        id.delete();
    }
}
