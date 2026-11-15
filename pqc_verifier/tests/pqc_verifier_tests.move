#[test_only]
module pqc_verifier::pqc_verifier_tests {
    use pqc_verifier::folding_verifier;
    use sui::hash::blake2b256;
    use sui::test_scenario;

    fun make_filled_bytes(byte_val: u8, len: u64): vector<u8> {
        let mut out = vector::empty<u8>();
        let mut i = 0;
        while (i < len) {
            out.push_back(byte_val);
            i = i + 1;
        };
        out
    }

    #[test]
    fun test_legacy_execute_zk_folded_tx() {
        let sender = @0xA11CE;
        let mut scenario = test_scenario::begin(sender);
        let pqc_pub = make_filled_bytes(0x77, 64);
        let pub_hash = blake2b256(&pqc_pub);

        let commitment = folding_verifier::commit_intent(pub_hash, scenario.ctx());
        let x_folded = make_filled_bytes(0x11, 32);
        let w_folded = make_filled_bytes(0x22, 32);

        folding_verifier::execute_zk_folded_tx(
            &commitment,
            pqc_pub,
            x_folded,
            w_folded,
            scenario.ctx(),
        );

        folding_verifier::destroy_commitment_for_testing(commitment);
        scenario.end();
    }

    #[test]
    fun test_fukuda_deadline_values() {
        assert!(folding_verifier::compute_fukuda_deadline(1000) == 5, 100);
        assert!(folding_verifier::compute_fukuda_deadline(2500) == 6, 101);
        assert!(folding_verifier::compute_fukuda_deadline(5000) == 8, 102);
        assert!(folding_verifier::compute_fukuda_deadline(7500) == 16, 103);
        assert!(folding_verifier::compute_fukuda_deadline(9000) == 40, 104);
    }

    #[test]
    fun test_dual_commit_xor_commit_reveal_rotate() {
        let sender = @0xA11CE;
        let mut scenario = test_scenario::begin(sender);

        let x0 = make_filled_bytes(0x11, 32);
        let x1 = make_filled_bytes(0x22, 32);
        let empty = vector::empty<u8>();
        let y0 = folding_verifier::domain_hash(b"PRE:", &x0, &empty);
        let y1 = folding_verifier::domain_hash(b"PRE:", &x1, &empty);

        let message = b"AQMP v2.0 Dual-Commit XOR Move test";
        let fxm = folding_verifier::domain_hash(b"MSG:", &x0, &message);
        let commit_c = folding_verifier::xor_32(&y0, &fxm);

        let mut anchor = folding_verifier::init_dual_commit_anchor(y0, scenario.ctx());
        folding_verifier::submit_dual_commit_xor(&mut anchor, commit_c, 100);

        // epsilon = 0.50 (5000 bps) -> Delta* = 8; current_epoch = 108 -> delta_eff = 8 >= 8
        folding_verifier::reveal_and_rotate_xor(
            &mut anchor,
            x0,
            y1,
            message,
            108,
            5000,
            scenario.ctx(),
        );

        assert!(folding_verifier::active_anchor(&anchor) == y1, 200);
        assert!(folding_verifier::rotation_count(&anchor) == 1, 201);

        folding_verifier::destroy_anchor_for_testing(anchor);
        scenario.end();
    }

    #[test, expected_failure(abort_code = 6, location = pqc_verifier::folding_verifier)]
    fun test_fukuda_window_violation_aborts() {
        let sender = @0xA11CE;
        let mut scenario = test_scenario::begin(sender);

        let x0 = make_filled_bytes(0x11, 32);
        let x1 = make_filled_bytes(0x22, 32);
        let empty = vector::empty<u8>();
        let y0 = folding_verifier::domain_hash(b"PRE:", &x0, &empty);
        let y1 = folding_verifier::domain_hash(b"PRE:", &x1, &empty);

        let message = b"Early reveal violating Fukuda bound";
        let fxm = folding_verifier::domain_hash(b"MSG:", &x0, &message);
        let commit_c = folding_verifier::xor_32(&y0, &fxm);

        let mut anchor = folding_verifier::init_dual_commit_anchor(y0, scenario.ctx());
        folding_verifier::submit_dual_commit_xor(&mut anchor, commit_c, 100);

        // epsilon = 0.50 -> Delta* = 8, but delta_eff = 107 - 100 = 7 < 8 -> abort 6
        folding_verifier::reveal_and_rotate_xor(
            &mut anchor,
            x0,
            y1,
            message,
            107,
            5000,
            scenario.ctx(),
        );

        folding_verifier::destroy_anchor_for_testing(anchor);
        scenario.end();
    }

    #[test]
    fun test_plonky3_indexed_batch_verification() {
        let sender = @0xB0B;
        let mut scenario = test_scenario::begin(sender);

        let n_tx = 6; // N*_ECDSA = 6 (300 + 44*6 = 564 B < 576 B ECDSA)
        let proof = make_filled_bytes(0xAA, 300);
        let indexed_metadata = make_filled_bytes(0x01, n_tx * 44);
        let batch_commitment = folding_verifier::domain_hash(
            b"P3_BATCH:",
            &proof,
            &indexed_metadata,
        );

        folding_verifier::verify_plonky3_indexed_batch(
            n_tx,
            proof,
            indexed_metadata,
            batch_commitment,
            scenario.ctx(),
        );

        scenario.end();
    }
}
