use hyperplonk::keccak::{Binomial4Challenge, KeccakMode};
use hyperplonk::test_utils::{
    XOR_LOOKUP_MULT_IDX, XOR_LOOKUP_Z_IDX, generate_byte_traces_and_public_digest_limbs,
    prepare_with_mode,
};
use p3_field::PrimeCharacteristicRing;
use p3_hyperplonk::{ProverInput, VerifierInput, prove as hyperprove, verify as hyperverify};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type Val = KoalaBear;

fn prepare_rewritten(input_size: usize) -> hyperplonk::keccak::PreparedKeccak<Binomial4Challenge> {
    let config = hyperplonk::keccak::make_config::<Binomial4Challenge>(100);
    prepare_with_mode(input_size, config, KeccakMode::ByteSpongeWithXorLookup)
        .expect("prepare failed")
}

fn prepare_single_block_no_lookup(
    input_size: usize,
) -> hyperplonk::keccak::PreparedKeccak<Binomial4Challenge> {
    let config = hyperplonk::keccak::make_config::<Binomial4Challenge>(100);
    prepare_with_mode(input_size, config, KeccakMode::SingleBlockNoLookup).expect("prepare failed")
}

fn first_nonzero_mult_row(trace: &p3_matrix::dense::RowMajorMatrix<Val>) -> usize {
    for row in 0..trace.height() {
        let row_slice = trace.row_slice(row).expect("missing trace row");
        if row_slice[XOR_LOOKUP_MULT_IDX] != Val::ZERO {
            return row;
        }
    }
    panic!("expected at least one non-zero multiplicity row");
}

#[test]
fn rewritten_roundtrip_single_block_128() {
    let prepared = prepare_rewritten(128);
    let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");
    hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
}

#[test]
fn single_block_no_lookup_roundtrip_128() {
    let prepared = prepare_single_block_no_lookup(128);
    let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");
    hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
}

#[test]
fn single_block_no_lookup_roundtrip_135() {
    let prepared = prepare_single_block_no_lookup(135);
    let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");
    hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
}

#[test]
fn single_block_no_lookup_rejects_input_136() {
    let config = hyperplonk::keccak::make_config::<Binomial4Challenge>(100);
    let result = prepare_with_mode(136, config, KeccakMode::SingleBlockNoLookup);
    match result {
        Ok(_) => panic!("input_size=136 must fail in SingleBlockNoLookup mode"),
        Err(err) => {
            assert!(
                format!("{err:#}")
                    .contains("SingleBlockNoLookup requires input_size <= 135; got 136")
            );
        }
    }
}

#[test]
fn rewritten_single_block_has_degenerate_lookup_trace() {
    let (_sponge_trace, lookup_trace, _digest_limbs) =
        generate_byte_traces_and_public_digest_limbs::<Val>(128).expect("trace generation failed");
    assert!(
        lookup_trace.height() >= 1,
        "lookup trace must have at least one row"
    );
    for row in 0..lookup_trace.height() {
        let row_slice = lookup_trace.row_slice(row).expect("missing trace row");
        assert_eq!(
            row_slice[XOR_LOOKUP_MULT_IDX],
            Val::ZERO,
            "single-block rewritten mode should not emit absorb interactions"
        );
    }
}

#[test]
fn rewritten_roundtrip_multi_block_136_and_200() {
    for input_size in [136usize, 200usize] {
        let prepared = prepare_rewritten(input_size);
        let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");
        hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
    }
}

#[test]
fn rewritten_meta_shape_matches_u16_design() {
    let prepared = prepare_rewritten(200);
    let metas = prepared.vk.metas();
    assert_eq!(
        metas.len(),
        2,
        "rewritten mode must have exactly two AIR metas"
    );

    let sponge = &metas[0];
    assert_eq!(sponge.width, 2909);
    assert_eq!(sponge.interaction_count, 68);
    assert_eq!(sponge.eval_check_uv_degree, 3);
    assert_eq!(sponge.eval_check_mv_degree, 3);

    let lookup = &metas[1];
    assert_eq!(lookup.width, 34);
    assert_eq!(lookup.interaction_count, 1);
    assert_eq!(lookup.eval_check_uv_degree, 1);
    assert_eq!(lookup.eval_check_mv_degree, 1);
}

#[test]
fn single_block_no_lookup_meta_shape() {
    let prepared = prepare_single_block_no_lookup(128);
    let metas = prepared.vk.metas();
    assert_eq!(
        metas.len(),
        1,
        "single-block no-lookup mode must have exactly one AIR meta"
    );

    let sponge = &metas[0];
    assert_eq!(sponge.width, 2909);
    assert_eq!(sponge.interaction_count, 0);
    assert_eq!(sponge.eval_check_uv_degree, 0);
    assert_eq!(sponge.eval_check_mv_degree, 0);
}

#[test]
fn tampered_lookup_row_is_rejected() {
    let prepared = prepare_rewritten(200);

    let (sponge_trace, mut lookup_trace, digest_limbs) =
        generate_byte_traces_and_public_digest_limbs::<Val>(200).expect("trace generation failed");

    let target_row = first_nonzero_mult_row(&lookup_trace);
    lookup_trace.row_mut(target_row)[XOR_LOOKUP_Z_IDX] += Val::ONE;

    let public_values: Vec<Val> = digest_limbs
        .into_iter()
        .map(|x| Val::new(x as u32))
        .collect();

    let prover_inputs = vec![
        ProverInput::new(
            prepared.airs[0].clone(),
            public_values.clone(),
            sponge_trace,
        ),
        ProverInput::new(prepared.airs[1].clone(), Vec::new(), lookup_trace),
    ];

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = hyperprove(&prepared.config, &prepared.pk, prover_inputs);
        let verifier_inputs = vec![
            VerifierInput::new(prepared.airs[0].clone(), public_values.clone()),
            VerifierInput::new(prepared.airs[1].clone(), Vec::new()),
        ];
        hyperverify(&prepared.config, &prepared.vk, verifier_inputs, &proof)
    }));

    match result {
        Err(_) => {}
        Ok(verify_result) => {
            assert!(
                verify_result.is_err(),
                "tampered lookup row must not verify successfully"
            );
        }
    }
}

#[test]
fn tampered_lookup_multiplicity_is_rejected() {
    let prepared = prepare_rewritten(200);

    let (sponge_trace, mut lookup_trace, digest_limbs) =
        generate_byte_traces_and_public_digest_limbs::<Val>(200).expect("trace generation failed");

    let target_row = first_nonzero_mult_row(&lookup_trace);
    lookup_trace.row_mut(target_row)[XOR_LOOKUP_MULT_IDX] += Val::ONE;

    let public_values: Vec<Val> = digest_limbs
        .into_iter()
        .map(|x| Val::new(x as u32))
        .collect();

    let prover_inputs = vec![
        ProverInput::new(
            prepared.airs[0].clone(),
            public_values.clone(),
            sponge_trace,
        ),
        ProverInput::new(prepared.airs[1].clone(), Vec::new(), lookup_trace),
    ];

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = hyperprove(&prepared.config, &prepared.pk, prover_inputs);
        let verifier_inputs = vec![
            VerifierInput::new(prepared.airs[0].clone(), public_values.clone()),
            VerifierInput::new(prepared.airs[1].clone(), Vec::new()),
        ];
        hyperverify(&prepared.config, &prepared.vk, verifier_inputs, &proof)
    }));

    match result {
        Err(_) => {}
        Ok(verify_result) => {
            assert!(
                verify_result.is_err(),
                "tampered lookup multiplicity must not verify successfully"
            );
        }
    }
}

#[test]
fn proof_size_helpers_handle_multi_air_arity() {
    let prepared = prepare_rewritten(128);
    let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");

    let _v1 = hyperplonk::proof_size_v1(&proof);
    let _v2 = hyperplonk::proof_size_v2(&proof);
    let _v3 = hyperplonk::proof_size(&proof, 100);
}

#[test]
fn proof_size_helpers_handle_single_air_no_lookup_arity() {
    let prepared = prepare_single_block_no_lookup(128);
    let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");

    let _v1 = hyperplonk::proof_size_v1(&proof);
    let _v2 = hyperplonk::proof_size_v2(&proof);
    let _v3 = hyperplonk::proof_size(&proof, 100);
}
