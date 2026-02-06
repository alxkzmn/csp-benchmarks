//! Negative test: verifies that a non-zero initial sponge state is rejected.
//!
//! The zero-IV constraint requires that the very first permutation's input state
//! equals `block_bits` (rate portion) XOR zero (capacity portion).  Flipping a
//! capacity bit in the first row should cause verification to fail.

use hyperplonk::test_utils::RATE_BITS;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::NUM_KECCAK_COLS;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type Val = KoalaBear;

/// Corrupt the first row's `a_prime` column for a capacity-region bit so the
/// recovered input bit is non-zero where it should be zero.  This simulates a
/// malicious prover using a non-standard IV.
#[test]
fn tampered_iv_capacity_bit_is_rejected() {
    let prepared = hyperplonk::prepare_keccak(128).expect("prepare failed");

    // Generate an honest trace.
    let (mut trace, digest_limbs) =
        hyperplonk::test_utils::generate_trace_and_public_digest_limbs::<Val>(128)
            .expect("trace generation failed");

    // Pick a capacity bit (any index >= RATE_BITS and < STATE_BITS).
    // The capacity starts right after the 1088 rate bits.
    let target_bit = RATE_BITS; // first capacity bit

    // The input bit A[y,x,z] is recovered from a_prime[y][x][z] XOR c[x][z] XOR c_prime[x][z].
    // Flipping a_prime[y][x][z] on the first row changes the recovered input bit from 0 to 1.
    let lane = target_bit / 64;
    let z = target_bit % 64;
    let x = lane % 5;
    let y = lane / 5;

    // Compute the column index for a_prime[y][x][z] within the KeccakCols layout
    // and read the original value, then drop the borrow before mutating.
    use core::borrow::Borrow;
    use p3_keccak_air::KeccakCols;

    let (a_prime_col, original) = {
        let first_row = trace.row_slice(0).expect("no first row");
        let keccak_cols: &KeccakCols<Val> = first_row[..NUM_KECCAK_COLS].borrow();
        let original = keccak_cols.a_prime[y][x][z];
        let col = {
            let base_ptr = keccak_cols as *const KeccakCols<Val> as *const Val;
            let field_ptr = &keccak_cols.a_prime[y][x][z] as *const Val;
            // SAFETY: both pointers are within the same allocation (the row slice).
            unsafe { field_ptr.offset_from(base_ptr) as usize }
        };
        (col, original)
    };

    // Flip the bit: 0 → 1 or 1 → 0.
    let flipped = if original == Val::ZERO {
        Val::ONE
    } else {
        Val::ZERO
    };
    trace.row_mut(0)[a_prime_col] = flipped;

    // Build public values from the (honest) digest.
    let public_values: Vec<Val> = digest_limbs
        .into_iter()
        .map(|x| Val::new(x as u32))
        .collect();

    // Attempt to prove with the tampered trace.
    use p3_hyperplonk::{ProverInput, VerifierInput, prove as hyperprove, verify as hyperverify};

    let prover_inputs = vec![ProverInput::new(
        hyperplonk::keccak::sponge_air::KeccakSpongeAir::new(),
        public_values.clone(),
        trace,
    )];

    // The prover may or may not panic; if it produces a proof, verification must fail.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = hyperprove(&prepared.config, &prepared.pk, prover_inputs);
        let verifier_inputs = vec![VerifierInput::new(
            hyperplonk::keccak::sponge_air::KeccakSpongeAir::new(),
            public_values.clone(),
        )];
        hyperverify(&prepared.config, &prepared.vk, verifier_inputs, &proof)
    }));

    match result {
        // Prover panicked — the constraint caught the tampering during evaluation.
        Err(_) => {} // expected
        // Prover succeeded — verification must fail.
        Ok(verify_result) => {
            assert!(
                verify_result.is_err(),
                "tampered IV trace must NOT verify successfully"
            );
        }
    }
}
