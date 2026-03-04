use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_field::PrimeCharacteristicRing;
use p3_hyperplonk::InteractionBuilder;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS_MIN_1, U64_LIMBS};
use p3_matrix::Matrix;
use p3_matrix::horizontally_truncated::HorizontallyTruncated;

use crate::keccak::XOR_BUS;

/// Keccak-f[1600] state bits.
pub const STATE_BITS: usize = 1600;
/// Keccak-256 digest bits (32 bytes).
const DIGEST_BITS: usize = 256;
/// Digest as 16-bit limbs.
pub const DIGEST_LIMBS: usize = DIGEST_BITS / 16;
/// Keccak-256 rate bytes.
pub const RATE_BYTES: usize = 136;
/// Number of 16-bit limbs in the Keccak-256 rate.
pub const RATE_U16S: usize = RATE_BYTES / 2;
/// Number of 16-bit limbs in the full state.
const STATE_U16S: usize = STATE_BITS / 16;

// Extra columns layout (appended after `p3_keccak_air` columns):
// [hash_end, seen_end, active, is_new_start, block_bytes(136), is_padding_byte(136)]
pub const HASH_END_IDX: usize = NUM_KECCAK_COLS;
pub const SEEN_END_IDX: usize = HASH_END_IDX + 1;
pub const ACTIVE_IDX: usize = SEEN_END_IDX + 1;
pub const IS_NEW_START_IDX: usize = ACTIVE_IDX + 1;
pub const BLOCK_BYTES_START: usize = IS_NEW_START_IDX + 1;
pub const IS_PADDING_START: usize = BLOCK_BYTES_START + RATE_BYTES;
pub const BYTE_EXTRA_COLS: usize = 1 + 1 + 1 + 1 + RATE_BYTES + RATE_BYTES;

#[derive(Clone, Debug)]
pub struct ByteSpongeAir {
    enable_lookup_interactions: bool,
}

impl ByteSpongeAir {
    pub fn new_lookup() -> Self {
        Self {
            enable_lookup_interactions: true,
        }
    }

    pub fn new_single_block_no_lookup() -> Self {
        Self {
            enable_lookup_interactions: false,
        }
    }
}

impl Default for ByteSpongeAir {
    fn default() -> Self {
        Self::new_lookup()
    }
}

impl<F> BaseAir<F> for ByteSpongeAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS + BYTE_EXTRA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for ByteSpongeAir {
    fn num_public_values(&self) -> usize {
        DIGEST_LIMBS
    }
}

struct PrefixAirBuilder<'a, AB> {
    inner: &'a mut AB,
}

impl<AB: AirBuilder> AirBuilder for PrefixAirBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = HorizontallyTruncated<AB::Var, AB::M>;

    fn main(&self) -> Self::M {
        HorizontallyTruncated::new(self.inner.main(), NUM_KECCAK_COLS)
            .expect("failed to truncate matrix")
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x)
    }
}

fn assert_bool_like<AB: AirBuilder>(builder: &mut AB, x: AB::Expr) {
    builder.assert_zero(x.clone() * (x - AB::Expr::ONE));
}

fn rate_u16_position(i: usize) -> (usize, usize, usize) {
    let lane = i / U64_LIMBS;
    let limb = i % U64_LIMBS;
    let y = lane / 5;
    let x = lane % 5;
    (y, x, limb)
}

fn block_u16_expr<AB: AirBuilder>(block_bytes: &[AB::Var], i: usize) -> AB::Expr {
    let lo: AB::Expr = block_bytes[2 * i].clone().into();
    let hi: AB::Expr = block_bytes[2 * i + 1].clone().into();
    lo + hi * AB::Expr::from_u64(1 << 8)
}

impl<AB: InteractionBuilder + AirBuilderWithPublicValues> Air<AB> for ByteSpongeAir {
    fn eval(&self, builder: &mut AB) {
        if !AB::ONLY_INTERACTION {
            let mut prefix = PrefixAirBuilder { inner: builder };
            KeccakAir {}.eval(&mut prefix);
        }

        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("empty trace"),
            main.row_slice(1).expect("trace has only 1 row"),
        );

        let local_keccak: &KeccakCols<AB::Var> = local_row[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AB::Var> = next_row[..NUM_KECCAK_COLS].borrow();

        let local_hash_end: AB::Expr = local_row[HASH_END_IDX].clone().into();
        let local_seen_end: AB::Expr = local_row[SEEN_END_IDX].clone().into();
        let next_seen_end: AB::Expr = next_row[SEEN_END_IDX].clone().into();
        let local_active: AB::Expr = local_row[ACTIVE_IDX].clone().into();
        let next_active: AB::Expr = next_row[ACTIVE_IDX].clone().into();
        let local_is_new_start: AB::Expr = local_row[IS_NEW_START_IDX].clone().into();
        let next_is_new_start: AB::Expr = next_row[IS_NEW_START_IDX].clone().into();

        let local_final_step: AB::Expr = local_keccak.step_flags[NUM_ROUNDS_MIN_1].clone().into();
        let next_first_step: AB::Expr = next_keccak.step_flags[0].clone().into();

        let local_block_bytes = &local_row[BLOCK_BYTES_START..BLOCK_BYTES_START + RATE_BYTES];
        let next_block_bytes = &next_row[BLOCK_BYTES_START..BLOCK_BYTES_START + RATE_BYTES];
        let local_is_padding = &local_row[IS_PADDING_START..IS_PADDING_START + RATE_BYTES];
        let next_is_padding = &next_row[IS_PADDING_START..IS_PADDING_START + RATE_BYTES];

        // `is_final_block` is derived from the last padding flag.
        // If a prover tries to set this too early, final-block padding constraints below force
        // the block bytes into a valid pad10*1 shape (e.g. tail 0x80 / 0x81), which conflicts
        // with non-final message blocks and is rejected.
        let local_is_final_block: AB::Expr = local_is_padding[RATE_BYTES - 1].clone().into();
        let continue_gate = local_final_step.clone()
            * local_active.clone()
            * (AB::Expr::ONE - local_is_final_block.clone());

        if AB::ONLY_INTERACTION {
            if !self.enable_lookup_interactions {
                return;
            }
            for i in 0..RATE_U16S {
                let (y, x, limb) = rate_u16_position(i);
                let next_block_u16 = block_u16_expr::<AB>(next_block_bytes, i);
                let local_post_limb: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb).into();
                let next_pre_limb: AB::Expr = next_keccak.preimage[y][x][limb].clone().into();
                builder.push_send(
                    XOR_BUS,
                    [next_block_u16, local_post_limb, next_pre_limb],
                    continue_gate.clone(),
                );
            }
            return;
        }

        assert_bool_like(builder, local_hash_end.clone());
        assert_bool_like(builder, local_seen_end.clone());
        assert_bool_like(builder, local_active.clone());
        assert_bool_like(builder, local_is_new_start.clone());

        for v in local_is_padding {
            assert_bool_like(builder, v.clone().into());
        }

        builder.when_first_row().assert_zero(local_seen_end.clone());
        builder.when_first_row().assert_one(local_active.clone());
        builder
            .when_first_row()
            .assert_one(local_is_new_start.clone());

        // is_new_start can only happen on first permutation row.
        let local_first_step: AB::Expr = local_keccak.step_flags[0].clone().into();
        builder
            .assert_zero(local_is_new_start.clone() * (AB::Expr::ONE - local_first_step.clone()));
        // Enforce unique start marker: first row is 1, all subsequent rows are 0.
        builder
            .when_transition()
            .assert_zero(next_is_new_start.clone());

        builder
            .when_transition()
            .assert_zero(next_seen_end - (local_seen_end.clone() + local_hash_end.clone()));
        builder
            .when_transition()
            .assert_zero(next_active.clone() - (local_active.clone() - local_hash_end.clone()));

        builder
            .when(local_hash_end.clone())
            .assert_zero((AB::Expr::ONE - local_active.clone()) * local_hash_end.clone());
        builder
            .when(local_hash_end.clone())
            .assert_zero(AB::Expr::ONE - local_final_step.clone());
        // Robust to the edge case where hash_end is on the final row.
        builder
            .when_last_row()
            .assert_one(local_seen_end + local_hash_end.clone());

        // is_padding_byte can only transition 0 -> 1 once.
        for i in 1..RATE_BYTES {
            builder
                .when(local_is_padding[i - 1].clone())
                .assert_one(local_is_padding[i].clone());
        }

        // block bytes and padding flags are constant within a permutation.
        let not_final_step = AB::Expr::ONE - local_final_step.clone();
        for i in 0..RATE_BYTES {
            builder
                .when_transition()
                .when(not_final_step.clone())
                .assert_eq(local_block_bytes[i].clone(), next_block_bytes[i].clone());
            builder
                .when_transition()
                .when(not_final_step.clone())
                .assert_eq(local_is_padding[i].clone(), next_is_padding[i].clone());
        }

        // Padding values for final block.
        let has_single_padding_byte: AB::Expr = local_is_padding[RATE_BYTES - 1].clone().into()
            - local_is_padding[RATE_BYTES - 2].clone().into();

        builder
            .when(local_is_final_block.clone())
            .when(has_single_padding_byte.clone())
            .assert_eq(
                local_block_bytes[RATE_BYTES - 1].clone(),
                AB::F::from_u8(0x81),
            );

        let has_multiple_padding_bytes: AB::Expr = AB::Expr::ONE - has_single_padding_byte.clone();
        for i in 0..RATE_BYTES - 1 {
            let is_first_padding_byte: AB::Expr = if i > 0 {
                local_is_padding[i].clone().into() - local_is_padding[i - 1].clone().into()
            } else {
                local_is_padding[i].clone().into()
            };

            builder
                .when(local_is_final_block.clone())
                .when(has_multiple_padding_bytes.clone())
                .when(is_first_padding_byte.clone())
                .assert_eq(local_block_bytes[i].clone(), AB::F::from_u8(0x01));

            builder
                .when(local_is_final_block.clone())
                .when(has_multiple_padding_bytes.clone())
                .when(local_is_padding[i].clone())
                .when(AB::Expr::ONE - is_first_padding_byte)
                .assert_zero(local_block_bytes[i].clone());
        }

        builder
            .when(local_is_final_block.clone())
            .when(has_multiple_padding_bytes)
            .assert_eq(
                local_block_bytes[RATE_BYTES - 1].clone(),
                AB::F::from_u8(0x80),
            );

        // FIXME(soundness): This phase enforces packed-u16 absorb consistency and targets
        // benchmark proof size. It does not independently enforce strict per-byte range soundness
        // for all non-padding positions.
        let start_gate = local_is_new_start.clone() * local_active.clone();
        for i in 0..RATE_U16S {
            let (y, x, limb) = rate_u16_position(i);
            let local_pre_limb: AB::Expr = local_keccak.preimage[y][x][limb].clone().into();
            let local_block_u16 = block_u16_expr::<AB>(local_block_bytes, i);
            builder
                .when(start_gate.clone())
                .assert_zero(local_pre_limb - local_block_u16);
        }

        for i in RATE_U16S..STATE_U16S {
            let lane = i / U64_LIMBS;
            let limb = i % U64_LIMBS;
            let y = lane / 5;
            let x = lane % 5;
            builder
                .when(start_gate.clone())
                .assert_zero(local_keccak.preimage[y][x][limb].clone());
        }

        // Capacity lanes pass through between non-final blocks.
        for i in RATE_U16S..STATE_U16S {
            let lane = i / U64_LIMBS;
            let limb = i % U64_LIMBS;
            let y = lane / 5;
            let x = lane % 5;
            builder
                .when_transition()
                .when(continue_gate.clone())
                .assert_eq(
                    local_keccak.a_prime_prime_prime(y, x, limb),
                    next_keccak.preimage[y][x][limb].clone(),
                );
        }

        // Absorb sends on each non-final block transition.
        if self.enable_lookup_interactions {
            for i in 0..RATE_U16S {
                let (y, x, limb) = rate_u16_position(i);
                let next_block_u16 = block_u16_expr::<AB>(next_block_bytes, i);
                let local_post_limb: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb).into();
                let next_pre_limb: AB::Expr = next_keccak.preimage[y][x][limb].clone().into();
                builder.push_send(
                    XOR_BUS,
                    [next_block_u16, local_post_limb, next_pre_limb],
                    continue_gate.clone(),
                );
            }
        }

        // Digest check on hash_end row: first 16 u16 limbs (32 bytes).
        for limb_idx in 0..DIGEST_LIMBS {
            let pv_limb: AB::Expr = builder.public_values()[limb_idx].into();
            let u64_index = limb_idx / U64_LIMBS;
            let limb_in_u64 = limb_idx % U64_LIMBS;
            let y = u64_index / 5;
            let x = u64_index % 5;
            let out_limb: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb_in_u64).into();
            builder
                .when(local_hash_end.clone())
                .assert_zero(out_limb - pv_limb);
        }

        // Keep transition linkage active at permutation boundaries while active.
        let boundary_gate = local_final_step * next_first_step * next_active;
        builder
            .when_transition()
            .when(boundary_gate)
            .assert_zero(local_active - AB::Expr::ONE);
    }
}
