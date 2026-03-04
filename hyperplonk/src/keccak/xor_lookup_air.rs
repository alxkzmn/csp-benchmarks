use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_field::PrimeCharacteristicRing;
use p3_hyperplonk::InteractionBuilder;
use p3_matrix::Matrix;

use crate::keccak::XOR_BUS;

pub const XOR_LOOKUP_X_BITS: usize = 16;
pub const XOR_LOOKUP_Y_BITS: usize = 16;
pub const XOR_LOOKUP_Z_IDX: usize = XOR_LOOKUP_X_BITS + XOR_LOOKUP_Y_BITS;
pub const XOR_LOOKUP_MULT_IDX: usize = XOR_LOOKUP_Z_IDX + 1;
pub const XOR_LOOKUP_COLS: usize = XOR_LOOKUP_MULT_IDX + 1;

#[derive(Clone, Debug, Default)]
pub struct XorLookupAir;

impl XorLookupAir {
    pub fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for XorLookupAir {
    fn width(&self) -> usize {
        XOR_LOOKUP_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for XorLookupAir {}

fn assert_bool_like<AB: AirBuilder>(builder: &mut AB, x: AB::Expr) {
    builder.assert_zero(x.clone() * (x - AB::Expr::ONE));
}

impl<AB: InteractionBuilder> Air<AB> for XorLookupAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");

        let x_bits = &local[..XOR_LOOKUP_X_BITS];
        let y_bits = &local[XOR_LOOKUP_X_BITS..XOR_LOOKUP_X_BITS + XOR_LOOKUP_Y_BITS];
        let z: AB::Expr = local[XOR_LOOKUP_Z_IDX].clone().into();
        let mult: AB::Expr = local[XOR_LOOKUP_MULT_IDX].clone().into();

        let mut x_expr = AB::Expr::ZERO;
        let mut y_expr = AB::Expr::ZERO;
        let mut z_expr = AB::Expr::ZERO;
        let mut pow2 = AB::Expr::ONE;

        for i in 0..XOR_LOOKUP_X_BITS {
            let xb: AB::Expr = x_bits[i].clone().into();
            let yb: AB::Expr = y_bits[i].clone().into();
            assert_bool_like(builder, xb.clone());
            assert_bool_like(builder, yb.clone());

            x_expr += xb.clone() * pow2.clone();
            y_expr += yb.clone() * pow2.clone();

            let xor_bit = xb.clone() + yb.clone() - (AB::Expr::TWO * xb * yb);
            z_expr += xor_bit * pow2.clone();

            pow2 = pow2.clone() + pow2;
        }

        builder.assert_zero(z.clone() - z_expr);
        builder.push_receive(XOR_BUS, [x_expr, y_expr, z], mult);
    }
}
