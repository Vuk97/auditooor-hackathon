// Positive fixture 2: column `secret_key` accessed via next row, unconstrained.
use p3_air::{Air, AirBuilder};

pub struct KeyScheduleAir;

impl<AB: AirBuilder> Air<AB> for KeyScheduleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        // Only `round` is constrained to advance monotonically.
        builder.assert_eq(local.round + AB::Expr::one(), next.round);

        // `secret_key` from next row is read but never constrained.
        // A malicious prover can set next.secret_key to any value.
        let _sk = next.secret_key;
    }
}
