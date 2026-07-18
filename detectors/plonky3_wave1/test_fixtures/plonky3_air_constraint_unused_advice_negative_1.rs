// Negative fixture 1: all accessed columns are constrained.
use p3_air::{Air, AirBuilder};

pub struct CorrectAir;

impl<AB: AirBuilder> Air<AB> for CorrectAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        // `value` constrained to be boolean.
        builder.assert_bool(local.value);

        // `counter` constrained to advance by 1.
        builder.assert_eq(local.counter + AB::Expr::one(), next.counter);

        // `hash` constrained to equal computed output.
        builder.assert_eq(local.hash, local.value * local.counter);
    }
}
