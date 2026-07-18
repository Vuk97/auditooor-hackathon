// Positive fixture 1: advice column `timestamp` accessed but never constrained.
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;

pub struct MyAir;

impl<AB: AirBuilder> Air<AB> for MyAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        // `counter` is constrained.
        builder.assert_eq(local.counter + AB::Expr::one(), next.counter);

        // `timestamp` is accessed but never appears in any assert call.
        let _t = local.timestamp;
        // Reviewer note: `timestamp` should be range-checked or asserted.
    }
}
