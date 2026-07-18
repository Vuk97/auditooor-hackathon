// Positive fixture 1: send arity=3 but receive arity=2 — width mismatch.
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues};

const RANGE_CHECK: u8 = 0;

pub struct MismatchedLookupAir;

impl<AB: AirBuilder> Air<AB> for MismatchedLookupAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        // Sends 3 values for the RANGE_CHECK channel.
        builder.send(RANGE_CHECK, &[local.a, local.b, local.c], local.mult);
    }
}

pub struct RangeTableAir;

impl<AB: AirBuilder> Air<AB> for RangeTableAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        // Receives only 2 values — arity mismatch with the send above.
        builder.receive(RANGE_CHECK, &[local.x, local.y], local.mult);
    }
}
