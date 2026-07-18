// Negative fixture 1: send arity=2 matches receive arity=2 — no finding.
use p3_air::{Air, AirBuilder};

const RANGE_CHECK: u8 = 0;

pub struct LookupAir;

impl<AB: AirBuilder> Air<AB> for LookupAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        builder.send(RANGE_CHECK, &[local.val, local.flag], local.mult);
    }
}

pub struct TableAir;

impl<AB: AirBuilder> Air<AB> for TableAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        builder.receive(RANGE_CHECK, &[local.val, local.flag], local.mult);
    }
}
