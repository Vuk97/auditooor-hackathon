// Positive fixture 2: send present but no receive — orphaned lookup send.
use p3_air::{Air, AirBuilder};

const XOR_TABLE: u8 = 1;

pub struct XorCpuAir;

impl<AB: AirBuilder> Air<AB> for XorCpuAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        // Sends to XOR_TABLE but the table chip (receive side) is missing.
        builder.send(XOR_TABLE, &[local.lhs, local.rhs, local.output], local.is_xor);
    }
}
// No builder.receive for XOR_TABLE anywhere in this file.
