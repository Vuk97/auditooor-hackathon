// Fixture: MUTANT - the enable_spends constraint tuple dropped. enable_spends
// is queried but referenced in NO returned Constraints expr -> must fire.
fn configure(meta: &mut ConstraintSystem) {
    meta.create_gate("Orchard circuit checks", |meta| {
        let q_orchard = meta.query_selector(q_orchard);
        let v_old = meta.query_advice(advices[0], Rotation::cur());
        let v_new = meta.query_advice(advices[1], Rotation::cur());
        let magnitude = meta.query_advice(advices[2], Rotation::cur());
        let sign = meta.query_advice(advices[3], Rotation::cur());
        let root = meta.query_advice(advices[4], Rotation::cur());
        let anchor = meta.query_advice(advices[5], Rotation::cur());
        let enable_spends = meta.query_advice(advices[6], Rotation::cur());
        let enable_outputs = meta.query_advice(advices[7], Rotation::cur());
        let one = Expression::Constant(pallas::Base::one());
        Constraints::with_selector(
            q_orchard,
            [
                ("v_old - v_new = magnitude * sign",
                 v_old.clone() - v_new.clone() - magnitude * sign),
                ("Either v_old = 0, or root = anchor",
                 v_old.clone() * (root - anchor)),
                ("v_new = 0 or enable_outputs = 1",
                 v_new * (one - enable_outputs)),
            ],
        )
    });
}
