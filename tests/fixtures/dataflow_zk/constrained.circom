pragma circom 2.0.0;

// CONSTRAINED variant - the mutation-pair sibling of under_constrained.circom.
//
// IDENTICAL data flow (`out` derives from `in + 1`) but here `out` IS bound by a
// CONSTRAINT. The `<==` operator both assigns the witness AND emits the R1CS
// constraint `out === in + 1`, so a prover cannot forge `out`. The extra explicit
// `=== ` line is redundant-but-harmless and makes the constraint edge unambiguous
// for the parser.
//
// Discriminator: `out` has a signal-constrain path -> tools/zk-dataflow.py must
// NOT flag it as an unguarded signal DefUsePath (unguarded:false / no flag row).
template Constrained() {
    signal input in;
    signal output out;

    // constraint assignment: binds the witness AND emits an R1CS constraint.
    out <== in + 1;
    // explicit constraint, redundant with the line above (defensive).
    out === in + 1;
}

component main = Constrained();
