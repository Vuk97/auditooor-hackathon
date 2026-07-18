pragma circom 2.0.0;

// UNDER-CONSTRAINED variant (the canonical ZK bug).
//
// The output signal `out` is ASSIGNED with the witness-only operator `<--`
// (which sets the witness value at proving time) but is NEVER reached by a
// CONSTRAINT operator (`<==` or `===`). The R1CS therefore imposes no algebraic
// relation on `out`: a malicious prover can put ANY field element in `out` and
// still produce a valid proof. This is the classic "assigned-but-not-constrained
// output signal" under-constraint (circomspect CS0013 / CA01 family).
//
// Discriminator: `out` has a signal-assign edge (`<--`) and NO signal-constrain
// path -> tools/zk-dataflow.py must emit an UNGUARDED signal DefUsePath for it.
template UnderConstrained() {
    signal input in;
    signal output out;

    // witness assignment only - no constraint binds `out` to `in`.
    out <-- in + 1;
}

component main = UnderConstrained();
