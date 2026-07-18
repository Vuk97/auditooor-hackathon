// Fixture: classic zkbugs under-constrained Circom circuit. The
// witness assigns `out` to `in * inv` but does not constrain `inv` to
// be the modular inverse of `in`, so a malicious prover can pick any
// `out` value. Mirrors the audit-pin shape in many zkbugs records
// (rootcause-assigned-but-unconstrained, dsl-circom, vuln-under-constrained).
//
// Detector w22_circom_under_constrained should fire on this file.
pragma circom 2.1.6;

template UnsafeInverse() {
    signal input in;
    signal output out;
    signal inv;

    // Witness assignment: <-- (no constraint introduced).
    inv <-- (in != 0) ? 1 / in : 0;

    // Constraint: out === in * inv;
    // POSITIVE: the assignment uses <-- (witness only) and there is NO
    // === / <== constraint pinning `inv` to in's modular inverse.
    // A malicious prover can set `inv` to any field element and produce
    // an `out` that does not equal 1 when in != 0.
    out <-- in * inv;
}

component main = UnsafeInverse();
