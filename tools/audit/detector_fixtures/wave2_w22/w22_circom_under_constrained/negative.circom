// Fixture: properly constrained Circom inverse circuit. `inv` is
// constrained to be `in`'s modular inverse via a multiplicative
// equality, and `out` is constrained via `<==` (which both assigns
// and constrains). Structurally similar to positive.circom but should
// NOT fire the w22_circom_under_constrained detector.
pragma circom 2.1.6;

template SafeInverse() {
    signal input in;
    signal output out;
    signal inv;

    // Witness assignment <-- is fine here because the constraint
    // below pins the value.
    inv <-- (in != 0) ? 1 / in : 0;

    // Constraint: in * inv === 1 when in != 0; this is the canonical
    // pattern used by circomlib's IsZero/Inverse template.
    in * inv === 1;

    // <== both assigns AND constrains, so `out` is pinned.
    out <== inv;
}

component main = SafeInverse();
