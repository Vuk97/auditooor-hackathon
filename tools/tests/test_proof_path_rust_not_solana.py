#!/usr/bin/env python3
"""Guard: a .rs source ref must NOT be mislabeled solana-program-test.

Rust != Solana. op-reth / monero-oxide / near / substrate / hyperbridge are Rust
but not Solana; the exploit-queue proof-route inference defaulted every .rs to
solana-program-test, mislabeling every non-Solana Rust lead's PoC route.
"""
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD = os.path.join(_HERE, "..", "exploit-queue.py")
spec = importlib.util.spec_from_file_location("exploit_queue", _MOD)
m = importlib.util.module_from_spec(spec)
_argv = sys.argv
sys.argv = ["exploit-queue.py"]
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass
finally:
    sys.argv = _argv

f = m._derive_proof_path_from_refs_and_class


def test_non_solana_rust_is_cargo_test():
    assert f(["src/rust/op-reth/crates/payload/builder.rs:494"], "consensus-divergence") == "rust-cargo-test"
    assert f(["monero-oxide/src/ringct.rs:88"], "double-spend") == "rust-cargo-test"


def test_actual_solana_is_solana_program_test():
    assert f(["programs/x/src/lib.rs:10"], "anchor sealevel cpi") == "solana-program-test"
    assert f(["src/lib.rs:1"], "solana account confusion") == "solana-program-test"


def test_sol_and_go_unchanged():
    assert f(["src/Foo.sol:10"], "reentrancy") == "foundry"
    assert f(["x/keeper/msg_server.go:20"], "cosmos") == "cosmos-production"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print("ok" if not failed else f"{failed} FAILED")
    raise SystemExit(1 if failed else 0)
