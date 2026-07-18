#!/usr/bin/env python3
"""Regression tests for move_block_callback_unbounded_iteration - the Move (Aptos/Sui)
chain-halt detector. Positive: a block/epoch callback (or public entry) loops over a
vector/Table grown by a PERMISSIONLESS public entry push with no cap. Negative: the same
shape but the loop is capped / the grow is admin-gated / the grow is size-capped -> clean."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "detectors" / "move_block_callback_unbounded_iteration.py"
_spec = importlib.util.spec_from_file_location("mbcui", _TOOL)
mbcui = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mbcui)


def _pkg(files: dict[str, str]) -> str:
    d = Path(tempfile.mkdtemp(prefix="mbcui_"))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(d)


# ---------------------------------------------------------------------------
# POSITIVE: block_prologue -> distribute_all iterates an uncapped vector that a
# permissionless `public entry fun register` grows via push_back with no cap.
# ---------------------------------------------------------------------------
POS_HOOK = """module app::rewards {
    use std::vector;
    struct State has key { validators: vector<address> }

    // system block callback (Aptos) - runs every block, gas-unmetered.
    public fun block_prologue(vm: &signer, _proposer: address) acquires State {
        distribute_all(vm);
    }

    fun distribute_all(_vm: &signer) acquires State {
        let s = borrow_global<State>(@app);
        // UNBOUNDED: no cap; length grows with permissionless registrations.
        vector::for_each_ref(&s.validators, |v| {
            let _addr = *v;
        });
    }
}
"""
POS_GROW = """module app::registry {
    use std::vector;
    use app::rewards;
    struct State has key { validators: vector<address> }

    // PERMISSIONLESS: anyone can call, no auth gate, no size cap.
    public entry fun register(user: &signer) acquires State {
        let s = borrow_global_mut<State>(@app);
        vector::push_back(&mut s.validators, signer::address_of(user));
    }
}
"""

# ---------------------------------------------------------------------------
# NEGATIVE 1: SAME hook loop but it IS capped (i >= MAX_BATCH break).
# ---------------------------------------------------------------------------
NEG_CAPPED_LOOP = """module app::rewards {
    use std::vector;
    const MAX_BATCH: u64 = 100;
    struct State has key { validators: vector<address> }

    public fun block_prologue(vm: &signer, _proposer: address) acquires State {
        distribute_all(vm);
    }

    fun distribute_all(_vm: &signer) acquires State {
        let s = borrow_global<State>(@app);
        let i = 0;
        let n = vector::length(&s.validators);
        while (i < n) {
            if (i >= MAX_BATCH) { break };
            i = i + 1;
        };
    }
}
"""
# grow is still permissionless, but the loop is bounded -> no halt.
NEG_GROW_OK = POS_GROW.replace("module app::registry", "module app::registry")

# ---------------------------------------------------------------------------
# NEGATIVE 2: uncapped loop, but the grow is ADMIN-GATED (not permissionless).
# ---------------------------------------------------------------------------
NEG_GATED_GROW = """module app::registry {
    use std::vector;
    struct State has key { validators: vector<address> }

    public entry fun register(admin: &signer, who: address) acquires State {
        assert!(signer::address_of(admin) == @app, 1);
        let s = borrow_global_mut<State>(@app);
        vector::push_back(&mut s.validators, who);
    }
}
"""

# ---------------------------------------------------------------------------
# NEGATIVE 3: uncapped loop, permissionless grow but SIZE-CAPPED.
# ---------------------------------------------------------------------------
NEG_SIZE_CAPPED_GROW = """module app::registry {
    use std::vector;
    const MAX_VALIDATORS: u64 = 128;
    struct State has key { validators: vector<address> }

    public entry fun register(user: &signer) acquires State {
        let s = borrow_global_mut<State>(@app);
        assert!(vector::length(&s.validators) < MAX_VALIDATORS, 2);
        vector::push_back(&mut s.validators, signer::address_of(user));
    }
}
"""

# ---------------------------------------------------------------------------
# NEGATIVE 4: uncapped loop grown permissionlessly, but NOT reachable from any
# block callback nor a public entry - a private view helper only.
# ---------------------------------------------------------------------------
NEG_NO_HOOK = """module app::rewards {
    use std::vector;
    struct State has key { validators: vector<address> }

    // private, not entry, not a callback - never on the per-block hot path.
    fun peek_all() acquires State {
        let s = borrow_global<State>(@app);
        vector::for_each_ref(&s.validators, |v| { let _a = *v; });
    }
}
"""


class MoveBlockCallbackUnboundedTest(unittest.TestCase):
    def test_fires_on_uncapped_hook_loop_over_permissionless_growable(self):
        root = _pkg({"sources/rewards.move": POS_HOOK, "sources/registry.move": POS_GROW})
        rep = mbcui.scan_root(root)
        fns = {f["function"] for f in rep["findings"]}
        self.assertIn("distribute_all", fns,
                      "must flag the uncapped block_prologue-reachable for_each over a "
                      "permissionlessly-growable vector")
        f = [x for x in rep["findings"] if x["function"] == "distribute_all"][0]
        self.assertEqual(f["severity_hint"], "high")
        self.assertEqual(f["reached_from_hook"], "block_prologue")
        self.assertEqual(f["impact"], "chain-halt")
        self.assertEqual(f["grow_fn"], "register")

    def test_schema_shape_complete(self):
        root = _pkg({"sources/rewards.move": POS_HOOK, "sources/registry.move": POS_GROW})
        rep = mbcui.scan_root(root)
        self.assertGreaterEqual(rep["finding_count"], 1)
        req = {"schema", "mechanism", "impact", "severity_hint", "file", "line",
               "function", "reason", "source_record_id"}
        for f in rep["findings"]:
            self.assertTrue(req.issubset(f.keys()), f"missing keys: {req - f.keys()}")
        self.assertEqual(rep["mechanism"], "consensus-hook-unbounded-iteration")

    def test_capped_loop_is_clean(self):
        root = _pkg({"sources/rewards.move": NEG_CAPPED_LOOP,
                     "sources/registry.move": NEG_GROW_OK})
        rep = mbcui.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "in-scope MAX_BATCH cap must suppress the finding")

    def test_admin_gated_grow_is_clean(self):
        root = _pkg({"sources/rewards.move": POS_HOOK,
                     "sources/registry.move": NEG_GATED_GROW})
        rep = mbcui.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "admin-gated grow is not attacker-growable -> no halt vector")

    def test_size_capped_grow_is_clean(self):
        root = _pkg({"sources/rewards.move": POS_HOOK,
                     "sources/registry.move": NEG_SIZE_CAPPED_GROW})
        rep = mbcui.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "size-capped grow bounds the collection -> no halt vector")

    def test_non_hot_path_loop_is_clean(self):
        root = _pkg({"sources/rewards.move": NEG_NO_HOOK,
                     "sources/registry.move": POS_GROW})
        rep = mbcui.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "a private non-entry helper is not on the per-block hot path")

    def test_single_file_scan_and_cli(self):
        # sanity: scan_root accepts a single file too (grow+hook in one module).
        one = POS_HOOK.replace("}\n", "", 0)  # keep as-is; combine grow into same file
        combined = """module app::all {
    use std::vector;
    struct State has key { validators: vector<address> }
    public fun block_prologue(vm: &signer) acquires State { distribute_all(vm); }
    fun distribute_all(_vm: &signer) acquires State {
        let s = borrow_global<State>(@app);
        vector::for_each_ref(&s.validators, |v| { let _a = *v; });
    }
    public entry fun register(user: &signer) acquires State {
        let s = borrow_global_mut<State>(@app);
        vector::push_back(&mut s.validators, signer::address_of(user));
    }
}
"""
        d = _pkg({"sources/all.move": combined})
        rep = mbcui.scan_root(d)
        self.assertGreaterEqual(rep["finding_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
