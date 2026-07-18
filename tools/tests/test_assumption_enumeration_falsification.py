#!/usr/bin/env python3
"""Tests for assumption-enumeration-falsification.py.

Non-vacuity discipline (mvc-style): a guard-neutralization MUTANT must flip an
ENFORCED assumption to FALSIFIABLE. If removing the authority guard does NOT
change the verdict, the enforcement check is vacuous and the test fails.
"""
import importlib.util
import json
import pathlib
import sys

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "assumption-enumeration-falsification.py"
_spec = importlib.util.spec_from_file_location("aef", _TOOL)
aef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aef)


def _write_ws(tmp_path, value_movers, guard_rows, dataflow_rows):
    ad = tmp_path / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    (ad / "value_moving_functions.json").write_text(json.dumps(
        {"functions": value_movers}))
    (ad / "guard_completeness.jsonl").write_text(
        "\n".join(json.dumps(r) for r in guard_rows))
    (ad / "dataflow_paths.jsonl").write_text(
        "\n".join(json.dumps(r) for r in dataflow_rows))
    return tmp_path


def _find(rep, unit, axis):
    for u in rep["units"]:
        if u["unit"].endswith(unit):
            for o in u["assumptions"]:
                if o["assumption"] == axis:
                    return o
    return None


def _guarded_df(fn, file, expr):
    return {"source": {"fn": fn, "file": file, "line": 10, "kind": "param-entrypoint"},
            "sink": {"kind": "transfer"},
            "hops": [], "guard_nodes": [{"file": file, "line": 12, "expr": expr}]}


def _unguarded_df(fn, file):
    return {"source": {"fn": fn, "file": file, "line": 10, "kind": "param-entrypoint"},
            "sink": {"kind": "transfer"},
            "hops": [], "guard_nodes": []}


VM_MOVER = lambda fn, file: {"file": file, "function": fn, "transfer_hit": True,
                             "ledger_write_hit": True, "authz_write_hit": True,
                             "guarded_callee_hit": False}


def test_unguarded_mover_is_falsifiable(tmp_path):
    f = "Vault.sol"
    ws = _write_ws(tmp_path,
                   [VM_MOVER("withdraw", f)],
                   [{"file": f, "function": "withdraw", "guarded": False, "guard_evidence": ""}],
                   [_unguarded_df("Vault.withdraw(uint256)", f)])
    rep = aef.run(ws)
    ct = _find(rep, "vault.sol::withdraw", "caller-trusted")
    assert ct is not None, "caller-trusted assumption must be enumerated for a mutator"
    assert ct["falsifiable"] is True and ct["enforced"] is False
    vb = _find(rep, "vault.sol::withdraw", "value-bounded")
    assert vb is not None and vb["falsifiable"] is True


def test_guarded_mover_is_enforced(tmp_path):
    f = "Vault.sol"
    ws = _write_ws(tmp_path,
                   [VM_MOVER("withdraw", f)],
                   [{"file": f, "function": "withdraw", "guarded": True,
                     "guard_evidence": "onlyOwner"}],
                   [_guarded_df("Vault.withdraw(uint256)", f, "msg.sender == owner")])
    rep = aef.run(ws)
    ct = _find(rep, "vault.sol::withdraw", "caller-trusted")
    assert ct is not None and ct["enforced"] is True and ct["falsifiable"] is False


def test_mutation_flips_enforced_to_falsifiable(tmp_path):
    """NON-VACUITY: neutralize the authority guard node; the SAME unit must flip
    caller-trusted from enforced->falsifiable. A no-flip would mean the
    enforcement check ignores the guard (vacuous)."""
    f = "Vault.sol"
    fn = "Vault.withdraw(uint256)"
    base = _write_ws(tmp_path / "base",
                     [VM_MOVER("withdraw", f)],
                     [{"file": f, "function": "withdraw", "guarded": True,
                       "guard_evidence": "onlyOwner"}],
                     [_guarded_df(fn, f, "msg.sender == owner")])
    mut = _write_ws(tmp_path / "mut",
                    [VM_MOVER("withdraw", f)],
                    # guard neutralized: authority evidence removed on BOTH readers
                    [{"file": f, "function": "withdraw", "guarded": False, "guard_evidence": ""}],
                    [_guarded_df(fn, f, "amount > 0")])  # non-authority guard remains
    ct_base = _find(aef.run(base), "vault.sol::withdraw", "caller-trusted")
    ct_mut = _find(aef.run(mut), "vault.sol::withdraw", "caller-trusted")
    assert ct_base["enforced"] is True, "baseline authority guard must be seen as enforced"
    assert ct_mut["falsifiable"] is True and ct_mut["enforced"] is False, \
        "mutant with guard removed must flip to falsifiable (non-vacuity)"


def test_init_once_axis(tmp_path):
    f = "M.sol"
    ws = _write_ws(tmp_path,
                   [{"file": f, "function": "initialize", "ledger_write_hit": True}],
                   [{"file": f, "function": "initialize", "guarded": False, "guard_evidence": ""}],
                   [])
    io = _find(aef.run(ws), "m.sol::initialize", "init-once")
    assert io is not None and io["enforced"] is False


def test_no_corpus_dependency(tmp_path):
    """Guard-rail: the tool derives from code, never a corpus class list. It must
    produce obligations with ZERO corpus artifacts present."""
    f = "X.sol"
    ws = _write_ws(tmp_path, [VM_MOVER("pull", f)],
                   [{"file": f, "function": "pull", "guarded": False, "guard_evidence": ""}],
                   [_unguarded_df("X.pull(uint256)", f)])
    rep = aef.run(ws)
    assert rep["total_obligations"] > 0
    # no attack-class / taxonomy key anywhere in the output
    blob = json.dumps({"units": rep["units"], "by_axis": rep["by_axis"]})
    assert "attack_class" not in blob and "taxonomy" not in blob


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
