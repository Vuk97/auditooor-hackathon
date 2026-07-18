"""Regression tests for tools/go-mustsucceed-panic-reachability.py.

Proves the Go consensus-halt reasoning query over the owned go-dataflow backend:
  1. an attacker-tainted panic node reachable (transitively, N hops) from a
     MUST-SUCCEED ABCI/lifecycle root is a SURVIVOR and IS emitted;
  2. an identically-shaped panic node whose only reaching entrypoint is a
     recover-wrapped Msg handler (NOT a must-succeed root) is KEPT (not emitted) -
     the recover-wrap distinction a body-scoped regex cannot make;
  3. NON-VACUITY MUTATION: renaming the root from `EndBlocker` to a plain method
     (`Process`) - so no must-succeed root reaches the node - FLIPS the same panic
     node from survivor to kept. The reachability filter is load-bearing, not a
     tautology that always emits;
  4. a panic node whose every tainted record carries a dominating guard
     (unguarded==False) is removed (guarded-operand credit);
  5. a fully-starved substrate (only degraded records) emits nothing + warns, and
     --fail-closed exits 3;
  6. vendored / out-of-workspace panic nodes never carry an obligation.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "go-mustsucceed-panic-reachability.py"
_spec = importlib.util.spec_from_file_location("ms_panic", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _panic_rec(root_fn, node_fn, node_file, *, op="type-assert", var="m",
               line=10, hops=None, unguarded=True):
    """A backward dataflow_path.v1 panic record: a param at `root_fn` reaches a
    kind=panic node in `node_fn` (`node_file`:`line`)."""
    return {
        "schema": "dataflow_path.v1", "language": "go", "direction": "backward",
        "degraded": False,
        "source": {"kind": "param", "fn": root_fn, "var": var},
        "sink": {"kind": "panic", "panic_op": op, "fn": node_fn,
                 "file": node_file, "line": line},
        "hops": [{"fn": h} for h in (hops or [])],
        "unguarded": unguarded,
    }


def _write(ws: Path, recs):
    ad = ws / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    src = ws / "x" / "nexus" / "keeper"
    src.mkdir(parents=True, exist_ok=True)
    (src / "abci.go").write_text("package keeper\n", encoding="utf-8")
    with (ad / "dataflow_paths.jsonl").open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    return ad / "mustsucceed_panic_obligations.jsonl"


def _run(ws: Path):
    return mod.run(["--workspace", str(ws), "--json"])


def _abci_file(ws: Path) -> str:
    return str(ws / "x" / "nexus" / "keeper" / "abci.go")


def test_survivor_from_mustsucceed_root(tmp_path):
    f = _abci_file(tmp_path)
    # EndBlocker (must-succeed) -> helper (2 hops) with an attacker-tainted assert.
    emit = _write(tmp_path, [
        _panic_rec("pkg.EndBlocker", "pkg.helper", f, hops=["pkg.mid", "pkg.helper"]),
    ])
    summ = _run(tmp_path)
    assert summ["n_mustsucceed_roots"] >= 1
    assert summ["n_reachable_survivors"] == 1
    obs = [json.loads(l) for l in emit.read_text().splitlines() if l.strip() and "examined_record" not in l]
    assert len(obs) == 1
    assert obs[0]["obligation_type"] == "mustsucceed-panic-reachability"
    assert obs[0]["panic_op"] == "type-assert"
    assert obs[0]["function"] == "helper"


def test_recoverwrapped_msg_handler_kept(tmp_path):
    f = _abci_file(tmp_path)
    # A Msg handler (recover-wrapped; NOT a must-succeed root) reaching the SAME
    # shape must NOT fire.
    emit = _write(tmp_path, [
        _panic_rec("pkg.MsgTransfer", "pkg.MsgTransfer", f, op="index"),
    ])
    summ = _run(tmp_path)
    assert summ["n_reachable_survivors"] == 0
    assert summ["n_kept_unreachable_or_guarded"] == 1
    assert not [l for l in emit.read_text().splitlines() if l.strip() and "examined_record" not in l]


def test_nonvacuity_mutation_root_rename_flips_verdict(tmp_path):
    """MUTATION: identical panic node; only the ROOT name changes from a
    must-succeed `EndBlocker` to a plain `Process`. The survivor must DISAPPEAR -
    proving the must-succeed-reachability filter is load-bearing, not a tautology."""
    f = _abci_file(tmp_path)
    baseline = _write(tmp_path, [
        _panic_rec("pkg.EndBlocker", "pkg.helper", f, hops=["pkg.helper"]),
    ])
    base = _run(tmp_path)
    assert base["n_reachable_survivors"] == 1  # baseline fires

    mutant = _write(tmp_path, [
        _panic_rec("pkg.Process", "pkg.helper", f, hops=["pkg.helper"]),
    ])
    mut = _run(tmp_path)
    assert mut["n_mustsucceed_roots"] == 0
    assert mut["n_reachable_survivors"] == 0  # mutant does NOT fire
    assert not [l for l in mutant.read_text().splitlines() if l.strip() and "examined_record" not in l]


def test_guarded_operand_removed(tmp_path):
    f = _abci_file(tmp_path)
    # Every tainted record for the node carries a dominating guard (unguarded=False).
    emit = _write(tmp_path, [
        _panic_rec("pkg.EndBlocker", "pkg.helper", f, hops=["pkg.helper"],
                   unguarded=False),
    ])
    summ = _run(tmp_path)
    assert summ["n_reachable_survivors"] == 0
    assert not [l for l in emit.read_text().splitlines() if l.strip() and "examined_record" not in l]


def test_starved_substrate_failclosed(tmp_path):
    ad = tmp_path / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    (ad / "dataflow_paths.jsonl").write_text(
        json.dumps({"schema": "dataflow_path.v1", "language": "go",
                    "degraded": True, "source": {"kind": "none"},
                    "sink": {"kind": "none"}}) + "\n", encoding="utf-8")
    summ = mod.run(["--workspace", str(tmp_path), "--json"])
    assert summ["substrate_starved"] is True
    assert summ["n_reachable_survivors"] == 0
    rc = mod.run(["--workspace", str(tmp_path), "--fail-closed"])
    assert rc == 3


def test_vendored_panic_node_excluded(tmp_path):
    # A panic node whose file is in the go module cache is not an in-scope
    # obligation even if a must-succeed root reaches it.
    vend = "/Users/wolf/go/pkg/mod/cosmossdk.io/x/foo/abci.go"
    emit = _write(tmp_path, [
        _panic_rec("pkg.EndBlocker", "pkg.vendorHelper", vend),
    ])
    summ = _run(tmp_path)
    assert summ["n_attacker_tainted_panic_nodes"] == 0
    assert not [l for l in emit.read_text().splitlines() if l.strip() and "examined_record" not in l]
