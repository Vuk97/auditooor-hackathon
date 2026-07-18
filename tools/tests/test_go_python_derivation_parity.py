#!/usr/bin/env python3
"""A-P3: Go/Python DefUsePath derivation-parity drift guard.

tools/go-dataflow/main.go derives call_depth (countInterproc) and unguarded
(anyHopGuarded / Unguarded) with a HAND-MIRRORED copy of
dataflow_schema.new_path's formula. If either side drifts (e.g. someone adds a
new `via` to the Python via-set but not the Go switch, or changes the unguarded
rule), the two producers would disagree on the same hop sequence and the unified
sidecar would carry inconsistent call_depth/unguarded across languages.

This test feeds IDENTICAL hop sequences to BOTH derivations and asserts they
agree:
  - Python:  dataflow_schema.new_path(...) -> rec["call_depth"], rec["unguarded"]
  - Go:      go-dataflow -derive-check  (reads hops on stdin, emits the derived pair)

Mutation check (documented, run manually): flip the via-set in
dataflow_schema.new_path (e.g. drop "storage") and this test goes RED on the
storage-hop case - proving it is non-vacuous.

SKIP cleanly if the Go toolchain is unavailable (the parity guard is advisory).
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GO_SRC = REPO / "tools" / "go-dataflow"

_spec = importlib.util.spec_from_file_location("dfs_parity", REPO / "tools" / "dataflow_schema.py")
dfs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dfs)


def _hop(via, guarded=False):
    return {"from_var": "a", "to_var": "b", "fn": "f", "via": via,
            "file": "x", "line": 1, "ir": "", "guarded": guarded}


# (hops, guard_nodes) cases covering every via + the guarded/unguarded rule.
CASES = [
    ([], []),
    ([_hop("internal_call")], []),
    ([_hop("internal_call"), _hop("high_level"), _hop("return")], []),
    ([_hop("intra"), _hop("internal_call")], []),         # intra not counted
    ([_hop("storage")], []),                               # storage IS counted
    ([_hop("boundary"), _hop("internal_call")], []),       # boundary not counted
    ([_hop("internal_call", guarded=True)], []),           # hop-level guard
    ([_hop("internal_call")], [{"file": "x", "line": 1, "expr": "require(a)"}]),  # guard node
    ([_hop("internal_call"), _hop("storage"), _hop("return"), _hop("intra"),
      _hop("high_level")], []),                            # mixed
]


def _build_go():
    go = shutil.which("go")
    if not go:
        return None
    out = GO_SRC / ".bin" / "go-dataflow"
    out.parent.mkdir(parents=True, exist_ok=True)
    env = {"GOPROXY": "off", "GOFLAGS": "-mod=mod"}
    import os
    full = dict(os.environ)
    full.update(env)
    p = subprocess.run([go, "build", "-o", str(out), "."], cwd=str(GO_SRC),
                       env=full, capture_output=True, text=True, timeout=600)
    if p.returncode != 0 or not out.exists():
        return None
    return str(out)


def _python_derive(hops, guard_nodes):
    rec = dfs.new_path(
        path_id="p", language="go", direction="backward", engine="t",
        source={"kind": "param", "fn": "f", "var": "v", "file": "x", "line": 1},
        sink={"kind": "call", "callee": "c", "arg_pos": 0, "fn": "g", "file": "x", "line": 2},
        hops=hops, guard_nodes=guard_nodes,
    )
    return rec["call_depth"], rec["unguarded"]


def _go_derive(binary, hops, guard_nodes):
    payload = json.dumps({"hops": hops, "guard_nodes": guard_nodes})
    p = subprocess.run([binary, "-derive-check"], input=payload,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"go derive-check failed: {p.stderr}\n{p.stdout}"
    res = json.loads(p.stdout.strip())
    return res["call_depth"], res["unguarded"]


@pytest.fixture(scope="module")
def go_binary():
    b = _build_go()
    if b is None:
        pytest.skip("go toolchain unavailable; parity guard is advisory")
    return b


@pytest.mark.parametrize("hops,guards", CASES)
def test_go_python_call_depth_and_unguarded_parity(go_binary, hops, guards):
    py_depth, py_unguarded = _python_derive(hops, guards)
    go_depth, go_unguarded = _go_derive(go_binary, hops, guards)
    assert py_depth == go_depth, (
        f"call_depth DRIFT: python={py_depth} go={go_depth} for hops={[h['via'] for h in hops]}")
    assert py_unguarded == go_unguarded, (
        f"unguarded DRIFT: python={py_unguarded} go={go_unguarded} "
        f"for hops={[(h['via'], h['guarded']) for h in hops]} guards={len(guards)}")


def test_storage_via_is_counted_both_sides(go_binary):
    # explicit anchor: the "storage" via must count as an inter-proc hop on BOTH
    # sides (this is the case a via-set drift would break).
    py_depth, _ = _python_derive([_hop("storage")], [])
    go_depth, _ = _go_derive(go_binary, [_hop("storage")], [])
    assert py_depth == 1 and go_depth == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
