#!/usr/bin/env python3
"""B-hops: UNBOUNDED-depth slice + recursive-cycle termination (Solidity arm).

Proves the depth cap was removed and replaced by a visited-(fn,var) terminator:

  - deep_chain_10hop.sol: a 10-hop tainted chain (>old MAX_HOPS_DEFAULT=6) yields a
    COMPLETE slice (call_depth == 10), with a real "param-entrypoint" source (NOT a
    "param-depth-bound" truncation source) and NO dataflow_truncated flag.

  - recursive_cycle_chain.sol: a mutually-recursive ping<->pong on the path
    TERMINATES (the test would hang/OOM if the visited-set guard were missing) and
    still recovers a source.

SKIP cleanly if slither/solc are unavailable.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "dataflow-slice.py"
FIX = REPO / "tests" / "fixtures" / "dataflow"


def _slither_ok():
    try:
        import slither  # noqa: F401
    except Exception:
        return False
    return shutil.which("solc-select") is not None or shutil.which("solc") is not None


pytestmark = pytest.mark.skipif(not _slither_ok(), reason="needs slither + solc")


def _run(fixture, extra=None, timeout=200):
    sol = FIX / fixture
    assert sol.exists(), f"fixture missing: {sol}"
    ws = Path(tempfile.mkdtemp(prefix=f"dfhop_{fixture}_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    p = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws), "--target", str(sol), "--json"]
        + (extra or []), capture_output=True, text=True, timeout=timeout)
    assert p.returncode == 0, f"rc={p.returncode}\n{p.stderr}\n{p.stdout}"
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    return recs, json.loads(p.stdout)


def test_deep_10hop_chain_complete_not_truncated():
    recs, summary = _run("deep_chain_10hop.sol")
    # the amount->transferFrom value slice
    cands = [r for r in recs
             if r["sink"]["callee"] == "transferFrom"
             and r["source"]["var"] == "amount"]
    assert cands, f"no amount->transferFrom slice: {[(r['source'],r['sink']) for r in recs]}"
    deep = max(cands, key=lambda r: r["call_depth"])
    # COMPLETE: 10 inter-procedural hops recovered (old cap of 6 would truncate)
    assert deep["call_depth"] == 10, f"expected call_depth==10, got {deep['call_depth']}"
    # real source reached, NOT a depth-bound truncation source
    assert deep["source"]["kind"] == "param-entrypoint", deep["source"]
    assert not deep.get("dataflow_truncated"), "10 hops must not hit the HIGH ceiling"
    assert summary.get("dataflow_truncated_paths", 0) == 0


def test_recursive_cycle_terminates():
    # If the visited-set terminator were missing, this would hang until the test
    # timeout (or OOM). Reaching the assertions at all is the termination proof.
    recs, summary = _run("recursive_cycle_chain.sol", timeout=120)
    assert summary["status"] == "ok"
    # a source is still recovered through the cycle to the sink
    cands = [r for r in recs if r["sink"]["callee"] == "transferFrom"]
    assert cands, "expected a slice through the recursive cycle to transferFrom"


def test_low_explicit_max_hops_flags_truncation():
    # Pinning a SMALL --max-hops on the 10-hop chain must produce a depth-bound
    # source + the honesty flag (proving the flag is wired, not dead).
    recs, summary = _run("deep_chain_10hop.sol", extra=["--max-hops", "3"])
    # With a cap of 3 the walk stops mid-chain: the source is a mid-chain param
    # (e.g. a4), kind=="param-depth-bound", and the chain is flagged truncated.
    cands = [r for r in recs if r["sink"]["callee"] == "transferFrom"]
    assert cands, f"no transferFrom slice at cap=3: {recs}"
    bound = [r for r in cands if r["source"]["kind"] == "param-depth-bound"]
    assert bound, f"expected a param-depth-bound source at cap=3, got {[r['source'] for r in cands]}"
    assert all(r.get("dataflow_truncated") is True for r in bound)
    assert summary.get("dataflow_truncated_paths", 0) >= 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
