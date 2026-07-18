#!/usr/bin/env python3
"""go-dataflow go1.25 TypeParam-panic recovery (surfaced by axelar-core).

Root cause: on go1.25.0 sources (generics-heavy cosmos-sdk / axelar-core keeper
packages), a MakeInterface operand whose type still contains a *types.TypeParam
gets registered into ssa.Program.makeInterfaceTypes. Program.RuntimeTypes() then
iterates that set through x/tools' internal typesinternal.ForEachElement, which
PANICS ("ForEachElement called on type containing *types.TypeParam"). Both
ssautil.AllFunctions and cha.CallGraph route through RuntimeTypes(), so the panic
previously unwound the ENTIRE go-dataflow analysis into a single degrade-0 record
- starving every dataflow-dependent lens (hunt / guard-reachability / chain-synth
/ SCC / coupled-state), and silently downgrading dataflow-substrate-health for the
'go' arm to STARVED.

The fix (allFunctionsSafe / chaCallGraphSafe / runtimeTypesSafe in
tools/go-dataflow/main.go) recover-guards the RuntimeTypes() step and degrades it
to a REPORTED partial (a stderr WARN) instead of a silent starve, so the IR-backed
function set + call graph are still produced and real semantic-ssa paths emit.

BEFORE the fix (verified manually on ./x/nexus/keeper): 1 record, degraded=True,
degrade_reason="panic during analysis: ForEachElement called on type containing
*types.TypeParam", 0 real paths.
AFTER the fix:                       1997 records, degraded=0, all semantic-ssa,
plus a single stderr WARN line documenting the reflection-reachability degrade.

This module has two tiers:

  1. A fast, offline-safe unit assertion that the go-dataflow binary NEVER emits a
     whole-arm ForEachElement degrade on a plain (non-generic) fixture module - it
     must produce a real JSON array (regression guard for the recover wrapper not
     accidentally swallowing everything).

  2. An OPT-IN integration test (AUDITOOOR_RUN_SLOW_INTEG=1) against a real
     go1.25 generics-heavy module (default: the axelar-core nexus keeper, override
     via AUDITOOOR_GO_TYPEPARAM_TARGET=<module_root>::<pkg-pattern>) that asserts
     the panic is RECOVERED (stderr WARN) AND real semantic-ssa records are still
     emitted (never a ForEachElement degrade). This is the test that exercises the
     actual failing shape end to end.

Both tiers SKIP cleanly when `go` is unavailable so the suite stays green offline.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GO_SRC = REPO / "tools" / "go-dataflow"
BIN = GO_SRC / ".bin" / "go-dataflow"

_FOREACH = "ForEachElement called on type containing"


def _have_go():
    return shutil.which("go") is not None


def _ensure_binary():
    """Build the standalone go-dataflow binary offline (as the wrapper does)."""
    if BIN.is_file():
        return True
    if not _have_go():
        return False
    BIN.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod")
    p = subprocess.run(
        [shutil.which("go"), "build", "-o", str(BIN), "."],
        cwd=str(GO_SRC), env=env, capture_output=True, text=True, timeout=600,
    )
    return p.returncode == 0 and BIN.is_file()


def _run_bin(cwd, pattern, timeout, extra_env=None):
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    p = subprocess.run(
        [str(BIN), pattern], cwd=str(cwd), env=env,
        capture_output=True, text=True, timeout=timeout,
    )
    recs = []
    out = p.stdout.strip()
    if out:
        try:
            recs = json.loads(out)
        except json.JSONDecodeError:
            recs = json.loads(out.splitlines()[-1])
    return p.returncode, recs, p.stderr


# ----------------------------------------------------- tier 1: fast guard -----

def test_plain_module_is_not_a_whole_arm_degrade(tmp_path):
    """A plain (non-generic) module must yield a real JSON array, NOT a single
    ForEachElement whole-arm degrade. Guards that the recover wrapper degrades
    only the reflection-reachability step, never the whole analysis."""
    if not _ensure_binary():
        pytest.skip("go toolchain unavailable or build failed")
    mod = tmp_path / "m"
    (mod / "g").mkdir(parents=True)
    (mod / "go.mod").write_text("module plain.fixture/m\n\ngo 1.25.0\n")
    (mod / "g" / "g.go").write_text(
        "package g\n"
        "type Store struct{ m map[string]string }\n"
        "func (s *Store) Set(k, v string) { s.m[k] = v }\n"
        "func Handler(s *Store, in string) { s.Set(\"k\", in) }\n"
    )
    rc, recs, stderr = _run_bin(mod, "./g", timeout=180)
    assert rc == 0, stderr
    assert isinstance(recs, list) and len(recs) >= 1, recs
    # never a whole-arm ForEachElement degrade
    for r in recs:
        assert _FOREACH not in (r.get("degrade_reason") or ""), r
    # a plain param->Set flow must be an IR-backed path
    assert any(r.get("confidence") == "semantic-ssa" and not r.get("degraded")
               for r in recs), recs


# ----------------------------------------------------- tier 2: real shape -----

def _resolve_target():
    """(module_root, pkg_pattern) for the real go1.25 generics-heavy target."""
    override = os.environ.get("AUDITOOOR_GO_TYPEPARAM_TARGET")
    if override and "::" in override:
        root, pat = override.split("::", 1)
        return Path(root), pat
    default_root = Path("/Users/wolf/audits/axelar-dlt/src/axelar-core")
    return default_root, "./x/nexus/keeper"


@pytest.mark.skipif(
    os.environ.get("AUDITOOOR_RUN_SLOW_INTEG") != "1",
    reason="slow real-module integration; set AUDITOOOR_RUN_SLOW_INTEG=1 to run",
)
def test_real_typeparam_shape_is_recovered_not_starved():
    """On a real go1.25 generics-heavy module the ForEachElement panic must be
    RECOVERED (loud stderr WARN) and real semantic-ssa records still emitted -
    never a whole-arm ForEachElement degrade, never zero paths."""
    if not _ensure_binary():
        pytest.skip("go toolchain unavailable or build failed")
    root, pat = _resolve_target()
    if not (root / "go.mod").is_file():
        pytest.skip(f"target module not present: {root}")
    # bounded work ceiling so a cosmos-scale keeper completes in the test window;
    # the recover path + non-zero real-path assertion are unaffected by the bound.
    rc, recs, stderr = _run_bin(
        root, pat, timeout=1500,
        extra_env={
            "AUDITOOOR_DATAFLOW_MAX_WORK": os.environ.get("AUDITOOOR_DATAFLOW_MAX_WORK", "40000"),
            "AUDITOOOR_DATAFLOW_MAX_DEPTH": os.environ.get("AUDITOOOR_DATAFLOW_MAX_DEPTH", "6"),
        },
    )
    assert rc == 0, stderr
    assert isinstance(recs, list), recs
    # the panic must have been recovered LOUDLY (reported partial, not silent)
    assert _FOREACH in stderr, (
        "expected the RuntimeTypes() ForEachElement panic to be recovered with a "
        "stderr WARN on this target; got stderr:\n" + stderr)
    # ...and it must NOT have degraded the whole arm
    assert not any(_FOREACH in (r.get("degrade_reason") or "") for r in recs), \
        "whole-arm ForEachElement degrade leaked through the recover wrapper"
    real = [r for r in recs if r.get("confidence") == "semantic-ssa"
            and not r.get("degraded")]
    assert len(real) > 0, (
        f"expected >=1 real semantic-ssa path after recovery, got {len(recs)} "
        f"records ({len(real)} real). stderr:\n{stderr}")
