#!/usr/bin/env python3
"""go-dataflow multi-module support (surfaced by Polygon).

tools/go-dataflow.py only covered ONE go.mod when --target was omitted
(_resolve_module_root picked one root + ./...). A multi-module workspace
(polygon: bor + cometbft + cosmos-sdk + ~20 cosmos sub-modules) therefore got at
most one module's paths or a single whole-arm degrade -> the whole Go surface
uncovered.

These tests prove the additive multi-module fix:

  - MULTI-MODULE: a ws with 2 in-scope go.mod (A clean -> real records,
    B non-compiling -> per-module degrade) returns A's real records + a B-TAGGED
    degrade, arm status=ok (NOT a whole-arm degrade), and module B did NOT wipe
    module A's go rows in the shared sidecar.
  - PER-MODULE DEGRADE isolation: one failing module does not abort the others.
  - SINGLE-MODULE BYTE-IDENTICAL: exactly one in-scope go.mod -> the legacy
    single-module code path runs unchanged (module_root key present, no
    multi_module key).
  - ENUMERATION: _enumerate_module_roots finds every in-scope module and EXCLUDES
    vendor/node_modules/testdata/.git/third_party/examples segments.
  - MODULE CAP: an env-overridable ceiling truncates with a logged, non-silent tail.

The arms shell out to the real `go` toolchain; each go-dependent case SKIPs
cleanly when `go` is unavailable so the suite stays green offline.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "go-dataflow.py"
GO_FIX = REPO / "tests" / "fixtures" / "dataflow_go"

_spec = importlib.util.spec_from_file_location("gd_mm", TOOL)
gd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gd)


def _have_go():
    return shutil.which("go") is not None


def _read(p):
    if not Path(p).is_file():
        return []
    return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]


def _run_tool(ws, *extra):
    p = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws), "--json", *extra],
        capture_output=True, text=True, timeout=1800)
    assert p.returncode == 0, f"go-dataflow rc={p.returncode}\n{p.stderr}\n{p.stdout}"
    out = p.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return json.loads(out.splitlines()[-1])


# ----------------------------------------------------- enumeration (no go) ---

def test_enumerate_excludes_oos_segments(tmp_path):
    """Every in-scope go.mod is found; vendor/node_modules/testdata/.git/
    third_party/examples segments are excluded."""
    # in-scope modules
    for rel in ("a", "b", "nested/c"):
        d = tmp_path / rel
        d.mkdir(parents=True)
        (d / "go.mod").write_text("module x\n\ngo 1.21\n")
    # OOS modules (must be excluded) - incl Cosmos sim/test scaffold simapp/testutil
    for rel in ("vendor/v", "node_modules/n", "testdata/t",
                "third_party/p", "examples/e", "a/vendor/inner",
                "src/vault/simapp", "x/testutil"):
        d = tmp_path / rel
        d.mkdir(parents=True)
        (d / "go.mod").write_text("module oos\n\ngo 1.21\n")
    roots = gd._enumerate_module_roots(tmp_path)
    rels = sorted(str(r.relative_to(tmp_path.resolve())) for r in roots)
    assert rels == ["a", "b", os.path.join("nested", "c")], rels
    # the Cosmos sim/test scaffold modules are NOT enumerated (the nuva
    # src/vault/simapp ForEachElement panic that STARVED the whole Go dataflow arm).
    assert not any("simapp" in r or "testutil" in r for r in rels), rels


def test_enumerate_single_module(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.21\n")
    roots = gd._enumerate_module_roots(tmp_path)
    assert len(roots) == 1


def test_module_cap_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_GO_MODULE_CAP", "3")
    assert gd._default_module_cap() == 3
    monkeypatch.setenv("AUDITOOOR_GO_MODULE_CAP", "bogus")
    assert gd._default_module_cap() == 64  # falls back to default on bad value


# ----------------------------------------------------- go-dependent ----------

def _mk_module_a(root: Path):
    """A clean in-scope module that yields real records (copy of the bank fixture)."""
    if not GO_FIX.is_dir():
        pytest.skip("dataflow_go fixture missing")
    shutil.copytree(GO_FIX, root)


def _mk_module_b_broken(root: Path):
    """A non-compiling in-scope module (its own go.mod + a syntactically broken .go)."""
    root.mkdir(parents=True)
    (root / "go.mod").write_text("module broken.fixture/modb\n\ngo 1.21\n")
    pkg = root / "broken"
    pkg.mkdir()
    # deliberately invalid Go: unterminated func / undefined symbol
    (pkg / "broken.go").write_text(
        "package broken\n\nfunc Bad( {\n  this is not valid go code zzz\n")


@pytest.mark.skipif(not _have_go(), reason="go toolchain unavailable")
def test_multi_module_clean_plus_broken(tmp_path):
    """A clean (records) + B broken (degrade) -> arm ok, A's rows survive, B tagged."""
    ws = tmp_path / "ws"
    ws.mkdir()
    _mk_module_a(ws / "modA")
    _mk_module_b_broken(ws / "modB")

    res = _run_tool(ws)
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    rows = _read(out)

    # multi-module path was taken
    assert res.get("multi_module") is True, res
    assert res["modules_discovered"] == 2
    assert res["modules_processed"] == 2
    # arm is OK because >=1 module produced real records (NOT a whole-arm degrade)
    assert res["status"] == "ok", res
    assert res["modules_with_records"] >= 1
    assert res["modules_degraded"] >= 1

    # module A real (non-degrade) go rows survive in the sidecar
    real_go = [r for r in rows if r["language"] == "go" and not r.get("degraded")]
    assert real_go, f"module A's real go rows missing (wiped?): {rows}"
    assert all(r.get("module_rel") == "modA" for r in real_go), \
        [r.get("module_rel") for r in real_go]

    # module B emitted a MODULE-TAGGED degrade (not a global whole-arm degrade)
    degrades = [r for r in rows if r["language"] == "go" and r.get("degraded")]
    assert degrades, "module B produced no per-module degrade"
    assert any(d.get("module_rel") == "modB" for d in degrades), \
        [d.get("module_rel") for d in degrades]

    # per-module report carries {records, degraded, error} for each
    reps = {r["module_rel"]: r for r in res["module_reports"]}
    assert reps["modA"]["degraded"] is False and reps["modA"]["records"] >= 1
    assert reps["modB"]["degraded"] is True and reps["modB"]["error"]


@pytest.mark.skipif(not _have_go(), reason="go toolchain unavailable")
def test_multi_module_b_does_not_wipe_a(tmp_path):
    """Explicit accumulate proof: the union write keeps BOTH modules' rows; the
    broken module's degrade is appended, not a truncation of A's real rows."""
    ws = tmp_path / "ws"
    ws.mkdir()
    _mk_module_a(ws / "modA")
    _mk_module_b_broken(ws / "modB")
    _run_tool(ws)
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    rows = _read(out)
    by_mod = {}
    for r in rows:
        by_mod.setdefault(r.get("module_rel"), []).append(r)
    assert "modA" in by_mod and any(not r.get("degraded") for r in by_mod["modA"])
    assert "modB" in by_mod


@pytest.mark.skipif(not _have_go(), reason="go toolchain unavailable")
def test_single_module_byte_identical(tmp_path):
    """Exactly one in-scope go.mod -> legacy single-module path (no multi_module key,
    module_root present), output identical to pre-fix behavior."""
    ws = tmp_path / "ws"
    _mk_module_a(ws)  # the bank fixture AT the ws root (single module; copytree creates ws)
    res = _run_tool(ws)
    # the single-module code path emits module_root and does NOT set multi_module
    assert "multi_module" not in res, res
    assert "module_root" in res, res
    assert res["status"] == "ok"
    assert res["records"] >= 1
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    rows = _read(out)
    real = [r for r in rows if r["language"] == "go" and not r.get("degraded")]
    assert real, "single-module produced no real go rows"


@pytest.mark.skipif(not _have_go(), reason="go toolchain unavailable")
def test_module_cap_logs_not_silent(tmp_path, monkeypatch):
    """A cap below the module count truncates the tail and REPORTS it (no silent
    truncation)."""
    ws = tmp_path / "ws"
    ws.mkdir()
    _mk_module_a(ws / "modA")
    _mk_module_b_broken(ws / "modB")
    monkeypatch.setenv("AUDITOOOR_GO_MODULE_CAP", "1")
    res = _run_tool(ws)
    assert res["multi_module"] is True
    assert res["modules_discovered"] == 2
    assert res["modules_processed"] == 1
    assert res["module_cap_hit"] is True
    assert res["modules_skipped_by_cap"], "skipped modules not reported (silent truncation!)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-s"]))
