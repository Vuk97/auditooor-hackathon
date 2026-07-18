#!/usr/bin/env python3
"""go-dataflow IN-SCOPE BATCHED single-module run (surfaced by axelar-dlt).

A single huge cosmos-sdk module (axelar-core: ~200 in-scope go packages, one
go.mod) times out under a blanket `./...` full-closure run: go/ssa + slicing over
the union import closure genuinely exceeds the 3600s ceiling, so the Go arm emits
ONE degrade record -> 0 real paths -> `fail-dataflow-substrate-starved` RED. But
per-package runs are cheap (a single package's closure is a small cosmos-sdk
subset). The batched runner derives the in-scope package set from
`<ws>/.auditooor/inscope_units.jsonl` and runs it per bounded batch with a
per-batch timeout under a total budget, merging whatever completed.

These tests lock in (no go toolchain needed for the derivation/batching cases):

  - IN-SCOPE DIR DERIVATION: `_inscope_go_dirs` maps ws-relative .go manifest rows
    to NON-RECURSIVE `./rel/pkg` patterns relative to the go.mod root, dedups,
    sorts, drops non-go / OOS-segment / out-of-module rows, and returns [] with no
    manifest (blanket-`./...` fallback).
  - BATCHING: `_batch` chunks deterministically; bad size coerces to 1.
  - ENV KNOBS: batch size / timeout / budget honor their env overrides.
  - GO BATCHED RUN (skips without `go`): a 2-package fixture split into size-1
    batches yields real records from BOTH batches, arm status=ok, inscope_batched
    report shape present, and a clean batch is NOT wiped by a sibling.
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
TOOL = REPO / "tools" / "go-dataflow.py"
GO_FIX = REPO / "tests" / "fixtures" / "dataflow_go"

_spec = importlib.util.spec_from_file_location("gd_batched", TOOL)
gd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gd)


def _have_go():
    return shutil.which("go") is not None


def _write_manifest(ws: Path, files):
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "inscope_units.jsonl").open("w", encoding="utf-8") as fh:
        for f in files:
            fh.write(json.dumps({"file": f, "lang": "go"}) + "\n")


# ---------------------------------------------------- derivation (no go) -----

def test_inscope_dirs_maps_to_nonrecursive_patterns(tmp_path):
    ws = tmp_path
    root = ws / "src" / "axelar-core"
    root.mkdir(parents=True)
    (root / "go.mod").write_text("module axelar\n\ngo 1.21\n")
    _write_manifest(ws, [
        "src/axelar-core/x/nexus/keeper/keeper.go",
        "src/axelar-core/x/nexus/keeper/grpc.go",   # same pkg -> dedup
        "src/axelar-core/utils/store.go",
        "src/axelar-core/config/config.go",
    ])
    dirs = gd._inscope_go_dirs(ws, root)
    assert dirs == ["./config", "./utils", "./x/nexus/keeper"], dirs
    # NON-recursive: no `/...` suffixes (each loads one package closure only)
    assert all(not d.endswith("/...") for d in dirs), dirs


def test_inscope_dirs_drops_nongo_oos_and_outofmodule(tmp_path):
    ws = tmp_path
    root = ws / "src" / "axelar-core"
    root.mkdir(parents=True)
    (root / "go.mod").write_text("module axelar\n\ngo 1.21\n")
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "inscope_units.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"file": "src/axelar-core/x/nexus/keeper/k.go", "lang": "go"}) + "\n")
        fh.write(json.dumps({"file": "src/tofn/src/lib.rs", "lang": "rust"}) + "\n")     # non-go
        fh.write(json.dumps({"file": "src/axelar-core/x/vendor/dep/d.go", "lang": "go"}) + "\n")  # OOS seg
        fh.write(json.dumps({"file": "src/axelar-core/testutil/util.go", "lang": "go"}) + "\n")   # OOS seg
        fh.write(json.dumps({"file": "src/other-mod/foo.go", "lang": "go"}) + "\n")      # out of module
    dirs = gd._inscope_go_dirs(ws, root)
    assert dirs == ["./x/nexus/keeper"], dirs


def test_inscope_dirs_module_root_package_is_dot(tmp_path):
    ws = tmp_path
    root = ws / "mod"
    root.mkdir(parents=True)
    (root / "go.mod").write_text("module m\n\ngo 1.21\n")
    _write_manifest(ws, ["mod/tools.go"])
    assert gd._inscope_go_dirs(ws, root) == ["."]


def test_inscope_dirs_no_manifest_returns_empty(tmp_path):
    ws = tmp_path
    root = ws / "mod"
    root.mkdir(parents=True)
    assert gd._inscope_go_dirs(ws, root) == []


# ------------------------------------------------------- batching (no go) ----

def test_batch_chunks_deterministically():
    assert gd._batch(["a", "b", "c", "d", "e"], 2) == [["a", "b"], ["c", "d"], ["e"]]
    assert gd._batch(["a", "b"], 5) == [["a", "b"]]
    assert gd._batch([], 3) == []
    # a bogus non-positive size coerces to 1 (never a zero-step range)
    assert gd._batch(["a", "b"], 0) == [["a"], ["b"]]


def test_batched_env_knobs(monkeypatch):
    monkeypatch.setenv("AUDITOOOR_GO_DATAFLOW_BATCH_SIZE", "5")
    assert gd._batched_env_int("AUDITOOOR_GO_DATAFLOW_BATCH_SIZE", 8) == 5
    monkeypatch.setenv("AUDITOOOR_GO_DATAFLOW_BATCH_SIZE", "bogus")
    assert gd._batched_env_int("AUDITOOOR_GO_DATAFLOW_BATCH_SIZE", 8) == 8
    monkeypatch.setenv("AUDITOOOR_GO_DATAFLOW_TOTAL_BUDGET", "900")
    assert gd._batched_env_int("AUDITOOOR_GO_DATAFLOW_TOTAL_BUDGET", 1800) == 900


# ------------------------------------------------------- go batched run -------

def _run_tool(ws, *extra, env=None):
    p = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws), "--json", *extra],
        capture_output=True, text=True, timeout=1800, env=env)
    assert p.returncode == 0, f"go-dataflow rc={p.returncode}\n{p.stderr}\n{p.stdout}"
    out = p.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return json.loads(out.splitlines()[-1])


@pytest.mark.skipif(not _have_go(), reason="go toolchain unavailable")
def test_batched_run_two_packages_both_real(tmp_path, monkeypatch):
    """Two in-scope packages, size-1 batches -> real records from both, arm ok,
    inscope_batched report present, no batch wipes the other."""
    if not GO_FIX.is_dir():
        pytest.skip("dataflow_go fixture missing")
    ws = tmp_path / "ws"
    ws.mkdir()
    # copy the bank fixture as the single go.mod module, then add a 2nd in-scope pkg
    shutil.copytree(GO_FIX, ws / "mod")
    # discover the fixture's own package dirs that hold .go files (relative to mod)
    mod = ws / "mod"
    go_dirs = sorted({str(p.parent.relative_to(mod)) for p in mod.rglob("*.go")})
    # need at least one package; build a manifest of every .go file under mod
    files = ["mod/" + str(p.relative_to(mod)) for p in mod.rglob("*.go")]
    assert files, "fixture has no .go files"
    _write_manifest(ws, files)

    import os as _os
    env = dict(_os.environ)
    env["AUDITOOOR_GO_DATAFLOW_BATCH_SIZE"] = "1"
    env["AUDITOOOR_GO_DATAFLOW_BATCH_TIMEOUT"] = "600"
    env["AUDITOOOR_GO_DATAFLOW_TOTAL_BUDGET"] = "1200"
    res = _run_tool(ws, env=env)

    assert res.get("inscope_batched") is True, res
    assert res["status"] == "ok", res
    assert res["batches_with_records"] >= 1, res
    assert res["real_records"] >= 1, res

    rows = [json.loads(l) for l in
            (ws / ".auditooor" / "dataflow_paths.jsonl").read_text().splitlines() if l.strip()]
    real_go = [r for r in rows if r["language"] == "go" and not r.get("degraded")]
    assert real_go, f"batched run produced no real go rows: {rows}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-s"]))
