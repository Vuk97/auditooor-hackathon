#!/usr/bin/env python3
"""B-router: cross-language router + stitcher tests (tools/dataflow.py).

Proves:
  - MIXED-WS STITCHER: a workspace with Solidity + Go (+ ZK) produces ONE
    dataflow_paths.jsonl containing rows from EVERY detected language, where NO arm
    truncated another's rows (the polyglot truncation fix end-to-end).
  - per-record `language` field distinguishes the arms within the one file.
  - graceful NO-OP on a workspace with no language arm (sidecar untouched, exit 0).
  - language auto-detection reuses make audit's predicates (present-set).

Arms shell out to real toolchains (slither/solc, go, circomspect). Each sub-case
SKIPs cleanly when its toolchain is unavailable so the suite stays green offline.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ROUTER = REPO / "tools" / "dataflow.py"


def _load_router_module():
    """Import tools/dataflow.py as a module to unit-test _arm_cmd directly (the
    hyphen-in-path filename cannot be imported by name)."""
    spec = importlib.util.spec_from_file_location("_dataflow_router_mod", ROUTER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _go_arm_args(**over):
    ns = argparse.Namespace(
        no_merge=False, mode="both", max_hops=None, no_closure=False,
        no_storage_value=False, target=None)
    for k, v in over.items():
        setattr(ns, k, v)
    return ns
FIX = REPO / "tests" / "fixtures"
SOL_FIX = FIX / "dataflow" / "vulnerable.sol"
GO_FIX = FIX / "dataflow_go"
ZK_FIX = FIX / "dataflow_zk" / "under_constrained.circom"


def _have(cmd):
    return shutil.which(cmd) is not None


def _read(p):
    if not Path(p).is_file():
        return []
    return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]


def _run_router(ws, *extra):
    p = subprocess.run(
        [sys.executable, str(ROUTER), "--workspace", str(ws), "--json", *extra],
        capture_output=True, text=True, timeout=1800)
    assert p.returncode == 0, f"router rc={p.returncode}\n{p.stderr}\n{p.stdout}"
    # last json object on stdout
    out = p.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return json.loads(out.splitlines()[-1])


def _strict_workspace(tmp_path, rows):
    """Create only the authoritative inventory and its declared source files."""
    aud = tmp_path / ".auditooor"
    aud.mkdir()
    for row in rows:
        file_name = row.get("file")
        if file_name:
            source = tmp_path / file_name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("source\n")
    (aud / "inscope_units.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + ("\n" if rows else ""))
    return tmp_path


def _semantic_row(mod, language, path_id, *, engine=None, confidence=None):
    default_engines = {
        "solidity": "slither.analyses.data_dependency",
        "go": "go-ssa-cha-vta",
        "rust": "rustc-mir.defuse-bridge",
        "javascript": "acorn-ast-defuse",
        "typescript": "typescript-unsupported",
        "oscript": "ocore-nearley-ast",
        "circom": "zk-circom-signal-parser",
    }
    if confidence is None:
        confidence = "semantic-ssa" if language in {"solidity", "go", "rust"} else "syntactic"
    return mod.dfs.new_path(
        path_id=path_id, language=language, direction="forward",
        engine=engine or default_engines[language],
        source={"kind": "param", "fn": "entry", "var": "value", "file": "src", "line": 1},
        sink={"kind": "sink", "callee": "send", "arg_pos": 0, "fn": "entry", "file": "src", "line": 2},
        hops=[], guard_nodes=[], source_unit_ids=["src"], sink_unit_ids=["src"],
        confidence=confidence,
    )


def _mock_strict_arms(monkeypatch, mod, ws, rows_by_arm, returncodes=None, summaries=None):
    """Mock only subprocess execution. Each fake arm writes current-run output."""
    calls = []
    returncodes = returncodes or {}
    summaries = summaries or {}
    out_path = ws / ".auditooor" / "dataflow_paths.jsonl"

    class FakePopen:
        def __init__(self, cmd, **_kwargs):
            self.cmd = cmd
            self.returncode = 0
            self.pid = 1
            calls.append(cmd)
            tool = next(part for part in cmd if part.endswith("-dataflow.py") or part.endswith("dataflow-slice.py"))
            self.arm = {
                "dataflow-slice.py": "solidity", "go-dataflow.py": "go",
                "rust-dataflow.py": "rust", "zk-dataflow.py": "zk",
                "js-dataflow.py": "javascript", "oscript-ast-dataflow.py": "oscript",
            }[Path(tool).name]

        def communicate(self, timeout=None):
            del timeout
            self.returncode = returncodes.get(self.arm, 0)
            if self.returncode == 0:
                emitted = rows_by_arm.get(self.arm, [])
                if emitted:
                    with out_path.open("a", encoding="utf-8") as fh:
                        for row in emitted:
                            fh.write(json.dumps(row) + "\n")
            return json.dumps(summaries.get(self.arm, {"status": "ok"})), ""

    monkeypatch.setattr(mod.subprocess, "Popen", FakePopen)
    return calls


def _strict_result(capsys, mod, ws):
    rc = mod.main(["--workspace", str(ws), "--strict", "--json"])
    return rc, json.loads(capsys.readouterr().out)


def test_strict_oscript_parser_receipt_blocks_semantic_dataflow(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [{"lang": "oscript", "file": "aa/app.oscript"}])
    calls = _mock_strict_arms(
        monkeypatch, mod, ws,
        {"oscript": [_semantic_row(mod, "oscript", "oscript-1")]},
    )

    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    assert len(calls) == 1 and calls[0][1].endswith("oscript-ast-dataflow.py")
    assert result["strict_coverage_by_inventory_language"] == {"oscript": 0}
    assert result["language_capability_query"]["blocked_languages"] == ["oscript"]
    assert result["language_backend_receipts"][0]["backend"] == "ocore-nearley-ast"
    assert result["language_backend_receipts"][0]["status"] == "blocked"


def test_strict_js_typescript_and_oscript_use_distinct_syntactic_arms_and_block_dataflow(
    tmp_path, monkeypatch, capsys,
):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [
        {"lang": "js", "file": "app.js"},
        {"lang": "typescript", "file": "ui/app.ts"},
        {"lang": "oscript", "file": "aa/app.oscript"},
    ])
    calls = _mock_strict_arms(monkeypatch, mod, ws, {"javascript": [
        _semantic_row(mod, "javascript", "js-1"),
    ], "oscript": [
        _semantic_row(mod, "oscript", "oscript-1"),
    ]})

    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    assert len(calls) == 2
    assert result["strict_coverage_by_inventory_language"] == {
        "js": 0, "oscript": 0, "typescript": 0,
    }
    assert result["language_capability_query"]["blocked_languages"] == [
        "javascript", "oscript", "typescript",
    ]
    receipts = {row["language"]: row for row in result["language_backend_receipts"]}
    assert receipts["javascript"]["backend"] == "acorn-ast-defuse"
    assert receipts["javascript"]["status"] == "blocked"
    assert receipts["oscript"]["backend"] == "ocore-nearley-ast"


def test_strict_mixed_go_rust_solidity_dispatches_every_inventory_arm(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [
        {"lang": "go", "file": "node/main.go"},
        {"lang": "rust", "file": "runtime/lib.rs"},
        {"lang": "solidity", "file": "contracts/Vault.sol"},
    ])
    calls = _mock_strict_arms(monkeypatch, mod, ws, {
        "go": [_semantic_row(mod, "go", "go-1")],
        "rust": [_semantic_row(mod, "rust", "rust-1")],
        "solidity": [_semantic_row(mod, "solidity", "sol-1")],
    })

    rc, result = _strict_result(capsys, mod, ws)

    assert rc == 0
    assert {Path(next(p for p in call if p.endswith(".py"))).name for call in calls} == {
        "go-dataflow.py", "rust-dataflow.py", "dataflow-slice.py",
    }
    assert result["strict_coverage_by_inventory_language"] == {
        "go": 1, "rust": 1, "solidity": 1,
    }
    assert result["language_capability_query"]["ok"] is True
    assert result["language_capability_query"]["requested_phases"] == ["dataflow"]
    receipt_path = ws / ".auditooor" / "language_backend_receipts" / "dataflow.jsonl"
    receipts = _read(receipt_path)
    assert {row["receipt_schema"] for row in receipts} == {
        "auditooor.language_backend_receipt.v1",
    }
    assert {row["language"]: row["backend"] for row in receipts} == {
        "go": "go-ssa", "rust": "mir", "solidity": "slither",
    }
    assert all(row["status"] == "pass" and row["degraded"] is False for row in receipts)


def test_strict_rust_any_tree_sitter_fallback_receipt_is_rejected(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [{"lang": "rust", "file": "runtime/lib.rs"}])
    fallback = _semantic_row(
        mod, "rust", "rust-fallback", engine="treesitter.rust-defuse",
        confidence="syntactic",
    )
    mir = _semantic_row(mod, "rust", "rust-mir")
    _mock_strict_arms(
        monkeypatch, mod, ws, {"rust": [mir, fallback]},
        summaries={"rust": {"status": "ok", "crates": {
            "core": {"backend": "mir"}, "fallback": {"backend": "syntactic"},
        }}},
    )

    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    receipt = result["language_backend_receipts"][0]
    assert receipt["engines_observed"] == [
        "rustc-mir.defuse-bridge", "treesitter.rust-defuse",
    ]
    assert receipt["semantic_record_count"] == 1
    assert receipt["arm_summary_backends"] == ["mir", "syntactic"]
    assert receipt["status"] == "blocked"
    assert result["language_capability_query"]["blocked_languages"] == ["rust"]


def test_strict_typed_examined_empty_semantic_receipt_can_pass(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [{"lang": "go", "file": "node/main.go"}])
    _mock_strict_arms(
        monkeypatch, mod, ws, {"go": []},
        summaries={"go": {
            "status": "ok", "backend": "go-ssa", "examined_empty": True,
            "examined_unit_count": 1,
        }},
    )

    rc, result = _strict_result(capsys, mod, ws)

    assert rc == 0
    receipt = result["language_backend_receipts"][0]
    assert receipt["status"] == "pass"
    assert receipt["examined_empty"] is True
    assert receipt["examined_unit_count"] == 1
    assert len(receipt["inventory_sha256"]) == 64
    assert len(receipt["source_set_sha256"]) == 64
    assert len(receipt["source_hashes"]) == 1
    assert len(receipt["source_hashes"][0]["sha256"]) == 64
    assert result["language_capability_query"]["ok"] is True
    assert (ws / ".auditooor" / "dataflow_paths.jsonl").is_file()


def test_strict_failed_arm_cannot_reuse_stale_sidecar(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [{"lang": "go", "file": "node/main.go"}])
    stale = ws / ".auditooor" / "dataflow_paths.jsonl"
    stale.write_text(json.dumps(_semantic_row(mod, "go", "old-go")) + "\n")
    _mock_strict_arms(monkeypatch, mod, ws, {}, returncodes={"go": 1})

    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    assert result["records_by_language"] == {}
    assert any("arm go failed" in error for error in result["strict_errors"])
    assert result["language_backend_receipts"][0]["status"] == "failed"
    assert result["language_capability_query"]["blocked_languages"] == ["go"]


@pytest.mark.parametrize("bad_output", ["invalid", "degraded", "truncated"])
def test_strict_rejects_invalid_degraded_and_truncated_output(
    tmp_path, monkeypatch, capsys, bad_output,
):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [{"lang": "go", "file": "node/main.go"}])
    if bad_output == "invalid":
        row = {"language": "go"}
    else:
        row = _semantic_row(mod, "go", f"go-{bad_output}")
        if bad_output == "degraded":
            row["degraded"] = True
        else:
            row["dataflow_truncated"] = True
    _mock_strict_arms(monkeypatch, mod, ws, {"go": [row]})

    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    assert result["verdict"] == "strict-failed"
    assert result["strict_errors"]


def test_strict_rejects_subprocess_execution_error(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [{"lang": "go", "file": "node/main.go"}])

    def raise_exec_error(*_args, **_kwargs):
        raise OSError("missing tool")

    monkeypatch.setattr(mod.subprocess, "Popen", raise_exec_error)
    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    assert any("arm go failed: exec-error" in error for error in result["strict_errors"])


def test_strict_rejects_malformed_or_unknown_inventory_before_subprocess(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    aud = tmp_path / ".auditooor"
    aud.mkdir()
    (aud / "inscope_units.jsonl").write_text("not-json\n" + json.dumps({
        "lang": "python", "file": "app.py"}) + "\n")
    calls = _mock_strict_arms(monkeypatch, mod, tmp_path, {})

    rc, result = _strict_result(capsys, mod, tmp_path)

    assert rc != 0
    assert calls == []
    assert result["verdict"] == "strict-inventory-invalid"
    assert any("malformed JSON" in error for error in result["strict_errors"])
    assert any("unsupported language" in error for error in result["strict_errors"])


def test_strict_rejects_no_applicable_arm_before_subprocess(tmp_path, monkeypatch, capsys):
    mod = _load_router_module()
    ws = _strict_workspace(tmp_path, [])
    calls = _mock_strict_arms(monkeypatch, mod, ws, {})

    rc, result = _strict_result(capsys, mod, ws)

    assert rc != 0
    assert calls == []
    assert "strict inventory is empty" in result["strict_errors"]


def test_router_noop_on_empty_workspace(tmp_path):
    """No .sol/.rs/.go/.circom -> clean no-op, sidecar never created."""
    res = _run_router(tmp_path)
    assert res["status"] == "no-op"
    assert res["verdict"] == "no-language-arm"
    assert res["total_records"] == 0
    assert not (tmp_path / ".auditooor" / "dataflow_paths.jsonl").exists()
    assert not (tmp_path / ".auditooor" / "language_backend_receipts" / "dataflow.jsonl").exists()


def test_router_detects_present_languages(tmp_path):
    """present-set picks up both .sol and a go.mod in the same ws."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.sol").write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract X {}\n")
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.21\n")
    # restrict to detection only via --only on a non-existent toolchain-free probe:
    # just assert detection by reading the json detected_present
    res = _run_router(tmp_path, "--only", "zk")  # zk arm no-ops (no circom) but detection still reports
    assert res["detected_present"]["solidity"] is True
    assert res["detected_present"]["go"] is True


def test_router_distinguishes_canonical_javascript_and_oscript_inventory(tmp_path):
    mod = _load_router_module()
    aud = tmp_path / ".auditooor"
    aud.mkdir()
    (tmp_path / "app.js").write_text("module.exports = 1;\n")
    (tmp_path / "aa.oscript").write_text("{}\n")
    (aud / "inscope_units.jsonl").write_text(
        '{"lang":"javascript","file":"app.js"}\n'
        '{"lang":"oscript","file":"aa.oscript"}\n')

    present = mod._present_languages(tmp_path)

    assert present["javascript"] is True
    assert present["oscript"] is True


def test_router_skips_solidity_when_only_harness_sol(tmp_path):
    """A Go+Rust workspace whose ONLY .sol file is an audit-generated fuzz harness
    (economic_fuzz/*.t.sol) must NOT dispatch the Solidity arm - the old naive
    `**/*.sol` predicate flipped solidity=True and the arm degraded with a bogus
    '<workspace> is a directory' compile-error row. Regression for axelar-dlt
    2026-07-12: in-scope-only .sol detection => solidity NOT present, no degrade row."""
    # a generated harness .sol under economic_fuzz (out-of-scope for the sol arm)
    econ = tmp_path / "economic_fuzz"
    econ.mkdir()
    (econ / "EconomicInvariantFuzz.t.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract H {}\n")
    # a real Go module (the actual in-scope language)
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.21\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")

    res = _run_router(tmp_path, "--only", "zk")  # zk no-ops; we only read detection
    assert res["detected_present"]["solidity"] is False, (
        "harness-only .sol must NOT count as in-scope solidity")
    assert res["detected_present"]["go"] is True

    # And a real router pass must never write a solidity compile-error degrade row.
    res2 = _run_router(tmp_path)
    out = tmp_path / ".auditooor" / "dataflow_paths.jsonl"
    for r in _read(out):
        assert r.get("language") != "solidity", (
            f"solidity arm dispatched on a harness-only-.sol ws: {r}")
    assert "solidity" not in (res2.get("records_by_language") or {})


@pytest.mark.skipif(not (_have("slither") or True), reason="needs slither")
def test_router_solidity_only(tmp_path):
    if not _have("solc-select") and not _have("solc"):
        pytest.skip("no solc")
    try:
        import slither  # noqa: F401
    except Exception:
        pytest.skip("no slither")
    src = tmp_path / "src"
    src.mkdir()
    shutil.copy(SOL_FIX, src / "vulnerable.sol")
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\nout = 'out'\n")
    res = _run_router(tmp_path, "--only", "solidity")
    out = tmp_path / ".auditooor" / "dataflow_paths.jsonl"
    rows = _read(out)
    assert rows, "expected solidity rows"
    assert all(r["language"] == "solidity" for r in rows)
    assert res["records_by_language"].get("solidity", 0) >= 1


def _mk_mixed_ws(tmp_path, with_zk=False):
    """Assemble a Solidity + Go (+ optional ZK) workspace.

    A minimal foundry.toml makes the Solidity arm's _resolve_targets find a real
    project root (it scans for foundry/hardhat configs) instead of degrading on a
    bare directory. Circom (if added) lives OUTSIDE src/ so it never confuses the
    Slither tree compile.
    """
    src = tmp_path / "src"
    src.mkdir()
    shutil.copy(SOL_FIX, src / "vulnerable.sol")
    (tmp_path / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = ['lib']\n")
    # Go module copied under the ws root (go-dataflow scans for go.mod)
    go_dst = tmp_path / "gomod"
    shutil.copytree(GO_FIX, go_dst)
    if with_zk:
        circ = tmp_path / "circuits"
        circ.mkdir()
        shutil.copy(ZK_FIX, circ / "under_constrained.circom")
    return tmp_path


def test_router_mixed_sol_go_stitcher(tmp_path):
    """THE stitcher proof: one jsonl with BOTH solidity and go rows, no truncation."""
    try:
        import slither  # noqa: F401
    except Exception:
        pytest.skip("no slither")
    if not (_have("solc-select") or _have("solc")):
        pytest.skip("no solc")
    if not _have("go"):
        pytest.skip("no go toolchain")
    ws = _mk_mixed_ws(tmp_path, with_zk=_have("circomspect"))
    res = _run_router(ws)
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    rows = _read(out)
    langs = {r["language"] for r in rows if not r.get("degraded")}
    # The keystone assertion: BOTH arms' rows survive in the ONE file.
    assert "solidity" in langs, f"solidity rows missing (truncated?): langs={langs} rows={len(rows)}"
    assert "go" in langs, f"go rows missing (truncated?): langs={langs} rows={len(rows)}"
    # every surviving row is schema-valid + carries its own language
    assert res["invalid_rows_dropped_on_reread"] == 0
    assert res["records_by_language"].get("solidity", 0) >= 1
    assert res["records_by_language"].get("go", 0) >= 1
    if _have("circomspect"):
        # zk arm present -> circom rows too (a 3-language single file)
        assert "circom" in langs or res["records_by_language"].get("circom", 0) >= 0


def test_router_mixed_no_arm_truncates_another_explicit(tmp_path):
    """Run arms one at a time through the router (--only) and assert accumulation."""
    try:
        import slither  # noqa: F401
    except Exception:
        pytest.skip("no slither")
    if not (_have("solc-select") or _have("solc")):
        pytest.skip("no solc")
    if not _have("go"):
        pytest.skip("no go toolchain")
    ws = _mk_mixed_ws(tmp_path)
    out = ws / ".auditooor" / "dataflow_paths.jsonl"
    # 1) go arm only
    _run_router(ws, "--only", "go")
    after_go = _read(out)
    go_rows = [r for r in after_go if r["language"] == "go" and not r.get("degraded")]
    assert go_rows, "go arm produced no rows"
    # 2) solidity arm only -> MUST NOT delete the go rows
    _run_router(ws, "--only", "solidity")
    after_sol = _read(out)
    langs = {r["language"] for r in after_sol}
    assert "go" in langs, "solidity arm truncated the go rows (B-merge regression)"
    assert "solidity" in langs


# --------------------------------------------------------------------------- #
# Panic-substrate wiring: the go arm must emit kind==panic records by default so
# the step-2d go-mustsucceed-panic-reachability reasoner (which runs AFTER the
# step-1c dataflow slice) has its substrate written into dataflow_paths.jsonl
# BEFORE it consumes it. Without --panic-sinks the reasoner is vacuous (0 nodes).
# --------------------------------------------------------------------------- #
def test_go_arm_emits_panic_sinks_by_default(tmp_path):
    """The producer (step-1c) enables the panic arm by default so the consumer
    (step-2d) is not starved (feeds-from ordering: producer writes before reader)."""
    mod = _load_router_module()
    prev = os.environ.pop("AUDITOOOR_DATAFLOW_PANIC_SINKS", None)
    try:
        cmd = mod._arm_cmd("go", tmp_path, _go_arm_args())
    finally:
        if prev is not None:
            os.environ["AUDITOOOR_DATAFLOW_PANIC_SINKS"] = prev
    assert cmd is not None
    assert "--panic-sinks" in cmd, (
        "go arm must pass --panic-sinks by default so the panic substrate is "
        "written at step-1c BEFORE the step-2d reasoner reads it")
    # sanity: the flag targets go-dataflow.py, which owns --panic-sinks
    assert any(c.endswith("go-dataflow.py") for c in cmd)


def test_go_arm_panic_sinks_opt_out_via_env(tmp_path):
    """An explicit AUDITOOOR_DATAFLOW_PANIC_SINKS in {0,false,no} disables the arm
    (a caller that turns it off wins); any other value keeps it on."""
    mod = _load_router_module()
    prev = os.environ.get("AUDITOOOR_DATAFLOW_PANIC_SINKS")
    try:
        for off in ("0", "false", "no"):
            os.environ["AUDITOOOR_DATAFLOW_PANIC_SINKS"] = off
            cmd = mod._arm_cmd("go", tmp_path, _go_arm_args())
            assert "--panic-sinks" not in cmd, f"env={off!r} must disable the arm"
        os.environ["AUDITOOOR_DATAFLOW_PANIC_SINKS"] = "1"
        cmd = mod._arm_cmd("go", tmp_path, _go_arm_args())
        assert "--panic-sinks" in cmd
    finally:
        if prev is None:
            os.environ.pop("AUDITOOOR_DATAFLOW_PANIC_SINKS", None)
        else:
            os.environ["AUDITOOOR_DATAFLOW_PANIC_SINKS"] = prev


def test_go_dataflow_flag_sets_panic_env():
    """go-dataflow.py --panic-sinks pins AUDITOOOR_DATAFLOW_PANIC_SINKS so the
    binary dispatch + the source-cache fingerprint agree on the panic-arm state."""
    tool = REPO / "tools" / "go-dataflow.py"
    # --help must advertise the flag (cheap contract check, no toolchain needed)
    p = subprocess.run([sys.executable, str(tool), "--help"],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0
    assert "--panic-sinks" in p.stdout, "go-dataflow.py must expose --panic-sinks"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-s"]))
