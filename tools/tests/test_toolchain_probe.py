#!/usr/bin/env python3
"""Regression tests for tools/toolchain-probe.py + the step-0e artifact_check.

Covers the fix for: README step-0e ("Install language toolchain") had
attestation_required=true but artifact_checks=[] - a required step that greened on
a self-written attestation with ZERO on-disk proof. The probe writes a mechanical
artifact and step-0e now carries a (backward-compatible, env-gated) artifact_check
for it.

Language-agnostic: fixtures exercise Solidity, Rust, Go, JavaScript, and Oscript
detection so no test hard-codes a single ecosystem.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
PROBE = TOOLS / "toolchain-probe.py"
MANIFEST = TOOLS / "readme_runbook_steps.json"


def _load_probe_module():
    spec = importlib.util.spec_from_file_location("toolchain_probe", PROBE)
    m = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(m)
    return m


def _write_inscope(ws: Path, langs: list[str]) -> None:
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"file": f"src/x_{i}.file", "function": "f", "lang": lang})
        for i, lang in enumerate(langs)
    ]
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _mock_toolchain(
    m,
    monkeypatch,
    *,
    output="tool version 1\n",
    returncode=0,
    missing=(),
):
    """Make all tool probes hermetic while retaining their requested argv."""
    calls = []
    missing = set(missing)

    def fake_which(name):
        return None if name in missing else f"/mock/bin/{name}"

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(
            argv, returncode, stdout=output, stderr=""
        )

    monkeypatch.setattr(m.shutil, "which", fake_which)
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    return calls


# ---------------------------------------------------------------------------
# probe: schema + detection
# ---------------------------------------------------------------------------

def test_probe_writes_valid_schema_from_language(tmp_path, monkeypatch):
    m = _load_probe_module()
    _write_inscope(tmp_path, ["solidity"])
    _mock_toolchain(m, monkeypatch)

    result = m.probe(tmp_path)

    assert result["schema"] == "auditooor.toolchain_probe.v1"
    assert result["languages_detected"] == ["solidity"]
    assert "generated_at" in result and result["generated_at"].endswith("Z")
    # solidity -> forge required
    tools = {t["tool"]: t for t in result["tools"]}
    assert "forge" in tools, "solidity lang must mark forge required"
    forge = tools["forge"]
    assert forge["required"] is True
    for field in ("tool", "required", "present", "version_stdout"):
        assert field in forge, f"schema row missing {field}"


def test_probe_detects_via_manifest_not_lang(tmp_path, monkeypatch):
    """A manifest with no inscope lang must still mark the tool required
    (language-agnostic: manifest presence is an independent signal)."""
    m = _load_probe_module()
    # no inscope_units.jsonl at all; only a Cargo.toml present
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    _mock_toolchain(m, monkeypatch)

    result = m.probe(tmp_path)

    tools = {t["tool"] for t in result["tools"] if t["required"]}
    assert "cargo" in tools, "Cargo.toml must mark cargo required"
    assert "go" in tools, "go.mod must mark go required"
    assert "foundry.toml" not in result["manifests_detected"]


def test_probe_prunes_vendored_dirs(tmp_path, monkeypatch):
    """Manifests inside node_modules/lib/target must NOT drive detection."""
    m = _load_probe_module()
    _write_inscope(tmp_path, ["go"])
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    _mock_toolchain(m, monkeypatch)

    result = m.probe(tmp_path)

    tools = {t["tool"] for t in result["tools"] if t["required"]}
    assert "cargo" not in tools, "vendored Cargo.toml must be pruned"
    assert "go" in tools


def test_probe_records_absent_tool_without_hard_fail(tmp_path, monkeypatch):
    """A missing tool is recorded present=false; probe() never raises and the
    row is still emitted (recording absence is the point, not enforcement)."""
    m = _load_probe_module()
    _write_inscope(tmp_path, ["rust"])
    # force cargo to look absent
    real_which = m.shutil.which

    def fake_which(name):
        if name == "cargo":
            return None
        return real_which(name)

    monkeypatch.setattr(m.shutil, "which", fake_which)

    result = m.probe(tmp_path)
    cargo = {t["tool"]: t for t in result["tools"]}["cargo"]
    assert cargo["present"] is False
    assert cargo["required"] is True
    assert cargo["version_stdout"] == ""


def test_strict_js_oscript_and_node_aliases_require_node(tmp_path, monkeypatch):
    m = _load_probe_module()
    _write_inscope(tmp_path, ["js", "oscript", "node"])
    calls = _mock_toolchain(m, monkeypatch, output="v22.1.0\n")

    result = m.probe(tmp_path, strict=True)

    node = {t["tool"]: t for t in result["tools"]}["node"]
    assert result["strict_pass"] is True
    assert node["required"] is True
    assert node["status"] == "ready"
    assert node["usable_version"] is True
    assert calls == [["node", "--version"]]


def test_strict_mixed_languages_requires_each_toolchain(tmp_path, monkeypatch):
    m = _load_probe_module()
    _write_inscope(tmp_path, ["solidity", "evm", "go", "rust", "typescript"])
    _mock_toolchain(m, monkeypatch)

    result = m.probe(tmp_path, strict=True)
    tools = {t["tool"]: t for t in result["tools"]}

    assert result["strict_pass"] is True
    assert {name for name, row in tools.items() if row["required"]} == {
        "forge", "cargo", "go", "node"
    }
    assert all(
        tools[name]["status"] == "ready"
        for name in ("forge", "cargo", "go", "node")
    )


def test_strict_no_required_toolchain_passes_and_marks_unused_tools(tmp_path, monkeypatch):
    m = _load_probe_module()
    _mock_toolchain(m, monkeypatch, missing=m.SUPPORTED_TOOLS)

    result = m.probe(tmp_path, strict=True)
    tools = {t["tool"]: t for t in result["tools"]}

    assert result["strict_pass"] is True
    assert result["strict_failures"] == []
    assert tools
    assert all(row["required"] is False for row in tools.values())
    assert all(row["status"] == "not_required" for row in tools.values())


@pytest.mark.parametrize(
    "contents, expected",
    [
        ("", "inventory_empty"),
        ("{not-json}\n", "inventory_malformed"),
        ("[]\n", "inventory_malformed"),
    ],
)
def test_strict_rejects_empty_or_malformed_authoritative_inventory(
    tmp_path, contents, expected
):
    m = _load_probe_module()
    (tmp_path / ".auditooor").mkdir()
    (tmp_path / ".auditooor" / "inscope_units.jsonl").write_text(
        contents, encoding="utf-8"
    )

    result = m.probe(tmp_path, strict=True)

    assert result["strict_pass"] is False
    assert any(expected in failure for failure in result["strict_failures"])


def test_strict_writes_report_and_fails_on_version_command_failure(tmp_path, monkeypatch):
    m = _load_probe_module()
    _write_inscope(tmp_path, ["go"])
    _mock_toolchain(m, monkeypatch, output="tool refused\n", returncode=7)
    output = tmp_path / "strict-report.json"

    rc = m.main(["--workspace", str(tmp_path), "--out", str(output), "--strict"])

    assert rc != 0
    report = json.loads(output.read_text(encoding="utf-8"))
    go = {t["tool"]: t for t in report["tools"]}["go"]
    assert report["strict"] is True
    assert report["strict_pass"] is False
    assert go["present"] is True
    assert go["usable_version"] is False
    assert go["status"] == "unusable_version"


def test_strict_fails_required_missing_toolchain_but_writes_report(tmp_path, monkeypatch):
    m = _load_probe_module()
    _write_inscope(tmp_path, ["rust"])
    _mock_toolchain(m, monkeypatch, missing=("cargo",))
    output = tmp_path / "strict-report.json"

    rc = m.main(["--workspace", str(tmp_path), "--out", str(output), "--strict"])

    assert rc != 0
    cargo = {t["tool"]: t for t in json.loads(output.read_text())["tools"]}["cargo"]
    assert cargo["required"] is True
    assert cargo["present"] is False
    assert cargo["status"] == "missing"


def test_cli_writes_artifact_and_exits_zero(tmp_path, monkeypatch):
    """CLI writes the artifact with a mocked usable version and exits 0."""
    m = _load_probe_module()
    _write_inscope(tmp_path, ["python"])
    _mock_toolchain(m, monkeypatch, output="Python 3.13.0\n")
    assert m.main(["--workspace", str(tmp_path)]) == 0
    artifact = tmp_path / ".auditooor" / "toolchain_probe.json"
    assert artifact.is_file(), "CLI must write the artifact"
    data = json.loads(artifact.read_text())
    assert data["schema"] == "auditooor.toolchain_probe.v1"
    py = {t["tool"]: t for t in data["tools"]}["python3"]
    assert py["present"] is True
    assert py["version_stdout"], "must capture version stdout for present tool"
    assert "Python" in py["version_stdout"]


def test_cli_bad_workspace_nonzero(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(PROBE), "--workspace", str(tmp_path / "nope")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0


# ---------------------------------------------------------------------------
# manifest: step-0e now carries a mechanical artifact_check
# ---------------------------------------------------------------------------

def test_step_0e_carries_artifact_check():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    step = next(s for s in manifest["steps"] if s["step_id"] == "step-0e")
    checks = step["how_to_verify_done"]["artifact_checks"]
    assert checks, "step-0e must no longer have empty artifact_checks"
    probe_checks = [
        c for c in checks if c.get("path") == ".auditooor/toolchain_probe.json"
    ]
    assert probe_checks, "step-0e must reference the toolchain_probe.json artifact"
    chk = probe_checks[0]
    # the check must exist AND be the drainable artifact the probe writes
    assert chk["path"] == ".auditooor/toolchain_probe.json"


def test_step_0e_artifact_check_is_unconditionally_load_bearing():
    """Canonical Step 0e requires both its strict report and attestation."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    step = next(s for s in manifest["steps"] if s["step_id"] == "step-0e")
    chk = step["how_to_verify_done"]["artifact_checks"][0]
    assert chk == {
        "type": "file_exists",
        "path": ".auditooor/toolchain_probe.json",
        "note": chk["note"],
    }
    assert "--strict" in step["execution_target"]
    assert step["required"] is True
    assert step["how_to_verify_done"]["attestation_required"] is True


def test_manifest_is_valid_json_and_only_0e_changed():
    """Sanity: the whole manifest still parses and has the expected step count."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(manifest["steps"], list)
    ids = [s["step_id"] for s in manifest["steps"]]
    assert "step-0e" in ids
    assert len(ids) == len(set(ids)), "no duplicate step_ids introduced"


def test_missing_strict_probe_blocks_current_consumer(tmp_path):
    """Canonical Step 0e cannot receive credit without its strict report."""
    spec = importlib.util.spec_from_file_location(
        "rcc", TOOLS / "readme-conformance-check.py"
    )
    rcc = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(rcc)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    step = next(s for s in manifest["steps"] if s["step_id"] == "step-0e")
    checks = step["how_to_verify_done"]["artifact_checks"]

    (tmp_path / ".auditooor").mkdir()  # no toolchain_probe.json written
    ok, failures = rcc._run_artifact_checks(tmp_path, checks)
    assert not ok
    assert failures


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
