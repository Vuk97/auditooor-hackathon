"""Regression tests for finding-quality-scorer Rust/DLT draft support."""

from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "finding-quality-scorer.py"
ENGAGE = ROOT / "tools" / "engage.py"


def _load_engage():
    tools_dir = str(ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage_quality_drafts_under_test", ENGAGE)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FindingQualityScorerTests(unittest.TestCase):
    def test_rust_dlt_poc_and_citations_score_as_strong_draft(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            harness = ws / "poc-tests" / "fn7" / "Cargo.toml"
            harness.parent.mkdir(parents=True)
            harness.write_text("[package]\nname = \"fn7\"\nversion = \"0.1.0\"\n")
            draft = ws / "draft.md"
            draft.write_text(
                """
**Severity (RECOMMENDED)**: High

## Summary

Per the rubric, this maps to High because the in-scope Engine API accepts an
invalid withdrawals_root and propagates a bad output_root/rootClaim while the
fault-proof layer remains the catch-net. $125,000 USDC High pool impact.

`external/base/crates/execution/node/src/engine.rs:130` returns Ok on parent
state miss. `external/base/crates/consensus/engine/src/query.rs:104` trusts the
header withdrawals_root. `external/base/crates/proof/proposer/src/output_proposer.rs:113`
submits the rootClaim.

## PoC

`poc-tests/fn7/Cargo.toml`

```text
cargo test --manifest-path poc-tests/fn7/Cargo.toml
test result: ok. 4 passed; 0 failed
```

## Production Path

Attacker can provide a malformed child payload on the normal in-scope Engine API
path. This does not rely on privileged admin action, no private key compromise,
and no role bypass. The output_root/rootClaim state assertion is the impact.

## Originality Check

Originality check passed; this is a novel and different vector.
"""
            )
            proc = subprocess.run(
                ["python3", str(TOOL), str(ws), str(draft), "--json"],
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(proc.stdout)
            self.assertGreaterEqual(payload["total_score"], 70)
            self.assertGreaterEqual(payload["dimensions"]["poc_quality"]["score"], 15)
            self.assertGreaterEqual(payload["dimensions"]["description_clarity"]["score"], 8)

    def test_engage_quality_collects_paste_ready_and_final_cantina_paste(self) -> None:
        mod = _load_engage()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            for lane in ("paste_ready", "final_cantina_paste"):
                d = ws / "submissions" / lane
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{lane}.md").write_text("# Finding\n\nSeverity: High\n")
            (ws / "submissions" / "final_cantina_paste" / "OOS_CHECK.md").write_text(
                "# Generated OOS sidecar\n"
            )
            drafts = mod._collect_quality_drafts(ws)
            self.assertEqual(
                {p.parent.name for p in drafts},
                {"paste_ready", "final_cantina_paste"},
            )
            self.assertNotIn("OOS_CHECK.md", {p.name for p in drafts})
            self.assertEqual(mod._collect_staging_drafts(ws), [])

    def test_engage_dispatch_resolves_nested_contract_roots(self) -> None:
        mod = _load_engage()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            root = ws / "external" / "reserve-governor" / "contracts"
            target = root / "staking" / "StakingVault.sol"
            target.parent.mkdir(parents=True)
            target.write_text("contract StakingVault {}\n", encoding="utf-8")
            meta = ws / ".auditooor"
            meta.mkdir(parents=True)
            (meta / "project_source_root_readiness.json").write_text(
                json.dumps(
                    {
                        "roots": [
                            {
                                "resolved_path": str(root),
                                "ready": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            resolved = mod._resolve_workspace_contract_path(
                ws, "contracts/staking/StakingVault.sol"
            )

            self.assertEqual(resolved, target.resolve())

    def test_engage_slither_python_autodetects_homebrew_python(self) -> None:
        mod = _load_engage()

        def fake_run(cmd, timeout, capture=True):
            py = cmd[0]
            if "python@3.13" in py:
                return 0, "", ""
            return 1, "", "no slither"

        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(mod, "run", side_effect=fake_run):
            py, rc, _so, _se = mod._select_slither_python()

        self.assertEqual(rc, 0)
        self.assertIn("python@3.13", py)

    def test_engage_slither_python_prefers_env_override(self) -> None:
        mod = _load_engage()
        calls = []

        def fake_run(cmd, timeout, capture=True):
            calls.append(cmd[0])
            return (0, "", "") if cmd[0] == "/custom/slither-python" else (1, "", "no slither")

        with mock.patch.dict(os.environ, {"AUDITOOOR_PYTHON_SLITHER": "/custom/slither-python"}, clear=True), \
                mock.patch.object(mod, "run", side_effect=fake_run):
            py, rc, _so, _se = mod._select_slither_python()

        self.assertEqual(rc, 0)
        self.assertEqual(py, "/custom/slither-python")
        self.assertEqual(calls[0], "/custom/slither-python")


if __name__ == "__main__":
    unittest.main()
