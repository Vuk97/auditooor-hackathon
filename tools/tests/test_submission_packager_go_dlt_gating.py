#!/usr/bin/env python3
"""NBQ-007 regression tests for Go/DLT gating-test command exactness."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGER_SRC = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    spec = importlib.util.spec_from_file_location("_packager_nbq007", PACKAGER_SRC)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PKG = _load_packager_module()


def _write_draft(ws: Path, name: str, body: str) -> Path:
    draft = ws / "submissions" / "staging" / name
    draft.parent.mkdir(parents=True, exist_ok=True)
    draft.write_text(body, encoding="utf-8")
    return draft


def _run_packager(ws: Path, draft: Path) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(PACKAGER_SRC), str(ws), str(draft), "--skip-gates", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.returncode, json.loads(proc.stdout)


class GatingCommandClassifierTest(unittest.TestCase):
    def test_classifies_exact_go_test_command(self) -> None:
        result = PKG.classify_gating_test_value("go test ./x/keeper -run TestRejectsNilValidator -count=1")
        self.assertTrue(result["executable"])
        self.assertEqual(result["classification"], "exact-command")
        self.assertEqual(result["reason"], "go-command")

    def test_classifies_prose_as_unclear(self) -> None:
        result = PKG.classify_gating_test_value("Run the DLT PoC tests in the keeper package and verify the panic.")
        self.assertFalse(result["executable"])
        self.assertEqual(result["classification"], "prose-unclear")

    def test_extracts_inline_exact_command_from_sentence(self) -> None:
        result = PKG.classify_gating_test_value("Run `go test ./x/keeper -run TestRejectsNilValidator -count=1`.")
        self.assertTrue(result["executable"])
        self.assertEqual(result["command"], "go test ./x/keeper -run TestRejectsNilValidator -count=1")

    def test_classifies_cd_then_go_test_command(self) -> None:
        result = PKG.classify_gating_test_value("cd chain && go test ./x/keeper -run TestRejectsNilValidator -count=1")
        self.assertTrue(result["executable"])
        self.assertEqual(result["classification"], "exact-command")


class GoDltGatingJsonTest(unittest.TestCase):
    def test_go_dlt_prose_gating_test_blocks_with_structured_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            draft = _write_draft(
                ws,
                "go-dlt-prose.md",
                "# Go DLT finding\n\n"
                "**Severity: Medium**\n\n"
                "Asset: Blockchain/DLT\n\n"
                "Affected file: `x/staking/keeper.go`\n\n"
                "gating_test: Run the DLT PoC tests in the keeper package and verify the panic.\n",
            )

            rc, payload = _run_packager(ws, draft)

            self.assertEqual(rc, 1)
            self.assertEqual(payload["execution_evidence"]["status"], "blocked")
            self.assertEqual(payload["execution_evidence"]["gating_tests"][0]["classification"], "prose-unclear")
            blocker_codes = {item["code"] for item in payload["execution_evidence"]["blockers"]}
            self.assertIn("go_dlt_gating_test_not_executable", blocker_codes)
            self.assertIn("blockers", payload)

    def test_go_dlt_exact_gating_test_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            draft = _write_draft(
                ws,
                "go-dlt-exact.md",
                "# Go DLT finding\n\n"
                "**Severity: Medium**\n\n"
                "Asset: Blockchain/DLT\n\n"
                "Affected file: `x/staking/keeper.go`\n\n"
                "gating_test: go test ./x/staking/keeper -run TestRejectsNilValidator -count=1\n",
            )

            rc, payload = _run_packager(ws, draft)

            self.assertEqual(rc, 0)
            evidence = payload["execution_evidence"]
            self.assertEqual(evidence["status"], "executable")
            self.assertEqual(evidence["gating_tests"][0]["classification"], "exact-command")
            manifest = Path(payload["package_dir"]) / "manifest.json"
            self.assertTrue(manifest.is_file())
            packaged = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(packaged["execution_evidence"]["status"], "executable")

    def test_solidity_foundry_draft_with_prose_gating_test_is_not_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "poc-tests").mkdir()
            (ws / "poc-tests" / "VaultPoC.t.sol").write_text(
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract VaultPoC {}\n",
                encoding="utf-8",
            )
            draft = _write_draft(
                ws,
                "foundry-prose.md",
                "# Solidity finding\n\n"
                "**Severity: Medium**\n\n"
                "Asset: Blockchain/DLT\n\n"
                "Affected contract: `src/Vault.sol`\n\n"
                "PoC: `VaultPoC.t.sol`\n\n"
                "gating_test: Run the Foundry PoC described above.\n",
            )

            rc, payload = _run_packager(ws, draft)

            self.assertEqual(rc, 0)
            self.assertEqual(payload["execution_evidence"]["status"], "not-applicable")
            self.assertFalse(payload["execution_evidence"]["applies"])


if __name__ == "__main__":
    unittest.main()
