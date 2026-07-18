#!/usr/bin/env python3
"""Regression coverage for pre-submit severity casing.

The shell wrapper keeps HIGH/CRITICAL-style uppercase severity for legacy bash
gates, but Python subtools with argparse choices expect title/lower-case
values. A `--severity CRITICAL` run must not turn into subtool "invalid choice"
noise.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


class PreSubmitSeverityNormalizationTests(unittest.TestCase):
    def _run_pre_submit(
        self,
        draft: Path,
        severity: str,
        ws: Path,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["AUDITS_DIR"] = str(ws.parent)
        env.pop("AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
            capture_output=True,
            text=True,
            env=env,
        )

    def _write_cited_source_draft(self, ws: Path, severity: str) -> Path:
        draft_dir = ws / "submissions" / "paste_ready"
        draft_dir.mkdir(parents=True)
        (ws / "SCOPE.md").write_text("In scope: src/Vault.sol\n", encoding="utf-8")
        draft = draft_dir / f"candidate-{severity.upper()}.md"
        draft.write_text(
            textwrap.dedent(
                f"""
                # Missing source-read receipt blocks {severity} filing

                **Severity:** {severity}
                **Rubric:** Direct theft of funds.

                ## Root Cause

                The vulnerable production path is `src/Vault.sol`.
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return draft

    def test_uppercase_critical_is_canonicalized_for_python_subtools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            draft_dir = ws / "submissions" / "paste_ready"
            draft_dir.mkdir(parents=True)
            (ws / "SCOPE.md").write_text("In scope: src/Vault.sol\n", encoding="utf-8")
            draft = draft_dir / "candidate-CRITICAL.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Panic in BeginBlocker leads to permanent freezing of funds

                    **Severity:** Critical
                    **Rubric:** Permanent freezing of funds.
                    **Dollar impact:** permanent chain halt.
                    **Originality:** prior audit grep run completed.
                    **In-scope:** source-level consensus bug.

                    ## Impact

                    Non-self impact demonstrated: a fresh attacker transaction
                    halts validators and freezes protocol/user funds the attacker
                    does not control.

                    ## Impact Contract

                    - Victim: validator set and protocol users
                    - Source proof: x/vault/keeper/valuation_engine.go:120
                    - Harness scaffold: poc-tests/chain_halt_test.go
                    - selected_impact: Permanent freezing of funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - evidence_class: source_review
                    - oos_traps: admin-only path excluded
                    - stop_condition: stop if production path no longer panics
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self._run_pre_submit(draft, "CRITICAL", ws)
            combined = proc.stdout + proc.stderr
            self.assertIn("Detected severity: CRITICAL", combined)
            self.assertNotIn("invalid choice", combined)

    def test_high_defaults_to_strict_source_read_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            draft = self._write_cited_source_draft(ws, "High")

            proc = self._run_pre_submit(draft, "High", ws)
            combined = proc.stdout + proc.stderr

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(
                "81. SOURCE-READ-RECEIPTS (default High/Critical cited source coverage)",
                combined,
            )
            self.assertIn(
                "81. SOURCE-READ-RECEIPTS missing or stale cited source receipts",
                combined,
            )
            self.assertIn("missing receipt: src/Vault.sol", combined)

    def test_false_env_value_does_not_disable_source_read_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            draft = self._write_cited_source_draft(ws, "High")

            proc = self._run_pre_submit(
                draft,
                "High",
                ws,
                {"AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS": "false"},
            )
            combined = proc.stdout + proc.stderr

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(
                "81. SOURCE-READ-RECEIPTS missing or stale cited source receipts",
                combined,
            )

    def test_stale_source_read_receipt_is_reported_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            draft = self._write_cited_source_draft(ws, "High")
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault {}\n", encoding="utf-8")
            receipt_dir = ws / ".auditooor"
            receipt_dir.mkdir(parents=True)
            receipt = {
                "schema": "auditooor.source_read_receipt.v1",
                "receipt_id": "stale-1",
                "workspace": str(ws),
                "file": "src/Vault.sol",
                "absolute_file_path": str(source),
                "functions_analyzed": 1,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "created_at_utc": "2026-05-19T00:00:00Z",
            }
            source.write_text("contract Vault { uint256 changed; }\n", encoding="utf-8")
            (receipt_dir / "source_read_receipts.jsonl").write_text(
                json.dumps(receipt, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            proc = self._run_pre_submit(draft, "High", ws)
            combined = proc.stdout + proc.stderr

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(
                "81. SOURCE-READ-RECEIPTS missing or stale cited source receipts",
                combined,
            )
            self.assertIn("stale=1", combined)
            self.assertIn("stale receipt: src/Vault.sol", combined)

    def test_zero_env_value_explicitly_disables_source_read_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            draft = self._write_cited_source_draft(ws, "High")

            proc = self._run_pre_submit(
                draft,
                "High",
                ws,
                {"AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS": "0"},
            )
            combined = proc.stdout + proc.stderr

            self.assertIn(
                "81. SOURCE-READ-RECEIPTS explicitly disabled by AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS=0",
                combined,
            )
            self.assertNotIn("81. SOURCE-READ-RECEIPTS missing cited source receipts", combined)

    def test_medium_skips_default_source_read_receipt_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "audits" / "demo"
            draft_dir = ws / "submissions" / "paste_ready"
            draft_dir.mkdir(parents=True)
            (ws / "SCOPE.md").write_text("In scope: src/Vault.sol\n", encoding="utf-8")
            draft = draft_dir / "candidate-MEDIUM.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Medium finding with cited source

                    **Severity:** Medium
                    **Rubric:** Temporary denial of service.

                    ## Root Cause

                    The affected production path is `src/Vault.sol`.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = self._run_pre_submit(draft, "Medium", ws)
            combined = proc.stdout + proc.stderr

            self.assertIn(
                "81. severity Medium below High",
                combined,
            )
            self.assertNotIn("81. SOURCE-READ-RECEIPTS missing cited source receipts", combined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
