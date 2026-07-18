#!/usr/bin/env python3
"""Regression coverage for pre-submit impact-contract gating."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _run(draft: Path, audits_dir: Path) -> subprocess.CompletedProcess[str]:
    audits_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(audits_dir)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


def _draft(include_impact_contract: bool, include_non_self: bool = False) -> str:
    lines = [
        "# Replay bug in Vault allows draining user funds",
        "",
        "**Severity:** High",
        "**Rubric:** Direct theft of user funds.",
        "**Dollar impact:** $500,000 of user funds.",
        "**Originality:** prior audit grep run completed.",
        "**In-scope:** source-level accounting bug.",
        "",
        "## Impact",
        "",
        "The attacker drains user funds from the vault.",
        "",
    ]
    if include_non_self:
        lines.extend(
            [
                "Non-self impact demonstrated: victim LP funds are debited, and funds the attacker does not control are transferred.",
                "",
            ]
        )
    lines.extend(
        [
        "## In-Scope Trigger / Root Cause",
        "",
        "A non-privileged attacker can replay `withdraw()` before accounting settles.",
        "",
        ]
    )
    if include_impact_contract:
        lines.extend(
            [
                "## Impact Contract",
                "",
                "- Victim: vault LPs",
                "- Source proof: src/Vault.sol:90-138",
                "- Harness scaffold: poc-tests/VaultRacePlan.t.sol",
                "- selected_impact: Direct theft of user funds",
                "- severity_tier: High",
                "- listed_impact_proven: true",
                "- evidence_class: forge_test",
                "- oos_traps: admin-only path excluded",
                "- stop_condition: stop if forge PoC no longer drains funds",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


class PreSubmitImpactContractTests(unittest.TestCase):
    def test_missing_explicit_contract_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "missing.md"
            draft.write_text(_draft(include_impact_contract=False), encoding="utf-8")
            proc = _run(draft, root / "audits")
            self.assertIn("41. impact-contract-missing", proc.stdout, proc.stdout)

    def test_explicit_contract_marks_check_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "explicit.md"
            draft.write_text(_draft(include_impact_contract=True), encoding="utf-8")
            proc = _run(draft, root / "audits")
            self.assertIn("41. Impact-contract preflight:", proc.stdout, proc.stdout)
            self.assertIn("impact-contract-explicit", proc.stdout, proc.stdout)

    def test_missing_non_self_impact_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "missing-nonself.md"
            draft.write_text(_draft(include_impact_contract=True), encoding="utf-8")
            proc = _run(draft, root / "audits")
            self.assertIn("62. R24-NON-SELF-IMPACT-REQUIRED blocked", proc.stdout, proc.stdout)

    def test_explicit_non_self_impact_marks_check_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "explicit-nonself.md"
            draft.write_text(
                _draft(include_impact_contract=True, include_non_self=True),
                encoding="utf-8",
            )
            proc = _run(draft, root / "audits")
            self.assertIn("62. R24-NON-SELF-IMPACT-REQUIRED:", proc.stdout, proc.stdout)
            self.assertIn("pass-non-self-impact", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
