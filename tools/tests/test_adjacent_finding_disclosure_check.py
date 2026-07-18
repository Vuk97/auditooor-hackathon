#!/usr/bin/env python3
"""Unit tests for Rule 27 adjacent-finding disclosure preflight."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "adjacent-finding-disclosure-check.py"
_spec = importlib.util.spec_from_file_location("adjacent_finding_disclosure_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_case(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r27_adjacent_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _draft(*, severity: str = "High", body: str = "") -> str:
    return f"Severity: {severity}\n\n{body}\n"


class AdjacentFindingDisclosureScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="A sibling path is also vulnerable and will be handled in a follow-up report.",
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_without_adjacent_language_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(body="The bug freezes victim withdrawals via this single path."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_negative_scope_adjacent_phrase_is_ignored(self) -> None:
        draft = _write_case(_draft(body="No adjacent finding is claimed; the report covers one path."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_triggers_gate(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="Another vulnerable path exists but is not covered in this report.",
            ),
            filename="draft.md",
        )
        rc, payload = mod.run(draft, severity_override="Critical", strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")
        self.assertEqual(payload["verdict"], "fail-adjacent-disclosure-missing")


class AdjacentFindingDisclosurePositiveTests(unittest.TestCase):
    def test_bounded_adjacent_disclosure_section_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "The same root cause appears near a sibling withdrawal path.\n\n"
                    "## Adjacent Finding Disclosure\n\n"
                    "- Adjacent path reviewed: `keeper/withdraw.go:88`.\n"
                    "- Filing boundary: this report covers both withdraw and transfer variants.\n"
                    "- Status: covered in this report; no separate report will be filed."
                ),
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-adjacent-disclosure-bounded")
        self.assertTrue(payload["evidence"]["boundary_hits"])

    def test_enumerated_call_sites_with_boundary_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Additional vulnerable call site was found during grep.\n\n"
                    "## Enumerated Call Sites\n\n"
                    "| Site | Status |\n"
                    "|---|---|\n"
                    "| `x/a.go:1` | covered in this report |\n"
                    "| `x/b.go:2` | different guard covers |\n"
                ),
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-adjacent-disclosure-bounded")

    def test_rebuttal_marker_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "<!-- r27-rebuttal: adjacent phrase quotes triager comment; no sibling vector is disclosed. -->\n"
                    "The triager asked about adjacent finding disclosure."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


class AdjacentFindingDisclosureNegativeTests(unittest.TestCase):
    def test_high_adjacent_followup_language_fails_without_boundary(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "The root cause also affects another vulnerable path in the same module. "
                    "We will leave that for a follow-up report."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-adjacent-disclosure-missing")
        self.assertTrue(payload["evidence"]["trigger_hits"])

    def test_hidden_adjacent_leak_in_poc_transcript_fails(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="r27_adjacent_poc_"))
        ws = root / "audits" / "demo"
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "poc-tests" / "case").mkdir(parents=True)
        (ws / "poc-tests" / "case" / "poc.log").write_text(
            "PASS: same root cause also affects sibling path and separate report will cover it\n",
            encoding="utf-8",
        )
        draft = ws / "submissions" / "paste_ready" / "draft-HIGH.md"
        draft.write_text(_draft(body="PoC: `poc-tests/case`"), encoding="utf-8")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-adjacent-disclosure-missing")
        self.assertIn("poc.log", payload["evidence"]["trigger_hits"][0]["source"])

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class AdjacentFindingDisclosureCliTests(unittest.TestCase):
    def test_cli_emits_json_and_nonzero_for_violation(self) -> None:
        draft = _write_case(_draft(body="A future report will cover the sibling path."))
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--strict", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "auditooor.adjacent_finding_disclosure_check.v1")
        self.assertEqual(payload["verdict"], "fail-adjacent-disclosure-missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
