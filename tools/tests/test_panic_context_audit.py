"""Unit tests for panic-context audit preflight."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "panic-context-audit.py"
_spec = importlib.util.spec_from_file_location("panic_context_audit", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_case(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="panic_context_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _draft(*, severity: str = "High", body: str = "") -> str:
    return f"Severity: {severity}\n\n{body}\n"


class PanicContextScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="The transaction panics during FinalizeBlock.",
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_without_live_panic_claim_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(body="The user can withdraw unclaimed yield."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_triggers_gate(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="Validator halt claim: panic: context canceled during t.Cleanup.",
            ),
            filename="draft.md",
        )
        rc, payload = mod.run(draft, severity_override="High", strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")
        self.assertEqual(payload["verdict"], "fail-teardown-contaminated-panic")


class PanicContextPositiveTests(unittest.TestCase):
    def test_stable_goroutine_dump_passes_even_with_cleanup_terms(self) -> None:
        draft = _write_case(
            _draft(
                severity="Critical",
                body=(
                    "Validator halt during Commit: panic: unlock of unlocked mutex.\n"
                    "A stable goroutine dump was captured before cleanup and shows no progress for 30s.\n"
                    "The stack trace points to production source before test cleanup starts."
                ),
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-stable-panic-evidence")
        self.assertTrue(payload["evidence"]["stable_evidence_hits"])

    def test_no_teardown_contamination_passes(self) -> None:
        draft = _write_case(
            _draft(
                body="Network-level liveness failure: panic: nil pointer dereference in FinalizeBlock.",
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-teardown-contamination")

    def test_rebuttal_marker_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "<!-- panic-context-rebuttal: cleanup token appears only in copied harness footer; "
                    "the panic timestamp is before cleanup. -->\n"
                    "Consensus halt panic: context canceled appears after the captured stack trace."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_stable_panic_evidence_in_log_file_passes(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="panic_context_log_"))
        ws = root / "audits" / "demo"
        logs = ws / "logs"
        logs.mkdir(parents=True)
        (logs / "panic.log").write_text(
            "goroutine dump: same stack for 60s before teardown\npanic: unlock of unlocked mutex\n",
            encoding="utf-8",
        )
        draft = ws / "submissions" / "draft-HIGH.md"
        draft.parent.mkdir(parents=True)
        draft.write_text(
            _draft(body="Transcript: logs/panic.log\nValidator halt during Commit."),
            encoding="utf-8",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-stable-panic-evidence")
        self.assertTrue(payload["evidence"]["scanned_files"])


class PanicContextNegativeTests(unittest.TestCase):
    def test_teardown_contaminated_panic_fails(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Network-level validator halt: panic: unlock of unlocked mutex.\n"
                    "The transcript also shows context canceled and t.Cleanup after db.Close()."
                )
            )
        )
        rc, payload = mod.run(draft, strict=False)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-teardown-contaminated-panic")
        self.assertTrue(payload["evidence"]["teardown_hits"])

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class PanicContextCliTests(unittest.TestCase):
    def test_cli_emits_json_and_nonzero_for_violation(self) -> None:
        draft = _write_case(_draft(body="Chain halt panic: EOF during test cleanup."))
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--strict", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "auditooor.panic_context_audit.v1")
        self.assertEqual(payload["verdict"], "fail-teardown-contaminated-panic")
        self.assertTrue(payload["strict"])


if __name__ == "__main__":
    unittest.main()
