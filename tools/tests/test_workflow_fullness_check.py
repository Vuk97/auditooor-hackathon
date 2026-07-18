#!/usr/bin/env python3
# r36-rebuttal: lane pathspec registered via tools/agent-pathspec-register.py to agent_pathspec.json
"""Tests for tools/workflow-fullness-check.py (Gap #39)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# r36-rebuttal: lane pathspec registered via tools/agent-pathspec-register.py to agent_pathspec.json
REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "workflow-fullness-check.py"

# Import the tool as a module (its name contains a hyphen, so we must use
# importlib explicitly). Python 3.14 requires the module be registered in
# sys.modules BEFORE exec_module so dataclass introspection succeeds.
_spec = importlib.util.spec_from_file_location(
    "workflow_fullness_check", str(TOOL_PATH)
)
assert _spec is not None and _spec.loader is not None
wfc = importlib.util.module_from_spec(_spec)
sys.modules["workflow_fullness_check"] = wfc
_spec.loader.exec_module(wfc)  # type: ignore[union-attr]


class _Tmp:
    """Small filesystem fixture helper."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)

    def cleanup(self) -> None:
        self.tmp.cleanup()

    def workspace(self) -> Path:
        ws = self.path / "ws"
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        return ws

    def draft(self, body: str, name: str = "draft.md") -> Path:
        ws = self.workspace()
        p = ws / name
        p.write_text(body, encoding="utf-8")
        return p

    def workflow_log(self, rows: list[dict]) -> Path:
        ws = self.workspace()
        log = ws / ".auditooor" / "workflow_invocation_log.jsonl"
        log.write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
        )
        return log


def _clear_env() -> None:
    for k in [
        "AUDITOOOR_GAP39_FULLNESS_PHRASES",
        "AUDITOOOR_GAP39_FULL_ENGINES",
        "AUDITOOOR_GAP39_WORKFLOW_LOG",
    ]:
        os.environ.pop(k, None)


class TestVerdicts(unittest.TestCase):
    def setUp(self) -> None:  # noqa: D401
        _clear_env()
        self.fx = _Tmp()

    def tearDown(self) -> None:
        self.fx.cleanup()
        _clear_env()

    # ------------------------------------------------------------------
    # PASS verdicts
    # ------------------------------------------------------------------

    def test_pass_out_of_scope_no_fullness_phrase(self) -> None:
        draft = self.fx.draft("# Finding\n\nNo fullness phrases here.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "pass-out-of-scope")
        self.assertEqual(v.draft.fullness_phrases_hit, [])

    def test_pass_cheap_path_acknowledged_marker(self) -> None:
        draft = self.fx.draft(
            "# F\n\nFull audit complete --cheap-path-acknowledged.\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "pass-cheap-path-acknowledged")

    def test_pass_full_workflow_evidence_all_engines_ran(self) -> None:
        self.fx.workflow_log(
            [
                {"tool": "halmos-runner", "status": "ok"},
                {"tool": "medusa-fuzz", "status": "ok"},
                {"tool": "echidna-campaign", "status": "ok"},
            ]
        )
        draft = self.fx.draft(
            "# F\n\nDeep audit complete on Hyperbridge surface.\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "pass-full-workflow-evidence")
        self.assertEqual(v.workflow.missing_engines, [])

    def test_pass_full_workflow_evidence_alt_status_terms(self) -> None:
        """`status` accepts ok/success/ran/completed (case-insensitive)."""
        self.fx.workflow_log(
            [
                {"tool": "halmos-runner", "status": "SUCCESS"},
                {"step": "medusa-fuzz", "status": "ran"},
                {"name": "echidna-campaign", "status": "Completed"},
            ]
        )
        draft = self.fx.draft("# F\n\ncomprehensive analysis.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "pass-full-workflow-evidence")

    # ------------------------------------------------------------------
    # REBUTTAL verdict
    # ------------------------------------------------------------------

    def test_ok_rebuttal_visible_line(self) -> None:
        draft = self.fx.draft(
            "# F\n\nComprehensive review of the bridge logic.\n"
            "gap39-rebuttal: operator-attested cheap-path with prior coverage\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "ok-rebuttal")
        self.assertIsNotNone(v.draft.rebuttal)

    def test_ok_rebuttal_html_comment(self) -> None:
        draft = self.fx.draft(
            "# F\n\nfully audited via static path.\n"
            "<!-- gap39-rebuttal: operator scoped to static-only batch -->\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "ok-rebuttal")

    def test_rebuttal_oversized_ignored(self) -> None:
        big = "x" * 250
        draft = self.fx.draft(
            f"# F\n\nfull audit complete.\n<!-- gap39-rebuttal: {big} -->\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        # Oversized rebuttal => ignored, fail verdict stands.
        self.assertTrue(v.verdict.startswith("fail"))
        self.assertTrue(v.draft.rebuttal_oversized)

    def test_rebuttal_empty_ignored(self) -> None:
        draft = self.fx.draft(
            "# F\n\nfull audit complete.\n<!-- gap39-rebuttal:    -->\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertTrue(v.verdict.startswith("fail"))

    # ------------------------------------------------------------------
    # FAIL verdicts
    # ------------------------------------------------------------------

    def test_fail_no_log_at_all(self) -> None:
        draft = self.fx.draft("# F\n\nFull audit complete on dydx scope.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(
            v.verdict, "fail-workflow-cheap-default-without-acknowledgement"
        )
        self.assertFalse(v.workflow.log_exists)

    def test_fail_log_present_engines_missing(self) -> None:
        self.fx.workflow_log(
            [{"tool": "halmos-runner", "status": "ok"}]
        )
        draft = self.fx.draft(
            "# F\n\nall engines ran successfully on the bridge.\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(
            v.verdict, "fail-workflow-cheap-default-without-acknowledgement"
        )
        self.assertIn("medusa-fuzz", v.workflow.missing_engines)
        self.assertIn("echidna-campaign", v.workflow.missing_engines)

    def test_fail_log_present_engines_skipped(self) -> None:
        self.fx.workflow_log(
            [
                {"tool": "halmos-runner", "status": "skipped"},
                {"tool": "medusa-fuzz", "status": "blocked"},
                {"tool": "echidna-campaign", "status": "skipped"},
            ]
        )
        draft = self.fx.draft(
            "# F\n\nthoroughly audited via static + dynamic.\n"
        )
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(
            v.verdict, "fail-workflow-cheap-default-without-acknowledgement"
        )

    # ------------------------------------------------------------------
    # ERROR verdicts
    # ------------------------------------------------------------------

    def test_error_draft_missing(self) -> None:
        nonexistent = self.fx.path / "no-such-draft.md"
        v = wfc.evaluate(nonexistent, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "error")
        self.assertIn("does not exist", v.reason)

    # ------------------------------------------------------------------
    # Env hooks
    # ------------------------------------------------------------------

    def test_env_extends_fullness_phrases(self) -> None:
        os.environ["AUDITOOOR_GAP39_FULLNESS_PHRASES"] = "drilled to bedrock"
        draft = self.fx.draft("# F\n\nWe drilled to bedrock on this one.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(
            v.verdict, "fail-workflow-cheap-default-without-acknowledgement"
        )

    def test_env_overrides_full_engines(self) -> None:
        os.environ["AUDITOOOR_GAP39_FULL_ENGINES"] = "mythril\nmanticore"
        self.fx.workflow_log(
            [
                {"tool": "mythril", "status": "ok"},
                {"tool": "manticore", "status": "ok"},
            ]
        )
        draft = self.fx.draft("# F\n\nfull audit complete.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "pass-full-workflow-evidence")

    def test_env_workflow_log_override(self) -> None:
        custom = self.fx.path / "alt_log.jsonl"
        custom.write_text(
            "\n".join(
                json.dumps({"tool": e, "status": "ok"})
                for e in ("halmos-runner", "medusa-fuzz", "echidna-campaign")
            ),
            encoding="utf-8",
        )
        os.environ["AUDITOOOR_GAP39_WORKFLOW_LOG"] = str(custom)
        draft = self.fx.draft("# F\n\nfull audit complete.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        self.assertEqual(v.verdict, "pass-full-workflow-evidence")

    # ------------------------------------------------------------------
    # JSON schema
    # ------------------------------------------------------------------

    def test_to_dict_carries_schema(self) -> None:
        draft = self.fx.draft("# F\n\nplain finding.\n")
        v = wfc.evaluate(draft, workspace=self.fx.workspace())
        d = v.to_dict()
        self.assertEqual(d["schema"], wfc.SCHEMA)
        self.assertIn("evidence", d)
        self.assertIn("draft", d["evidence"])
        self.assertIn("workflow", d["evidence"])


class TestExitCodes(unittest.TestCase):
    def test_exit_codes_pass(self) -> None:
        self.assertEqual(wfc._verdict_exit_code("pass-out-of-scope"), 0)
        self.assertEqual(wfc._verdict_exit_code("ok-rebuttal"), 0)
        self.assertEqual(
            wfc._verdict_exit_code("pass-full-workflow-evidence"), 0
        )

    def test_exit_codes_fail(self) -> None:
        self.assertEqual(
            wfc._verdict_exit_code(
                "fail-workflow-cheap-default-without-acknowledgement"
            ),
            1,
        )

    def test_exit_codes_error(self) -> None:
        self.assertEqual(wfc._verdict_exit_code("error"), 2)


if __name__ == "__main__":
    unittest.main()
