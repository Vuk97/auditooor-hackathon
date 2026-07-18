"""Tests for tools/wave2-b-close-readiness.py.

Synthetic fixtures only.  Each fixture workspace is marked
``synthetic_fixture: true`` per operator emphasis.  No corpus material is
created here; the test exercises each of the six Wave-2-B close criteria
via fake workspaces and via the ``--skip-criteria`` testing knob.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-b-close-readiness.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave2_b_close_readiness", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


READINESS = _load_module()


DEFAULT_FIRMS = (
    "tob",
    "sherlock",
    "pashov",
    "zellic",
    "cyfrin",
    "spearbit",
    "chainsecurity",
    "openzeppelin",
)


def _make_fake_workspace(
    tmp: Path,
    *,
    include_w22_loader: bool = True,
    w22_loader_text: Optional[str] = None,
    firms: Iterable[str] = DEFAULT_FIRMS,
    include_vault_server: bool = True,
    vault_server_text: Optional[str] = None,
    include_dedup_detector: bool = True,
    dedup_detector_text: Optional[str] = None,
) -> Path:
    """Synthesize a workspace with just enough surface for each criterion.

    Marker: ``synthetic_fixture: true``.
    """
    ws = tmp / "ws"
    (ws / "tools" / "audit").mkdir(parents=True)
    (ws / "tools" / "tests").mkdir(parents=True)

    # Marker file (operator emphasis: synthetic fixtures must be tagged).
    (ws / "SYNTHETIC_FIXTURE.txt").write_text(
        "synthetic_fixture: true\n"
        "purpose: wave2-b-close-readiness unit-test surface\n"
    )

    # W2.2 loader.
    if include_w22_loader:
        if w22_loader_text is None:
            w22_loader_text = textwrap.dedent(
                '''
                """Stub W2.2 loader.

                Gated by AUDITOOOR_W22_PHASE1_ENABLED env flag (default OFF).
                """
                ENV_FLAG_NAME = "AUDITOOOR_W22_PHASE1_ENABLED"
                '''
            ).strip() + "\n"
        (ws / "tools" / "audit" / "wave2_w22_detector_loader.py").write_text(
            w22_loader_text
        )

    # W2.4 firm parsers.
    for firm in firms:
        (ws / "tools" / f"hackerman-etl-from-audit-firm-pdf-{firm}.py").write_text(
            f"# stub firm parser: {firm}\n"
        )

    # vault-mcp-server.py stub.
    if include_vault_server:
        if vault_server_text is None:
            vault_server_text = textwrap.dedent(
                '''
                # stub vault-mcp-server
                class _Stub:
                    def vault_corpus_freshness(self, **kwargs):
                        return {}

                    def vault_resume_context(self, **kwargs):
                        return {}

                CALLABLES = [
                    {"name": "vault_corpus_freshness"},
                    {"name": "vault_resume_context"},
                ]
                '''
            ).strip() + "\n"
        (ws / "tools" / "vault-mcp-server.py").write_text(vault_server_text)

    # Cross-firm dedup detector stub.
    if include_dedup_detector:
        if dedup_detector_text is None:
            dedup_detector_text = (
                "# stub cross-firm dedup detector\n"
                "def main():\n"
                "    pass\n"
            )
        (ws / "tools" / "wave2-cross-firm-dedup-detector.py").write_text(
            dedup_detector_text
        )

    return ws


def _stub_pass(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "status": "PASS",
        "detail": "stub",
        "evidence_ref": "stub",
    }


class TestAllCriteriaPass(unittest.TestCase):
    """All six criteria pass on a fully-stubbed workspace."""

    def test_all_pass_yields_ready_to_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(Path(tmp))
            with mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_no_pr_a_leakage",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[5]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "READY_TO_MERGE")
        self.assertEqual(payload["failures"], [])
        self.assertEqual(payload["schema"], READINESS.SCHEMA)
        self.assertEqual(payload["pr_url"], READINESS.PR_URL)


class TestCriterion1Failure(unittest.TestCase):
    """W2.2 loader file missing -> criterion 1 FAIL."""

    def test_missing_w22_loader_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(Path(tmp), include_w22_loader=False)
            with mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_no_pr_a_leakage",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[5]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "w22_detector_loader_phase1_wired", payload["failures"]
        )

    def test_w22_loader_without_env_flag_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                # Loader exists but does NOT reference the env flag.
                w22_loader_text=(
                    '"""Stub loader without the env-flag reference."""\n'
                    "VAR = 1\n"
                ),
            )
            with mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_no_pr_a_leakage",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[5]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "w22_detector_loader_phase1_wired", payload["failures"]
        )


class TestCriterion2Failure(unittest.TestCase):
    """Fewer than 7 firm parsers -> criterion 2 FAIL."""

    def test_too_few_firm_parsers_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                firms=("tob", "sherlock", "pashov"),  # only 3 firms
            )
            with mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_no_pr_a_leakage",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[5]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "w24_firm_pdf_parsers_seven_plus", payload["failures"]
        )


class TestCriterion3Failure(unittest.TestCase):
    """vault_corpus_freshness callable missing from vault-mcp-server.py."""

    def test_missing_callable_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                vault_server_text=(
                    "# stub vault-mcp-server without vault_corpus_freshness\n"
                    "class _Stub:\n"
                    "    def vault_resume_context(self, **kwargs):\n"
                    "        return {}\n"
                    'CALLABLES = [{"name": "vault_resume_context"}]\n'
                ),
            )
            with mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_no_pr_a_leakage",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[5]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "w28_vault_corpus_freshness_callable_wired",
            payload["failures"],
        )


class TestCriterion6Leakage(unittest.TestCase):
    """Criterion 6 FAIL when PR-A dependency phrase detected in a commit
    body, and PASS when allowlist phrase ('does not depend on') is also
    present."""

    def test_dependency_phrase_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(Path(tmp))
            fake_commits = [
                {
                    "sha": "abc1234",
                    "body": (
                        "Wave-2-B intro commit that depends on Phase-3 "
                        "migration landing first."
                    ),
                },
            ]
            with mock.patch.object(
                READINESS,
                "_branch_commit_messages",
                return_value=fake_commits,
            ), mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn("no_pr_a_dependency_leakage", payload["failures"])

    def test_allowlist_phrase_keeps_close_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(Path(tmp))
            fake_commits = [
                {
                    "sha": "def4567",
                    "body": (
                        "Wave-2-B: this PR does not depend on Phase-3 "
                        "migration; PR-B is independently mergeable."
                    ),
                },
            ]
            with mock.patch.object(
                READINESS,
                "_branch_commit_messages",
                return_value=fake_commits,
            ), mock.patch.object(
                READINESS,
                "check_criterion_5_firm_regression",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[4]),
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "READY_TO_MERGE")


class TestStrictExitCode(unittest.TestCase):
    """--strict returns 1 on BLOCKED/PARTIAL, 0 on READY_TO_MERGE."""

    def _patch_eval(self, overall: str, failures=None, skipped=None):
        return mock.patch.object(
            READINESS,
            "evaluate",
            return_value={
                "schema": READINESS.SCHEMA,
                "branch": "x",
                "head_sha": "x",
                "pr_url": READINESS.PR_URL,
                "overall_status": overall,
                "criteria": [],
                "failures": failures or [],
                "passes": [],
                "skipped": skipped or [],
            },
        )

    def test_strict_exits_zero_on_ready(self):
        with self._patch_eval("READY_TO_MERGE"):
            rc = READINESS.main(["--json", "--strict"])
        self.assertEqual(rc, 0)

    def test_strict_exits_one_on_blocked(self):
        with self._patch_eval(
            "BLOCKED", failures=["w22_detector_loader_phase1_wired"]
        ):
            rc = READINESS.main(["--json", "--strict"])
        self.assertEqual(rc, 1)

    def test_strict_exits_one_on_partial(self):
        with self._patch_eval(
            "PARTIAL", skipped=["w24_firm_parser_regression_pass"]
        ):
            rc = READINESS.main(["--json", "--strict"])
        self.assertEqual(rc, 1)


class TestSkipCriteria(unittest.TestCase):
    """--skip-criteria marks criteria SKIPPED and yields PARTIAL when no
    failures are present."""

    def test_skip_yields_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(Path(tmp))
            with mock.patch.object(
                READINESS,
                "check_criterion_6_no_pr_a_leakage",
                return_value=_stub_pass(READINESS.CRITERION_NAMES[5]),
            ):
                payload = READINESS.evaluate(
                    ws,
                    skip_criteria={
                        READINESS.CRITERION_NAMES[4],
                    },
                )
        self.assertEqual(payload["overall_status"], "PARTIAL")
        self.assertIn(
            "w24_firm_parser_regression_pass", payload["skipped"]
        )

    def test_unknown_skip_name_returns_error(self):
        rc = READINESS.main(
            ["--json", "--skip-criteria", "no_such_criterion"]
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
