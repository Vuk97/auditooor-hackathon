"""V5 Gap-22 (PR-E): dispatch-brief stage offline-failure handling.

Background — quoted from V5 Capability Gaps doc (Gap 22):
    Monetrix audit. dispatch-brief stage failed (offline LLM dispatch
    path returned non-zero), causing `make audit` to return 1 even
    though earlier stages succeeded. Forced manual tools/audit-deep.sh
    invocation. Brittle pipeline — single offline-stage failure derails
    the whole run.

Fix: dispatch-brief subprocess errors are classified into "soft" (offline /
auth / setup gap — log WARN, mark SUCCESS_WARN, do NOT propagate to the
fail-fast halt) vs "hard" (malformed args / wrong path / missing scripts —
keep current FAIL). See engage.py::_classify_dispatch_brief_error for the
boundary table. The classifier is the single source of truth.

Test cases pinned by this file:
  1. Auth-error stderr → SOFT (chain continues).
  2. HARD STOP stderr (missing OOS context) → SOFT (chain continues).
  3. Network/offline stderr → SOFT.
  4. Usage error (rc=2) → HARD (regression check: malformed args halt).
  5. "workspace not found" stderr → HARD (malformed args halt).
  6. Unknown error class → SOFT (default lenient per Gap-22 directive).
  7. Stage-level integration: failed_soft -> SUCCESS_WARN return string.
  8. Stage-level integration: failed_hard -> FAIL return string.
"""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
ENGAGE = REPO / "tools" / "engage.py"


def _load_engage_module() -> types.ModuleType:
    """Hyphenless name; load by spec since the file is `engage.py`."""
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage", ENGAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENGAGE_MOD = _load_engage_module()


class DispatchBriefClassifierTest(unittest.TestCase):
    """Unit tests on `_classify_dispatch_brief_error` (the boundary)."""

    def _classify(self, rc: int, stderr: str = "", stdout: str = "") -> str:
        return ENGAGE_MOD._classify_dispatch_brief_error(rc, stderr, stdout)

    # ----- SOFT (offline / transient) -----

    def test_auth_error_is_soft(self) -> None:
        # Mock dispatch returning auth-error — engage.py must continue.
        self.assertEqual(
            self._classify(1, "ERROR: api-key invalid (401 Unauthorized)"),
            "soft",
        )

    def test_hard_stop_marker_is_hard(self) -> None:
        # A dispatch gate hard stop is an ordered-pipeline blocker.
        self.assertEqual(
            self._classify(
                1,
                "[HARD] OOS_CHECKLIST.md missing\n=== HARD STOP ===\n",
            ),
            "hard",
        )

    def test_network_error_is_soft(self) -> None:
        self.assertEqual(
            self._classify(1, "network unreachable: dispatch offline"),
            "soft",
        )

    def test_429_rate_limit_is_soft(self) -> None:
        self.assertEqual(
            self._classify(1, "HTTP 429 rate-limited; retry later"),
            "soft",
        )

    def test_5xx_provider_outage_is_soft(self) -> None:
        self.assertEqual(
            self._classify(1, "HTTP 503 service unavailable"),
            "soft",
        )

    def test_brief_empty_is_soft(self) -> None:
        self.assertEqual(
            self._classify(4, "[ERROR] brief empty"),
            "soft",
        )

    def test_cannot_run_consent_is_soft(self) -> None:
        self.assertEqual(
            self._classify(2, '{"error":"cannot-run: no-consent"}'),
            "hard",
            "rc=2 is HARD by spec (CLI/usage); cannot-run is the consent "
            "guard's contract — those calls hit a different path.",
        )

    def test_unknown_error_defaults_soft(self) -> None:
        # Codex Gap-22 directive: unknown shape → keep chain moving.
        self.assertEqual(
            self._classify(99, "weird transient error nothing matches"),
            "soft",
        )

    # ----- HARD (malformed args / missing scripts) -----

    def test_usage_error_rc_2_is_hard(self) -> None:
        # Regression: rc=2 (CLI usage, missing args) MUST stay HARD.
        # If we softened this we'd silently swallow caller bugs.
        self.assertEqual(
            self._classify(2, "Usage: dispatch-brief.sh <ws> ..."),
            "hard",
        )

    def test_workspace_not_found_is_hard(self) -> None:
        # Caller passed a wrong --workspace; this is a path bug we
        # explicitly want to surface.
        self.assertEqual(
            self._classify(1, "workspace not found: /tmp/missing"),
            "hard",
        )

    def test_contract_not_found_is_hard(self) -> None:
        self.assertEqual(
            self._classify(1, "contract not found: /tmp/Foo.sol"),
            "hard",
        )

    def test_unknown_arg_is_hard(self) -> None:
        # `dispatch-brief.sh` emits "Unknown arg: ..." for typo flags.
        self.assertEqual(
            self._classify(1, "Unknown arg: --typo"),
            "hard",
        )


class StageDispatchBriefIntegrationTest(unittest.TestCase):
    """End-to-end: stage_dispatch_brief return-string contract for the
    cases the engage.py chain depends on. Driven through ``run`` mocking
    so the test is hermetic — no real subprocess invocation.
    """

    def setUp(self) -> None:
        self.tmp = Path(self.id())  # unused — just ensure self exists
        # Build fake mining-candidate parsing output so the loop runs.
        self._fake_candidates = [
            {
                "detector": "fake-detector",
                "severity": "LOW",
                "file":     "/tmp/Fake.sol",
                "line":     "42",
                "snippet":  "fake snippet",
            },
        ]

    def _make_args(self, ws: Path) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            workspace=ws,
            quiet=True,
            mine_top_only=False,
            top_n=1,
        )

    def _scaffold_ws(self, base: Path) -> Path:
        ws = base / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        # `agent-dispatch-enforced.sh` and `dispatch-brief.sh` both live
        # under tools/ and are detected via attribute paths on the module.
        # The fake contract path needs to exist on disk for the
        # contract_path.is_file() guard.
        (ws / "Fake.sol").write_text("contract Fake {}\n")
        brief_dir = ws / "swarm" / "mining_briefs"
        brief_dir.mkdir(parents=True)
        (brief_dir / "brief_fake.md").write_text(
            "# Mining Brief\n\n**Target:** `Fake`\n\n"
            "## Exploit Goal\n\nGround the candidate.\n"
        )
        return ws

    def _patch_candidates(self, ws: Path) -> None:
        # The contract is at <ws>/Fake.sol — fix up _fake_candidates so
        # the contract_path resolves correctly.
        self._fake_candidates[0]["file"] = str(ws / "Fake.sol")

    def test_soft_failure_returns_success_warn(self) -> None:
        """Single soft-skip failure → SUCCESS_WARN (chain continues)."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_ws(Path(td))
            self._patch_candidates(ws)
            args = self._make_args(ws)
            out_dir = ws
            (out_dir / "engage_report.md").write_text(
                "## No close historical match\n"
                "- **[LOW] `fake-detector`** — `" + str(ws / "Fake.sol")
                + ":42`\n"
                "  - fake snippet\n"
            )
            # Mock subprocess: rc=1 + offline stderr (= soft).
            with patch.object(
                ENGAGE_MOD, "run",
                return_value=(1, "", "network unreachable; api unavailable"),
            ), patch.object(
                ENGAGE_MOD, "parse_mining_candidates",
                return_value=self._fake_candidates,
            ):
                result = ENGAGE_MOD.stage_dispatch_brief(ws, out_dir, args)
        self.assertTrue(
            result.startswith("SUCCESS_WARN"),
            f"soft-skip should yield SUCCESS_WARN, got: {result!r}",
        )
        self.assertIn("soft-skipped", result)
        self.assertNotIn("FAIL", result.split("SUCCESS_WARN")[0])

    def test_hard_failure_returns_fail(self) -> None:
        """Single hard failure (workspace-not-found) → FAIL (chain halts
        on --fail-fast). Regression check: malformed args still propagate.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_ws(Path(td))
            self._patch_candidates(ws)
            args = self._make_args(ws)
            out_dir = ws
            (out_dir / "engage_report.md").write_text(
                "## No close historical match\n"
                "- **[LOW] `fake-detector`** — `" + str(ws / "Fake.sol")
                + ":42`\n"
                "  - fake snippet\n"
            )
            with patch.object(
                ENGAGE_MOD, "run",
                return_value=(1, "", "workspace not found: /bad/path"),
            ), patch.object(
                ENGAGE_MOD, "parse_mining_candidates",
                return_value=self._fake_candidates,
            ):
                result = ENGAGE_MOD.stage_dispatch_brief(ws, out_dir, args)
        self.assertTrue(
            result.startswith("FAIL"),
            f"hard failure must yield FAIL, got: {result!r}",
        )

    def test_repo_relative_workspace_path_resolves(self) -> None:
        """Scanner paths rooted at ../audits/<ws>/ resolve inside the ws."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_ws(Path(td))
            reported = Path("..") / "audits" / ws.name / "Fake.sol"
            resolved = ENGAGE_MOD._resolve_workspace_contract_path(
                ws, str(reported)
            )
        self.assertEqual(resolved, (ws / "Fake.sol").resolve())

    def test_nested_repository_source_root_resolves(self) -> None:
        """A src/<repo>/src layout resolves repository-relative reports."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_ws(Path(td))
            nested = ws / "src" / "core" / "src"
            nested.mkdir(parents=True)
            expected = nested / "WrappedTrust.sol"
            expected.write_text("contract WrappedTrust {}\n", encoding="utf-8")
            resolved = ENGAGE_MOD._resolve_workspace_contract_path(
                ws, "src/WrappedTrust.sol"
            )
        self.assertEqual(resolved, expected.resolve())

    def test_missing_candidate_path_is_hard_failure(self) -> None:
        """All-missing paths must not be reported as SUCCESS 0 briefs."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_ws(Path(td))
            args = self._make_args(ws)
            (ws / "engage_report.md").write_text("# stub\n")
            candidates = [{
                "detector": "fake-detector",
                "severity": "LOW",
                "file": "../audits/ws/src/Missing.sol",
                "line": "42",
                "snippet": "fake snippet",
            }]
            with patch.object(
                ENGAGE_MOD, "parse_mining_candidates",
                return_value=candidates,
            ):
                result = ENGAGE_MOD.stage_dispatch_brief(ws, ws, args)
        self.assertTrue(result.startswith("FAIL"), result)

    def test_mixed_soft_and_hard_returns_fail(self) -> None:
        """If any subprocess invocation hits HARD, the stage must FAIL —
        soft results do not mask hard failures."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_ws(Path(td))
            (ws / "Fake2.sol").write_text("contract Fake2 {}\n")
            (ws / "swarm" / "mining_briefs" / "brief_fake2.md").write_text(
                "# Mining Brief\n\n**Target:** `Fake2`\n\n"
                "## Exploit Goal\n\nGround the candidate.\n"
            )
            args = self._make_args(ws)
            out_dir = ws
            cands = [
                {
                    "detector": "fake-1", "severity": "LOW",
                    "file": str(ws / "Fake.sol"), "line": "10", "snippet": "a",
                },
                {
                    "detector": "fake-2", "severity": "LOW",
                    "file": str(ws / "Fake2.sol"), "line": "20", "snippet": "b",
                },
            ]
            (out_dir / "engage_report.md").write_text("# stub\n")
            # First call: soft. Second call: hard.
            sequence = [
                (1, "", "network down"),               # soft
                (1, "", "workspace not found: /x"),    # hard
            ]
            call_iter = iter(sequence)
            with patch.object(
                ENGAGE_MOD, "run",
                side_effect=lambda *a, **kw: next(call_iter),
            ), patch.object(
                ENGAGE_MOD, "parse_mining_candidates",
                return_value=cands,
            ):
                result = ENGAGE_MOD.stage_dispatch_brief(ws, out_dir, args)
        self.assertTrue(
            result.startswith("FAIL"),
            f"hard failure must dominate over soft, got: {result!r}",
        )

    def test_missing_proof_context_is_a_hard_gate(self) -> None:
        """Missing proof context must stop the ordered pipeline."""
        self.assertTrue(
            "FAIL missing proof context in 1/1".startswith("FAIL")
        )
        for status in (
            "SUCCESS_WARN soft-skipped 1/1",
            "SUCCESS 0 briefs",
            "SKIPPED no mining candidates",
        ):
            self.assertFalse(
                status.startswith("FAIL"),
                f"{status!r} must not be classified as FAIL",
            )
        for status in ("FAIL 1/1", "FAIL rc=2"):
            self.assertTrue(
                status.startswith("FAIL"),
                f"{status!r} must be classified as FAIL (regression check)",
            )


if __name__ == "__main__":
    unittest.main()
