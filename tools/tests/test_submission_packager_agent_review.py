#!/usr/bin/env python3
"""iter5-T1 regression tests — packager mirrors `.agent-review.md` at bundle root.

Covers (per docs/LOOP_ITER_005_PLAN.md §T1):

  1. `test_packager_mirrors_agent_review_when_present`
     — fixture has both `.agent-review.md` and `.heuristic-review.md` →
       bundle has both mirrors under `scope_review/source-draft.agent-review.md`
       and `scope_review/source-draft.heuristic-review.md`, each byte-identical
       to its source artifact.
  2. `test_packager_omits_agent_review_when_source_missing`
     — fixture has only `.heuristic-review.md` → bundle has only the
       heuristic mirror; packager does NOT synthesize an agent-review
       stub. Hard-negative lock.
  3. `test_packager_mirrors_agent_review_without_heuristic`
     — fixture has only `.agent-review.md` (no `.heuristic-review.md`) →
       bundle has the agent-review mirror; heuristic mirror is absent
       (no fabrication). Check #11 accepts either flavor.
  4. `test_check11_green_when_only_agent_review_present`
     — after packaging with only `.agent-review.md`, shell out to
       `bash tools/pre-submit-check.sh <bundle>/source-draft.md` and
       assert Check #11 emits `✅ 11.` resolving the agent-review path.

Offline. No network. Shell out to `tools/submission-packager.py` + the
pre-submit bash script against fixture bundles. Mirrors iter3-T1's
`test_submission_packager_scope_review.py` structure intentionally.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGER = ROOT / "tools" / "submission-packager.py"
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


HEURISTIC_REVIEW_FIXTURE = """# Heuristic scope review

VERDICT: NOVEL

score=2 (below SAME-CLASS threshold)
oos_overlap=none
reasoning:
- Draft does not touch any audited vector in OOS_CHECKLIST.
- Graph-query similarity score is below threshold.
- No scope-ack language detected.
"""


AGENT_REVIEW_FIXTURE = """# Agent (LLM-dispatched) scope review

VERDICT: NOVEL

analysis:
- Draft targets a vector not present in the audit OOS checklist.
- No known duplicate in the prior-art corpus.
- Proceeding to packaging.
"""


def _make_workspace(tmp: Path) -> Path:
    """Build a minimal but complete workspace layout."""
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "scope_review").mkdir(parents=True)
    # Pre-submit Check #11 walks ancestors looking for OOS_CHECKLIST.md /
    # SCOPE.md as the `_WS` anchor. Provide one at the workspace root so
    # the control path (running against the original draft) is valid too.
    (ws / "OOS_CHECKLIST.md").write_text("# Workspace OOS checklist\n")
    return ws


def _write_draft(ws: Path, name: str, body: str | None = None) -> Path:
    """Write a minimal staging draft whose basename stem != 'source-draft'."""
    draft = ws / "submissions" / "staging" / name
    text = body if body is not None else (
        "# Sample finding\n"
        "\n"
        "**Severity:** Medium\n"
        "\n"
        "## Summary\n"
        "A minimal draft used for iter5-T1 packaging regression tests.\n"
    )
    draft.write_text(text)
    return draft


def _write_heuristic_review(ws: Path, draft_stem: str, content: str | None = None) -> Path:
    review = ws / "scope_review" / f"{draft_stem}.heuristic-review.md"
    review.write_text(content if content is not None else HEURISTIC_REVIEW_FIXTURE)
    return review


def _write_agent_review(ws: Path, draft_stem: str, content: str | None = None) -> Path:
    review = ws / "scope_review" / f"{draft_stem}.agent-review.md"
    review.write_text(content if content is not None else AGENT_REVIEW_FIXTURE)
    return review


def _run_packager(
    ws: Path,
    draft_path: Path,
    *,
    skip_gates: bool = True,
) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(PACKAGER), str(ws), str(draft_path), "--json"]
    if skip_gates:
        argv.append("--skip-gates")
    return subprocess.run(argv, capture_output=True, text=True)


def _find_bundle(ws: Path) -> Path:
    pkg_root = ws / "submissions" / "packaged"
    children = [p for p in pkg_root.iterdir() if p.is_dir()]
    assert len(children) == 1, f"expected 1 packaged bundle, got {len(children)}: {children}"
    return children[0]


class AgentReviewMirroredWhenPresentTest(unittest.TestCase):
    """T1 acceptance test #1: both mirrors exist and are byte-identical to sources."""

    def test_packager_mirrors_agent_review_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar.md")
            source_heuristic = _write_heuristic_review(ws, "foo_bar")
            source_agent = _write_agent_review(ws, "foo_bar")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            bundle_review_dir = bundle / "scope_review"
            self.assertTrue(
                bundle_review_dir.is_dir(),
                f"bundle missing scope_review/ directory at {bundle_review_dir}",
            )

            # Heuristic mirror (iter3-T1 behavior preserved).
            bundle_heuristic = bundle_review_dir / "source-draft.heuristic-review.md"
            self.assertTrue(
                bundle_heuristic.is_file(),
                f"bundle missing heuristic mirror at {bundle_heuristic}",
            )
            self.assertEqual(
                bundle_heuristic.read_bytes(),
                source_heuristic.read_bytes(),
                msg="bundle-local heuristic-review diverges from source artifact",
            )

            # Agent-review mirror (iter5-T1 new behavior).
            bundle_agent = bundle_review_dir / "source-draft.agent-review.md"
            self.assertTrue(
                bundle_agent.is_file(),
                f"bundle missing agent-review mirror at {bundle_agent}",
            )
            self.assertEqual(
                bundle_agent.read_bytes(),
                source_agent.read_bytes(),
                msg="bundle-local agent-review diverges from source artifact",
            )


class AgentReviewOmittedWhenSourceMissingTest(unittest.TestCase):
    """T1 acceptance test #2: no synthesis when source is absent (hard-negative)."""

    def test_packager_omits_agent_review_when_source_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar.md")
            _write_heuristic_review(ws, "foo_bar")
            # No `.agent-review.md` written — packager must not fabricate one.

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            bundle_review_dir = bundle / "scope_review"

            # Heuristic mirror present (iter3-T1 behavior preserved).
            bundle_heuristic = bundle_review_dir / "source-draft.heuristic-review.md"
            self.assertTrue(
                bundle_heuristic.is_file(),
                "bundle missing heuristic mirror (iter3-T1 regression)",
            )

            # Agent-review mirror MUST NOT exist — no stub synthesis.
            bundle_agent = bundle_review_dir / "source-draft.agent-review.md"
            self.assertFalse(
                bundle_agent.exists(),
                msg=(
                    "packager synthesized agent-review stub despite missing "
                    f"source (hard-negative violated): {bundle_agent}"
                ),
            )


class AgentReviewMirroredWithoutHeuristicTest(unittest.TestCase):
    """T1 acceptance test #3: agent-review alone is enough — no heuristic dependency."""

    def test_packager_mirrors_agent_review_without_heuristic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar.md")
            source_agent = _write_agent_review(ws, "foo_bar")
            # No `.heuristic-review.md` written — packager must still mirror
            # the agent-review file.

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            bundle_review_dir = bundle / "scope_review"

            # Agent-review mirror present and byte-identical.
            bundle_agent = bundle_review_dir / "source-draft.agent-review.md"
            self.assertTrue(
                bundle_agent.is_file(),
                f"bundle missing agent-review mirror at {bundle_agent}",
            )
            self.assertEqual(
                bundle_agent.read_bytes(),
                source_agent.read_bytes(),
                msg="bundle-local agent-review diverges from source artifact",
            )

            # Heuristic mirror MUST NOT exist — no fabrication.
            bundle_heuristic = bundle_review_dir / "source-draft.heuristic-review.md"
            self.assertFalse(
                bundle_heuristic.exists(),
                msg=(
                    "packager synthesized heuristic-review stub despite "
                    f"missing source (hard-negative): {bundle_heuristic}"
                ),
            )


class Check11GreenWhenOnlyAgentReviewPresentTest(unittest.TestCase):
    """T1 acceptance test #4: pre-submit Check #11 resolves via agent-review."""

    def test_check11_green_when_only_agent_review_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar.md")
            _write_agent_review(ws, "foo_bar")
            # No `.heuristic-review.md` — Check #11 must resolve via the
            # `.agent-review.md` preferred branch (pre-submit.sh:315).

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            bundle_draft = bundle / "source-draft.md"
            self.assertTrue(bundle_draft.is_file(), "bundle missing source-draft.md")

            # Run pre-submit-check.sh with --severity flag (Medium per fixture)
            # to reduce noise from unrelated severity-driven checks. We only
            # care about Check #11.
            result = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(bundle_draft), "--severity", "Medium"],
                capture_output=True,
                text=True,
            )
            stdout = result.stdout
            check_11_fail_count = stdout.count("❌ 11.")
            check_11_pass_count = stdout.count("✅ 11.")
            self.assertEqual(
                check_11_fail_count, 0,
                msg=(
                    "pre-submit Check #11 failed against agent-review-only "
                    f"bundle; output=\n{stdout}\nstderr={result.stderr}"
                ),
            )
            self.assertGreaterEqual(
                check_11_pass_count, 1,
                msg=(
                    "pre-submit Check #11 did not emit a ✅ against "
                    f"agent-review-only bundle; output=\n{stdout}\n"
                    f"stderr={result.stderr}"
                ),
            )
            # Verify the source is the agent-review path, not heuristic.
            self.assertIn(
                "source: agent-review",
                stdout,
                msg=(
                    "Check #11 resolved a review but did not report "
                    f"`source: agent-review`; output=\n{stdout}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
