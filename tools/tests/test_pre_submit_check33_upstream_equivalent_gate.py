#!/usr/bin/env python3
"""Check #33 regressions for the UPSTREAM-EQUIVALENT-GATE wrapper in
pre-submit-check.sh (Wave J-1A / Wave K-1).

The shell-side wrapper:
  * walks `<workspace>/.auditooor/**/promotion_candidates.json` (depth 4),
  * runs `tools/upstream-equivalent-gate.py --max-queries 0 --print-json` on
    each (Step 5 / gh search disabled to keep the gate offline-safe),
  * accumulates `walked_back_count` across all candidate files,
  * emits one of:
      - `33. UPSTREAM-EQUIVALENT-GATE advisory` (no candidate files),
      - `33. UPSTREAM-EQUIVALENT-GATE pass`     (all rows promotion_allowed),
      - `33. UPSTREAM-EQUIVALENT-GATE warn`     (>=1 walkback, default),
      - `33. UPSTREAM-EQUIVALENT-GATE blocked`  (>=1 walkback, STRICT=1).

These tests pin the four edge shapes by constructing a synthetic
workspace tree and running the gate end-to-end via bash.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
GATE = ROOT / "tools" / "upstream-equivalent-gate.py"


def _run_pre_submit(
    draft: Path,
    workspace: Path,
    severity: str = "Medium",
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["WS"] = str(workspace)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True,
        text=True,
        env=env,
    )


def _make_workspace(tmp: Path) -> Path:
    """Construct a minimal audit workspace with SCOPE.md / SEVERITY.md / asset."""
    ws = tmp / "ws"
    (ws / "external" / "asset" / "src").mkdir(parents=True)
    (ws / ".auditooor").mkdir()
    (ws / "external" / "asset" / "src" / "real.rs").write_text(
        "// Long enough source line to exceed the gate's 100-char content threshold "
        "so step-2 line-content matching has something substantive to match against.\n"
        "fn verify(x: u64) -> bool {\n"
        "    x == 0\n"
        "}\n",
        encoding="utf-8",
    )
    (ws / "SCOPE.md").write_text(
        "# Scope\n\nIn scope: external/asset/.\n\n## Out of Scope\n- private_keys\n",
        encoding="utf-8",
    )
    (ws / "SEVERITY.md").write_text(
        "# Severity\n\n### Critical\n- Direct loss of funds.\n\n### Medium\n- Minor.\n",
        encoding="utf-8",
    )
    return ws


def _draft(tmp: Path, workspace: Path) -> Path:
    """Minimal Medium draft inside the workspace tree (so the walk-up
    workspace-resolution heuristic in pre-submit-check.sh finds SCOPE.md)."""
    sub_dir = workspace / "submissions"
    sub_dir.mkdir(parents=True, exist_ok=True)
    d = sub_dir / "draft.md"
    d.write_text(
        textwrap.dedent(
            """
            # Synthetic test draft for Check #33 regressions

            **Severity:** Medium

            **Rubric:** Minor.

            ## Impact

            This is a synthetic draft used by the Check #33 wrapper smoke
            test. It is not meant to pass every other check.

            ## Description

            See pre-submit-check Check #33.
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return d


class Check33UpstreamEquivalentGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(PRE_SUBMIT.is_file(), f"missing {PRE_SUBMIT}")
        self.assertTrue(GATE.is_file(), f"missing {GATE}")

    def test_advisory_when_no_candidates_present(self) -> None:
        """Workspace with no promotion_candidates.json → advisory line."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            draft = _draft(tmp_path, ws)
            proc = _run_pre_submit(draft, ws)
            self.assertIn(
                "33. UPSTREAM-EQUIVALENT-GATE advisory",
                proc.stdout,
                proc.stdout,
            )

    def test_pass_when_all_rows_allowed(self) -> None:
        """Candidate row with file present + content match + in-scope path → pass."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            draft = _draft(tmp_path, ws)
            cand_dir = ws / ".auditooor" / "wave-test-pass"
            cand_dir.mkdir(parents=True)
            (cand_dir / "promotion_candidates.json").write_text(
                json.dumps({
                    "wave": "TEST",
                    "candidates": [
                        {
                            "row_index": 1,
                            "file": "external/asset/src/real.rs",
                            "line": 1,
                            "evidence_snippet": "Long enough source line to exceed the gate's 100-char content threshold",
                            "severity_tier": "Medium",
                            "selected_impact": "Minor.",
                        }
                    ],
                }),
                encoding="utf-8",
            )
            proc = _run_pre_submit(draft, ws)
            self.assertIn(
                "33. UPSTREAM-EQUIVALENT-GATE pass",
                proc.stdout,
                proc.stdout,
            )

    def test_warn_default_on_walkback(self) -> None:
        """Candidate citing a non-existent path → walkback → WARN by default."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            draft = _draft(tmp_path, ws)
            cand_dir = ws / ".auditooor" / "wave-test-walkback"
            cand_dir.mkdir(parents=True)
            (cand_dir / "promotion_candidates.json").write_text(
                json.dumps({
                    "wave": "TEST",
                    "candidates": [
                        {
                            "row_index": 99,
                            "file": "external/asset/src/does_not_exist.rs",
                            "line": 1,
                            "evidence_snippet": "ghost",
                            "severity_tier": "Critical",
                            "selected_impact": "Direct loss of funds.",
                        }
                    ],
                }),
                encoding="utf-8",
            )
            proc = _run_pre_submit(draft, ws)
            self.assertIn(
                "33. UPSTREAM-EQUIVALENT-GATE warn",
                proc.stdout,
                proc.stdout,
            )
            # Must NOT have escalated to a hard FAIL by default.
            self.assertNotIn(
                "33. UPSTREAM-EQUIVALENT-GATE blocked",
                proc.stdout,
                proc.stdout,
            )

    def test_strict_env_blocks_walkback(self) -> None:
        """STRICT_UPSTREAM_EQUIVALENT_GATE=1 turns walkback into hard FAIL."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            draft = _draft(tmp_path, ws)
            cand_dir = ws / ".auditooor" / "wave-test-strict"
            cand_dir.mkdir(parents=True)
            (cand_dir / "promotion_candidates.json").write_text(
                json.dumps({
                    "wave": "TEST",
                    "candidates": [
                        {
                            "row_index": 99,
                            "file": "external/asset/src/does_not_exist.rs",
                            "line": 1,
                            "evidence_snippet": "ghost",
                            "severity_tier": "Critical",
                            "selected_impact": "Direct loss of funds.",
                        }
                    ],
                }),
                encoding="utf-8",
            )
            proc = _run_pre_submit(
                draft, ws, extra_env={"STRICT_UPSTREAM_EQUIVALENT_GATE": "1"}
            )
            self.assertIn(
                "33. UPSTREAM-EQUIVALENT-GATE blocked",
                proc.stdout,
                proc.stdout,
            )
            # A blocked Check #33 must contribute to non-zero exit code.
            self.assertNotEqual(proc.returncode, 0, proc.stdout)

    def test_finalizer_count_updated_to_33(self) -> None:
        """The 'ALL N CHECKS PASSED' finalizer must say 33, not 32."""
        text = PRE_SUBMIT.read_text(encoding="utf-8")
        self.assertIn("ALL 33 CHECKS PASSED", text)
        self.assertNotIn("ALL 32 CHECKS PASSED", text)


if __name__ == "__main__":
    unittest.main()
