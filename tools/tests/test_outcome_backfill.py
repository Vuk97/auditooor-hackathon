#!/usr/bin/env python3
"""PR 9 (wave 8) — outcome + duplicate learning backfill regression tests.

Locked invariants the tests must maintain:

  1. The `backfill` subcommand materializes one outcome row per spec record
     when the spec is well-formed (5-row baseline test).
  2. Hidden-duplicate-root semantics: when a spec row carries
     `final_triager_outcome=duplicate_of_accepted` plus
     `original_visibility=hidden`, the materialized row preserves both keys
     and the renderer surfaces the row in the dup-root surfacing block.
  3. Same with `duplicate_of_rejected`.
  4. paste-ready-generator surfaces a dup-root block when a back-filled row
     matches the draft's title.
  5. adversarial-copilot's `--surface-duplicate-root` flag emits the dup-root
     surfacing block for a workspace with back-filled rows and emits an
     empty-state line otherwise.

Tests are stdlib-only (no pytest) so they match the existing
`tools/tests/*` style used by tracker / outcome-telemetry / paste-ready
regressions. The track-submissions module is loaded via importlib because
the source file uses a hyphenated name.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
TRACK_TOOL = TOOLS_DIR / "track-submissions.py"
ADVERSARIAL_TOOL = TOOLS_DIR / "adversarial-copilot.py"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_track_submissions():
    spec = importlib.util.spec_from_file_location(
        "track_submissions_pr9", TRACK_TOOL
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_paste_ready():
    spec_path = TOOLS_DIR / "paste-ready-generator.py"
    spec = importlib.util.spec_from_file_location(
        "paste_ready_generator_pr9", spec_path
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------

# A 5-row synthetic SUBMISSIONS.md backfill spec covering accepted, rejected,
# pending, withdrawn, and a duplicate_of_<x> case. Matches the JSONL schema
# the `backfill` subcommand consumes.
SYNTHETIC_SPEC_BASE: List[Dict[str, Any]] = [
    {
        "draft_id": "syn-pr9-1",
        "report_id": "SYN-1",
        "workspace": "synthetic-ws",
        "platform": "cantina",
        "title": "Synthetic accepted finding (token-supply truncation)",
        "lane": "source-mine",
        "model_route": "operator+codex",
        "proof_artifact": "syn/proof_1.md",
        "production_path_blockers_cleared": "yes",
        "final_triager_outcome": "accepted",
        "outcome_evidence_path": "syn/triager_reply_1.md",
        "severity_filed": "High",
        "severity_accepted": "High",
        "recorded_at": "2026-04-20T00:00:00Z",
        "resolved_at": "2026-04-22T00:00:00Z",
    },
    {
        "draft_id": "syn-pr9-2",
        "report_id": "SYN-2",
        "workspace": "synthetic-ws",
        "platform": "cantina",
        "title": "Synthetic rejected finding (cosmetic event mis-indexing)",
        "lane": "source-mine",
        "model_route": "operator+codex",
        "proof_artifact": "syn/proof_2.md",
        "production_path_blockers_cleared": "no",
        "final_triager_outcome": "rejected",
        "outcome_evidence_path": "syn/rejection_2.md",
        "severity_filed": "Low",
        "recorded_at": "2026-04-20T00:00:00Z",
        "resolved_at": "2026-04-22T00:00:00Z",
    },
    {
        "draft_id": "syn-pr9-3",
        "report_id": "SYN-3",
        "workspace": "synthetic-ws",
        "platform": "cantina",
        "title": "Synthetic pending finding awaiting triage",
        "lane": "source-mine",
        "model_route": "operator+codex",
        "proof_artifact": "syn/proof_3.md",
        "production_path_blockers_cleared": "unknown",
        "final_triager_outcome": "pending",
        "outcome_evidence_path": "syn/staging_3.md",
        "severity_filed": "Medium",
        "recorded_at": "2026-04-21T00:00:00Z",
    },
    {
        "draft_id": "syn-pr9-4",
        "report_id": "SYN-4",
        "workspace": "synthetic-ws",
        "platform": "other",
        "title": "Synthetic operator-withdrawn pre-submit",
        "lane": "source-mine",
        "model_route": "operator+codex",
        "proof_artifact": "syn/proof_4.md",
        "production_path_blockers_cleared": "no",
        "final_triager_outcome": "withdrawn",
        "outcome_evidence_path": "syn/withdraw_4.md",
        "severity_filed": "Low",
        "recorded_at": "2026-04-21T00:00:00Z",
        "resolved_at": "2026-04-21T00:00:00Z",
    },
    {
        "draft_id": "syn-pr9-5",
        "report_id": "SYN-5",
        "workspace": "synthetic-ws",
        "platform": "cantina",
        "title": "Synthetic duplicate-of-accepted (hidden parent)",
        "lane": "source-mine",
        "model_route": "operator+codex",
        "proof_artifact": "syn/proof_5.md",
        "production_path_blockers_cleared": "yes",
        "final_triager_outcome": "duplicate_of_accepted",
        "original_visibility": "hidden",
        "outcome_evidence_path": "syn/dup_evidence_5.md",
        "severity_filed": "Medium",
        "recorded_at": "2026-04-22T00:00:00Z",
    },
]


def _write_spec(tmpdir: Path, records: List[Dict[str, Any]]) -> Path:
    path = tmpdir / "spec.jsonl"
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n"
    )
    return path


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class FiveRowMaterializationTest(unittest.TestCase):
    """Lock the 5-row baseline: every well-formed spec row materializes one
    outcome row, fields preserved."""

    def setUp(self) -> None:
        self.mod = _load_track_submissions()
        self.tmp = Path(tempfile.mkdtemp(prefix="pr9_backfill_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_five_row_baseline_materializes(self) -> None:
        spec_path = _write_spec(self.tmp, SYNTHETIC_SPEC_BASE)
        ledger = self.tmp / "outcomes.jsonl"
        rc = self.mod.main([
            "backfill",
            "--spec", str(spec_path),
            "--ledger-path", str(ledger),
        ])
        self.assertEqual(rc, 0)
        rows = _read_jsonl(ledger)
        self.assertEqual(len(rows), 5)
        outcomes = sorted(r["outcome"] for r in rows)
        self.assertEqual(
            outcomes,
            ["accepted", "duplicate_of_accepted", "pending", "rejected",
             "withdrawn"],
        )
        # Every row carries the rich PR 9 fields, including the linkage set.
        for row in rows:
            self.assertIn("draft_id", row)
            self.assertIn("lane", row)
            self.assertIn("model_route", row)
            self.assertIn("proof_artifact", row)
            self.assertIn("production_path_blockers_cleared", row)
            self.assertIn("final_triager_outcome", row)
            self.assertIn("outcome_evidence_path", row)
            self.assertIn("severity_filed", row)
            self.assertIn("backfilled_at", row)

    def test_invalid_spec_refuses_with_exit_2(self) -> None:
        bad = list(SYNTHETIC_SPEC_BASE)
        bad[0] = dict(bad[0])
        bad[0].pop("lane")
        spec_path = _write_spec(self.tmp, bad)
        ledger = self.tmp / "outcomes.jsonl"
        rc = self.mod.main([
            "backfill",
            "--spec", str(spec_path),
            "--ledger-path", str(ledger),
        ])
        self.assertEqual(rc, 2)
        self.assertFalse(ledger.exists() and ledger.stat().st_size > 0)

    def test_dup_root_state_requires_visibility(self) -> None:
        bad = list(SYNTHETIC_SPEC_BASE)
        bad_dup = dict(bad[4])
        bad_dup.pop("original_visibility")
        bad[4] = bad_dup
        spec_path = _write_spec(self.tmp, bad)
        ledger = self.tmp / "outcomes.jsonl"
        rc = self.mod.main([
            "backfill",
            "--spec", str(spec_path),
            "--ledger-path", str(ledger),
        ])
        self.assertEqual(rc, 2)


class HiddenDuplicateRootSemanticsTest(unittest.TestCase):
    """Lock the hidden-parent semantics: visible parent state determines the
    dup-root outcome; the row preserves `original_visibility=hidden`."""

    def setUp(self) -> None:
        self.mod = _load_track_submissions()
        self.tmp = Path(tempfile.mkdtemp(prefix="pr9_dup_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _materialize(self, parent_outcome: str) -> Dict[str, Any]:
        record = dict(SYNTHETIC_SPEC_BASE[4])  # duplicate_of_accepted base
        record["draft_id"] = f"dup-of-{parent_outcome}"
        record["report_id"] = f"DUP-{parent_outcome.upper()}"
        record["title"] = (
            f"Synthetic duplicate of {parent_outcome} parent (hidden)"
        )
        record["final_triager_outcome"] = f"duplicate_of_{parent_outcome}"
        record["original_visibility"] = "hidden"
        sub = self.tmp / parent_outcome
        sub.mkdir(parents=True, exist_ok=True)
        spec_path = _write_spec(sub, [record])
        ledger = sub / "outcomes.jsonl"
        rc = self.mod.main([
            "backfill",
            "--spec", str(spec_path),
            "--ledger-path", str(ledger),
        ])
        self.assertEqual(rc, 0)
        rows = _read_jsonl(ledger)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_visible_parent_accepted_produces_duplicate_of_accepted(self) -> None:
        row = self._materialize("accepted")
        self.assertEqual(row["outcome"], "duplicate_of_accepted")
        self.assertEqual(row["final_triager_outcome"], "duplicate_of_accepted")
        self.assertEqual(row["original_visibility"], "hidden")
        # Collapse-to-simple should bucket as accepted for legacy readers.
        self.assertEqual(
            self.mod.collapse_duplicate_root(row["outcome"]), "accepted"
        )
        self.assertTrue(self.mod.is_duplicate_root(row["outcome"]))

    def test_visible_parent_rejected_produces_duplicate_of_rejected(self) -> None:
        row = self._materialize("rejected")
        self.assertEqual(row["outcome"], "duplicate_of_rejected")
        self.assertEqual(row["final_triager_outcome"], "duplicate_of_rejected")
        self.assertEqual(row["original_visibility"], "hidden")
        self.assertEqual(
            self.mod.collapse_duplicate_root(row["outcome"]), "rejected"
        )

    def test_render_duplicate_root_summary_surfaces_both_cases(self) -> None:
        rows = [
            self._materialize("accepted"),
            self._materialize("rejected"),
        ]
        rendered = self.mod.render_duplicate_root_summary(rows)
        self.assertIn("Duplicate-Root Status", rendered)
        self.assertIn("duplicate_of_accepted", rendered)
        self.assertIn("duplicate_of_rejected", rendered)
        self.assertIn("hidden", rendered)
        # Surfaces the inherited bucket so reviewers can read at a glance.
        self.assertIn("| accepted |", rendered)
        self.assertIn("| rejected |", rendered)

    def test_render_skips_plain_rows(self) -> None:
        plain_row = {
            "outcome": "rejected", "report_id": "SYN-2", "title": "x",
        }
        rendered = self.mod.render_duplicate_root_summary([plain_row])
        self.assertEqual(rendered, "")


class DuplicateRootStatusCommandTest(unittest.TestCase):
    """Lock the `duplicate-root-status` subcommand surfaces the same content
    as the in-process renderer."""

    def setUp(self) -> None:
        self.mod = _load_track_submissions()
        self.tmp = Path(tempfile.mkdtemp(prefix="pr9_dup_cmd_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_command_emits_block_with_dup_rows(self) -> None:
        spec_path = _write_spec(self.tmp, SYNTHETIC_SPEC_BASE)
        ledger = self.tmp / "outcomes.jsonl"
        self.mod.main([
            "backfill",
            "--spec", str(spec_path),
            "--ledger-path", str(ledger),
        ])
        result = subprocess.run(
            [
                sys.executable, str(TRACK_TOOL),
                "duplicate-root-status",
                "--ledger-path", str(ledger),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Duplicate-Root Status", result.stdout)
        self.assertIn("duplicate_of_accepted", result.stdout)

    def test_command_json_returns_structured_payload(self) -> None:
        spec_path = _write_spec(self.tmp, SYNTHETIC_SPEC_BASE)
        ledger = self.tmp / "outcomes.jsonl"
        self.mod.main([
            "backfill",
            "--spec", str(spec_path),
            "--ledger-path", str(ledger),
        ])
        result = subprocess.run(
            [
                sys.executable, str(TRACK_TOOL),
                "duplicate-root-status",
                "--ledger-path", str(ledger),
                "--json",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("duplicate_root_rows", payload)
        outcomes = sorted(d["outcome"] for d in payload["duplicate_root_rows"])
        self.assertEqual(outcomes, ["duplicate_of_accepted"])


class PasteReadyDuplicateRootIntegrationTest(unittest.TestCase):
    """Lock paste-ready surfaces the dup-root block when a back-filled row
    matches the draft's title."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pr9_paste_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        # Synthetic workspace under a controllable parent so paste-ready's
        # `_resolve_central_ledger` can be redirected via a stand-in
        # AUDITOOOR_DIR. Easiest path: build a fake repo root with a
        # `reference/outcomes.jsonl` pointing at our row.
        self.fake_repo = self.tmp / "fake_repo"
        (self.fake_repo / "reference").mkdir(parents=True)
        (self.fake_repo / "tools").mkdir(parents=True)
        # Copy the real track-submissions.py into the fake repo so the
        # importlib loader can find it under <fake_repo>/tools/.
        shutil.copy2(TRACK_TOOL, self.fake_repo / "tools" / "track-submissions.py")
        # Build a workspace named `wave8-syn` whose draft heading matches a
        # back-filled row's title.
        self.workspace = self.fake_repo / "audits" / "wave8-syn"
        (self.workspace / "submissions").mkdir(parents=True)
        # Materialize a duplicate_of_accepted row tied to workspace=wave8-syn.
        record = dict(SYNTHETIC_SPEC_BASE[4])
        record["workspace"] = "wave8-syn"
        record["title"] = "wave8-syn duplicate of accepted parent token"
        ledger = self.fake_repo / "reference" / "outcomes.jsonl"
        spec = _write_spec(self.tmp, [record])
        mod = _load_track_submissions()
        mod.main([
            "backfill",
            "--spec", str(spec),
            "--ledger-path", str(ledger),
        ])
        self.ledger = ledger

    def test_paste_ready_dup_root_block_matches_workspace_row(self) -> None:
        # Reload paste-ready with AUDITOOOR_DIR pointing at the fake repo.
        # We do that by injecting the path then re-importing.
        import importlib
        spec = importlib.util.spec_from_file_location(
            "_pr9_paste_ready_test",
            TOOLS_DIR / "paste-ready-generator.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        # Override the constants the module uses.
        mod.AUDITOOOR_DIR = self.fake_repo
        # Clear the lazy-load cache so the next call sees the fresh fake.
        sys.modules.pop("_paste_ready_track_submissions_lib", None)

        draft = self.workspace / "submissions" / "test_draft.md"
        draft.write_text(textwrap.dedent("""
            # H1 — wave8-syn duplicate of accepted parent token

            ## Program Impact Mapping
            - mapping body
            ## Production Path
            1. step one
            ## Source-only Justification
            justification
        """).strip() + "\n")
        rendered = mod._render_duplicate_root_block_for_draft(
            self.workspace, draft
        )
        self.assertIn("Duplicate-Root Status", rendered)
        self.assertIn("duplicate_of_accepted", rendered)

    def test_paste_ready_dup_root_block_empty_when_no_match(self) -> None:
        import importlib
        spec = importlib.util.spec_from_file_location(
            "_pr9_paste_ready_test_nomatch",
            TOOLS_DIR / "paste-ready-generator.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        mod.AUDITOOOR_DIR = self.fake_repo
        sys.modules.pop("_paste_ready_track_submissions_lib", None)

        draft = self.workspace / "submissions" / "unrelated.md"
        draft.write_text("# Completely Unrelated Heading XYZQQQ\n\nbody\n")
        rendered = mod._render_duplicate_root_block_for_draft(
            self.workspace, draft
        )
        self.assertEqual(rendered, "")


class AdversarialCopilotDuplicateRootIntegrationTest(unittest.TestCase):
    """Lock adversarial-copilot's --surface-duplicate-root flag returns the
    expected block (or empty-state) for a workspace."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pr9_adv_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.workspace = self.tmp / "polymarket"
        (self.workspace / "agent_outputs").mkdir(parents=True)
        # Build a synthetic ledger row whose workspace matches.
        record = dict(SYNTHETIC_SPEC_BASE[4])
        record["workspace"] = "polymarket"
        record["title"] = "polymarket dup-root regression target"
        spec = _write_spec(self.tmp, [record])
        self.ledger = self.tmp / "outcomes.jsonl"
        mod = _load_track_submissions()
        mod.main([
            "backfill",
            "--spec", str(spec),
            "--ledger-path", str(self.ledger),
        ])

    def test_surface_flag_emits_block(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(ADVERSARIAL_TOOL),
                str(self.workspace),
                "--surface-duplicate-root",
                "--ledger-path", str(self.ledger),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Duplicate-Root Status", result.stdout)
        self.assertIn("duplicate_of_accepted", result.stdout)
        self.assertIn("hidden", result.stdout)

    def test_surface_flag_empty_state_for_unrelated_workspace(self) -> None:
        empty_ws = self.tmp / "unrelated-ws"
        (empty_ws / "agent_outputs").mkdir(parents=True)
        result = subprocess.run(
            [
                sys.executable, str(ADVERSARIAL_TOOL),
                str(empty_ws),
                "--surface-duplicate-root",
                "--ledger-path", str(self.ledger),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no duplicate-root rows", result.stdout)


class CollapseAndIsDuplicateRootHelpersTest(unittest.TestCase):
    """Lock the small helpers used by readers."""

    def setUp(self) -> None:
        self.mod = _load_track_submissions()

    def test_collapse_duplicate_root_known_states(self) -> None:
        self.assertEqual(self.mod.collapse_duplicate_root("duplicate_of_accepted"), "accepted")
        self.assertEqual(self.mod.collapse_duplicate_root("duplicate_of_rejected"), "rejected")
        self.assertEqual(self.mod.collapse_duplicate_root("withdrawn"), "rejected")
        # Plain states pass through unchanged.
        self.assertEqual(self.mod.collapse_duplicate_root("accepted"), "accepted")
        self.assertEqual(self.mod.collapse_duplicate_root("pending"), "pending")
        self.assertEqual(self.mod.collapse_duplicate_root("duplicate"), "duplicate")

    def test_is_duplicate_root_filter(self) -> None:
        self.assertTrue(self.mod.is_duplicate_root("duplicate_of_accepted"))
        self.assertTrue(self.mod.is_duplicate_root("duplicate_of_rejected"))
        self.assertFalse(self.mod.is_duplicate_root("duplicate"))
        self.assertFalse(self.mod.is_duplicate_root("accepted"))
        self.assertFalse(self.mod.is_duplicate_root("withdrawn"))


if __name__ == "__main__":
    unittest.main()
