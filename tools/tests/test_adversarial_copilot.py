#!/usr/bin/env python3
"""Offline tests for tools/adversarial-copilot.py (PR 204 skeleton).

All subprocess / swarm-orchestrator calls are patched out. These tests MUST
run without network, without foundry, and without a real swarm dispatch.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "adversarial-copilot.py"


def _load_copilot_module():
    """Import adversarial-copilot.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location("adversarial_copilot", TOOL)
    assert spec and spec.loader, "adversarial-copilot.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


COPILOT = _load_copilot_module()


SAMPLE_NOT_A_BUG_MD = """\
# Agent analysis: vault reentrancy angle

Traced the suspect callback path. Downstream mutex guards the state write.

VERDICT: NOT-A-BUG — reentry re-enters into a view function only.
"""

SAMPLE_MALFORMED_MD = """\
MALFORMED AGENT OUTPUT — this file has no VERDICT line at all.
Just some prose.
"""


def _mk_agent_output(ws: Path, name: str, body: str) -> Path:
    agent_dir = ws / "agent_outputs"
    agent_dir.mkdir(parents=True, exist_ok=True)
    p = agent_dir / name
    p.write_text(body, encoding="utf-8")
    return p


class AdversarialCopilotTest(unittest.TestCase):
    # ------------------------------------------------------------------
    # Test 1 — break verdict seeds a new angle in mining_priorities.json
    # ------------------------------------------------------------------
    def test_copilot_breaks_verdict_seeds_new_angle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "angle01.md", SAMPLE_NOT_A_BUG_MD)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                # Co-pilot literally says "VERDICT CONTESTED".
                self.assertFalse(live, "offline tests must stay in --dry-run")
                return (
                    "VERDICT CONTESTED: the mutex is held only on the happy "
                    "path; attacker can race via the refund branch.",
                    "dry-run",
                )

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_BREAK)

            # Break artifact exists in agent_outputs/.
            adv = ws / "agent_outputs" / f"adversarial_{COPILOT.slug_from_path(src)}.md"
            self.assertTrue(adv.is_file(), f"expected break artifact at {adv}")
            self.assertIn("VERDICT CONTESTED", adv.read_text())

            # Angle seeded into <ws>/mining_priorities.json.
            prio = ws / "mining_priorities.json"
            self.assertTrue(prio.is_file(), "mining_priorities.json must exist after break")
            data = json.loads(prio.read_text())
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 1)
            row = data[0]
            self.assertEqual(row["source"], "adversarial-copilot")
            self.assertEqual(row["angle"]["category"], "A-ADVERSARIAL")
            self.assertTrue(row["angle"]["id"].startswith("ADV-"))

    # ------------------------------------------------------------------
    # Test 2 — hold verdict appends to provisional_non_bugs.md with marker
    # ------------------------------------------------------------------
    def test_copilot_cannot_break_verdict_writes_provisional(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "angle02.md", SAMPLE_NOT_A_BUG_MD)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return (
                    "VERDICT HOLDS: invariant checked-effects-interactions "
                    "at src/Vault.sol:142",
                    "dry-run",
                )

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_HOLD)

            prov = ws / "reference" / "provisional_non_bugs.md"
            self.assertTrue(prov.is_file(), "provisional_non_bugs.md must be created")
            text = prov.read_text()
            # Required human-review marker must be present in the row.
            self.assertIn(COPILOT.HUMAN_REVIEW_MARKER, text)
            # Row must reference the hold status and the slug.
            self.assertIn(COPILOT.STATUS_HOLD, text)
            self.assertIn(COPILOT.slug_from_path(src), text)
            # No break artifact should have been written.
            adv = ws / "agent_outputs" / f"adversarial_{COPILOT.slug_from_path(src)}.md"
            self.assertFalse(adv.is_file(), "hold path must not write adversarial_*.md")

    # ------------------------------------------------------------------
    # Test 3 — malformed input → SKIPPED, no writes
    # ------------------------------------------------------------------
    def test_copilot_malformed_agent_output_exits_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "angle03.md", SAMPLE_MALFORMED_MD)

            called = {"n": 0}

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                called["n"] += 1
                return ("VERDICT CONTESTED: should never run", "dry-run")

            status, reason = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_SKIPPED)
            self.assertIsNotNone(reason)
            self.assertIn("malformed", reason or "")
            # Dispatcher must not have been called for malformed input.
            self.assertEqual(called["n"], 0)
            # No side-effect files created.
            self.assertFalse((ws / "mining_priorities.json").exists())
            self.assertFalse((ws / "reference" / "provisional_non_bugs.md").exists())
            # Also verify the end-to-end entrypoint exits cleanly (rc 0, not error).
            rc = COPILOT.main([str(ws)])
            self.assertEqual(rc, 0, "SKIPPED-only runs must exit 0, not error")

    # ------------------------------------------------------------------
    # Test 4 (regression, PR 204 truth-audit) — no writes to submissions/ready/
    # ------------------------------------------------------------------
    def test_copilot_never_writes_to_submissions_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Pre-create submissions/ready/ to make an accidental write obvious.
            ready = ws / "submissions" / "ready"
            ready.mkdir(parents=True)
            src = _mk_agent_output(ws, "angle04.md", SAMPLE_NOT_A_BUG_MD)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT CONTESTED: attacker drains via fallback", "dry-run")

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_BREAK)
            # Guard: submissions/ directory must remain empty (aside from the
            # empty ready/ dir we pre-created).
            submissions_files = list((ws / "submissions").rglob("*"))
            file_entries = [p for p in submissions_files if p.is_file()]
            self.assertEqual(
                file_entries, [],
                f"adversarial-copilot must never write under submissions/; "
                f"found: {file_entries}",
            )

            # And: the _guard_target() primitive itself must refuse a forced
            # submissions-path write.
            with self.assertRaises(ValueError) as ctx:
                COPILOT._guard_target(ws, ws / "submissions" / "ready" / "x.md")
            self.assertIn("submissions", str(ctx.exception))

    # ==================================================================
    # Iter-v3-2 T1 grammar-extension tests (4 new).
    # ==================================================================

    # ------------------------------------------------------------------
    # Test 5 — heading-form verdict: ``## Verdict: Not a bug`` must parse.
    # ------------------------------------------------------------------
    def test_grammar_heading_verdict_form_parsed(self) -> None:
        body = (
            "# R99-X — some draft\n\n"
            "## Candidate\n\n"
            "Some narrative.\n\n"
            "## Verdict: Not a bug\n\n"
            "The invariant in src/Foo.sol:42 prevents it.\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "heading_form.md", body)
            # Grammar: must NOT be classified as malformed.
            self.assertFalse(
                COPILOT.is_malformed(body),
                "heading-form '## Verdict: Not a bug' must parse as well-formed",
            )
            verdicts = COPILOT.extract_not_a_bug_verdicts(body)
            self.assertTrue(
                verdicts,
                "expected at least one NOT-A-BUG verdict extracted from "
                "heading form",
            )
            self.assertIn("NOT A BUG", " ".join(verdicts).upper())

            # End-to-end: dispatcher runs → classified, not skipped.
            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT HOLDS: invariant at src/Foo.sol:42", "dry-run")

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_HOLD,
                             "heading form must flow through to classification")

    # ------------------------------------------------------------------
    # Test 6 — title-prefix form: ``# poly-45 — INVESTIGATED — FALSE POSITIVE``.
    # ------------------------------------------------------------------
    def test_grammar_investigated_title_prefix_parsed(self) -> None:
        body = (
            "# poly-45 — INVESTIGATED — FALSE POSITIVE\n\n"
            "## Candidate\n\n"
            "Explored the conditionId collision angle.\n\n"
            "## Why\n\nDerivation parity verified on Polygon mainnet.\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "title_prefix.md", body)
            self.assertFalse(
                COPILOT.is_malformed(body),
                "title-prefix '# X — INVESTIGATED — FALSE POSITIVE' must parse",
            )
            verdicts = COPILOT.extract_not_a_bug_verdicts(body)
            self.assertTrue(
                verdicts,
                "expected at least one NOT-A-BUG verdict extracted from "
                "title-prefix form",
            )
            self.assertIn("FALSE POSITIVE", " ".join(verdicts).upper())

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return (
                    "VERDICT CONTESTED: title-prefix drafts often mask "
                    "real attacker paths",
                    "dry-run",
                )

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_BREAK,
                             "title-prefix form must flow to classification")

    # ------------------------------------------------------------------
    # Test 7 — bold-inline backward compat: ``**Verdict**: FP``.
    # ------------------------------------------------------------------
    def test_grammar_existing_inline_still_works(self) -> None:
        body = (
            "# Some agent analysis\n\n"
            "Traced the path carefully.\n\n"
            "**Verdict**: FP — the mutex guards downstream writes.\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "bold_inline.md", body)
            self.assertFalse(
                COPILOT.is_malformed(body),
                "bold-inline '**Verdict**: FP' must still parse (backward compat)",
            )
            verdicts = COPILOT.extract_not_a_bug_verdicts(body)
            self.assertTrue(
                verdicts,
                "expected at least one NOT-A-BUG verdict extracted from "
                "bold-inline form",
            )

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT HOLDS: bold-inline still works", "dry-run")

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_HOLD)

    # ------------------------------------------------------------------
    # Test 8 (HARD-NEGATIVE) — a truly verdictless markdown must still
    # be classified `skipped`, not fake-classified by the new grammar.
    # ------------------------------------------------------------------
    def test_grammar_truly_malformed_still_skipped(self) -> None:
        body = (
            "# Random notes\n\n"
            "Just some musings on the architecture.\n"
            "No verdict anywhere. No investigation marker.\n"
            "Not even the word 'bug'.\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = _mk_agent_output(ws, "truly_malformed.md", body)
            self.assertTrue(
                COPILOT.is_malformed(body),
                "verdictless markdown must stay classified as malformed",
            )

            called = {"n": 0}

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                called["n"] += 1
                return ("VERDICT CONTESTED: should never run", "dry-run")

            status, reason = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
            )
            self.assertEqual(status, COPILOT.STATUS_SKIPPED)
            self.assertIsNotNone(reason)
            self.assertIn("malformed", reason or "")
            # Dispatcher MUST NOT be called for verdictless input.
            self.assertEqual(called["n"], 0,
                             "dispatcher invoked on verdictless hard-negative")


class AdversarialCopilotStep5Test(unittest.TestCase):
    """Kimi 20/10 Step 5 — per-engagement + novelty-to-pattern promotion."""

    # ------------------------------------------------------------------
    # Test 9 — per-engagement break emits a candidate DSL pattern under
    # reference/patterns.dsl/_novelty/<slug>.yaml.
    # ------------------------------------------------------------------
    def test_per_engagement_break_emits_novelty_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as ws_tmp, \
             tempfile.TemporaryDirectory() as repo_tmp:
            ws = Path(ws_tmp)
            repo_root = Path(repo_tmp)
            src = _mk_agent_output(ws, "angle10.md", SAMPLE_NOT_A_BUG_MD)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT CONTESTED: bridge race in refund branch", "dry-run")

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
                per_engagement=True, repo_root=repo_root,
            )
            self.assertEqual(status, COPILOT.STATUS_BREAK)

            slug = COPILOT.slug_from_path(src)
            pattern = (repo_root / "reference" / "patterns.dsl"
                       / "_novelty" / f"{slug}.yaml")
            self.assertTrue(pattern.is_file(),
                            f"expected novelty pattern at {pattern}")
            text = pattern.read_text()
            # Required DSL fields.
            self.assertIn(f"pattern: novelty-{slug}", text)
            self.assertIn("source: adversarial-copilot", text)
            self.assertIn("severity: UNKNOWN", text)
            self.assertIn("status: candidate", text)
            self.assertIn("VERDICT CONTESTED", text)

    # ------------------------------------------------------------------
    # Test 10 — per-engagement break appends a record to
    # tools/novelty_promotion_log.json with the expected JSON shape.
    # ------------------------------------------------------------------
    def test_per_engagement_break_appends_novelty_log_json(self) -> None:
        with tempfile.TemporaryDirectory() as ws_tmp, \
             tempfile.TemporaryDirectory() as repo_tmp:
            ws = Path(ws_tmp)
            repo_root = Path(repo_tmp)
            src = _mk_agent_output(ws, "angle11.md", SAMPLE_NOT_A_BUG_MD)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT CONTESTED: missed mev path", "dry-run")

            COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
                per_engagement=True, repo_root=repo_root,
            )
            log_path = repo_root / "tools" / "novelty_promotion_log.json"
            self.assertTrue(log_path.is_file(),
                            f"expected novelty log at {log_path}")
            data = json.loads(log_path.read_text())
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 1)
            row = data[0]
            # Schema check — every required field must be present and typed.
            for field in ("ts", "slug", "workspace", "source",
                          "first_verdict", "pattern_path", "status",
                          "origin", "validation"):
                self.assertIn(field, row, f"missing field {field!r} in log row")
                self.assertIsInstance(row[field], str)
            self.assertEqual(row["origin"], "adversarial-copilot")
            self.assertEqual(row["status"], "candidate")
            self.assertEqual(row["validation"], "pending")

    # ------------------------------------------------------------------
    # Test 11 — per-engagement OFF (default) → no novelty artifacts even
    # on a break verdict. Backwards-compat invariant.
    # ------------------------------------------------------------------
    def test_default_mode_no_novelty_artifacts_on_break(self) -> None:
        with tempfile.TemporaryDirectory() as ws_tmp, \
             tempfile.TemporaryDirectory() as repo_tmp:
            ws = Path(ws_tmp)
            repo_root = Path(repo_tmp)
            src = _mk_agent_output(ws, "angle12.md", SAMPLE_NOT_A_BUG_MD)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT CONTESTED: classic backcompat", "dry-run")

            status, _ = COPILOT.process_one(
                ws, src, live=False, swarm_tool=Path("/nonexistent"),
                dispatcher=fake_dispatcher,
                # per_engagement defaults to False
                repo_root=repo_root,
            )
            self.assertEqual(status, COPILOT.STATUS_BREAK)
            # No novelty pattern dir.
            novelty_dir = repo_root / "reference" / "patterns.dsl" / "_novelty"
            self.assertFalse(
                novelty_dir.exists() and any(novelty_dir.iterdir()),
                "default mode must NOT emit novelty patterns",
            )
            # No novelty log.
            log_path = repo_root / "tools" / "novelty_promotion_log.json"
            self.assertFalse(log_path.exists(),
                             "default mode must NOT touch novelty log")

    # ------------------------------------------------------------------
    # Test 12 — multiple per-engagement breaks accumulate into a single
    # JSON-array log file (no clobber).
    # ------------------------------------------------------------------
    def test_per_engagement_log_accumulates_across_calls(self) -> None:
        with tempfile.TemporaryDirectory() as ws_tmp, \
             tempfile.TemporaryDirectory() as repo_tmp:
            ws = Path(ws_tmp)
            repo_root = Path(repo_tmp)

            def fake_dispatcher(workspace, brief, live, swarm_tool):
                return ("VERDICT CONTESTED: yet another path", "dry-run")

            for i, name in enumerate(("a.md", "b.md", "c.md")):
                src = _mk_agent_output(ws, name, SAMPLE_NOT_A_BUG_MD)
                COPILOT.process_one(
                    ws, src, live=False, swarm_tool=Path("/nonexistent"),
                    dispatcher=fake_dispatcher,
                    per_engagement=True, repo_root=repo_root,
                )

            log_path = repo_root / "tools" / "novelty_promotion_log.json"
            data = json.loads(log_path.read_text())
            self.assertEqual(len(data), 3,
                             "log must accumulate one row per break")
            slugs = {r["slug"] for r in data}
            self.assertEqual(slugs, {"a", "b", "c"})

    # ------------------------------------------------------------------
    # Test 13 — `--per-engagement` CLI flag is wired through main() and
    # exits 0 with novelty artifacts created when a fake dispatcher
    # produces a break.
    # ------------------------------------------------------------------
    def test_cli_per_engagement_flag_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as ws_tmp, \
             tempfile.TemporaryDirectory() as repo_tmp:
            ws = Path(ws_tmp)
            repo_root = Path(repo_tmp)
            _mk_agent_output(ws, "angle_cli.md", SAMPLE_NOT_A_BUG_MD)

            # Monkey-patch the default dispatcher so live=False still goes
            # through process_one and seeds novelty artifacts. Restore on
            # exit.
            orig = COPILOT.dispatch_counter_brief
            def _fake(workspace, brief, live, swarm_tool):
                return ("VERDICT CONTESTED: CLI smoke", "dry-run")
            COPILOT.dispatch_counter_brief = _fake
            try:
                rc = COPILOT.main([
                    str(ws),
                    "--per-engagement",
                    "--repo-root", str(repo_root),
                ])
            finally:
                COPILOT.dispatch_counter_brief = orig

            self.assertEqual(rc, 0)
            log_path = repo_root / "tools" / "novelty_promotion_log.json"
            self.assertTrue(log_path.is_file(),
                            "CLI --per-engagement must seed novelty log")
            data = json.loads(log_path.read_text())
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["origin"], "adversarial-copilot")

    # ------------------------------------------------------------------
    # Test 14 — `--use-llm-dispatch` without consent gracefully falls back
    # to dry-run (so test envs without API keys don't blow up). The
    # dispatcher does not invoke a real subprocess in this dry-run path.
    # ------------------------------------------------------------------
    def test_use_llm_dispatch_dry_run_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as ws_tmp, \
             tempfile.TemporaryDirectory() as repo_tmp:
            ws = Path(ws_tmp)
            repo_root = Path(repo_tmp)
            # In dry-run mode dispatch_via_llm_dispatch returns the brief
            # itself — no subprocess, no API key required.
            response, mode = COPILOT.dispatch_via_llm_dispatch(
                ws, "brief body", live=False,
                swarm_tool=Path("/nonexistent"),
                repo_root=repo_root, provider="kimi",
            )
            self.assertEqual(mode, "dry-run")
            self.assertEqual(response, "brief body")

    # ------------------------------------------------------------------
    # Test 15 — calibration cite helper survives a missing
    # llm-calibration-log.py module: returns [] without raising.
    # ------------------------------------------------------------------
    def test_cite_calibration_missing_module_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp:
            # No tools/llm-calibration-log.py in this scratch repo root.
            lines = COPILOT._cite_calibration_lines(Path(repo_tmp))
            self.assertEqual(lines, [],
                             "missing calibration module must yield []")


if __name__ == "__main__":
    unittest.main()
