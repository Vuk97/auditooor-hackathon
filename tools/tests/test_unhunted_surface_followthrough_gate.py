#!/usr/bin/env python3
"""Tests for unhunted-surface-followthrough-gate.py.

Genericity is the whole point of this tool, so the tests assert:
  - the morpho-midnight ANCHOR (canIncreaseCredit abandoned unhunted surface)
    is caught when the real workspace is present (skipped if absent);
  - the tool body contains NO hardcoded morpho path / contract / function /
    finding id (grep-based no-hardcoding assertion);
  - synthetic generic workspaces (JSON queue + markdown packet) in any
    language exercise terminal vs non-terminal classification;
  - graceful degradation on an empty workspace.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_THIS = Path(__file__).resolve()
_TOOLS = _THIS.parent.parent
_TOOL_PATH = _TOOLS / "unhunted-surface-followthrough-gate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "unhunted_surface_followthrough_gate", _TOOL_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GATE = _load_module()

MORPHO_WS = Path("/Users/wolf/audits/morpho-midnight")


def _mkworkspace(tmp: Path, queue_obj=None, reports: dict | None = None):
    """Create a minimal workspace under tmp with optional queue + reports."""
    ws = tmp / "ws"
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "reports").mkdir(parents=True, exist_ok=True)
    if queue_obj is not None:
        (ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps(queue_obj), encoding="utf-8"
        )
    for name, content in (reports or {}).items():
        (ws / "reports" / name).write_text(content, encoding="utf-8")
    return ws


class TestNoHardcoding(unittest.TestCase):
    def test_tool_body_has_no_morpho_specifics(self):
        body = _TOOL_PATH.read_text(encoding="utf-8")
        # Strip the module docstring (anchor mentioned only in prose there).
        # We assert these literals never appear in code at all to be strict
        # EXCEPT inside the leading docstring where the empirical anchor is
        # explained. Split on the first occurrence of the closing of the
        # module docstring.
        # The anchor lives in the docstring; assert it is NOT used as code.
        # Simplest robust check: these tokens must not appear after the
        # docstring terminator.
        parts = body.split('"""', 2)
        # parts[0]=before, parts[1]=docstring, parts[2]=rest (code)
        code = parts[2] if len(parts) >= 3 else body
        forbidden = [
            "morpho-midnight",
            "morpho_midnight",
            "canIncreaseCredit",
            "IGate.sol",
            "TRST-M-2",
            "/Users/wolf/audits/morpho",
        ]
        for tok in forbidden:
            self.assertNotIn(
                tok,
                code,
                msg=f"hardcoded morpho specific {tok!r} found in tool CODE body",
            )


class TestVerdictClassification(unittest.TestCase):
    def test_terminal_tokens_pass(self):
        self.assertEqual(GATE._classify_verdict("proof_status: killed"), "terminal")
        self.assertEqual(GATE._classify_verdict("State: filed"), "terminal")
        self.assertEqual(GATE._classify_verdict("verdict confirmed"), "terminal")

    def test_nonterminal_tokens_fail(self):
        self.assertEqual(
            GATE._classify_verdict("State: ready_for_poc_planning"), "nonterminal"
        )
        self.assertEqual(GATE._classify_verdict("proof_status: unproved"), "nonterminal")

    def test_terminal_wins_over_nonterminal(self):
        # A row both killed AND queued is terminal (killed).
        self.assertEqual(
            GATE._classify_verdict("queued but killed after review"), "terminal"
        )

    def test_unknown_signal(self):
        self.assertEqual(GATE._classify_verdict(""), "unknown")
        self.assertEqual(GATE._classify_verdict("something else"), "unknown")


class TestGenericJsonWorkspace(unittest.TestCase):
    def test_abandoned_unhunted_surface_in_queue_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            queue = {
                "queue": [
                    {
                        "lead_id": "EQ-100",
                        "title": "unhunted-surface target: Foo.sol::bar",
                        "proof_status": "unproved",
                    },
                    {
                        "lead_id": "EQ-101",
                        "title": "unhunted-surface target: Foo.sol::baz",
                        "proof_status": "killed",  # terminal -> ok
                    },
                ]
            }
            ws = _mkworkspace(tmp, queue_obj=queue)
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "fail-abandoned-surfaces")
            ids = {r["id"] for r in res["abandoned_surfaces"]}
            self.assertIn("EQ-100", ids)
            self.assertNotIn("EQ-101", ids)

    def test_all_terminal_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            queue = {
                "queue": [
                    {
                        "lead_id": "EQ-1",
                        "title": "unhunted-surface target: A::a",
                        "proof_status": "filed",
                    },
                    {
                        "lead_id": "EQ-2",
                        "title": "unhunted-surface target: A::b",
                        "proof_status": "refuted",
                    },
                ]
            }
            ws = _mkworkspace(tmp, queue_obj=queue)
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "pass-no-surfaces")

    def test_rust_and_move_surface_language_agnostic(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            queue = {
                "candidate_rows": [
                    {
                        "id": "RS-1",
                        "title": "unhunted-surface target: pallet_ismp::dispatch",
                        "state": "queued",
                    },
                    {
                        "id": "MV-1",
                        "title": "unhunted-surface target: coin::transfer (move)",
                        "status": "identified",
                    },
                ]
            }
            ws = _mkworkspace(tmp, queue_obj=queue)
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "fail-abandoned-surfaces")
            ids = {r["id"] for r in res["abandoned_surfaces"]}
            self.assertSetEqual(ids, {"RS-1", "MV-1"})


class TestMarkdownPacket(unittest.TestCase):
    def test_markdown_block_without_terminal_verdict_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            packet = (
                "# Candidate Judgment Packet\n\n"
                "### CJP-1 - EQ-9\n"
                "- Title: unhunted-surface target: Widget.sol::doThing\n"
                "- State: `ready_for_poc_planning`\n"
                "- Proof readiness: `not_claimed`\n\n"
                "### CJP-2 - EQ-10\n"
                "- Title: unhunted-surface target: Widget.sol::doOther\n"
                "- State: `killed`\n"
            )
            ws = _mkworkspace(tmp, reports={"candidate_judgment_packet.md": packet})
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "fail-abandoned-surfaces")
            # Heading id = first id token in the heading (CJP-N), matching the
            # real morpho candidate-judgment-packet convention.
            ids = {r["id"] for r in res["abandoned_surfaces"]}
            titles = " | ".join(r["title"] for r in res["abandoned_surfaces"])
            self.assertIn("CJP-1", ids)  # the abandoned (non-terminal) block
            self.assertNotIn("CJP-2", ids)  # the killed (terminal) block
            self.assertIn("doThing", titles)
            self.assertNotIn("doOther", titles)


# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
class TestFunctionCoverageCrossCredit(unittest.TestCase):
    """Generic fix: the surface-miners enumerate EVERY function (incl. pure
    leaf-helpers / OZ-std / view getters). The authoritative scope-filtered,
    R55-filtered value-moving unit ledger is function_coverage_completeness.json.
    A flagged surface is a genuine abandoned surface ONLY when it maps to an
    fc unit that is in-universe AND non-terminal. Terminal fc units (already
    hunted) and rows outside the value-moving universe are not abandoned."""

    def _ws_with_fc(self, tmp, packet, fc_functions):
        ws = _mkworkspace(tmp, reports={"candidate_judgment_packet.md": packet})
        (ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(
                {
                    "verdict": "pass-fully-covered",
                    "counts": {"total": len(fc_functions)},
                    "functions": fc_functions,
                    "hollow_or_untouched": [],
                }
            ),
            encoding="utf-8",
        )
        return ws

    def test_terminal_and_leaf_helper_dropped_genuine_gap_kept(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            packet = (
                "# Candidate Judgment Packet\n\n"
                "### CJP-1 - EQ-1\n"
                "- Title: unhunted-surface target: Vault.sol::withdraw\n"
                "- State: `ready_for_poc_planning`\n\n"
                "### CJP-2 - EQ-2\n"
                "- Title: unhunted-surface target: Vault.sol::deposit\n"
                "- State: `ready_for_poc_planning`\n\n"
                "### CJP-3 - EQ-3\n"
                "- Title: unhunted-surface target: TypedMemView.sol::leftShift\n"
                "- State: `ready_for_poc_planning`\n\n"
                "### CJP-4 - EQ-4\n"
                "- Title: unhunted-surface target: ProxyAdmin.sol\n"
                "- State: `ready_for_poc_planning`\n"
            )
            fc = [
                # withdraw = in-universe, terminally dispositioned -> dropped
                {"file": "src/Vault.sol", "name": "withdraw",
                 "classification": "real-attack"},
                # deposit = in-universe but NOT terminal -> genuine gap, KEPT
                {"file": "src/Vault.sol", "name": "deposit",
                 "classification": "hollow"},
                # TypedMemView/ProxyAdmin = not tracked as value-moving units
            ]
            ws = self._ws_with_fc(tmp, packet, fc)
            res = GATE.evaluate(str(ws))
            titles = " | ".join(r["title"] for r in res["abandoned_surfaces"])
            self.assertEqual(res["verdict"], "fail-abandoned-surfaces")
            # genuine in-universe-non-terminal gap stays abandoned
            self.assertIn("deposit", titles)
            # terminal fc unit + leaf-helper + OZ-std file are all cross-credited
            self.assertNotIn("withdraw", titles)
            self.assertNotIn("leftShift", titles)
            self.assertNotIn("ProxyAdmin", titles)
            self.assertGreaterEqual(res["stats"]["fc_dropped_terminal"], 1)
            self.assertGreaterEqual(res["stats"]["fc_dropped_out_of_universe"], 2)

    def test_all_terminal_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            packet = (
                "# Candidate Judgment Packet\n\n"
                "### CJP-1 - EQ-1\n"
                "- Title: unhunted-surface target: Vault.sol::withdraw\n"
                "- State: `ready_for_poc_planning`\n"
            )
            fc = [{"file": "src/Vault.sol", "name": "withdraw",
                   "classification": "real-attack"}]
            ws = self._ws_with_fc(tmp, packet, fc)
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "pass-no-surfaces")
            self.assertEqual(res["abandoned_surfaces"], [])

    def test_legacy_fallback_when_no_fc_artifact(self):
        # No function_coverage_completeness.json -> legacy behavior, surface
        # stays abandoned (gate never silently weakens without the ledger).
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            packet = (
                "# Candidate Judgment Packet\n\n"
                "### CJP-1 - EQ-1\n"
                "- Title: unhunted-surface target: Vault.sol::withdraw\n"
                "- State: `ready_for_poc_planning`\n"
            )
            ws = _mkworkspace(tmp, reports={"candidate_judgment_packet.md": packet})
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "fail-abandoned-surfaces")
            self.assertEqual(res["stats"]["fc_dropped_terminal"], 0)
            self.assertEqual(res["stats"]["fc_dropped_out_of_universe"], 0)


class TestGracefulDegradation(unittest.TestCase):
    def test_empty_workspace_pass_no_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            ws.mkdir()
            res = GATE.evaluate(str(ws))
            self.assertEqual(res["verdict"], "pass-no-workspace-inputs")
            self.assertEqual(res["abandoned_surfaces"], [])

    def test_missing_workspace_error(self):
        res = GATE.evaluate("/nonexistent/path/xyz123")
        self.assertEqual(res["verdict"], "error")


# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
class TestMorphoAnchor(unittest.TestCase):
    """The morpho specifics live HERE in the test, never in the tool body."""

    @unittest.skipUnless(
        MORPHO_WS.is_dir(), "morpho-midnight workspace not present on this host"
    )
    def test_interface_surface_resolved_by_ledger(self):
        """canIncreaseCredit exists ONLY as an interface declaration
        (IGate.sol) - no in-scope implementation; its in-scope USE is covered
        under take(). So the unhunted-surface-adjudicate ledger must drive that
        marker to a terminal `interface-declaration` verdict (it must NOT sit
        abandoned), while the gate still flags the genuine residual surfaces
        (bridge_replay / hacker-q) that have no evidence basis yet."""
        # Ensure the evidence-grounded terminal-verdict ledger exists (audit-deep
        # writes it in the real pipeline; run the producer here so the test is
        # self-contained and not dependent on prior on-disk state).
        spec = importlib.util.spec_from_file_location(
            "_adj", _TOOLS / "unhunted-surface-adjudicate.py")
        adj = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adj)
        adj.adjudicate(MORPHO_WS)

        res = GATE.evaluate(str(MORPHO_WS))
        titles = " | ".join(r["title"] for r in res["abandoned_surfaces"])
        # the interface-declaration surface is resolved, not abandoned
        self.assertNotIn(
            "canIncreaseCredit", titles,
            msg="an interface-declaration surface must be ledger-resolved, not abandoned",
        )
        self.assertGreater(
            res["stats"].get("resolved_by_ledger", 0), 0,
            msg="the terminal-verdict ledger must credit evidence-grounded surfaces",
        )


class TestSecondWorkspaceSmoke(unittest.TestCase):
    """Run against a real, different workspace to prove genericity in the
    field (not just synthetic). Any /Users/wolf/audits/<other> with inputs."""

    def test_runs_on_a_second_real_workspace(self):
        base = Path("/Users/wolf/audits")
        if not base.is_dir():
            self.skipTest("no /Users/wolf/audits on host")
        candidates = [
            d
            for d in sorted(base.iterdir())
            if d.is_dir()
            and d.name != "morpho-midnight"
            and (d / ".auditooor" / "exploit_queue.json").is_file()
        ]
        if not candidates:
            self.skipTest("no second workspace with exploit_queue.json")
        res = GATE.evaluate(str(candidates[0]))
        # Must not error and must return a known verdict on a different ws.
        self.assertIn(
            res["verdict"],
            {
                "pass-no-workspace-inputs",
                "pass-no-surfaces",
                "pass-all-followed-through",
                "fail-abandoned-surfaces",
            },
        )


class TestCli(unittest.TestCase):
    def test_cli_json_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            queue = {
                "queue": [
                    {
                        "lead_id": "EQ-X",
                        "title": "unhunted-surface target: Z::z",
                        "proof_status": "unproved",
                    }
                ]
            }
            ws = _mkworkspace(tmp, queue_obj=queue)
            proc = subprocess.run(
                [sys.executable, str(_TOOL_PATH), "--workspace", str(ws), "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            out = json.loads(proc.stdout)
            self.assertEqual(out["schema"], GATE.SCHEMA)
            self.assertEqual(out["verdict"], "fail-abandoned-surfaces")


# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
class TestStructuralHeadingSkip(unittest.TestCase):
    """A bare document-structure heading (a CONTAINER like `## Rows` whose body
    aggregates the real leads counted elsewhere) must NOT be counted as its own
    abandoned surface."""

    def test_structural_heading_not_counted(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            # A markdown packet with a `## Rows` container whose body mentions
            # unhunted-surface text, plus a genuine lead block.
            (ws / ".auditooor" / "queue_proof_hard_close.md").write_text(
                "## Rows\n"
                "- unhunted-surface target: A.sol::a (proof_status open)\n"
                "- unhunted-surface target: B.sol::b (proof_status open)\n\n"
                "### CJP-001 - EQ-9\n- Title: corpus-hunt-fuel: INV-9 (x) @ f\n"
                "- State: `ready_for_poc_planning`\n",
                encoding="utf-8")
            res = GATE.evaluate(str(ws))
            titles = [r["title"] for r in res["abandoned_surfaces"]]
            self.assertNotIn("Rows", titles, "structural container heading must be skipped")
            # the genuine CJP lead is still caught
            self.assertTrue(any("corpus-hunt-fuel" in t for t in titles),
                            "a genuine lead block must still be flagged")


if __name__ == "__main__":
    unittest.main()


class TestLedgerEvidenceExcludedFromScan(unittest.TestCase):
    """Strata 2026-07-01 self-reference fix: a disposition-evidence artifact (a
    refutation .md cited by the terminal-verdict ledger) lives under .auditooor/ and
    textually names the surfaces it closes, so the surface scan RE-FLAGGED it as a new
    abandoned surface - a self-referential false-positive. _candidate_artifacts now
    excludes any file cited as an evidence_ref in the ledger."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp()).resolve()
        (self.ws / ".auditooor").mkdir(parents=True)
        # a refutation note that names an unhunted/unattempted surface (would trip detection)
        (self.ws / ".auditooor" / "refutation.md").write_text(
            "# Unhunted-surface follow-through: refutation of unattempted-rubric-class leads\n"
            "Terminal verdict: REFUTED after exhaustive hunt.\n")
        (self.ws / ".auditooor" / "unhunted_terminal_verdicts.json").write_text(json.dumps({
            "schema": "auditooor.unhunted_terminal_verdicts.v1",
            "verdicts": [{
                "lead_id": "CJP-999", "verdict": "refuted",
                "evidence_ref": ".auditooor/refutation.md",
            }],
        }))

    def test_evidence_ref_excluded_from_candidate_artifacts(self):
        jsons, texts = GATE._candidate_artifacts(self.ws)
        names = {p.name for p in (jsons + texts)}
        self.assertNotIn("refutation.md", names,
                         "ledger-cited evidence must be excluded from the surface scan")

    def test_ledger_evidence_paths_resolves(self):
        paths = GATE._ledger_evidence_paths(self.ws)
        self.assertIn(str((self.ws / ".auditooor" / "refutation.md").resolve()), paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
