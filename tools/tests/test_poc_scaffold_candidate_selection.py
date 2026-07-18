#!/usr/bin/env python3
"""Tests for plan-candidate selection diagnostics in tools/poc-scaffold.py.

Covers item #16 / P1-5 burn-down:
  - Single-match plan-json resolves cleanly.
  - Multi-match plan-json without --candidate-index fails closed with a
    helpful error message that includes title, source file:line, and
    evidence_class for each candidate.
  - Multi-match plan-json WITH --candidate-index resolves and writes a
    JSONL ambiguity-resolution log entry.
  - Out-of-range --candidate-index fails loud.
  - Closeout (audit-closeout-check.poc-execution) warns when the
    ambiguity-resolution log has entries.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "poc-scaffold.py"


def locked_impact_fields(candidate_id: str = "C-LOCKED") -> dict:
    return {
        "candidate_id": candidate_id,
        "impact_contract_id": f"impact-contract-{candidate_id.lower()}",
        "selected_impact": "Direct theft of user funds without user interaction",
        "severity": "High",
        "exact_impact_row": True,
        "listed_impact_proven": True,
    }


def load_tool():
    spec = importlib.util.spec_from_file_location("poc_scaffold", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PocScaffoldCandidateSelectionTest(unittest.TestCase):
    def write_plan(self, root: Path) -> Path:
        plan = root / "brief_candidates.json"
        plan.write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "contract": "Vault",
                            "angle_id": "A-RACE",
                            "angle_title": "first race",
                            "exploit_goal": "prove first race",
                            "source_file": "swarm/a.md",
                            "source_line": 42,
                            "evidence_class": "topology-relation",
                        },
                        {
                            "contract": "Vault",
                            "angle_id": "A-RACE",
                            "angle_title": "second race",
                            "exploit_goal": "prove second race",
                            "source_file": "swarm/b.md",
                            "source_line": 17,
                            "evidence_class": "guard-bypass",
                        },
                        {
                            "contract": "Oracle",
                            "angle_id": "A-ORACLE",
                            "angle_title": "stale price",
                            "exploit_goal": "prove stale price",
                            "source_file": "swarm/c.md",
                            "evidence_class": "stale-data",
                        },
                    ]
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return plan

    # ----- selection / disambiguation behaviors -----

    def test_single_candidate_resolves_without_ambiguity(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.write_plan(Path(tmp))
            candidate, meta = tool.load_candidate_plan(plan, "Oracle", "A-ORACLE", None)
        self.assertEqual(candidate["contract"], "Oracle")
        self.assertFalse(meta["ambiguity_resolved"])
        self.assertEqual(meta["selected_index"], 2)
        self.assertEqual(meta["alternative_indexes"], [])

    def test_ambiguous_selector_lists_matching_candidate_indexes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.write_plan(Path(tmp))
            with self.assertRaises(ValueError) as ctx:
                tool.load_candidate_plan(plan, "Vault", "A-RACE", None)

        message = str(ctx.exception)
        self.assertIn("pass --candidate-index <n>", message)
        # Title, source:line, and evidence_class must all be present.
        self.assertIn("title='first race'", message)
        self.assertIn("source=swarm/a.md:42", message)
        self.assertIn("evidence_class=topology-relation", message)
        self.assertIn("title='second race'", message)
        self.assertIn("source=swarm/b.md:17", message)
        self.assertIn("evidence_class=guard-bypass", message)
        # Non-matching candidate must NOT be in the matching list.
        self.assertNotIn("[2] contract=Oracle", message)

    def test_no_match_lists_available_candidate_indexes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.write_plan(Path(tmp))
            with self.assertRaises(ValueError) as ctx:
                tool.load_candidate_plan(plan, "Missing", "A-RACE", None)

        message = str(ctx.exception)
        self.assertIn("No candidate matched", message)
        self.assertIn("available candidates:", message)
        self.assertIn("[0] contract=Vault angle_id=A-RACE", message)
        self.assertIn("[2] contract=Oracle angle_id=A-ORACLE", message)
        # New: evidence_class is surfaced even on the no-match listing so the
        # operator sees what each candidate is about.
        self.assertIn("evidence_class=topology-relation", message)
        self.assertIn("evidence_class=stale-data", message)

    def test_explicit_index_resolves_ambiguity_and_records_alternatives(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.write_plan(Path(tmp))
            candidate, meta = tool.load_candidate_plan(plan, "Vault", "A-RACE", 1)
        self.assertEqual(candidate["angle_title"], "second race")
        self.assertTrue(meta["ambiguity_resolved"])
        self.assertEqual(meta["selected_index"], 1)
        self.assertEqual(meta["alternative_indexes"], [0])
        self.assertEqual(len(meta["alternatives"]), 1)
        alt = meta["alternatives"][0]
        self.assertEqual(alt["index"], 0)
        self.assertEqual(alt["angle_title"], "first race")
        self.assertEqual(alt["source"], "swarm/a.md:42")
        self.assertEqual(alt["evidence_class"], "topology-relation")

    def test_out_of_range_index_fails_loud(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.write_plan(Path(tmp))
            with self.assertRaises(ValueError) as ctx:
                tool.load_candidate_plan(plan, None, None, 99)
        self.assertIn("out of range", str(ctx.exception))

    def test_explicit_index_without_selector_does_not_log_ambiguity(self) -> None:
        """Picking [0] without filters is not 'disambiguation' - just a direct pick."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.write_plan(Path(tmp))
            _, meta = tool.load_candidate_plan(plan, None, None, 0)
        self.assertFalse(meta["ambiguity_resolved"])
        self.assertEqual(meta["selected_index"], 0)


class PocScaffoldAmbiguityLogTest(unittest.TestCase):
    """Subprocess-level tests: ambiguous --plan-json behavior end-to-end."""

    def _write_plan(self, root: Path) -> Path:
        plan = root / "brief_candidates.json"
        plan.write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "contract": "Vault",
                            "angle_id": "A-RACE",
                            "angle_title": "first race",
                            "exploit_goal": "prove first race",
                            "source_file": "swarm/a.md",
                            "source_line": 10,
                            "evidence_class": "topology-relation",
                            **locked_impact_fields("C-RACE-1"),
                        },
                        {
                            "contract": "Vault",
                            "angle_id": "A-RACE",
                            "angle_title": "second race",
                            "exploit_goal": "prove second race",
                            "source_file": "swarm/b.md",
                            "source_line": 20,
                            "evidence_class": "guard-bypass",
                            **locked_impact_fields("C-RACE-2"),
                        },
                    ]
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return plan

    def test_subprocess_fail_closed_when_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan = self._write_plan(tmp_path)
            out = tmp_path / "out.t.sol"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json", str(plan),
                    "--contract", "Vault",
                    "--angle-id", "A-RACE",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(
                result.returncode, 0,
                f"expected non-zero rc, got {result.returncode}; "
                f"stdout={result.stdout!r}",
            )
            combined = result.stdout + result.stderr
            self.assertIn("Multiple candidates matched", combined)
            self.assertIn("--candidate-index", combined)
            self.assertFalse(out.exists(), "scaffold must not be written on fail-closed")

    def test_subprocess_with_index_writes_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan = self._write_plan(tmp_path)
            out = tmp_path / "out.t.sol"
            env = os.environ.copy()
            # Pin the log root so we don't depend on workspace inference.
            env["AUDITOOOR_AMBIGUITY_LOG_ROOT"] = str(tmp_path)
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json", str(plan),
                    "--contract", "Vault",
                    "--angle-id", "A-RACE",
                    "--candidate-index", "1",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(
                result.returncode, 0,
                f"unexpected rc {result.returncode}; "
                f"stdout={result.stdout!r}; stderr={result.stderr!r}",
            )
            log = tmp_path / ".auditooor" / "poc_scaffold_ambiguity_resolutions.jsonl"
            self.assertTrue(log.exists(), "ambiguity-resolution log was not written")
            rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["selected"]["index"], 1)
            self.assertEqual(row["selected"]["angle_title"], "second race")
            self.assertEqual(len(row["alternatives"]), 1)
            self.assertEqual(row["alternatives"][0]["index"], 0)
            self.assertEqual(row["alternatives"][0]["evidence_class"], "topology-relation")
            # Closeout warning text is on stdout.
            self.assertIn("ambiguity resolution logged", result.stdout)

    def test_subprocess_refuses_scaffold_when_candidate_metadata_blocks_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan = tmp_path / "brief_candidates.json"
            plan.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "contract": "Vault",
                                "angle_id": "A-RACE",
                                "angle_title": "source-mined hypothesis",
                                "exploit_goal": "prove source-mined race",
                                "source_file": "source_mining/run/summary.md",
                                "evidence_class": "generated_hypothesis",
                                "impact_contract_required": True,
                                "impact_contract_id": "",
                                "allocation_gate": {
                                    "status": "missing_contract",
                                    "blocked_task_types": ["harness", "poc", "report"],
                                },
                                "outcome_calibrated_routing": {
                                    "routing_status": "input_only_local_verification_required",
                                    "local_verification_required": True,
                                },
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out = tmp_path / "blocked.t.sol"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json", str(plan),
                    "--contract", "Vault",
                    "--angle-id", "A-RACE",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("Refusing to scaffold blocked candidate", combined)
            self.assertIn("local verification still required", combined)
            self.assertIn("allocation gate still blocks harness/PoC/report work", combined)
            self.assertFalse(out.exists())


class PocScaffoldImpactContractGateTest(unittest.TestCase):
    """Subprocess tests for PR560 plan-mode impact-contract locking."""

    def test_subprocess_fail_closed_without_locked_impact_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan = tmp_path / "brief_candidates.json"
            plan.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "candidate_id": "C-UNLOCKED",
                                "contract": "Vault",
                                "angle_id": "A-RACE",
                                "angle_title": "race",
                                "exploit_goal": "prove race",
                                "source_file": "swarm/a.md",
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out = tmp_path / "PlanRacePoC.t.sol"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json", str(plan),
                    "--contract", "Vault",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            combined = result.stdout + result.stderr
            self.assertIn("blocked_missing_impact_contract", combined)
            self.assertFalse(out.exists(), "scaffold must not be written")
            self.assertFalse(
                out.with_name(out.name + ".evidence_class.json").exists(),
                "sidecar must not be written when impact contract is missing",
            )

    def test_subprocess_passes_with_matching_workspace_impact_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            swarm = ws / "swarm"
            swarm.mkdir()
            plan = swarm / "brief_candidates.json"
            plan.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "candidate_id": "C-WORKSPACE-LOCKED",
                                "contract": "Vault",
                                "angle_id": "A-RACE",
                                "angle_title": "race",
                                "exploit_goal": "prove race",
                                "source_file": "swarm/a.md",
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir()
            (auditooor / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.pr560.impact_contracts.v1",
                        "contracts": [
                            {
                                "candidate_id": "C-WORKSPACE-LOCKED",
                                "impact_contract_id": "impact-contract-workspace-locked",
                                "selected_impact": (
                                    "Direct theft of user funds without user interaction"
                                ),
                                "severity": "Critical",
                                "exact_impact_row": True,
                                "listed_impact_proven": True,
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out = ws / "poc-tests" / "PlanRacePoC.t.sol"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json", str(plan),
                    "--contract", "Vault",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode, 0,
                f"stdout={result.stdout!r}; stderr={result.stderr!r}",
            )
            self.assertTrue(out.exists(), "locked candidate should write scaffold")
            self.assertTrue(out.with_name(out.name + ".evidence_class.json").exists())


class PocScaffoldAmbiguityCloseoutTest(unittest.TestCase):
    """Closeout integration: ``poc-scaffold-ambiguity`` row warns when the
    ambiguity-resolution log has entries (item #16 / P1-5 burn-down)."""

    def _load_closeout_module(self):
        # The tool uses @dataclass, which on Python 3.12+ inspects
        # ``sys.modules[cls.__module__]``. Register the module before exec.
        mod_name = "audit_closeout_check_for_test"
        spec = importlib.util.spec_from_file_location(
            mod_name,
            REPO_ROOT / "tools" / "audit-closeout-check.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(mod_name, None)
            raise
        return module

    def test_no_log_passes(self) -> None:
        mod = self._load_closeout_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            row = mod.check_poc_scaffold_ambiguity(ws)
            self.assertEqual(row.status, mod.PASS)
            self.assertEqual(row.detail["entry_count"], 0)
            self.assertFalse(row.detail["log_present"])

    def test_empty_log_passes(self) -> None:
        mod = self._load_closeout_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            log = ws / ".auditooor" / "poc_scaffold_ambiguity_resolutions.jsonl"
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text("", encoding="utf-8")
            row = mod.check_poc_scaffold_ambiguity(ws)
            self.assertEqual(row.status, mod.PASS)
            self.assertTrue(row.detail["log_present"])
            self.assertEqual(row.detail["entry_count"], 0)

    def test_log_with_entries_warns(self) -> None:
        mod = self._load_closeout_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            log = ws / ".auditooor" / "poc_scaffold_ambiguity_resolutions.jsonl"
            log.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "schema": "auditooor.poc_scaffold_ambiguity.v1",
                "timestamp": "2026-04-29T00:00:00Z",
                "plan_json": "/ws/swarm/brief_candidates.json",
                "out_path": "/ws/poc-tests/T.t.sol",
                "selector": {"contract": "Vault", "angle_id": "A-RACE"},
                "selected": {
                    "index": 1,
                    "contract": "Vault",
                    "angle_id": "A-RACE",
                    "angle_title": "second race",
                    "source": "swarm/b.md:20",
                    "evidence_class": "guard-bypass",
                },
                "alternatives": [
                    {
                        "index": 0,
                        "contract": "Vault",
                        "angle_id": "A-RACE",
                        "angle_title": "first race",
                        "source": "swarm/a.md:10",
                        "evidence_class": "topology-relation",
                    }
                ],
            }
            log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            row = mod.check_poc_scaffold_ambiguity(ws)
            self.assertEqual(row.status, mod.WARN)
            self.assertEqual(row.detail["entry_count"], 1)
            self.assertIn("ambiguity-resolved", row.reason)

    def test_run_all_includes_check(self) -> None:
        """`run_all` must include the new poc-scaffold-ambiguity row."""
        mod = self._load_closeout_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            results = mod.run_all(ws, require_deep=False)
            check_names = [r.check for r in results]
            self.assertIn("poc-scaffold-ambiguity", check_names)


class PocScaffoldEvidenceClassSidecarTest(unittest.TestCase):
    """Item #14: pattern-mode and plan-mode scaffolds emit a sidecar JSON
    declaring ``evidence_class: scaffolded_unverified``.
    """

    def test_pattern_mode_writes_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ReentrancyDemo.t.sol"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--pattern",
                    "A-REENT",
                    "--contract",
                    "Vault",
                    "--func",
                    "withdraw",
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sidecar = out.with_name(out.name + ".evidence_class.json")
            self.assertTrue(sidecar.exists(), proc.stdout)
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["evidence_class"], "scaffolded_unverified")
            self.assertEqual(payload["pattern_id"], "A-REENT")
            self.assertEqual(payload["target_contract"], "Vault")
            self.assertEqual(payload["target_function"], "withdraw")
            self.assertIsNone(payload["upstream_candidate_evidence_class"])

    def test_plan_mode_warns_on_legacy_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan = tmp_path / "brief_candidates.json"
            plan.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "contract": "Vault",
                                "angle_id": "A-RACE",
                                "angle_title": "race",
                                "exploit_goal": "prove race",
                                "source_file": "swarm/a.md",
                                **locked_impact_fields("C-LEGACY-EVIDENCE"),
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out = tmp_path / "PlanRacePoC.t.sol"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json",
                    str(plan),
                    "--contract",
                    "Vault",
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("upstream candidate has no evidence_class", proc.stderr)
            sidecar = out.with_name(out.name + ".evidence_class.json")
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["evidence_class"], "scaffolded_unverified")
            self.assertTrue(payload["upstream_candidate_legacy"])

    def test_plan_mode_propagates_upstream_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan = tmp_path / "brief_candidates.json"
            plan.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "contract": "Vault",
                                "angle_id": "A-RACE",
                                "angle_title": "race",
                                "exploit_goal": "prove race",
                                "source_file": "swarm/a.md",
                                "evidence_class": "generated_hypothesis",
                                **locked_impact_fields("C-UPSTREAM-EVIDENCE"),
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out = tmp_path / "PlanRacePoC.t.sol"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--plan-json",
                    str(plan),
                    "--contract",
                    "Vault",
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("upstream candidate has no evidence_class", proc.stderr)
            sidecar = out.with_name(out.name + ".evidence_class.json")
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["evidence_class"], "scaffolded_unverified")
            self.assertEqual(
                payload["upstream_candidate_evidence_class"], "generated_hypothesis"
            )
            self.assertFalse(payload["upstream_candidate_legacy"])


if __name__ == "__main__":
    unittest.main()
