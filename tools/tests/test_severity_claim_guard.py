#!/usr/bin/env python3
"""Tests for tools/severity-claim-guard.py (Wave 6 Worker L, PR #556 §P4).

Stdlib-only, hermetic. Covers the load-bearing rule:

    severity in Critical/High/Medium AND exact impact proof absent -> rc=1

Plus the surrounding behavior:

  * Critical with selected impact + listed_impact_proven=true ->  rc=0
  * Medium with listed_impact_proven=false                    ->  rc=1
  * Snappy selecting mempool impact                           ->  rc=1
  * Workspace mode resolves matrix path under
    <ws>/critical_hunt/base_critical_candidate_matrix.json    ->  rc=0/1
  * Missing matrix                                            ->  rc=2
  * Invalid JSON                                              ->  rc=2
  * Two-Critical mix (one proven, one unproven)               ->  rc=1
  * --json emits a structured payload with the violations.

Mirrors the conventions of test_base_critical_candidate_matrix.py.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "severity-claim-guard.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("severity_claim_guard", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["severity_claim_guard"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _run(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _json_from_stdout(stdout: str) -> dict:
    payload, _ = json.JSONDecoder().raw_decode(stdout)
    return payload


def _write_matrix(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.base_critical_candidate_matrix.v1",
        "listed_impacts": [
            "Permanent freeze of user funds",
            "Direct theft of user funds without user interaction",
            "Total network shutdown of the canonical chain",
            "Increasing network processing node resource consumption by at least 30%",
            "Node resource consumption >=30%",
            "Shutdown >=30% of nodes",
        ],
        "listed_critical_impacts": [
            "Permanent freeze of user funds",
            "Direct theft of user funds without user interaction",
            "Total network shutdown of the canonical chain",
            "Increasing network processing node resource consumption by at least 30%",
            "Node resource consumption >=30%",
            "Shutdown >=30% of nodes",
        ],
        "rows": rows,
        "status_counts": {},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_impact_contracts(path: Path, contracts: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.automation_closure.impact_contracts.v1",
        "contracts": contracts,
        "status": "ok" if contracts else "empty_no_candidates",
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class TestSeverityClaimGuard(unittest.TestCase):
    # ------------------------------------------------------------------
    # Vulnerable: Critical + listed_impact_proven=false -> guard FAILS
    # ------------------------------------------------------------------
    def test_critical_unproven_fails(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_crit_unproven_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "C-WAVE5-SNAPPY",
                    "raw_severity": "Critical",
                    "listed_impact_selected": (
                        "Permanent freeze of user funds"
                    ),
                    "listed_impact_proven": False,
                    "network_level_evidence": "absent",
                    "component_poc_only": True,
                }
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 1, result.stderr)
        # And the offending candidate id must appear on stderr.
        self.assertIn("C-WAVE5-SNAPPY", result.stderr)

    # ------------------------------------------------------------------
    # Clean: Critical + listed_impact_proven=true -> guard PASSES
    # ------------------------------------------------------------------
    def test_critical_proven_passes(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_crit_proven_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "C-NETWORK-PROVEN",
                    "raw_severity": "Critical",
                    "listed_impact_selected": (
                        "Direct theft of user funds without user interaction"
                    ),
                    "listed_impact_proven": True,
                    "network_level_evidence": (
                        "poc_execution/network_replay/manifest.json"
                    ),
                    "component_poc_only": False,
                }
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    # ------------------------------------------------------------------
    # Vulnerable: Medium + listed_impact_proven=false -> guard FAILS.
    # Reportable severity is not allowed unless the selected exact impact is
    # proved; otherwise the row must be NOT_SUBMIT_READY/kill_or_reframe with
    # impact removed.
    # ------------------------------------------------------------------
    def test_medium_unproven_fails(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_med_unproven_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "M-1",
                    "raw_severity": "Medium",
                    "listed_impact_selected": (
                        "Increasing network processing node resource "
                        "consumption by at least 30%"
                    ),
                    "listed_impact_proven": False,
                    "network_level_evidence": "absent",
                    "component_poc_only": True,
                }
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("M-1", result.stderr)

    # ------------------------------------------------------------------
    # Clean: Medium + exact selected impact + listed_impact_proven=true
    # passes. This is the Snappy resource-threshold shape after measurement,
    # not a component-only decode PoC.
    # ------------------------------------------------------------------
    def test_medium_proven_passes(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_med_proven_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "M-PROVEN",
                    "raw_severity": "Medium",
                    "listed_impact_selected": (
                        "Increasing network processing node resource "
                        "consumption by at least 30%"
                    ),
                    "listed_impact_proven": True,
                    "network_level_evidence": "poc_execution/resource/manifest.json",
                    "component_poc_only": False,
                }
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)

    # ------------------------------------------------------------------
    # Mixed: one Critical proven + one Critical unproven -> still FAILS.
    # The guard never tolerates a single over-claim, even if other rows
    # in the matrix are clean.
    # ------------------------------------------------------------------
    def test_mixed_critical_one_unproven_fails(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_mixed_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "C-CLEAN",
                    "raw_severity": "Critical",
                    "listed_impact_selected": (
                        "Total network shutdown of the canonical chain"
                    ),
                    "listed_impact_proven": True,
                    "network_level_evidence": "poc_execution/x/manifest.json",
                    "component_poc_only": False,
                },
                {
                    "candidate_id": "C-DIRTY",
                    "raw_severity": "Critical",
                    "listed_impact_proven": False,
                    "network_level_evidence": "absent",
                    "component_poc_only": True,
                },
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("C-DIRTY", result.stderr)
        self.assertNotIn("C-CLEAN", result.stderr)

    # ------------------------------------------------------------------
    # Empty matrix (zero rows) -> guard PASSES.
    # ------------------------------------------------------------------
    def test_empty_matrix_passes(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_empty_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(matrix, [])
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)

    # ------------------------------------------------------------------
    # Missing Base matrix is no longer a bypass. Generic workspace mode with
    # no candidate artifacts simply scans zero rows and passes.
    # ------------------------------------------------------------------
    def test_missing_matrix_empty_generic_workspace_passes(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_missing_"))
        result = _run(["--workspace", str(ws), "--json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = _json_from_stdout(result.stdout)
        self.assertEqual(payload["row_count"], 0)
        self.assertEqual(payload["violation_count"], 0)

    # ------------------------------------------------------------------
    # Non-Base workspace mode: .auditooor/impact_contracts.json with a
    # reportable row and missing proof must fail even without a Base matrix.
    # ------------------------------------------------------------------
    def test_generic_impact_contract_exact_flag_unproven_reportable_fails(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_generic_unproven_"))
        _write_impact_contracts(
            ws / ".auditooor" / "impact_contracts.json",
            [
                {
                    "impact_contract_id": "impact-contract-c1",
                    "candidate_id": "GEN-HIGH-UNPROVEN",
                    "severity": "High",
                    "selected_impact": "Permanent freeze of user funds",
                    "exact_impact_row": True,
                    "listed_impact_proven": False,
                    "posture": "NOT_SUBMIT_READY",
                }
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("GEN-HIGH-UNPROVEN", result.stderr)
        self.assertIn("listed_impact_not_proven", result.stderr)

    # ------------------------------------------------------------------
    # Non-Base workspace mode: a proven exact impact contract may pass. The
    # explicit exact-row flag is required when no rubric list is bundled.
    # ------------------------------------------------------------------
    def test_generic_impact_contract_proven_exact_reportable_passes(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_generic_proven_"))
        _write_impact_contracts(
            ws / ".auditooor" / "impact_contracts.json",
            [
                {
                    "impact_contract_id": "impact-contract-c2",
                    "candidate_id": "GEN-CRIT-PROVEN",
                    "severity": "Critical",
                    "selected_impact": "Direct theft of user funds without user interaction",
                    "exact_impact_row": True,
                    "listed_impact_proven": True,
                    "posture": "in_scope_direct_submit",
                }
            ],
        )
        result = _run(["--workspace", str(ws), "--json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = _json_from_stdout(result.stdout)
        self.assertEqual(payload["row_count"], 1)
        self.assertEqual(payload["violation_count"], 0)

    def test_generic_impact_contract_non_exact_reportable_fails(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_generic_non_exact_"))
        _write_impact_contracts(
            ws / ".auditooor" / "impact_contracts.json",
            [
                {
                    "impact_contract_id": "impact-contract-c3",
                    "candidate_id": "GEN-HIGH-NON-EXACT",
                    "severity": "High",
                    "selected_impact": "Some serious fund-loss impact",
                    "exact_impact_row": False,
                    "listed_impact_proven": True,
                }
            ],
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("GEN-HIGH-NON-EXACT", result.stderr)
        self.assertIn("selected_impact_not_exact_listed_sentence", result.stderr)

    # ------------------------------------------------------------------
    # Invalid matrix JSON -> harness rc=2 (advisory).
    # ------------------------------------------------------------------
    def test_invalid_matrix_returns_two(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_invalid_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        matrix.parent.mkdir(parents=True)
        matrix.write_text("{not-json", encoding="utf-8")
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 2, result.stderr)

    # ------------------------------------------------------------------
    # Direct --matrix mode (bypass --workspace) — still gates correctly.
    # ------------------------------------------------------------------
    def test_direct_matrix_mode(self):
        tmp = Path(tempfile.mkdtemp(prefix="scg_direct_"))
        matrix = tmp / "matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "C-DIRECT",
                    "raw_severity": "Critical",
                    "listed_impact_proven": False,
                }
            ],
        )
        result = _run(["--matrix", str(matrix)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("C-DIRECT", result.stderr)

    def test_generic_impact_contract_program_matrix_unproven_reportable_fails(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_generic_contract_fail_"))
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        (aud / "program_impact_matrix.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "impact": "Direct theft of user funds without user interaction",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (aud / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "candidate_id": "GENERIC-HIGH",
                            "severity": "High",
                            "selected_impact": "Direct theft of user funds without user interaction",
                            "listed_impact_proven": False,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("GENERIC-HIGH", result.stderr)

    def test_generic_impact_contract_program_matrix_proven_reportable_passes(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_generic_contract_pass_"))
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        (aud / "program_impact_matrix.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "impact": "Direct theft of user funds without user interaction",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (aud / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "candidate_id": "GENERIC-HIGH",
                            "severity": "High",
                            "selected_impact": "Direct theft of user funds without user interaction",
                            "listed_impact_proven": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)

    # ------------------------------------------------------------------
    # --json emits structured violations.
    # ------------------------------------------------------------------
    def test_json_output(self):
        ws = Path(tempfile.mkdtemp(prefix="scg_json_"))
        matrix = ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        _write_matrix(
            matrix,
            [
                {
                    "candidate_id": "C-J1",
                    "raw_severity": "Critical",
                    "listed_impact_selected": (
                        "Total network shutdown of the canonical chain"
                    ),
                    "listed_impact_proven": False,
                }
            ],
        )
        result = _run(["--workspace", str(ws), "--json"])
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], _MOD.SCHEMA_VERSION)
        self.assertEqual(payload["violation_count"], 1)
        self.assertEqual(payload["violations"][0]["candidate_id"], "C-J1")

    # ------------------------------------------------------------------
    # Missing both --workspace and --matrix -> rc=2.
    # ------------------------------------------------------------------
    def test_no_args_returns_two(self):
        result = _run([])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("required", result.stderr)

    # ------------------------------------------------------------------
    # Pure-Python: find_violations honors string-typed booleans
    # (matches base-critical-candidate-matrix.py _coerce_bool semantics
    # — defensive for matrices generated by older tooling).
    # ------------------------------------------------------------------
    def test_string_typed_booleans(self):
        rows = [
            {
                "candidate_id": "C-STRBOOL",
                "raw_severity": "Critical",
                "listed_impact_selected": "Total network shutdown of the canonical chain",
                "listed_impact_proven": "false",  # string
            }
        ]
        violations = _MOD.find_violations(
            rows, ["Total network shutdown of the canonical chain"]
        )
        self.assertEqual(len(violations), 1)

        rows2 = [
            {
                "candidate_id": "C-STRTRUE",
                "raw_severity": "Critical",
                "listed_impact_selected": "Total network shutdown of the canonical chain",
                "listed_impact_proven": "true",  # string
            }
        ]
        self.assertEqual(
            _MOD.find_violations(rows2, ["Total network shutdown of the canonical chain"]),
            [],
        )

    def test_selected_impact_must_be_exact_listed_sentence(self):
        rows = [
            {
                "candidate_id": "C-PARTIAL",
                "raw_severity": "Critical",
                "listed_impact_selected": "Total network shutdown",
                "listed_impact_proven": True,
            }
        ]
        violations = _MOD.find_violations(
            rows, ["Total network shutdown of the canonical chain"]
        )
        self.assertEqual(len(violations), 1)
        self.assertIn(
            "selected_impact_not_exact_listed_sentence",
            violations[0]["reasons"],
        )

    def test_direct_submit_without_reportable_severity_still_requires_exact_proof(self):
        rows = [
            {
                "candidate_id": "DIRECT-LOW",
                "raw_severity": "Low",
                "submission_posture": "in_scope_direct_submit",
                "listed_impact_selected": "Total network shutdown",
                "listed_impact_proven": True,
            }
        ]
        violations = _MOD.find_violations(
            rows, ["Total network shutdown of the canonical chain"]
        )
        self.assertEqual(len(violations), 1)
        self.assertIn(
            "selected_impact_not_exact_listed_sentence",
            violations[0]["reasons"],
        )

    def test_not_submit_ready_row_must_remove_unproved_selected_impact(self):
        rows = [
            {
                "candidate_id": "KILL-WITH-IMPACT",
                "raw_severity": "Critical",
                "candidate_status": "kill_or_reframe",
                "listed_impact_selected": "Total network shutdown of the canonical chain",
                "listed_impact_proven": False,
            }
        ]
        violations = _MOD.find_violations(
            rows, ["Total network shutdown of the canonical chain"]
        )
        self.assertEqual(len(violations), 1)
        self.assertIn(
            "impact_not_removed_for_non_submit_ready",
            violations[0]["reasons"],
        )

    # ------------------------------------------------------------------
    # `severity` field (instead of `raw_severity`) — defensive for
    # caller-supplied matrices that follow the alternate key.
    # ------------------------------------------------------------------
    def test_severity_alias(self):
        rows = [
            {
                "candidate_id": "C-ALIAS",
                "severity": "Critical",
                "listed_impact_selected": "Total network shutdown of the canonical chain",
                "listed_impact_proven": False,
            }
        ]
        self.assertEqual(len(_MOD.find_violations(rows)), 1)

    # ------------------------------------------------------------------
    # Snappy gossip decode cannot select mempool impact. The selected impact
    # is invalid even if a row tries to set listed_impact_proven=true.
    # ------------------------------------------------------------------
    def test_snappy_mempool_impact_fails(self):
        rows = [
            {
                "candidate_id": "C-WAVE5-SNAPPY",
                "raw_severity": "Medium",
                "listed_impact_selected": "Mempool transaction propagation delay",
                "listed_impact_proven": True,
                "network_level_evidence": "poc_execution/snappy/manifest.json",
                "component_poc_only": False,
            }
        ]
        violations = _MOD.find_violations(rows)
        self.assertEqual(len(violations), 1)
        self.assertIn(
            "snappy_gossip_decode_cannot_select_mempool_impact",
            violations[0]["reasons"],
        )

    def test_snappy_critical_without_threshold_fails(self):
        rows = [
            {
                "candidate_id": "C-SNAPPY-CRIT",
                "scope_asset": "snappy gossip decode",
                "raw_severity": "Critical",
                "listed_impact_selected": "Node resource consumption >=30%",
                "listed_impact_proven": True,
                "node_resource_consumption_pct": 12,
                "realistic_non_bruteforce": False,
                "network_level_evidence": "absent",
                "component_poc_only": True,
            }
        ]
        violations = _MOD.find_violations(rows, ["Node resource consumption >=30%"])
        self.assertEqual(len(violations), 1)
        self.assertIn("snappy_threshold_not_proven", violations[0]["reasons"])
        self.assertIn(
            "snappy_realistic_non_bruteforce_missing",
            violations[0]["reasons"],
        )

    def test_snappy_critical_with_threshold_passes(self):
        rows = [
            {
                "candidate_id": "C-SNAPPY-CRIT",
                "scope_asset": "snappy gossip decode",
                "raw_severity": "Critical",
                "listed_impact_selected": "Node resource consumption >=30%",
                "listed_impact_proven": True,
                "node_resource_consumption_pct": 31,
                "realistic_non_bruteforce": True,
                "network_level_evidence": "critical_hunt/node_resource_wave5/results.json",
                "component_poc_only": False,
            }
        ]
        self.assertEqual(
            _MOD.find_violations(rows, ["Node resource consumption >=30%"]),
            [],
        )


if __name__ == "__main__":
    unittest.main()
