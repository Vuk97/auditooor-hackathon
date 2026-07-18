#!/usr/bin/env python3
"""Regression coverage for tools/orient-prefilter.py.

Anchor: 2026-05-25 hyperbridge full-hunt - 8 of 10 dispatched DRILL lanes
returned DROP after ~16h compute.  The prefilter (Capability Gap 1+3 fix)
should flag those candidates as warn-multi-gate-risk or fail-high-kill-risk
BEFORE the drill lanes are spawned, while leaving DRILL-6 (the lone
POSITIVE) discoverable.

Tests cover:
- Load the real hunt_orient.json fixture and assert per-candidate verdicts
- DRILL-3 specifically downgraded by R47 attack-class direct-hit (PR #865)
- DRILL-2 specifically caught by R53 self-declared CAUTION (SRL coverage)
- DRILL-6 (POSITIVE) NOT false-killed
- JSON schema sanity
- Per-gate kill-risk grade emit
- Empty / malformed input handling
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "orient-prefilter.py"
HUNT_JSON = ROOT / "reports" / "v3_iter_2026-05-25" / \
    "lane_HYPERBRIDGE_FULL_HUNT_ORIENT" / "hunt_orient.json"
HYPERBRIDGE_WS = Path("/Users/wolf/audits/hyperbridge")

DRILL_IDS_THAT_DROPPED = ("DRILL-1", "DRILL-2", "DRILL-3", "DRILL-4",
                          "DRILL-5", "DRILL-7", "DRILL-8")
DRILL_ID_POSITIVE = "DRILL-6"

FAIL_OR_WARN_MULTI = {"warn-multi-gate-risk", "fail-high-kill-risk"}
ACCEPTABLE_FOR_POSITIVE = {"pass-likely-fileable", "warn-1-gate-risk"}


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(TOOL), *args]
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        env=full_env,
    )


def _run_real_hunt() -> dict:
    proc = _run(
        "--candidates", str(HUNT_JSON),
        "--workspace", str(HYPERBRIDGE_WS),
        "--audit-pin", "70c8429d9b5c7c3260e37c02714c4026601dabd3",
        "--json",
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"orient-prefilter exited {proc.returncode}\n"
            f"stdout: {proc.stdout[:400]}\nstderr: {proc.stderr[:400]}"
        )
    return json.loads(proc.stdout)


class OrientPrefilterHyperbridgeAnchorTests(unittest.TestCase):
    """Replay the 2026-05-25 hyperbridge full-hunt anchor.

    Acceptance: 7 of 8 drill_candidates flagged as DROP-eligible
    (warn-multi-gate-risk or fail-high-kill-risk).  DRILL-6 (POSITIVE)
    stays at warn-1-gate-risk or pass-likely-fileable.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures_exist = HUNT_JSON.is_file() and HYPERBRIDGE_WS.is_dir()
        if not cls.fixtures_exist:
            return
        cls.payload = _run_real_hunt()
        cls.per_candidate = {
            c["candidate_id"]: c for c in cls.payload["per_candidate"]
        }

    def setUp(self) -> None:
        if not self.fixtures_exist:
            self.skipTest(
                f"fixtures unavailable: HUNT_JSON={HUNT_JSON} "
                f"HYPERBRIDGE_WS={HYPERBRIDGE_WS}"
            )

    def test_seven_dropped_candidates_flagged(self) -> None:
        """The 7 DROPped DRILL lanes (1, 2, 3, 4, 5, 7, 8) must score as
        warn-multi-gate-risk or fail-high-kill-risk.
        """
        flagged_ok: list[str] = []
        misses: list[tuple[str, str]] = []
        for drill_id in DRILL_IDS_THAT_DROPPED:
            self.assertIn(
                drill_id, self.per_candidate,
                f"{drill_id} missing from prefilter output",
            )
            verdict = self.per_candidate[drill_id]["verdict"]
            if verdict in FAIL_OR_WARN_MULTI:
                flagged_ok.append(drill_id)
            else:
                misses.append((drill_id, verdict))
        self.assertEqual(
            len(flagged_ok), len(DRILL_IDS_THAT_DROPPED),
            f"Expected all 7 DROPped candidates to score "
            f"warn-multi-gate-risk or fail-high-kill-risk. Misses: {misses}",
        )

    def test_drill_6_positive_not_false_killed(self) -> None:
        """DRILL-6 was the lone POSITIVE - the prefilter MUST NOT score it
        higher than warn-1-gate-risk.
        """
        self.assertIn(
            DRILL_ID_POSITIVE, self.per_candidate,
            "DRILL-6 missing from prefilter output",
        )
        verdict = self.per_candidate[DRILL_ID_POSITIVE]["verdict"]
        self.assertIn(
            verdict, ACCEPTABLE_FOR_POSITIVE,
            f"DRILL-6 (POSITIVE) was false-killed with verdict={verdict}; "
            f"prefilter must score it as pass-likely-fileable or warn-1-gate-risk",
        )

    def test_drill_3_downgraded_by_r47_recent_fix(self) -> None:
        """DRILL-3 MUST be downgraded by R47 recent-fix-commit (PR #865
        = 9cb22fa8, 2026-05-17 'Bind solver and session to a single
        transient-storage commitment').
        """
        rec = self.per_candidate[DRILL_ID := "DRILL-3"]
        r47 = next(g for g in rec["gate_results"] if g["gate"] == "R47")
        self.assertIn(
            r47["kill_risk"], {"high", "extreme"},
            f"DRILL-3 R47 kill-risk must be high or extreme; got {r47['kill_risk']}",
        )
        direct_hits = r47.get("direct_hit_commits", [])
        self.assertTrue(
            direct_hits,
            "DRILL-3 R47 must have at least one direct_hit_commit "
            "(PR #865 / 9cb22fa8 'Bind solver and session...')",
        )
        # Check at least one direct-hit commit cites PR #865 SHA prefix.
        found_pr_865 = any(c.get("sha", "").startswith("9cb22fa8") for c in direct_hits)
        self.assertTrue(
            found_pr_865,
            f"DRILL-3 R47 must surface PR #865 (9cb22fa8) as a direct hit; "
            f"direct_hit_commits={direct_hits}",
        )

    def test_drill_2_caught_by_r53_self_declared_caution(self) -> None:
        """DRILL-2 metadata explicitly flags 'CAUTION: SRL covered old
        IntentGatewayV2 fee-on-transfer' - R53 must escalate to high/extreme.
        """
        rec = self.per_candidate["DRILL-2"]
        r53 = next(g for g in rec["gate_results"] if g["gate"] == "R53")
        self.assertIn(
            r53["kill_risk"], {"high", "extreme"},
            f"DRILL-2 R53 kill-risk must be high or extreme (SRL CAUTION); "
            f"got {r53['kill_risk']}",
        )
        # The self_declared_kill_risk field should be populated.
        self.assertIn(
            "self_declared_kill_risk", r53,
            "DRILL-2 R53 must surface the self_declared_kill_risk field",
        )

    def test_prefilter_summary_shape(self) -> None:
        """The prefilter_summary block must enumerate verdict counts."""
        s = self.payload["prefilter_summary"]
        for k in ("total_candidates", "verdict_counts",
                  "candidate_ids_by_verdict", "recommended_dispatch_order",
                  "recommended_drop_or_downgrade"):
            self.assertIn(k, s)
        self.assertEqual(s["total_candidates"], 8)
        sum_counts = sum(s["verdict_counts"].values())
        self.assertEqual(
            sum_counts, 8,
            f"verdict_counts must sum to total_candidates; got {s['verdict_counts']}",
        )

    def test_dispatch_order_recommends_drill_6_first_or_alone(self) -> None:
        """DRILL-6 (POSITIVE) MUST appear in recommended_dispatch_order
        (or be the only PASS).  At least one of the 7 DROPpeds must NOT
        appear in dispatch order.
        """
        s = self.payload["prefilter_summary"]
        dispatch = s["recommended_dispatch_order"]
        drop = s["recommended_drop_or_downgrade"]
        self.assertIn(
            DRILL_ID_POSITIVE, dispatch,
            f"DRILL-6 must be in recommended_dispatch_order; got {dispatch}",
        )
        # All 7 DROPped IDs must be in drop list (not dispatch).
        for d in DRILL_IDS_THAT_DROPPED:
            self.assertIn(
                d, drop,
                f"{d} must be in recommended_drop_or_downgrade; got {drop}",
            )

    def test_per_candidate_gate_shape(self) -> None:
        """Each candidate must emit per-gate kill-risk records for R45/R46/R47/R48/R53."""
        for cid, rec in self.per_candidate.items():
            grades = rec.get("per_gate_kill_risk", {})
            for gate in ("R45", "R46", "R47", "R48", "R53"):
                self.assertIn(
                    gate, grades,
                    f"{cid} missing per_gate_kill_risk[{gate}]",
                )
                self.assertIn(
                    grades[gate], {"low", "medium", "high", "extreme"},
                    f"{cid} {gate} kill_risk not a valid grade: {grades[gate]}",
                )


class OrientPrefilterSchemaTests(unittest.TestCase):
    """Top-level schema sanity."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures_exist = HUNT_JSON.is_file() and HYPERBRIDGE_WS.is_dir()

    def setUp(self) -> None:
        if not self.fixtures_exist:
            self.skipTest("hyperbridge fixtures unavailable")
        self.payload = _run_real_hunt()

    def test_schema_version(self) -> None:
        self.assertEqual(
            self.payload["schema_version"],
            "auditooor.orient_prefilter.v1",
        )

    def test_required_top_level_fields(self) -> None:
        for k in (
            "schema_version", "tool", "generated_at_utc",
            "candidates_path", "workspace", "audit_pin",
            "recent_fix_window_days", "source_meta",
            "workspace_doc_count", "prior_audit_doc_count",
            "prefilter_summary", "per_candidate",
        ):
            self.assertIn(k, self.payload, f"missing top-level field {k}")

    def test_audit_pin_passthrough(self) -> None:
        self.assertEqual(
            self.payload["audit_pin"],
            "70c8429d9b5c7c3260e37c02714c4026601dabd3",
        )

    def test_source_meta_carries_workspace(self) -> None:
        sm = self.payload["source_meta"]
        self.assertEqual(sm["candidate_count"], 8)
        self.assertEqual(sm["source_workspace"], "hyperbridge")


class OrientPrefilterInputHandlingTests(unittest.TestCase):
    """Edge cases: missing candidates file, malformed JSON, empty list."""

    def test_missing_candidates_file(self) -> None:
        proc = _run(
            "--candidates", "/tmp/does-not-exist.json",
            "--workspace", "/tmp",
            "--json",
        )
        self.assertNotEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "error")
        self.assertIn("candidates file not found", payload["error"])

    def test_missing_workspace(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False) as tmp:
            json.dump({"drill_candidates": []}, tmp)
            tmp.flush()
            tmp_path = tmp.name
        try:
            proc = _run(
                "--candidates", tmp_path,
                "--workspace", "/tmp/does-not-exist-xyz",
                "--json",
            )
            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "error")
        finally:
            os.unlink(tmp_path)

    def test_empty_candidates_list(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False) as tmp:
            json.dump({"drill_candidates": []}, tmp)
            tmp.flush()
            tmp_path = tmp.name
        try:
            proc = _run(
                "--candidates", tmp_path,
                "--workspace", "/tmp",
                "--json",
            )
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["prefilter_summary"]["total_candidates"], 0)
            self.assertEqual(payload["per_candidate"], [])
        finally:
            os.unlink(tmp_path)

    def test_malformed_candidate_missing_id(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False) as tmp:
            # Candidate missing required 'id' field.
            json.dump({"drill_candidates": [{"name": "no id"}]}, tmp)
            tmp.flush()
            tmp_path = tmp.name
        try:
            proc = _run(
                "--candidates", tmp_path,
                "--workspace", "/tmp",
                "--json",
            )
            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "error")
        finally:
            os.unlink(tmp_path)

    def test_alternative_candidates_key(self) -> None:
        """Tool accepts 'candidates' key as alternative to 'drill_candidates'."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False) as tmp:
            json.dump({
                "candidates": [{
                    "id": "FOO-1",
                    "files": ["test/file.sol"],
                    "name": "test candidate",
                }],
            }, tmp)
            tmp.flush()
            tmp_path = tmp.name
        try:
            proc = _run(
                "--candidates", tmp_path,
                "--workspace", "/tmp",
                "--json",
            )
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["prefilter_summary"]["total_candidates"], 1)
            self.assertEqual(payload["per_candidate"][0]["candidate_id"], "FOO-1")
        finally:
            os.unlink(tmp_path)


class OrientPrefilterGateContractTests(unittest.TestCase):
    """Verify each per-gate record carries the expected field shape."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures_exist = HUNT_JSON.is_file() and HYPERBRIDGE_WS.is_dir()

    def setUp(self) -> None:
        if not self.fixtures_exist:
            self.skipTest("hyperbridge fixtures unavailable")
        self.payload = _run_real_hunt()

    def test_r45_gate_carries_hits_field(self) -> None:
        for rec in self.payload["per_candidate"]:
            r45 = next(g for g in rec["gate_results"] if g["gate"] == "R45")
            self.assertIn("hits", r45)
            self.assertIn("reason", r45)

    def test_r46_gate_carries_component_and_oos_fields(self) -> None:
        for rec in self.payload["per_candidate"]:
            r46 = next(g for g in rec["gate_results"] if g["gate"] == "R46")
            self.assertIn("component_hits", r46)
            self.assertIn("oos_clause_hits", r46)

    def test_r47_gate_carries_commits_and_direct_hits(self) -> None:
        for rec in self.payload["per_candidate"]:
            r47 = next(g for g in rec["gate_results"] if g["gate"] == "R47")
            self.assertIn("recent_security_commits", r47)
            self.assertIn("direct_hit_commits", r47)
            self.assertIn("audit_pin", r47)

    def test_r48_gate_carries_topology_and_non_core(self) -> None:
        for rec in self.payload["per_candidate"]:
            r48 = next(g for g in rec["gate_results"] if g["gate"] == "R48")
            self.assertIn("topology_hits", r48)
            self.assertIn("non_core_paths", r48)

    def test_r53_gate_carries_matches_and_matched_terms(self) -> None:
        for rec in self.payload["per_candidate"]:
            r53 = next(g for g in rec["gate_results"] if g["gate"] == "R53")
            self.assertIn("prior_audit_matches", r53)
            self.assertIn("matched_terms", r53)


class OrientPrefilterUtilityPathTests(unittest.TestCase):
    """DRILL-4 (VWAPOracle.sol in src/utils/) should trigger R48 non-core path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures_exist = HUNT_JSON.is_file() and HYPERBRIDGE_WS.is_dir()

    def setUp(self) -> None:
        if not self.fixtures_exist:
            self.skipTest("hyperbridge fixtures unavailable")
        self.payload = _run_real_hunt()

    def test_drill_4_non_core_path_detected(self) -> None:
        rec = next(c for c in self.payload["per_candidate"]
                   if c["candidate_id"] == "DRILL-4")
        r48 = next(g for g in rec["gate_results"] if g["gate"] == "R48")
        self.assertTrue(
            r48.get("non_core_paths"),
            f"DRILL-4 R48 must detect VWAPOracle.sol in /utils/ path; "
            f"got non_core_paths={r48.get('non_core_paths')}",
        )


if __name__ == "__main__":
    unittest.main()
