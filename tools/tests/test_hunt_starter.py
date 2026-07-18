"""Unit tests for hunt-starter.py (Phase -1 A / WF-3 REC-1).

Covers:
  - engage_report.md parser
  - exploit_queue.json parser
  - mined_findings_obligations.json parser (dict + list shapes)
  - synthetic-draft builder
  - roll_up_verdict precedence
  - run() end-to-end with synthetic workspaces
  - Makefile target and CLI surface
  - graceful no-op when restored tools (pattern-migration-alert / scan-report-thicken) are absent

>= 10 cases per the brief.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "hunt_starter",
    ROOT / "tools" / "hunt-starter.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _make_ws(severity_md: str | None = None, prior_audits: list[tuple[str, str]] | None = None) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="hunt_starter_ws_"))
    if severity_md is not None:
        (ws / "SEVERITY.md").write_text(severity_md, encoding="utf-8")
    (ws / ".auditooor").mkdir(exist_ok=True)
    if prior_audits:
        (ws / "prior_audits").mkdir()
        for name, text in prior_audits:
            (ws / "prior_audits" / name).write_text(text, encoding="utf-8")
    # L31 needs a submissions/ dir to scan; absent is fine - tool will return "distinct".
    return ws


SEV_DYDX_LIKE = """# Severity - test

## Critical
- Significant loss of user funds.
- Large-scale insolvency of the protocol.

## High
- Network-level downtime.
- Matching engine degradation.

## Medium
- Failure in non-core products.

## Low
- Display or event-parsing issues.
"""


class TestEngageReportParser(unittest.TestCase):
    """Case 1: engage_report.md cluster extraction."""

    def test_parses_clusters_and_hits(self):
        text = """# Engagement Report

## Clusters

### Cluster: `go.race.unsynchronized` (42 hits)

- **[LOW] `go.race.unsynchronized`** - `src/foo.go:10`
  - snippet: `x = nil`
- **[LOW] `go.race.unsynchronized`** - `src/bar.go:20`
  - snippet: `y = nil`

### Cluster: `go.panic.nil_deref` (3 hits)

- **[HIGH] `go.panic.nil_deref`** - `src/quux.go:1`
  - snippet: `*p = 1`
"""
        clusters = mod.parse_engage_report(text)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(clusters[0]["detector"], "go.race.unsynchronized")
        self.assertEqual(clusters[0]["hit_count"], 42)
        self.assertEqual(len(clusters[0]["samples"]), 2)
        self.assertEqual(clusters[0]["samples"][0]["severity"], "LOW")
        self.assertEqual(clusters[0]["samples"][0]["path"], "src/foo.go:10")
        self.assertEqual(clusters[1]["detector"], "go.panic.nil_deref")
        self.assertEqual(clusters[1]["hit_count"], 3)
        self.assertEqual(clusters[1]["samples"][0]["severity"], "HIGH")


class TestExploitQueueParser(unittest.TestCase):
    """Case 2: exploit_queue.json normalisation."""

    def test_normalises_rows(self):
        data = {
            "queue": [
                {"lead_id": "EQ-001", "title": "T1", "likely_severity": "high"},
                {"lead_id": "EQ-002", "title": "T2", "severity": "critical"},
                {"id": "EQ-003"},  # missing title - should default
            ]
        }
        rows = mod.parse_exploit_queue(data)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["lead_id"], "EQ-001")
        self.assertEqual(rows[0]["severity_max"], "HIGH")
        self.assertEqual(rows[1]["severity_max"], "CRITICAL")
        self.assertEqual(rows[2]["lead_id"], "EQ-003")
        self.assertEqual(rows[2]["title"], "(no title)")


class TestMinedObligationsParser(unittest.TestCase):
    """Case 3: mined_findings_obligations.json - dict shape + list shape."""

    def test_dict_shape(self):
        data = {"obligations": [{"id": "MO-001", "title": "X", "severity": "low"}]}
        rows = mod.parse_mined_obligations(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["candidate_id"], "mob:MO-001")
        self.assertEqual(rows[0]["severity_max"], "LOW")

    def test_list_shape(self):
        data = [{"finding_id": "F1", "name": "Y", "severity": "MEDIUM", "location": "src/x.go:9"}]
        rows = mod.parse_mined_obligations(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "Y")
        self.assertEqual(rows[0]["file_line"], "src/x.go:9")


class TestSyntheticDraft(unittest.TestCase):
    """Case 4: synth_draft produces a parseable minimal draft."""

    def test_builds_required_fields(self):
        cand = {
            "candidate_id": "cluster:foo.bar",
            "detector": "foo.bar",
            "severity_max": "HIGH",
            "samples": [{"severity": "HIGH", "path": "src/x.go:1"}],
        }
        draft = mod.synth_draft(cand, asset_selector="testasset")
        self.assertIn("cantina-asset: testasset", draft)
        self.assertIn("Severity: High", draft)
        self.assertIn("foo.bar", draft)
        self.assertIn("src/x.go:1", draft)
        self.assertIn("Network-level downtime", draft)

    def test_critical_impact_phrasing(self):
        cand = {"candidate_id": "x", "severity_max": "CRITICAL"}
        draft = mod.synth_draft(cand)
        self.assertIn("Severity: Critical", draft)
        self.assertIn("Significant loss of user funds", draft)


class TestRollupVerdict(unittest.TestCase):
    """Case 5: roll_up_verdict precedence rules."""

    def test_default_hunt_ready(self):
        verdict, reasons = mod.roll_up_verdict({"gates": {
            "R45": {"verdict": "pass-out-of-scope"},
            "R47": {"verdict": "pass-out-of-scope"},
            "R52": {"verdict": "fail-no-rubric-row-cited"},  # generic synth - ignored
            "R53": {"verdict": "pass-no-matching-prior-finding"},
            "L31": {"verdict": "distinct"},
            "pattern_migration": {"status": "tool-absent", "matched_paid": False},
        }})
        self.assertEqual(verdict, mod.VERDICT_HUNT_READY)

    def test_design_choice_skip_beats_other(self):
        verdict, _ = mod.roll_up_verdict({"gates": {
            "R45": {"verdict": "fail-designed-as-intended-with-defense-in-depth", "reason": "test"},
            "R52": {"verdict": "fail-program-severity-missing-impact-class"},
            "L31": {"verdict": "duplicate"},
        }})
        # Per precedence: PAID > DESIGN > RUBRIC-NO-ROW > DUPE
        self.assertEqual(verdict, mod.VERDICT_DESIGN_CHOICE_SKIP)

    def test_paid_match_beats_design_choice(self):
        verdict, _ = mod.roll_up_verdict({"gates": {
            "pattern_migration": {"matched_paid": True},
            "R45": {"verdict": "fail-designed-as-intended-with-defense-in-depth"},
        }})
        self.assertEqual(verdict, mod.VERDICT_PAID_MATCH)

    def test_rubric_no_row_skip(self):
        verdict, reasons = mod.roll_up_verdict({"gates": {
            "R52": {"verdict": "fail-program-severity-missing-impact-class", "reason": "no row"},
            "L31": {"verdict": "distinct"},
        }})
        self.assertEqual(verdict, mod.VERDICT_RUBRIC_NO_ROW_SKIP)

    def test_l31_duplicate_skip(self):
        verdict, _ = mod.roll_up_verdict({"gates": {
            "L31": {"verdict": "duplicate"},
        }})
        self.assertEqual(verdict, mod.VERDICT_LIKELY_DUPE_SKIP)

    def test_l31_no_priors_is_non_blocking(self):
        verdict, _ = mod.roll_up_verdict({"gates": {
            "L31": {"verdict": "no_priors_to_compare"},
        }})
        self.assertEqual(verdict, mod.VERDICT_HUNT_READY)

    def test_r47_acknowledged_skip(self):
        verdict, _ = mod.roll_up_verdict({"gates": {
            "L31": {"verdict": "distinct"},
            "R47": {"verdict": "fail-acknowledged-without-extension-distinct"},
        }})
        self.assertEqual(verdict, mod.VERDICT_LIKELY_DUPE_SKIP)

    def test_r53_superseded_skip(self):
        verdict, _ = mod.roll_up_verdict({"gates": {
            "L31": {"verdict": "distinct"},
            "R47": {"verdict": "pass-out-of-scope"},
            "R53": {"verdict": "fail-superseded-by-prior-audit"},
        }})
        self.assertEqual(verdict, mod.VERDICT_LIKELY_DUPE_SKIP)


class TestEndToEnd(unittest.TestCase):
    """Case 6: end-to-end run() with a synthetic workspace + minimal candidates."""

    def test_run_emits_artifacts(self):
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        # Write a minimal engage_report.md
        (ws / "engage_report.md").write_text("""# Engagement Report

## Clusters

### Cluster: `test.detector` (1 hits)

- **[LOW] `test.detector`** - `src/foo.go:1`
  - snippet: `x = 1`
""", encoding="utf-8")
        env = mod.run(ws, limit=None, emit_files=True)
        self.assertEqual(env["schema"], mod.SCHEMA)
        self.assertEqual(env["candidate_count"], 1)
        self.assertGreaterEqual(env["verdict_count"], 1)
        self.assertIn("artifacts", env)
        self.assertTrue(Path(env["artifacts"]["json"]).exists())
        self.assertTrue(Path(env["artifacts"]["md"]).exists())

    def test_run_with_no_inputs_yields_empty(self):
        ws = _make_ws()
        env = mod.run(ws, emit_files=False)
        self.assertEqual(env["candidate_count"], 0)
        self.assertEqual(env["verdict_count"], 0)

    def test_severityless_candidates_are_fast_pathed_without_gates(self):
        # Raw source-mined candidates with no rubric severity (severity_max
        # UNKNOWN/empty) must NOT be run through the ~7 gate subprocesses - they
        # get a deterministic NO-SEVERITY-TRIAGE-SKIP verdict with empty gates.
        # Guards the 21k-UNKNOWN-row source_mined explosion that serialized the
        # sweep into hours. run_gates is patched to a sentinel so the test fails
        # loudly if a severity-less candidate ever reaches it.
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        sm = {
            "rows": [
                {"lead_id": f"sm-{i}", "title": f"grep hit {i}",
                 "source_refs": [f"src/x{i}.sol:1"], "severity": "UNKNOWN"}
                for i in range(5)
            ]
        }
        (ws / ".auditooor" / "exploit_queue.source_mined.json").write_text(
            json.dumps(sm), encoding="utf-8"
        )
        called = {"n": 0}
        orig = mod.run_gates

        def _boom(*a, **k):
            called["n"] += 1
            return orig(*a, **k)

        mod.run_gates = _boom
        try:
            env = mod.run(ws, limit=None, emit_files=False)
        finally:
            mod.run_gates = orig
        sev_rows = [v for v in env["verdicts"] if str(v.get("candidate_id", "")).startswith("smq:sm-")]
        self.assertEqual(len(sev_rows), 5)
        for v in sev_rows:
            self.assertEqual(v["verdict"], mod.VERDICT_NO_SEVERITY_SKIP)
            self.assertEqual(v["gates"], {})
        # No severity-less candidate reached the expensive gate sweep.
        self.assertEqual(called["n"], 0)

    def test_parallel_run_preserves_candidate_order(self):
        # The per-candidate gate sweep is parallelized across candidates; the
        # emitted verdicts must stay 1:1 and in the SAME order as
        # collect_candidates (executor.map preserves input order). Forcing
        # >1 worker exercises the threadpool branch.
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        clusters = "\n".join(
            f"""### Cluster: `det.{i}` ({1} hits)

- **[LOW] `det.{i}`** - `src/m{i}.go:{i}`
  - snippet: `x = {i}`
"""
            for i in range(8)
        )
        (ws / "engage_report.md").write_text(
            "# Engagement Report\n\n## Clusters\n\n" + clusters, encoding="utf-8"
        )
        expected_ids = [c.get("candidate_id") for c in mod.collect_candidates(ws)]
        self.assertGreaterEqual(len(expected_ids), 8)
        prev = os.environ.get("AUDITOOOR_HUNT_STARTER_WORKERS")
        os.environ["AUDITOOOR_HUNT_STARTER_WORKERS"] = "4"
        try:
            env = mod.run(ws, limit=None, emit_files=False)
        finally:
            if prev is None:
                os.environ.pop("AUDITOOOR_HUNT_STARTER_WORKERS", None)
            else:
                os.environ["AUDITOOOR_HUNT_STARTER_WORKERS"] = prev
        self.assertEqual(env["verdict_count"], len(expected_ids))
        self.assertEqual(
            [v.get("candidate_id") for v in env["verdicts"]], expected_ids
        )


class TestCLI(unittest.TestCase):
    """Case 7: CLI surface works (subprocess test)."""

    def test_cli_help(self):
        out = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "hunt-starter.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(out.returncode, 0)
        self.assertIn("--workspace", out.stdout)
        self.assertIn("--limit", out.stdout)

    def test_cli_missing_workspace_errors(self):
        out = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "hunt-starter.py"), "--workspace", "/nonexistent_path_xyz_42"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(out.returncode, 0)


class TestRestoredToolsGraceful(unittest.TestCase):
    """Case 8: missing pattern-migration-alert.py / scan-report-thicken.py is OK."""

    def test_tool_versions_reflect_absence(self):
        ws = _make_ws()
        env = mod.run(ws, emit_files=False)
        # These two are absent at the time of test authoring.
        self.assertIn("pattern_migration_present", env["tool_versions"])
        self.assertIn("scan_report_thicken_present", env["tool_versions"])


class TestSeverityOrdering(unittest.TestCase):
    """Case 9: collect_candidates produces severity-ranked output (CRIT > HIGH > MED > LOW)."""

    def test_sort_order(self):
        ws = _make_ws()
        eq = {
            "queue": [
                {"lead_id": "A", "title": "T-low", "likely_severity": "low"},
                {"lead_id": "B", "title": "T-crit", "likely_severity": "critical"},
                {"lead_id": "C", "title": "T-high", "likely_severity": "high"},
            ]
        }
        (ws / ".auditooor" / "exploit_queue.json").write_text(json.dumps(eq), encoding="utf-8")
        cands = mod.collect_candidates(ws)
        # Sorted CRITICAL, HIGH, LOW
        self.assertEqual(cands[0]["severity_max"], "CRITICAL")
        self.assertEqual(cands[1]["severity_max"], "HIGH")
        self.assertEqual(cands[2]["severity_max"], "LOW")


class TestMakefileIntegration(unittest.TestCase):
    """Case 10: Makefile `hunt-starter` target exists and invokes our tool."""

    def test_makefile_target_present(self):
        mk = (ROOT / "Makefile").read_text(encoding="utf-8")
        # The target body uses tools/hunt-starter.py.
        self.assertIn("hunt-starter:", mk)
        self.assertIn("tools/hunt-starter.py", mk)
        self.assertIn("live-target-intel:", mk)
        self.assertIn("tools/live-target-intelligence-report.py", mk)
        self.assertIn("exploit_queue.source_mined.json", mk)


class TestVerdictPriorityList(unittest.TestCase):
    """Case 11: verdict label constants are documented in VERDICT_PRIORITY."""

    def test_all_labels_in_priority(self):
        for v in (
            mod.VERDICT_HUNT_READY,
            mod.VERDICT_HUNT_READY_RICH_CONTEXT,
            mod.VERDICT_LIKELY_DUPE_SKIP,
            mod.VERDICT_LIKELY_OOS_SKIP,
            mod.VERDICT_RUBRIC_NO_ROW_SKIP,
            mod.VERDICT_DESIGN_CHOICE_SKIP,
            mod.VERDICT_PAID_MATCH,
        ):
            self.assertIn(v, mod.VERDICT_PRIORITY)


class TestParseErrorHandled(unittest.TestCase):
    """Case 12: malformed JSON inputs are turned into LIKELY-OOS-SKIP rows, not crashes."""

    def test_malformed_exploit_queue(self):
        ws = _make_ws()
        (ws / ".auditooor" / "exploit_queue.json").write_text("not json {", encoding="utf-8")
        env = mod.run(ws, emit_files=False)
        # At least one parse-error row should land as LIKELY-OOS-SKIP.
        sk = [v for v in env["verdicts"] if v["verdict"] == mod.VERDICT_LIKELY_OOS_SKIP]
        self.assertTrue(any("parse-error" in r for v in sk for r in v["reasons"]))


# ---------------------------------------------------------------------------
# WIRING-1 lane new cases: P1+P3 enrichment + RICH-CONTEXT promotion.

class TestP1InvariantEnrichmentPerCategory(unittest.TestCase):
    """Case 13: P1 invariant matching joins by detector cluster category."""

    def test_match_p1_for_candidate_atomicity_go(self):
        # Synthesised P1 index with two atomicity entries for go + any.
        p1_index = {
            "atomicity|go": ["INV-ATOM-G-001", "INV-ATOM-G-002"],
            "atomicity|any": ["INV-ATOM-X-001"],
            "ordering|go": ["INV-ORD-G-001"],
        }
        candidate = {"detector": "go.crypto.race.unsynchronized"}
        matched = mod.match_p1_for_candidate(candidate, p1_index)
        # atomicity bucket fires + any-language bucket merged.
        self.assertIn("INV-ATOM-G-001", matched)
        self.assertIn("INV-ATOM-G-002", matched)
        self.assertIn("INV-ATOM-X-001", matched)
        self.assertNotIn("INV-ORD-G-001", matched)

    def test_match_p1_no_detector_returns_empty(self):
        # Candidates from exploit_queue.json have no detector slug.
        matched = mod.match_p1_for_candidate(
            {"candidate_id": "eq:EQ-001"}, {"atomicity|go": ["INV-X"]}
        )
        self.assertEqual(matched, [])

    def test_match_p1_unresolvable_cluster_returns_empty(self):
        # Cluster slug doesn't match any token in CLUSTER_TOKEN_TO_CATEGORY.
        matched = mod.match_p1_for_candidate(
            {"detector": "go.weirdo.unknown_token_xyz"},
            {"atomicity|go": ["INV-X"]},
        )
        self.assertEqual(matched, [])


class TestP3PatternEnrichmentPerLanguage(unittest.TestCase):
    """Case 14: P3 pattern matching joins by detector category + language."""

    def test_match_p3_solidity_reentrancy(self):
        p3_index = {
            "reentrancy|solidity": ["solidity.reentrancy-without-modifier"],
            "atomicity-and-ordering|go": ["go.race-condition-pattern"],
        }
        candidate = {"detector": "sol.contract.reentrancy.cross_call"}
        matched = mod.match_p3_for_candidate(candidate, p3_index)
        self.assertEqual(matched, ["solidity.reentrancy-without-modifier"])

    def test_match_p3_no_per_lang_match_emits_sentinel(self):
        # Go cluster + atomicity-and-ordering category, but no Go yaml yet.
        p3_index = {"atomicity-and-ordering|solidity": ["sol.foo"]}
        candidate = {"detector": "go.crypto.race.foo"}
        matched = mod.match_p3_for_candidate(candidate, p3_index)
        self.assertEqual(len(matched), 1)
        self.assertTrue(matched[0].startswith("no-P3-match:atomicity-and-ordering:go"))


class TestRichContextBucketActivation(unittest.TestCase):
    """Case 15: HUNT-READY-RICH-CONTEXT verdict promotion."""

    def test_rich_context_promotion_via_run(self):
        # Synthesise a workspace whose cluster has rich P1+P3 coverage.
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        # An auth-class Solidity cluster joins the real Solidity P3 catalog
        # and the audited P1 library has multiple authorization invariants.
        (ws / "engage_report.md").write_text("""# Engagement Report

## Clusters

### Cluster: `sol.contract.tx_origin.auth_bypass` (3 hits)

- **[HIGH] `sol.contract.tx_origin.auth_bypass`** - `src/Vault.sol:42`
  - snippet: `require(tx.origin == owner);`
""", encoding="utf-8")
        env = mod.run(ws, limit=None, emit_files=False)
        self.assertEqual(env["candidate_count"], 1)
        v = env["verdicts"][0]
        # The cluster resolves to authorization (P1) + auth-and-access-control
        # (P3), giving enough real P1/P3 context to promote.
        self.assertGreaterEqual(len(v["matched_p1_invariants"]), mod.HUNT_READY_RICH_MIN_P1)
        real_p3 = [p for p in v["matched_p3_patterns"] if not p.startswith("no-P3-match:")]
        self.assertGreaterEqual(len(real_p3), mod.HUNT_READY_RICH_MIN_P3)
        self.assertEqual(v["verdict"], mod.VERDICT_HUNT_READY_RICH_CONTEXT)

    def test_no_promotion_when_p3_only_sentinels(self):
        # Move cluster -> P3 returns only no-P3-match sentinels; should NOT
        # promote even if P1 hits are plentiful.
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        (ws / "engage_report.md").write_text("""# Engagement Report

## Clusters

### Cluster: `move.module.parse.unbounded_decode` (1 hits)

- **[LOW] `move.module.parse.unbounded_decode`** - `sources/x.move:1`
  - snippet: `x = nil`
""", encoding="utf-8")
        env = mod.run(ws, limit=None, emit_files=False)
        v = env["verdicts"][0]
        # P1 hits likely present (bounds|move + bounds|any), but P3
        # for Move has no yaml today -> sentinel only -> NOT promoted.
        real_p3 = [p for p in v["matched_p3_patterns"] if not p.startswith("no-P3-match:")]
        self.assertEqual(real_p3, [])
        self.assertNotEqual(v["verdict"], mod.VERDICT_HUNT_READY_RICH_CONTEXT)


class TestWorkspaceWithoutP5Report(unittest.TestCase):
    """Case 16: A workspace lacking the P5 LIVE_TARGET_REPORT.md doesn't break hunt-starter."""

    def test_run_emits_compose_metadata_even_without_p5(self):
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        (ws / "engage_report.md").write_text("""# Engagement Report

## Clusters

### Cluster: `test.detector` (1 hits)

- **[LOW] `test.detector`** - `src/foo.go:1`
  - snippet: `x = 1`
""", encoding="utf-8")
        # No docs/LIVE_TARGET_REPORT.md exists - hunt-starter must still
        # emit p1_p3_compose metadata + per-row matched_* fields.
        env = mod.run(ws, limit=None, emit_files=False)
        self.assertIn("p1_p3_compose", env)
        self.assertIn("p1_source", env["p1_p3_compose"])
        for v in env["verdicts"]:
            self.assertIn("matched_p1_invariants", v)
            self.assertIn("matched_p3_patterns", v)


class TestLiveTargetAndSourceMinedContext(unittest.TestCase):
    """Case 16b: WG001/WG003 wiring - P5 + source-mined rows are consumed."""

    def test_source_mined_queue_rows_are_first_class_with_impact_contract(self):
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        (ws / ".auditooor" / "exploit_queue.source_mined.json").write_text(json.dumps({
            "schema": "auditooor.exploit_queue.source_mined.v1",
            "queue": [
                {
                    "lead_id": "SRC-001",
                    "title": "source backed bridge replay",
                    "likely_severity": "high",
                    "attack_class": "replay",
                    "impact_path": "direct theft of user funds",
                    "source_refs": ["runtime/src/bridge.rs:120"],
                    "source_artifact_path": ".auditooor/source_artifacts/SRC-001.source_artifact.json",
                    "source_artifacts_complete": True,
                    "proof_status": "needs_harness",
                    "quality_gate_status": "pass",
                    "learning_route": "build-harness",
                    "impact_contract_id": "impact-contract-src-001",
                    "impact_contract_status": "mapped",
                    "impact_contract_gaps": [],
                    "listed_impact_selected": "Direct theft of user funds",
                    "negative_control": "consumed nonce must fail",
                    "next_command": "cargo test bridge_replay",
                },
                {
                    "lead_id": "SRC-KILLED",
                    "title": "killed row",
                    "proof_status": "killed",
                },
            ],
        }), encoding="utf-8")

        env = mod.run(ws, emit_files=False)
        self.assertEqual(env["source_mined_context"]["candidate_count"], 1)
        self.assertEqual(env["source_mined_context"]["with_impact_contract"], 1)
        row = env["verdicts"][0]
        self.assertEqual(row["source"], "exploit_queue.source_mined.json")
        self.assertEqual(row["candidate_id"], "smq:SRC-001")
        self.assertEqual(row["impact_contract_id"], "impact-contract-src-001")
        self.assertEqual(row["impact_contract_status"], "mapped")
        self.assertTrue(row["source_artifacts_complete"])
        self.assertEqual(row["proof_status"], "needs_harness")

    def test_live_target_context_pack_is_joined_by_cluster(self):
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        (ws / "engage_report.md").write_text("""# Engagement Report

## Clusters

### Cluster: `sol.contract.reentrancy.external_call_pre_state_write` (3 hits)

- **[HIGH] `sol.contract.reentrancy.external_call_pre_state_write`** - `src/Vault.sol:42`
  - snippet: `(bool ok,) = recipient.call{value: amt}("");`
""", encoding="utf-8")
        docs = ws / "docs"
        docs.mkdir()
        (docs / "LIVE_TARGET_REPORT.json").write_text(json.dumps({
            "schema": "auditooor.live_target_intelligence.v2",
            "prioritized_hunt_list": [
                {
                    "cluster_id": "sol.contract.reentrancy.external_call_pre_state_write",
                    "hunt_priority": "HIGH-PRIORITY-HUNT",
                    "engage_severity_score": 91.5,
                    "file_line": "src/Vault.sol:42",
                    "matched_anti_patterns": ["solidity.reentrancy-without-modifier"],
                    "matched_p1_invariants": ["INV-CTX-001"],
                    "composability_score": 2,
                }
            ],
        }), encoding="utf-8")

        env = mod.run(ws, emit_files=False)
        self.assertEqual(env["live_target_context"]["source"], "loaded")
        self.assertEqual(env["live_target_context"]["clusters"], 1)
        row = env["verdicts"][0]
        self.assertEqual(row["live_target_context"]["hunt_priority"], "HIGH-PRIORITY-HUNT")
        self.assertIn("INV-CTX-001", row["matched_p1_invariants"])
        self.assertTrue(any("P5 live-target context" in reason for reason in row["reasons"]))


class TestPilotAuditedSubsetPreference(unittest.TestCase):
    """Case 17: When invariants_pilot_audited.jsonl is present, prefer it."""

    def test_pilot_audited_preferred_when_present(self):
        # Build a tempdir mimicking the P1 file structure with a small
        # pilot_audited override.
        td = Path(tempfile.mkdtemp(prefix="hunt_p1_"))
        pa = td / "invariants_pilot_audited.jsonl"
        pa.write_text(
            json.dumps({"invariant_id": "INV-AUDITED-001", "category": "atomicity", "target_lang": "go"}) + "\n",
            encoding="utf-8",
        )
        p = td / "invariants_pilot.jsonl"
        p.write_text(
            json.dumps({"invariant_id": "INV-PILOT-001", "category": "atomicity", "target_lang": "go"}) + "\n",
            encoding="utf-8",
        )
        e = td / "invariants_extracted.jsonl"
        e.write_text(
            json.dumps({"invariant_id": "INV-EXTRACTED-001", "category": "atomicity", "target_lang": "go"}) + "\n",
            encoding="utf-8",
        )
        index, source = mod.load_p1_invariants(pilot_audited=pa, pilot=p, extracted=e)
        # Pilot-audited wins; pilot + extracted ignored.
        self.assertEqual(source, "pilot-audited")
        self.assertIn("INV-AUDITED-001", index.get("atomicity|go", []))
        self.assertNotIn("INV-PILOT-001", index.get("atomicity|go", []))
        self.assertNotIn("INV-EXTRACTED-001", index.get("atomicity|go", []))

    def test_full_library_fallback_when_pilot_audited_missing(self):
        td = Path(tempfile.mkdtemp(prefix="hunt_p1_"))
        # No pilot_audited.jsonl.
        pa = td / "invariants_pilot_audited.jsonl"
        p = td / "invariants_pilot.jsonl"
        p.write_text(
            json.dumps({"invariant_id": "INV-PILOT-001", "category": "atomicity", "target_lang": "go"}) + "\n",
            encoding="utf-8",
        )
        e = td / "invariants_extracted.jsonl"
        e.write_text(
            json.dumps({"invariant_id": "INV-EXTRACTED-001", "category": "atomicity", "target_lang": "go"}) + "\n",
            encoding="utf-8",
        )
        index, source = mod.load_p1_invariants(pilot_audited=pa, pilot=p, extracted=e)
        self.assertEqual(source, "full-library")
        self.assertIn("INV-PILOT-001", index.get("atomicity|go", []))
        self.assertIn("INV-EXTRACTED-001", index.get("atomicity|go", []))


class TestBackwardCompatExistingFixtures(unittest.TestCase):
    """Case 18: Original end-to-end fixture still passes verdict assertions."""

    def test_existing_e2e_fixture_still_valid(self):
        # Same fixture as TestEndToEnd.test_run_emits_artifacts but
        # asserts the new P1/P3 fields are present (not breaking shape).
        ws = _make_ws(severity_md=SEV_DYDX_LIKE)
        (ws / "engage_report.md").write_text("""# Engagement Report

## Clusters

### Cluster: `test.detector` (1 hits)

- **[LOW] `test.detector`** - `src/foo.go:1`
  - snippet: `x = 1`
""", encoding="utf-8")
        env = mod.run(ws, limit=None, emit_files=True)
        self.assertEqual(env["candidate_count"], 1)
        self.assertGreaterEqual(env["verdict_count"], 1)
        # Schema-preserving check: every verdict row carries the new fields.
        for v in env["verdicts"]:
            self.assertIn("matched_p1_invariants", v)
            self.assertIn("matched_p3_patterns", v)
            self.assertIsInstance(v["matched_p1_invariants"], list)
            self.assertIsInstance(v["matched_p3_patterns"], list)
        # Existing artifact-emit contract still holds.
        self.assertIn("artifacts", env)
        self.assertTrue(Path(env["artifacts"]["json"]).exists())
        self.assertTrue(Path(env["artifacts"]["md"]).exists())


class TestIfStaleOnly(unittest.TestCase):
    """Freshness short-circuit (--if-stale-only): the make-audit freshness path and
    the audit-deep `audit` prerequisite both re-invoke hunt-starter; regenerating the
    ranked artifact there is a full re-screen of every exploit-queue candidate and is
    pure waste when Step 1 just produced it. --if-stale-only skips a fresh artifact,
    regenerates a stale/missing one, and leaves the default (no flag) unchanged."""

    @staticmethod
    def _ranked(ws: Path) -> Path:
        return ws / ".auditooor" / "hunt_candidates_ranked.json"

    def test_fresh_artifact_is_skipped_not_overwritten(self):
        ws = _make_ws()
        ranked = self._ranked(ws)
        ranked.write_text('{"sentinel":"KEEP"}', encoding="utf-8")
        rc = mod.main(["--workspace", str(ws), "--if-stale-only"])
        self.assertEqual(rc, 0)
        self.assertEqual(ranked.read_text(encoding="utf-8"), '{"sentinel":"KEEP"}')

    def test_stale_artifact_is_regenerated(self):
        ws = _make_ws()
        ranked = self._ranked(ws)
        ranked.write_text('{"sentinel":"KEEP"}', encoding="utf-8")
        old = time.time() - 3600  # 60 min old
        os.utime(ranked, (old, old))
        rc = mod.main(["--workspace", str(ws), "--if-stale-only", "--stale-ttl-min", "45"])
        self.assertEqual(rc, 0)
        self.assertNotIn("KEEP", ranked.read_text(encoding="utf-8"))

    def test_missing_artifact_is_regenerated(self):
        ws = _make_ws()
        ranked = self._ranked(ws)
        self.assertFalse(ranked.exists())
        rc = mod.main(["--workspace", str(ws), "--if-stale-only"])
        self.assertEqual(rc, 0)
        self.assertTrue(ranked.exists())

    def test_default_no_flag_always_regenerates(self):
        ws = _make_ws()
        ranked = self._ranked(ws)
        ranked.write_text('{"sentinel":"KEEP"}', encoding="utf-8")
        rc = mod.main(["--workspace", str(ws)])
        self.assertEqual(rc, 0)
        self.assertNotIn("KEEP", ranked.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
