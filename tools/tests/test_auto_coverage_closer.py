# r36: lane AUTO-COVERAGE-CLOSER registered in .auditooor/agent_pathspec.json
"""Tests for tools/auto-coverage-closer.py + tools/rubric-to-hunt-seed.py.

Covers:
  - surface seeding (per-unit deterministic hunt over uncovered units)
  - rubric seeding (one brief + claim-free queue row per uncovered rubric row)
  - bounded-loop termination (fixpoint + max-iters; never infinite)
  - honesty (a no-finding verdict carries NO attack_class/severity/claim and
    self-labels coverage_credit=mechanical-source-cited; not an R80 PoC)
  - residual worker-dispatch queue emission

These tests build a tiny self-contained workspace with seeded coverage +
rubric reports so they do NOT depend on the heavy heatmap enumeration; the
orchestrator's measurement re-reads degrade gracefully to the on-disk reports
when the live enumerator finds no source (an empty fixture tree).
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent


def _load(name: str, rel: str):
    path = TOOLS_DIR / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
ACC = _load("acc_under_test", "auto-coverage-closer.py")
RTS = _load("rts_under_test", "rubric-to-hunt-seed.py")
HM = _load("hm_under_test", "workspace-coverage-heatmap.py")


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _mk_coverage_report(uncovered_units, total=10, covered=0):
    return {
        "schema": "auditooor.workspace_coverage_report.v1",
        "workspace_name": "fixture",
        "total_units": total,
        "covered": covered,
        "uncovered": len(uncovered_units),
        "uncovered_units": list(uncovered_units),
        "uncovered_units_truncated": False,
        "source_freshness": {},
        "numerator_freshness": {},
        "enumeration": {"source_root": ""},
    }


def _mk_rubric_report(uncovered_rows, total_rows=None):
    total = total_rows if total_rows is not None else len(uncovered_rows)
    return {
        "schema": "auditooor.workspace_rubric_coverage.v1",
        "workspace": "fixture",
        "severity_md": "SEVERITY.md",
        "total_rows": total,
        "rows_with_candidate": total - len(uncovered_rows),
        "rows_uncovered": len(uncovered_rows),
        "rubric_coverage_fraction": 0.0,
        "candidates_scanned": 0,
        "uncovered_rows": list(uncovered_rows),
        "covered_rows": [],
        "rows": [],
    }


class RubricSeedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "fixture"
        (self.ws / ".auditooor").mkdir(parents=True)
        self.rows = [
            {"tier": "critical", "rubric_id": "C1",
             "sentence": "Balance manipulation: minting tokens out of thin air."},
            {"tier": "high", "rubric_id": "",
             "sentence": "Loss of funds requiring specific preconditions."},
        ]
        _write_json(self.ws / ".auditooor" / "rubric_coverage_report.json",
                    _mk_rubric_report(self.rows))
        _write_json(self.ws / ".auditooor" / "coverage_report.json",
                    _mk_coverage_report(["Vault.sol::withdraw", "Pool.sol::deposit"]))

    def tearDown(self):
        self.tmp.cleanup()

    def test_seeds_one_brief_per_uncovered_row(self):
        res = RTS.seed(self.ws, seed_queue=True)
        self.assertEqual(res["uncovered_rows_seeded"], 2)
        self.assertEqual(res["queue_rows_written"], 2)
        briefs = list((self.ws / ".auditooor" / "rubric_hunt_briefs").glob("*.md"))
        self.assertEqual(len(briefs), 2)

    def test_queue_row_is_claim_free_and_noun_free_title(self):
        RTS.seed(self.ws, seed_queue=True)
        q = json.loads((self.ws / ".auditooor" / "exploit_queue.json").read_text())
        rubric_rows = [r for r in q["queue"]
                       if r.get("source") == "unattempted-rubric-class"]
        self.assertEqual(len(rubric_rows), 2)
        for r in rubric_rows:
            # claim-free: no attack_class/severity/etc.
            for f in RTS.FORBIDDEN_CLAIM_FIELDS:
                self.assertNotIn(f, r)
            # title must NOT echo the load-bearing impact nouns (no self-credit)
            self.assertNotIn("minting", r["title"].lower())
            self.assertNotIn("balance manipulation", r["title"].lower())
            # rubric_sentence is NOT stored on the queue row (only in the brief)
            self.assertNotIn("rubric_sentence", r)

    def test_no_self_credit_of_rubric_rows(self):
        # Seeding the targets must NOT mark the rubric rows covered: a claim-free
        # target is not a candidate. We assert the seeded queue rows carry no
        # impact wording any blob-reader could match.
        RTS.seed(self.ws, seed_queue=True)
        q = json.loads((self.ws / ".auditooor" / "exploit_queue.json").read_text())
        for r in q["queue"]:
            if r.get("source") != "unattempted-rubric-class":
                continue
            blob = " ".join(
                str(r.get(k, "")) for k in
                ("title", "impact", "selected_impact", "summary", "description",
                 "listed_impact", "attack_class", "impact_claim")
            ).lower()
            self.assertNotIn("minting", blob)
            self.assertNotIn("loss of funds", blob)

    def test_dry_run_writes_nothing(self):
        res = RTS.seed(self.ws, seed_queue=True, dry_run=True)
        self.assertEqual(res["uncovered_rows_seeded"], 2)
        self.assertFalse((self.ws / ".auditooor" / "rubric_hunt_briefs").exists())
        self.assertFalse((self.ws / ".auditooor" / "exploit_queue.json").exists())

    def test_idempotent_reseed(self):
        RTS.seed(self.ws, seed_queue=True)
        res2 = RTS.seed(self.ws, seed_queue=True)
        # second pass refreshes, does not duplicate
        self.assertEqual(res2["queue_rows_written"], 0)
        self.assertEqual(res2["queue_rows_updated"], 2)
        q = json.loads((self.ws / ".auditooor" / "exploit_queue.json").read_text())
        rubric_rows = [r for r in q["queue"]
                       if r.get("source") == "unattempted-rubric-class"]
        self.assertEqual(len(rubric_rows), 2)


class PerUnitHuntHonestyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "fixture"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_finding_verdict_carries_no_claim(self):
        # a unit with no invariant-anchorable keywords -> no questions ->
        # mechanical-hunt-no-finding, which MUST carry no claim.
        sidecar = ACC._run_unit_deterministic_hunt(
            self.ws, "Misc.sol::helperFoo", "src/Misc.sol", run_id="t1"
        )
        self.assertEqual(sidecar["verdict"], ACC.VERDICT_NO_FINDING)
        self.assertEqual(sidecar["coverage_credit"], ACC.COVERAGE_CREDIT_LABEL)
        self.assertFalse(sidecar["is_r80_poc"])
        for f in ACC.FORBIDDEN_NO_FINDING_FIELDS:
            self.assertNotIn(f, sidecar)

    def test_keyword_unit_emits_questions_needs_llm(self):
        # a unit whose name carries an anchorable keyword -> questions ->
        # needs-llm-depth (still no proven impact).
        sidecar = ACC._run_unit_deterministic_hunt(
            self.ws, "Vault.sol::withdraw", "src/Vault.sol", run_id="t1"
        )
        self.assertEqual(sidecar["verdict"], ACC.VERDICT_NEEDS_LLM)
        self.assertGreater(sidecar["question_count"], 0)
        # needs-llm is still claim-free about a PROVEN bug; it only records fuel
        self.assertNotIn("exploit_proven", sidecar)
        self.assertFalse(sidecar["is_r80_poc"])

    def test_per_unit_pass_writes_sidecars(self):
        units = ["Vault.sol::withdraw", "Misc.sol::helperFoo", "Token.sol::mint"]
        res = ACC._per_unit_hunt_pass(self.ws, units, run_id="t1", unit_cap=400)
        self.assertEqual(res["units_processed"], 3)
        self.assertEqual(
            res["mechanical_hunt_no_finding"] + res["needs_llm_depth"], 3
        )
        sidecars = list(
            (self.ws / ".auditooor" / "coverage_unit_verdicts").glob("*.json")
        )
        self.assertEqual(len(sidecars), 3)

    def test_unit_cap_bounds_processing(self):
        units = [f"F{i}.sol::withdraw" for i in range(50)]
        res = ACC._per_unit_hunt_pass(self.ws, units, run_id="t1", unit_cap=5)
        self.assertEqual(res["units_processed"], 5)


class ResidualQueueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "fixture"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_emits_surface_and_rubric_residuals(self):
        needs_llm = ["Vault.sol::withdraw", "Pool.sol::deposit"]
        uncovered_rows = [
            {"tier": "critical", "rubric_id": "C1", "sentence": "Balance manip."},
        ]
        payload = ACC._emit_residual_queue(
            self.ws, needs_llm, uncovered_rows, run_id="t1"
        )
        self.assertEqual(payload["residual_surface_units"], 2)
        self.assertEqual(payload["residual_rubric_classes"], 1)
        self.assertEqual(payload["total_residual"], 3)
        on_disk = json.loads(
            (self.ws / ".auditooor" / "coverage_residual_worker_queue.json").read_text()
        )
        self.assertEqual(on_disk["schema"], ACC.RESIDUAL_QUEUE_SCHEMA)
        kinds = {it["kind"] for it in on_disk["items"]}
        self.assertEqual(kinds, {"surface-unit", "rubric-class"})

    def test_empty_residual_when_nothing_outstanding(self):
        payload = ACC._emit_residual_queue(self.ws, [], [], run_id="t1")
        self.assertEqual(payload["total_residual"], 0)


class BoundedLoopTest(unittest.TestCase):
    """The loop MUST terminate: fixpoint (no strict decrease) OR max-iters.

    We stub the seed/measure helpers so the test is fast and deterministic and
    does not invoke the real heatmap / subprocess tools.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "fixture"
        (self.ws / ".auditooor").mkdir(parents=True)
        self._orig = {}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(ACC, k, v)
        self.tmp.cleanup()

    def _stub(self, name, fn):
        self._orig[name] = getattr(ACC, name)
        setattr(ACC, name, fn)

    def test_fixpoint_stops_when_no_progress(self):
        # effective_uncovered stays constant -> must stop after the 2nd iter via
        # fixpoint (never reaches max_iters=9).
        self._stub("_seed_surface", lambda ws, rid: {"rc": 0, "seed_rows_total": 0,
                   "rows_written": 0, "rows_updated": 0, "verdict": "x"})
        self._stub("_seed_rubric", lambda ws, rid: {"rc": 0,
                   "uncovered_rows_seeded": 0, "queue_rows_written": 0,
                   "queue_rows_updated": 0, "seeded_briefs": [], "verdict": "x"})
        self._stub("_rebuild_coverage_report",
                   lambda ws: _mk_coverage_report(["A.sol::f", "B.sol::g"], total=10, covered=8))
        self._stub("_read_g15_result", lambda ws, rid: {
            "verdict": "fail-coverage-below-threshold",
            "uncovered_count": 2, "coverage_fraction": 0.8,
            "unlogged_uncovered": ["A.sol::f", "B.sol::g"]})
        self._stub("_read_rubric_uncovered",
                   lambda ws: (_mk_rubric_report([{"tier": "high", "rubric_id": "",
                                                   "sentence": "loss"}]),
                               [{"tier": "high", "rubric_id": "", "sentence": "loss"}]))
        res = ACC.run(self.ws, max_iters=9, coverage_threshold=1.0, unit_cap=10)
        self.assertEqual(res["stop_reason"], "fixpoint-no-progress")
        self.assertLessEqual(res["iters_run"], 2)

    def test_coverage_threshold_met_stops(self):
        self._stub("_seed_surface", lambda ws, rid: {"rc": 0, "seed_rows_total": 0,
                   "rows_written": 0, "rows_updated": 0, "verdict": "x"})
        self._stub("_seed_rubric", lambda ws, rid: {"rc": 0,
                   "uncovered_rows_seeded": 0, "queue_rows_written": 0,
                   "queue_rows_updated": 0, "seeded_briefs": [], "verdict": "x"})
        self._stub("_rebuild_coverage_report",
                   lambda ws: _mk_coverage_report([], total=10, covered=10))
        self._stub("_read_g15_result", lambda ws, rid: {
            "verdict": "pass-coverage-met", "uncovered_count": 0,
            "coverage_fraction": 1.0, "unlogged_uncovered": []})
        self._stub("_read_rubric_uncovered",
                   lambda ws: (_mk_rubric_report([]), []))
        res = ACC.run(self.ws, max_iters=5, coverage_threshold=1.0, unit_cap=10)
        self.assertEqual(res["stop_reason"], "coverage-threshold-met-and-rubric-complete")
        self.assertEqual(res["iters_run"], 1)

    def test_max_iters_caps_when_progress_continues(self):
        # effective_uncovered strictly decreases every iter, but never hits 0,
        # so the loop must stop at max_iters (never infinite).
        state = {"u": 10}

        def cov(ws):
            return _mk_coverage_report(
                [f"F{i}.sol::f" for i in range(state["u"])], total=20, covered=20 - state["u"])

        def g15(ws, rid):
            u = state["u"]
            state["u"] = max(1, u - 1)  # strict decrease, floored at 1
            return {"verdict": "fail-coverage-below-threshold",
                    "uncovered_count": u, "coverage_fraction": (20 - u) / 20,
                    "unlogged_uncovered": [f"F{i}.sol::f" for i in range(u)]}

        self._stub("_seed_surface", lambda ws, rid: {"rc": 0, "seed_rows_total": 0,
                   "rows_written": 0, "rows_updated": 0, "verdict": "x"})
        self._stub("_seed_rubric", lambda ws, rid: {"rc": 0,
                   "uncovered_rows_seeded": 0, "queue_rows_written": 0,
                   "queue_rows_updated": 0, "seeded_briefs": [], "verdict": "x"})
        self._stub("_rebuild_coverage_report", cov)
        self._stub("_read_g15_result", g15)
        self._stub("_read_rubric_uncovered",
                   lambda ws: (_mk_rubric_report([{"tier": "high", "rubric_id": "",
                                                   "sentence": "loss"}]),
                               [{"tier": "high", "rubric_id": "", "sentence": "loss"}]))
        res = ACC.run(self.ws, max_iters=3, coverage_threshold=1.0, unit_cap=5)
        self.assertEqual(res["stop_reason"], "max-iters-reached")
        self.assertEqual(res["iters_run"], 3)

    def test_run_writes_snapshot_and_residual(self):
        self._stub("_seed_surface", lambda ws, rid: {"rc": 0, "seed_rows_total": 0,
                   "rows_written": 0, "rows_updated": 0, "verdict": "x"})
        self._stub("_seed_rubric", lambda ws, rid: {"rc": 0,
                   "uncovered_rows_seeded": 0, "queue_rows_written": 0,
                   "queue_rows_updated": 0, "seeded_briefs": [], "verdict": "x"})
        self._stub("_rebuild_coverage_report",
                   lambda ws: _mk_coverage_report([], total=5, covered=5))
        self._stub("_read_g15_result", lambda ws, rid: {
            "verdict": "pass-coverage-met", "uncovered_count": 0,
            "coverage_fraction": 1.0, "unlogged_uncovered": []})
        self._stub("_read_rubric_uncovered", lambda ws: (_mk_rubric_report([]), []))
        res = ACC.run(self.ws, max_iters=2, coverage_threshold=1.0, unit_cap=5)
        self.assertEqual(res["schema"], ACC.SCHEMA)
        self.assertTrue((self.ws / ".auditooor" / "auto_coverage_closer_last_result.json").exists())
        self.assertTrue((self.ws / ".auditooor" / "coverage_residual_worker_queue.json").exists())


class FunctionLevelCoverageAllLanguagesTest(unittest.TestCase):
    """Item 3: non-Solidity languages enumerate at FUNCTION granularity.

    The heatmap historically degraded .rs/.go/.move/.cairo/.vy to FILE-level.
    They are now FUNCTION-granular (in-file regex parse mirroring
    per-function-invariant-gen) and PREFER the per_function_invariants manifest
    when present. .sol behavior is unchanged.
    # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "fixture"
        (self.ws / "src").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel, body):
        p = self.ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_sol_unchanged_function_granular(self):
        self._write("src/Vault.sol",
                    "contract V {\n function deposit(uint x) external {}\n"
                    " function withdraw(uint x) external {}\n constructor(){}\n}")
        units, detail = HM.enumerate_units(self.ws)
        self.assertIn("Vault.sol::deposit", units)
        self.assertIn("Vault.sol::withdraw", units)
        self.assertIn("Vault.sol::constructor", units)
        self.assertEqual(detail["granularity"].get(".sol"), "function")

    def test_go_function_granular(self):
        self._write("src/pool.go",
                    "package pool\nfunc Deposit(x uint) {}\n"
                    "func (p *Pool) Withdraw(x uint) {}\n")
        units, detail = HM.enumerate_units(self.ws)
        self.assertIn("pool.go::Deposit", units)
        self.assertIn("pool.go::Withdraw", units)
        self.assertEqual(detail["granularity"].get(".go"), "function")

    def test_move_cairo_vy_function_granular(self):
        self._write("src/token.move",
                    "module token {\n public fun mint(a: u64) {}\n"
                    " entry fun burn(a: u64) {}\n}")
        self._write("src/c.cairo",
                    "fn transfer(a: u256) {}\npub fn approve(a: u256) {}")
        self._write("src/v.vy",
                    "@external\ndef deposit(x: uint256):\n    pass\n"
                    "def _helper(x: uint256):\n    pass")
        units, _ = HM.enumerate_units(self.ws)
        self.assertIn("token.move::mint", units)
        self.assertIn("token.move::burn", units)
        self.assertIn("c.cairo::transfer", units)
        self.assertIn("c.cairo::approve", units)
        self.assertIn("v.vy::deposit", units)
        self.assertIn("v.vy::_helper", units)

    def test_rust_function_granular_no_manifest(self):
        # plain .rs with no manifest -> in-file regex parse (function-level).
        self._write("src/lib.rs",
                    "pub fn alpha(x: u64) -> u64 { x }\n"
                    "fn beta() {}\nasync fn gamma() {}")
        units, detail = HM.enumerate_units(self.ws)
        self.assertIn("lib.rs::alpha", units)
        self.assertIn("lib.rs::beta", units)
        self.assertIn("lib.rs::gamma", units)
        self.assertEqual(detail["granularity"].get(".rs"), "function")

    def test_manifest_preferred_over_regex(self):
        # When the per_function_invariants manifest covers a file, its function
        # list is the authoritative enumeration (item 3 manifest preference).
        self._write("src/accounts.rs",
                    "pub fn into_owned() {}\nfn private_helper() {}")
        manifest = {
            "schema": "auditooor.per_function_invariant.v1",
            "language": "rust",
            "function_count": 2,
            "functions": [
                {"function": "into_owned",
                 "source": "src/accounts.rs:1", "language": "rust"},
                {"function": "manifest_only_fn",
                 "source": "src/accounts.rs:5", "language": "rust"},
            ],
        }
        _write_json(
            self.ws / ".auditooor" / "per_function_invariants" / "manifest.json",
            manifest,
        )
        idx = HM._load_per_fn_manifest_index(self.ws)
        self.assertIn("src/accounts.rs", idx)
        self.assertIn("manifest_only_fn", idx["src/accounts.rs"])
        units, detail = HM.enumerate_units(self.ws)
        # manifest-listed function present even though it is not the only regex
        # match - manifest is authoritative
        self.assertIn("accounts.rs::into_owned", units)
        self.assertIn("accounts.rs::manifest_only_fn", units)
        self.assertEqual(
            detail["granularity"].get(".rs"), "per_function_invariant_manifest"
        )

    def test_manifest_index_strips_line_suffix(self):
        manifest = {
            "functions": [
                {"function": "foo", "source": "src/a.rs:42", "language": "rust"},
                {"function": "bar", "source": "src/a.rs:99", "language": "rust"},
            ]
        }
        _write_json(
            self.ws / ".auditooor" / "per_function_invariants" / "manifest.json",
            manifest,
        )
        idx = HM._load_per_fn_manifest_index(self.ws)
        self.assertEqual(sorted(idx.get("src/a.rs", [])), ["bar", "foo"])


class FullArsenalPerUnitTest(unittest.TestCase):
    """Item 4: each uncovered unit is driven through the FULL bounded arsenal
    (per-fn hacker-questions + scoped detector + per-fn mimo harness brief +
    invariant-synth), recording WHICH tools ran + their (no-finding|hypothesis)
    result, bounded + honest (no claim on no-finding).
    # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "fixture"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sidecar_records_all_four_arsenal_tools(self):
        sc = ACC._run_unit_deterministic_hunt(
            self.ws, "Vault.sol::withdraw", "src/Vault.sol", run_id="t1"
        )
        ran = sc["arsenal_tools_ran"]
        self.assertIn("per-function-hacker-questions", ran)
        self.assertIn("scoped-detector", ran)
        self.assertIn("per-fn-mimo-harness", ran)
        self.assertIn("invariant-auto-synth", ran)
        # each record carries tool/status/result
        for tr in sc["arsenal_tools"]:
            self.assertIn(tr["status"], (
                ACC.TOOL_STATUS_RAN, ACC.TOOL_STATUS_TIMEOUT,
                ACC.TOOL_STATUS_UNAVAILABLE, ACC.TOOL_STATUS_ERROR,
            ))
            self.assertIn(tr["result"], (
                ACC.TOOL_RESULT_NO_FINDING, ACC.TOOL_RESULT_HYPOTHESIS, "n/a",
            ))

    def test_hypothesis_tool_drives_needs_llm(self):
        # a keyword unit yields hacker questions -> hypothesis -> needs-llm
        sc = ACC._run_unit_deterministic_hunt(
            self.ws, "Vault.sol::withdraw", "src/Vault.sol", run_id="t1"
        )
        self.assertEqual(sc["verdict"], ACC.VERDICT_NEEDS_LLM)
        self.assertIn("per-function-hacker-questions",
                      sc["arsenal_hypothesis_tools"])

    def test_no_finding_unit_carries_no_claim(self):
        # a unit with no anchorable keywords -> no hypotheses from question/
        # mimo, detector unavailable for .sol, invariant clean -> no-finding,
        # which MUST carry no claim field (R80 honesty).
        sc = ACC._run_unit_deterministic_hunt(
            self.ws, "Misc.sol::helperFoo", "src/Misc.sol", run_id="t1"
        )
        self.assertEqual(sc["verdict"], ACC.VERDICT_NO_FINDING)
        self.assertFalse(sc["is_r80_poc"])
        for f in ACC.FORBIDDEN_NO_FINDING_FIELDS:
            self.assertNotIn(f, sc)
        # no arsenal tool may ever emit a claim field either
        for tr in sc["arsenal_tools"]:
            for f in ACC.FORBIDDEN_NO_FINDING_FIELDS:
                self.assertNotIn(f, tr)

    def test_arsenal_cache_shared_across_pass(self):
        # the per-pass arsenal tally aggregates per-tool results
        units = ["Vault.sol::withdraw", "Token.sol::mint", "Misc.sol::helperFoo"]
        res = ACC._per_unit_hunt_pass(self.ws, units, run_id="t1", unit_cap=400)
        self.assertEqual(res["units_processed"], 3)
        self.assertIn("arsenal_tool_tally", res)
        # every unit drives the hacker-q tool
        self.assertIn("per-function-hacker-questions", res["arsenal_tool_tally"])

    def test_unit_cap_still_bounds_arsenal(self):
        units = [f"F{i}.sol::withdraw" for i in range(30)]
        res = ACC._per_unit_hunt_pass(self.ws, units, run_id="t1", unit_cap=4)
        self.assertEqual(res["units_processed"], 4)

    def test_slow_tool_timeout_not_skipped(self):
        # a per-tool timeout records a `timeout` status, NOT a silent skip.
        rc, out, err, timed_out = ACC._shell_timeout(
            [ACC.sys.executable, "-c", "import time; time.sleep(5)"], 1
        )
        self.assertTrue(timed_out)
        self.assertEqual(rc, 124)

    def test_mimo_harness_brief_is_advisory_not_poc(self):
        questions = [{"question": "can withdraw underflow the balance?"}]
        rec = ACC._arsenal_mimo_harness(
            self.ws, "Vault.sol::withdraw", "src/Vault.sol", questions, "t1"
        )
        self.assertEqual(rec["result"], ACC.TOOL_RESULT_HYPOTHESIS)
        brief_path = Path(rec["detail"]["brief_path"])
        self.assertTrue(brief_path.is_file())
        brief = json.loads(brief_path.read_text())
        self.assertTrue(brief["advisory"])
        self.assertFalse(brief["is_r80_poc"])
        for f in ACC.FORBIDDEN_NO_FINDING_FIELDS:
            self.assertNotIn(f, brief)


class MevOrderingFoldTest(unittest.TestCase):
    """MOL hypotheses fold into per_fn_hacker_questions as needs-fuzz fuel."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = Path(self.tmp)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        rec = {
            "file": "src/Pool.sol",
            "function": "swapOut",
            "language": "sol",
            "read_kind": "balanceof-this-reserve",
            "sensitivity_reason": "balanceOf(this) as reserve denominator",
            "protection_reason": "no minOut slippage bound, no deadline",
            "attack_class": "sandwich-front-run-ordering",
            "source": "MOL",
            "verdict": "needs-fuzz",
        }
        (self.ws / ".auditooor" / "mev_ordering_hypotheses.jsonl").write_text(
            json.dumps(rec) + "\n", encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mol_hypothesis_becomes_needs_fuzz_question(self):
        res = ACC._fold_lane_hypotheses_into_corpus(self.ws, "mol-fold-test")
        self.assertGreaterEqual(res.get("appended", 0), 1)
        out = self.ws / ACC.PER_FN_HACKER_QUESTIONS_REL
        rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        mol = [r for r in rows if "[MOL]" in (r.get("question") or "")]
        self.assertEqual(len(mol), 1, f"expected 1 MOL question, got {len(mol)}")
        self.assertEqual(mol[0].get("verdict"), "needs-fuzz",
                         "MOL question must never auto-credit - verdict=needs-fuzz")
        self.assertIn("swapOut", mol[0]["question"])
        self.assertEqual(mol[0].get("attack_class"), "sandwich-front-run-ordering")


class FoldQuestionInScopeTest(unittest.TestCase):
    """_fold_question_in_scope: only filters when an authoritative inscope
    manifest exists; drops out-of-scope/stale source paths (e.g. rust units in
    a Solidity-scoped workspace) without breaking the no-manifest legacy path."""

    def test_no_manifest_keeps_all(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self.assertTrue(ACC._fold_question_in_scope(ws, "src/whatever.sol", None))
            self.assertTrue(ACC._fold_question_in_scope(ws, "src/rust/x.rs", None))

    def test_manifest_filters_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            insc = {str((ws / "src/solidity/contracts/Mailbox.sol").resolve())}
            self.assertTrue(ACC._fold_question_in_scope(
                ws, "src/solidity/contracts/Mailbox.sol", insc))
            self.assertFalse(ACC._fold_question_in_scope(
                ws, "src/rust/main/ethers-prometheus/src/contracts/erc_20.rs", insc))
            self.assertFalse(ACC._fold_question_in_scope(ws, "", insc))


if __name__ == "__main__":
    unittest.main()
