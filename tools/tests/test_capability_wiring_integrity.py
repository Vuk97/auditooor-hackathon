#!/usr/bin/env python3
"""Non-vacuous tests for tools/capability-wiring-integrity-check.py.

Calibration oracles (assert against the REAL repo, per the build brief):
  * a3-authority-blast-radius            -> WIRED (audit-deep Step 28b + drain)
  * go-detector-runner-advisory-lanes-*  -> WIRED (audit-deep Step 5b + GO fold)
  * ru1-rust-untrusted-ingress-panic     -> WIRED (audit-deep Step 5c + RUST fold;
                                            was ORPHAN before a1064c6014 wired it)
  * CAP-routing-integrity-check          -> WIRED (audit-deep run_routing_integrity_audit;
                                            was the last not-invoked orphan before this wiring)

The synthetic-fixture test (SyntheticFixtureTest) independently pins the checker's
ORPHAN -> rc 1 under --enforce and rc 0 (WARN) by default behaviour, so the live
inventory no longer has to carry a real orphan to prove the detector works. A
capability_set_hash stability/staleness test rounds it out.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "tools" / "capability-wiring-integrity-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("cap_wiring_integrity", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _verdicts(report: dict) -> dict:
    return {e["id"]: e["verdict"] for e in report["rows"]}


class RealRepoCalibrationTest(unittest.TestCase):
    """The three authoritative calibration oracles on the live inventory."""

    @classmethod
    def setUpClass(cls):
        cls.report, cls.rc = MOD.run(REPO, enforce=False)
        cls.by_id = {e["id"]: e for e in cls.report["rows"]}
        cls.verdicts = _verdicts(cls.report)

    def test_a3_authority_blast_radius_is_wired(self):
        e = self.by_id.get("a3-authority-blast-radius")
        self.assertIsNotNone(e, "A3 row missing from inventory")
        self.assertEqual(
            e["verdict"], "WIRED",
            f"A3 must be WIRED (audit-deep Step 28b + exploit-queue drain); got "
            f"{e['verdict']} inv={e['invoked']} feeds_to={e['feeds_to']} reasons={e['reasons']}",
        )
        self.assertTrue(e["invoked"])
        self.assertTrue(e["feeds_to"])

    def test_go_lane_is_wired(self):
        e = self.by_id.get("go-detector-runner-advisory-lanes-wave2")
        self.assertIsNotNone(e, "Go advisory-lanes row missing from inventory")
        self.assertEqual(
            e["verdict"], "WIRED",
            f"Go lanes must be WIRED (audit-deep Step 5b + GO_ADVISORY fold); got "
            f"{e['verdict']} reasons={e['reasons']}",
        )
        self.assertTrue(e["invoked"])
        self.assertTrue(e["feeds_to"])

    def test_rust_lane_is_now_wired(self):
        # UPDATED 2026-07-10: the rust-detector-runner advisory axes are now auto-run
        # by audit-deep Step 5c (commit a1064c6014) + folded (RUST_ADVISORY_HYPOTHESES_REL),
        # so ru1-rust-untrusted-ingress-panic flipped ORPHAN -> WIRED. That is CORRECT
        # (real wiring progress), so this oracle now pins the WIRED state; the orphan
        # calibration moved to test_current_orphan_is_detected below.
        e = self.by_id.get("ru1-rust-untrusted-ingress-panic")
        self.assertIsNotNone(e, "RU1 row missing from inventory")
        self.assertEqual(
            e["verdict"], "WIRED",
            f"RU1 must be WIRED now (rust-detector-runner auto-run by audit-deep Step 5c); "
            f"got {e['verdict']} inv={e['invoked']} feeds_to={e['feeds_to']} reasons={e['reasons']}",
        )
        self.assertTrue(e["invoked"])

    def test_routing_integrity_is_now_wired(self):
        # UPDATED: CAP-routing-integrity-check was the last not-invoked orphan. It is
        # now auto-run by audit-deep's run_routing_integrity_audit stage (same
        # repo-corpus advisory phase as run_r37_audit), so it flipped ORPHAN -> WIRED.
        # This is the non-vacuous regression proof that the stage now INVOKES the tool:
        # revert the audit-deep.sh wiring and this assertion (invoked/verdict) fails.
        e = self.by_id.get("CAP-routing-integrity-check")
        self.assertIsNotNone(e, "CAP-routing-integrity-check row missing from inventory")
        self.assertEqual(
            e["verdict"], "WIRED",
            f"CAP-routing-integrity-check must be WIRED now (audit-deep "
            f"run_routing_integrity_audit runs routing-integrity-check.py); got "
            f"{e['verdict']} inv={e['invoked']} feeds_to={e['feeds_to']} reasons={e['reasons']}",
        )
        self.assertTrue(e["invoked"], "routing-integrity-check.py must be auto-run/invoked")
        self.assertIn("routing-integrity-check.py", e["invoked_by"])
        self.assertNotIn("CAP-routing-integrity-check",
                         {o["id"] for o in self.report["orphans"]})

    def test_audit_deep_dispatches_routing_integrity_stage(self):
        # Hardening beyond the substring/invoked check: the wiring checker only looks
        # for the tool basename SOMEWHERE in audit-deep.sh, which a defined-but-never-
        # called function would still satisfy. Assert the stage function BOTH exists
        # (and references the tool) AND is actually dispatched at top level.
        audit_deep = (REPO / "tools" / "audit-deep.sh").read_text(encoding="utf-8")
        self.assertIn("run_routing_integrity_audit()", audit_deep,
                      "run_routing_integrity_audit function must be defined")
        self.assertIn("routing-integrity-check.py", audit_deep,
                      "the stage must reference tools/routing-integrity-check.py")
        # The dispatch call (not the definition) must be present exactly once at the
        # top-level run sequence, immediately following the R37 audit dispatch.
        self.assertIn('run_routing_integrity_audit "$RUN_LOG"', audit_deep,
                      "run_routing_integrity_audit must be dispatched in the main run flow")
        r37_idx = audit_deep.find('run_r37_audit "$RUN_LOG"')
        ri_idx = audit_deep.find('run_routing_integrity_audit "$RUN_LOG"')
        self.assertGreater(r37_idx, 0, "run_r37_audit dispatch not found (DAG anchor)")
        self.assertGreater(ri_idx, r37_idx,
                           "routing-integrity dispatch must come after the R37 corpus audit")

    def test_enforce_rc_matches_orphan_presence(self):
        # The checker MUST fail-close under --enforce iff a real problem exists. With
        # the live inventory now clean (0 orphan/0 broken-flow) that means rc 0; a
        # future orphan/broken-flow flips it to rc 1. SyntheticFixtureTest below pins
        # the rc-1-on-orphan path independently of the live inventory's cleanliness.
        problems = self.report["counts"]["orphan"] + self.report["counts"]["broken_flow"]
        _report, rc = MOD.run(REPO, enforce=True)
        self.assertEqual(rc, 1 if problems else 0,
                         f"enforce rc must track problem count (problems={problems})")

    def test_default_is_advisory_rc0(self):
        self.assertEqual(self.rc, 0, "default (WARN) run must never hard-block (rc 0)")
        self.assertIn(self.report["verdict"], ("WARN-wiring-integrity", "pass-wiring-integrity"))

    def test_capability_set_hash_is_stable_hex64(self):
        h = self.report["capability_set_hash"]
        self.assertEqual(len(h), 64)
        int(h, 16)  # raises if not hex


class SyntheticFixtureTest(unittest.TestCase):
    """A fully controlled tiny repo: exactly one WIRED cap + one ORPHAN cap."""

    def _build_fixture(self, tmp: Path):
        (tmp / "reference").mkdir(parents=True)
        (tmp / "tools").mkdir(parents=True)

        wired = {
            "id": "cap-wired-foo",
            "name": "foo-lane",
            "category": "python-tool",
            "status": "LANDED",
            "inputs": [".auditooor/inscope_units.jsonl"],
            "outputs": [".auditooor/foo_hyp.jsonl"],
            "file_paths": ["tools/foo.py", "tools/tests/test_foo.py"],
            "consumers": [],
        }
        orphan = {
            "id": "cap-orphan-bar",
            "name": "bar-lane",
            "category": "python-tool",
            "status": "LANDED",
            "inputs": ["rust source"],
            "outputs": [".auditooor/bar_hyp.jsonl"],
            "file_paths": ["tools/bar.py"],
            "consumers": [],  # no declared consumer -> orphan cannot be rescued
        }
        (tmp / "reference" / "capability_inventory.jsonl").write_text(
            json.dumps(wired) + "\n" + json.dumps(orphan) + "\n", encoding="utf-8"
        )

        # audit-deep runs foo.py (invokes it) but never bar.py.
        (tmp / "tools" / "audit-deep.sh").write_text(
            '#!/usr/bin/env bash\npython3 "$HERE/foo.py" --workspace "$WORKSPACE"\n',
            encoding="utf-8",
        )
        # closer consumes BOTH outputs (so bar's orphan-ness is purely not-invoked).
        (tmp / "tools" / "auto-coverage-closer.py").write_text(
            'REL = [".auditooor/foo_hyp.jsonl", ".auditooor/bar_hyp.jsonl"]\n',
            encoding="utf-8",
        )
        (tmp / "tools" / "readme_runbook_steps.json").write_text(
            json.dumps({"steps": []}), encoding="utf-8"
        )
        (tmp / "tools" / "exploit-queue.py").write_text("", encoding="utf-8")
        (tmp / "tools" / "audit-completeness-check.py").write_text(
            "_SIGNAL_ORDER = ()\n", encoding="utf-8"
        )

    def test_orphan_detected_and_enforce_rc1(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._build_fixture(tmp)

            report, rc = MOD.run(tmp, enforce=False)
            verdicts = _verdicts(report)
            self.assertEqual(verdicts["cap-wired-foo"], "WIRED", report["rows"])
            self.assertEqual(verdicts["cap-orphan-bar"], "ORPHAN", report["rows"])
            self.assertEqual(report["counts"]["orphan"], 1)
            self.assertEqual(report["counts"]["wired"], 1)

            # Advisory-first: default WARN never hard-blocks.
            self.assertEqual(rc, 0)
            self.assertEqual(report["verdict"], "WARN-wiring-integrity")

            # Enforce: fail-closed rc 1 because >=1 orphan.
            report_e, rc_e = MOD.run(tmp, enforce=True)
            self.assertEqual(rc_e, 1)
            self.assertEqual(report_e["verdict"], "fail-wiring-integrity")
            self.assertEqual([o["id"] for o in report_e["orphans"]], ["cap-orphan-bar"])

    def test_orphan_reason_is_not_invoked(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._build_fixture(tmp)
            report, _ = MOD.run(tmp, enforce=False)
            bar = next(e for e in report["rows"] if e["id"] == "cap-orphan-bar")
            self.assertFalse(bar["invoked"])
            self.assertTrue(bar["feeds_to"])  # closer consumes it
            self.assertTrue(any("not-invoked" in r for r in bar["reasons"]))


class InvokedFractionLiveTest(unittest.TestCase):
    """The invoked=True FIRING fraction (distinct from wired_by_closure) is
    computed + reported on the REAL inventory. This is the north-star firing
    metric the roadmap drives toward 100% (today ~14%)."""

    def test_invoked_fraction_reported_on_live_repo(self):
        report, _ = MOD.run(REPO, enforce=False)
        inv = report.get("invoked")
        self.assertIsNotNone(inv, "report must carry an 'invoked' block")
        for key in ("invoked_true", "resolvable", "invoked_fraction", "min_invoked_ratio"):
            self.assertIn(key, inv, f"invoked block missing {key}")
        # invoked_true is a strict subset of resolvable, which is a subset of total.
        self.assertGreater(inv["invoked_true"], 0, "some cap must actually fire")
        self.assertLessEqual(inv["invoked_true"], inv["resolvable"])
        self.assertLessEqual(inv["resolvable"], report["counts"]["total"])
        # The fraction is the ratio over the RESOLVABLE denominator, in [0,1].
        self.assertAlmostEqual(
            inv["invoked_fraction"],
            round(inv["invoked_true"] / inv["resolvable"], 4),
            places=4,
        )
        self.assertGreaterEqual(inv["invoked_fraction"], 0.0)
        self.assertLessEqual(inv["invoked_fraction"], 1.0)
        # invoked=True (firing) is DISTINCT from wired_by_closure (transitive-only):
        # the closure-rescued bucket is real and NOT counted as firing.
        self.assertGreater(
            report["wired_by_closure"], inv["invoked_true"],
            "closure-only rescues must be distinct from (and today exceed) firing caps",
        )


class StrictFiringGateTest(unittest.TestCase):
    """The STRICT gate-signal path (AUDITOOOR_WIRING_STRICT=1 / --strict): FAILS a
    synthetic closure-only (vacuous) capability and PASSES an invoked one whose
    emit artifact materialised on a real workspace."""

    @staticmethod
    def _write_common_tools(tmp: Path) -> None:
        (tmp / "reference").mkdir(parents=True, exist_ok=True)
        (tmp / "tools").mkdir(parents=True, exist_ok=True)
        # audit-deep INVOKES foo.py (so foo is invoked=True) but never bar.py.
        (tmp / "tools" / "audit-deep.sh").write_text(
            '#!/usr/bin/env bash\npython3 "$HERE/foo.py" --workspace "$WORKSPACE"\n',
            encoding="utf-8",
        )
        # closer CONSUMES foo's emit artifact (canonical FEEDS-TO).
        (tmp / "tools" / "auto-coverage-closer.py").write_text(
            'REL = [".auditooor/foo_hyp.jsonl"]\n', encoding="utf-8"
        )
        (tmp / "tools" / "readme_runbook_steps.json").write_text(
            json.dumps({"steps": []}), encoding="utf-8"
        )
        (tmp / "tools" / "exploit-queue.py").write_text("", encoding="utf-8")
        (tmp / "tools" / "audit-completeness-check.py").write_text(
            "_SIGNAL_ORDER = ()\n", encoding="utf-8"
        )

    @staticmethod
    def _foo_cap() -> dict:
        # A genuinely-wired, invoked cap that emits foo_hyp.jsonl.
        return {
            "id": "cap-invoked-foo",
            "name": "foo-lane",
            "category": "python-tool",
            "status": "LANDED",
            "inputs": [".auditooor/inscope_units.jsonl"],
            "outputs": [".auditooor/foo_hyp.jsonl"],
            "file_paths": ["tools/foo.py", "tools/tests/test_foo.py"],
            "consumers": [],
        }

    def _build_invoked_only(self, tmp: Path) -> None:
        self._write_common_tools(tmp)
        (tmp / "reference" / "capability_inventory.jsonl").write_text(
            json.dumps(self._foo_cap()) + "\n", encoding="utf-8"
        )

    def _build_with_closure_only_cap(self, tmp: Path) -> None:
        self._write_common_tools(tmp)
        # bar declares NO emit artifact -> FEEDS-TO undeterminable -> verdict
        # 'unknown', which the closure stub below RESCUES to WIRED (closure-only).
        bar = {
            "id": "cap-closure-only-bar",
            "name": "bar-lane",
            "category": "python-tool",
            "status": "LANDED",
            "inputs": ["rust source"],
            "file_paths": ["tools/bar.py"],  # exists as a token, never invoked
            "consumers": [],
        }
        (tmp / "reference" / "capability_inventory.jsonl").write_text(
            json.dumps(self._foo_cap()) + "\n" + json.dumps(bar) + "\n",
            encoding="utf-8",
        )
        # A faithful stub of capability-orphan-closure-check.py: it classifies
        # EVERY cap WIRED (reachable). Only 'unknown' rows are rescued, so bar
        # becomes feeds_to_method='closure-wired' (vacuous by construction).
        (tmp / "tools" / "capability-orphan-closure-check.py").write_text(
            "import json\n"
            "def load_inventory(p):\n"
            "    rows = []\n"
            "    for line in open(p, encoding='utf-8'):\n"
            "        line = line.strip()\n"
            "        if line:\n"
            "            rows.append(json.loads(line))\n"
            "    return rows\n"
            "def load_declarations(p):\n"
            "    return ({}, {})\n"
            "def classify(caps, declarations, policy):\n"
            "    return [{'cap_id': c.get('id'), 'name': c.get('name'), "
            "'disposition': 'WIRED'} for c in caps]\n",
            encoding="utf-8",
        )

    def _make_workspace(self, tmp: Path, materialise_foo: bool = True) -> Path:
        ws = tmp / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        if materialise_foo:
            (ws / ".auditooor" / "foo_hyp.jsonl").write_text(
                '{"hit": 1}\n', encoding="utf-8"
            )
        return ws

    def test_strict_passes_invoked_cap(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._build_invoked_only(tmp)
            ws = self._make_workspace(tmp)
            report, rc = MOD.run(
                tmp, enforce=False, strict=True, workspace=ws, min_invoked_ratio=0.0
            )
            self.assertEqual(rc, 0, report)
            self.assertEqual(report["verdict"], "pass-wiring-integrity")
            # The invoked cap fired AND its artifact materialised -> not vacuous.
            self.assertEqual(report["non_vacuity"]["vacuous_wired"], 0)
            self.assertEqual(report["non_vacuity"]["vacuity_failed"], False)
            self.assertEqual(report["invoked"]["invoked_true"], 1)
            self.assertEqual(report["invoked"]["invoked_fraction"], 1.0)
            self.assertEqual(report["non_vacuity"]["ws_emit_present"], 1)

    def test_strict_fails_closure_only_vacuous_cap(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._build_with_closure_only_cap(tmp)
            ws = self._make_workspace(tmp)
            # min_invoked_ratio=0.0 ISOLATES the vacuity path from the floor path.
            report, rc = MOD.run(
                tmp, enforce=False, strict=True, workspace=ws, min_invoked_ratio=0.0
            )
            self.assertEqual(rc, 1, report)
            self.assertEqual(report["verdict"], "fail-wiring-integrity")
            self.assertTrue(report["non_vacuity"]["vacuity_failed"])
            self.assertGreaterEqual(report["non_vacuity"]["vacuous_wired"], 1)
            self.assertIn(
                "cap-closure-only-bar",
                {e["id"] for e in report["vacuous_wired"]},
                "the closure-only cap must be flagged vacuous",
            )
            # The invoked cap in the SAME run stays non-vacuous (fires + emits).
            self.assertFalse(report["invoked"]["invoked_fraction_low"])

    def test_strict_is_advisory_by_default_no_regression(self):
        # Without --strict/--enforce, the SAME closure-only fixture must NOT hard-
        # block (advisory-first): rc 0, and vacuity is annotated but not failing.
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._build_with_closure_only_cap(tmp)
            report, rc = MOD.run(tmp, enforce=False)
            self.assertEqual(rc, 0)
            self.assertIn(report["verdict"], ("pass-wiring-integrity", "WARN-wiring-integrity"))
            self.assertFalse(report["non_vacuity"]["vacuity_failed"])

    def test_min_invoked_ratio_floor(self):
        # The invoked-fraction FLOOR: with a floor above the actual fraction the
        # STRICT gate flags invoked_fraction_low; below it, it does not.
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._build_with_closure_only_cap(tmp)  # foo invoked, bar not -> 1/2
            ws = self._make_workspace(tmp)
            hi, rc_hi = MOD.run(
                tmp, enforce=False, strict=True, workspace=ws, min_invoked_ratio=0.9
            )
            self.assertTrue(hi["invoked"]["invoked_fraction_low"])
            self.assertEqual(rc_hi, 1)
            lo, _ = MOD.run(
                tmp, enforce=False, strict=True, workspace=ws, min_invoked_ratio=0.0
            )
            self.assertFalse(lo["invoked"]["invoked_fraction_low"])
            self.assertAlmostEqual(lo["invoked"]["invoked_fraction"], 0.5, places=4)


class VacuityUnitTest(unittest.TestCase):
    """Unit-level pins on the non-vacuity primitives."""

    def test_scan_skips_empty_artifacts(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "full.jsonl").write_text("x\n", encoding="utf-8")
            (ws / ".auditooor" / "empty.jsonl").write_text("", encoding="utf-8")
            got = MOD.scan_workspace_artifacts(ws)
            self.assertIn("full.jsonl", got)
            self.assertNotIn("empty.jsonl", got, "0-byte artifact is not a real emit")

    def test_scan_missing_auditooor_dir_is_empty(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(MOD.scan_workspace_artifacts(Path(d)), set())

    def test_row_vacuity_closure_only_is_vacuous(self):
        e = {"verdict": "WIRED", "feeds_to_method": "closure-wired",
             "emit_artifacts": []}
        MOD._row_vacuity(e, {"whatever.jsonl"})
        self.assertTrue(e["vacuous"])

    def test_row_vacuity_emit_present_not_vacuous(self):
        e = {"verdict": "WIRED", "feeds_to_method": "canonical",
             "emit_artifacts": ["foo.jsonl"]}
        MOD._row_vacuity(e, {"foo.jsonl"})
        self.assertFalse(e["vacuous"])
        self.assertTrue(e["emit_present_on_ws"])

    def test_row_vacuity_emit_absent_is_vacuous(self):
        e = {"verdict": "WIRED", "feeds_to_method": "canonical",
             "emit_artifacts": ["foo.jsonl"]}
        MOD._row_vacuity(e, {"other.jsonl"})
        self.assertTrue(e["vacuous"])
        self.assertFalse(e["emit_present_on_ws"])

    def test_row_vacuity_non_wired_untouched(self):
        e = {"verdict": "ORPHAN", "feeds_to_method": "none", "emit_artifacts": []}
        MOD._row_vacuity(e, {"foo.jsonl"})
        self.assertFalse(e["vacuous"])


class CapabilitySetHashTest(unittest.TestCase):
    def test_hash_stable_and_changes_on_status_bump(self):
        rows = [
            {"id": "b", "name": "beta", "status": "LANDED"},
            {"id": "a", "name": "alpha", "status": "LANDED"},
        ]
        h1 = MOD.compute_capability_set_hash(rows)
        # Order-independent: sorting by id makes the hash stable.
        h2 = MOD.compute_capability_set_hash(list(reversed(rows)))
        self.assertEqual(h1, h2)

        # A status bump (version change) => new hash => a done marker earned under
        # the old hash is stale.
        bumped = [dict(r) for r in rows]
        bumped[0]["status"] = "PARTIAL"
        h3 = MOD.compute_capability_set_hash(bumped)
        self.assertNotEqual(h1, h3)

        # Adding a capability => new hash.
        added = rows + [{"id": "c", "name": "gamma", "status": "LANDED"}]
        self.assertNotEqual(h1, MOD.compute_capability_set_hash(added))


if __name__ == "__main__":
    unittest.main()
