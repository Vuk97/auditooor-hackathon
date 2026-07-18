"""Non-vacuous regression test for the GENERAL enforcement-point COVERAGE PLANE
(wsitb-enforcement-plane.py increment-2 consolidation mode).

The plane CONSOLIDATES the already-emitted enforcement-point signals (A2 trust
seams + A3 authority-blast-radius roles + SCG coupled-state edges + ELC layers)
into ONE deduped plane of concrete points, attaches the 8 trusted-enforcer
questions per point, and marks each point analyzed / un-analyzed via a coverage
marker. Advisory-first: WARN (rc 0) by default; fail-closed (rc 1) ONLY under a
named strict env when a SEVERITY-ELIGIBLE point is un-analyzed.

NON-VACUITY (mutating the JOIN/gate must break a test):
  - test_consolidates_all_four_signals: one row per source -> exactly the 4 kinds
    of point; drop a consolidator arm and a kind vanishes.
  - test_advisory_by_default_strict_fails_closed: with an open severity-eligible
    point, the DEFAULT gate is rc 0 but STRICT flips to rc 1. Remove the strict
    branch (always advisory) and the strict case fails; remove the severity filter
    and the default WARN count drops to 0.
  - test_ingest_verdict_flips_analyzed_and_passes_strict: ingesting a terminal q8
    verdict for every open point flips analyzed -> strict now PASSES (rc 0). Without
    the ingest it is rc 1: the flip proves the coverage marker is load-bearing.
  - test_sidecar_coverage_marks_analyzed: a hunt sidecar at a point's (file,line)
    marks it analyzed WITHOUT an agent verdict (the second marker path).
  - test_dedup_on_consolidation_key: two source rows on the same (file,line,kind)
    collapse to ONE point carrying both source_signals.
  - test_absent_substrate_is_fail_open: no source artifacts -> 0 points,
    substrate_starved, and strict still rc 0 (no un-analyzed point to block on).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_PLANE = _load("t_epc_plane", "wsitb-enforcement-plane.py")

_STRICT_ENVS = ("AUDITOOOR_ENFORCEMENT_POINT_STRICT", "AUDITOOOR_L37_STRICT")


def _write_jsonl(p: Path, rows):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""),
                 encoding="utf-8")


def _seed_a2(ws, sink_file="src/A.sol", sink_line=10, fn="consume", var="navPrice"):
    _write_jsonl(ws / ".auditooor" / "cross_module_trust_seams.jsonl", [{
        "seam_id": "cmts-0001", "state_var": var,
        "guarded_producer": {"fn": "setNav", "file": "src/Oracle.sol", "line": 5},
        "unguarded_consumer_sink": {"fn": fn, "file": sink_file, "line": sink_line},
        "trust_edge": "setNav guards navPrice; consume never re-checks it",
        "confidence": "semantic-ssa", "advisory": True,
    }])


def _seed_a3(ws):
    _write_jsonl(ws / ".auditooor" / "authority_blast_radius_hypotheses.jsonl", [{
        "flag_kind": "blast-radius", "role": "MINTER_ROLE",
        "distinct_impact_classes": ["mint", "burn"],
        "sink_fns": [{"contract": "Token", "fn": "mint",
                      "file_line": "src/Token.sol:20",
                      "impacts": ["unauthorized-mint"], "guard_confirmed": True}],
        "verdict": "needs-fuzz", "attack_class": "privilege",
    }])


def _seed_scg(ws, vfile="src/V.sol", vline=30, fn="payout"):
    _write_jsonl(ws / ".auditooor" / "state_coupling_edges.jsonl", [{
        "schema": "state_coupling_edge.v1", "edge_id": "sce-0001", "language": "sol",
        "kind": "conserved-with", "cell_a": "assets", "cell_b": "totalShares",
        "writers_a": [fn], "writers_b": [fn],
        "obligation": "sum(shares) == totalShares",
        "violators": [{"fn": fn, "file": vfile, "line": vline,
                       "mutates": ["assets"], "omits": ["totalShares"]}],
        "impact_class": "insolvency", "confidence": "semantic-ssa", "evidence": {},
    }])


def _seed_elc(ws, flagged_layer="oracle", hunted_layer="access-control"):
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "enforcement_layer_census.json").write_text(json.dumps({
        "schema": "auditooor.enforcement_layer_census.v1",
        "layers": {
            flagged_layer: {"present": True, "source_hits": 5, "sidecar_count": 0,
                            "flagged": True},
            hunted_layer: {"present": True, "source_hits": 8, "sidecar_count": 2,
                           "flagged": False},
        },
        "flagged_layers": [flagged_layer], "advisory": True,
    }), encoding="utf-8")


class EnforcementPointCoveragePlaneTest(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in _STRICT_ENVS}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_consolidates_all_four_signals(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_a2(ws)
            _seed_a3(ws)
            _seed_scg(ws)
            _seed_elc(ws)
            nodes, acct = _PLANE.consolidate_plane(ws)
            kinds = {n["kind"] for n in nodes}
            self.assertEqual(
                kinds, {"trust-seam", "authority-guard", "coupled-state-edge",
                        "enforcement-layer"},
                "each consolidated source must contribute its kind of point")
            # every point carries the 8-question checklist keyed on q1..q8.
            for n in nodes:
                self.assertEqual(len(n["questions"]), 8)
                self.assertIn("q8_invariant_soundness", n["questions"])
                self.assertIn("delegated-property",
                              [q["axis"] for q in n["questions"].values()])
            self.assertTrue(all(acct["sources_present"].values()))
            # the hunted access-control layer is coverage-marked analyzed already.
            ac = next(n for n in nodes if n["kind"] == "enforcement-layer"
                      and n["enforcement_layer"] == "access-control")
            self.assertTrue(ac["analyzed"])
            self.assertEqual(ac["analyzed_by"], "layer-sidecar")
            # the flagged oracle layer is present-but-unhunted -> open.
            orc = next(n for n in nodes if n["enforcement_layer"] == "oracle")
            self.assertFalse(orc["analyzed"])
            self.assertGreaterEqual(acct["severity_eligible_unanalyzed"], 3)

    def test_advisory_by_default_strict_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_a2(ws)
            _seed_scg(ws)
            # DEFAULT: advisory WARN, rc 0, but there ARE open severity points.
            rc = _PLANE.check_consolidated(ws)
            self.assertEqual(rc, 0, "default gate is advisory (rc 0)")
            _, acct = _PLANE.consolidate_plane(ws)
            self.assertGreater(acct["severity_eligible_unanalyzed"], 0,
                               "the WARN must be non-vacuous (real open points)")
            # STRICT: same open point now fails closed.
            os.environ["AUDITOOOR_ENFORCEMENT_POINT_STRICT"] = "1"
            rc_strict = _PLANE.check_consolidated(ws)
            self.assertEqual(rc_strict, 1,
                             "strict must fail closed on an un-analyzed severity point")
            # the L37 umbrella env is an equivalent trigger.
            os.environ.pop("AUDITOOOR_ENFORCEMENT_POINT_STRICT", None)
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            self.assertEqual(_PLANE.check_consolidated(ws), 1)

    def test_ingest_verdict_flips_analyzed_and_passes_strict(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_a2(ws)
            _seed_a3(ws)
            _seed_scg(ws)
            _seed_elc(ws)
            nodes, _ = _PLANE.consolidate_plane(ws)
            open_ids = [n["point_id"] for n in nodes
                        if n["severity_eligible"] and not n["analyzed"]]
            self.assertTrue(open_ids)
            os.environ["AUDITOOOR_ENFORCEMENT_POINT_STRICT"] = "1"
            self.assertEqual(_PLANE.check_consolidated(ws), 1,
                             "un-analyzed -> strict incomplete")
            # ingest a terminal q8 verdict for every open point.
            vpath = ws / "verdicts.jsonl"
            _write_jsonl(vpath, [{"point_id": pid, "q8_verdict": "safe"}
                                 for pid in open_ids])
            _PLANE.ingest_verdicts(ws, vpath)
            nodes2, acct2 = _PLANE.consolidate_plane(ws)
            self.assertEqual(acct2["severity_eligible_unanalyzed"], 0,
                             "every severity point now analyzed")
            self.assertTrue(all(n["q8_verdict"] == "safe"
                                for n in nodes2 if n["point_id"] in open_ids))
            self.assertEqual(_PLANE.check_consolidated(ws), 0,
                             "all-analyzed -> strict PASSES")

    def test_sidecar_coverage_marks_analyzed(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_scg(ws, vfile="src/V.sol", vline=30, fn="payout")
            # a hunt sidecar exactly at the coupled-state violator's (file,line).
            sc_dir = ws / ".auditooor" / "hunt_findings_sidecars"
            sc_dir.mkdir(parents=True, exist_ok=True)
            (sc_dir / "s1.json").write_text(json.dumps({
                "file": "src/V.sol", "line": 30, "function": "payout",
                "bug_class": "conservation"}), encoding="utf-8")
            nodes, _ = _PLANE.consolidate_plane(ws)
            cse = next(n for n in nodes if n["kind"] == "coupled-state-edge")
            self.assertTrue(cse["analyzed"],
                            "a sidecar at the point's file:line must mark it analyzed")
            self.assertEqual(cse["analyzed_by"], "hunt-sidecar")
            self.assertEqual(cse["q8_verdict"], "covered")

    def test_dedup_on_consolidation_key(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            # two A2 rows on the SAME sink (file,line) -> one deduped point.
            _write_jsonl(ws / ".auditooor" / "cross_module_trust_seams.jsonl", [
                {"seam_id": "cmts-0001", "state_var": "navPrice",
                 "unguarded_consumer_sink": {"fn": "consume", "file": "src/A.sol",
                                             "line": 10}},
                {"seam_id": "cmts-0002", "state_var": "navPrice2",
                 "unguarded_consumer_sink": {"fn": "consume", "file": "src/A.sol",
                                             "line": 10}},
            ])
            nodes, _ = _PLANE.consolidate_plane(ws)
            seams = [n for n in nodes if n["kind"] == "trust-seam"]
            self.assertEqual(len(seams), 1, "same (file,line,kind) must dedup to one")
            self.assertEqual(len(seams[0]["source_signals"]), 2,
                             "both source rows must be recorded as provenance")

    def test_function_anchor_and_nested_result_credit(self):
        """A per-fn hunt sidecar that nests its source-review anchor under
        ``function_anchor`` (frequently an ABSOLUTE path) or inside a stringified
        ``result`` must still credit its point - the serving-join the canonical
        readers (hunt-coverage-gate / function-coverage-completeness) close. Before
        the fix these scored un-analyzed: the nuva BridgeBurnShares false-red, where
        0 of 1264 sidecars credited because _from_rec read neither field."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            # two coupled-state points: P1 payout@src/V.sol, P2 settle@src/W.sol.
            _write_jsonl(ws / ".auditooor" / "state_coupling_edges.jsonl", [
                {"schema": "state_coupling_edge.v1", "edge_id": "sce-1",
                 "language": "sol", "kind": "conserved-with", "cell_a": "a",
                 "cell_b": "b", "writers_a": ["payout"], "writers_b": ["payout"],
                 "obligation": "a==b",
                 "violators": [{"fn": "payout", "file": "src/V.sol", "line": 30,
                                "mutates": ["a"], "omits": ["b"]}],
                 "impact_class": "insolvency", "confidence": "semantic-ssa",
                 "evidence": {}},
                {"schema": "state_coupling_edge.v1", "edge_id": "sce-2",
                 "language": "sol", "kind": "conserved-with", "cell_a": "a",
                 "cell_b": "b", "writers_a": ["settle"], "writers_b": ["settle"],
                 "obligation": "a==b",
                 "violators": [{"fn": "settle", "file": "src/W.sol", "line": 40,
                                "mutates": ["a"], "omits": ["b"]}],
                 "impact_class": "insolvency", "confidence": "semantic-ssa",
                 "evidence": {}},
            ])
            sc_dir = ws / ".auditooor" / "hunt_findings_sidecars"
            sc_dir.mkdir(parents=True, exist_ok=True)
            # P1: anchor ONLY under function_anchor, ABSOLUTE path (agents cite the
            # real source path), no top-level file/fn -> credits via basename+fn.
            (sc_dir / "p1.json").write_text(json.dumps({
                "task_id": "t1",
                "function_anchor": {"file": str(ws / "src" / "V.sol"),
                                    "function": "payout"},
                "result": "{\"verdict\": \"FP-DEFENDED\"}"}), encoding="utf-8")
            # P2: anchor nested inside a STRINGIFIED result (no top-level file/fn,
            # no top-level function_anchor).
            (sc_dir / "p2.json").write_text(json.dumps({
                "task_id": "t2",
                "result": json.dumps({"file": "src/W.sol", "function": "settle",
                                      "verdict": "CONFIRMED"})}), encoding="utf-8")
            nodes, _ = _PLANE.consolidate_plane(ws)
            p1 = next(n for n in nodes if n.get("fn") == "payout")
            p2 = next(n for n in nodes if n.get("fn") == "settle")
            self.assertTrue(
                p1["analyzed"],
                "an absolute-path function_anchor must credit its point (basename+fn)")
            self.assertTrue(
                p2["analyzed"],
                "an anchor nested in a stringified result must credit its point")
            self.assertEqual(p1["q8_verdict"], "covered")
            self.assertEqual(p2["q8_verdict"], "covered")

    def test_absent_substrate_is_fail_open(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            nodes, acct = _PLANE.consolidate_plane(ws)
            self.assertEqual(len(nodes), 0)
            self.assertTrue(acct["substrate_starved"])
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            self.assertEqual(_PLANE.check_consolidated(ws), 0,
                             "no substrate -> no open point -> strict still rc 0")

    def test_explicit_strict_fails_starved_substrate(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            self.assertEqual(_PLANE.check_consolidated(ws, strict=True), 1)

    def test_explicit_strict_fails_syntactic_only_input(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_a3(ws)
            self.assertEqual(_PLANE.check_consolidated(ws, strict=True), 1)

    def test_explicit_strict_passes_cited_semantic_terminal_closure(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_scg(ws)
            nodes, _ = _PLANE.consolidate_plane(ws)
            self.assertTrue(nodes)
            _write_jsonl(ws / ".auditooor" / "enforcement_point_verdicts.jsonl", [{
                "point_id": nodes[0]["point_id"], "q8_verdict": "safe",
                "source_refs": ["src/Vault.sol:30"],
                "rationale": "semantic source review confirms the invariant",
            }])
            self.assertEqual(_PLANE.main([
                "--workspace", str(ws), "--check", "--strict"]), 0)

    def test_explicit_strict_accepts_typed_not_applicable_closure(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".auditooor" / "enforcement_point_terminal.json").write_text(
                json.dumps({"status": "not-applicable", "source_refs": ["scope.md"],
                            "rationale": "no enforcement-point class is in scope"}))
            self.assertEqual(_PLANE.main([
                "--workspace", str(ws), "--check", "--strict"]), 0)

    def test_explicit_strict_rejects_uncited_terminal_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _seed_scg(ws)
            nodes, _ = _PLANE.consolidate_plane(ws)
            _write_jsonl(ws / ".auditooor" / "enforcement_point_verdicts.jsonl", [{
                "point_id": nodes[0]["point_id"], "q8_verdict": "safe",
            }])
            self.assertEqual(_PLANE.main([
                "--workspace", str(ws), "--check", "--strict"]), 1)


if __name__ == "__main__":
    unittest.main()
