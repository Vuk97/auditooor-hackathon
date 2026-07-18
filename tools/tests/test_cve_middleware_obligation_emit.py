#!/usr/bin/env python3
"""Unit tests for tools/cve-middleware-obligation-emit.py (WAVE-2 ITEM 9 adapter).

Coverage matrix
---------------
OPEN_FIX_MISSING     - reachability=open, ancestry=fix-missing -> emitted (1 obligation,
                       advisory=False, proof_status="open", entrypoint+advisory_id anchor).
OPEN_UNKNOWN_ANCESTRY- reachability=open, ancestry=unknown -> emitted (fix not proven present).
OPEN_FIX_PRESENT     - reachability=open BUT ancestry=fix-present -> NOT emitted (patched).
BLOCKED              - reachability=blocked-by-middleware -> NOT emitted (no seam).
UNKNOWN_REACH        - reachability=unknown -> NOT emitted (no class mapping).
EMPTY_REPORT         - report with 0 open advisories -> EMPTY ledger written (ran=True, 0).
NA_NO_INPUT          - neither --report nor --middleware-file -> NOTHING written (ran=False).
NA_NO_MIDDLEWARE     - --middleware-file that does not exist -> NOTHING written (ran=False).

Invariants
----------
- Emitted rows carry advisory=False + proof_status="open".
- Emitted rows carry advisory_id and a stable obligation_id (entrypoint anchor).
- No em-dash (U+2014) or en-dash (U+2013) in any string field.
- logic-obligation-resolution-check.py scores an EMITTED open row as OPEN and an
  absent ledger as ran=False (mechanical, via the registered tuple).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_EMIT_PATH = Path(__file__).resolve().parent.parent / "cve-middleware-obligation-emit.py"
_CHECK_PATH = Path(__file__).resolve().parent.parent / "logic-obligation-resolution-check.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


emit_mod = _load(_EMIT_PATH, "cve_middleware_obligation_emit")
check_mod = _load(_CHECK_PATH, "logic_obligation_resolution_check")


def _report(advisories):
    return {
        "schema": "auditooor.cve_middleware_reachability.v1",
        "count": len(advisories),
        "advisories": advisories,
        "summary": {},
    }


def _adv(advisory_id, reach, ancestry, entrypoint="ibc-hooks-receive"):
    return {
        "advisory_id": advisory_id,
        "ancestry_status": ancestry,
        "ancestry_evidence": "git merge-base --is-ancestor ... => no (rc=1)",
        "reachability_status": reach,
        "attack_entrypoint_class": entrypoint,
        "candidate_severity_if_unblocked": "HIGH",
        "upstream_repo": "github.com/cosmos/ibc-apps",
        "fix_commit_sha": "abc123def456",
        "matched_middleware": ["IBCHooksKeeper"],
        "sentinel_fires_if": "already open",
    }


def _no_dash(obj):
    """Recursively assert no em/en-dash in any string field."""
    if isinstance(obj, str):
        assert "—" not in obj and "–" not in obj, f"dash in {obj!r}"
    elif isinstance(obj, dict):
        for v in obj.values():
            _no_dash(v)
    elif isinstance(obj, list):
        for v in obj:
            _no_dash(v)


class TestReportToObligations(unittest.TestCase):
    def test_open_fix_missing_emitted(self):
        rows = emit_mod.report_to_obligations(
            _report([_adv("GHSA-open-1", "open", "fix-missing")]))
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertIs(r["advisory"], False)
        self.assertEqual(r["proof_status"], "open")
        self.assertEqual(r["advisory_id"], "GHSA-open-1")
        self.assertEqual(r["entrypoint"], "ibc-hooks-receive")
        self.assertTrue(r["obligation_id"].startswith("cve-mw::GHSA-open-1::"))
        self.assertEqual(r["attack_class"], "known-cve-unfixed-reachable")

    def test_open_unknown_ancestry_emitted(self):
        rows = emit_mod.report_to_obligations(
            _report([_adv("GHSA-open-2", "open", "unknown")]))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ancestry_status"], "unknown")

    def test_open_but_fix_present_not_emitted(self):
        rows = emit_mod.report_to_obligations(
            _report([_adv("GHSA-patched", "open", "fix-present")]))
        self.assertEqual(rows, [])

    def test_blocked_not_emitted(self):
        rows = emit_mod.report_to_obligations(
            _report([_adv("GHSA-blocked", "blocked-by-middleware", "fix-missing")]))
        self.assertEqual(rows, [])

    def test_unknown_reach_not_emitted(self):
        rows = emit_mod.report_to_obligations(
            _report([_adv("GHSA-unk", "unknown", "fix-missing")]))
        self.assertEqual(rows, [])

    def test_mixed_report_only_open_survivors(self):
        rows = emit_mod.report_to_obligations(_report([
            _adv("A", "open", "fix-missing"),
            _adv("B", "blocked-by-middleware", "fix-missing"),
            _adv("C", "open", "fix-present"),
            _adv("D", "open", "unknown", entrypoint="cosmwasm-execute"),
        ]))
        ids = sorted(r["advisory_id"] for r in rows)
        self.assertEqual(ids, ["A", "D"])

    def test_no_dashes_in_output(self):
        rows = emit_mod.report_to_obligations(
            _report([_adv("GHSA-open-1", "open", "fix-missing")]))
        _no_dash(rows)


class TestEmitAndResolutionJoin(unittest.TestCase):
    def _fresh_ws(self, tmp):
        ws = Path(tmp)
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        # give the ws a dataflow substrate so the resolution gate does not
        # short-circuit on "no substrate" (not required for ran/total scoring
        # of this specific ledger, but keeps the harness realistic).
        (ws / ".auditooor" / "dataflow_paths.jsonl").write_text("", encoding="utf-8")
        return ws

    def test_emit_writes_ledger_and_gate_scores_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._fresh_ws(tmp)
            n = emit_mod.emit(
                ws, _report([_adv("GHSA-open-1", "open", "fix-missing")]), None)
            self.assertEqual(n, 1)
            ledger = ws / ".auditooor" / emit_mod.LEDGER_NAME
            self.assertTrue(ledger.is_file())
            row = json.loads(ledger.read_text().splitlines()[0])
            self.assertIs(row["advisory"], False)
            # resolution gate: the ledger tuple is registered -> row scored OPEN.
            res = check_mod.check(ws)
            per = {l["ledger"]: l for l in res["per_ledger"]}
            self.assertIn(emit_mod.LEDGER_NAME, per)
            entry = per[emit_mod.LEDGER_NAME]
            self.assertTrue(entry["ran"])
            self.assertEqual(entry["total"], 1)
            self.assertEqual(entry["open"], 1)
            self.assertEqual(entry["resolved"], 0)

    def test_empty_report_writes_empty_ledger_ran_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._fresh_ws(tmp)
            n = emit_mod.emit(ws, _report([]), None)
            self.assertEqual(n, 0)
            ledger = ws / ".auditooor" / emit_mod.LEDGER_NAME
            self.assertTrue(ledger.is_file())
            res = check_mod.check(ws)
            per = {l["ledger"]: l for l in res["per_ledger"]}
            entry = per[emit_mod.LEDGER_NAME]
            self.assertTrue(entry["ran"])
            self.assertEqual(entry["total"], 0)

    def test_terminal_status_resolves_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._fresh_ws(tmp)
            emit_mod.emit(
                ws, _report([_adv("GHSA-open-1", "open", "fix-missing")]), None)
            # flip the row to a terminal verdict, mirroring a hunt disposition.
            ledger = ws / ".auditooor" / emit_mod.LEDGER_NAME
            row = json.loads(ledger.read_text().splitlines()[0])
            row["proof_status"] = "refuted"
            ledger.write_text(json.dumps(row) + "\n", encoding="utf-8")
            res = check_mod.check(ws)
            per = {l["ledger"]: l for l in res["per_ledger"]}
            entry = per[emit_mod.LEDGER_NAME]
            self.assertEqual(entry["open"], 0)
            self.assertEqual(entry["resolved"], 1)


class TestNaDiscipline(unittest.TestCase):
    def test_no_input_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            rc = emit_mod.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            self.assertFalse((ws / ".auditooor" / emit_mod.LEDGER_NAME).is_file())
            # gate scores the (absent) ledger ran=False, never silently green.
            res = check_mod.check(ws)
            per = {l["ledger"]: l for l in res["per_ledger"]}
            self.assertFalse(per[emit_mod.LEDGER_NAME]["ran"])

    def test_missing_middleware_file_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            adv = ws / "adv.json"
            adv.write_text(json.dumps([_adv("X", "open", "fix-missing")]),
                           encoding="utf-8")
            rc = emit_mod.main([
                "--workspace", str(ws),
                "--middleware-file", str(ws / "does-not-exist-app.go"),
                "--advisory-list", str(adv),
            ])
            self.assertEqual(rc, 0)
            self.assertFalse((ws / ".auditooor" / emit_mod.LEDGER_NAME).is_file())

    def test_middleware_missing_advisory_list_is_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            rc = emit_mod.main([
                "--workspace", str(ws),
                "--middleware-file", str(ws / "app.go"),
            ])
            self.assertEqual(rc, 2)


class TestRegisteredTuple(unittest.TestCase):
    def test_ledger_registered_in_reasoner_ledgers(self):
        names = {t[0] for t in check_mod._REASONER_LEDGERS}
        self.assertIn(emit_mod.LEDGER_NAME, names)
        # language scope is go (cosmos fork lane)
        row = next(t for t in check_mod._REASONER_LEDGERS
                   if t[0] == emit_mod.LEDGER_NAME)
        self.assertEqual(row[2], "go")
        self.assertEqual(row[1], "cve-middleware-reachability.py")


if __name__ == "__main__":
    unittest.main()
