#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-HQ-RESOLVE-CORPUS-FUEL registered via agent-pathspec-register.py -->
"""Guard: hacker-question-obligation-resolve.resolve() must EXCLUDE corpus-fuel
class-probes and vendored-dependency rows from its per-function open count, so its
reported "still open" aligns with the audit-complete hacker-Q gate (which excludes
them). Otherwise a hunter is misdirected to hundreds of phantom obligations that can
never be answered by a per-question source verdict sidecar (NUVA 2026-07-12: the
resolver reported 549 open while the gate correctly counted 46).

Load-bearing negatives:
 - a corpus-fuel row (function_name=mined_findings_hunter_bridge / question_source=
   mined-finding / file with <workspace> or the bridge artifact) is NOT counted as
   per-fn open, and is surfaced under excluded_corpus_fuel_open.
 - a vendored-dep row (/go/pkg/mod/...) is NOT counted as per-fn open.
 - a GENUINE in-scope per-fn obligation IS still counted open (never false-excluded).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "hqor", str(_TOOLS / "hacker-question-obligation-resolve.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["hqor"] = m
spec.loader.exec_module(m)


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / "src").mkdir()
    return ws


def _write_obls(ws: Path, rows):
    p = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _row(**kw):
    base = {
        "schema": "auditooor.hacker_question_obligation.v1",
        "state": "open",
        "question": "q",
        "attack_class": "x",
    }
    base.update(kw)
    return base


class TestCorpusFuelPartition(unittest.TestCase):
    def test_corpus_fuel_and_vendored_excluded_real_kept(self):
        ws = _ws()
        # 1 genuine in-scope per-fn obligation (real source file + real fn)
        (ws / "src" / "msg_server.go").write_text(
            "func (k Keeper) UpdateParams() {}\n", encoding="utf-8")
        rows = [
            _row(obligation_id="real1", file=str(ws / "src" / "msg_server.go"),
                 function_name="UpdateParams", question_source="per-fn"),
            # corpus-fuel: three distinct markers
            _row(obligation_id="cf1", function_name="mined_findings_hunter_bridge",
                 file="<workspace>/.auditooor/mined_findings_hunter_bridge.json",
                 question_source="mined-finding"),
            _row(obligation_id="cf2", function_name="mined_findings_hunter_bridge",
                 file=str(ws / ".auditooor" / "mined_findings_hunter_bridge.json"),
                 question_source="per-fn"),
            _row(obligation_id="cf3", function_name="SomeFn",
                 file="/tmp/whatever.sol", question_source="mined-finding"),
        ]
        _write_obls(ws, rows)
        res = m.resolve(ws, dry_run=True)
        # corpus-fuel excluded from the per-fn open count; the real one stays open.
        self.assertEqual(res["open_before"], 1, res)          # only the real one
        self.assertEqual(res["open_before_all"], 4, res)
        self.assertEqual(res["excluded_corpus_fuel_open"], 3, res)

    def test_all_corpus_fuel_reports_no_per_fn_open(self):
        ws = _ws()
        rows = [
            _row(obligation_id="cf1", function_name="mined_findings_hunter_bridge",
                 file="<workspace>/.auditooor/mined_findings_hunter_bridge.json",
                 question_source="mined-finding"),
        ]
        _write_obls(ws, rows)
        res = m.resolve(ws, dry_run=True)
        self.assertEqual(res["open_before"], 0, res)
        self.assertEqual(res["action"], "no-open-obligations", res)
        self.assertIn("corpus-fuel", res["reason"], res)

    def test_classifiers_never_false_exclude_genuine(self):
        # a genuine per-fn row with a normal source file + question_source is never
        # classified as corpus-fuel or vendored.
        r = _row(obligation_id="g", file="/repo/src/vault/keeper/payout.go",
                 function_name="processPendingSwapOuts", question_source="per-fn")
        self.assertFalse(m._is_corpus_fuel_row(r))
        self.assertFalse(m._is_vendored_row(r))


class TestHuntSidecarServingJoin(unittest.TestCase):
    """The per-fn HUNT sidecar schema (nested `result` + top-level `function_anchor`,
    no flat question_id/file/function_name) must join to a per-fn obligation by
    (file, function_name) - including abs-vs-rel path mismatch - with R76 still enforced.
    NUVA 2026-07-12 serving-join false-red: 41 obligations, all with matching hunt
    sidecars, scored 0 credit before this fix."""

    def _ws_with_source(self):
        ws = _ws()
        src = ws / "src" / "vault" / "keeper"
        src.mkdir(parents=True)
        (src / "msg_server.go").write_text(
            "func (k msgServer) UpdateInterestRate(ctx, msg) {\n"
            "\tif err := vault.ValidateManagementAuthority(msg.Authority); err != nil {\n"
            "\t\treturn nil, err\n\t}\n}\n", encoding="utf-8")
        return ws

    def _hunt_sidecar(self, ws, fn, file_abs, file_line, excerpt, applies="no"):
        d = ws / ".auditooor" / "hunt_findings_sidecars"
        d.mkdir(parents=True, exist_ok=True)
        body = {
            "status": "ok", "task_type": "workspace_hunt_harnessed",
            "function_anchor": {"file": file_abs, "fn": fn},
            "result": json.dumps({
                "applies_to_target": applies, "file_line": file_line,
                "code_excerpt": excerpt, "confidence": "high"}),
        }
        (d / f"hunt__{fn}.json").write_text(json.dumps(body), encoding="utf-8")

    def test_hunt_sidecar_joins_by_function_anchor_abs_vs_rel(self):
        ws = self._ws_with_source()
        abs_file = str(ws / "src" / "vault" / "keeper" / "msg_server.go")
        self._hunt_sidecar(
            ws, "UpdateInterestRate", abs_file,
            "src/vault/keeper/msg_server.go:2",
            "vault.ValidateManagementAuthority(msg.Authority)")
        # obligation anchors a RELATIVE path; sidecar function_anchor is ABSOLUTE
        _write_obls(ws, [_row(obligation_id="o1",
                              file="src/vault/keeper/msg_server.go",
                              function_name="UpdateInterestRate",
                              question_source="per-fn")])
        res = m.resolve(ws, dry_run=True)
        self.assertEqual(res["open_before"], 1, res)
        self.assertEqual(res["resolved_killed"], 1, res)
        self.assertEqual(res["still_open"], 0, res)

    def test_hunt_sidecar_rejected_when_excerpt_absent_from_source(self):
        # R76 must still bite: a fabricated code_excerpt that does not grep in the
        # cited file is NOT credited (never-false-pass).
        ws = self._ws_with_source()
        abs_file = str(ws / "src" / "vault" / "keeper" / "msg_server.go")
        self._hunt_sidecar(
            ws, "UpdateInterestRate", abs_file,
            "src/vault/keeper/msg_server.go:2",
            "this excerpt is fabricated and not in the file at all")
        _write_obls(ws, [_row(obligation_id="o1",
                              file="src/vault/keeper/msg_server.go",
                              function_name="UpdateInterestRate",
                              question_source="per-fn")])
        res = m.resolve(ws, dry_run=True)
        self.assertEqual(res["still_open"], 1, res)  # not credited
        self.assertEqual(res["resolved_killed"], 0, res)


if __name__ == "__main__":
    unittest.main()
