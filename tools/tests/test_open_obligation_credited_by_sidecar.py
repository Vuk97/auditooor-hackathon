#!/usr/bin/env python3
"""Guard: check_hacker_questions_resolved must credit an OPEN-state per-fn
obligation when a matching R76-VERIFIED sidecar exists on disk, regardless of the
lagging `state` field.

Root cause (nuva / axelar-dlt / axelar-sc 2026-07-12): `make audit-complete`
REGENERATES obligations (state resets to `open`) on every `make audit` / dataflow
re-emit, while the standalone hacker-question-obligation-resolve.py that flips
state -> terminal runs OUTSIDE the gate. So within a single audit-complete run the
freshly-regenerated obligations are state=open even though their verified sidecars
are already on disk. The gate credited only `is_terminal AND has_sidecar`, so it
counted them OPEN -> a permanent false-red fail-open-hacker-questions (standalone
resolve => 0 open, in-pipeline gate => fail-open every run). Fix: credit on
has_sidecar alone (the same _verified_sidecar_index the resolver uses).

NEVER-FALSE-PASS: an open obligation with NO verified sidecar stays OPEN.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load_acc():
    spec = importlib.util.spec_from_file_location(
        "acc_openci", str(_TOOLS / "audit-completeness-check.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_openci"] = m
    spec.loader.exec_module(m)
    return m


class TestOpenObligationCreditedBySidecar(unittest.TestCase):
    def setUp(self):
        self._saved_l37 = os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.acc = _load_acc()

    def tearDown(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        if self._saved_l37 is not None:
            os.environ["AUDITOOOR_L37_STRICT"] = self._saved_l37

    def _build_ws(self, tmp: Path, with_sidecar: bool):
        ad = tmp / ".auditooor"
        (ad / "hunt_findings_sidecars").mkdir(parents=True, exist_ok=True)
        src = tmp / "src" / "vault" / "keeper"
        src.mkdir(parents=True, exist_ok=True)
        f = src / "msg_server.go"
        # line 2 carries the excerpt the sidecar cites (R76 grep must match)
        f.write_text(
            "package keeper\n"
            "func (k Keeper) UpdateInterestRate(ctx Ctx) error {\n"
            "\tif err := vault.ValidateManagementAuthority(msg.Authority); err != nil {\n"
            "\t\treturn err\n\t}\n\treturn nil\n}\n", encoding="utf-8")
        # OPEN-state per-fn obligation (freshly regenerated)
        ob = {
            "obligation_id": "regen1", "state": "open",
            "file": str(f), "function_name": "UpdateInterestRate",
            "question_source": "per-fn", "language": "go",
            "question": "auth-gated?",
        }
        (ad / "hacker_question_obligations.jsonl").write_text(
            json.dumps(ob) + "\n", encoding="utf-8")
        if with_sidecar:
            sc = {
                "question_id": "regen1",
                "verdict": "KILL",
                "applies_to_target": "no",
                "file_line": f"{f}:3",
                "code_excerpt": "vault.ValidateManagementAuthority(msg.Authority)",
                "file": str(f), "function_name": "UpdateInterestRate",
            }
            (ad / "hunt_findings_sidecars" / "hunt__regen1.json").write_text(
                json.dumps(sc), encoding="utf-8")
        return tmp

    def test_open_obligation_with_verified_sidecar_is_credited(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_ws(Path(tmp), with_sidecar=True)
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            r = self.acc.check_hacker_questions_resolved(ws)
            self.assertEqual(r.detail.get("open"), 0, r.detail)
            self.assertTrue(r.ok, "open row backed by a verified sidecar must be credited")

    def test_open_obligation_without_sidecar_stays_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._build_ws(Path(tmp), with_sidecar=False)
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            r = self.acc.check_hacker_questions_resolved(ws)
            self.assertEqual(r.detail.get("open"), 1, r.detail)
            self.assertFalse(r.ok, "open row with NO verified sidecar must stay OPEN (never-false-pass)")


class TestGateBasenameFallbackMatchesResolver(unittest.TestCase):
    """_obligation_has_verified_sidecar must credit by (basename, fn), mirroring the
    resolver's _match_obligation, so the GATE credits exactly what the resolver flips
    terminal. axelar-dlt 2026-07-12: resolver state=9 open but the gate counted 53 open
    because 44 rows only matched by basename (obligation anchors a RELATIVE path; the
    sidecar function_anchor is ABSOLUTE, indexed under (abs,fn)+(basename,fn))."""

    def setUp(self):
        self.acc = _load_acc()

    def test_credits_by_basename_when_obligation_path_relative(self):
        ob = {"obligation_id": "x", "file": "src/vault/keeper/msg_server.go",
              "function_name": "UpdateInterestRate"}
        # index keyed only under ABSOLUTE + basename (as _build_sidecar_index does)
        by_file_fn = {
            ("/abs/ws/src/vault/keeper/msg_server.go", "UpdateInterestRate"): {"v": 1},
            ("msg_server.go", "UpdateInterestRate"): {"v": 1},
        }
        self.assertTrue(self.acc._obligation_has_verified_sidecar(ob, {}, by_file_fn))

    def test_no_false_credit_when_no_key_matches(self):
        ob = {"obligation_id": "x", "file": "src/other.go", "function_name": "Foo"}
        by_file_fn = {("msg_server.go", "UpdateInterestRate"): {"v": 1}}
        self.assertFalse(self.acc._obligation_has_verified_sidecar(ob, {}, by_file_fn))


if __name__ == "__main__":
    unittest.main()
