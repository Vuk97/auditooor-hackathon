#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-F2-DONE-GATE registered via agent-pathspec-register.py -->
"""F2 done-gate regression (spec E2.1 + E2.2 + E2.4).

The per-fn hacker-question hunt writes one OPEN obligation per pre-source-read
question into <ws>/.auditooor/hacker_question_obligations.jsonl. Until F2 those
obligations were never gated by audit-complete / audit-done-guard - a workspace
could pass with 1262 OPEN obligations. This test pins the close-the-loop gate:

  E2.1 - audit-completeness-check STRICT fails `fail-open-hacker-questions` when
         any obligation is open (and flips green once every row carries a
         terminal state backed by an R76-verified verdict sidecar).
  E2.2 - audit-done-guard prints NOT-DONE on the same OPEN backlog (and DONE once
         resolved), recomputed un-fakeably.
  E2.4 - a dead/401/402 hunt provider with OPEN obligations fires
         `fail-llm-provider-dead`.

Un-fakeable: a hand-written state=resolved with NO verified sidecar stays OPEN.
Per-language: the open count is keyed by the row `language` field.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name: str, alias: str):
    spec = importlib.util.spec_from_file_location(alias, str(_TOOLS / name))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


acc = _load("audit-completeness-check.py", "_f2_acc")
adg = _load("audit-done-guard.py", "_f2_adg")


# Env vars we toggle; restored after each test.
_ENV_KEYS = (
    "AUDITOOOR_L37_STRICT",
    "AUDITOOOR_L37_HACKER_QUESTIONS_RESOLVED_STRICT",
    "AUDITOOOR_L37_PROVIDER_LIVENESS_STRICT",
    "AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT",
    "AUDITOOOR_HUNT_PROVIDER",
    "ENFORCE_AUTONOMOUS_PROOF_CONVERSION",
)


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    return ws


def _write_obligations(ws: Path, rows: list[dict]) -> None:
    p = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _open_row(oid: str, *, language: str = "solidity", file: str = "src/Vault.sol",
              fn: str = "withdraw") -> dict:
    return {
        "obligation_id": oid,
        "state": "open",
        "language": language,
        "file": file,
        "function_name": fn,
        "function_signature": fn,
        "question": f"is {fn} re-entrancy-safe?",
    }


def _drop_resolving_evidence(ws: Path, oid: str, *, file: str = "src/Vault.sol",
                             fn: str = "withdraw") -> None:
    """Create a REAL source file + an R76-verifiable verdict sidecar that the
    resolver will accept (so the obligation flips terminal). Also flip the row's
    state to a terminal value so BOTH conditions (state + sidecar) hold."""
    # real source the sidecar cites
    src = ws / file
    src.parent.mkdir(parents=True, exist_ok=True)
    excerpt = "function withdraw() external { balances[msg.sender] = 0; }"
    src.write_text(
        "// SPDX\npragma solidity ^0.8.0;\ncontract Vault {\n"
        f"  {excerpt}\n}}\n",
        encoding="utf-8",
    )
    # verified verdict sidecar in the canonical dir
    scdir = ws / ".auditooor" / "hacker_question_verdicts"
    scdir.mkdir(parents=True, exist_ok=True)
    (scdir / f"{oid}.json").write_text(json.dumps({
        "question_id": oid,
        "verdict": "KILL - not a bug, balance is zeroed before send",
        "file_line": f"{file}:4",
        "code_excerpt": excerpt,
        "file": file,
        "function_name": fn,
    }), encoding="utf-8")


class TestF2DoneGate(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        # Keep the provider-liveness arm deterministic + offline by default:
        # force the provider usable so it does not interfere with the
        # hacker-questions-resolved assertions unless a test overrides it.
        os.environ["AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT"] = "usable"

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ---- E2.1: audit-completeness-check signal -----------------------------
    def test_open_obligations_signal_fails_strict(self):
        ws = _ws()
        _write_obligations(ws, [_open_row("aaa111"), _open_row("bbb222", language="move")])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = acc.check_hacker_questions_resolved(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertEqual(r.detail["open"], 2)
        # per-language keying: both languages surface
        self.assertIn("solidity", r.detail["open_by_language"])
        self.assertIn("move", r.detail["open_by_language"])

    def test_open_obligations_warn_pass_non_strict(self):
        ws = _ws()
        _write_obligations(ws, [_open_row("aaa111")])
        # no strict env -> WARN-pass (surfaced, not bricking)
        r = acc.check_hacker_questions_resolved(ws)
        self.assertTrue(r.ok)
        self.assertTrue(r.reason.startswith("WARN:"))

    def test_absent_obligations_pass(self):
        ws = _ws()
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = acc.check_hacker_questions_resolved(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.detail.get("rows"), 0)

    def test_hand_written_resolved_without_sidecar_stays_open(self):
        # E2.1 un-fakeable: a row claiming state=resolved with NO verified
        # sidecar must still count as OPEN under STRICT.
        ws = _ws()
        row = _open_row("ccc333")
        row["state"] = "resolved"  # hand-written, no sidecar
        _write_obligations(ws, [row])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = acc.check_hacker_questions_resolved(ws)
        self.assertFalse(r.ok, "hand-written resolved with no sidecar must stay open")
        self.assertEqual(r.detail["open"], 1)

    def test_valid_sidecar_flips_green(self):
        ws = _ws()
        row = _open_row("ddd444")
        row["state"] = "killed"  # terminal AND backed by the sidecar below
        _write_obligations(ws, [row])
        _drop_resolving_evidence(ws, "ddd444")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = acc.check_hacker_questions_resolved(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.detail["open"], 0)
        self.assertEqual(r.detail["resolved"], 1)

    def test_evaluate_surfaces_fail_open_hacker_questions(self):
        # The named verdict must appear in the gate's failures list under STRICT.
        ws = _ws()
        _write_obligations(ws, [_open_row("eee555")])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        result = acc.evaluate(ws)
        self.assertIn("fail-open-hacker-questions", result["failures"])

    # ---- E2.4: provider-liveness arm ---------------------------------------
    def test_dead_provider_with_open_obligations_reds(self):
        ws = _ws()
        _write_obligations(ws, [_open_row("fff666")])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT"] = "dead"
        r = acc.check_provider_liveness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertIn("DEAD", r.reason)

    def test_dead_provider_no_open_obligations_passes(self):
        # No open obligations -> nothing to hunt -> provider-liveness not gating.
        ws = _ws()
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT"] = "dead"
        r = acc.check_provider_liveness(ws)
        self.assertTrue(r.ok, r.reason)

    def test_evaluate_surfaces_fail_llm_provider_dead(self):
        ws = _ws()
        _write_obligations(ws, [_open_row("ggg777")])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_L37_PROVIDER_LIVENESS_VERDICT"] = "dead"
        result = acc.evaluate(ws)
        self.assertIn("fail-llm-provider-dead", result["failures"])

    # ---- E2.2: audit-done-guard mirror -------------------------------------
    def _done_happy_ws(self) -> Path:
        ws = _ws()
        (ws / ".auditooor" / "audit_completion.json").write_text(
            json.dumps({"verdict": "pass-audit-complete", "strict": True}),
            encoding="utf-8",
        )
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f.md").write_text("a finding")
        return ws

    def test_done_guard_not_done_on_open_obligations(self):
        ws = self._done_happy_ws()
        _write_obligations(ws, [_open_row("hhh888"), _open_row("iii999", language="go")])
        r = adg.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], r["reason"])
        self.assertIn("open hacker-question obligations", r["reason"])
        self.assertTrue(any(g.startswith("open-hacker-questions") for g in r["fail_gates"]))

    def test_done_guard_resolved_obligations_do_not_fire_gate(self):
        # E2.2 green half: a terminal + verified-sidecar-backed obligation must
        # NOT trigger the open-hacker-questions gate. (Downstream gates such as
        # README-conformance may still keep a bare fixture NOT-DONE in this env,
        # so we assert the obligation gate specifically does not fire rather than
        # full DONE.)
        ws = self._done_happy_ws()
        row = _open_row("jjj000")
        row["state"] = "answered"
        _write_obligations(ws, [row])
        _drop_resolving_evidence(ws, "jjj000")
        obl = adg._count_open_obligations(ws)
        self.assertEqual(obl["open"], 0, obl)
        r = adg.evaluate(ws, ttl_hours=6)
        self.assertNotIn("open hacker-question obligations", r["reason"])

    def test_count_open_obligations_recompute(self):
        # The un-fakeable recompute: 2 open + 1 hand-resolved (no sidecar, stays
        # open) + 1 truly resolved -> 3 open.
        ws = _ws()
        rows = [_open_row("o1"), _open_row("o2", language="go")]
        hand = _open_row("o3"); hand["state"] = "resolved"      # no sidecar -> open
        good = _open_row("o4", fn="deposit"); good["state"] = "killed"
        _write_obligations(ws, rows + [hand, good])
        _drop_resolving_evidence(ws, "o4", fn="deposit")
        obl = adg._count_open_obligations(ws)
        self.assertEqual(obl["open"], 3, obl)
        self.assertEqual(obl["rows"], 4)

    def test_done_guard_absent_obligations_do_not_fire_gate(self):
        # No obligations file -> the F2 gate must be a no-op (fail-open).
        ws = self._done_happy_ws()
        obl = adg._count_open_obligations(ws)
        self.assertEqual(obl["open"], 0)
        r = adg.evaluate(ws, ttl_hours=6)
        self.assertNotIn("open hacker-question obligations", r["reason"])

    def test_done_guard_hand_written_resolved_blocks_done(self):
        ws = self._done_happy_ws()
        row = _open_row("kkk111")
        row["state"] = "resolved"  # no sidecar
        _write_obligations(ws, [row])
        r = adg.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], "hand-written resolved with no sidecar must block done")
        self.assertIn("open hacker-question obligations", r["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
