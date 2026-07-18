#!/usr/bin/env python3
"""Guard test for the TYPED DEEP-ENGINE SKIP disposition in L37
``tools/audit-completeness-check.py``.

Bug (deep-engine-typed-skip): a mixed Go + Rust + Solidity workspace fails the
L37 ``live-engines`` (signal c, ``fail-engines-not-run-for-language``) and
``engine-harness`` (signal c2, ``fail-engine-false-pass``) signals because:

  (a) the Go / Rust deep arm has NO applicable coverage-guided engine wired
      (a Cosmos Go chain has no medusa / echidna equivalent), and the Solidity
      ``check_freshness`` authority short-circuits at ``fail-no-current-run-start``
      with ``skip=null`` BEFORE it ever reads the typed-skip record - so an
      honestly-emitted typed skip was never credited; and
  (b) the EVM coverage-guided fuzzers (halmos / medusa / echidna) were blocked
      rc=2 on the mixed layout, leaving NO real engine harness - which the proof
      gate reports as ``pass-no-engine-harness`` and the c2 signal then turned
      into the Morpho hollow false-pass.

The HONEST fix is a TYPED DEEP-ENGINE SKIP: a documented, justified
``.auditooor/stage_skips.json`` record that the completeness check credits as a
``typed-skip`` disposition (NOT a hollow ``pass`` and NOT a faked harness count)
for a language arm that genuinely has no applicable coverage-guided engine in
this run.

These tests assert:

  Case A  Go/Rust arm + a typed deep-engine skip on disk (no audit-run-full
          start row, so check_freshness is coupling-blind) -> ``check_live_engines``
          PASSES via the coupling-independent typed-skip and marks it as such.
  Case B  SAME workspace WITHOUT the skip -> ``check_live_engines`` FAILS with
          ``fail-engines-not-run-for-language`` (the fix does NOT weaken the
          gate - no skip means no credit).
  Case C  the EVM-no-engine-harness shape (proof gate verdict
          ``pass-no-engine-harness``) + a typed deep-engine skip ->
          ``check_engine_harness`` is recorded as a ``engine-harness-typed-skip``
          disposition (ok), NOT ``fail-engine-false-pass``.
  Case D  NEGATIVE / anti-false-green: a DETECTED fake/tautological stub
          (proof gate returns ``unproven`` non-empty) + a typed skip present ->
          ``check_engine_harness`` STILL FAILS. The skip cannot launder a
          tautological stub into a pass.
  Case E  a typed skip with an EMPTY reason is NOT credited (not a documented,
          justified skip).

The test never touches a live workspace; all fixtures are TMPDIR. It does not
modify the tool under test.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit-completeness-check.py"
_LANG_MISMATCH_VERDICT = "fail-engines-not-run-for-language"


def _load_acc_module():
    spec = importlib.util.spec_from_file_location("_acc_typed_skip_test_mod", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acc_typed_skip_test_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


_ACC = _load_acc_module()


def _mk_go_rust_ws() -> Path:
    """A mixed Go + Rust workspace (the non-EVM deep arm). NO
    audit_run_full_manifest.jsonl start row, so check_freshness is
    coupling-blind (fail-no-current-run-start) and only the COUPLING-INDEPENDENT
    typed-skip path can credit the arm."""
    ws = Path(tempfile.mkdtemp(prefix="l37_typed_skip_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "keeper.go").write_text(
        "package keeper\nfunc Mint() {}\n", encoding="utf-8"
    )
    (ws / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
    return ws


def _write_typed_skip(ws: Path, reason: str) -> None:
    """Write a genuine typed deep-engine skip record (the shape audit-deep.sh
    emits): a stage_skips.json entry under the default skip key with a reason, a
    timestamp, and a run_id."""
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "stage_skips.json").write_text(
        json.dumps(
            {
                "NO_AUDIT_DEEP_REASON": {
                    "reason": reason,
                    "generated_at": datetime.now(timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "run_id": "TEST-RUN-1",
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )


class TypedDeepEngineSkipLiveEnginesTests(unittest.TestCase):
    def test_case_a_typed_skip_credits_go_rust_arm(self) -> None:
        ws = _mk_go_rust_ws()
        _write_typed_skip(
            ws,
            "no coverage-guided non-EVM engine wired for this Cosmos Go / Rust "
            "chain (no medusa/echidna equivalent); scanners ran",
        )
        res = _ACC.check_live_engines(ws)
        self.assertTrue(
            res.ok,
            msg=f"live-engines should PASS via typed-skip, got reason={res.reason}",
        )
        self.assertTrue(res.detail.get("audit_deep_skip"))
        self.assertTrue(
            res.detail.get("audit_deep_skip_coupling_independent"),
            msg="skip must be credited via the coupling-independent path",
        )

    def test_case_b_no_skip_still_fails_not_weakened(self) -> None:
        ws = _mk_go_rust_ws()
        # NO stage_skips.json.
        res = _ACC.check_live_engines(ws)
        self.assertFalse(
            res.ok,
            msg="live-engines must FAIL when no engine ran and no typed skip exists",
        )
        self.assertEqual(res.verdict_override, _LANG_MISMATCH_VERDICT)
        self.assertFalse(res.detail.get("audit_deep_skip"))


class TypedDeepEngineSkipEngineHarnessTests(unittest.TestCase):
    def _patch_proof_gate(self, payload: dict):
        orig = _ACC._call_engine_proof_gate

        def fake(_ws):
            return payload

        _ACC._call_engine_proof_gate = fake
        self.addCleanup(setattr, _ACC, "_call_engine_proof_gate", orig)

    def _mk_evm_ws_with_blocked_engines(self) -> Path:
        """An EVM workspace whose solidity-named scanner/detector steps execute
        (non-empty stdout) but produced NO real coverage-guided engine harness -
        the rc=2-blocked-on-mixed-layout shape."""
        ws = Path(tempfile.mkdtemp(prefix="l37_typed_skip_eh_"))
        (ws / ".auditooor" / "solidity-deep-audit").mkdir(parents=True, exist_ok=True)
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "X.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract X {}\n", encoding="utf-8"
        )
        # A solidity-named detector step that "executed" (non-empty stdout) and
        # so trips the EVM proof requirement on this EVM workspace.
        (ws / ".auditooor" / "solidity-deep-audit" / "aderyn-solidity.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.solidity_deep_audit.step.v1",
                    "tool": "aderyn-solidity",
                    "status": "ok",
                    "returncode": 0,
                    "stdout_tail": "aderyn scan complete: 0 issues",
                }
            ),
            encoding="utf-8",
        )
        return ws

    def test_case_c_no_harness_blocked_plus_skip_is_typed_skip(self) -> None:
        ws = self._mk_evm_ws_with_blocked_engines()
        _write_typed_skip(
            ws,
            "EVM coverage-guided fuzzers (medusa/halmos/echidna) blocked rc=2 on "
            "mixed Go+Solidity layout; no single forge project root",
        )
        # Proof gate honestly reports NO engine harness files were discovered.
        self._patch_proof_gate(
            {
                "verdict": "pass-no-engine-harness",
                "proven": [],
                "unproven": [],
                "harnesses": [],
                "reason": "no engine harness files discovered",
            }
        )
        res = _ACC.check_engine_harness(ws)
        self.assertTrue(
            res.ok,
            msg=f"engine-harness should be a typed-skip, got reason={res.reason}",
        )
        self.assertEqual(res.detail.get("disposition"), "engine-harness-typed-skip")

    def _force_strict(self) -> None:
        """Force the engine-proof STRICT mode for the duration of a test."""
        import os

        prev = os.environ.get("AUDITOOOR_L37_ENGINE_PROOF_STRICT")
        os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = "1"

        def _restore():
            if prev is None:
                os.environ.pop("AUDITOOOR_L37_ENGINE_PROOF_STRICT", None)
            else:
                os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = prev

        self.addCleanup(_restore)

    def test_case_c_strict_no_harness_blocked_plus_skip_is_typed_skip(self) -> None:
        """STRICT mode: the typed-skip must be credited even when the engine-proof
        manifest is absent - because the proof gate has already PROVEN there is no
        harness to certify (the rc=2 strict-manifest-missing ordering fix)."""
        self._force_strict()
        ws = self._mk_evm_ws_with_blocked_engines()
        # NO .auditooor/evm_engine_proof/engine_harness_proof.json manifest.
        _write_typed_skip(
            ws,
            "EVM coverage-guided fuzzers blocked rc=2 on mixed Go+Solidity layout",
        )
        self._patch_proof_gate(
            {
                "verdict": "pass-no-engine-harness",
                "proven": [],
                "unproven": [],
                "harnesses": [],
                "reason": "no engine harness files discovered",
            }
        )
        res = _ACC.check_engine_harness(ws)
        self.assertTrue(
            res.ok,
            msg=f"STRICT typed-skip should pass, got reason={res.reason}",
        )
        self.assertEqual(res.detail.get("disposition"), "engine-harness-typed-skip")

    def test_case_d_strict_detected_stub_plus_skip_still_fails(self) -> None:
        """STRICT ANTI-FALSE-GREEN: a DETECTED stub must STILL fail in strict
        mode even with a skip present (the no-harness early-out requires an EMPTY
        unproven list, so a stub falls through to the strict / proof-fail path)."""
        self._force_strict()
        ws = self._mk_evm_ws_with_blocked_engines()
        _write_typed_skip(ws, "engines blocked rc=2")
        self._patch_proof_gate(
            {
                "verdict": "fail-engine-harness-proof",
                "proven": [],
                "unproven": ["StubHarness.sol::test_noop"],
                "harnesses": ["StubHarness.sol::test_noop"],
                "reason": "1 tautological stub harness",
            }
        )
        res = _ACC.check_engine_harness(ws)
        self.assertFalse(
            res.ok,
            msg="STRICT: a detected stub must STILL fail even with a typed skip",
        )
        self.assertNotEqual(res.detail.get("disposition"), "engine-harness-typed-skip")

    def test_case_d_detected_stub_plus_skip_still_fails(self) -> None:
        """ANTI-FALSE-GREEN: a typed skip must NOT launder a DETECTED fake/
        tautological stub harness into a pass."""
        ws = self._mk_evm_ws_with_blocked_engines()
        _write_typed_skip(ws, "engines blocked rc=2")
        # Proof gate DETECTED a tautological stub harness (unproven non-empty).
        self._patch_proof_gate(
            {
                "verdict": "fail-engine-harness-proof",
                "proven": [],
                "unproven": ["StubHarness.sol::test_noop"],
                "harnesses": ["StubHarness.sol::test_noop"],
                "reason": "1 tautological stub harness",
            }
        )
        res = _ACC.check_engine_harness(ws)
        self.assertFalse(
            res.ok,
            msg="a DETECTED stub must STILL fail even when a typed skip is present",
        )
        self.assertNotEqual(res.detail.get("disposition"), "engine-harness-typed-skip")

    def test_case_c_no_skip_still_fails_false_pass(self) -> None:
        """Without a typed skip, the no-harness shape STILL fails (the original
        Morpho false-pass guard is preserved)."""
        ws = self._mk_evm_ws_with_blocked_engines()
        # NO stage_skips.json.
        self._patch_proof_gate(
            {
                "verdict": "pass-no-engine-harness",
                "proven": [],
                "unproven": [],
                "harnesses": [],
                "reason": "no engine harness files discovered",
            }
        )
        res = _ACC.check_engine_harness(ws)
        self.assertFalse(
            res.ok,
            msg="no-harness shape WITHOUT a typed skip must remain a fail-engine-false-pass",
        )


class TypedDeepEngineSkipValidityTests(unittest.TestCase):
    def test_case_e_empty_reason_not_credited(self) -> None:
        ws = _mk_go_rust_ws()
        (ws / ".auditooor" / "stage_skips.json").write_text(
            json.dumps(
                {
                    "NO_AUDIT_DEEP_REASON": {
                        "reason": "",
                        "generated_at": datetime.now(timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "run_id": "TEST-RUN-1",
                    }
                }
            ),
            encoding="utf-8",
        )
        self.assertIsNone(
            _ACC._independent_typed_deep_skip(ws),
            msg="an empty-reason skip is not a documented, justified skip",
        )
        res = _ACC.check_live_engines(ws)
        self.assertFalse(
            res.ok,
            msg="an empty-reason skip must NOT credit the live-engines signal",
        )

    def test_missing_skip_file_returns_none(self) -> None:
        ws = _mk_go_rust_ws()
        self.assertIsNone(_ACC._independent_typed_deep_skip(ws))


if __name__ == "__main__":
    unittest.main()
