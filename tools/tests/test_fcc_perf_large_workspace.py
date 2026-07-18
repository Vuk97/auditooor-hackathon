#!/usr/bin/env python3
"""Guard test for the fcc-perf bug (function-coverage-completeness.py timeout).

Bug
---
``tools/function-coverage-completeness.py`` timed out (>120s, well over 500s on
the 6399-unit injective workspace) and returned NOTHING. The keystone failure
mode: an empty result -> empty residual -> 0 per_fn_hacker_questions ->
``make hunt-scoped`` builds 0 tasks -> the canonical README hunt is dead.

Root cause (verified by phase timing): two classify passes were quadratic in
the number of in-scope functions.

  - Pass 2 (vacuous-harness markers) re-ran BOTH target regexes
    (``_UNDER_TEST_RE.finditer`` over the whole harness body AND a freshly-built
    ``check_/test_/invariant_/prove_<re.escape(name)>`` search) ONCE PER
    FUNCTION for every harness file: O(harness_files x functions x len(text)).
    On injective that was 319 harness files x 29 371 functions = ~9.4M full-text
    regex passes -> the timeout.
  - Pass 3 (CCIA angles) ran a dynamic ``\b<re.escape(fn.name)>\b`` search over
    each angle title once per function (angles x functions), thrashing Python's
    512-entry compiled-pattern cache (~15s).

Fix
---
Scan each harness body / angle title ONCE into a target index, then visit ONLY
the candidate functions (looked up by name via the name index) instead of every
function. Pass 2 dropped from >500s to ~0.4s and Pass 3 from ~15s to ~0.4s with
IDENTICAL classifications.

This guard builds a synthetic workspace whose size makes the OLD O(N^2) code
take tens of seconds (and the real injective workspace time out) while the
fixed code finishes in well under the time bound, AND asserts the resulting
classifications are still correct (so a regression that "speeds up by skipping
work" fails the semantic asserts, not just the time bound).
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("function_coverage_completeness", _MOD_PATH)
fcc = importlib.util.module_from_spec(_spec)
sys.modules["function_coverage_completeness"] = fcc
_spec.loader.exec_module(fcc)


def _mkws(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="fcc_perf_test_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


# Size knobs. Picked so the OLD quadratic code clearly blows past the budget
# (measured: ~47s on the pre-fix code at this size) while the fixed code is
# ~linear (measured: ~0.2s) and the classifications are byte-identical.
_N_CONTRACTS = 100
_FNS_PER_CONTRACT = 60           # -> 6000 in-scope functions
_N_HARNESS = 120                 # vacuous per-function harnesses
_HARNESS_FILLER = "x" * 6000     # body bulk so a per-fn full-text scan is costly
_TIME_BUDGET_S = 20.0            # fixed code ~0.2s; pre-fix code ~47s -> fails


def _build_large_ws() -> tuple:
    """Return (ws, expected) where expected maps a few sentinel fn names to the
    classification the gate MUST produce."""
    files = {}
    # Many source files, each with FNS_PER_CONTRACT external functions.
    for c in range(_N_CONTRACTS):
        body = [f"contract C{c} {{"]
        for f in range(_FNS_PER_CONTRACT):
            body.append(f"  function fn_{c}_{f}(uint256 a) external {{ x = a; }}")
        body.append("}")
        files[f"src/C{c}.sol"] = "\n".join(body) + "\n"

    # Vacuous per-function harnesses targeting one fn each via an explicit
    # "Function under test:" header -> those fns must be classified HOLLOW.
    hollow_fns = []
    for h in range(_N_HARNESS):
        c = h % _N_CONTRACTS
        target = f"fn_{c}_0"
        hollow_fns.append(target)
        files[f"poc-tests/per_function_invariants/Halmos_C{c}_{target}.t.sol"] = (
            f"// Function under test: C{c}.{target} at src/C{c}.sol:2\n"
            f"// filler {_HARNESS_FILLER}\n"
            f"contract H{h} {{ function check_{target}() public {{ assert(true); }} }}\n"
        )

    # A CCIA angle file referencing a different fn per contract -> HOLLOW too.
    angles = []
    ccia_fns = []
    for c in range(_N_CONTRACTS):
        target = f"fn_{c}_1"
        ccia_fns.append(target)
        angles.append({
            "id": f"A-{c}",
            "severity": "MEDIUM",
            "title": f"Unauthenticated state write: C{c}.{target}",
            "contracts": [f"C{c}"],
            "line": 3,
        })
    files[".auditooor/ccia_attack_angles.json"] = json.dumps(angles)

    # A real CONFIRMED finding for one fn -> real-attack.
    files[".auditooor/hunt_findings_sidecars/F1.json"] = json.dumps({
        "verdict": "CONFIRMED",
        "file_line": "src/C0.sol:4",   # body span of fn_0_2 (decl line ~4)
        "function": "fn_0_2",
        "poc_evidence_lines": "[PASS] testDrain",
    })

    ws = _mkws(files)
    expected = {
        # explicit-header vacuous harness -> hollow
        "fn_0_0": "hollow",
        # ccia angle -> hollow
        "fn_0_1": "hollow",
        # a fn with no reference at all -> untouched
        "fn_5_7": "untouched",
        "fn_42_30": "untouched",
    }
    return ws, expected, hollow_fns, ccia_fns


class TestFccPerfLargeWorkspace(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_UNIVERSAL_BYPASS"] = "1"
        os.environ["AUDITOOOR_SPAWN_WORKER_BYPASS"] = "1"

    def test_large_workspace_completes_under_time_bound_with_worklist(self):
        ws, expected, hollow_fns, ccia_fns = _build_large_ws()
        t0 = time.time()
        r = fcc.evaluate(ws)
        elapsed = time.time() - t0

        # 1. Time bound: the fix must keep classify ~linear. The old O(N^2)
        #    code (harness x functions full-text regex) blows past this on a
        #    workspace this size.
        self.assertLess(
            elapsed, _TIME_BUDGET_S,
            f"function-coverage-completeness took {elapsed:.1f}s on a "
            f"{_N_CONTRACTS * _FNS_PER_CONTRACT}-fn workspace "
            f"(budget {_TIME_BUDGET_S}s) - the fcc-perf O(N^2) regression is back",
        )

        # 2. A worklist MUST be emitted and be non-empty (the keystone: empty
        #    residual kills the README hunt).
        payload = fcc._emit_worklist(r)
        self.assertGreater(
            payload["worklist_size"], 0,
            "fcc emitted an EMPTY worklist - downstream hunt-scoped builds 0 tasks",
        )

        # 3. Semantic guard: the fix must NOT have sped things up by skipping
        #    work. The specific classifications must still be correct.
        classes = {f["name"]: f["classification"] for f in r["functions"]}
        for name, want in expected.items():
            self.assertEqual(
                classes.get(name), want,
                f"{name}: got {classes.get(name)!r}, want {want!r} "
                f"(semantic regression in the perf fix)",
            )
        # Every explicit-header harness target is hollow; every ccia target is
        # hollow; the one CONFIRMED fn is real-attack.
        for name in hollow_fns:
            self.assertEqual(classes.get(name), "hollow", f"{name} harness target")
        for name in ccia_fns:
            self.assertEqual(classes.get(name), "hollow", f"{name} ccia target")
        self.assertEqual(classes.get("fn_0_2"), "real-attack")

    def test_harness_target_index_matches_singleton_helper(self):
        """The precomputed index path must agree with the single-fn helper on
        both targeting branches (explicit header and marker-name fallback)."""
        # Explicit "Function under test:" header form.
        explicit_txt = (
            "// Function under test: Vault.deposit at src/Vault.sol:2\n"
            "contract H { function check_deposit() public {} }\n"
        )
        # Marker-name-only form (no explicit header).
        marker_txt = "contract H { function invariant_withdraw() public {} }\n"

        class _Fn:
            def __init__(self, name, file):
                self.name = name
                self.file = file

        deposit = _Fn("deposit", "src/Vault.sol")
        withdraw = _Fn("withdraw", "src/Vault.sol")
        other = _Fn("transfer", "src/Vault.sol")
        wrong_file = _Fn("deposit", "src/Other.sol")

        for txt, fn, want in [
            (explicit_txt, deposit, True),
            (explicit_txt, withdraw, False),
            (explicit_txt, wrong_file, False),   # name matches but file does not
            (marker_txt, withdraw, True),
            (marker_txt, other, False),
        ]:
            idx = fcc._harness_target_index(txt)
            self.assertEqual(
                fcc._index_targets_function(idx, fn),
                fcc._harness_targets_function(txt, fn),
                f"index vs singleton disagree for {fn.name}",
            )
            self.assertEqual(fcc._index_targets_function(idx, fn), want)


if __name__ == "__main__":
    unittest.main()
