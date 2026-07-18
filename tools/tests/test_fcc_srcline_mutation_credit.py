#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-FCC-SRCLINE-MUT-CREDIT registered via agent-pathspec-register.py -->
"""Guard: a mutation-KILLED record source-anchored to a function's decl line
credits that function under the mutation_verify bar, even when the record's
``function`` field is a harness ALIAS (e.g. ``XFn_account.t`` -> junk name
``t``) so the function-name key silently misses.

Regression for the morpho-midnight function-coverage false-RED: take/repay/
setFeeSetter each had killed, non-vacuous cross_function harnesses anchored to
their exact source line (``source: Midnight.sol:502`` etc.), but the kill was
keyed to the harness alias and never credited the real function; a sibling
vacuous PF stub keyed correctly and voided the terminal-clean rule-out, so all
three were reported hollow.

The negative case is the load-bearing half: a line with ONLY vacuous /
no-baseline records must NOT be credited (no false-green).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("fcc", str(_TOOLS / "function-coverage-completeness.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["fcc"] = m
spec.loader.exec_module(m)


_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

contract C {
    uint256 public x;

    function killed_fn(uint256 v) external {
        require(v > 0, "z");
        x = v + 1;
    }

    function only_vacuous_fn(uint256 v) external {
        require(v > 0, "z");
        x = v - 1;
    }
}
"""


def _ws_with(records: list) -> Path:
    ws = Path(tempfile.mkdtemp())
    src = ws / "src"
    src.mkdir()
    (src / "C.sol").write_text(_SRC, encoding="utf-8")
    (ws / ".auditooor").mkdir()
    # r36-rebuttal: lane FIX-FCC-SRCLINE-MUT-CREDIT registered in .auditooor/agent_pathspec.json
    # Flat-list payload shape (one of the container shapes _records_from_payload
    # accepts directly), so the test exercises the source-line index, not the
    # container-key parsing.
    (ws / ".auditooor" / "mutation_verify_coverage.json").write_text(
        json.dumps(records), encoding="utf-8")
    return ws


def _line_of(name: str) -> int:
    for i, ln in enumerate(_SRC.splitlines(), start=1):
        if f"function {name}(" in ln:
            return i
    raise AssertionError(name)


class TestSrclineMutationCredit(unittest.TestCase):
    def test_killed_alias_record_credits_via_source_line(self):
        kl = _line_of("killed_fn")
        # harness-alias function field (-> junk name) + source anchors killed_fn,
        # plus a sibling vacuous record at the SAME line (must not win).
        ws = _ws_with([
            {"function": "XFn_alias.t", "source": f"src/C.sol:{kl}",
             "killed": True, "oracle_verdict": "non-vacuous", "verdict": "killed"},
            {"function": "killed_fn", "source": f"src/C.sol:{kl}",
             "killed": False, "verdict": "vacuous"},
        ])
        r = m.evaluate(ws, mutation_verify=True)
        names = {f["name"] for f in r["hollow_or_untouched"]}
        self.assertNotIn("killed_fn", names,
                         "source-anchored kill must credit the function")

    def test_only_vacuous_line_is_not_credited(self):
        vl = _line_of("only_vacuous_fn")
        # ONLY vacuous / no-baseline at this line -> must stay uncredited.
        ws = _ws_with([
            {"function": "XFn_alias2.t", "source": f"src/C.sol:{vl}",
             "killed": False, "oracle_verdict": "no-baseline", "verdict": "no-baseline"},
            {"function": "only_vacuous_fn", "source": f"src/C.sol:{vl}",
             "killed": False, "verdict": "vacuous"},
        ])
        r = m.evaluate(ws, mutation_verify=True)
        names = {f["name"] for f in r["hollow_or_untouched"]}
        self.assertIn("only_vacuous_fn", names,
                      "a vacuous/no-baseline-only line must NOT be credited (false-green guard)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
