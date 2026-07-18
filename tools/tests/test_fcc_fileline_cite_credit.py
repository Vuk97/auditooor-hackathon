"""Guard test - function-coverage-completeness credits a source-cited
applies_to_target=no rule-out whose citation is in `file_line` (the mega /
workflow-drill per-fn hunt shape), not only `defending_lines`.

Root cause this guards (2026-06-13): the applies=no branch only credited as
real-attack when `defending_lines` carried a file:line. The mega/workflow-drill
per-fn hunt records its source citation in `file_line` (+ code_excerpt), often
with an 'L' line prefix ("Foo.sol:L2") that _FILE_LINE_RE does not match, and no
`defending_lines` field - so thousands of genuine source-cited rule-outs landed
hollow (monero real_attack 0, after fix 30). R80 must stay enforced: an
R76-flagged-hallucinated cite, and a bare-prose "no", stay hollow.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("function_coverage_completeness", _MOD)
fcc = importlib.util.module_from_spec(_spec)
sys.modules["function_coverage_completeness"] = fcc
_spec.loader.exec_module(fcc)

SRC = "contract Foo {\n  function bar() external {\n    x = 1;\n  }\n}\n"


def _mkws(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="fcc_fl_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def _cls(r):
    return {f["name"]: f["classification"] for f in r["functions"]}


def _sidecar(extra_inner):
    inner = {"applies_to_target": "no", "confidence": "high", "candidate_finding": "N/A"}
    inner.update(extra_inner)
    return json.dumps({"status": "ok", "task_type": "perfn_mega_hunt",
                       "function_anchor": {"file": "src/Foo.sol", "function": "bar", "line": 2},
                       "result": inner})


class FccFileLineCiteTest(unittest.TestCase):
    def test_file_line_cite_with_L_prefix_credits(self):
        # the mega shape: cite in file_line (L-prefix), no defending_lines
        ws = _mkws({"src/Foo.sol": SRC,
                    ".auditooor/hunt_findings_sidecars/m.json":
                        _sidecar({"file_line": "src/Foo.sol:L2", "code_excerpt": "x = 1;"})})
        r = fcc.evaluate(ws)
        self.assertEqual(_cls(r)["bar"], "real-attack",
                         "applies=no with a real file_line cite must credit as real-attack")
        ev = [f for f in r["functions"] if f["name"] == "bar"][0]["evidence"]
        self.assertTrue(any("finding-fp-defended-anchor" in e for e in ev), ev)

    def test_r76_flagged_cite_stays_hollow(self):
        # R80: an R76-flagged-hallucinated cite must NOT credit
        ws = _mkws({"src/Foo.sol": SRC,
                    ".auditooor/hunt_findings_sidecars/m.json":
                        _sidecar({"file_line": "src/Foo.sol:L2",
                                  "r76_source_existence_fail": True})})
        r = fcc.evaluate(ws)
        self.assertEqual(_cls(r)["bar"], "hollow",
                         "R76-flagged cite must stay hollow, not credit")

    def test_bare_prose_no_cite_stays_hollow(self):
        # bare "no" with no file:line in either field stays hollow
        ws = _mkws({"src/Foo.sol": SRC,
                    ".auditooor/hunt_findings_sidecars/m.json":
                        _sidecar({"reasoning": "looks safe, no exploit"})})
        r = fcc.evaluate(ws)
        self.assertEqual(_cls(r)["bar"], "hollow",
                         "bare-prose 'no' with no file:line must stay hollow")


if __name__ == "__main__":
    unittest.main()
