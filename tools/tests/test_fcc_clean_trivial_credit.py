"""Guard: function-coverage-completeness Pass-1 must credit a STRUCTURED clean
terminal verdict (ruled-out / NEGATIVE / KILL) on a GENUINELY TRIVIAL one-line
body as real-attack - consistent with _row_has_terminal_evidence + the
morpho-midnight one-line-getter precedent. Before this fix Pass-1 unconditionally
downgraded every clean verdict to hollow (the near-intents step-3 false-red where
trivial accessors k/a/b/get_version stayed hollow despite source-verified KILLs).

NEVER-FALSE-PASS: a clean verdict on a NON-trivial body (control flow / guard /
>1 statement) MUST still be hollow (R80: prose is not coverage for code an
auditor must actually attack)."""
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

# tally: trivial one-line accessor with a NON-getter name (so it is NOT
# read-only-excluded; it stays in scope and must get clean-trivial credit).
# risky: non-trivial control-flow (line 4) -> must stay hollow.
SRC = (
    "pub struct S { x: u64 }\n"
    "impl S {\n"
    "  pub fn tally(&self) -> u64 { self.x }\n"
    "  pub fn risky(&self, a: u64) -> u64 {\n"
    "    if a > 0 { self.x } else { 0 }\n"
    "  }\n"
    "}\n"
)


def _mkws(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="fcc_ct_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def _cls(r):
    return {f["name"]: f["classification"] for f in r["functions"]}


def _sidecar(fn, line):
    return json.dumps({
        "function": fn, "file": "src/lib.rs", "line": line,
        "file_line": f"src/lib.rs:{line}", "source_refs": [f"src/lib.rs:{line}"],
        "verdict": "NEGATIVE", "in_scope": True,
        "code_excerpt": "self.x", "reason": "source-verified clean: pure accessor",
    })


class FccCleanTrivialCreditTest(unittest.TestCase):
    def test_clean_verdict_on_trivial_body_credits(self):
        ws = _mkws({
            "src/lib.rs": SRC,
            ".auditooor/hunt_findings_sidecars/getx.json": _sidecar("tally", 3),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_cls(r).get("tally"), "real-attack",
                         "clean NEGATIVE verdict on a trivial one-line accessor must credit")

    def test_clean_verdict_on_nontrivial_body_stays_hollow(self):
        # NEVER-FALSE-PASS: a clean verdict on a control-flow body is NOT coverage
        ws = _mkws({
            "src/lib.rs": SRC,
            ".auditooor/hunt_findings_sidecars/risky.json": _sidecar("risky", 4),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_cls(r).get("risky"), "hollow",
                         "clean verdict on a NON-trivial body must stay hollow (R80)")


if __name__ == "__main__":
    unittest.main()
