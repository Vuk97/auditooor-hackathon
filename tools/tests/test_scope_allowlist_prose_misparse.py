#!/usr/bin/env python3
"""Regression: a PROSE SCOPE.md must not empty the coverage denominator.

SEI 2026-07-04: a whole-repo Primacy-of-Impact SCOPE.md (repos listed, no per-file
enumeration) mis-parsed vuln-class prose ("Crash/halt of >= 1/3 validators",
"tx-fee-calculation manipulation outside protocol-defined bounds") into
in_scope_paths tokens that pass _scope_token_is_path_like (they contain '/' or
'-') yet match ZERO real source files. The per-file coverage consumer has no batch
fail-safe, so this spurious allowlist dropped the ENTIRE in-scope Go tree from the
coverage denominator (SEI: 0 of 2949 .go admitted; total_units collapsed to 5 OOS
Rust examples). Fix: _load_scope_md_allowlist grounds the allowlist against the
authoritative intake enumeration (inscope_units.jsonl); an allowlist admitting
NONE of the real in-scope files is treated as absent (whole-repo scope).
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "workspace-coverage-heatmap.py"
_s = importlib.util.spec_from_file_location("workspace_coverage_heatmap", _T)
hm = importlib.util.module_from_spec(_s)
_s.loader.exec_module(hm)


def _write_inscope(ws: Path, files: list[str]) -> None:
    ad = ws / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    with (ad / "inscope_units.jsonl").open("w", encoding="utf-8") as fh:
        for f in files:
            fh.write(json.dumps({"file": f, "unit_id": f + "::Fn"}) + "\n")


class InscopeUnitsSampleTest(unittest.TestCase):
    def test_reads_distinct_paths(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_inscope(ws, ["src/a.go", "src/a.go", "src/b.go", "src/c.sol"])
            got = hm._inscope_units_sample_paths(ws, limit=100)
            self.assertEqual(sorted(got), ["src/a.go", "src/b.go", "src/c.sol"])

    def test_absent_manifest_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(hm._inscope_units_sample_paths(Path(td)), [])

    def test_limit_respected(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_inscope(ws, [f"src/f{i}.go" for i in range(50)])
            self.assertEqual(len(hm._inscope_units_sample_paths(ws, limit=10)), 10)


class ProseMisparseGroundOutTest(unittest.TestCase):
    # A prose SCOPE.md that reproduces the SEI mis-parse: vuln-class sentences whose
    # words ('Crash/halt', 'tx-fee-calculation') are the ONLY path-like tokens the
    # parser can harvest - none of which match a real .go file.
    PROSE_SCOPE = """# Prose Program Scope

## Codebases (Assets In Scope)
| Repo | Local name |
|------|-----------|
| https://github.com/acme/chain | chain |

## In-Scope Vulnerability Classes
- **Critical**: Permanent freezing of funds with no on-chain remediation.
- **High**: Crash/halt of >= 1/3 validators -> loss of liveness.
- **Low**: tx-fee-calculation manipulation outside protocol-defined bounds.
"""

    def _mk_ws(self, td: str, scope_text: str, inscope: list[str]) -> Path:
        ws = Path(td)
        (ws / "SCOPE.md").write_text(scope_text, encoding="utf-8")
        _write_inscope(ws, inscope)
        return ws

    def test_prose_scope_with_go_inscope_grounds_out(self):
        # The whole in-scope tree is .go; a prose allowlist admitting none of them
        # MUST be treated as absent so the coverage denominator is not emptied.
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_ws(td, self.PROSE_SCOPE,
                             ["src/chain/x/evm/keeper/keeper.go",
                              "src/chain/x/bank/keeper.go"])
            mf, smp = hm._load_scope_md_allowlist(ws)
            self.assertIsNone(mf, "a prose allowlist matching 0 real .go files must be absent")
            self.assertIsNone(smp)

    def test_no_inscope_manifest_does_not_ground_out(self):
        # Never-under-scope on the EMISSION path: when inscope_units.jsonl is absent
        # the grounding check is skipped (the emitter has its own batch fail-safe).
        # We only assert the call does not crash and returns a 2-tuple.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "SCOPE.md").write_text(self.PROSE_SCOPE, encoding="utf-8")
            res = hm._load_scope_md_allowlist(ws)
            self.assertEqual(len(res), 2)


if __name__ == "__main__":
    unittest.main()
