#!/usr/bin/env python3
"""Guard test: invariant-auto-synth consumes the real-incident invariant library.

Meta-audit finding: "invariant-auto-synth reads the 200+ real-incident
invariant library zero times". This test pins the wiring: the library loads,
is indexed by language, and category-matched real-incident invariants are
attached to a synthesized function record. Offline; temp dirs / inline JSONL.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-auto-synth.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("_invariant_auto_synth", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_LIB_RECORDS = [
    {"invariant_id": "INV-AUT-001", "category": "authorization",
     "statement": "admin-gated fn must verify caller", "target_lang": "solidity",
     "source_count": 20, "source_finding_ids": ["x"]},
    {"invariant_id": "INV-CON-001", "category": "conservation",
     "statement": "sum of balances preserved", "target_lang": "solidity",
     "source_count": 9, "source_finding_ids": ["y"]},
    {"invariant_id": "INV-ANY-001", "category": "bounds",
     "statement": "amount must be > 0", "target_lang": "any",
     "source_count": 3, "source_finding_ids": ["z"]},
]


class TestIncidentLibraryWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    def _write_lib(self, td: str) -> Path:
        p = Path(td) / "lib.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in _LIB_RECORDS), encoding="utf-8")
        return p

    def test_library_loads_indexed_by_language(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            lib = self.mod.load_incident_library(self._write_lib(td))
        self.assertIn("solidity", lib)
        self.assertIn("any", lib)
        self.assertEqual(len(lib["solidity"]), 2)
        # highest source_count first
        self.assertEqual(lib["solidity"][0]["invariant_id"], "INV-AUT-001")

    def test_category_match_attaches_real_incident_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            lib = self.mod.load_incident_library(self._write_lib(td))
            cands = ["INV-foo-access-control-missing: verify role/auth by-design"]
            attached = self.mod.incident_invariants_for(cands, "solidity", lib)
        ids = {a["invariant_id"] for a in attached}
        self.assertIn("INV-AUT-001", ids,
                      "authorization candidate pulls the authorization incident invariant")

    def test_empty_library_is_honest_zero(self) -> None:
        attached = self.mod.incident_invariants_for(["INV-foo-x"], "solidity", {})
        self.assertEqual(attached, [])

    def test_end_to_end_attaches_to_synth_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            lib_path = self._write_lib(td)
            src = tdp / "C.sol"
            src.write_text(
                "contract C {\n"
                "  function increment() public { count += 1; }\n"
                "}\n",
                encoding="utf-8",
            )
            out = tdp / "out.jsonl"
            rc = self.mod.main([
                "--workspace", str(tdp),
                "--src-glob", "*.sol",
                "--output", str(out),
                "--incident-library", str(lib_path),
            ])
            self.assertEqual(rc, 0)
            recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        self.assertTrue(recs, "at least one function record emitted")
        self.assertTrue(
            any(r.get("incident_invariants") for r in recs),
            "at least one record carries real-incident invariants (library consumed)",
        )


if __name__ == "__main__":
    unittest.main()
