#!/usr/bin/env python3
"""Guard tests for the coverage-map per-language completeness fix in
workspace-coverage-heatmap.py (Obyte 2026-07-09 false-green).

Two defects are pinned:

1. REGISTRY-DRIVEN CLASSIFIER: the coverage denominator must count EVERY
   recognized source language from the canonical registry
   (tools/lib/source_extensions.py) - Oscript `.oscript`/`.aa`, Clarity,
   Circom, ... - not just the historical Solidity-plus-a-few list. Before the
   fix, Obyte's 382 Oscript AA units read 0 in coverage_report.json while
   inscope_units.jsonl carried them (63% of scope invisible). Solidity-only
   workspaces must classify IDENTICALLY (no regression).

2. FAIL-LOUD BACKSTOP: when a whole in-scope language is present in
   inscope_units.jsonl (>0 units) but the coverage report classified ZERO
   units of it, that is the false-green - the tool must FAIL LOUD (advisory
   WARN by default; BLOCK under AUDITOOOR_COVERAGE_COMPLETENESS_STRICT), never
   silently pass."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "hm_completeness", ROOT / "tools" / "workspace-coverage-heatmap.py"
)
hm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hm)  # type: ignore[union-attr]

_OSCRIPT = '{ "messages": [ { "app": "payment" } ] }\n'
_SOL = "// SPDX\npragma solidity ^0.8;\ncontract C {{ function {n}() public {{}} }}\n"
_CLAR = "(define-public (transfer) (ok true))\n"


def _ws(files: dict[str, str]) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="cov_complete_"))
    for rel, content in files.items():
        p = ws / "src" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return ws


def _write_manifest(ws: Path, rows: list[dict]) -> None:
    p = ws / ".auditooor" / "inscope_units.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


class TestRegistryDrivenClassifier(unittest.TestCase):
    def test_oscript_and_registry_langs_enumerated(self):
        """Oscript (.oscript/.aa) and other registry languages are counted at
        file granularity (0 -> N), not silently dropped like before."""
        ws = _ws({
            "aa/city-lib.oscript": _OSCRIPT,
            "aa/agent.aa": _OSCRIPT,
            "stx/pool.clar": _CLAR,
            "evm/Vault.sol": _SOL.format(n="deposit"),
        })
        units, detail = hm.enumerate_units(ws)
        langs = detail.get("languages") or {}
        # every registry language present is classified (>0), not just .sol
        self.assertGreater(langs.get(".oscript", 0), 0, langs)
        self.assertGreater(langs.get(".aa", 0), 0, langs)
        self.assertGreater(langs.get(".clar", 0), 0, langs)
        self.assertGreater(langs.get(".sol", 0), 0, langs)
        bases = {u.split("::")[0].split("--")[0] for u in units}
        self.assertIn("city-lib.oscript", bases)
        self.assertIn("agent.aa", bases)
        self.assertIn("pool.clar", bases)

    def test_solidity_only_no_regression(self):
        """A Solidity-only workspace classifies IDENTICALLY - the new registry
        extensions add no keys and change no counts when no such files exist."""
        ws = _ws({
            "A.sol": _SOL.format(n="foo"),
            "sub/B.sol": _SOL.format(n="bar"),
        })
        units, detail = hm.enumerate_units(ws)
        langs = detail.get("languages") or {}
        self.assertEqual(set(langs.keys()), {".sol"}, langs)
        self.assertEqual(langs[".sol"], 2, langs)
        # exactly the two Solidity functions, nothing else
        self.assertEqual(len(units), 2, sorted(units))


class TestCompletenessBackstop(unittest.TestCase):
    def _report(self, ext_langs: dict[str, int], total: int) -> dict:
        return {"enumeration": {"languages": ext_langs}, "total_units": total}

    def test_dropped_language_warns(self):
        ws = _ws({"evm/V.sol": _SOL.format(n="d")})
        _write_manifest(ws, [
            {"file": "src/aa/x.oscript", "function": "m", "lang": "oscript"},
            {"file": "src/aa/y.oscript", "function": "n", "lang": "oscript"},
            {"file": "src/evm/V.sol", "function": "d", "lang": "solidity"},
        ])
        # coverage classified ONLY .sol - oscript whole language dropped
        report = self._report({".sol": 1}, 1)
        os.environ.pop("AUDITOOOR_COVERAGE_COMPLETENESS_STRICT", None)
        res = hm.check_coverage_completeness_vs_manifest(ws, report)
        self.assertTrue(res["checked"])
        self.assertTrue(res["material_undercount"])
        self.assertEqual(res["dropped_languages"], {"oscript": 2})
        self.assertEqual(res["status"], "warn")

    def test_dropped_language_blocks_under_strict(self):
        ws = _ws({"evm/V.sol": _SOL.format(n="d")})
        _write_manifest(ws, [
            {"file": "src/aa/x.oscript", "function": "m", "lang": "oscript"},
            {"file": "src/evm/V.sol", "function": "d", "lang": "solidity"},
        ])
        report = self._report({".sol": 1}, 1)
        os.environ["AUDITOOOR_COVERAGE_COMPLETENESS_STRICT"] = "1"
        try:
            res = hm.check_coverage_completeness_vs_manifest(ws, report)
        finally:
            os.environ.pop("AUDITOOOR_COVERAGE_COMPLETENESS_STRICT", None)
        self.assertEqual(res["status"], "block")
        self.assertTrue(res["strict"])
        self.assertEqual(res["dropped_languages"], {"oscript": 1})

    def test_no_drop_when_language_present(self):
        """The file-vs-function granularity gap (382 manifest fns vs 40 file
        units) must NOT false-fire: oscript present in coverage (>0) is OK."""
        ws = _ws({"evm/V.sol": _SOL.format(n="d")})
        _write_manifest(ws, [
            {"file": "src/aa/x.oscript", "function": "m", "lang": "oscript"},
            {"file": "src/aa/x.oscript", "function": "n", "lang": "oscript"},
            {"file": "src/aa/x.oscript", "function": "o", "lang": "oscript"},
            {"file": "src/evm/V.sol", "function": "d", "lang": "solidity"},
        ])
        # coverage classified BOTH languages (oscript only 1 FILE vs 3 manifest fns)
        report = self._report({".sol": 1, ".oscript": 1}, 2)
        res = hm.check_coverage_completeness_vs_manifest(ws, report)
        self.assertFalse(res["material_undercount"])
        self.assertEqual(res["dropped_languages"], {})
        self.assertEqual(res["status"], "ok")

    def test_fail_open_when_no_manifest(self):
        ws = _ws({"evm/V.sol": _SOL.format(n="d")})
        report = self._report({".sol": 1}, 1)
        res = hm.check_coverage_completeness_vs_manifest(ws, report)
        self.assertFalse(res["checked"])
        self.assertEqual(res["status"], "ok")

    def test_lang_derived_from_extension_when_lang_field_absent(self):
        """A manifest row with no ``lang`` field derives it from the file
        extension via the registry, so the backstop still fires."""
        ws = _ws({"evm/V.sol": _SOL.format(n="d")})
        _write_manifest(ws, [
            {"file": "src/aa/x.oscript", "function": "m"},  # no lang field
            {"file": "src/evm/V.sol", "function": "d"},
        ])
        report = self._report({".sol": 1}, 1)
        os.environ.pop("AUDITOOOR_COVERAGE_COMPLETENESS_STRICT", None)
        res = hm.check_coverage_completeness_vs_manifest(ws, report)
        self.assertEqual(res["dropped_languages"], {"oscript": 1})


class TestBuildReportIntegration(unittest.TestCase):
    def test_build_report_counts_oscript_and_attaches_backstop(self):
        ws = _ws({
            "aa/lib.oscript": _OSCRIPT,
            "evm/V.sol": _SOL.format(n="deposit"),
        })
        _write_manifest(ws, [
            {"file": "src/aa/lib.oscript", "function": "messages", "lang": "oscript"},
            {"file": "src/evm/V.sol", "function": "deposit", "lang": "solidity"},
        ])
        report = hm.build_coverage_report(ws)
        langs = report["enumeration"]["languages"]
        self.assertGreater(langs.get(".oscript", 0), 0, langs)
        backstop = report.get("coverage_completeness_backstop")
        self.assertIsInstance(backstop, dict)
        self.assertTrue(backstop["checked"])
        # both manifest languages classified -> no false-green
        self.assertEqual(backstop["dropped_languages"], {})
        self.assertEqual(backstop["status"], "ok")


if __name__ == "__main__":
    unittest.main()
