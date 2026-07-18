#!/usr/bin/env python3
"""Focused semantic tests for inscope-manifest-validate.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
PRODUCER_PATH = TOOLS / "workspace-coverage-heatmap.py"
VALIDATOR_PATH = TOOLS / "inscope-manifest-validate.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PRODUCER = _load("inscope_manifest_producer_test", PRODUCER_PATH)
VALIDATOR = _load("inscope_manifest_validator_test", VALIDATOR_PATH)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _workspace(root: Path) -> Path:
    ws = root / "ws"
    _write(ws / "src" / "Vault.sol", "pragma solidity ^0.8.0; contract Vault { function deposit() external {} }\n")
    _write(ws / "src" / "client.js", "export function submit() { return true; }\n")
    _write(ws / "src" / "agent.aa", "{ messages: [ { app: 'payment', payload: {} } ] }\n")
    return ws


class TestInscopeManifestValidate(unittest.TestCase):
    def test_valid_nonempty_solidity_javascript_oscript_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            PRODUCER.write_inscope_manifest(ws)
            result = VALIDATOR.validate_manifest(ws)
            self.assertTrue(result["valid"], result["diagnostics"])
            rows = [json.loads(line) for line in (ws / ".auditooor" / "inscope_units.jsonl").read_text().splitlines()]
            self.assertTrue(rows)
            self.assertTrue({"solidity", "javascript", "oscript"}.issubset({row["lang"] for row in rows}))

    def test_rejects_malformed_empty_nonobject_stale_and_forged_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            manifest = ws / ".auditooor" / "inscope_units.jsonl"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("\nnot-json\n[]\n" + json.dumps({
                "file": "../outside.sol", "function": "x", "lang": "solidity"
            }) + "\n" + json.dumps({
                "file": "src/Vault.sol", "function": "deposit", "lang": "javascript"
            }) + "\n", encoding="utf-8")
            result = VALIDATOR.validate_manifest(ws)
            self.assertFalse(result["valid"])
            codes = {item["code"] for item in result["diagnostics"]}
            self.assertTrue({"EMPTY_ROW", "MALFORMED_JSON", "NON_OBJECT_ROW", "ESCAPING_OR_MISSING_FILE", "LANGUAGE_EXTENSION_MISMATCH", "EXPECTED_ROW_SET_MISMATCH"}.issubset(codes))

    def test_rejects_duplicate_identity_nondeterministic_order_and_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            PRODUCER.write_inscope_manifest(ws)
            manifest = ws / ".auditooor" / "inscope_units.jsonl"
            rows = [json.loads(line) for line in manifest.read_text().splitlines()]
            rows.append(dict(rows[0]))
            rows.reverse()
            rows.append({"function": "missing", "lang": "solidity"})
            manifest.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            result = VALIDATOR.validate_manifest(ws)
            codes = {item["code"] for item in result["diagnostics"]}
            self.assertIn("DUPLICATE_UNIT_IDENTITY", codes)
            self.assertIn("NONDETERMINISTIC_ORDER", codes)
            self.assertIn("MISSING_FILE", codes)

    def test_cli_is_machine_readable_and_does_not_rewrite(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            manifest, _, _ = PRODUCER.write_inscope_manifest(ws)
            before = manifest.read_bytes()
            proc = subprocess.run([sys.executable, str(VALIDATOR_PATH), "--workspace-path", str(ws)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["valid"])
            self.assertEqual(before, manifest.read_bytes())


if __name__ == "__main__":
    unittest.main()
