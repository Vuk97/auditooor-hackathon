#!/usr/bin/env python3
"""test_native_suite_r21_r27.py

Enforcement-gap R21/R27 (2026-07-03): a Go/Rust workspace whose CORE native test
suite FAILS still greened `make audit-complete STRICT=1` - no gate parsed cargo/go
test results into a required finding. Closed by a PRODUCER (native-suite-run.py:
parse go/cargo test json -> native_suite_result.json) + an advisory-first READER
(native-suite-result-check.py, wired into audit-done-guard.py under
AUDITOOOR_DONE_NATIVE_SUITE_STRICT). This pins: the parsers count pass/fail/skip,
the reader FLAGs a failing suite, and PRODUCER-CONDITIONAL fail-open means an
absent/skipped artifact never false-red's a non-Go/Rust ws.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_PRODUCER = _TOOLS / "native-suite-run.py"
_READER = _TOOLS / "native-suite-result-check.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def _ws_with_artifact(obj):
    d = Path(tempfile.mkdtemp())
    (d / ".auditooor").mkdir()
    (d / ".auditooor" / "native_suite_result.json").write_text(json.dumps(obj), encoding="utf-8")
    return d


_GO_TRANSCRIPT = "\n".join([
    json.dumps({"Action": "pass", "Package": "x/core", "Test": "TestA"}),
    json.dumps({"Action": "fail", "Package": "x/core", "Test": "TestB"}),
    json.dumps({"Action": "skip", "Package": "x/util", "Test": "TestC"}),
    json.dumps({"Action": "pass", "Package": "x/core"}),  # pkg-level summary, ignored
])

_CARGO_TRANSCRIPT = "\n".join([
    json.dumps({"type": "test", "event": "ok", "name": "mod::test_a"}),
    json.dumps({"type": "test", "event": "failed", "name": "mod::test_b"}),
    json.dumps({"type": "test", "event": "ignored", "name": "mod::test_c"}),
    json.dumps({"type": "suite", "event": "failed"}),  # non-test event, ignored
])


class TestProducerParsers(unittest.TestCase):
    def setUp(self):
        self.m = _load("native_suite_run", _PRODUCER)

    def test_go_parser_counts(self):
        r = self.m.parse_go_transcript(_GO_TRANSCRIPT)
        self.assertEqual(r["total_passed"], 1)
        self.assertEqual(r["total_failed"], 1)
        self.assertEqual(r["total_skipped"], 1)
        self.assertIn("x/core::TestB", r["failing"])

    def test_cargo_parser_counts(self):
        r = self.m.parse_cargo_transcript(_CARGO_TRANSCRIPT)
        self.assertEqual(r["total_passed"], 1)
        self.assertEqual(r["total_failed"], 1)
        self.assertEqual(r["total_skipped"], 1)
        self.assertIn("crate::mod::test_b", r["failing"])

    def test_go_plaintext_parser_counts(self):
        # what the existing engine-runner logs actually contain (no -json)
        txt = "\n".join([
            "--- PASS: TestA (0.01s)",
            "--- FAIL: TestB (0.02s)",
            "--- SKIP: TestC (0.00s)",
            "FAIL\tx/core\t0.4s",
        ])
        r = self.m.parse_go_plaintext(txt)
        self.assertEqual(r["total_passed"], 1)
        self.assertEqual(r["total_failed"], 1)
        self.assertEqual(r["total_skipped"], 1)

    def test_cargo_plaintext_parser_counts(self):
        txt = "\n".join([
            "test mod::test_a ... ok",
            "test mod::test_b ... FAILED",
            "test mod::test_c ... ignored",
            "test result: FAILED. 1 passed; 1 failed; 1 ignored;",
        ])
        r = self.m.parse_cargo_plaintext(txt)
        self.assertEqual(r["total_passed"], 1)
        self.assertEqual(r["total_failed"], 1)
        self.assertEqual(r["total_skipped"], 1)
        self.assertIn("crate::mod::test_b", r["failing"])

    def test_auto_detect_dispatches(self):
        # json transcript -> json parser; plain -> plaintext parser, same failing set
        self.assertEqual(self.m.parse_transcript(_GO_TRANSCRIPT, "go")["total_failed"], 1)
        self.assertEqual(
            self.m.parse_transcript("--- FAIL: TestX (0s)\nFAIL\tx/y\t0s", "go")["total_failed"], 1)

    def test_run_live_non_go_rust_is_skipped(self):
        # empty ws: no go.mod / Cargo.toml -> lang none, status skipped (fail-open)
        r = self.m.run_live(Path(tempfile.mkdtemp()))
        self.assertEqual(r["lang"], "none")
        self.assertEqual(r["status"], "skipped")

    def test_parse_transcript_cli_writes_artifact(self):
        td = Path(tempfile.mkdtemp())
        tf = td / "go.json"
        tf.write_text(_GO_TRANSCRIPT, encoding="utf-8")
        out = td / "result.json"
        rc = self.m.main(["--parse-transcript", str(tf), "--lang", "go", "--out", str(out)])
        self.assertEqual(rc, 0)
        obj = json.loads(out.read_text())
        self.assertEqual(obj["total_failed"], 1)


class TestReaderVerdicts(unittest.TestCase):
    def setUp(self):
        self.m = _load("native_suite_result_check", _READER)

    def test_failing_suite_flags(self):
        ws = _ws_with_artifact({"schema": "auditooor.native_suite_result.v1", "lang": "go",
                                "status": "ran", "total_passed": 3, "total_failed": 2,
                                "failing": ["x/core::TestB", "x/core::TestD"]})
        self.assertEqual(self.m.check(ws)["verdict"], "FLAG")

    def test_clean_suite_passes(self):
        ws = _ws_with_artifact({"lang": "go", "status": "ran", "total_passed": 10, "total_failed": 0,
                                "failing": []})
        self.assertEqual(self.m.check(ws)["verdict"], "pass")

    def test_skipped_suite_passes(self):
        ws = _ws_with_artifact({"lang": "none", "status": "skipped", "total_failed": 0, "failing": []})
        self.assertEqual(self.m.check(ws)["verdict"], "pass")

    def test_absent_artifact_passes(self):
        # PRODUCER-CONDITIONAL: no artifact -> pass (never false-red a ws w/o a captured suite)
        self.assertEqual(self.m.check(Path(tempfile.mkdtemp()))["verdict"], "pass")

    def test_strict_env_rc1_on_flag(self):
        ws = _ws_with_artifact({"lang": "rust", "status": "ran", "total_failed": 1,
                                "failing": ["crate::mod::test_b"]})
        env = dict(os.environ, AUDITOOOR_NATIVE_SUITE_STRICT="1")
        r = subprocess.run([sys.executable, str(_READER), str(ws), "--json"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1)

    def test_default_env_rc0_on_flag(self):
        ws = _ws_with_artifact({"lang": "rust", "status": "ran", "total_failed": 1,
                                "failing": ["crate::mod::test_b"]})
        env = {k: v for k, v in os.environ.items() if k != "AUDITOOOR_NATIVE_SUITE_STRICT"}
        r = subprocess.run([sys.executable, str(_READER), str(ws), "--json"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)  # advisory by default


class TestDoneGuardWiring(unittest.TestCase):
    def test_reader_wired_into_done_guard(self):
        src = (_TOOLS / "audit-done-guard.py").read_text(encoding="utf-8", errors="replace")
        self.assertIn("native-suite-result-check.py", src)
        self.assertIn("native_suite_advisory", src)
        self.assertIn("AUDITOOOR_DONE_NATIVE_SUITE_STRICT", src)
        self.assertIn("native-suite-failing-tests", src)


if __name__ == "__main__":
    unittest.main()
