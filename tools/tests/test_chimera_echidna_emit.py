#!/usr/bin/env python3
# <!-- r36-rebuttal: lane CHIMERA-ECHIDNA-EMIT registered in commit message -->
"""NUVA 2026-06-30: chimera harnesses shipped medusa.json + forge invariant but
NO echidna.yaml (chimera-scaffold is display-only), so README Step-2c's echidna
engine never ran on the real CUT. chimera-echidna-emit materializes a runnable
assertion-mode echidna.yaml per harness targeting the *Handler. Pins: writes for
a harness with a Handler, skips Mutant-only dirs, idempotent, never touches .sol.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "chimera-echidna-emit.py"


def _load():
    spec = importlib.util.spec_from_file_location("cee", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cee"] = m
    spec.loader.exec_module(m)
    return m


cee = _load()


def _mk(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cee_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class ChimeraEchidnaEmitTest(unittest.TestCase):
    def test_emits_for_handler_and_skips_mutant(self):
        ws = _mk({
            "chimera_harnesses/Foo/test/FooHandler.sol": "contract FooHandler {}\n",
            "chimera_harnesses/Foo/test/FooMutantHandler.sol": "contract FooMutantHandler {}\n",
            "chimera_harnesses/Bar/test/BarHandler.sol": "contract BarHandler {}\n",
        })
        r = cee.emit(ws, test_limit=1_000_000, seq_len=50, force=False)
        written = {w["harness"]: w["contract"] for w in r["written"]}
        self.assertEqual(written, {"Foo": "FooHandler", "Bar": "BarHandler"},
                         "one echidna.yaml per harness, targeting the non-Mutant Handler")
        cfg = (ws / "chimera_harnesses/Foo/echidna.yaml").read_text()
        self.assertIn("testMode: assertion", cfg)
        self.assertIn("--foundry-compile-all", cfg)
        self.assertIn("testLimit: 1000000", cfg)

    def test_idempotent_skip_existing_assertion_config(self):
        ws = _mk({"chimera_harnesses/Foo/test/FooHandler.sol": "contract FooHandler {}\n"})
        cee.emit(ws, 1_000_000, 50, force=False)
        r2 = cee.emit(ws, 1_000_000, 50, force=False)
        self.assertIn("Foo", r2["skipped"])
        self.assertEqual(r2["written"], [])

    def test_force_overwrites(self):
        ws = _mk({"chimera_harnesses/Foo/test/FooHandler.sol": "contract FooHandler {}\n"})
        cee.emit(ws, 1_000_000, 50, force=False)
        r2 = cee.emit(ws, 500_000, 50, force=True)
        self.assertEqual([w["harness"] for w in r2["written"]], ["Foo"])
        self.assertIn("testLimit: 500000", (ws / "chimera_harnesses/Foo/echidna.yaml").read_text())

    def test_no_handler_dir_reported_not_written(self):
        ws = _mk({"chimera_harnesses/Empty/README.md": "no handler here\n"})
        r = cee.emit(ws, 1_000_000, 50, force=False)
        self.assertIn("Empty", r["no_handler"])
        self.assertEqual(r["written"], [])

    def test_never_touches_sol(self):
        ws = _mk({"chimera_harnesses/Foo/test/FooHandler.sol": "contract FooHandler {}\n"})
        before = (ws / "chimera_harnesses/Foo/test/FooHandler.sol").read_text()
        cee.emit(ws, 1_000_000, 50, force=False)
        self.assertEqual((ws / "chimera_harnesses/Foo/test/FooHandler.sol").read_text(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
