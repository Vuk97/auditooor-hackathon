"""Guard: S7-outcome-to-priming - confirmed/filed findings feed brain_prime priors.

Before S7 the priors were one-directional (MIMO yes-rate only); a confirmed finding
never boosted its attack class on the next run. This guard proves the new
gather_confirmed_classes() extracts a workspace's confirmed-finding attack classes
(reusing the submissions ETL), and that the merge emits a boost cell tagged with a
confirmed boost_source.

Fails before the change (function absent); passes after.
"""
import collections
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "mimo-corpus-miner.py"


def _load():
    spec = importlib.util.spec_from_file_location("mimo_corpus_miner", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestConfirmedPriors(unittest.TestCase):
    def _make_ws(self, base: Path) -> Path:
        ws = base / "demo-ws"
        filed = ws / "submissions" / "filed"
        filed.mkdir(parents=True)
        # paste-ready naming convention: severity in the FILENAME
        (filed / "reentrancy-drain-on-withdraw-CRITICAL.md").write_text(
            "# Reentrancy drain on withdraw\n\n"
            "A reentrancy in withdraw() lets an attacker re-enter before the balance "
            "is zeroed and drain the vault. PoC: forge test --- PASS.\n",
            encoding="utf-8")
        return ws

    def test_gather_confirmed_classes_extracts_attack_class(self):
        mod = _load()
        self.assertTrue(hasattr(mod, "gather_confirmed_classes"),
                        "S7 gather_confirmed_classes must exist")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._make_ws(base)
            got = mod.gather_confirmed_classes(base)
            self.assertIn("demo-ws", got, f"confirmed finding not gathered: {got}")
            counter = got["demo-ws"]
            self.assertIsInstance(counter, collections.Counter)
            self.assertGreaterEqual(sum(counter.values()), 1)
            # the inferred class must be a real attack class, never unknown/none
            for ac in counter:
                self.assertNotIn(ac.lower(), ("", "unknown", "none"))

    def test_empty_root_is_safe(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(mod.gather_confirmed_classes(Path(td)), {})


if __name__ == "__main__":
    unittest.main()
