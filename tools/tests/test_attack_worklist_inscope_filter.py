#!/usr/bin/env python3
"""Guard: the per-function attack worklist honors the in-scope manifest
(.auditooor/inscope_units.jsonl) and the belt-and-suspenders EXCLUDE_* guards,
so the audit's OWN chimera harnesses + *Mutant*.sol contracts (SSV: ~43/265
inflated rows) do NOT pollute the worklist, while real in-scope production rows
are kept. Manifest-absent => no filtering (legacy behavior preserved)."""
import importlib.util, sys, json, tempfile, os, unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "pfaw", str(Path(__file__).resolve().parent.parent / "per-function-attack-worklist.py"))
m = importlib.util.module_from_spec(_spec); sys.modules["pfaw"] = m; _spec.loader.exec_module(m)

_PROD = """// SPDX
contract Vault {
    function deposit(uint256 amount) external { }
}
"""
# A chimera/Echidna harness + a mutant: both are the audit's OWN artifacts.
_HARNESS = """// SPDX
contract VaultEchidnaHarness {
    function fuzz_invariant() public { }
}
"""
_MUTANT = """// SPDX
contract VaultMutant {
    function deposit(uint256 amount) external { }
}
"""


def _mkws():
    ws = Path(tempfile.mkdtemp())
    src = ws / "src"; src.mkdir(parents=True)
    (src / "Vault.sol").write_text(_PROD)
    cm = src / "chimera_harnesses"; cm.mkdir()
    (cm / "VaultEchidnaHarness.sol").write_text(_HARNESS)
    (src / "VaultMutant.sol").write_text(_MUTANT)
    (ws / ".auditooor").mkdir(parents=True)
    return ws


class T(unittest.TestCase):
    def setUp(self):
        # Make sure the opt-out env is not leaking from a prior run.
        os.environ.pop("AUDITOOOR_ATTACK_WORKLIST_NO_INSCOPE", None)

    def test_excludes_chimera_and_mutant_keeps_inscope(self):
        ws = _mkws()
        # Manifest lists ONLY the real production file.
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Vault.sol"}) + "\n")
        rows = m.build_worklist(ws)
        files = {r.file_line.split(":")[0] for r in rows}
        fns = {r.function for r in rows}
        self.assertIn("src/Vault.sol", files)       # in-scope production kept
        self.assertIn("deposit", fns)
        # Chimera harness + Mutant excluded (both manifest-OOS AND name/path guards).
        self.assertNotIn("fuzz_invariant", fns)
        self.assertFalse(any("chimera_harnesses" in f for f in files))
        self.assertFalse(any("VaultMutant" in f for f in files))

    def test_belt_and_suspenders_no_manifest(self):
        # No inscope_units.jsonl => fall through to EXCLUDE_* guards only.
        ws = _mkws()
        rows = m.build_worklist(ws)
        files = {r.file_line.split(":")[0] for r in rows}
        fns = {r.function for r in rows}
        self.assertIn("deposit", fns)                # production still discovered
        self.assertIn("src/Vault.sol", files)
        # Even WITHOUT a manifest, the name/path EXCLUDE guards drop these.
        self.assertNotIn("fuzz_invariant", fns)
        self.assertFalse(any("chimera_harnesses" in f for f in files))
        self.assertFalse(any("VaultMutant" in f for f in files))

    def test_env_optout_disables_inscope_filter(self):
        ws = _mkws()
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Vault.sol"}) + "\n")
        os.environ["AUDITOOOR_ATTACK_WORKLIST_NO_INSCOPE"] = "1"
        try:
            self.assertIsNone(m._load_inscope_file_set(ws))
        finally:
            os.environ.pop("AUDITOOOR_ATTACK_WORKLIST_NO_INSCOPE", None)

    def test_loader_returns_none_when_absent(self):
        ws = Path(tempfile.mkdtemp())
        self.assertIsNone(m._load_inscope_file_set(ws))


if __name__ == "__main__":
    unittest.main()
