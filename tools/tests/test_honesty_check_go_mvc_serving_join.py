"""Loop-fix 2026-07-04 (nuva hollow-engines serving-join false-red).

audit-honesty-check's Go arm computed real_execution ONLY from go_engine_runs
(fuzz_runs/*/manifest.json filtered to engine=go/staticcheck/govulncheck with a
pass/ok status + positive count) OR _nonevm_engine_genuinely_executed (a fuzz_runs
positive-count non-EVM manifest). It NEVER consulted _mutation_verified_cut_harnesses,
the same un-fakeable mutation ground truth the Solidity arm already folds into
real_execution (via real_inscope + _mutation_verified_cut_harnesses).

Effect on nuva (lang=go, Cosmos vault): 26 genuine mutation-verified CUT harnesses on
disk, incl. Go economic_invariant_test.go / reconcile_test.go / xfn_state_test.go that
killed behaviour-changing mutants over src/vault/keeper/*.go, but the only Go fuzz_runs
manifests were failed medusa (EVM) runs. real_execution stayed False -> fail-hollow-engines
-> fail-hollow-not-genuinely-audited, even though genuine deep Go engine execution existed.
Same serving-join delivery bug as test_honesty_check_cluster_sidecar (Solidity) and the
core-coverage / engine-harness-proof cluster-sidecar fixes.

Fix: the Go arm (and the peer Rust arm) credit _mutation_verified_cut_harnesses(ws) into
real_execution. False-green-safe: the helper requires baseline PASS + >=1 behaviour-
changing kill + a real on-disk CUT/harness file, and rejects drifted/vacuous sidecars, so
a vacuous (0-kill) sidecar or one whose CUT paths are absent from disk credits nothing.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("ah_go_sj", str(_TOOLS / "audit-honesty-check.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ah_go_sj"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestHonestyCheckGoMvcServingJoin(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()
        # Real on-disk Go CUT + harness so the helper's on-disk-file requirement is met.
        (self.ws / "src" / "vault" / "keeper").mkdir(parents=True)
        (self.ws / "src" / "vault" / "keeper" / "vault.go").write_text("package keeper\n")
        (self.ws / "src" / "vault" / "keeper" / "economic_invariant_test.go").write_text(
            "package keeper\n"
        )
        (self.ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)

    def _write(self, name, payload):
        (self.ws / ".auditooor" / "mvc_sidecar" / name).write_text(json.dumps(payload))

    def _genuine_go_sidecar(self):
        return {
            "function": "SwapIn",
            "language": "go",
            "mutation_verified": True,
            "verdict": "non-vacuous",
            "mutants_killed": 1,
            "harness_path": "src/vault/keeper/economic_invariant_test.go",
            "source_file": "src/vault/keeper/vault.go",
        }

    def test_go_real_execution_credited_from_genuine_mvc_sidecar(self):
        """A genuine mutation-verified Go CUT harness flips real_execution True for lang=go
        even with zero fuzz_runs Go engine manifests (the nuva serving-join case)."""
        self._write("go_vault_economic_invariant.json", self._genuine_go_sidecar())
        eng = self.m._engine_reality(self.ws, "go")
        self.assertTrue(eng["real_execution"], eng)
        self.assertTrue(eng.get("mutation_verified_cut_harnesses"), eng)

    def test_rust_real_execution_credited_from_genuine_mvc_sidecar(self):
        """Peer arm: the Rust arm credits the same un-fakeable ground truth."""
        self._write("go_vault_economic_invariant.json", self._genuine_go_sidecar())
        eng = self.m._engine_reality(self.ws, "rust")
        self.assertTrue(eng["real_execution"], eng)

    def test_go_vacuous_sidecar_not_credited(self):
        """False-green-safe: a 0-kill sidecar credits nothing (stays hollow)."""
        vac = self._genuine_go_sidecar()
        vac["mutants_killed"] = 0
        vac["verdict"] = "vacuous"
        self._write("vac.json", vac)
        eng = self.m._engine_reality(self.ws, "go")
        self.assertFalse(eng["real_execution"], eng)

    def test_go_kill_but_missing_cut_file_not_credited(self):
        """False-green-safe: a genuine kill whose CUT/harness paths are absent from disk
        credits nothing (a bare marker cannot flip real_execution)."""
        ghost = self._genuine_go_sidecar()
        ghost["harness_path"] = "src/vault/keeper/nope_test.go"
        ghost["source_file"] = "src/vault/keeper/nope.go"
        self._write("ghost.json", ghost)
        eng = self.m._engine_reality(self.ws, "go")
        self.assertFalse(eng["real_execution"], eng)


if __name__ == "__main__":
    unittest.main(verbosity=2)
