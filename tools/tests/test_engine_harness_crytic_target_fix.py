"""Guard test - engine-harness-crytic-target-fix repoints medusa target to the
property FILE (not ".") and adds echidna --foundry-compile-all, so crytic-compile
does not skip the test/ FuzzProps contract (the medusa/echidna engine-error +
DEEP_AUDIT_HOLLOW root cause; README #505)."""
from __future__ import annotations
import importlib.util, json, tempfile, types
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "engine-harness-crytic-target-fix.py"
_spec = importlib.util.spec_from_file_location("ehctf", _MOD)
m = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(m)


def _mk_harness(ws: Path, name: str, with_propfile: bool):
    h = ws / "poc-tests" / f"{name}-engine-harness"
    (h / "test").mkdir(parents=True)
    contract = f"{name}_FuzzProps"
    json.dump({"fuzzing": {"targetContracts": [contract]},
               "compilation": {"platform": "crytic-compile",
                               "platformConfig": {"target": ".", "solcVersion": ""}}},
              open(h / "medusa.json", "w"))
    (h / "echidna.yaml").write_text("testMode: assertion\ncryticArgs:\n  - --solc-remaps\n")
    if with_propfile:
        (h / "test" / f"{contract}.sol").write_text(f"contract {contract} {{}}\n")
    return h


class Test(__import__("unittest").TestCase):
    def test_repoints_target_and_adds_compile_all(self):
        ws = Path(tempfile.mkdtemp())
        h = _mk_harness(ws, "ApprovalFacet", with_propfile=True)
        res = m.run(ws)
        self.assertEqual(res["medusa_targets_fixed"], 1)
        self.assertEqual(res["echidna_compile_all_added"], 1)
        tgt = json.load(open(h / "medusa.json"))["compilation"]["platformConfig"]["target"]
        self.assertEqual(tgt, "test/ApprovalFacet_FuzzProps.sol")
        self.assertIn("--foundry-compile-all", (h / "echidna.yaml").read_text())

    def test_missing_propfile_left_unchanged(self):
        ws = Path(tempfile.mkdtemp())
        h = _mk_harness(ws, "Ghost", with_propfile=False)
        res = m.run(ws)
        self.assertEqual(res["medusa_targets_fixed"], 0)
        tgt = json.load(open(h / "medusa.json"))["compilation"]["platformConfig"]["target"]
        self.assertEqual(tgt, ".", "must NOT point target at a nonexistent file")

    def test_idempotent(self):
        ws = Path(tempfile.mkdtemp())
        _mk_harness(ws, "Conv", with_propfile=True)
        m.run(ws)
        res2 = m.run(ws)
        self.assertEqual(res2["medusa_targets_fixed"], 0, "second run is a no-op")


if __name__ == "__main__":
    __import__("unittest").main()
