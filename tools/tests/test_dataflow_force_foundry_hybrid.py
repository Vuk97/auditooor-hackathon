#!/usr/bin/env python3
# <!-- r36-rebuttal: lane DATAFLOW-FORCE-FOUNDRY-HYBRID registered in commit message -->
"""dataflow-slice Tier-3 must force the foundry framework on a hybrid project.

Strata 2026-06-30 R1b: src/contracts had foundry.toml + hardhat.config.js + node_modules;
crytic-compile auto-detection picked HARDHAT (28min hang -> 0 output, capability dark).
forge build compiles the same 122 contracts in ~60s. Pin: when a foundry.toml is present
at the project root, load_slither_offline passes compile_force_framework='foundry'.
"""
import importlib.util, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

_T = Path(__file__).resolve().parent.parent / "dataflow-slice.py"
_s = importlib.util.spec_from_file_location("dfslice", _T)
df = importlib.util.module_from_spec(_s); sys.modules["dfslice"] = df; _s.loader.exec_module(df)


class ForceFoundryHybridTest(unittest.TestCase):
    def test_foundry_forced_when_foundry_toml_present(self):
        root = Path(tempfile.mkdtemp())
        (root / "foundry.toml").write_text("[profile.default]\n")
        (root / "hardhat.config.js").write_text("module.exports={};\n")  # hybrid
        calls = []

        class FakeSlither:
            def __init__(self, target, **kw):
                calls.append(kw)
                if "compile_force_framework" not in kw:
                    raise RuntimeError("simulate hardhat auto-detect hang/failure")

        with mock.patch.dict("sys.modules", {"slither": mock.MagicMock(Slither=FakeSlither)}):
            obj, err = df.load_slither_offline(root)
        # first Tier-3 attempt must carry the foundry force kwarg
        self.assertTrue(any(c.get("compile_force_framework") == "foundry" for c in calls),
                        f"expected compile_force_framework=foundry, calls={calls}")
        self.assertIsNotNone(obj)
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
