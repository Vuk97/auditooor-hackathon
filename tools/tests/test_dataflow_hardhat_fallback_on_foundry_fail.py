#!/usr/bin/env python3
# <!-- r36-rebuttal: lane DATAFLOW-HARDHAT-FALLBACK registered in commit message -->
"""dataflow-slice Tier-3 must fall back to compile_force_framework='hardhat' when the
forced-foundry compile itself fails and a hardhat.config.* is also present.

axelar-sc 2026-07-12 (gap55 / SC-DATAFLOW-HARDHAT lane): axelar-cgp-solidity ships BOTH
foundry.toml (solc 0.8.9, via_ir=true) and hardhat.config.js. `forge build` on that exact
package hits a solc 0.8.9 via-IR stack-depth limitation ("Yul exception: Variable param_N
is N slot(s) too deep inside the stack") and crytic-compile surfaces it as
"ERROR:CryticCompile:'forge' returned non-zero exit code 1" - hard stop, 0 dataflow rows,
even though the SAME contracts compile cleanly under the repo's own hardhat.config.js
(different optimizer codegen path, no full via-IR). Fix: load_slither_offline retries with
compile_force_framework='hardhat' when the forced-foundry attempt raises AND a
hardhat.config.{js,ts,cjs,mjs} exists at the project root, before falling through to plain
auto-detect. Verified live on axelar-sc/src/axelar-cgp-solidity: 59 real dataflow_path.v1
rows emitted (previously 0 / hard ERROR stop).
"""
import importlib.util, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

_T = Path(__file__).resolve().parent.parent / "dataflow-slice.py"
_s = importlib.util.spec_from_file_location("dfslice_hhfallback", _T)
df = importlib.util.module_from_spec(_s); sys.modules["dfslice_hhfallback"] = df; _s.loader.exec_module(df)


class HardhatFallbackOnFoundryFailTest(unittest.TestCase):
    def test_hardhat_forced_when_forced_foundry_compile_fails(self):
        root = Path(tempfile.mkdtemp())
        (root / "foundry.toml").write_text(
            "[profile.default]\nsolc = \"0.8.9\"\nvia_ir = true\n"
        )
        (root / "hardhat.config.js").write_text("module.exports={};\n")
        calls = []

        class FakeSlither:
            def __init__(self, target, **kw):
                calls.append(kw)
                if kw.get("compile_force_framework") == "foundry":
                    raise RuntimeError(
                        "ERROR:CryticCompile:'forge' returned non-zero exit code 1 "
                        "(Yul exception: Variable param_5 is 2 slot(s) too deep)"
                    )
                if kw.get("compile_force_framework") != "hardhat":
                    raise RuntimeError("simulate plain auto-detect failure too")

        with mock.patch.dict("sys.modules", {"slither": mock.MagicMock(Slither=FakeSlither)}):
            obj, err = df.load_slither_offline(root)

        frameworks_tried = [c.get("compile_force_framework") for c in calls]
        self.assertEqual(
            frameworks_tried, ["foundry", "hardhat"],
            f"expected foundry attempted then hardhat fallback, got {frameworks_tried}",
        )
        self.assertIsNotNone(obj)
        self.assertIsNone(err)

    def test_no_hardhat_config_no_fallback_attempt(self):
        """A pure foundry project (no hardhat.config.*) must NOT try compile_force_framework='hardhat';
        it should fall through to plain auto-detect instead (unchanged prior behavior)."""
        root = Path(tempfile.mkdtemp())
        (root / "foundry.toml").write_text("[profile.default]\n")
        calls = []

        class FakeSlither:
            def __init__(self, target, **kw):
                calls.append(kw)
                if kw.get("compile_force_framework") == "foundry":
                    raise RuntimeError("simulate foundry compile failure")
                # plain auto-detect (no compile_force_framework kwarg) succeeds

        with mock.patch.dict("sys.modules", {"slither": mock.MagicMock(Slither=FakeSlither)}):
            obj, err = df.load_slither_offline(root)

        frameworks_tried = [c.get("compile_force_framework") for c in calls]
        self.assertNotIn("hardhat", frameworks_tried,
                          f"no hardhat.config.* present, must not force hardhat: {calls}")
        self.assertIsNotNone(obj)
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
