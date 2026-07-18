"""CCIA must only analyse production .sol - not vendored deps / scripts / test /
mocks / doc mirrors (all OOS), so its cross-contract attack angles aren't drowned
in forge-std / soldeer dependencies / script noise."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "ccia.py"


def _load():
    spec = importlib.util.spec_from_file_location("ccia", TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ccia"] = m
    spec.loader.exec_module(m)
    return m


M = _load()


class CciaScopeTest(unittest.TestCase):
    def test_find_sol_files_excludes_oos_and_keeps_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            kept = ["contracts/Real.sol", "contracts/v2/Bridge.sol", "src/Token.sol"]
            dropped = [
                "dependencies/forge-std-1.10.0/src/StdUtils.sol",  # soldeer vendored
                "lib/openzeppelin/Ownable.sol",                    # git-submodule vendored
                "script/Deploy.s.sol",                             # foundry script
                "test/Token.t.sol",                                # foundry test
                "contracts/mocks/Mock.sol",                        # mock
                "contracts/previousVersions/Old.sol",              # historical
                "docs/contracts/src/Mirror.sol",                   # doc mirror
                "node_modules/@openzeppelin/contracts/A.sol",      # npm vendored
            ]
            for rel in kept + dropped:
                p = d / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("contract X {}\n")
            got = {str(p.relative_to(d)) for p in M.find_sol_files(d)}
            self.assertEqual(got, set(kept), f"unexpected scope: {sorted(got)}")


if __name__ == "__main__":
    unittest.main()
