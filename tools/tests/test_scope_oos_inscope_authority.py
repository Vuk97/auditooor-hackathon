#!/usr/bin/env python3
"""Regression: scope_oos_globs must NOT turn an OOS-prose noun that coincides with
an in-scope directory basename (or the workspace root) into an exclude glob
(Strata 2026-07-07). A genuine bare-noun OOS dir (not in-scope) still excludes."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "lib" / "scope_oos_globs.py"
_spec = importlib.util.spec_from_file_location("scope_oos_globs", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


def _mk_ws(scope_md: str, dirs: list[str], inscope_file: str | None = None) -> Path:
    # Name the workspace dir "strata" so the OOS prose word "Strata" coincides with it.
    base = Path(tempfile.mkdtemp())
    ws = base / "strata"
    ws.mkdir()
    for d in dirs:
        (ws / d).mkdir(parents=True, exist_ok=True)
    if inscope_file:
        p = ws / inscope_file
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// sol")
    (ws / "SCOPE.md").write_text(scope_md)
    return ws


SCOPE = """# In-scope files
contracts/governance/AccessControlManager.sol
contracts/tranches/oracles/AprPairFeed.sol

## OUT-OF-SCOPE (verbatim from the program)
- Bugs in third-party dependencies not directly part of Strata's deployed contracts
- Centralization risk or attacks requiring access to privileged keys (governance and strategist)
- Incorrect data supplied by third party oracles
- The legacy module is out of scope
"""


class TestInscopeAuthority(unittest.TestCase):
    def test_inscope_dirs_and_wsroot_never_excluded(self):
        ws = _mk_ws(
            SCOPE,
            dirs=["contracts/governance", "contracts/tranches/oracles", "legacy"],
            inscope_file="contracts/governance/AccessControlManager.sol",
        )
        spec = _m.load_oos_spec(str(ws))
        globs = spec["exclude_globs"]
        # workspace root "strata" must never be an exclude glob
        self.assertNotIn("**/strata/**", globs)
        # in-scope ancestor dirs must never be excluded
        self.assertFalse(any(g.endswith("/governance/**") for g in globs), globs)
        self.assertFalse(any(g.endswith("/oracles/**") for g in globs), globs)
        # and is_oos must resolve an in-scope file IN-scope
        self.assertEqual(
            _m.is_oos("contracts/governance/AccessControlManager.sol", spec, str(ws)),
            (False, None))

    def test_genuine_oos_bare_noun_still_excluded(self):
        # "legacy" is named OOS and is NOT an in-scope ancestor -> stays excludable.
        ws = _mk_ws(
            SCOPE,
            dirs=["contracts/governance", "contracts/tranches/oracles", "legacy"],
            inscope_file="contracts/governance/AccessControlManager.sol",
        )
        spec = _m.load_oos_spec(str(ws))
        self.assertTrue(any(g.endswith("/legacy/**") for g in spec["exclude_globs"]),
                        spec["exclude_globs"])
        self.assertEqual(_m.is_oos("legacy/Foo.sol", spec, str(ws))[0], True)


if __name__ == "__main__":
    unittest.main()
