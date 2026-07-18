#!/usr/bin/env python3
"""Regression for storage-layout.py --compare-dir upgrade-shift detection.

storage-layout.py advertises (docstring items 3 + 4) a `--compare-dir` mode
that diffs the current workspace layout against a prior-version source dir and
flags upgradeable-storage corruption:

  (3) a new state var inserted BEFORE existing ones -> shifts later slots, and
  (4) packed-struct / packed-var member reorder across versions.

argparse previously only had the positional `workspace`; --compare-dir was
unimplemented. This pins the implementation.

Two layers of evidence:

  * Pure-logic (`_diff_layouts`, Slither-free, ALWAYS runs):
      - leading-var insertion          -> UPWARD slot-shift flagged
      - removal-before-survivor        -> DOWNWARD slot-shift flagged (CASE B)
      - type-shrink repack into earlier slot -> DOWNWARD slot-shift (CASE C)
      - identical layout               -> []
      - packed offset reorder          -> offset-shift flagged
      - type-width change at same slot -> type-change flagged
      - trailing addition / trailing removal -> no spurious shift on survivors
    Non-vacuity: the SAME differ on the SAME survivors returns [] when nothing
    shifted, so a flag is caused by the shift, not by the differ always firing.
    BOTH shift directions are corruption signals (insertion shifts survivors up,
    removal shifts them down); only the genuinely-moved survivors are flagged.

  * End-to-end Slither compile (`_compare_dir_contracts`, SKIPs without
    slither): an old vs new on-disk contract with an inserted leading var is
    flagged; an identical-layout pair is clean. This exercises the real
    `_compute_layout` over a real compile, not a hand-built layout.

R80: the Slither cases require a real in-tree compile; they SKIP (not fake-pass)
when slither is not importable. No em-dashes.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_storage_layout():
    spec = importlib.util.spec_from_file_location(
        "storage_layout_cmp", TOOLS / "storage-layout.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # py3.14 importlib quirk: register before exec so intra-module refs resolve.
    sys.modules["storage_layout_cmp"] = mod
    spec.loader.exec_module(mod)
    return mod


SL = _load_storage_layout()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; --compare-dir e2e needs a real compile",
)


def _lay(*entries):
    """Helper: build a layout list from (name, type, slot, offset, size)."""
    return [
        {"name": n, "type": t, "slot": s, "offset": o, "size": z}
        for (n, t, s, o, z) in entries
    ]


class DiffLayoutsPureTest(unittest.TestCase):
    """The pure differ - no Slither needed, so this layer always runs."""

    def test_leading_var_insertion_flags_slot_shift(self):
        # OLD: a@0, b@1 ; NEW: inserted x@0, so a@1, b@2.
        old = _lay(("a", "uint256", 0, 0, 32), ("b", "uint256", 1, 0, 32))
        new = _lay(
            ("x", "uint256", 0, 0, 32),
            ("a", "uint256", 1, 0, 32),
            ("b", "uint256", 2, 0, 32),
        )
        findings = SL._diff_layouts(old, new)
        kinds = {(f["kind"], f["name"]) for f in findings}
        self.assertIn(("slot-shift", "a"), kinds)
        self.assertIn(("slot-shift", "b"), kinds)
        a = next(f for f in findings if f["name"] == "a")
        self.assertEqual((a["old_slot"], a["new_slot"]), (0, 1))

    def test_identical_layout_is_clean(self):
        old = _lay(("a", "uint256", 0, 0, 32), ("b", "address", 1, 0, 20))
        new = _lay(("a", "uint256", 0, 0, 32), ("b", "address", 1, 0, 20))
        self.assertEqual(SL._diff_layouts(old, new), [])

    def test_packed_offset_reorder_flags_offset_shift(self):
        # Two packed uint128 in slot 0 swap order: a@off0/b@off16 -> b@off0/a@off16
        old = _lay(("a", "uint128", 0, 0, 16), ("b", "uint128", 0, 16, 16))
        new = _lay(("b", "uint128", 0, 0, 16), ("a", "uint128", 0, 16, 16))
        findings = SL._diff_layouts(old, new)
        kinds = {(f["kind"], f["name"]) for f in findings}
        self.assertIn(("offset-shift", "a"), kinds)
        self.assertIn(("offset-shift", "b"), kinds)

    def test_type_width_change_at_same_slot_flags_type_change(self):
        old = _lay(("a", "uint128", 0, 0, 16))
        new = _lay(("a", "uint256", 0, 0, 32))
        findings = SL._diff_layouts(old, new)
        self.assertEqual(
            [(f["kind"], f["old_type"], f["new_type"]) for f in findings],
            [("type-change", "uint128", "uint256")],
        )

    def test_pure_trailing_addition_causes_no_spurious_shift(self):
        # NEW appends c@2; a,b unchanged (still slots 0,1). A trailing addition
        # does not move any survivor, so there is no shift to flag.
        old = _lay(("a", "uint256", 0, 0, 32), ("b", "uint256", 1, 0, 32))
        new = _lay(
            ("a", "uint256", 0, 0, 32),
            ("b", "uint256", 1, 0, 32),
            ("c", "uint256", 2, 0, 32),
        )
        self.assertEqual(SL._diff_layouts(old, new), [])

    def test_removal_before_survivor_flags_downward_slot_shift(self):
        # CASE B (was a silent-pass): OLD a@0, b@1, c@2. NEW removes `a`, so the
        # survivors shift DOWN: b@0, c@1. That is genuine proxy storage
        # corruption (b/c now read whatever the proxy stored at the lower slots)
        # and MUST be flagged via a downward slot-shift on the survivors.
        old = _lay(
            ("a", "uint256", 0, 0, 32),
            ("b", "uint256", 1, 0, 32),
            ("c", "uint256", 2, 0, 32),
        )
        new = _lay(("b", "uint256", 0, 0, 32), ("c", "uint256", 1, 0, 32))
        findings = SL._diff_layouts(old, new)
        kinds = {(f["kind"], f["name"]) for f in findings}
        self.assertIn(("slot-shift", "b"), kinds)
        self.assertIn(("slot-shift", "c"), kinds)
        b = next(f for f in findings if f["name"] == "b")
        self.assertEqual((b["old_slot"], b["new_slot"]), (1, 0))
        self.assertEqual(b["direction"], "down")

    def test_type_shrink_repack_into_earlier_slot_flags_downward_shift(self):
        # CASE C (was a silent-pass): a type-shrink lets a later var repack into
        # an earlier slot. OLD a@0(uint256), b@1. NEW a shrinks to uint128 and b
        # packs into slot 0 -> b@0 (downward). Must flag the downward shift on b.
        old = _lay(("a", "uint256", 0, 0, 32), ("b", "uint128", 1, 0, 16))
        new = _lay(("a", "uint128", 0, 0, 16), ("b", "uint128", 0, 16, 16))
        findings = SL._diff_layouts(old, new)
        kinds = {(f["kind"], f["name"]) for f in findings}
        self.assertIn(("slot-shift", "b"), kinds)
        b = next(f for f in findings if f["name"] == "b" and f["kind"] == "slot-shift")
        self.assertEqual((b["old_slot"], b["new_slot"]), (1, 0))
        self.assertEqual(b["direction"], "down")

    def test_unchanged_survivors_with_removal_only_flag_the_shifted(self):
        # Non-vacuity guard: a survivor whose slot did NOT change (the removal was
        # AFTER it) is NOT flagged; only the genuinely-shifted survivors are.
        old = _lay(
            ("a", "uint256", 0, 0, 32),
            ("b", "uint256", 1, 0, 32),
            ("c", "uint256", 2, 0, 32),
        )
        # remove c (trailing) -> a,b unchanged -> clean.
        new = _lay(("a", "uint256", 0, 0, 32), ("b", "uint256", 1, 0, 32))
        self.assertEqual(SL._diff_layouts(old, new), [])


# -- End-to-end: real Slither compile of old-vs-new fixture dirs ---------------

_OLD_INSERT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    uint256 public totalSupply;
}
"""

_NEW_INSERT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public newlyInsertedAdmin; // inserted BEFORE existing vars
    address public owner;
    uint256 public totalSupply;
}
"""

_IDENTICAL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    uint256 public totalSupply;
}
"""


def _write_ws(root: pathlib.Path, body: str) -> pathlib.Path:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Vault.sol").write_text(body)
    return root


@SKIP_NO_SLITHER
class CompareDirE2ETest(unittest.TestCase):
    def test_inserted_leading_var_is_flagged_via_real_compile(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td)
            old_dir = _write_ws(base / "old", _OLD_INSERT)
            new_ws = _write_ws(base / "new", _NEW_INSERT)
            ws_contracts = list(SL._contracts_from_sources(new_ws))
            self.assertTrue(
                any(c.name == "Vault" for _s, c in ws_contracts),
                "fixture Vault did not compile",
            )
            results = SL._compare_dir_contracts(ws_contracts, old_dir)
            self.assertIn("Vault", results)
            kinds = {(f["kind"], f["name"]) for f in results["Vault"]}
            self.assertIn(("slot-shift", "owner"), kinds)
            self.assertIn(("slot-shift", "totalSupply"), kinds)

    def test_identical_layout_is_clean_via_real_compile(self):
        with tempfile.TemporaryDirectory() as td:
            base = pathlib.Path(td)
            old_dir = _write_ws(base / "old", _IDENTICAL)
            new_ws = _write_ws(base / "new", _IDENTICAL)
            ws_contracts = list(SL._contracts_from_sources(new_ws))
            self.assertTrue(any(c.name == "Vault" for _s, c in ws_contracts))
            results = SL._compare_dir_contracts(ws_contracts, old_dir)
            self.assertNotIn("Vault", results)
            self.assertEqual(results, {})


if __name__ == "__main__":
    unittest.main()
