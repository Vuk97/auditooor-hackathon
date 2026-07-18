#!/usr/bin/env python3
"""Focused fixtures for the zkBugs Penumbra fixed-point addition detector."""

from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = "zkbugs_unsound_fixed_point_addition"

sys.path.insert(0, str(ROOT / "detectors" / "rust_wave1"))

import zkbugs_unsound_fixed_point_addition as detector  # noqa: E402


@dataclass
class FakeNode:
    type: str
    start_byte: int
    end_byte: int
    children: list["FakeNode"] = field(default_factory=list)
    start_point: tuple[int, int] = (0, 0)
    parent: "FakeNode | None" = None


@dataclass
class FakeTree:
    root_node: FakeNode


def _line_col_for(source: bytes, offset: int) -> tuple[int, int]:
    prefix = source[:offset]
    line = prefix.count(b"\n")
    last_nl = prefix.rfind(b"\n")
    col = len(prefix) if last_nl == -1 else len(prefix) - last_nl - 1
    return line, col


def _tree_for_checked_add(fixture: str) -> tuple[FakeTree, bytes]:
    source = fixture.encode("utf-8")
    fn_start = source.index(b"pub fn checked_add")
    name_start = source.index(b"checked_add", fn_start)
    name_end = name_start + len(b"checked_add")
    body_start = source.index(b"{", name_end)
    body_end = source.rindex(b"}") + 1

    ident = FakeNode(
        "identifier",
        name_start,
        name_end,
        start_point=_line_col_for(source, name_start),
    )
    body = FakeNode(
        "block",
        body_start,
        body_end,
        start_point=_line_col_for(source, body_start),
    )
    fn = FakeNode(
        "function_item",
        fn_start,
        body_end,
        [ident, body],
        start_point=_line_col_for(source, fn_start),
    )
    ident.parent = fn
    body.parent = fn
    root = FakeNode(
        "source_file",
        0,
        len(source),
        [fn],
        start_point=(0, 0),
    )
    fn.parent = root
    return FakeTree(root), source


def _run_detector(fixture: str) -> list[dict]:
    tree, source = _tree_for_checked_add(fixture)
    return detector.run(tree, source, "fixpoint.rs")


VULNERABLE = r"""
struct U128x128Var {
    limbs: [UInt64; 4],
}

impl U128x128Var {
    pub fn checked_add(self, rhs: &Self) -> Result<Self, SynthesisError> {
        let x0 = Boolean::<Fq>::le_bits_to_fp_var(&self.limbs[0].to_bits_le())?;
        let y0 = Boolean::<Fq>::le_bits_to_fp_var(&rhs.limbs[0].to_bits_le())?;
        let x1 = Boolean::<Fq>::le_bits_to_fp_var(&self.limbs[1].to_bits_le())?;
        let y1 = Boolean::<Fq>::le_bits_to_fp_var(&rhs.limbs[1].to_bits_le())?;

        let z0_raw = &x0 + &y0;
        let z1_raw = &x1 + &y1;

        let z0_bits = bit_constrain(z0_raw, 64)?;
        let z0 = UInt64::from_bits_le(&z0_bits[0..64]);
        let c1 = Boolean::<Fq>::le_bits_to_fp_var(&z0_bits[64..].to_bits_le()?)?;

        let z1_bits = bit_constrain(z1_raw + c1, 66)?;
        let z1 = UInt64::from_bits_le(&z1_bits[0..64]);
        Ok(Self { limbs: [z0, z1, z0, z1] })
    }
}
"""


FIXED = VULNERABLE.replace(
    "let z0_bits = bit_constrain(z0_raw, 64)?;",
    "let z0_bits = bit_constrain(z0_raw, 65)?;",
)


UNRELATED_64_BIT_CONSTRAINT = r"""
impl RangeGadget {
    pub fn checked_add(self, rhs: &Self) -> Result<Self, SynthesisError> {
        let z0_raw = self.value + rhs.value;
        let z0_bits = bit_constrain(z0_raw, 64)?;
        let z0 = UInt64::from_bits_le(&z0_bits[0..64]);
        Ok(Self { value: z0 })
    }
}
"""


class TestZkbugsUnsoundFixedPointAddition(unittest.TestCase):
    def test_flags_64_bit_limb_constraint_used_for_carry(self):
        hits = _run_detector(VULNERABLE)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "high")
        self.assertIn("unsound", hits[0]["message"])
        self.assertIn("z0_bits[64..]", hits[0]["message"])

    def test_allows_fixed_65_bit_first_limb_constraint(self):
        hits = _run_detector(FIXED)
        self.assertEqual(hits, [])

    def test_allows_64_bit_constraint_when_not_used_as_carry(self):
        hits = _run_detector(UNRELATED_64_BIT_CONSTRAINT)
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
