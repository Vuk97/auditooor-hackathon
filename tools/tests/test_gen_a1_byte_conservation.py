#!/usr/bin/env python3
"""Non-vacuous tests for GEN-A1 parse/consume byte-conservation seam screen.

Every positive case has a paired negative (the SAME code WITH the byte-
conservation assertion) that must NOT fire - proving the assertion predicate is
load-bearing, not a shape match. Includes the real-fleet mutation witness on
morpho BytesLib.get (bounded original silent, require-removed copy fires).
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL = TOOLS / "parse-consume-byte-conservation-screen.py"

_spec = importlib.util.spec_from_file_location("bc_screen", TOOL)
bc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bc)


def _scan(text, name):
    return bc.scan_file(Path(name), name, file_text=text)


def _kinds(rows):
    return {r["pattern_id"] for r in rows}


class SolidityAsmSliceTests(unittest.TestCase):
    def test_unbounded_asm_slice_fires(self):
        src = """
        library L {
            function get(bytes memory data, uint256 offset) internal pure returns (uint256 v) {
                assembly ("memory-safe") {
                    v := mload(add(32, add(data, offset)))
                }
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertIn("S_ASM_UNBOUNDED_SLICE", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_ASM_UNBOUNDED_SLICE"][0]
        self.assertEqual(r["missing_assertion"], "child-overflow-parent")
        self.assertIn(r["decoded_var"], {"data", "offset"})

    def test_bounded_asm_slice_silent(self):
        # SAME code WITH the require length bound - must NOT fire.
        src = """
        library L {
            function get(bytes memory data, uint256 offset) internal pure returns (uint256 v) {
                require(offset <= data.length - 32, "oob");
                assembly ("memory-safe") {
                    v := mload(add(32, add(data, offset)))
                }
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertNotIn("S_ASM_UNBOUNDED_SLICE", _kinds(rows))

    def test_fixed_slot_read_silent(self):
        # mload of a fixed slot (no add() over a param) is not a slice read.
        src = """
        contract C {
            function f() internal view returns (uint256 v) {
                assembly { v := mload(0x40) }
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertEqual(rows, [])


class SolidityDecodeTrailingTests(unittest.TestCase):
    def test_calldata_slice_decode_fires(self):
        src = """
        contract C {
            function exec(bytes calldata data) external {
                (address a, uint256 x) = abi.decode(data[4:], (address, uint256));
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_DECODE_TRAILING", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_DECODE_TRAILING"][0]
        self.assertEqual(r["missing_assertion"], "consumed==declared")

    def test_length_asserted_decode_silent(self):
        # SAME decode WITH a length assertion - must NOT fire.
        src = """
        contract C {
            function exec(bytes calldata data) external {
                require(data.length == 68, "len");
                (address a, uint256 x) = abi.decode(data[4:], (address, uint256));
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_DECODE_TRAILING", _kinds(rows))

    def test_plain_bytes_decode_silent(self):
        # abi.decode of a whole (non-sliced) bytes value is not the trailing class.
        src = """
        contract C {
            function exec(bytes memory data) external {
                (address a) = abi.decode(data, (address));
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_DECODE_TRAILING", _kinds(rows))


class GoLenPrefixTests(unittest.TestCase):
    def test_unbounded_lenprefix_reslice_fires(self):
        src = """
        package p
        func decode(buf []byte) []byte {
            n := binary.BigEndian.Uint32(buf[0:4])
            body := buf[4 : 4+n]
            return body
        }
        """
        rows = _scan(src, "d.go")
        self.assertIn("G_LENPREFIX_RESLICE", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "G_LENPREFIX_RESLICE"][0]
        self.assertEqual(r["missing_assertion"], "child-overflow-parent")
        self.assertEqual(r["decoded_var"], "n")

    def test_bounded_lenprefix_silent(self):
        # SAME code WITH a len() bound - must NOT fire.
        src = """
        package p
        func decode(buf []byte) ([]byte, error) {
            n := binary.BigEndian.Uint32(buf[0:4])
            if int(n) > len(buf)-4 {
                return nil, errors.New("overflow")
            }
            body := buf[4 : 4+n]
            return body, nil
        }
        """
        rows = _scan(src, "d.go")
        self.assertNotIn("G_LENPREFIX_RESLICE", _kinds(rows))

    def test_lenprefix_not_used_as_index_silent(self):
        # length decoded but never used to reslice/allocate - nothing to overflow.
        src = """
        package p
        func decode(buf []byte) uint32 {
            n := binary.BigEndian.Uint32(buf[0:4])
            return n + 1
        }
        """
        rows = _scan(src, "d.go")
        self.assertNotIn("G_LENPREFIX_RESLICE", _kinds(rows))


class ExclusionTests(unittest.TestCase):
    def test_codegen_marker_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            gen = root / "x.pb.go"
            gen.write_text(
                "// Code generated by protoc. DO NOT EDIT.\n"
                "package p\n"
                "func decode(buf []byte) []byte {\n"
                "  n := binary.BigEndian.Uint32(buf[0:4])\n"
                "  return buf[4:4+n]\n}\n")
            rows = bc.scan_tree(root, workspace=Path(td))
            self.assertEqual(rows, [])


class MutationWitnessTests(unittest.TestCase):
    """Real-fleet non-vacuity witness on morpho BytesLib.get."""

    BYTESLIB = Path(
        "/Users/wolf/audits/morpho/src/bundler3/src/libraries/BytesLib.sol")

    def test_real_bounded_original_silent_weakened_fires(self):
        if not self.BYTESLIB.exists():
            self.skipTest("morpho BytesLib.sol not present")
        orig = self.BYTESLIB.read_text()
        # benign original: bounded require -> must NOT fire
        rows0 = bc.scan_file(self.BYTESLIB, self.BYTESLIB.name, file_text=orig)
        self.assertNotIn("S_ASM_UNBOUNDED_SLICE", _kinds(rows0))
        # weaken get(): drop its require bound -> must newly fire
        weak_lines = [
            l for l in orig.split("\n")
            if not l.strip().startswith("require(offset <= data.length - 32")
        ]
        weak = "\n".join(weak_lines)
        self.assertNotEqual(weak, orig, "mutation did not change source")
        rows1 = bc.scan_file(self.BYTESLIB, self.BYTESLIB.name, file_text=weak)
        fired = [r for r in rows1 if r["pattern_id"] == "S_ASM_UNBOUNDED_SLICE"]
        self.assertTrue(fired, "weakened BytesLib did not fire")


class CliTests(unittest.TestCase):
    def test_cli_source_mode_and_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "library L {\n"
                "    function g(bytes memory d, uint256 o) internal pure returns (uint256 v) {\n"
                "        assembly { v := mload(add(32, add(d, o))) }\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            summ = json.loads(r.stdout)
            self.assertEqual(summ["schema"], bc.HYP_SCHEMA)
            self.assertGreaterEqual(summ["fired"], 1)
            side = Path(td) / ".auditooor" / "byte_conservation_hypotheses.jsonl"
            self.assertTrue(side.exists())

    def test_cli_strict_exit1_on_fire(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "library L {\n"
                "    function g(bytes memory d, uint256 o) internal pure returns (uint256 v) {\n"
                "        assembly { v := mload(add(32, add(d, o))) }\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td, "--strict"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
