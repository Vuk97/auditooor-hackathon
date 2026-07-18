#!/usr/bin/env python3
"""Tests for GEN-EL1 compiler-known-bug shape-JOIN reachability screen.

The load-bearing property (the whole point, the E2-gap it closes):
a row fires ONLY on the JOIN of (version-affected) AND (source-shape-present).
Version-affected WITHOUT the shape is SILENT; shape-present on a NON-affected
pin is SILENT. Both halves are independently proven load-bearing here.
"""
import importlib.util
import json
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / \
    "compiler-known-bug-shape-join-screen.py"
_spec = importlib.util.spec_from_file_location("_gen_el1", TOOL)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)


def _scan(src, name="C.sol"):
    return M.scan_file(Path(name), name, file_text=src)


# ---------------------------------------------------------------------------
# EL1-TSTORE-SAMETYPE (SOL-2026-1, window [0.8.28, 0.8.34))
# ---------------------------------------------------------------------------
_TSTORE_SHAPE_28 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract C {
    address public transient initiator;
    address public lastInitiator;
    function go() external {
        initiator = msg.sender;
        lastInitiator = msg.sender;
    }
}
"""

# version-affected but NO same-type persistent var -> the E2-gap-closing case.
_TSTORE_NO_SHAPE_28 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract C {
    address public transient initiator;
    bytes32 public transient reenterHash;
    function go() external {
        initiator = msg.sender;
        reenterHash = bytes32(0);
    }
}
"""

# same shape, NON-affected pin (>= fixed 0.8.34) -> version half load-bearing.
_TSTORE_SHAPE_34 = _TSTORE_SHAPE_28.replace(
    "pragma solidity 0.8.28;", "pragma solidity 0.8.34;")

# same shape, NON-affected pin (< introduced 0.8.28) -> version half load-bearing.
_TSTORE_SHAPE_27 = _TSTORE_SHAPE_28.replace(
    "pragma solidity 0.8.28;", "pragma solidity 0.8.27;")

# transient + persistent but DIFFERENT types, both written -> shape absent.
_TSTORE_DIFFTYPE_28 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract C {
    address public transient initiator;
    bytes32 public lastHash;
    function go() external {
        initiator = msg.sender;
        lastHash = bytes32(0);
    }
}
"""

# same type but written in DIFFERENT functions -> not one-function shape.
_TSTORE_DIFFFN_28 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract C {
    address public transient initiator;
    address public lastInitiator;
    function a() external { initiator = msg.sender; }
    function b() external { lastInitiator = msg.sender; }
}
"""


class TestTstoreSameType(unittest.TestCase):
    def test_join_fires(self):
        rows = _scan(_TSTORE_SHAPE_28)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["bug_id"], "SOL-2026-1")
        self.assertEqual(r["capability"], "GEN_EL1")
        self.assertEqual(r["function"], "go")
        self.assertEqual(r["pinned_version"], "0.8.28")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        self.assertIn("initiator", r["excerpt"])
        self.assertIn("lastInitiator", r["excerpt"])

    def test_version_alone_no_shape_is_SILENT(self):
        # THE E2-gap-closing proof: in-window pin + transient feature used, but
        # no same-type persistent var -> the specific miscompile is unreachable.
        self.assertEqual(_scan(_TSTORE_NO_SHAPE_28), [])

    def test_shape_on_fixed_pin_is_SILENT(self):
        self.assertEqual(_scan(_TSTORE_SHAPE_34), [])

    def test_shape_on_pre_introduced_pin_is_SILENT(self):
        self.assertEqual(_scan(_TSTORE_SHAPE_27), [])

    def test_different_types_is_SILENT(self):
        self.assertEqual(_scan(_TSTORE_DIFFTYPE_28), [])

    def test_written_in_different_functions_is_SILENT(self):
        self.assertEqual(_scan(_TSTORE_DIFFFN_28), [])


# ---------------------------------------------------------------------------
# EL1-UDVT-SUB256 (SOL-2021-4, window [0.8.8, 0.8.9))
# ---------------------------------------------------------------------------
_UDVT_SHAPE_88 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.8;
type Fixed is uint128;
contract C {
    function f(uint128 x) external pure returns (Fixed) {
        return Fixed.wrap(x);
    }
}
"""
# UDVT over full 256-bit underlying -> not the dirty-bits shape.
_UDVT_256_88 = _UDVT_SHAPE_88.replace("uint128", "uint256")
# affected shape but pin out of window (0.8.9 == fixed).
_UDVT_SHAPE_89 = _UDVT_SHAPE_88.replace(
    "pragma solidity 0.8.8;", "pragma solidity 0.8.9;")


class TestUdvtSub256(unittest.TestCase):
    def test_join_fires(self):
        rows = _scan(_UDVT_SHAPE_88)
        self.assertTrue(any(r["bug_id"] == "SOL-2021-4" for r in rows))

    def test_full_width_underlying_is_SILENT(self):
        self.assertEqual(
            [r for r in _scan(_UDVT_256_88) if r["bug_id"] == "SOL-2021-4"], [])

    def test_out_of_window_is_SILENT(self):
        self.assertEqual(
            [r for r in _scan(_UDVT_SHAPE_89) if r["bug_id"] == "SOL-2021-4"], [])


# ---------------------------------------------------------------------------
# EL1-ABI-HEAD-OVERFLOW (SOL-2022-6, window [0.5.8, 0.8.16))
# ---------------------------------------------------------------------------
_ABI_SHAPE_815 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
contract C {
    uint256[3] public fixedArr;
    function f() external view returns (bytes memory) {
        return abi.encode(fixedArr);
    }
}
"""
# abi.encode but NO fixed-size array -> shape absent.
_ABI_NOARR_815 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
contract C {
    uint256 public x;
    function f() external view returns (bytes memory) {
        return abi.encode(x);
    }
}
"""
_ABI_SHAPE_816 = _ABI_SHAPE_815.replace(
    "pragma solidity 0.8.15;", "pragma solidity 0.8.16;")


class TestAbiHeadOverflow(unittest.TestCase):
    def test_join_fires(self):
        rows = _scan(_ABI_SHAPE_815)
        self.assertTrue(any(r["bug_id"] == "SOL-2022-6" for r in rows))

    def test_no_fixed_array_is_SILENT(self):
        self.assertEqual(
            [r for r in _scan(_ABI_NOARR_815) if r["bug_id"] == "SOL-2022-6"],
            [])

    def test_fixed_pin_is_SILENT(self):
        self.assertEqual(
            [r for r in _scan(_ABI_SHAPE_816) if r["bug_id"] == "SOL-2022-6"],
            [])


# ---------------------------------------------------------------------------
# EL1-NESTED-CALLDATA-ARRAY (SOL-2022-2, window [0.5.8, 0.8.14))
# ---------------------------------------------------------------------------
_NESTED_SHAPE_813 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;
contract C {
    function f(uint256[][] calldata data) external pure returns (uint256) {
        return data.length;
    }
}
"""
_NESTED_NONE_813 = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;
contract C {
    function f(uint256 x) external pure returns (uint256) { return x; }
}
"""
_NESTED_SHAPE_814 = _NESTED_SHAPE_813.replace(
    "pragma solidity 0.8.13;", "pragma solidity 0.8.14;")


class TestNestedCalldataArray(unittest.TestCase):
    def test_join_fires(self):
        rows = _scan(_NESTED_SHAPE_813)
        self.assertTrue(any(r["bug_id"] == "SOL-2022-2" for r in rows))

    def test_no_nested_array_is_SILENT(self):
        self.assertEqual(
            [r for r in _scan(_NESTED_NONE_813) if r["bug_id"] == "SOL-2022-2"],
            [])

    def test_fixed_pin_is_SILENT(self):
        self.assertEqual(
            [r for r in _scan(_NESTED_SHAPE_814) if r["bug_id"] == "SOL-2022-2"],
            [])


# ---------------------------------------------------------------------------
# comment/string masking + sidecar/summary/exclusion plumbing
# ---------------------------------------------------------------------------
_COMMENTED_TSTORE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract C {
    // address public transient initiator;
    // address public lastInitiator;
    uint256 public x;
    function go() external { x = 1; }
}
"""


class TestPlumbing(unittest.TestCase):
    def test_commented_shape_is_SILENT(self):
        self.assertEqual(_scan(_COMMENTED_TSTORE), [])

    def test_row_schema_and_uid_reuse(self):
        r = _scan(_TSTORE_SHAPE_28)[0]
        self.assertEqual(r["schema"], M.HYP_SCHEMA)
        # REUSES the E2 curated advisory uid (dedup, not a fresh id).
        self.assertEqual(
            r["matched_advisory_uid"],
            "solc-compiler:sol-2026-1:transientstorageclearinghelpercollision:"
            "24a202785af6")
        self.assertIn("affected_range", r)
        self.assertIn("why_version_and_shape_both_present", r)

    def test_summary_shape(self):
        rows = _scan(_TSTORE_SHAPE_28)
        s = M._summary(rows)
        self.assertEqual(s["fired"], 1)
        self.assertEqual(s["verdict"], "needs-fuzz")
        self.assertTrue(s["advisory"])

    def test_workspace_scan_emits_sidecar(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "C.sol").write_text(_TSTORE_SHAPE_28)
            rc = M.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)  # advisory default exit 0
            side = ws / ".auditooor" / M._SIDE_NAME
            self.assertTrue(side.exists())
            lines = [l for l in side.read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["bug_id"], "SOL-2026-1")
            # strict elevates exit code when a row fired.
            self.assertEqual(M.main(["--workspace", str(ws), "--strict"]), 1)

    def test_test_file_excluded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "C.t.sol").write_text(_TSTORE_SHAPE_28)
            M.main(["--workspace", str(ws)])
            side = ws / ".auditooor" / M._SIDE_NAME
            lines = [l for l in side.read_text().splitlines() if l.strip()] \
                if side.exists() else []
            self.assertEqual(lines, [])


if __name__ == "__main__":
    unittest.main()
