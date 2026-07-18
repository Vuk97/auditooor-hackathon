#!/usr/bin/env python3
"""Tests for GEN-EL4 crypto-preimage soundness census.

The load-bearing property: each arm fires ONLY when its caller-side guard is
ABSENT at a real signature-verify / AEAD site. A correctly guarded site is
SILENT; weakening (dropping) the guard makes the arm newly fire. Non-vacuity is
proven per-arm both on synthetic fixtures AND on REAL fleet code
(morpho-blue Morpho.sol setAuthorizationWithSig).
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / \
    "crypto-preimage-soundness-screen.py"
_spec = importlib.util.spec_from_file_location("_gen_el4", TOOL)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

_MORPHO = Path("/Users/wolf/audits/morpho/src/morpho-rewards-emissions-"
               "provider/lib/morpho-blue/src/Morpho.sol")


def _scan(src, name="C.sol"):
    return M.scan_file(Path(name), name, file_text=src)


def _arms(src, name="C.sol"):
    return sorted(r["arm_id"] for r in _scan(src, name))


# ---------------------------------------------------------------------------
# ARM D - domain-separator absent
# ---------------------------------------------------------------------------
# GUARDED: EIP-712 with a domainSeparator in the preimage.
_D_GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonce;
    function verify(address a, uint8 v, bytes32 r, bytes32 s, uint256 n) external {
        require(n == nonce[a]++);
        bytes32 hs = keccak256(abi.encode(a, n));
        bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, hs));
        require(ecrecover(digest, v, r, s) == a);
    }
}
"""
# UNGUARDED: no domainSeparator / chainid / address(this) / \x19\x01 prefix.
_D_UNGUARDED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    mapping(address => uint256) public nonce;
    function verify(address a, uint8 v, bytes32 r, bytes32 s, uint256 n) external {
        require(n == nonce[a]++);
        bytes32 digest = keccak256(abi.encode(a, n));
        require(ecrecover(digest, v, r, s) == a);
    }
}
"""


class TestArmDDomainSep(unittest.TestCase):
    def test_guarded_silent(self):
        self.assertNotIn("D_NO_DOMAIN_SEP", _arms(_D_GUARDED))

    def test_unguarded_fires(self):
        self.assertIn("D_NO_DOMAIN_SEP", _arms(_D_UNGUARDED))

    def test_chainid_alone_guards(self):
        s = _D_UNGUARDED.replace("keccak256(abi.encode(a, n))",
                                 "keccak256(abi.encode(a, n, block.chainid))")
        self.assertNotIn("D_NO_DOMAIN_SEP", _arms(s))


# ---------------------------------------------------------------------------
# ARM N - nonce read but never incremented
# ---------------------------------------------------------------------------
_N_GUARDED = _D_GUARDED  # nonce[a]++ present
_N_UNGUARDED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonce;
    function verify(address a, uint8 v, bytes32 r, bytes32 s, uint256 n) external {
        require(n == nonce[a]);
        bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, n));
        require(ecrecover(digest, v, r, s) == a);
    }
}
"""


class TestArmNNonce(unittest.TestCase):
    def test_guarded_silent(self):
        self.assertNotIn("N_NONCE_NOT_BUMPED", _arms(_N_GUARDED))

    def test_unguarded_fires(self):
        self.assertIn("N_NONCE_NOT_BUMPED", _arms(_N_UNGUARDED))

    def test_oz_usenonce_guards(self):
        s = _N_UNGUARDED.replace("require(n == nonce[a]);",
                                 "require(n == _useNonce(a));")
        self.assertNotIn("N_NONCE_NOT_BUMPED", _arms(s))


# ---------------------------------------------------------------------------
# ARM M - malleability (raw ecrecover, no low-s) - DISTINCT from A5 zero-signer
# ---------------------------------------------------------------------------
_M_GUARDED_OZ = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {ECDSA} from "oz/ECDSA.sol";
contract C {
    bytes32 public immutable DOMAIN_SEPARATOR;
    function verify(bytes32 digest, bytes calldata sig) external view {
        address a = ECDSA.recover(digest, sig);
        require(a != address(0));
    }
}
"""
_M_UNGUARDED_RAW = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    bytes32 public immutable DOMAIN_SEPARATOR;
    function verify(bytes32 digest, uint8 v, bytes32 r, bytes32 s, address a) external pure {
        require(ecrecover(digest, v, r, s) == a);
    }
}
"""


class TestArmMMalleability(unittest.TestCase):
    def test_oz_recover_silent(self):
        self.assertNotIn("M_NO_LOW_S", _arms(_M_GUARDED_OZ))

    def test_raw_ecrecover_fires(self):
        self.assertIn("M_NO_LOW_S", _arms(_M_UNGUARDED_RAW))

    def test_explicit_low_s_check_guards(self):
        s = _M_UNGUARDED_RAW.replace(
            "require(ecrecover(digest, v, r, s) == a);",
            "require(uint256(s) <= "
            "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);"
            " require(ecrecover(digest, v, r, s) == a);")
        self.assertNotIn("M_NO_LOW_S", _arms(s))


# ---------------------------------------------------------------------------
# ARM E - empty signer array in a threshold verify
# ---------------------------------------------------------------------------
_E_GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    uint256 public threshold;
    function verify(address[] calldata signers) external view returns (bool) {
        require(signers.length >= threshold);
        uint256 count;
        for (uint256 i; i < signers.length; i++) { count++; }
        return count >= threshold;
    }
}
"""
_E_UNGUARDED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    uint256 public threshold;
    function verify(address[] calldata signers) external view returns (bool) {
        uint256 count;
        for (uint256 i; i < signers.length; i++) { count++; }
        return count >= threshold;
    }
}
"""


class TestArmEEmptySigners(unittest.TestCase):
    def test_guarded_silent(self):
        self.assertNotIn("E_EMPTY_SIGNERS", _arms(_E_GUARDED))

    def test_unguarded_fires(self):
        self.assertIn("E_EMPTY_SIGNERS", _arms(_E_UNGUARDED))


# ---------------------------------------------------------------------------
# Rust/Go ARM N - fixed / zero AEAD IV (distinct from A5 untagged-discriminant)
# ---------------------------------------------------------------------------
_RS_FIXED_IV = """
pub fn encrypt(key: &Key, pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.encrypt(nonce, pt).unwrap()
}
"""
_RS_ROTATED_IV = """
pub fn encrypt(key: &Key, pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, pt).unwrap()
}
"""


class TestRustFixedIv(unittest.TestCase):
    def test_fixed_iv_fires(self):
        self.assertIn("N_FIXED_IV", _arms(_RS_FIXED_IV, "crypto.rs"))

    def test_rotated_iv_silent(self):
        self.assertNotIn("N_FIXED_IV", _arms(_RS_ROTATED_IV, "crypto.rs"))


# ---------------------------------------------------------------------------
# REAL fleet non-vacuity: morpho-blue Morpho.sol setAuthorizationWithSig
# ---------------------------------------------------------------------------
class TestRealFleetMorpho(unittest.TestCase):
    def setUp(self):
        if not _MORPHO.exists():
            self.skipTest("morpho fleet ws not present")
        self.src = _MORPHO.read_text()

    def test_benign_only_malleability(self):
        # Real site: EIP-712 domainSeparator + nonce[x]++ present (D, N silent);
        # raw ecrecover with no low-s (M fires). This is the true advisory.
        arms = _arms(self.src, "Morpho.sol")
        self.assertEqual(arms, ["M_NO_LOW_S"], arms)

    def test_mutate_drop_domain_separator_fires_D(self):
        mut = self.src.replace(
            'keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, '
            'hashStruct))',
            'keccak256(abi.encodePacked(hashStruct))')
        self.assertNotEqual(mut, self.src, "mutation must alter real source")
        self.assertIn("D_NO_DOMAIN_SEP", _arms(mut, "Morpho.sol"))

    def test_mutate_drop_nonce_bump_fires_N(self):
        mut = self.src.replace(
            "nonce[authorization.authorizer]++",
            "nonce[authorization.authorizer]")
        self.assertNotEqual(mut, self.src, "mutation must alter real source")
        self.assertIn("N_NONCE_NOT_BUMPED", _arms(mut, "Morpho.sol"))

    def test_byte_identical_restore(self):
        mut = self.src.replace(
            "nonce[authorization.authorizer]++",
            "nonce[authorization.authorizer]")
        restored = mut.replace(
            "nonce[authorization.authorizer]",
            "nonce[authorization.authorizer]++")
        self.assertEqual(restored, self.src)


# ---------------------------------------------------------------------------
# plumbing: masking, sidecar, summary, exclusion, strict
# ---------------------------------------------------------------------------
_COMMENTED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    // function verify(bytes32 d, uint8 v, bytes32 r, bytes32 s, address a) external {
    //     require(ecrecover(d, v, r, s) == a);
    // }
    uint256 public x;
    function go() external { x = 1; }
}
"""


class TestPlumbing(unittest.TestCase):
    def test_commented_is_silent(self):
        self.assertEqual(_scan(_COMMENTED), [])

    def test_row_schema(self):
        r = _scan(_D_UNGUARDED)[0]
        self.assertEqual(r["schema"], M.HYP_SCHEMA)
        self.assertEqual(r["capability"], "GEN_EL4")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        self.assertIn(r["arm"], (
            "domain-sep-absent", "nonce-reuse", "malleability-low-s",
            "empty-signer-array"))

    def test_summary_shape(self):
        s = M._summary(_scan(_D_UNGUARDED))
        self.assertGreaterEqual(s["fired"], 1)
        self.assertEqual(s["verdict"], "needs-fuzz")
        self.assertTrue(s["advisory"])

    def test_workspace_scan_emits_sidecar_and_strict(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "C.sol").write_text(_D_UNGUARDED)
            rc = M.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)  # advisory default exit 0
            side = ws / ".auditooor" / M._SIDE_NAME
            self.assertTrue(side.exists())
            lines = [l for l in side.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["capability"], "GEN_EL4")
            # strict elevates exit when a row fired.
            self.assertEqual(M.main(["--workspace", str(ws), "--strict"]), 1)

    def test_test_file_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "C.t.sol").write_text(_D_UNGUARDED)
            M.main(["--workspace", str(ws)])
            side = ws / ".auditooor" / M._SIDE_NAME
            lines = [l for l in side.read_text().splitlines() if l.strip()] \
                if side.exists() else []
            self.assertEqual(lines, [])


if __name__ == "__main__":
    unittest.main()
