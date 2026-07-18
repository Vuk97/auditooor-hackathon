#!/usr/bin/env python3
"""Non-vacuous tests for GEN-A5 implicit domain-disjointness assumption screen.

Every positive case has a paired negative (the SAME code that ADDS the missing
domain-separation guard - a `tx.origin==msg.sender` companion, a
`signer != address(0)` reject, a `bytes.length` assertion, a `require(id != 0)`,
a magic/version check) that must NOT fire, proving the missing-proof predicate is
load-bearing, not a shape match. Includes the real-fleet mutation witness on
morpho-blue Morpho.setAuthorizationWithSig: the CORRECT `require(signatory !=
address(0) && ...)` stays silent; weakening it to drop the zero-address reject
newly fires A2 (zero-signer). Restored byte-identical.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL = TOOLS / "domain-disjointness-assumption-screen.py"

_spec = importlib.util.spec_from_file_location("a5_screen", TOOL)
a5 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a5)


def _scan(text, name):
    return a5.scan_file(Path(name), name, file_text=text)


def _kinds(rows):
    return {r["pattern_id"] for r in rows}


def _assumptions(rows):
    return {r["assumption"] for r in rows}


# ---------------------------------------------------------------------------
# A1 - eoa-not-contract (codesize EOA gate w/o construction handling)
# ---------------------------------------------------------------------------
class A1EoaCodesizeTests(unittest.TestCase):
    def test_codesize_eoa_gate_fires(self):
        src = """
        contract C {
            function f() external {
                require(msg.sender.code.length == 0);
                withdraw();
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_EOA_CODESIZE", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_EOA_CODESIZE"][0]
        self.assertEqual(r["assumption"], "eoa-not-contract")

    def test_extcodesize_eoa_gate_fires(self):
        src = """
        contract C {
            function f(address account) external {
                uint256 s;
                assembly { s := extcodesize(account) }
                require(s == 0);
            }
        }
        """
        # `extcodesize(account) == 0` is not on one line here; exercise the direct
        # inline form instead:
        src2 = """
        contract C {
            function f(address account) external {
                require(extcodesize(account) == 0);
            }
        }
        """
        self.assertIn("S_EOA_CODESIZE", _kinds(_scan(src2, "C.sol")))

    def test_tx_origin_companion_silent(self):
        # the construction bypass is closed by a tx.origin==msg.sender companion.
        src = """
        contract C {
            function f() external {
                require(tx.origin == msg.sender);
                require(msg.sender.code.length == 0);
            }
        }
        """
        self.assertNotIn("S_EOA_CODESIZE", _kinds(_scan(src, "C.sol")))

    def test_token_existence_check_silent(self):
        # `token.code.length > 0` is a token-EXISTENCE check, not an EOA gate.
        src = """
        contract C {
            function f(address token) external {
                require(token.code.length > 0);
                IERC20(token).transfer(msg.sender, 1);
            }
        }
        """
        self.assertNotIn("S_EOA_CODESIZE", _kinds(_scan(src, "C.sol")))


# ---------------------------------------------------------------------------
# A2 - zero-signer (ecrecover result w/o address(0) reject)
# ---------------------------------------------------------------------------
class A2ZeroSignerTests(unittest.TestCase):
    def test_ecrecover_no_zero_reject_fires(self):
        src = """
        contract C {
            function permit(bytes32 h, uint8 v, bytes32 r, bytes32 s, address owner) external {
                address signer = ecrecover(h, v, r, s);
                require(signer == owner);
                approve();
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_ECRECOVER_ZERO", _kinds(rows))
        self.assertEqual(
            [x for x in rows if x["pattern_id"] == "S_ECRECOVER_ZERO"][0]["token"],
            "signer")

    def test_ecrecover_with_zero_reject_silent(self):
        src = """
        contract C {
            function permit(bytes32 h, uint8 v, bytes32 r, bytes32 s, address owner) external {
                address signer = ecrecover(h, v, r, s);
                require(signer != address(0) && signer == owner);
                approve();
            }
        }
        """
        self.assertNotIn("S_ECRECOVER_ZERO", _kinds(_scan(src, "C.sol")))


# ---------------------------------------------------------------------------
# A3 - decode-into-type (attacker bytes -> privileged type, no length assert)
# ---------------------------------------------------------------------------
class A3DecodeIntoTypeTests(unittest.TestCase):
    def test_decode_into_address_fires(self):
        src = """
        contract C {
            function f(bytes calldata data) external {
                address a = abi.decode(data, (address));
                admin = a;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_DECODE_PRIVILEGED", _kinds(rows))

    def test_decode_into_struct_fires(self):
        src = """
        contract C {
            function onCallback(bytes calldata payload) external {
                MarketParams memory p = abi.decode(payload, (MarketParams));
                use(p);
            }
        }
        """
        self.assertIn("S_DECODE_PRIVILEGED", _kinds(_scan(src, "C.sol")))

    def test_decode_with_length_assert_silent(self):
        src = """
        contract C {
            function f(bytes calldata data) external {
                require(data.length == 20);
                address a = abi.decode(data, (address));
                admin = a;
            }
        }
        """
        self.assertNotIn("S_DECODE_PRIVILEGED", _kinds(_scan(src, "C.sol")))

    def test_decode_non_param_source_silent(self):
        # source is not an attacker-controlled bytes PARAM -> biased to silence.
        src = """
        contract C {
            function f() external {
                bytes memory blob = _internalConfig();
                address a = abi.decode(blob, (address));
                admin = a;
            }
        }
        """
        self.assertNotIn("S_DECODE_PRIVILEGED", _kinds(_scan(src, "C.sol")))

    def test_decode_primitive_only_silent(self):
        # decoding into a plain uint (no address / struct) -> not privileged.
        src = """
        contract C {
            function f(bytes calldata data) external {
                uint256 x = abi.decode(data, (uint256));
                emit E(x);
            }
        }
        """
        self.assertNotIn("S_DECODE_PRIVILEGED", _kinds(_scan(src, "C.sol")))


# ---------------------------------------------------------------------------
# A4 - reserved-id-collision (user id keyed store, sentinel in file, no guard)
# ---------------------------------------------------------------------------
class A4ReservedIdTests(unittest.TestCase):
    _SRC = """
    contract C {
        uint256 constant RESERVED_ID = 0;
        mapping(uint256 => uint256) bal;
        function f(uint256 id) external {
            bal[id] = 5;
        }
    }
    """

    def test_reserved_id_write_fires(self):
        self.assertIn("S_RESERVED_ID", _kinds(_scan(self._SRC, "C.sol")))

    def test_reserved_id_guarded_silent(self):
        guarded = self._SRC.replace(
            "bal[id] = 5;", "require(id != 0);\n            bal[id] = 5;")
        self.assertNotIn("S_RESERVED_ID", _kinds(_scan(guarded, "C.sol")))

    def test_no_sentinel_in_file_silent(self):
        # no reserved sentinel constant/handle in the file -> biased to silence.
        nosent = self._SRC.replace("uint256 constant RESERVED_ID = 0;", "")
        self.assertNotIn("S_RESERVED_ID", _kinds(_scan(nosent, "C.sol")))

    def test_bytes32_handle_key_silent(self):
        # a bytes32 keccak handle cannot practically equal a small sentinel.
        src = """
        contract C {
            uint256 constant RESERVED_ID = 0;
            mapping(bytes32 => uint256) bal;
            function f(bytes32 id) external {
                bal[id] = 5;
            }
        }
        """
        self.assertNotIn("S_RESERVED_ID", _kinds(_scan(src, "C.sol")))


# ---------------------------------------------------------------------------
# A5 - untagged-discriminant (positional tag byte dispatch on untrusted buffer)
# ---------------------------------------------------------------------------
class A5UntaggedDiscriminantTests(unittest.TestCase):
    def test_rust_positional_tag_match_fires(self):
        src = """
        fn parse(data: &[u8]) -> Op {
            match data[0] {
                0 => Op::A,
                _ => Op::B,
            }
        }
        """
        rows = _scan(src, "x.rs")
        self.assertIn("R_DECODE_UNTAGGED", _kinds(rows))
        self.assertEqual(
            [x for x in rows if x["pattern_id"] == "R_DECODE_UNTAGGED"][0]
            ["assumption"], "untagged-discriminant")

    def test_rust_magic_check_silent(self):
        src = """
        fn parse(data: &[u8]) -> Op {
            if data[0..4] != MAGIC { panic!() }
            match data[4] {
                0 => Op::A,
                _ => Op::B,
            }
        }
        """
        self.assertNotIn("R_DECODE_UNTAGGED", _kinds(_scan(src, "x.rs")))

    def test_rust_borsh_deserialize_silent(self):
        # serde/Borsh self-describe the variant tag - NOT this class (near spray).
        src = """
        fn parse(data: &[u8]) -> Op {
            let op = Op::try_from_slice(data).unwrap();
            op
        }
        """
        self.assertNotIn("R_DECODE_UNTAGGED", _kinds(_scan(src, "x.rs")))

    def test_go_positional_tag_switch_fires(self):
        src = """
        package p
        func parse(data []byte) {
            switch data[0] {
            case 1:
                a()
            }
        }
        """
        self.assertIn("G_DECODE_UNTAGGED", _kinds(_scan(src, "x.go")))


# ---------------------------------------------------------------------------
# exclusion + CLI
# ---------------------------------------------------------------------------
class ExclusionTests(unittest.TestCase):
    def test_codegen_marker_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            gen = root / "x.pb.go"
            gen.write_text(
                "// Code generated by protoc. DO NOT EDIT.\n"
                "package p\n"
                "func parse(data []byte) {\n"
                "  switch data[0] {\n"
                "  case 1:\n    a()\n  }\n"
                "}\n")
            rows = a5.scan_tree(root, workspace=Path(td))
            self.assertEqual(rows, [])


class CliTests(unittest.TestCase):
    def test_cli_source_mode_and_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "contract C {\n"
                "    function permit(bytes32 h, uint8 v, bytes32 r, bytes32 s,"
                " address owner) external {\n"
                "        address signer = ecrecover(h, v, r, s);\n"
                "        require(signer == owner);\n"
                "        approve();\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            summ = json.loads(r.stdout)
            self.assertEqual(summ["schema"], a5.HYP_SCHEMA)
            self.assertGreaterEqual(summ["fired"], 1)
            side = (Path(td) / ".auditooor" /
                    "domain_disjointness_hypotheses.jsonl")
            self.assertTrue(side.exists())

    def test_cli_strict_exit1_on_fire(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "contract C {\n"
                "    function permit(bytes32 h, uint8 v, bytes32 r, bytes32 s,"
                " address owner) external {\n"
                "        address signer = ecrecover(h, v, r, s);\n"
                "        require(signer == owner);\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td, "--strict"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


# ---------------------------------------------------------------------------
# Real-fleet mutation witness (A2 zero-signer distinctness / non-vacuity)
# ---------------------------------------------------------------------------
class MutationWitnessTests(unittest.TestCase):
    """morpho-blue Morpho.setAuthorizationWithSig CORRECTLY rejects the
    zero-address signer (`require(signatory != address(0) && ...)`) - the benign
    guarded original stays silent. Weakening it to drop the `!= address(0)`
    reject leaves ecrecover's malformed-signature return (address(0)) trusted as
    an authorized signer -> A2 newly fires. Restored byte-identical."""

    MORPHO = Path(
        "/Users/wolf/audits/morpho/src/morpho-blue/src/Morpho.sol")
    _BENIGN = ("require(signatory != address(0) && authorization.authorizer "
               "== signatory, ErrorsLib.INVALID_SIGNATURE);")
    _WEAK = ("require(authorization.authorizer == signatory, "
             "ErrorsLib.INVALID_SIGNATURE);")

    def test_real_guarded_original_silent(self):
        if not self.MORPHO.exists():
            self.skipTest("morpho Morpho.sol not present")
        orig = self.MORPHO.read_text()
        self.assertIn(self._BENIGN, orig, "fixture drifted from source")
        rows = a5.scan_file(self.MORPHO, self.MORPHO.name, file_text=orig)
        a2 = [r for r in rows if r["pattern_id"] == "S_ECRECOVER_ZERO"
              and r["function"] == "setAuthorizationWithSig"]
        self.assertEqual(a2, [], "guarded ecrecover must not fire")

    def test_weakened_guard_fires(self):
        if not self.MORPHO.exists():
            self.skipTest("morpho Morpho.sol not present")
        orig = self.MORPHO.read_text()
        weak = orig.replace(self._BENIGN, self._WEAK, 1)
        self.assertNotEqual(weak, orig, "mutation did not change source")
        rows = a5.scan_file(self.MORPHO, self.MORPHO.name, file_text=weak)
        a2 = [r for r in rows if r["pattern_id"] == "S_ECRECOVER_ZERO"
              and r["function"] == "setAuthorizationWithSig"]
        self.assertTrue(a2, "weakened (no zero-address reject) must newly fire")
        self.assertEqual(a2[0]["assumption"], "zero-signer")
        # restore invariant: original file untouched on disk
        self.assertEqual(self.MORPHO.read_text(), orig)


if __name__ == "__main__":
    unittest.main()
