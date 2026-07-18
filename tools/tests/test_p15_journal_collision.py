#!/usr/bin/env python3
"""Lock test for P-15 journal_collision_at_boundary_config.

Source: Base-Azul engagement-3 FN-3 (AggregateVerifier.sol:548-602). Two
functions (``verifyProposalProof`` and ``nullify``) use ``abi.encodePacked``
for semantically different journal preimages. If a config value can make the
two schemas produce byte-identical output (an N=1 boundary collision),
cross-operation forgery becomes possible.

Positive fixture: two functions both call abi.encodePacked with no leading
domain-tag — scanner flags.

Hard-negative #1: functions use a leading bytes1/string domain tag
("PROPOSAL(...)" vs "NULLIFY(...)"). Scanner must NOT flag.

Hard-negative #2: a contract that uses abi.encodePacked in only ONE function
must NOT flag (keeps the scanner from devolving into "any encodePacked").
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "journal-collision-scanner.py"


def _run(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(path), "--json"],
        capture_output=True,
        text=True,
    )


class P15JournalCollisionTests(unittest.TestCase):
    def test_flags_two_encode_calls_without_domain_tag(self) -> None:
        """AggregateVerifier verifyProposalProof + nullify shape — must flag."""
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "AggregateVerifier.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract AggregateVerifier {
                        function verifyProposalProof(
                            bytes32 parent,
                            bytes32 leaf,
                            uint256 nonce
                        ) external view returns (bytes memory) {
                            return abi.encodePacked(parent, leaf, nonce);
                        }

                        function nullify(
                            bytes32 parent,
                            bytes32 leaf,
                            uint256 nonce
                        ) external view returns (bytes memory) {
                            return abi.encodePacked(parent, leaf, nonce);
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(len(out["findings"]), 1, out)
            finding = out["findings"][0]
            self.assertEqual(finding["contract"], "AggregateVerifier")
            self.assertIn("verifyProposalProof", finding["functions"])
            self.assertIn("nullify", finding["functions"])

    def test_does_not_flag_when_domain_tag_prefixes_both_preimages(self) -> None:
        """Counter-fixture #1: both preimages start with a selector-style tag."""
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "AggregateVerifier.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract AggregateVerifier {
                        function verifyProposalProof(
                            bytes32 parent,
                            bytes32 leaf,
                            uint256 nonce
                        ) external view returns (bytes memory) {
                            return abi.encodePacked("PROPOSAL(bytes32,bytes32,uint256)", parent, leaf, nonce);
                        }

                        function nullify(
                            bytes32 parent,
                            bytes32 leaf,
                            uint256 nonce
                        ) external view returns (bytes memory) {
                            return abi.encodePacked("NULLIFY(bytes32,bytes32,uint256)", parent, leaf, nonce);
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)

    def test_two_single_fn_contracts_clean(self) -> None:
        """Codex review #2 regression: two unrelated contracts that each
        contain ONE ``abi.encodePacked`` must NOT trigger the
        >=2-functions check. Aggregation has to be per-contract, not
        per-file.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "TwoContracts.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract A {
                        function foo(bytes32 x) external pure returns(bytes32){
                            return keccak256(abi.encodePacked(x));
                        }
                    }
                    contract B {
                        function bar(bytes32 y) external pure returns(bytes32){
                            return keccak256(abi.encodePacked(y));
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)

    def test_hard_negative_only_one_function_uses_encode(self) -> None:
        """Hard-negative #2: a single function that uses abi.encodePacked
        must not trip the >=2-function requirement. This keeps the scanner
        from devolving into 'any encodePacked is a collision'."""
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "LoneHash.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract LoneHash {
                        function leaf(bytes32 a, bytes32 b) external pure returns (bytes32) {
                            return keccak256(abi.encodePacked(a, b));
                        }

                        function other(uint256 x) external pure returns (uint256) {
                            return x + 1;
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)

    def test_hard_negative_abi_encode_only_does_not_trigger(self) -> None:
        """Codex review round 2 (#117 follow-up): abi.encode calls are
        length-prefixed and NOT the preimage-collision shape. A contract with
        ONE tag-less abi.encodePacked helper plus unrelated safe abi.encode
        calls must NOT produce a finding — only abi.encodePacked counts toward
        the >=2 distinct functions trigger.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "SafeMixed.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract SafeMixed {
                        function packedHelper(bytes32 x) external pure returns(bytes32){
                            return keccak256(abi.encodePacked(x));
                        }
                        function safeA(bytes32 x, uint256 y) external pure returns(bytes32){
                            return keccak256(abi.encode(x, y));
                        }
                        function safeB(address a, bytes32 z) external pure returns(bytes32){
                            return keccak256(abi.encode(a, z));
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(
                out["findings"],
                [],
                f"SafeMixed has 1 packed + 2 abi.encode — must NOT flag. got: {out}",
            )

    def test_two_packed_trigger_but_abi_encode_listed_as_context(self) -> None:
        """Codex review round 2 (#117 follow-up): when >=2 tag-less packed
        preimages trigger the finding, any abi.encode-only functions in the
        same contract must appear as ``context_abi_encode_functions`` context
        but NOT as a trigger function.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "MixedTrigger.sol"
            sol.write_text(
                textwrap.dedent(
                    """
                    contract MixedTrigger {
                        function proposalHash(bytes32 x, bytes32 y) external pure returns(bytes32){
                            return keccak256(abi.encodePacked(x, y));
                        }
                        function nullifyHash(bytes32 x, bytes32 y) external pure returns(bytes32){
                            return keccak256(abi.encodePacked(x, y));
                        }
                        function safeHelper(address a, uint256 v) external pure returns(bytes32){
                            return keccak256(abi.encode(a, v));
                        }
                    }
                    """
                ).strip()
                + "\n"
            )

            proc = _run(sol)
            # Positive fixture — scanner exits 1 when findings exist.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(len(out["findings"]), 1, out)
            finding = out["findings"][0]
            # trigger functions are only the packed ones
            self.assertEqual(
                sorted(finding["functions"]),
                ["nullifyHash", "proposalHash"],
            )
            # abi.encode function listed only as context, not trigger
            self.assertEqual(
                finding.get("context_abi_encode_functions"),
                ["safeHelper"],
            )


if __name__ == "__main__":
    unittest.main()
