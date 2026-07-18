#!/usr/bin/env python3
"""Focused P1 auth predicate coverage, including tx.origin authorization."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_SPEC = importlib.util.spec_from_file_location("live_target_intelligence_report_auth", _TOOL_PATH)
ltir_mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC is not None and _SPEC.loader is not None
_SPEC.loader.exec_module(ltir_mod)


class _FakeSlitherModule:
    def __init__(self, labels: dict[str, bool], calls: list[str]) -> None:
        self._labels = labels
        self._calls = calls

    def check(self, function: object, label: str) -> bool:
        del function
        self._calls.append(label)
        return self._labels.get(label, False)


class _FakeSourceMapping:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeSlitherFunction:
    def __init__(self, content: str, name: str = "withdraw", visibility: str = "external") -> None:
        self.name = name
        self.visibility = visibility
        self.source_mapping = _FakeSourceMapping(content)


class AuthPredicateCoverageTests(unittest.TestCase):
    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "auth-coverage",
            matched_p1=[inv_id],
            file_line="src/AuthPredicate.sol:1",
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_inv_auth_010_positive_tx_origin_authorization(self) -> None:
        source = """
        contract TxOriginAuth {
          address owner;
          function withdraw() external {
            require(tx.origin == owner, "not owner");
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), ["INV-AUTH-010"])

    def test_inv_auth_010_positive_if_tx_origin_not_owner_revert(self) -> None:
        source = """
        contract TxOriginAuth {
          address owner;
          function withdraw() external {
            if (tx.origin != owner) revert NotOwner();
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), ["INV-AUTH-010"])

    def test_inv_auth_010_positive_if_tx_origin_not_owner_braced_revert(self) -> None:
        source = """
        contract TxOriginAuth {
          address owner;
          function withdraw() external {
            if (tx.origin != owner) {
              revert NotOwner();
            }
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), ["INV-AUTH-010"])

    def test_inv_auth_010_negative_require_tx_origin_not_attacker(self) -> None:
        source = """
        contract TxOriginAuth {
          address attacker;
          function withdraw() external {
            require(tx.origin != attacker, "not attacker");
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), [])

    def test_inv_auth_010_negative_string_literal_only(self) -> None:
        source = """
        contract TxOriginAuth {
          function withdraw() external {
            require(true, "tx.origin == owner");
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), [])

    def test_inv_auth_010_negative_if_tx_origin_equals_banned_revert(self) -> None:
        source = """
        contract TxOriginAuth {
          address banned;
          function withdraw() external {
            if (tx.origin == banned) revert Banned();
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), [])

    def test_inv_auth_010_negative_msg_sender_owner_authorization(self) -> None:
        source = """
        contract MsgSenderAuth {
          address owner;
          function withdraw() external {
            require(msg.sender == owner, "not owner");
          }
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), [])

    def test_inv_auth_010_negative_role_authorization(self) -> None:
        source = """
        contract RoleAuth {
          function withdraw() external onlyRole(GUARDIAN_ROLE) {}
        }
        """
        self.assertEqual(self._semantic("INV-AUTH-010", source), [])

    def test_inv_auth_010_slither_helper_consumes_reads_tx_origin(self) -> None:
        function_source = """
        function withdraw() external {
          require(tx.origin == owner, "not owner");
        }
        """
        calls: list[str] = []
        fake_module = _FakeSlitherModule({"reads_tx_origin": True}, calls)
        fake_function = _FakeSlitherFunction(function_source)
        with (
            mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module),
            mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ),
        ):
            self.assertTrue(ltir_mod._p1_predicate_auth_010(function_source, ""))
        self.assertIn("reads_tx_origin", calls)

    def test_inv_auth_010_does_not_promote_other_function_snippet(self) -> None:
        source_context = """
        contract MixedAuth {
          address owner;
          address banned;

          function gate() external {
            if (tx.origin != owner) revert NotOwner();
          }

          function withdraw() external {
            require(msg.sender != banned, "not banned");
          }
        }
        """
        source_contract_context = """
        contract MixedAuth {
          address owner;
          address banned;

          function withdraw() external {
            require(msg.sender != banned, "not banned");
          }
        }
        """
        self.assertEqual(
            ltir_mod._semantic_p1_matches(
                "auth-coverage",
                matched_p1=["INV-AUTH-010"],
                file_line="src/MixedAuth.sol:1",
                snippet='require(msg.sender != banned, "not banned");',
                source_context=source_context,
                source_contract_context=source_contract_context,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
