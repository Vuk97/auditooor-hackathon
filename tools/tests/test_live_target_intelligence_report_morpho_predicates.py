#!/usr/bin/env python3
"""Focused Morpho/Solidity semantic predicate coverage tests."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_TOOL_PATH = _ROOT / "tools" / "live-target-intelligence-report.py"
_SPEC = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_morpho_predicates",
    _TOOL_PATH,
)
ltir_mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC is not None and _SPEC.loader is not None
_SPEC.loader.exec_module(ltir_mod)


class MorphoPredicateCoverageTests(unittest.TestCase):
    def _semantic(self, cluster_id: str, inv_id: str, source: str, *, snippet: str = "") -> list[str]:
        return ltir_mod._semantic_p1_matches(
            cluster_id,
            matched_p1=[inv_id],
            file_line="src/MorphoPredicate.sol:1",
            snippet=snippet,
            source_context=source,
            source_contract_context=source,
        )

    def test_selected_breadth_invariants_are_available_despite_audited_key(self) -> None:
        p1_index = ltir_mod._load_p1_invariants(_ROOT)
        self.assertIn("INV-BND-006", p1_index["bounds|solidity"])
        self.assertIn("INV-CON-002", p1_index["conservation|solidity"])
        self.assertIn("INV-ORD-008", p1_index["ordering|solidity"])

    def test_erc4626_first_depositor_slug_resolves_to_erc4626(self) -> None:
        self.assertEqual(
            ltir_mod._resolve_cluster_category("erc4626-first-depositor-no-min-check"),
            ("erc4626", "custody-and-accounting"),
        )

    def test_erc4626_mutable_entrypoint_without_bound_is_semantic(self) -> None:
        source = """
        contract Vault {
          function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
            shares = _convertToShares(assets);
            _deposit(msg.sender, receiver, assets, shares);
          }
        }
        """
        self.assertEqual(
            self._semantic("erc4626-first-depositor-no-min-check", "INV-ERC4626-001", source),
            ["INV-ERC4626-001"],
        )

    def test_erc4626_bound_rejects_semantic_match(self) -> None:
        source = """
        contract Vault {
          function deposit(uint256 assets, address receiver, uint256 minShares) public returns (uint256 shares) {
            shares = _convertToShares(assets);
            require(shares >= minShares, "slippage");
            _deposit(msg.sender, receiver, assets, shares);
          }
        }
        """
        self.assertEqual(
            self._semantic("erc4626-first-depositor-no-min-check", "INV-ERC4626-001", source),
            [],
        )

    def test_exact_transfer_assumption_requires_balance_delta_accounting(self) -> None:
        vulnerable = """
        contract Adapter {
          function transferFrom2(address asset, uint256 amount) external {
            Permit2Lib.PERMIT2.transferFrom(msg.sender, address(this), amount.toUint160(), asset);
            assets += amount;
          }
        }
        """
        fixed = """
        contract Adapter {
          function transferFrom2(IERC20 asset, uint256 amount) external {
            uint256 balanceBefore = asset.balanceOf(address(this));
            asset.safeTransferFrom(msg.sender, address(this), amount);
            uint256 balanceAfter = asset.balanceOf(address(this));
            uint256 received = balanceAfter - balanceBefore;
            assets += received;
          }
        }
        """
        self.assertEqual(
            self._semantic("fee-on-transfer-not-accounted", "INV-CON-002", vulnerable),
            ["INV-CON-002"],
        )
        self.assertEqual(self._semantic("fee-on-transfer-not-accounted", "INV-CON-002", fixed), [])

    def test_post_transfer_erc4626_share_conversion_is_ordering_match(self) -> None:
        vulnerable = """
        contract Vault {
          function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
            asset.safeTransferFrom(msg.sender, address(this), assets);
            shares = convertToShares(assets);
            _mint(receiver, shares);
          }
        }
        """
        fixed = """
        contract Vault {
          function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
            shares = convertToShares(assets);
            asset.safeTransferFrom(msg.sender, address(this), assets);
            _mint(receiver, shares);
          }
        }
        """
        self.assertEqual(
            self._semantic("erc4626-first-depositor-no-min-check", "INV-ORD-008", vulnerable),
            ["INV-ORD-008"],
        )
        self.assertEqual(self._semantic("erc4626-first-depositor-no-min-check", "INV-ORD-008", fixed), [])

    def test_adapter_allocation_without_cap_guard_is_semantic(self) -> None:
        vulnerable = """
        contract Allocator {
          mapping(bytes32 => uint256) allocation;
          function allocate(bytes32 id, uint256 assets) external {
            allocation[id] += assets;
            adapter.allocate(assets);
          }
        }
        """
        fixed = """
        contract Allocator {
          mapping(bytes32 => uint256) allocation;
          mapping(bytes32 => uint256) cap;
          function allocate(bytes32 id, uint256 assets) external {
            allocation[id] += assets;
            require(allocation[id] <= cap[id], "cap");
            adapter.allocate(assets);
          }
        }
        """
        self.assertEqual(
            self._semantic("adapter-cap-allocation", "INV-BND-006", vulnerable),
            ["INV-BND-006"],
        )
        self.assertEqual(self._semantic("adapter-cap-allocation", "INV-BND-006", fixed), [])

    def test_eip712_signature_nonce_predicate_keeps_domain_and_nonce_together(self) -> None:
        vulnerable = """
        contract PermitLike {
          bytes32 DOMAIN_SEPARATOR;
          function setAuthorizationWithSig(bytes32 digest, bytes calldata sig) external {
            address signer = ECDSA.recover(_hashTypedDataV4(digest), sig);
            isAuthorized[signer][msg.sender] = true;
          }
        }
        """
        fixed = """
        contract PermitLike {
          bytes32 DOMAIN_SEPARATOR;
          mapping(address => uint256) nonce;
          function setAuthorizationWithSig(Authorization memory authorization, Signature calldata signature) external {
            require(authorization.nonce == nonce[authorization.authorizer]++, "nonce");
            bytes32 digest = keccak256(bytes.concat(hex"1901", DOMAIN_SEPARATOR, keccak256(abi.encode(authorization))));
            address signer = ecrecover(digest, signature.v, signature.r, signature.s);
            isAuthorized[signer][msg.sender] = true;
          }
        }
        """
        self.assertEqual(
            self._semantic("signature-without-nonce", "INV-UNI-002", vulnerable),
            ["INV-UNI-002"],
        )
        self.assertEqual(self._semantic("signature-without-nonce", "INV-UNI-002", fixed), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
