#!/usr/bin/env python3
"""Check #26 regressions for mock-PoC contamination gating.

PR #124 / Base Azul FN-5 + FN-6 lesson: a passing harness with a hardcoded
verifier success cannot support permissionless attacker claims. High/Critical
findings whose PoC cites a suspicious mock (verifier / oracle / portal /
registry / proof / signature / messenger / bridge / dispute-game / harness with
verification shortcut, hardcoded `returns true`, or seeded proof state) MUST
include a `## Real-Component Precondition` section explaining:
  (1) what the mock replaces in production,
  (2) why reaching the branch is in-scope (not requiring prover / project /
      off-chain compromise),
  (3) what severity remains if the real component blocks reachability.

Medium severity gets a warning (rc=0). Benign MockERC20 / MockToken /
MockSystemConfig fixtures must pass cleanly.
"""
from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _run_pre_submit(draft: Path, severity: str = "Critical") -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True,
        text=True,
    )


class Check26MockPreconditionTests(unittest.TestCase):
    def test_fn5_style_mockverifier_without_section_fails(self) -> None:
        """FN-5-style: High/Critical + MockVerifier + no section → Check #26 hard fail.

        We assert on Check #26's specific line, not the overall pre-submit rc,
        because synthetic fixtures may fail other unrelated checks (PoC,
        originality grep, etc.). Check #26's hard-fail signature is the
        `26. mock-poc-contamination:` line (without `-warning`).
        """
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "fn5_like.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Mocked verifier proves bridge drain finalizes against poisoned grandchild

                    **Severity:** Critical

                    **Rubric:** Direct theft of user funds.
                    **Dollar impact:** Base bridge TVL at risk.

                    ## Impact

                    OptimismPortal2 finalizes against a poisoned descendant. The
                    PoC harness uses `MockVerifier` to short-circuit proof
                    verification and demonstrate downstream bridge drain.

                    ## Poisoned State Creation Path

                    The attacker plants the poisoned root via an in-scope
                    permissionless on-chain trigger; the contract bug accepts
                    it and the descendant is finalized.

                    ```solidity
                    contract MockVerifier is IVerifier {
                        function verify(bytes calldata) external pure returns (bool) {
                            return true;
                        }
                    }
                    ```
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft, severity="Critical")
            self.assertIn(
                "26. mock-poc-contamination:",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn(
                "26. mock-poc-contamination-warning",
                proc.stdout,
                "expected hard fail, got warning",
            )
            self.assertIn("Real-Component Precondition", proc.stdout)

    def test_fn6_style_hardcoded_returns_true_fails(self) -> None:
        """FN-6-style: High + hardcoded `returns true` verifier + no section → fail."""
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "fn6_like.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Verifier nullified flag has no reset path — protocol-wide liveness loss

                    **Severity:** High

                    **Rubric:** Temporary freezing of bridge operations.
                    **Dollar impact:** $500,000 of locked withdrawals.

                    ## Impact

                    Once `Verifier.nullified` is true the entire bridge fast
                    path stalls. PoC uses a stub verifier with a hardcoded
                    success path to keep the test deterministic.

                    ## In-Scope Trigger / Root Cause

                    The attacker calls `Verifier.nullify()` from a proper /
                    respected AggregateVerifier clone. Permissionless on-chain
                    trigger; no prover or admin compromise required.

                    ```solidity
                    contract StubVerifier is IVerifier {
                        function verify(bytes calldata, bytes32) external pure returns (bool) {
                            return true;
                        }
                    }
                    ```
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft, severity="High")
            self.assertIn(
                "26. mock-poc-contamination:",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn(
                "26. mock-poc-contamination-warning",
                proc.stdout,
                "expected hard fail, got warning",
            )

    def test_fn_b_style_real_components_passes(self) -> None:
        """FN-B-style: Medium + real AnchorStateRegistry trigger via guardian
        retirement, no suspicious verifier mock → pass."""
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "fn_b_like.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Stale anchor after guardian retires the active dispute game

                    **Severity:** Medium

                    **Rubric:** Functional impact on protocol bookkeeping.
                    **Dollar impact:** Conservative ~$0 direct, liveness only.

                    ## Impact

                    AnchorStateRegistry retains the prior anchor when the
                    guardian retires the active dispute game; the next
                    finalization runs against a stale ancestor.

                    ## In-Scope Trigger / Root Cause

                    The PoC drives the real `AnchorStateRegistry`,
                    `DisputeGameFactory`, and `OptimismPortal2`. Only
                    `MockSystemConfig` is used as a deployment-convenience
                    stand-in for the L1 system config; no proof verifier or
                    portal is mocked.

                    ```solidity
                    // Real production verifier and portal are used.
                    AnchorStateRegistry registry = new AnchorStateRegistry(...);
                    OptimismPortal2 portal = new OptimismPortal2(...);
                    MockSystemConfig systemConfig = new MockSystemConfig();
                    ```
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft, severity="Medium")
            self.assertIn(
                "26. Mock-PoC contamination gate:",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn("26. mock-poc-contamination:", proc.stdout)
            self.assertNotIn("26. mock-poc-contamination-warning", proc.stdout)

    def test_benign_mockerc20_passes(self) -> None:
        """High severity with only MockERC20 → pass (deployment convenience)."""
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "benign_mock.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug lets attacker steal user funds

                    **Severity:** High

                    **Rubric:** Direct theft of any user funds.
                    **Dollar impact:** $500,000 of user funds.

                    ## Impact

                    Reentrant `withdraw()` updates accounting after the
                    external transfer, allowing double-spend.

                    ## In-Scope Trigger / Root Cause

                    Permissionless on-chain trigger via `withdraw()`; no
                    privileged role, no prover, no off-chain dependency.
                    The PoC uses `MockERC20` as the underlying asset for
                    test convenience; the bug is in the vault accounting
                    code itself, not in any token shortcut.

                    ```solidity
                    MockERC20 token = new MockERC20("Test", "TST", 18);
                    vault.deposit(token, 100e18);
                    ```
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft, severity="High")
            self.assertIn(
                "26. Mock-PoC contamination gate:",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn("26. mock-poc-contamination:", proc.stdout)
            self.assertNotIn("26. mock-poc-contamination-warning", proc.stdout)

    def test_fn6_real_md_clean_cited_poc_dirty_fails(self) -> None:
        """PR #124 Slice 1 (Path A): submission .md is clean but the cited
        PoC test file (`FN6_PoC.t.sol`) imports `MockVerifier` /
        `FixedMockVerifier` → Check #26 must hard-fail.

        Mirrors the real FN-6 contamination: the .md alone passes the
        original gate (no suspicious-mock token in the markdown), so without
        the cited-file scan extension the contamination would slip through.
        We assert two things in one test:

          (1) The .md *alone* (no cited PoC, or cited PoC missing) does NOT
              hard-fail Check #26 — proves the original gate would have
              passed.
          (2) With the dirty cited PoC on disk and referenced by the .md,
              Check #26 hard-fails citing `cited PoC: FN6_PoC.t.sol`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            poc = tmp_path / "FN6_PoC.t.sol"
            poc.write_text(
                textwrap.dedent(
                    """
                    // SPDX-License-Identifier: MIT
                    pragma solidity ^0.8.20;

                    import "./MockVerifier.sol";

                    contract FN6Test {
                        FixedMockVerifier internal v;

                        function setUp() public {
                            v = new FixedMockVerifier();
                        }

                        function test_bridge_drain() public {
                            // exercises bridge drain assuming verifier
                            // returns true under the FixedMockVerifier
                        }
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            draft = tmp_path / "fn6_clean_md_dirty_poc.md"
            draft_body = textwrap.dedent(
                f"""
                # Verifier nullified flag has no reset path — protocol-wide liveness loss

                **Severity:** High

                **Rubric:** Temporary freezing of bridge operations.
                **Dollar impact:** $500,000 of locked withdrawals.

                ## Impact

                Once `Verifier.nullified` is true the entire bridge fast
                path stalls. The PoC drives the real `Verifier` and the
                real `OptimismPortal2` to demonstrate liveness loss.

                ## In-Scope Trigger / Root Cause

                The attacker calls `Verifier.nullify()` from a proper /
                respected AggregateVerifier clone. Permissionless on-chain
                trigger; no prover or admin compromise required.

                ## PoC

                See `{poc}` for the harness.
                """
            ).strip() + "\n"
            draft.write_text(draft_body, encoding="utf-8")

            # (1) Sanity: the .md content alone (no .t.sol citation) would
            # have passed the original gate. We re-write the draft with the
            # PoC reference stripped, run pre-submit, and assert no Check #26
            # contamination fail. This is the assertion that proves the
            # cited-file scan is what makes the FN-6-style fixture fail.
            clean_only_draft = tmp_path / "fn6_md_only.md"
            clean_only_draft.write_text(
                draft_body.replace(
                    f"See `{poc}` for the harness.",
                    "PoC drives the real `Verifier` directly; no test file cited.",
                ),
                encoding="utf-8",
            )
            proc_clean = _run_pre_submit(clean_only_draft, severity="High")
            self.assertNotIn(
                "26. mock-poc-contamination:",
                proc_clean.stdout,
                "draft without cited PoC must NOT fail Check #26 — that "
                "would mean the .md alone is dirty and the cited-PoC scan "
                "is not what's catching FN-6:\n" + proc_clean.stdout,
            )

            # (2) With the cited PoC on disk and referenced from the .md,
            # Check #26 must hard-fail and the result line must mention the
            # cited PoC source.
            proc = _run_pre_submit(draft, severity="High")
            self.assertIn(
                "26. mock-poc-contamination:",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn(
                "26. mock-poc-contamination-warning",
                proc.stdout,
                "expected hard fail (cited PoC dirty), got warning",
            )
            self.assertIn(
                "cited PoC: FN6_PoC.t.sol",
                proc.stdout,
                "Check #26 must surface which cited PoC tripped the gate; "
                "got:\n" + proc.stdout,
            )

    def test_medium_suspicious_mock_warns_without_blocking(self) -> None:
        """Medium severity + suspicious mock + no section → warning (rc=0)."""
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "medium_suspicious.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Oracle staleness lets stale price affect liquidation gating

                    **Severity:** Medium

                    **Rubric:** Functional impact on liquidation eligibility.
                    **Dollar impact:** ~$10,000 worst case before correction.

                    ## Impact

                    The contract uses a Chainlink oracle but does not bound
                    `updatedAt`. PoC uses a `MockOracle` to drive a stale
                    timestamp into the liquidation path.

                    ```solidity
                    contract MockOracle {
                        int256 public answer;
                        function setResolvedPrice(int256 a) external { answer = a; }
                        function latestRoundData() external view returns (
                            uint80, int256, uint256, uint256, uint80
                        ) {
                            return (0, answer, 0, 0, 0);
                        }
                    }
                    ```
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft, severity="Medium")
            # Medium + suspicious mock + no section → warning, NOT hard fail.
            # rc may still be non-zero due to other unrelated checks on the
            # synthetic fixture; assert on Check #26's specific signature.
            self.assertIn(
                "26. mock-poc-contamination-warning",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn("26. mock-poc-contamination:", proc.stdout)


if __name__ == "__main__":
    unittest.main()
