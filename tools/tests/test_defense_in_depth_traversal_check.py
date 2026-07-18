"""Unit tests for Rule 25 defense-in-depth traversal preflight."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "defense_in_depth_traversal_check",
    ROOT / "tools" / "defense-in-depth-traversal-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r25_defense_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests" / "case").mkdir(parents=True)
    return root


def _write(body: str, source: str | None = None, filename: str = "draft-HIGH.md") -> Path:
    root = _workspace()
    if source is not None:
        (root / "poc-tests" / "case" / "poc_test.go").write_text(source, encoding="utf-8")
        body += "\nPoC: `poc-tests/case`\n"
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


class DefenseInDepthTraversalTests(unittest.TestCase):
    def test_medium_severity_out_of_scope(self) -> None:
        draft = _write("Severity: MEDIUM\nmatching-engine degradation.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_no_downstream_trigger_out_of_scope(self) -> None:
        draft = _write("Severity: HIGH\nLocal accounting mismatch only.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_local_only_downstream_claim_fails(self) -> None:
        draft = _write(
            "Severity: HIGH\nmatching-engine degradation.",
            "package poc\nfunc TestX(t *testing.T){ k.ProcessSingleMatch(ctx, match) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-local-only-downstream-claim")

    def test_finalizeblock_traversal_passes(self) -> None:
        draft = _write(
            "Severity: HIGH\nmatching-engine degradation.",
            "package poc\nfunc TestX(t *testing.T){ app.BaseApp.FinalizeBlock(req) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-defense-traversal")

    def test_broadcast_tx_traversal_passes(self) -> None:
        draft = _write("Severity: CRITICAL\nfund loss.\nThe attack tx reaches DeliverTx after BroadcastTxSync.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-defense-traversal")

    def test_honest_walkback_passes(self) -> None:
        draft = _write("Severity: HIGH\nmatching-engine degradation. ValidateNestedMsg categorically rejected the tx; downgraded from HIGH to MEDIUM.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-honest-walkback")

    def test_rebuttal_passes(self) -> None:
        draft = _write("Severity: HIGH\nfund loss. <!-- r25-rebuttal: source-only impact path has no runtime defense layer -->")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_not_proven_scope_line_does_not_trigger(self) -> None:
        draft = _write("Severity: HIGH\nnot_proven: matching-engine degradation; chain halt.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_missing_file_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    # --- EVM / Solidity generalization ---

    def test_evm_traversal_passes(self) -> None:
        draft = _write(
            "Severity: HIGH\nmatching-engine degradation via the vault.\n"
            "Fork-test end-to-end: vm.prank as a non-privileged caller then the "
            "call lands; the payload passes onlyOwner and reaches the external call.",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-defense-traversal")

    def test_evm_local_only_high_claim_fails(self) -> None:
        draft = _write(
            "Severity: HIGH\nfund loss in the lending pool.",
            "// SPDX-License-Identifier: MIT\n"
            "contract T { function test() public {\n"
            "  // internal function called directly, unit test with no access-control caller\n"
            "  // vm.store slot-seeded, no fork\n"
            "} }\n",
        )
        # PoC file gets a .go suffix from the harness; embed smells in the draft body too.
        draft.write_text(
            draft.read_text(encoding="utf-8")
            + "\nThe PoC is a unit test with no access-control caller; no fork.\n",
            encoding="utf-8",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-local-only-downstream-claim")

    def test_evm_walkback_passes(self) -> None:
        draft = _write(
            "Severity: HIGH\nfund loss in the vault. The call reverts in the "
            "modifier; blocked by the access-control gate; downgraded from HIGH to MEDIUM.",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-honest-walkback")

    # --- Substrate generalization ---

    def test_substrate_traversal_passes(self) -> None:
        draft = _write(
            "Severity: CRITICAL\nfund loss in the staking pallet.\n"
            "The extrinsic is dispatched after it passes ensure_signed and "
            "survives the SignedExtension; construct_runtime dispatch reaches "
            "on_finalize.",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-defense-traversal")

    def test_substrate_walkback_passes(self) -> None:
        draft = _write(
            "Severity: HIGH\nnetwork-level liveness failure. The unsigned tx is "
            "rejected by validate_unsigned; blocked by the SignedExtension.",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-honest-walkback")

    # --- env-override hook ---

    def test_env_override_traversal_patterns(self) -> None:
        draft = _write(
            "Severity: HIGH\nfund loss.\nThe payload survives my_custom_guard_layer.",
        )
        os.environ["AUDITOOOR_R25_TRAVERSAL_PATTERNS"] = "survives my_custom_guard_layer"
        try:
            import importlib

            reloaded = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(reloaded)  # type: ignore[union-attr]
            rc, payload = reloaded.run(draft, strict=True)
        finally:
            del os.environ["AUDITOOOR_R25_TRAVERSAL_PATTERNS"]
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-defense-traversal")


if __name__ == "__main__":
    unittest.main(verbosity=2)
