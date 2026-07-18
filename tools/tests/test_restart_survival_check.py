"""Unit tests for Rule 22 restart-survival preflight."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "restart_survival_check",
    ROOT / "tools" / "restart-survival-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r22_restart_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    return root


def _write_case(body: str, source: str | None = None, source_name: str = "poc_test.go") -> Path:
    root = _workspace()
    if source is not None:
        d = root / "poc-tests" / "case"
        d.mkdir(parents=True)
        (d / source_name).write_text(source, encoding="utf-8")
        body += "\nPoC: `poc-tests/case`\n"
    draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
    draft.write_text(body, encoding="utf-8")
    return draft


class RestartSurvivalTests(unittest.TestCase):
    def test_no_persistence_trigger_out_of_scope(self) -> None:
        draft = _write_case("Severity: HIGH\nTemporary matching engine degradation.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_permanent_freezing_without_restart_evidence_fails(self) -> None:
        draft = _write_case("Severity: HIGH\nSelected impact: permanent freezing of funds.")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-restart-survival")

    def test_restart_named_test_passes(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nThe bug causes chain halt.",
            "package poc\nfunc TestProtocol_AbBa_RestartSurvival(t *testing.T) {}\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_close_reopen_pattern_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nPersistent AppHash divergence.",
            "package poc\nfunc TestX(t *testing.T){ db.Close(); tree := NewMutableTree(OpenDB()) ; _ = tree }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_phase_restart_scaffold_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nBlock production halt.",
            "PHASE 1 seed on disk\nsome text\nPHASE 2 restart and reopen same store\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_honest_restart_heals_disclosure_passes_nonstrict(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nNetwork halt claim. A process restart clears the staleness; no persistent durability divergence."
        )
        rc, payload = mod.run(draft, strict=False)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-honest-disclosure")

    def test_honest_restart_heals_disclosure_fails_strict(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nNetwork halt claim. A process restart clears the staleness; no persistent durability divergence."
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-strict-contradiction")

    def test_rebuttal_passes(self) -> None:
        draft = _write_case("Chain halt. <!-- r22-rebuttal: halt means local process exit, not persistence -->")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_not_proven_scope_line_does_not_trigger(self) -> None:
        draft = _write_case("Severity: CRITICAL\nnot_proven: chain halt; permanent freezing.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_missing_file_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    # --- Rust restart-survival evidence -----------------------------------
    def test_rust_sled_drop_reopen_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nPersistent durability divergence in the substrate store.",
            "fn reproduce() {\n"
            "    let db = sled::open(path).unwrap();\n"
            "    db.insert(b\"k\", b\"v\").unwrap();\n"
            "    drop(db);\n"
            "    let db = sled::open(path).unwrap();\n"
            "    assert_eq!(db.get(b\"k\").unwrap(), None);\n"
            "}\n",
            source_name="poc.rs",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_rust_rocksdb_flush_reopen_passes(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nThe bug causes a chain halt requiring hardfork.",
            "fn corrupt_store() {\n"
            "    db.flush().unwrap();\n"
            "    let db = rocksdb::DB::open_default(path).unwrap();\n"
            "}\n",
            source_name="poc.rs",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_rust_restart_named_fn_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nPermanent freezing of funds.",
            "#[test]\nfn store_state_after_restart_recovery() { /* ... */ }\n",
            source_name="poc.rs",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    # --- Foundry / Solidity restart-survival evidence ---------------------
    def test_foundry_fork_recreation_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nPersistent AppHash divergence after redeploy.",
            "function reproduce() public {\n"
            "    vm.makePersistent(target);\n"
            "    uint256 fresh = vm.createSelectFork(rpcUrl, blockNumber);\n"
            "    assertEq(IVault(target).balanceOf(victim), 0);\n"
            "}\n",
            source_name="Poc.t.sol",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_foundry_restart_named_fn_passes(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nPermanent freezing of funds (fix requires hardfork).",
            "function testRestartSurvivesFrozenState() public { /* ... */ }\n",
            source_name="Poc.t.sol",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    # --- Env-override hook ------------------------------------------------
    def test_env_override_close_reopen_pattern_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nPermanent freezing of funds.",
            "package poc\nfunc TestX(t *testing.T){ customReopenIdiom() }\n",
        )
        prev = os.environ.get("AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS")
        os.environ["AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS"] = r"customReopenIdiom\("
        try:
            rc, payload = mod.run(draft, strict=True)
        finally:
            if prev is None:
                os.environ.pop("AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS", None)
            else:
                os.environ["AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS"] = prev
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-restart-survival")

    def test_env_override_absent_still_fails(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nPermanent freezing of funds.",
            "package poc\nfunc TestX(t *testing.T){ customReopenIdiom() }\n",
        )
        prev = os.environ.pop("AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS", None)
        try:
            rc, payload = mod.run(draft, strict=True)
        finally:
            if prev is not None:
                os.environ["AUDITOOOR_R22_CLOSE_REOPEN_PATTERNS"] = prev
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-restart-survival")


    # --- Regression: LOW severity gate (iter9 Lane III FP fix) ---------------
    def test_low_severity_draft_skips_r22(self) -> None:
        """LOW drafts must get pass-out-of-scope even if text contains trigger words."""
        draft = _write_case(
            "Severity: LOW\n"
            "- not_proven_impacts: permanent freezing of funds; chain halt; hardfork required.\n"
            "The bug is a read-only query panic bounded by BaseApp recovery; no persistent state change.\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")
        self.assertIn("low", payload.get("reason", "").lower())

    def test_not_proven_impacts_field_is_negation_context(self) -> None:
        """not_proven_impacts: ... permanent freezing ... must NOT trigger R22 for HIGH draft."""
        draft = _write_case(
            "Severity: HIGH\n"
            "- not_proven_impacts: Direct loss of user funds; permanent freezing of funds; chain halt.\n"
            "Actual impact: read-only RPC query panic, no state mutation.\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
