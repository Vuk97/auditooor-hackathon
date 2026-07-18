#!/usr/bin/env python3
"""Regression tests for tools/paste-ready-generator.py (Wave 7 ww2).

Covers (per PR brief):
  1. Clean draft + complete mapping -> emits paste-ready, exit 0
  2. Pre-submit hard fail → refuses, exit 1
  3. Missing Program Impact Mapping → refuses, exit 1
  4. Mapping present but unresolved dossier blocker → refuses, exit 1
  5. Idempotent: same input, two runs, identical output bytes
  6. Multi-draft sweep (--all-staging) processes both drafts deterministically

Stdlib-only. Hermetic - fakes pre-submit-check.sh via a local override script
that we hand the generator through PATH manipulation. This locks the tool's
contract (subprocess invocation + parsing) without depending on the live
30-check gate's heavy lifting.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GEN = ROOT / "tools" / "paste-ready-generator.py"


CLEAN_DRAFT = """# Critical - Sample finding for paste-ready test

**Severity (RECOMMENDED)**: **Critical**

## Program Impact Mapping

- Program: SampleProtocol Immunefi
- Asset: Vault.sol on mainnet
- selected_impact: Direct theft of user funds in cold storage
- Severity implied: Critical
- listed_impact_proven: true
- evidence_class: forge_poc
- stop_condition: stop if forge PoC does not drain user funds
- proof_contract:
  - PoC artifact must prove direct theft of user funds in cold storage.
- oos_traps:
  - Do not claim governance takeover.
- downgrade_clauses:
  - Downgrade if the PoC does not drain user funds.
- proof_artifact: poc-tests/sample/test_drain.t.sol
- not_proven_impacts: governance takeover, oracle manipulation

## Source-only Justification

The cited code in `Vault.sol:42-58` is the only path that triggers the bug;
PoC harness exercises the production handler. No live-state precondition is
required.

## Production Path

1. Asset in scope: Vault.sol (mainnet)
2. External actor: any EOA caller of `withdraw()`
3. Concrete entrypoint: `Vault.withdraw(uint256)` at `src/Vault.sol:42`
4. Privileged precondition: none
5. State precondition: vault has non-zero balance
6. Trigger sequence: 1 tx
7. Production-component proof: PoC drains 1000 USDC
8. Real-victim impact: lender loses deposit
9. Live-deployment evidence: `Vault.deployed()` on mainnet block N
10. Mock-component caveat: none

## Real-component Precondition

<!-- claim-precondition: Vault.balance > 0 at attack block -->

## Originality Reference

- Sherlock 2023-08-vault: only covers reentrancy, not this CEI violation
  https://github.com/sherlock-audit/2023-08-vault/issues
- Code4rena Cantina dup grep: 0 hits for `Vault.withdraw CEI`

## Likelihood

High: any external withdraw caller can trigger the path once the vault has funds.

## PoC / Test Proof

Command:

```bash
forge test --match-path test/poc/VaultDrain.t.sol --match-test testDrain
```

Observed output:

```text
PASS testDrain() (gas: 123456)
```
"""


PIM_BLOCK = """## Program Impact Mapping

- Program: SampleProtocol Immunefi
- Asset: Vault.sol on mainnet
- selected_impact: Direct theft of user funds in cold storage
- Severity implied: Critical
- listed_impact_proven: true
- evidence_class: forge_poc
- stop_condition: stop if forge PoC does not drain user funds
- proof_contract:
  - PoC artifact must prove direct theft of user funds in cold storage.
- oos_traps:
  - Do not claim governance takeover.
- downgrade_clauses:
  - Downgrade if the PoC does not drain user funds.
- proof_artifact: poc-tests/sample/test_drain.t.sol
- not_proven_impacts: governance takeover, oracle manipulation

"""


def _make_workspace(tmp: Path, *, draft_text: str = CLEAN_DRAFT,
                    name: str = "FN1-sample.md",
                    extra_drafts: dict | None = None,
                    dossier_blockers: list | None = None,
                    write_impact_contract: bool = True) -> Path:
    """Create a workspace shape with the given draft + optional dossier blockers."""
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "SEVERITY.md").write_text(
        "# Severity\n\n"
        "## Critical\n\n"
        "- Direct theft of user funds in cold storage\n",
        encoding="utf-8",
    )
    (ws / "poc-tests" / "sample").mkdir(parents=True)
    (ws / "poc-tests" / "sample" / "test_drain.t.sol").write_text(
        "// synthetic paste-ready proof fixture\n",
        encoding="utf-8",
    )
    if write_impact_contract:
        (ws / ".auditooor" / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.automation_closure.impact_contracts.v1",
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-fn1",
                            "candidate_id": "FN1-sample",
                            "severity": "Critical",
                            "selected_impact": "Direct theft of user funds in cold storage",
                            "listed_impact_proven": True,
                            "posture": "in_scope_direct_submit",
                        }
                    ],
                    "status": "ok",
                }
            ),
            encoding="utf-8",
        )
    (ws / "submissions" / "staging" / name).write_text(draft_text, encoding="utf-8")
    for fname, body in (extra_drafts or {}).items():
        (ws / "submissions" / "staging" / fname).write_text(body, encoding="utf-8")
    if dossier_blockers is not None:
        (ws / ".auditooor" / "fn1-sample_dossier.json").write_text(
            json.dumps({"blockers": dossier_blockers}), encoding="utf-8"
        )
    return ws


def _run_generator(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(GEN), *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _paste_path(ws: Path, slug: str = "FN1-sample") -> Path:
    return ws / "submissions" / "paste_ready" / slug / f"{slug}.md"


class TestPasteReadyGenerator(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prg-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    # 1. Clean draft exits 0 and writes a file.
    def test_clean_draft_emits_paste_ready(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        proc = _run_generator(str(ws), str(draft), "--skip-pre-submit")
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        out = _paste_path(ws)
        self.assertTrue(out.is_file(), f"missing output: {out}")
        text = out.read_text(encoding="utf-8")
        # All eight sections present in order (PR #535 PR 1 added Not Proven).
        for h in ["# Critical", "## Program Impact Mapping",
                  "## Source-only Justification", "## Production Path",
                  "## Real-component Precondition", "## Originality Reference",
                  "## Not Proven",
                  "## Warning Summary"]:
            self.assertIn(h, text, msg=f"missing section header: {h}")

    # 2. Pre-submit hard fail is refused.
    def test_pre_submit_hard_fail_refuses(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        # Stub pre-submit-check.sh on PATH ahead of repo's copy by
        # placing a fake bin first AND replacing the in-tree script with one
        # that always exits 1.
        # The simplest hermetic approach: invoke without --skip-pre-submit but
        # point the generator at a temp AUDITOOOR_DIR clone with a stub script.
        clone = self.tmp / "auditooor-clone"
        clone.mkdir()
        (clone / "tools").mkdir()
        (clone / "tools" / "paste-ready-generator.py").write_text(
            GEN.read_text(encoding="utf-8"), encoding="utf-8"
        )
        # Stub script (always exits 1, prints failure summary line)
        stub = clone / "tools" / "pre-submit-check.sh"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'FAKE pre-submit run for $1'\n"
            "echo '  X 1 check(s) failed, 0 warning(s) - FIX BEFORE SUBMITTING'\n"
            "exit 1\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        # Re-use the production_path.py lib by symlinking tools/lib
        os.symlink(ROOT / "tools" / "lib", clone / "tools" / "lib")
        cloned_gen = clone / "tools" / "paste-ready-generator.py"
        proc = subprocess.run(
            [sys.executable, str(cloned_gen), str(ws), str(draft)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
        self.assertIn("pre-submit-check hard FAIL", proc.stderr)
        # Output file must NOT be written.
        self.assertFalse(_paste_path(ws).exists())

    # 3. Missing Program Impact Mapping is refused.
    def test_missing_program_impact_mapping_refuses(self) -> None:
        bad = CLEAN_DRAFT.replace(PIM_BLOCK, "")
        ws = _make_workspace(self.tmp, draft_text=bad)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        proc = _run_generator(str(ws), str(draft), "--skip-pre-submit")
        self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
        self.assertIn("Program Impact Mapping", proc.stderr)
        self.assertFalse(_paste_path(ws).exists())

    def test_reportable_draft_without_workspace_impact_contract_refuses(self) -> None:
        ws = _make_workspace(self.tmp, write_impact_contract=False)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        proc = _run_generator(str(ws), str(draft), "--skip-pre-submit")
        self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
        self.assertIn("impact_contract", proc.stderr)
        self.assertIn("impact_contract_missing", proc.stderr)
        self.assertFalse(_paste_path(ws).exists())

    def test_draft_severity_must_match_locked_impact_contract_tier(self) -> None:
        ws = _make_workspace(self.tmp, write_impact_contract=False)
        (ws / "SEVERITY.md").write_text(
            "# Severity\n\n"
            "## Critical\n\n"
            "- Direct theft of user funds in cold storage\n\n"
            "## Medium\n\n"
            "- Temporary freeze of user withdrawals requiring admin recovery\n",
            encoding="utf-8",
        )
        (ws / ".auditooor" / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.automation_closure.impact_contracts.v1",
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-fn1",
                            "candidate_id": "FN1-sample",
                            "severity": "Medium",
                            "selected_impact": (
                                "Temporary freeze of user withdrawals requiring "
                                "admin recovery"
                            ),
                            "listed_impact_proven": True,
                            "posture": "in_scope_direct_submit",
                        }
                    ],
                    "status": "ok",
                }
            ),
            encoding="utf-8",
        )
        draft_text = CLEAN_DRAFT.replace(
            "selected_impact: Direct theft of user funds in cold storage",
            "selected_impact: Temporary freeze of user withdrawals requiring admin recovery",
        ).replace(
            "Severity implied: Critical",
            "Severity implied: Medium",
        ).replace(
            "PoC artifact must prove direct theft of user funds in cold storage.",
            "PoC artifact must prove temporary freeze of withdrawals.",
        )
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        draft.write_text(draft_text, encoding="utf-8")

        proc = _run_generator(str(ws), str(draft), "--skip-pre-submit")

        self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
        self.assertIn(
            "severity_claim_not_backed_by_selected_impact_tier",
            proc.stderr,
        )
        self.assertFalse(_paste_path(ws).exists())

    # 4. Unresolved dossier blocker → refused
    def test_unresolved_dossier_blocker_refuses(self) -> None:
        ws = _make_workspace(self.tmp,
                             dossier_blockers=["external_actor_path_missing"])
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        proc = _run_generator(str(ws), str(draft), "--skip-pre-submit")
        self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
        self.assertIn("dossier", proc.stderr)
        self.assertIn("external_actor_path_missing", proc.stderr)

    # 5. Idempotent
    def test_idempotent_same_bytes(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        for _ in range(2):
            proc = _run_generator(str(ws), str(draft), "--skip-pre-submit")
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        out = _paste_path(ws)
        first = out.read_bytes()
        # Run again, capture again, compare.
        _run_generator(str(ws), str(draft), "--skip-pre-submit")
        second = out.read_bytes()
        self.assertEqual(first, second, "paste-ready output is non-deterministic")

    def test_explicit_out_dir_preserves_flat_output(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"
        out_dir = ws / "custom-output"
        proc = _run_generator(str(ws), str(draft), "--skip-pre-submit", "--out-dir", str(out_dir))
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertTrue((out_dir / "FN1-sample.md").is_file())
        self.assertFalse(_paste_path(ws).exists())

    def test_bundle_default_output_uses_bundle_slug(self) -> None:
        ws = _make_workspace(self.tmp)
        bundle = ws / "submissions" / "packaged" / "bundle-slug"
        bundle.mkdir(parents=True)
        (bundle / "source-draft.md").write_text(CLEAN_DRAFT, encoding="utf-8")
        proc = _run_generator("--bundle", str(bundle), "--skip-pre-submit")
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        out = _paste_path(ws, "bundle-slug")
        self.assertTrue(out.is_file(), f"missing output: {out}")

    # 6. --all-staging sweep
    def test_all_staging_sweep(self) -> None:
        # Two clean drafts; both should be emitted, exit 0.
        ws = _make_workspace(
            self.tmp,
            extra_drafts={"FN2-sample.md": CLEAN_DRAFT.replace(
                "Sample finding for paste-ready test",
                "Second sample finding"
            )},
        )
        proc = _run_generator(str(ws), "--all-staging", "--skip-pre-submit")
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertTrue(_paste_path(ws, "FN1-sample").exists())
        self.assertTrue(_paste_path(ws, "FN2-sample").exists())

    def test_triager_paste_cantina_emits_required_fields_and_proof(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"

        proc = _run_generator(
            str(ws), str(draft),
            "--skip-pre-submit",
            "--platform", "cantina",
            "--triager-paste",
            "--verify-commands",
        )

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        out = _paste_path(ws)
        self.assertTrue(out.is_file(), f"missing output: {out}")
        text = out.read_text(encoding="utf-8")
        self.assertIn("- Severity: Critical", text)
        self.assertIn("- Likelihood: High:", text)
        self.assertIn("- Impact: Direct theft of user funds in cold storage", text)
        self.assertIn("forge test --match-path test/poc/VaultDrain.t.sol", text)
        self.assertIn("PASS testDrain()", text)
        self.assertNotRegex(
            text,
            r"/Users/|/private/|\.auditooor|impact_contracts|originality",
        )

    def test_triager_paste_preserves_l27_justification_sections(self) -> None:
        """L27 known-issue regression: the canonical triager paste must NOT
        strip Severity Justification / Likelihood / Source-Only / Impact
        Contract. A draft carrying all sections -> the generated paste retains
        Severity Justification + the full Likelihood reasoning + the PoC PASS
        line (R80: the assertions read the real generated paste file).
        """
        # Inject a Severity Justification section (CLEAN_DRAFT omits it) plus a
        # distinctive second Likelihood line so we can prove the FULL section
        # body survives, not just the collapsed summary bullet.
        draft_text = CLEAN_DRAFT.replace(
            "## Likelihood\n\n"
            "High: any external withdraw caller can trigger the path once the vault has funds.\n",
            "## Severity Justification\n\n"
            "Maps to SEVERITY.md Critical row 'Direct theft of user funds in cold "
            "storage'; parity with prior accepted CEI filings establishes the tier.\n\n"
            "## Likelihood\n\n"
            "High: any external withdraw caller can trigger the path once the vault has funds.\n"
            "No privileged role, no off-chain precondition, single-tx trigger.\n",
        )
        ws = _make_workspace(self.tmp, draft_text=draft_text)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"

        proc = _run_generator(
            str(ws), str(draft),
            "--skip-pre-submit",
            "--platform", "cantina",
            "--triager-paste",
            "--verify-commands",
        )

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        out = _paste_path(ws)
        self.assertTrue(out.is_file(), f"missing output: {out}")
        text = out.read_text(encoding="utf-8")

        # 1. Severity Justification section is preserved verbatim (not stripped).
        self.assertIn("## Severity Justification", text)
        self.assertIn(
            "Maps to SEVERITY.md Critical row", text,
            msg="Severity Justification body was stripped from triager paste",
        )
        # 2. Full Likelihood section body survives (not just the summary bullet).
        self.assertIn("## Likelihood", text)
        self.assertIn(
            "No privileged role, no off-chain precondition, single-tx trigger.",
            text,
            msg="full Likelihood reasoning was collapsed/stripped",
        )
        # 3. Source-Only Justification heading is preserved per the L27 template.
        self.assertIn("## Source-Only Justification", text)
        self.assertIn("Vault.sol:42-58", text)
        # 4. Impact Contract directives survive.
        self.assertIn("## Impact Contract", text)
        self.assertIn("selected_impact: Direct theft of user funds", text)
        # 5. The runnable-PoC PASS line is carried through.
        self.assertIn("forge test --match-path test/poc/VaultDrain.t.sol", text)
        self.assertIn("PASS testDrain()", text)
        # 6. Title H1 stays under 128 chars.
        h1 = text.splitlines()[0]
        self.assertTrue(h1.startswith("# "))
        self.assertLess(len(h1), 128, msg=f"title too long: {h1!r}")
        # 7. No local/internal path leak survived the un-stripping.
        self.assertNotRegex(text, r"/Users/|/private/|/var/folders/")

    def test_triager_paste_refuses_local_internal_path_leak(self) -> None:
        bad = CLEAN_DRAFT.replace(
            "forge test --match-path test/poc/VaultDrain.t.sol --match-test testDrain",
            "forge test --match-path /Users/wolf/audits/revert/poc-tests/VaultDrain.t.sol --match-test testDrain",
        )
        ws = _make_workspace(self.tmp, draft_text=bad)
        draft = ws / "submissions" / "staging" / "FN1-sample.md"

        proc = _run_generator(
            str(ws), str(draft),
            "--skip-pre-submit",
            "--platform", "cantina",
            "--triager-paste",
            "--verify-commands",
        )

        self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
        self.assertIn("local/internal-only", proc.stderr)
        self.assertFalse(_paste_path(ws).exists())


if __name__ == "__main__":
    unittest.main()
