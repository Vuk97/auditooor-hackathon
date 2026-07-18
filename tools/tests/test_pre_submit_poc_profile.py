from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "pre-submit-check.sh"


class PreSubmitPocProfileTest(unittest.TestCase):
    def test_inline_go_poc_counts_as_substantive_poc_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            poc_dir = ws / "poc"
            submissions.mkdir(parents=True)
            poc_dir.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            (poc_dir / "coop_exit_chain_watcher_bypass_test.go.draft").write_text(
                "package poc\n"
            )
            go_poc = "\n".join(
                [
                    "package poc",
                    "",
                    "import (",
                    '    "testing"',
                    "",
                    '    "github.com/stretchr/testify/require"',
                    ")",
                    "",
                    "type watcherState struct {",
                    "    observedExitTxid string",
                    "    expectedExitTxid string",
                    "    spendAccepted bool",
                    "    balanceBefore int64",
                    "    balanceAfter int64",
                    "    channelID string",
                    "    victim string",
                    "    attacker string",
                    "}",
                    "",
                    "func initialWatcherState() watcherState {",
                    "    return watcherState{",
                    '        observedExitTxid: "refund-txid",',
                    '        expectedExitTxid: "refund-txid",',
                    "        spendAccepted: false,",
                    "        balanceBefore: 25_000_000,",
                    "        balanceAfter: 25_000_000,",
                    '        channelID: "channel-1",',
                    '        victim: "alice",',
                    '        attacker: "mallory",',
                    "    }",
                    "}",
                    "",
                    "func applyCoopExitMutation(s watcherState) watcherState {",
                    "    mutated := s",
                    '    mutated.observedExitTxid = "coop-exit-txid"',
                    "    if mutated.observedExitTxid != mutated.expectedExitTxid {",
                    "        mutated.spendAccepted = true",
                    "        mutated.balanceAfter = 0",
                    "    }",
                    "    return mutated",
                    "}",
                    "",
                    "func TestCoopExitChainWatcherBypass(t *testing.T) {",
                    "    before := initialWatcherState()",
                    "    after := applyCoopExitMutation(before)",
                    '    require.Equal(t, "channel-1", after.channelID)',
                    '    require.Equal(t, "alice", after.victim)',
                    '    require.Equal(t, "mallory", after.attacker)',
                    '    require.Equal(t, "coop-exit-txid", after.observedExitTxid)',
                    "    require.True(t, after.spendAccepted)",
                    "    require.Equal(t, int64(25_000_000), before.balanceBefore)",
                    "    require.Equal(t, int64(0), after.balanceAfter)",
                    "    if after.balanceAfter >= before.balanceBefore {",
                    '        t.Fatalf("expected measurable loss, before=%d after=%d", before.balanceBefore, after.balanceAfter)',
                    "    }",
                    "}",
                ]
            )
            indented_go_poc = textwrap.indent(go_poc, "                    ")
            draft = submissions / "go-inline-poc.md"
            draft.write_text(
                textwrap.dedent(
                    f"""
                    # Chain watcher exit txid bypass leads to direct balance loss

                    Severity: Medium
                    Impact: $250K of live channel funds can be released through the bypass.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope Go statechain watcher logic and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    The full Go PoC is inline below and is stored as `poc/coop_exit_chain_watcher_bypass_test.go.draft`.
                    Run it with `go test ./poc -run TestCoopExitChainWatcherBypass -count=1` or the project `mise test`
                    wrapper after copying the draft into the target Go package.

                    ```go
                    {indented_go_poc}
                    ```

                    Observed result:

                    ```text
                    === RUN   TestCoopExitChainWatcherBypass
                    --- PASS: TestCoopExitChainWatcherBypass (0.00s)
                    PASS
                    ok github.com/example/spark/poc 0.011s
                    ```
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertIn("✅ 4. Go PoC reference", out)
            self.assertIn("✅ 4c. substantive inline PoC/test code is present", out)
            self.assertIn("✅ 10. Go test PoC transcript cited", out)
            self.assertNotIn("4. PoC test required", out)
            self.assertNotIn("4c. substantive inline PoC code missing", out)

    def test_pointer_only_poc_file_block_fails_even_with_later_inline_excerpt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = submissions / "bad-pointer-poc.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bad PoC shape

                    Severity: Medium
                    Impact: $100K of TVL-equivalent pool function at risk.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    PoC file:

                    ```text
                    external/project/test/BadPoC.t.sol
                    ```

                    ### Inline PoC excerpts

                    ```solidity
                    function test_poc_BadShape() public {
                        assertTrue(true);
                    }
                    ```
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("4b. pointer-only PoC section detected", out)

    def test_pointer_only_go_poc_file_block_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = submissions / "bad-go-pointer-poc.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bad Go PoC shape

                    Severity: Medium
                    Impact: $100K of direct loss.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope Go state-machine logic.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    PoC file:

                    ```text
                    external/spark/spark/so/chain/watch_chain_lead1_test.go
                    ```
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("4b. pointer-only PoC section detected", out)

    def test_short_inline_excerpt_without_full_test_body_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = submissions / "excerpt-only-poc.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Excerpt-only PoC shape

                    Severity: Medium
                    Impact: $100K of TVL-equivalent pool function at risk.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    Run the coded PoC:

                    ```bash
                    forge test --match-path test/ExcerptOnlyPoC.t.sol -vv
                    ```

                    ### Inline PoC excerpts

                    ```solidity
                    function test_poc_ExcerptOnly() public {
                        assertTrue(true);
                    }
                    ```
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("4c. substantive inline PoC code missing", out)

    def test_reportable_final_paste_requires_platform_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = submissions / "missing-selectors.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Missing selector fields

                    Severity: Medium
                    Impact: $100K of protocol funds can be locked.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    The coded PoC is omitted in this focused selector fixture.
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("42. FINAL-PASTE-FORM-GATE blocked", out)
            self.assertIn("missing\tLikelihood selector", out)
            self.assertIn("missing\tImpact(s) selector", out)
            self.assertNotIn("missing\tSeverity selector", out)

    def test_final_paste_rejects_internal_only_phrases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = submissions / "internal-leak.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Internal leakage fixture

                    Severity: Medium
                    Likelihood: Medium
                    Choose Impact(s): Direct theft of user funds.
                    Impact: $100K of protocol funds can be stolen.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Operator Notes

                    dupe-risk reviewer warning: review nearby rejected submissions.
                    Run pre-submit with --skip-live-verify only if the local proof is enough.

                    ## Proof of Concept

                    The coded PoC is omitted in this focused leakage fixture.
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("42. FINAL-PASTE-FORM-GATE blocked", out)
            self.assertIn("leak\tdupe-risk-reviewer-warning", out)
            self.assertIn("leak\tskip-live-verify", out)
            self.assertNotIn("missing\tSeverity selector", out)
            self.assertNotIn("missing\tLikelihood selector", out)
            self.assertNotIn("missing\tImpact(s) selector", out)

    def test_final_paste_hygiene_rejects_current_draft_html_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = submissions / "html-comment.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # HTML comment leakage fixture

                    Severity: Medium
                    Likelihood: Medium
                    Choose Impact(s): Direct theft of user funds.
                    Impact: $100K of protocol funds can be stolen.

                    <!-- internal reviewer note: remove before paste -->

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    The coded PoC is omitted in this focused hygiene fixture.
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("43. FINAL-PASTE-HYGIENE blocked", out)
            self.assertIn("html_comment", out)
            self.assertIn("internal reviewer note", out)

    def test_final_paste_hygiene_sweeps_workspace_paste_ready_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            submissions = ws / "submissions"
            paste_ready = submissions / "paste-ready"
            paste_ready.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            (paste_ready / "leaky.md").write_text(
                textwrap.dedent(
                    """
                    # Existing paste artifact

                    Severity: Medium

                    ## Proof of Concept

                    /Users/alice/audits/demo/poc/Exploit.t.sol
                    """
                ).strip()
                + "\n"
            )
            draft = submissions / "clean-current-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Clean current draft

                    Severity: Medium
                    Likelihood: Medium
                    Choose Impact(s): Direct theft of user funds.
                    Impact: $100K of protocol funds can be stolen.

                    ## Severity Justification

                    This maps to the Medium rubric impact category.

                    ## Scope Exclusion Check

                    The root cause is in-scope and does not rely on out of scope behavior.

                    ## Originality Check

                    Distinction from prior findings: novel vector.

                    ## Proof of Concept

                    The coded PoC is omitted in this focused hygiene fixture.
                    """
                ).strip()
                + "\n"
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, out)
            self.assertIn("43. FINAL-PASTE-HYGIENE blocked", out)
            self.assertIn("submissions/paste-ready/leaky.md", out)
            self.assertIn("local_absolute_path", out)
            self.assertIn("path_only_poc", out)

    def test_check10_uses_poc_profile_and_test_contract_not_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            project = ws / "harness"
            submission_dir = ws / "submissions"
            test_dir = project / "test"
            bin_dir = root / "bin"
            submission_dir.mkdir(parents=True)
            test_dir.mkdir(parents=True)
            bin_dir.mkdir()
            (ws / "AUDIT.md").write_text("# fixture\n")

            (project / "foundry.toml").write_text(
                "[profile.default]\n"
                "test = 'invariants'\n\n"
                "[profile.poc]\n"
                "test = 'test'\n"
            )
            (test_dir / "FN2_PoC.t.sol").write_text(
                textwrap.dedent(
                    """
                    contract JournalMockVerifier {
                        function helper() external {}
                    }

                    contract FN2_PoC {
                        function test_FN2_replay() public {}
                    }
                    """
                ).strip()
                + "\n"
            )
            draft = submission_dir / "FN2.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # FN2

                    **Severity:** Medium
                    **Impact:** $100K at risk.
                    **Rubric:** Medium impact example.

                    ## Out-of-scope clause citation
                    In-scope: smart contract proof verification logic.

                    ### Distinction from prior findings
                    This is distinct from prior findings.

                    ## Proof of Concept
                    PoC: `harness/test/FN2_PoC.t.sol`.
                    """
                ).strip()
                + "\n"
            )
            forge = bin_dir / "forge"
            forge.write_text(
                "#!/bin/sh\n"
                "echo \"profile=${FOUNDRY_PROFILE:-} args=$@\" > \"$FORGE_CAPTURE\"\n"
                "case \"$*\" in\n"
                "  *'--match-contract FN2_PoC'*) echo '1 passed; 0 failed'; exit 0 ;;\n"
                "  *) echo 'No tests match'; exit 0 ;;\n"
                "esac\n"
            )
            forge.chmod(0o755)
            capture = root / "forge-capture.txt"
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            env["FORGE_BIN"] = str(forge)
            env["FORGE_CAPTURE"] = str(capture)

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "Medium"],
                cwd=REPO,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )

            out = proc.stdout + proc.stderr
            self.assertIn("PoC FN2_PoC.t.sol passed (FN2_PoC)", out)
            self.assertIn("FOUNDRY_PROFILE=poc", out)
            self.assertIn("profile=poc", capture.read_text())
            self.assertIn("--offline", capture.read_text())
            self.assertIn("--match-contract FN2_PoC", capture.read_text())
            self.assertNotIn("--match-contract JournalMockVerifier", capture.read_text())


if __name__ == "__main__":
    unittest.main()
