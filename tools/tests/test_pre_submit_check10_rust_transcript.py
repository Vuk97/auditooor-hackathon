"""
Check #10 Rust transcript parsing unit tests.

Validates that pre-submit-check.sh correctly recognizes:
  - cargo test standard output  (test result: ok.)
  - cargo nextest per-test PASS lines  (PASS [   0.001s] crate::test)
  - inline Rust PoC (#[test] attr, no .rs file reference required)
  - failing transcripts are NOT accepted
"""
from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "pre-submit-check.sh"
TRANSCRIPTS = REPO / "detectors" / "fixtures" / "transcripts"


def _build_rust_draft(
    poc_section: str,
    *,
    has_rs_ref: bool = False,
    severity: str = "High",
) -> str:
    rs_ref = "poc/exploit_test.rs" if has_rs_ref else ""
    return textwrap.dedent(
        f"""
        # Rust PoC leads to direct loss of user funds

        Severity: {severity}
        Likelihood: Medium
        Choose Impact(s): Direct theft of user funds.
        Impact: $500K of depositor funds at risk.

        ## Severity Justification

        Matches CRIT-1 Direct loss of funds rubric row verbatim.

        ## Scope Exclusion Check

        Root cause is inside in-scope Rust crate; does not rely on out-of-scope behavior.

        ## Originality Check

        Distinction from prior findings: novel attack vector confirmed by bidirectional mining.
        {"PoC file: `" + rs_ref + "`" if rs_ref else ""}

        ## Proof of Concept

        {poc_section}
        """
    ).strip() + "\n"


# ---------------------------------------------------------------------------
# Minimal inline Rust PoC body (>40 non-empty lines to pass Check 4c)
# ---------------------------------------------------------------------------
_RUST_INLINE_BODY = textwrap.dedent(
    """
    use std::collections::HashMap;

    struct ExitState {
        observed_exit_txid: String,
        expected_exit_txid: String,
        spend_accepted: bool,
        balance_before: i64,
        balance_after: i64,
    }

    fn initial_state() -> ExitState {
        ExitState {
            observed_exit_txid: "refund-txid".to_string(),
            expected_exit_txid: "refund-txid".to_string(),
            spend_accepted: false,
            balance_before: 25_000_000,
            balance_after: 25_000_000,
        }
    }

    fn apply_coop_exit_mutation(mut s: ExitState) -> ExitState {
        s.observed_exit_txid = "coop-exit-txid".to_string();
        if s.observed_exit_txid != s.expected_exit_txid {
            s.spend_accepted = true;
            s.balance_after = 0;
        }
        s
    }

    #[test]
    fn test_exit_bypass_leads_to_balance_drain() {
        let before = initial_state();
        let after = apply_coop_exit_mutation(ExitState {
            observed_exit_txid: before.observed_exit_txid.clone(),
            expected_exit_txid: before.expected_exit_txid.clone(),
            spend_accepted: before.spend_accepted,
            balance_before: before.balance_before,
            balance_after: before.balance_after,
        });
        assert!(after.spend_accepted, "expected spend to be accepted");
        assert_eq!(after.balance_after, 0, "expected full drain");
        assert!(
            after.balance_after < before.balance_before,
            "balance_after={} should be less than balance_before={}",
            after.balance_after,
            before.balance_before,
        );
        let mut ledger: HashMap<&str, i64> = HashMap::new();
        ledger.insert("victim", before.balance_before);
        ledger.insert("attacker_gain", before.balance_before - after.balance_after);
        assert_eq!(*ledger.get("attacker_gain").unwrap(), 25_000_000);
    }
    """
).strip()


class Check10CargoTranscriptTest(unittest.TestCase):
    # ------------------------------------------------------------------
    # cargo test standard format: "test result: ok."
    # ------------------------------------------------------------------
    def test_cargo_test_standard_pass_transcript_accepted(self) -> None:
        transcript = (TRANSCRIPTS / "cargo_pass.txt").read_text()
        poc = textwrap.dedent(
            f"""
            Run with `cargo test`:

            ```rust
            {_RUST_INLINE_BODY}
            ```

            Transcript:

            ```text
            {transcript}
            ```
            """
        ).strip()
        draft_text = _build_rust_draft(poc, has_rs_ref=False)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            subs = ws / "submissions"
            subs.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = subs / "rust-cargo-test.md"
            draft.write_text(draft_text)
            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "High"],
                cwd=REPO, capture_output=True, text=True, timeout=30,
            )
            out = proc.stdout + proc.stderr
            self.assertIn("✅ 10. Rust/DLT cargo-test PoC transcript cited", out, out)
            self.assertNotIn("No executable Forge/Rust/Go PoC transcript recognized", out)

    # ------------------------------------------------------------------
    # cargo nextest format: "PASS [   0.001s] crate::test_name"
    # ------------------------------------------------------------------
    def test_cargo_nextest_pass_transcript_accepted(self) -> None:
        transcript = (TRANSCRIPTS / "cargo_nextest_pass.txt").read_text()
        poc = textwrap.dedent(
            f"""
            Run with `cargo nextest run`:

            ```rust
            {_RUST_INLINE_BODY}
            ```

            Transcript:

            ```text
            {transcript}
            ```
            """
        ).strip()
        draft_text = _build_rust_draft(poc, has_rs_ref=False)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            subs = ws / "submissions"
            subs.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = subs / "rust-nextest.md"
            draft.write_text(draft_text)
            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "High"],
                cwd=REPO, capture_output=True, text=True, timeout=30,
            )
            out = proc.stdout + proc.stderr
            self.assertIn("✅ 10. Rust/DLT cargo-test PoC transcript cited", out, out)
            self.assertNotIn("No executable Forge/Rust/Go PoC transcript recognized", out)

    # ------------------------------------------------------------------
    # Failing transcript must NOT be accepted as PASS
    # ------------------------------------------------------------------
    def test_cargo_test_fail_transcript_not_accepted(self) -> None:
        transcript = (TRANSCRIPTS / "cargo_fail.txt").read_text()
        poc = textwrap.dedent(
            f"""
            Run with `cargo test`:

            ```rust
            {_RUST_INLINE_BODY}
            ```

            Transcript:

            ```text
            {transcript}
            ```
            """
        ).strip()
        draft_text = _build_rust_draft(poc, has_rs_ref=False)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            subs = ws / "submissions"
            subs.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = subs / "rust-cargo-fail.md"
            draft.write_text(draft_text)
            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "High"],
                cwd=REPO, capture_output=True, text=True, timeout=30,
            )
            out = proc.stdout + proc.stderr
            # Must NOT emit the green tick for Check 10
            self.assertNotIn("✅ 10. Rust/DLT cargo-test PoC transcript cited", out, out)

    # ------------------------------------------------------------------
    # .rs file reference + cargo test (original behaviour preserved)
    # ------------------------------------------------------------------
    def test_rs_file_ref_with_cargo_test_transcript_accepted(self) -> None:
        transcript = (TRANSCRIPTS / "cargo_pass.txt").read_text()
        poc = textwrap.dedent(
            f"""
            Full PoC in `poc/exploit_test.rs`. Run with `cargo test`:

            ```rust
            {_RUST_INLINE_BODY}
            ```

            Transcript:

            ```text
            {transcript}
            ```
            """
        ).strip()
        draft_text = _build_rust_draft(poc, has_rs_ref=True)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            subs = ws / "submissions"
            subs.mkdir(parents=True)
            (ws / "AUDIT.md").write_text("# fixture\n")
            draft = subs / "rust-rs-ref.md"
            draft.write_text(draft_text)
            proc = subprocess.run(
                ["bash", str(SCRIPT), str(draft), "--severity", "High"],
                cwd=REPO, capture_output=True, text=True, timeout=30,
            )
            out = proc.stdout + proc.stderr
            self.assertIn("✅ 10. Rust/DLT cargo-test PoC transcript cited", out, out)

    # ------------------------------------------------------------------
    # Smoke: fixture files exist and have expected marker lines
    # ------------------------------------------------------------------
    def test_cargo_pass_fixture_has_ok_result_line(self) -> None:
        text = (TRANSCRIPTS / "cargo_pass.txt").read_text()
        self.assertIn("test result: ok.", text)
        self.assertNotIn("FAILED", text)

    def test_cargo_fail_fixture_has_failed_result_line(self) -> None:
        text = (TRANSCRIPTS / "cargo_fail.txt").read_text()
        self.assertIn("test result: FAILED", text)

    def test_cargo_nextest_pass_fixture_has_pass_bracket(self) -> None:
        text = (TRANSCRIPTS / "cargo_nextest_pass.txt").read_text()
        self.assertIn("PASS [", text)
        self.assertNotIn("FAIL", text)


if __name__ == "__main__":
    unittest.main()
