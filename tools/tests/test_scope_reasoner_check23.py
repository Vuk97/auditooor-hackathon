#!/usr/bin/env python3
"""capability-v3 iter-003 T3 — Check #23 regression tests.

The tool under test is the Check #23 region of `tools/pre-submit-check.sh`,
which wires `tools/scope-reasoner.py` into the pre-submit gate with a
`SCOPE_REASONER_FAIL_MODE ∈ {warn, block}` knob.

Hermetic: every fixture is built in a `tempfile.TemporaryDirectory`. No
network, no real submissions.

Iter-v3-3 T3 baseline (3 tests):

1. `test_warn_mode_does_not_block`
   warn mode + a `likely_oos`-triggering draft (draft co-located with a
   SCOPE.md that enumerates cross-chain atomicity as OOS) → Check #23
   prints a WARN. Exit is not asserted because other checks may fail
   on a skeletal draft.

2. `test_block_mode_blocks_on_likely_oos`
   block mode + a `likely_oos`-triggering draft → Check #23 prints the
   compact failure code `scope-reasoner-likely-oos` and the exit code
   is non-zero.

3. `test_new_patterns_catch_poly45_and_poly46_fixtures`
   Runs the reasoner against the synthetic POLY-45 / POLY-46 fixtures
   shipped under `tools/tests/fixtures/scope_reasoner/` and asserts the
   expected pattern_name fires on each.

Codex PR#104 fix slate (4 additional tests, one per bug + delimited block):

4. `test_check23_passes_real_scope_md_through_to_reasoner` (bug #3)
   workspace with real SCOPE.md + clean draft → reasoner's scope_file
   field points to the real SCOPE.md, not empty.

5. `test_check23_pattern_hit_without_scope_clause_is_advisory_not_likely_oos`
   (bug #4) — pattern fires but SCOPE.md does not mention the OOS
   territory → Check #23 emits an ADVISORY warn, NOT likely_oos,
   even in block mode.

6. `test_check23_claim_after_pre_emptive_response_line_still_flagged`
   (bug #5) — substantive OOS claim on the line after
   `Pre-emptive response:` (NOT inside markers) → Check #23 flags
   likely_oos (it no longer silently strips that line).

7. `test_check23_delimited_rebuttal_block_is_stripped`
   — rebuttal content wrapped in `<!-- rebuttal:start --> ... <!-- rebuttal:end -->`
   is stripped before the reasoner sees it → Check #23 does NOT flag.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
REASONER = ROOT / "tools" / "scope-reasoner.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "scope_reasoner"


def _minimal_high_draft_triggering_cross_chain() -> str:
    """A minimal High-severity draft that:
      * satisfies enough of the earlier checks to NOT make this test
        spuriously pass because Check #23 was never reached,
      * and explicitly contains a `cross-chain atomicity` claim that the
        reasoner's `cross_chain_atomicity` pattern will match.

    This is intentionally skeletal; we only need Check #23 itself to
    render its decision. Other checks may fail — the test asserts on the
    specific Check #23 substring, not on the global exit code. (The
    block-mode test does separately assert non-zero exit.)
    """
    return textwrap.dedent(
        """
        # Finding: cross-chain atomicity pre-fund theft

        **Severity:** High

        **Rubric:** stealing of funds (Polymarket rubric row 1).

        **Dollar impact:** $10,000 per pre-fund window.

        ## Claim

        The attacker can atomically compose a pre-fund then deposit from the
        Polkadot side of a bridgehub message, causing an atomic prefund
        race. Cross-chain atomicity is the core exploit primitive.

        ## PoC

        `test/R67_L1AdaptorPreFundTheft.t.sol` — forge test verified.
        """
    ).strip() + "\n"


def _scope_md_with_cross_chain_oos() -> str:
    """A SCOPE.md that enumerates cross-chain atomicity as out-of-scope.

    Required by the new semantics (Codex PR#104 bug #4): `likely_oos`
    only fires when the reasoner finds a SCOPE.md OOS clause that
    mentions the same territory as the pattern-matched draft line.
    """
    return textwrap.dedent(
        """
        # Workspace SCOPE

        ## In-scope

        - Destination-chain contract state on L1.

        ## Out of scope

        - Cross-chain atomicity. Bridge-origin transactions that require
          Polkadot-side or parachain-side composition are OOS. Pre-fund
          race conditions spanning bridgehub are OOS.
        """
    ).strip() + "\n"


def _scope_md_no_cross_chain() -> str:
    """A SCOPE.md whose OOS section does NOT mention cross-chain
    atomicity. Used to exercise the `advisory` (not likely_oos) path in
    Check #23.
    """
    return textwrap.dedent(
        """
        # Workspace SCOPE

        ## In-scope

        - All single-chain L1 contract state.

        ## Out of scope

        - Centralization risks (admin key custody).
        - Gas-cost-only findings.
        """
    ).strip() + "\n"


def _make_workspace(tmp: Path, draft_text: str, scope_text: str | None) -> Path:
    """Build a `packaged`-shape workspace:

        <tmp>/ws/
          SCOPE.md                 (optional)
          submissions/packaged/fid/source-draft.md

    Returns the draft path.
    """
    ws = tmp / "ws"
    (ws / "submissions" / "packaged" / "fid").mkdir(parents=True)
    if scope_text is not None:
        (ws / "SCOPE.md").write_text(scope_text)
    draft = ws / "submissions" / "packaged" / "fid" / "source-draft.md"
    draft.write_text(draft_text)
    return draft


def _run_pre_submit(draft: Path, *, fail_mode: str | None, severity: str = "High") -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if fail_mode is not None:
        env["SCOPE_REASONER_FAIL_MODE"] = fail_mode
    cmd = ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity]
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _check23_line(stdout: str) -> str:
    """Extract the line that represents Check #23's decision. Prefers the
    failure/warn/pass-status line, not the echo header.
    """
    for line in stdout.splitlines():
        s = line.strip()
        # Skip the `  23. Scope-reasoner OOS gate (SCOPE_REASONER_FAIL_MODE=...)...`
        # header line — it ends with "..." and does not carry status.
        if s.endswith("..."):
            continue
        if "23." in s and any(marker in s for marker in ("✅", "❌", "⚠️", "scope-reasoner")):
            return s
    return ""


class Check23Tests(unittest.TestCase):
    def test_warn_mode_does_not_block(self) -> None:
        """warn mode + likely_oos draft → Check #23 does not hard-fail.

        We run the full pre-submit and assert: the Check #23 line is a
        WARN (not ❌), and no `scope-reasoner-likely-oos` code appears.
        The test does not assert on the global exit code, because other
        pre-existing checks may hard-fail on a skeletal draft; the gate
        under test is Check #23 in isolation.
        """
        with tempfile.TemporaryDirectory() as tmp:
            draft = _make_workspace(
                Path(tmp),
                _minimal_high_draft_triggering_cross_chain(),
                _scope_md_with_cross_chain_oos(),
            )

            proc = _run_pre_submit(draft, fail_mode="warn")

            # Check #23 fired.
            self.assertIn(
                "23. Scope-reasoner OOS gate (SCOPE_REASONER_FAIL_MODE=warn)",
                proc.stdout,
                proc.stdout,
            )
            line23 = _check23_line(proc.stdout)
            self.assertTrue(line23, f"no Check #23 status line found in:\n{proc.stdout}")
            # It is a warn, not a failure.
            self.assertIn("WARN", line23, line23)
            self.assertIn("likely_oos:cross_chain_atomicity", line23, line23)
            self.assertNotIn("scope-reasoner-likely-oos", line23, line23)

    def test_block_mode_blocks_on_likely_oos(self) -> None:
        """block mode + likely_oos draft → compact failure code fires and
        global exit is non-zero."""
        with tempfile.TemporaryDirectory() as tmp:
            draft = _make_workspace(
                Path(tmp),
                _minimal_high_draft_triggering_cross_chain(),
                _scope_md_with_cross_chain_oos(),
            )

            proc = _run_pre_submit(draft, fail_mode="block")

            self.assertIn(
                "23. Scope-reasoner OOS gate (SCOPE_REASONER_FAIL_MODE=block)",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn(
                "scope-reasoner-likely-oos",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn(
                "pattern=cross_chain_atomicity",
                proc.stdout,
                proc.stdout,
            )
            # Non-zero exit: either from Check #23 itself (block hard-
            # fail) or from unrelated failing checks. What matters is the
            # code appears above and the global exit is not 0.
            self.assertNotEqual(proc.returncode, 0, proc.stdout)

    def test_new_patterns_catch_poly45_and_poly46_fixtures(self) -> None:
        """Runs the reasoner against synthetic fixtures for the two new
        patterns; asserts the correct pattern_name fires on each. This
        guards against silent pattern removal / regex breakage."""
        poly45 = FIXTURES / "poly45_unrealistic_bounds_fixture.md"
        poly46 = FIXTURES / "poly46_event_only_fixture.md"
        self.assertTrue(poly45.exists(), poly45)
        self.assertTrue(poly46.exists(), poly46)

        for fixture, expected_pattern in (
            (poly45, "unrealistic_bounds"),
            (poly46, "event_only_impact"),
        ):
            proc = subprocess.run(
                [sys.executable, str(REASONER), "--draft", str(fixture)],
                check=True,
                capture_output=True,
                text=True,
            )
            out = json.loads(proc.stdout)
            names = [f["pattern_name"] for f in out.get("flags", [])]
            self.assertIn(
                expected_pattern,
                names,
                f"{fixture.name}: expected {expected_pattern!r} in {names} (raw: {out})",
            )

    def test_oz_l02_mirror_fixture_flags_public_audit_endorsed_design(self) -> None:
        """PR #120 lesson 5: a candidate that mirrors an acknowledged-not-
        fixed audit asymmetry (e.g. OZ-2025-L-02 indexing-side single-slot
        endorsement) must be flagged `public_audit_endorsed_design_mirror`.
        The counter-fixture (genuinely novel candidate, no public-audit
        endorsement of the underlying design) must NOT be flagged."""
        fixture = FIXTURES / "oz_l02_public_audit_endorsed_design_mirror_fixture.md"
        counter = FIXTURES / "oz_l02_public_audit_endorsed_design_mirror_counterfixture.md"
        self.assertTrue(fixture.exists(), fixture)
        self.assertTrue(counter.exists(), counter)

        # Positive: the mirror fixture must hit the new pattern.
        proc = subprocess.run(
            [sys.executable, str(REASONER), "--draft", str(fixture)],
            check=True, capture_output=True, text=True,
        )
        out = json.loads(proc.stdout)
        names = [f["pattern_name"] for f in out.get("flags", [])]
        self.assertIn(
            "public_audit_endorsed_design_mirror",
            names,
            f"mirror fixture: expected pattern in {names} (raw: {out})",
        )

        # Negative: the counter-fixture must NOT hit the new pattern.
        proc = subprocess.run(
            [sys.executable, str(REASONER), "--draft", str(counter)],
            check=True, capture_output=True, text=True,
        )
        out = json.loads(proc.stdout)
        names = [f["pattern_name"] for f in out.get("flags", [])]
        self.assertNotIn(
            "public_audit_endorsed_design_mirror",
            names,
            f"counter-fixture: pattern fired falsely in {names} (raw: {out})",
        )

    # ------------------------------------------------------------------
    # Codex PR#104 bug fix regressions
    # ------------------------------------------------------------------

    def test_check23_passes_real_scope_md_through_to_reasoner(self) -> None:
        """Bug #3 regression. With a real SCOPE.md in the workspace,
        Check #23 must resolve and forward it to the reasoner via
        `--scope`. We verify the reasoner's JSON `scope_file` field is
        not empty and points into the workspace directory. Because the
        shell check consumes the JSON internally, we also invoke the
        reasoner directly against a drafted stripped copy (same CLI
        shape Check #23 uses) to lock the contract.
        """
        with tempfile.TemporaryDirectory() as tmp:
            draft = _make_workspace(
                Path(tmp),
                # Clean draft — no OOS patterns should fire at all.
                textwrap.dedent(
                    """
                    # Finding: in-scope ERC20 accounting bug

                    **Severity:** High
                    **Rubric:** stealing of funds.
                    **Dollar impact:** $5,000.

                    ## Claim
                    The token's transferFrom allowance deduction is skipped
                    when `from == msg.sender`, permitting double-spend of
                    an already-approved allowance against another caller.

                    ## PoC
                    `test/AllowanceDoubleSpend.t.sol` — forge test.
                    """
                ).strip() + "\n",
                _scope_md_with_cross_chain_oos(),
            )

            # Drive the reasoner directly with the explicit --scope path
            # Check #23 will resolve.
            ws = draft.parents[3]
            scope = ws / "SCOPE.md"
            self.assertTrue(scope.exists(), scope)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REASONER),
                    "--draft",
                    str(draft),
                    "--scope",
                    str(scope),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            out = json.loads(proc.stdout)
            self.assertEqual(out.get("scope_file", ""), str(scope))
            # And Check #23 end-to-end: with a clean draft it should
            # report `in_scope` (not `cannot_judge`), proving SCOPE.md
            # actually reached the reasoner.
            pre_proc = _run_pre_submit(draft, fail_mode="warn")
            self.assertIn(
                "scope-reasoner: in_scope",
                pre_proc.stdout,
                pre_proc.stdout,
            )

    def test_check23_pattern_hit_without_scope_clause_is_advisory_not_likely_oos(
        self,
    ) -> None:
        """Bug #4 regression. If a draft pattern fires but SCOPE.md does
        NOT mention that OOS territory, Check #23 must emit an ADVISORY
        warn — never `likely_oos`, never a hard-fail in block mode.
        """
        with tempfile.TemporaryDirectory() as tmp:
            draft = _make_workspace(
                Path(tmp),
                _minimal_high_draft_triggering_cross_chain(),
                _scope_md_no_cross_chain(),
            )

            # Block mode is the strict setting — if the ladder is wrong,
            # this would hard-fail Check #23.
            proc = _run_pre_submit(draft, fail_mode="block")

            # The ADVISORY line appears.
            self.assertIn(
                "23. ADVISORY: scope-reasoner pattern cross_chain_atomicity",
                proc.stdout,
                proc.stdout,
            )
            # And critically: Check #23 did NOT emit the failure code.
            self.assertNotIn(
                "scope-reasoner-likely-oos",
                proc.stdout,
                proc.stdout,
            )
            # And the reasoner's JSON risk_level is `advisory`, not
            # `likely-OOS` (contract-level guard).
            ws = draft.parents[3]
            scope = ws / "SCOPE.md"
            rproc = subprocess.run(
                [
                    sys.executable,
                    str(REASONER),
                    "--draft",
                    str(draft),
                    "--scope",
                    str(scope),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            out = json.loads(rproc.stdout)
            self.assertEqual(out.get("risk_level"), "advisory", out)

    def test_check23_claim_after_pre_emptive_response_line_still_flagged(
        self,
    ) -> None:
        """Bug #5 regression. A draft that places a real OOS claim on
        the line right after `Pre-emptive response:` — WITHOUT wrapping
        it in the new markers — must NOT escape Check #23. The stripper
        no longer silently drops lines based on that header.
        """
        draft_text = textwrap.dedent(
            """
            # Finding: bridge pre-fund theft

            **Severity:** High
            **Rubric:** stealing of funds.
            **Dollar impact:** $12,000.

            ## Claim

            Standard draft body without cross-chain wording on its own.

            ## Triager-risk

            - [SNOW-R67-F001] Likely triager pushback: cross-chain.
              Pre-emptive response:
              The real exploit relies on cross-chain atomicity composed
              via a Polkadot-side bridgehub pre-fund race. Attacker
              atomically composes prefund then deposit across parachain
              origins, stealing $12k.

            ## PoC
            `test/PreFund.t.sol`.
            """
        ).strip() + "\n"

        with tempfile.TemporaryDirectory() as tmp:
            draft = _make_workspace(
                Path(tmp),
                draft_text,
                _scope_md_with_cross_chain_oos(),
            )

            proc = _run_pre_submit(draft, fail_mode="block")

            # The substantive OOS claim after `Pre-emptive response:` is
            # preserved; Check #23 must still flag likely_oos.
            self.assertIn(
                "scope-reasoner-likely-oos",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn(
                "pattern=cross_chain_atomicity",
                proc.stdout,
                proc.stdout,
            )

    def test_check23_delimited_rebuttal_block_is_stripped(self) -> None:
        """Bug #5 delimited-block regression. A rebuttal block wrapped
        in `<!-- rebuttal:start -->` / `<!-- rebuttal:end -->` markers
        IS stripped before the reasoner sees it. On a draft whose only
        cross-chain wording lives inside the markers, Check #23 must
        NOT flag.
        """
        draft_text = textwrap.dedent(
            """
            # Finding: clean in-scope accounting bug

            **Severity:** High
            **Rubric:** stealing of funds.
            **Dollar impact:** $5,000.

            ## Claim

            The contract's internal accounting under-credits the user on
            settlement. No cross-domain composition is involved; the
            entire attack is single-tx, single-chain.

            ## Triager-risk

            <!-- rebuttal:start -->
            - [SNOW-R67-F001] Likely triager pushback: OOS cross-chain atomicity.
              Pre-emptive response: Explicitly verify that the bridge /
              cross-chain step does NOT atomically compose the
              attacker-visible state transition end-to-end
              (Polkadot-origin + Ethereum-side). Cite the scope-review
              sub-agent's bridge semantics analysis. parachain bridgehub
              atomic prefund — all rebuttal prose.
            <!-- rebuttal:end -->

            ## PoC
            `test/Accounting.t.sol`.
            """
        ).strip() + "\n"

        with tempfile.TemporaryDirectory() as tmp:
            draft = _make_workspace(
                Path(tmp),
                draft_text,
                _scope_md_with_cross_chain_oos(),
            )

            proc = _run_pre_submit(draft, fail_mode="block")

            # No likely_oos and no advisory hit: the stripper dropped
            # the only cross-chain content.
            self.assertNotIn(
                "scope-reasoner-likely-oos",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn(
                "23. ADVISORY: scope-reasoner",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn(
                "scope-reasoner: in_scope",
                proc.stdout,
                proc.stdout,
            )


if __name__ == "__main__":
    unittest.main()
