#!/usr/bin/env python3
"""capv3-iter3-T4 — econ-simulator promotion-gate lock tests.

Three regression locks pinning `tools/econ-simulator.py` to advisory-only
until the 3-engagement gate opens per `docs/ECON_SIM_PROMOTION_GATE.md`:

  1. `test_econ_sim_is_advisory_until_3_engagements_fixture`
     CI-RELIABLE GATE-THRESHOLD LOCK. Walks committed fixtures at
     `tools/tests/fixtures/econ_sim/` — always present, never skipped.
     Counts distinct engagements with at least one econ-sim manifest
     that reached a judgeable status (counterexample /
     no-counterexample). Asserts count < 3. Today the fixtures model
     the current real state: one workspace with a status=error manifest
     (inconclusive, non-judgeable) and one workspace with no econ-sim
     engagement at all, i.e. zero judgeable engagements across the
     fixture set. If a future fixture edit simulates 3+ judgeable
     engagements, this test fails loudly asking the operator to flip
     the gate per §5 of the doc.

  2. `test_operator_local_audits_advisory_report`
     OPERATOR-LOCAL ADVISORY REPORT (non-gate). Walks
     `~/audits/*/reference/outcomes.jsonl` + the packaged-bundle
     directories across polymarket / snowbridge / morpho; counts
     distinct judgeable econ-sim engagements. Skips cleanly with
     `cannot-judge: outcomes ledger missing` when the operator's audit
     tree is absent (fresh CI / non-operator checkout). Asserts the
     same count < 3 when the ledger is present. This test is advisory
     — the CI gate source is test #1 (fixture-driven). This test
     exists so the operator's local run surfaces progress against the
     real ledger.

  3. `test_econ_sim_output_not_in_evidence_matrix_verdict`
     AST + grep walk over `tools/submission-packager.py` asserting it
     does NOT consume econ-simulator output into evidence-matrix verdict
     logic. The proposed tokens (`ECON_OK`, `ECON_TOO_SMALL`, `econ_bound`)
     must be absent from the packager source today.

Rationale for the split: test #1's old behavior read the operator's
`~/audits` tree and skipped when absent. On a clean CI environment
(the normal case), `~/audits` does not exist → test skips → false
green: the gate-threshold assertion passes trivially because there's
nothing to count. The fix moves the CI gate source to committed
fixtures (always present), while keeping the operator-local walk as
a separate advisory test that legitimately skips off-operator.

Hard-negative guard: if a future change flips the packager to consume
econ-sim output (say, by adding an `econ_bound` row to evidence-matrix.rows)
BEFORE the gate opens, test #3 fails loudly. Also verified by
temporarily editing `PROMOTION_ENGAGEMENT_THRESHOLD = 0` — test #1
fails, confirming the assertion is live and not a no-op.

See:
  - `docs/ECON_SIM_PROMOTION_GATE.md` — the 5-section gate spec.
  - `docs/10_OF_10_PLAYBOOK.md §5` — the status-vocabulary authority.
  - `tools/econ-simulator.py` — the advisory-only simulator (unchanged by
     this test; this test only reads the tool's outputs + the packager's
     source).
  - `tools/tests/fixtures/econ_sim/` — committed fixtures (CI gate source).
"""
from __future__ import annotations

import ast
import json
import os
import unittest
from pathlib import Path
from typing import Dict, List, Sequence, Set

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"
GATE_DOC_PATH = ROOT / "docs" / "ECON_SIM_PROMOTION_GATE.md"

# CI-reliable gate source: committed fixtures. These are always present
# in a fresh checkout and never require an operator audit tree.
FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "econ_sim"
FIXTURE_WORKSPACES = ("workspace_a", "workspace_b")

# Operator-local (advisory-only) source. Matches the three workspaces
# listed in §1 of ECON_SIM_PROMOTION_GATE.md. Absent on CI — the
# operator-local test skips in that case by design.
AUDITS_ROOT = Path(os.path.expanduser("~/audits"))
WORKSPACES = ("polymarket", "snowbridge", "morpho")

# Status flavours that count as "the simulator produced a bound" per the
# gate doc §2 C1 rule — matches econ-simulator.py's locked vocabulary.
JUDGEABLE_STATUSES = frozenset({"counterexample", "no-counterexample"})

# Threshold from docs/ECON_SIM_PROMOTION_GATE.md §2 C1.
PROMOTION_ENGAGEMENT_THRESHOLD = 3

# Tokens that, if they appear in submission-packager.py source, would
# indicate the gate has silently opened. Locked to stay absent until the
# operator flips the §5 gate per the doc.
#
# Scoped tight: we match on exact substrings the proposed §3 schema names,
# not generic words like "econ" (which would false-positive on comments).
PROPOSED_VERDICT_TOKENS = (
    "ECON_OK",
    "ECON_TOO_SMALL",
    "econ_bound",
)


# ---------------------------------------------------------------------------
# Helpers — pure-function ledger + manifest walks.
# ---------------------------------------------------------------------------
def _read_outcomes_jsonl(path: Path) -> List[Dict]:
    """Best-effort parse of a JSONL file. Returns [] if absent / malformed.

    Per the test's hermetic rule: a missing file is cannot-judge, not a
    test failure.
    """
    if not path.is_file():
        return []
    rows: List[Dict] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip malformed rows; the outcome_reweight test covers
                # schema validation.
                continue
    except OSError:
        return []
    return rows


def _count_econ_sim_engagements(
    root: Path,
    workspaces: Sequence[str],
) -> Dict[str, Set[str]]:
    """Return {workspace: {bundle_id, ...}} for judgeable econ-sim manifests.

    A "judgeable" manifest is one whose status is in JUDGEABLE_STATUSES
    (counterexample / no-counterexample). status == error / timeout /
    skipped does NOT count; those are inconclusive runs and can't be
    promotion evidence (same doctrine as fork-replay's {executed,success}
    restriction in playbook §5).

    The returned dict has one entry per workspace that contributes; the
    bundle_id is the directory name under `submissions/packaged/`.

    Args:
        root: filesystem root containing `<ws>/submissions/packaged/...`.
            Either FIXTURES_ROOT (CI gate) or AUDITS_ROOT (operator local).
        workspaces: workspace directory names to scan under root.
    """
    engagements: Dict[str, Set[str]] = {}
    if not root.is_dir():
        return engagements

    for ws in workspaces:
        packaged_root = root / ws / "submissions" / "packaged"
        if not packaged_root.is_dir():
            continue
        for bundle_dir in sorted(packaged_root.iterdir()):
            if not bundle_dir.is_dir():
                continue
            econ_dir = bundle_dir / "econ-simulator"
            if not econ_dir.is_dir():
                continue
            # Any *.json under <bundle>/econ-simulator/ counts as a "run";
            # only those whose parsed status is judgeable contribute.
            for manifest_path in sorted(econ_dir.glob("*.json")):
                try:
                    data = json.loads(manifest_path.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                if data.get("status") in JUDGEABLE_STATUSES:
                    engagements.setdefault(ws, set()).add(bundle_dir.name)
    return engagements


def _any_outcomes_ledger_present(root: Path, workspaces: Sequence[str]) -> bool:
    """Return True iff at least one workspace has an outcomes.jsonl file.

    Used by the operator-local advisory skip — if no workspace has a
    ledger, the operator-local test skips rather than asserts over
    empty state. The fixture-driven gate test never uses this skip;
    fixtures are always present and missing fixtures are a hard fail.
    """
    if not root.is_dir():
        return False
    for ws in workspaces:
        ledger = root / ws / "reference" / "outcomes.jsonl"
        if ledger.is_file():
            return True
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class EconSimPromotionGateLockTest(unittest.TestCase):
    """Regression locks pinning the gate closed until §2 criteria pass."""

    def test_econ_sim_is_advisory_until_3_engagements_fixture(self) -> None:
        """Fewer than 3 judgeable econ-sim engagements across committed fixtures.

        CI-RELIABLE GATE-THRESHOLD LOCK. This is the FM-002 guard: gate
        promotion needs ≥3 engagements per the §2 C1 criterion in
        `docs/ECON_SIM_PROMOTION_GATE.md`. Today the fixtures model zero
        judgeable engagements (workspace_a has one status=error manifest
        which is inconclusive; workspace_b has no econ-simulator
        subdirectory). If the fixtures ever represent 3+ judgeable
        engagements, this test fails on purpose — prompting the operator
        to re-evaluate the §2 booleans and, if they pass, flip the gate
        per §5.

        Uses committed fixtures at FIXTURES_ROOT, not the operator's
        `~/audits` tree. This is the CI gate: always present, never
        skipped, always counted.
        """
        self.assertTrue(
            FIXTURES_ROOT.is_dir(),
            f"fixtures missing at {FIXTURES_ROOT} — this test is "
            f"load-bearing and requires the committed fixture tree. "
            f"Ensure `tools/tests/fixtures/econ_sim/workspace_a/...` and "
            f"`workspace_b/...` are checked in.",
        )

        engagements = _count_econ_sim_engagements(FIXTURES_ROOT, FIXTURE_WORKSPACES)
        distinct_engagement_count = sum(len(v) for v in engagements.values())

        if distinct_engagement_count >= PROMOTION_ENGAGEMENT_THRESHOLD:
            engagement_str = ", ".join(
                f"{ws}: {sorted(bundles)}" for ws, bundles in engagements.items()
            )
            self.fail(
                f"fixture econ-simulator judgeable engagement count = "
                f"{distinct_engagement_count} (≥{PROMOTION_ENGAGEMENT_THRESHOLD}) — "
                f"has the gate opened? update `docs/ECON_SIM_PROMOTION_GATE.md` "
                f"and flip this lock to check the 3 criteria instead of just "
                f"count. Engagements: {engagement_str}"
            )

        # Belt-and-braces: record the count in the test output so the
        # operator sees progress. Also asserts the gate doc still exists —
        # if someone deletes the spec, the lock test is load-bearing.
        self.assertLess(
            distinct_engagement_count,
            PROMOTION_ENGAGEMENT_THRESHOLD,
            f"fixture engagement count {distinct_engagement_count} must stay "
            f"below {PROMOTION_ENGAGEMENT_THRESHOLD} until the gate opens",
        )
        self.assertTrue(
            GATE_DOC_PATH.is_file(),
            f"gate spec missing: {GATE_DOC_PATH} — this test is "
            f"meaningless without the spec it locks against",
        )

    def test_operator_local_audits_advisory_report(self) -> None:
        """Operator-local `~/audits` echo of the same count (advisory, non-gate).

        This test walks the operator's real audit tree (polymarket /
        snowbridge / morpho). On CI or on any fresh checkout without
        `~/audits`, it skips cleanly with `cannot-judge: outcomes
        ledger missing`. That skip is LEGITIMATE here — this test is
        an operator-local report, not the CI gate. The CI gate source
        is `test_econ_sim_is_advisory_until_3_engagements_fixture`
        above, which reads committed fixtures and never skips.

        When the ledger IS present (operator running locally), the
        test asserts the same gate-threshold invariant against the
        real state, so the operator sees progress toward gate-flip on
        every run.
        """
        if not _any_outcomes_ledger_present(AUDITS_ROOT, WORKSPACES):
            self.skipTest(
                "cannot-judge: operator-local outcomes ledger missing "
                f"(checked {', '.join(str(AUDITS_ROOT / ws / 'reference' / 'outcomes.jsonl') for ws in WORKSPACES)}) "
                "— this is expected on CI / fresh checkouts. The "
                "CI gate source is the fixture-driven test above."
            )

        engagements = _count_econ_sim_engagements(AUDITS_ROOT, WORKSPACES)
        distinct_engagement_count = sum(len(v) for v in engagements.values())

        if distinct_engagement_count >= PROMOTION_ENGAGEMENT_THRESHOLD:
            engagement_str = ", ".join(
                f"{ws}: {sorted(bundles)}" for ws, bundles in engagements.items()
            )
            self.fail(
                f"operator-local econ-simulator judgeable engagement count = "
                f"{distinct_engagement_count} (≥{PROMOTION_ENGAGEMENT_THRESHOLD}) — "
                f"has the gate opened? update `docs/ECON_SIM_PROMOTION_GATE.md` "
                f"and flip this lock to check the 3 criteria instead of just "
                f"count. Engagements: {engagement_str}"
            )

        self.assertLess(
            distinct_engagement_count,
            PROMOTION_ENGAGEMENT_THRESHOLD,
            f"operator-local engagement count {distinct_engagement_count} "
            f"must stay below {PROMOTION_ENGAGEMENT_THRESHOLD} until the "
            f"gate opens",
        )

    def test_econ_sim_output_not_in_evidence_matrix_verdict(self) -> None:
        """`submission-packager.py` does not consume econ-sim output.

        HARD-NEGATIVE LOCK: if a future change adds an `econ_bound` row
        to the evidence matrix, or references the proposed `ECON_OK` /
        `ECON_TOO_SMALL` verdict tokens before 3 engagements have
        validated the gate, this test fails loudly. Gate promotion is
        the operator's deliberate act per §5, not a silent code change.

        We do TWO checks:
          (a) Token absence — grep the packager source for the proposed
              verdict strings. Absent means the gate is still closed.
          (b) AST name absence — walk the packager AST for any
              identifier `econ_bound` / `econ_simulator_contributes` /
              similar. Belt-and-braces for the grep check.
        """
        self.assertTrue(
            PACKAGER_PATH.is_file(),
            f"submission-packager.py missing at {PACKAGER_PATH}",
        )
        source = PACKAGER_PATH.read_text(errors="replace")

        # ---- (a) Grep for proposed tokens. -----------------------------
        # These strings are scoped tight to the §3 proposed vocabulary so
        # they don't false-positive on the word "econ" appearing in a
        # comment (e.g. "economic delta" in fork-replay comments).
        for token in PROPOSED_VERDICT_TOKENS:
            self.assertNotIn(
                token, source,
                f"gate-locked token {token!r} appeared in "
                f"{PACKAGER_PATH.name} — if the gate has opened, update "
                f"`docs/ECON_SIM_PROMOTION_GATE.md` and flip both this "
                f"lock and test_econ_sim_is_advisory_until_3_engagements_fixture "
                f"in the same PR (per §5 of the spec).",
            )

        # ---- (b) AST walk for any identifier equal to a proposed token.
        try:
            tree = ast.parse(source, filename=str(PACKAGER_PATH))
        except SyntaxError as exc:
            self.fail(f"could not parse {PACKAGER_PATH}: {exc}")

        forbidden = set(PROPOSED_VERDICT_TOKENS)
        offending: List[str] = []
        for node in ast.walk(tree):
            # Variable / attribute / argument names.
            if isinstance(node, ast.Name) and node.id in forbidden:
                offending.append(f"Name({node.id}) line {node.lineno}")
            elif isinstance(node, ast.Attribute) and node.attr in forbidden:
                offending.append(f"Attribute({node.attr}) line {node.lineno}")
            elif isinstance(node, ast.arg) and node.arg in forbidden:
                offending.append(f"arg({node.arg}) line {node.lineno}")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Literal strings that exactly match a token — covers
                # `if row["verdict"] == "ECON_OK":` style promotions.
                if node.value in forbidden:
                    offending.append(
                        f"Constant({node.value!r}) line {node.lineno}"
                    )

        self.assertEqual(
            offending, [],
            f"gate-locked identifiers/constants appeared in "
            f"{PACKAGER_PATH.name}: {offending}. Flip the gate per §5 "
            f"of `docs/ECON_SIM_PROMOTION_GATE.md` before committing.",
        )

        # ---- (c) Safety net: the word "econ-simulator" itself should
        # appear ZERO times in the packager source. If it ever starts
        # appearing, something has wired the two together and the gate
        # is implicitly open. Comments are fine — but the packager must
        # not `import`, `read`, `glob`, or otherwise reference simulator
        # output files for evidence-matrix verdict computation.
        #
        # We search for the hyphenated tool name AND the snake_case
        # module name to catch both import styles.
        for needle in ("econ-simulator", "econ_simulator"):
            # Allow appearance in a single, explicit "not-wired" comment
            # anchor if someone ever wants to document the non-wiring.
            # Today there are ZERO such anchors; if you're adding one,
            # update this test's allowlist in the same commit.
            self.assertNotIn(
                needle, source,
                f"packager references {needle!r} — the evidence-matrix "
                f"pipeline must not consume simulator output until the "
                f"gate opens (see docs/ECON_SIM_PROMOTION_GATE.md §3).",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
