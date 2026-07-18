#!/usr/bin/env python3
"""capv3-iter7-T3 — symbolic-runner promotion-gate lock tests.

Three regression locks pinning `tools/symbolic-runner.sh` to advisory-only
until the 3-engagement gate flips per `docs/SYMBOLIC_PROMOTION_GATE.md`:

  1. `test_symbolic_gate_before_3_engagements_is_advisory`
     CI-RELIABLE GATE-THRESHOLD LOCK. Walks committed fixtures at
     `tools/tests/fixtures/symbolic_gate/` — always present, never
     skipped. Counts distinct engagements where a symbolic-runner
     manifest produced `status: counterexample` AND the matching
     outcomes.jsonl row is triager-accepted at High+. Asserts the
     S1 predicate count < 3. ALSO asserts the proposed post-promotion
     vocabulary (`SYM_OK`, `SYM_CE`, `symbolic_bound`) is absent
     from `tools/submission-packager.py` (grep + AST walk) — the
     two halves of "the gate has not silently opened" live together.
     Today the fixtures model zero qualifying engagements:
     workspace_a has one `status: no-counterexample` manifest
     (negative, does NOT count) + one `status: error` manifest
     (inconclusive, does NOT count); workspace_b has a packaged
     bundle with no symbolic/ subdir (mirrors
     polymarket/snowbridge/morpho).

  2. `test_symbolic_gate_with_3_qualifying_engagements_would_promote`
     HYPOTHETICAL-PROMOTION PROBE. Builds an in-memory scratch tree
     representing 3 distinct workspaces each with a
     `status: counterexample` manifest AND a matching
     `outcome ∈ {accepted, paid, in_review}` + `severity ∈ {High,
     Critical}` row in outcomes.jsonl. Asserts the S1 predicate
     evaluates True against that scratch tree (would promote) while
     the real/fixture state stays at 0 (does NOT actually promote).
     This test proves the gate's promotion arm is live — if the
     predicate were bricked to always-False, this test would fail.

  3. `test_symbolic_gate_false_positive_escalation_keeps_advisory`
     S3 FALSE-POSITIVE LOCK. Builds an in-memory scratch tree with
     1 `status: counterexample` symbolic manifest AND 1 outcomes.jsonl
     row with `outcome: rejected` + `rejection_reason` matching the
     S3 false-positive regex (e.g. "unrealistic bounds"). Asserts S3
     evaluates >= 1 → gate stays advisory regardless of S1/S2 state.
     Proves the S3 arm is live.

Hard-negative guards: if a future change flips the packager to
consume symbolic-runner output (adds any of `SYM_OK` / `SYM_CE` /
`symbolic_bound`), test #1's belt-and-braces arm fails loudly.
Patching `PROMOTION_ENGAGEMENT_THRESHOLD = 0` or bricking
`_count_symbolic_s1_engagements` to always-0 → test #2 fails
because the synthetic scratch tree no longer satisfies the
predicate. Bricking `_count_s3_false_positive_escalations` to
always-0 → test #3 fails.

See:
  - `docs/SYMBOLIC_PROMOTION_GATE.md` — the 5-section gate spec.
  - `docs/10_OF_10_PLAYBOOK.md §5` — the status-vocabulary authority.
  - `docs/ECON_SIM_PROMOTION_GATE.md` — sister gate (template).
  - `tools/symbolic-runner.sh` — the advisory-only runner (unchanged
    by this test; this test only reads outputs + packager source).
  - `tools/tests/fixtures/symbolic_gate/` — committed fixtures.
"""
from __future__ import annotations

import ast
import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Sequence, Set

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"
GATE_DOC_PATH = ROOT / "docs" / "SYMBOLIC_PROMOTION_GATE.md"

# CI-reliable gate source: committed fixtures. Always present in a fresh
# checkout; never require an operator audit tree.
FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "symbolic_gate"
FIXTURE_WORKSPACES = ("workspace_a", "workspace_b")

# Threshold from docs/SYMBOLIC_PROMOTION_GATE.md §2 S1.
PROMOTION_ENGAGEMENT_THRESHOLD = 3

# S1: only `counterexample` status counts. `no-counterexample`, `timeout`,
# `error`, `skipped`, `pass` do not — see gate doc §2 S1 "Status flavours
# that count".
S1_COUNTING_STATUSES = frozenset({"counterexample"})

# Triager-accept states per gate doc §2 S1.
ACCEPT_OUTCOMES = frozenset({"accepted", "paid", "in_review"})

# Severity floor for S1 qualifying engagements.
HIGH_PLUS_SEVERITIES = frozenset({"High", "Critical"})

# S3 false-positive rejection-reason regex.
S3_FALSE_POSITIVE_RX = re.compile(
    r"symbolic[- ]only|bounds[- ]out[- ]of[- ]scope|"
    r"economic(ally)? (infeasible|impossible)|unrealistic[- ]bounds|"
    r"POLY-45",
    re.IGNORECASE,
)

# Tokens that, if they appear in submission-packager.py, indicate the gate
# has silently flipped. Scoped tight to §3's proposed schema names.
PROPOSED_VERDICT_TOKENS = (
    "SYM_OK",
    "SYM_CE",
    "symbolic_bound",
)


# ---------------------------------------------------------------------------
# Helpers — pure-function ledger + manifest walks.
# ---------------------------------------------------------------------------
def _read_outcomes_jsonl(path: Path) -> List[Dict]:
    """Best-effort parse of a JSONL file. Returns [] if absent / malformed."""
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
                continue
    except OSError:
        return []
    return rows


def _bundle_id_matches_report(bundle_id: str, report_id: str) -> bool:
    """Heuristic match between a bundle directory name and a report_id.

    Fixture convention: bundle `sample-cent-bundle` matches outcome
    `FIXTURE-SYMA-01` by position (first bundle alphabetically matches
    first outcome row). This mirrors the econ-sim gate's practice of
    pairing by directory-order. In real engagements the operator
    establishes the mapping via the report_id → bundle-slug convention.
    """
    # Substring / slug match; fall back to alphanumeric containment.
    ba = re.sub(r"[^a-z0-9]", "", bundle_id.lower())
    ra = re.sub(r"[^a-z0-9]", "", report_id.lower())
    if not ba or not ra:
        return False
    return ba in ra or ra in ba


def _count_symbolic_s1_engagements(
    root: Path,
    workspaces: Sequence[str],
) -> int:
    """Return S1-qualifying engagement count under `root`.

    An engagement counts iff: (a) a symbolic-runner manifest under
    `<ws>/submissions/packaged/<bundle>/symbolic/*.json` has
    `status: counterexample`, AND (b) outcomes.jsonl in that
    workspace has a row whose report_id maps to <bundle> with
    `outcome ∈ ACCEPT_OUTCOMES` AND `severity ∈ HIGH_PLUS_SEVERITIES`.

    Each (workspace, bundle) pair counts once.
    """
    if not root.is_dir():
        return 0

    qualifying = 0
    for ws in workspaces:
        packaged_root = root / ws / "submissions" / "packaged"
        if not packaged_root.is_dir():
            continue
        outcomes = _read_outcomes_jsonl(
            root / ws / "reference" / "outcomes.jsonl"
        )
        for bundle_dir in sorted(packaged_root.iterdir()):
            if not bundle_dir.is_dir():
                continue
            sym_dir = bundle_dir / "symbolic"
            if not sym_dir.is_dir():
                continue
            has_ce = False
            for manifest_path in sorted(sym_dir.glob("*.json")):
                try:
                    data = json.loads(manifest_path.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                if data.get("status") in S1_COUNTING_STATUSES:
                    has_ce = True
                    break
            if not has_ce:
                continue
            for row in outcomes:
                if not _bundle_id_matches_report(
                    bundle_dir.name, row.get("report_id", "")
                ):
                    continue
                if (
                    row.get("outcome") in ACCEPT_OUTCOMES
                    and row.get("severity") in HIGH_PLUS_SEVERITIES
                ):
                    qualifying += 1
                    break
    return qualifying


def _count_s3_false_positive_escalations(
    root: Path,
    workspaces: Sequence[str],
) -> int:
    """Return count of S3 false-positive escalations under `root`.

    An escalation counts iff: (a) outcomes.jsonl row has
    `outcome: rejected` AND `rejection_reason` matches
    S3_FALSE_POSITIVE_RX, AND (b) the matching packaged bundle
    has a symbolic manifest with `status: counterexample` (i.e.
    the CE would have contributed to promoting the rejected draft).
    """
    if not root.is_dir():
        return 0

    count = 0
    for ws in workspaces:
        packaged_root = root / ws / "submissions" / "packaged"
        if not packaged_root.is_dir():
            continue
        outcomes = _read_outcomes_jsonl(
            root / ws / "reference" / "outcomes.jsonl"
        )
        for row in outcomes:
            if row.get("outcome") != "rejected":
                continue
            reason = row.get("rejection_reason", "")
            if not S3_FALSE_POSITIVE_RX.search(reason):
                continue
            report_id = row.get("report_id", "")
            for bundle_dir in sorted(packaged_root.iterdir()):
                if not bundle_dir.is_dir():
                    continue
                if not _bundle_id_matches_report(bundle_dir.name, report_id):
                    continue
                sym_dir = bundle_dir / "symbolic"
                if not sym_dir.is_dir():
                    continue
                for manifest_path in sorted(sym_dir.glob("*.json")):
                    try:
                        data = json.loads(manifest_path.read_text())
                    except (OSError, json.JSONDecodeError):
                        continue
                    if data.get("status") == "counterexample":
                        count += 1
                        break
                break
    return count


def _write_manifest(
    path: Path, *, status: str, angle: str, bundle_name: str
) -> None:
    """Write a minimal symbolic-runner-shaped manifest to `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "advisory": True,
                "angle": angle,
                "bundle": f"<scratch>/{bundle_name}",
                "evidence_matrix_contributes": False,
                "mode": "live",
                "schema_version": 1,
                "severity_upgrade_allowed": False,
                "status": status,
                "timestamp": "2026-04-24T00:00:00Z",
                "tool": "symbolic-runner",
            },
            indent=2,
        )
    )


def _write_outcomes(path: Path, rows: Sequence[Dict]) -> None:
    """Write a JSONL outcomes file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _build_hypothetical_3_qualifying_tree(root: Path) -> Sequence[str]:
    """Build a scratch tree with 3 distinct S1-qualifying engagements.

    Three workspaces, each with one bundle containing one
    `status: counterexample` symbolic manifest + one outcomes.jsonl
    row with `outcome: accepted` + `severity: High` whose report_id
    maps to that bundle. Returns the list of workspace names written.
    """
    workspaces = (
        "hypo_polymarket",
        "hypo_snowbridge",
        "hypo_morpho",
    )
    for i, ws in enumerate(workspaces, start=1):
        bundle = f"hypo-bundle-r{i:02d}"
        manifest = (
            root
            / ws
            / "submissions"
            / "packaged"
            / bundle
            / "symbolic"
            / "A-HYPO-ANGLE.json"
        )
        _write_manifest(
            manifest,
            status="counterexample",
            angle="A-HYPO-ANGLE",
            bundle_name=bundle,
        )
        outcomes_path = root / ws / "reference" / "outcomes.jsonl"
        _write_outcomes(
            outcomes_path,
            [
                {
                    "outcome": "accepted",
                    "platform": "cantina",
                    "recorded_at": "2026-04-24T00:00:00Z",
                    "report_id": bundle,  # exact match to bundle name
                    "severity": "High",
                    "status": "Accepted",
                    "title": (
                        "Hypothetical row \u2014 post-promotion S1 "
                        "qualifying: symbolic CE + High+ accept"
                    ),
                    "url": "pending",
                    "workspace": ws,
                }
            ],
        )
    return workspaces


def _build_fp_escalation_tree(root: Path) -> Sequence[str]:
    """Build a scratch tree with 1 S3 false-positive escalation.

    One workspace, one bundle with `status: counterexample` symbolic
    manifest, plus an outcomes.jsonl row with `outcome: rejected` AND
    `rejection_reason` matching the S3 false-positive regex. This
    represents the failure-mode scenario: symbolic CE triggered
    escalation, triager then rejected for economic-impossibility.
    """
    workspaces = ("fp_polymarket",)
    bundle = "fp-bundle-r45"
    manifest = (
        root
        / workspaces[0]
        / "submissions"
        / "packaged"
        / bundle
        / "symbolic"
        / "A-FP-ANGLE.json"
    )
    _write_manifest(
        manifest,
        status="counterexample",
        angle="A-FP-ANGLE",
        bundle_name=bundle,
    )
    outcomes_path = (
        root / workspaces[0] / "reference" / "outcomes.jsonl"
    )
    _write_outcomes(
        outcomes_path,
        [
            {
                "outcome": "rejected",
                "platform": "cantina",
                "recorded_at": "2026-04-24T00:00:00Z",
                "rejection_reason": (
                    "unrealistic bounds: CE uses makerAmount >= 2^248 "
                    "which is not economically feasible given token supply"
                ),
                "report_id": bundle,
                "resolved_at": "2026-04-24T00:00:00Z",
                "severity": "High",
                "status": "Rejected",
                "title": (
                    "Hypothetical FP row \u2014 symbolic CE led to draft "
                    "that triager rejected for economic impossibility"
                ),
                "url": "pending",
                "workspace": workspaces[0],
            }
        ],
    )
    return workspaces


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class SymbolicPromotionGateLockTest(unittest.TestCase):
    """Regression locks pinning the gate closed until §2 criteria pass."""

    def test_symbolic_gate_before_3_engagements_is_advisory(self) -> None:
        """Fewer than 3 S1-qualifying symbolic engagements across fixtures.

        CI-RELIABLE GATE-THRESHOLD LOCK. Gate promotion needs ≥3
        engagements per §2 S1 in `docs/SYMBOLIC_PROMOTION_GATE.md`.
        Today the fixtures model zero qualifying engagements
        (workspace_a: no-counterexample + error manifests — neither
        judgeable as CE; workspace_b: bundle with no symbolic/ dir).
        If the committed fixtures ever represent 3+ qualifying
        engagements, this test fails on purpose — prompting the
        operator to re-evaluate §2 booleans and, if they pass, flip
        the gate per §5.

        Uses committed fixtures at FIXTURES_ROOT — always present,
        never skipped.
        """
        self.assertTrue(
            FIXTURES_ROOT.is_dir(),
            f"fixtures missing at {FIXTURES_ROOT} — this test is "
            f"load-bearing and requires the committed fixture tree. "
            f"Ensure `tools/tests/fixtures/symbolic_gate/workspace_a/...` "
            f"and `workspace_b/...` are checked in.",
        )

        qualifying = _count_symbolic_s1_engagements(
            FIXTURES_ROOT, FIXTURE_WORKSPACES
        )

        if qualifying >= PROMOTION_ENGAGEMENT_THRESHOLD:
            self.fail(
                f"fixture symbolic S1 qualifying engagement count = "
                f"{qualifying} (>= {PROMOTION_ENGAGEMENT_THRESHOLD}) — "
                f"has the gate flipped? update "
                f"`docs/SYMBOLIC_PROMOTION_GATE.md` and flip this "
                f"lock to check the 3 criteria instead of just count."
            )

        self.assertLess(
            qualifying,
            PROMOTION_ENGAGEMENT_THRESHOLD,
            f"fixture S1 engagement count {qualifying} must stay "
            f"below {PROMOTION_ENGAGEMENT_THRESHOLD} until the gate flips",
        )
        self.assertTrue(
            GATE_DOC_PATH.is_file(),
            f"gate spec missing: {GATE_DOC_PATH} — this test is "
            f"meaningless without the spec it locks against",
        )
        # Honest-zero: today the fixtures represent 0 qualifying
        # engagements (no 'counterexample' status anywhere in fixtures).
        self.assertEqual(
            qualifying,
            0,
            f"fixture S1 count expected 0 today (no counterexample "
            f"manifests in committed fixtures); got {qualifying}. If "
            f"fixtures were intentionally updated to model a CE, "
            f"update this assertion in the same PR.",
        )

        # Belt-and-braces: the proposed post-promotion vocabulary
        # (SYM_OK / SYM_CE / symbolic_bound) must be ABSENT from
        # submission-packager.py until the gate flips. This lives
        # inside test #1 because the advisory-state assertion and
        # the not-yet-emitted-tokens assertion are two halves of the
        # same invariant: "the gate has not silently opened".
        self.assertTrue(
            PACKAGER_PATH.is_file(),
            f"submission-packager.py missing at {PACKAGER_PATH}",
        )
        packager_src = PACKAGER_PATH.read_text(errors="replace")
        for token in PROPOSED_VERDICT_TOKENS:
            self.assertNotIn(
                token,
                packager_src,
                f"gate-locked token {token!r} appeared in "
                f"{PACKAGER_PATH.name} — if the gate has flipped, "
                f"update `docs/SYMBOLIC_PROMOTION_GATE.md` and this "
                f"lock in the same PR (per §5).",
            )
        # AST walk for identifiers / literals matching tokens — catches
        # the case where a proposed token appears as a variable / attr /
        # arg / constant (not only inside comments).
        try:
            tree = ast.parse(packager_src, filename=str(PACKAGER_PATH))
        except SyntaxError as exc:
            self.fail(f"could not parse {PACKAGER_PATH}: {exc}")
        forbidden = set(PROPOSED_VERDICT_TOKENS)
        offending: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in forbidden:
                offending.append(f"Name({node.id}) line {node.lineno}")
            elif isinstance(node, ast.Attribute) and node.attr in forbidden:
                offending.append(f"Attribute({node.attr}) line {node.lineno}")
            elif isinstance(node, ast.arg) and node.arg in forbidden:
                offending.append(f"arg({node.arg}) line {node.lineno}")
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in forbidden
            ):
                offending.append(
                    f"Constant({node.value!r}) line {node.lineno}"
                )
        self.assertEqual(
            offending,
            [],
            f"gate-locked identifiers/constants appeared in "
            f"{PACKAGER_PATH.name}: {offending}",
        )

    def test_symbolic_gate_with_3_qualifying_engagements_would_promote(
        self,
    ) -> None:
        """Synthetic 3-qualifying-engagement tree would flip the S1 bit.

        HYPOTHETICAL-PROMOTION PROBE. Builds an in-memory scratch tree
        with 3 qualifying engagements in 3 workspaces; asserts S1
        predicate count >= 3 against that tree — i.e. if this state
        were real, the S1 arm would pass. The real fixture / ~/audits
        state stays at 0, so the gate does NOT actually flip.

        This test is the promotion-arm proof: without it, the S1
        counter could silently be bricked to always-0 and test #1
        would still pass (trivially). With this test, a bricked S1
        would fail here.
        """
        with tempfile.TemporaryDirectory(prefix="sym_gate_promo_") as tmp:
            scratch = Path(tmp)
            workspaces = _build_hypothetical_3_qualifying_tree(scratch)

            qualifying = _count_symbolic_s1_engagements(
                scratch, workspaces
            )

            self.assertGreaterEqual(
                qualifying,
                PROMOTION_ENGAGEMENT_THRESHOLD,
                f"hypothetical scratch tree built with 3 qualifying "
                f"engagements but S1 predicate counted only "
                f"{qualifying} — the S1 counter is bricked or the "
                f"scratch-tree builder is mis-specified. If the S1 "
                f"predicate has been updated, update the scratch "
                f"builder in the same PR.",
            )

            # Belt-and-braces: real fixture state must still be < 3,
            # i.e. the gate has NOT actually flipped because of this
            # hypothetical test. This is the FM-002 guard.
            real_fixture_count = _count_symbolic_s1_engagements(
                FIXTURES_ROOT, FIXTURE_WORKSPACES
            )
            self.assertLess(
                real_fixture_count,
                PROMOTION_ENGAGEMENT_THRESHOLD,
                f"real fixture S1 count {real_fixture_count} >= "
                f"{PROMOTION_ENGAGEMENT_THRESHOLD} — the hypothetical "
                f"probe must not leak into the CI gate; test #1 should "
                f"be the authoritative gate-state assertion.",
            )

    def test_symbolic_gate_false_positive_escalation_keeps_advisory(
        self,
    ) -> None:
        """S3 arm fires on a single FP escalation → gate stays advisory.

        Builds an in-memory scratch tree with 1 symbolic CE + 1
        rejection with `rejection_reason` matching the S3 regex.
        Asserts the S3 counter returns >= 1, which per gate doc §2
        S3 means S3 FAILS → gate cannot flip even if S1 and S2 both
        passed.

        This test proves the S3 arm is live and not a no-op.
        """
        with tempfile.TemporaryDirectory(prefix="sym_gate_fp_") as tmp:
            scratch = Path(tmp)
            workspaces = _build_fp_escalation_tree(scratch)

            fp_count = _count_s3_false_positive_escalations(
                scratch, workspaces
            )

            self.assertGreaterEqual(
                fp_count,
                1,
                f"hypothetical scratch tree built with 1 FP escalation "
                f"but S3 counter returned {fp_count} — the S3 arm is "
                f"bricked or the scratch-tree builder is mis-specified. "
                f"If the S3 regex has been updated, update the scratch "
                f"builder's `rejection_reason` in the same PR.",
            )

            # Real-fixture state: S3 count must be 0 today. Fixtures
            # deliberately do NOT include an FP escalation row; S3
            # passes trivially at baseline.
            real_fp_count = _count_s3_false_positive_escalations(
                FIXTURES_ROOT, FIXTURE_WORKSPACES
            )
            self.assertEqual(
                real_fp_count,
                0,
                f"real fixture S3 false-positive count expected 0 "
                f"(no FP escalations in fixtures); got {real_fp_count}. "
                f"If fixtures were intentionally updated, update this "
                f"assertion in the same PR.",
            )

            # Gate-state implication: because fp_count >= 1 against
            # the scratch tree, S3 fails → gate.advisory_status ==
            # 'advisory' regardless of S1/S2. Encoded as a boolean.
            gate_would_stay_advisory = fp_count >= 1
            self.assertTrue(
                gate_would_stay_advisory,
                "S3 failure must keep gate advisory; inversion means "
                "the S3 arm is not load-bearing",
            )

if __name__ == "__main__":
    unittest.main(verbosity=2)
