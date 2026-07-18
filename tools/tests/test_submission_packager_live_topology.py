#!/usr/bin/env python3
"""iter4-T1 regression tests — packager/pre-submit live-topology filename reconciliation.

Covers (per docs/LOOP_ITER_004_PLAN.md §T1):

  1. `test_packager_writes_bundle_local_live_topology_at_bundle_root`
     — packager mirrors <ws>/live_topology_checks.json into
       <bundle>/live_topology_checks.json byte-for-byte for live-proof-
       dependent drafts.
  2. `test_packager_bundle_passes_check21_after_repackage`
     — `tools/pre-submit-check.sh <bundle>/source-draft.md --severity <sev>`
       emits zero `❌ 21.` and at least one `✅ 21.` or `⚠️  21.` for a
       freshly packaged bundle.
  3. `test_packager_preserves_live_proof_subdir_alias`
     — existing reviewer-friendly `<bundle>/live-proof/live_topology_checks.json`
       copy is still written.
  4. `test_packager_fails_when_source_live_topology_missing`
     — fail-closed path: gates-run with live-proof-dependent draft + no
       `<ws>/live_topology_checks.json` → packager returns non-zero and
       does NOT produce a bundle. Hard-negative lock: never synthesize a
       stub live-topology file.

Offline. No network. Shell out to `tools/submission-packager.py` + the
pre-submit bash script against fixture bundles. Mirrors iter3-T1's
`test_submission_packager_scope_review.py` structure intentionally.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGER = ROOT / "tools" / "submission-packager.py"
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


SCOPE_REVIEW_FIXTURE = """# Heuristic scope review

VERDICT: NOVEL

score=2 (below SAME-CLASS threshold)
oos_overlap=none
reasoning:
- Draft does not touch any audited vector in OOS_CHECKLIST.
- Graph-query similarity score is below threshold.
- No scope-ack language detected.
"""


# Draft that trips `draft_requires_live_proof` (mainnet + 0x... hits >= 2)
# and carries a Live Proof section citing the one known row id we bundle
# into the fixture `live_topology_checks.json`. Uses source-only override
# language so pre-submit Check #21 accepts the bundle via the ⚠️  branch
# even if row-matching heuristics don't find every contract — we only
# need the lookup to resolve to a readable JSON (i.e. ❌ never emitted
# for the "file missing" reason, which is what iter4-T1 is repairing).
LIVE_PROOF_DRAFT = """# Sample finding — live-proof-dependent

**Severity:** Medium

## Summary

A minimal finding targeting a contract deployed to Polygon mainnet at
address `0xADa100874d00e3331D00F2007a9c336a65009718`. Used only for
iter4-T1 packaging regression tests.

## Finding Description

The `CtfCollateralAdapter` at `0xADa100874d00e3331D00F2007a9c336a65009718`
is deployed on Polygon mainnet. It reads `balanceOf(address(this))` and
pays the full balance to the caller.

## Impact

Minor — fixture-level finding used only for packaging tests.

## Live Proof

**Live proof evidence: source-only rationale.** This finding is a source-
level pattern defect and does not depend on mutable on-chain state. Live
topology data is bundled as `test-row-0` in `live_topology_checks.json`
for reviewer completeness.
"""


LIVE_TOPOLOGY_FIXTURE = {
    # Use status=dry_run so the packager emits a warning rather than
    # failing closed on "executed-unpinned" (which requires a pinned block
    # field on pass/fail rows — orthogonal to iter4-T1's filename-copy
    # concern). This keeps the fixture live-proof-complete from Check #21's
    # POV (the JSON exists, is well-formed, has a matching row) while
    # avoiding unrelated gate failures.
    "results": [
        {
            "id": "test-row-0",
            "contract": "CtfCollateralAdapter",
            "address": "0xADa100874d00e3331D00F2007a9c336a65009718",
            "status": "dry_run",
            "related_angle_ids": ["A-TEST"],
        }
    ]
}


PAIR_PROOF_DRAFT = """# Cross-contract live proof fixture

**Severity:** High

## Summary

The deployed VaultAdapter on Polygon mainnet reads a live RiskManager wiring
edge before allowing withdrawals.

## Finding Description

VaultAdapter at `0x1111111111111111111111111111111111111111` depends on
RiskManager at `0x2222222222222222222222222222222222222222`.

## Impact

Cross-contract wiring proof fixture.

## Live Proof

A-AUTH is supported by exact live-proof rows `edge-row` and `authority-row`.
"""


def _make_workspace(tmp: Path, *, with_live_topology: bool = True) -> Path:
    """Build a minimal but complete workspace layout.

    When ``with_live_topology`` is True, writes a minimal
    ``live_topology_checks.json`` at the workspace root (the source of
    truth the packager copies into the bundle).
    """
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "scope_review").mkdir(parents=True)
    # Workspace anchor for pre-submit's `_WS` ancestor walk when running
    # against the original (pre-package) draft.
    (ws / "OOS_CHECKLIST.md").write_text("# Workspace OOS checklist\n")
    if with_live_topology:
        (ws / "live_topology_checks.json").write_text(
            json.dumps(LIVE_TOPOLOGY_FIXTURE, indent=2)
        )
    return ws


def _write_draft(ws: Path, name: str, body: str | None = None) -> Path:
    """Write a live-proof-dependent staging draft (basename stem != 'source-draft')."""
    draft = ws / "submissions" / "staging" / name
    draft.write_text(body if body is not None else LIVE_PROOF_DRAFT)
    return draft


def _write_scope_review(ws: Path, draft_stem: str, content: str | None = None) -> Path:
    review = ws / "scope_review" / f"{draft_stem}.heuristic-review.md"
    review.write_text(content if content is not None else SCOPE_REVIEW_FIXTURE)
    return review


def _write_pair_live_topology(ws: Path, *, authority_block: str = "12345") -> None:
    (ws / "live_topology_checks.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "id": "edge-row",
                        "contract": "VaultAdapter",
                        "address": "0x1111111111111111111111111111111111111111",
                        "status": "pass",
                        "block": "12345",
                        "evidence_class": "topology-relation",
                        "related_angle_ids": ["A-AUTH"],
                    },
                    {
                        "id": "authority-row",
                        "contract": "RiskManager",
                        "address": "0x2222222222222222222222222222222222222222",
                        "status": "pass",
                        "block": authority_block,
                        "evidence_class": "topology-relation",
                        "related_angle_ids": ["A-AUTH"],
                    },
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _run_packager(
    ws: Path,
    draft_path: Path,
    *,
    skip_gates: bool = True,
) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(PACKAGER), str(ws), str(draft_path), "--json"]
    if skip_gates:
        argv.append("--skip-gates")
    return subprocess.run(argv, capture_output=True, text=True)


def _find_bundle(ws: Path) -> Path:
    pkg_root = ws / "submissions" / "packaged"
    children = [p for p in pkg_root.iterdir() if p.is_dir()]
    assert len(children) == 1, f"expected 1 packaged bundle, got {len(children)}: {children}"
    return children[0]


class BundleLocalLiveTopologyTest(unittest.TestCase):
    """T1 acceptance test #1: bundle-local live-topology mirror at bundle root."""

    def test_packager_writes_bundle_local_live_topology_at_bundle_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar_live.md")
            _write_scope_review(ws, "foo_bar_live")
            source = ws / "live_topology_checks.json"

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)

            # A) Bundle-local live-topology anchor exists at bundle root.
            bundle_anchor = bundle / "live_topology_checks.json"
            self.assertTrue(
                bundle_anchor.is_file(),
                f"bundle missing bundle-local live_topology_checks.json at {bundle_anchor}",
            )

            # B) The anchor is byte-identical to the source artifact.
            self.assertEqual(
                bundle_anchor.read_bytes(),
                source.read_bytes(),
                msg=(
                    "bundle-local live_topology_checks.json diverges from "
                    "source artifact — must be byte-identical copy, never a stub"
                ),
            )


class BundlePassesCheck21Test(unittest.TestCase):
    """T1 acceptance test #2: pre-submit Check #21 stops ❌-ing against the bundle."""

    def test_packager_bundle_passes_check21_after_repackage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar_live.md")
            _write_scope_review(ws, "foo_bar_live")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            bundle_draft = bundle / "source-draft.md"
            self.assertTrue(bundle_draft.is_file(), "bundle missing source-draft.md")

            # Run pre-submit-check.sh against the bundle's source-draft.md.
            # We only care about Check #21: 0 × `❌ 21.` and >=1 × ✅/⚠️ 21.
            # Other pre-submit checks may fail against the toy fixture;
            # that's outside T1's scope.
            result = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(bundle_draft), "--severity", "Medium"],
                capture_output=True,
                text=True,
            )
            stdout = result.stdout
            check_21_fail_count = stdout.count("❌ 21.")
            check_21_pass_count = (
                stdout.count("✅ 21.") + stdout.count("⚠️  21.")
            )
            self.assertEqual(
                check_21_fail_count, 0,
                msg=(
                    "pre-submit Check #21 failed against bundle-local draft; "
                    f"output=\n{stdout}\nstderr={result.stderr}"
                ),
            )
            self.assertGreaterEqual(
                check_21_pass_count, 1,
                msg=(
                    "pre-submit Check #21 did not emit a ✅ or ⚠️ against bundle; "
                    f"output=\n{stdout}\nstderr={result.stderr}"
                ),
            )


class LegacyLiveProofSubdirAliasTest(unittest.TestCase):
    """T1 acceptance test #3: legacy <bundle>/live-proof/ alias still written."""

    def test_packager_preserves_live_proof_subdir_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = _write_draft(ws, "foo_bar_live.md")
            _write_scope_review(ws, "foo_bar_live")
            source = ws / "live_topology_checks.json"

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)

            # Legacy reviewer-legibility subdirectory copy must persist —
            # iter4-T1 adds a bundle-root anchor but does NOT regress the
            # existing bundle layout. Mirrors iter3-T1's `scope-review.md`
            # legacy-alias preservation pattern.
            legacy_subdir = bundle / "live-proof" / "live_topology_checks.json"
            self.assertTrue(
                legacy_subdir.is_file(),
                f"legacy <bundle>/live-proof/live_topology_checks.json missing at {legacy_subdir}",
            )
            self.assertEqual(
                legacy_subdir.read_bytes(),
                source.read_bytes(),
                msg="legacy live-proof/ subdir copy drifted from source artifact",
            )


class LiveProofPairIntegrityManifestTest(unittest.TestCase):
    """Packaged live-proof manifests should surface same-block pair integrity."""

    def test_packager_records_complete_same_block_topology_pair_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), with_live_topology=False)
            _write_pair_live_topology(ws)
            draft = _write_draft(ws, "pair_live.md", PAIR_PROOF_DRAFT)
            _write_scope_review(ws, "pair_live")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            manifest = json.loads((bundle / "live-proof" / "manifest.json").read_text())
            summary = manifest["proof_pair_integrity_summary"]
            self.assertEqual(summary["declared"], 1)
            self.assertEqual(summary["complete"], 1)
            self.assertEqual(summary["same_block"], 1)
            self.assertEqual(summary["incomplete"], 0)
            self.assertEqual(summary["cross_block"], 0)
            pair = manifest["proof_pairs"][0]
            self.assertTrue(pair["pair_complete"])
            self.assertTrue(pair["same_block"])
            self.assertEqual(pair["pair_blocks"], ["12345"])

    def test_packager_warns_when_required_topology_pair_crosses_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), with_live_topology=False)
            _write_pair_live_topology(ws, authority_block="12346")
            draft = _write_draft(ws, "pair_live.md", PAIR_PROOF_DRAFT)
            _write_scope_review(ws, "pair_live")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            result = json.loads(proc.stdout)
            self.assertTrue(
                any("not same-block" in warning for warning in result["warnings"]),
                msg=f"expected same-block warning, got {result['warnings']}",
            )
            bundle = _find_bundle(ws)
            manifest = json.loads((bundle / "live-proof" / "manifest.json").read_text())
            summary = manifest["proof_pair_integrity_summary"]
            self.assertEqual(summary["declared"], 1)
            self.assertEqual(summary["complete"], 1)
            self.assertEqual(summary["same_block"], 0)
            self.assertEqual(summary["cross_block"], 1)
            self.assertEqual(summary["cross_block_pair_ids"], ["a-auth-topology-pair"])

    def test_pre_submit_surfaces_packaged_cross_block_pair_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), with_live_topology=False)
            _write_pair_live_topology(ws, authority_block="12346")
            draft = _write_draft(ws, "pair_live.md", PAIR_PROOF_DRAFT)
            _write_scope_review(ws, "pair_live")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            result = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(bundle / "source-draft.md"), "--severity", "High"],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Packaged live-proof manifest reports cross-block proof pairs",
                result.stdout,
            )
            self.assertIn("packaged_pair_cross_block=a-auth-topology-pair", result.stdout)


class LiveTopologyMissingFailClosedTest(unittest.TestCase):
    """T1 acceptance test #4: gates-run path fails closed when source absent.

    Locks in the pre-existing fail-closed behavior that the bundle-local
    copy logic must never bypass. Hard-negative catch for the truth-audit
    overclaim risk called out in LOOP_ITER_004_PLAN.md §T1: packager must
    NEVER synthesize an empty-results `live_topology_checks.json` in the
    bundle to get past Check #21.
    """

    def test_packager_fails_when_source_live_topology_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), with_live_topology=False)
            draft = _write_draft(ws, "foo_bar_live.md")
            _write_scope_review(ws, "foo_bar_live")

            # Double-check the source file does NOT exist (defensive —
            # if _make_workspace ever starts creating it unconditionally
            # this test would become vacuous).
            self.assertFalse(
                (ws / "live_topology_checks.json").exists(),
                "fixture precondition: source live_topology_checks.json must be absent",
            )

            # Run WITHOUT --skip-gates so gates-run evaluates live-proof
            # requirement + fails closed on missing artifact.
            proc = _run_packager(ws, draft, skip_gates=False)

            # Must exit non-zero.
            self.assertNotEqual(
                proc.returncode, 0,
                msg=(
                    "packager must fail closed when live-topology source is "
                    f"missing; stdout={proc.stdout}\nstderr={proc.stderr}"
                ),
            )

            # No bundle must exist on disk. This locks in the "no stub
            # synthesis" invariant: the only way a bundle with
            # live_topology_checks.json exists is if the packager copied
            # a real artifact into it.
            pkg_root = ws / "submissions" / "packaged"
            if pkg_root.exists():
                bundles = [p for p in pkg_root.iterdir() if p.is_dir()]
                # If a bundle was somehow produced (shouldn't happen on
                # gates-run failure), it must NOT contain a bundle-root
                # live_topology_checks.json.
                for bundle in bundles:
                    self.assertFalse(
                        (bundle / "live_topology_checks.json").exists(),
                        msg=(
                            f"packager synthesized a bundle-root "
                            f"live_topology_checks.json at {bundle} despite "
                            f"missing source — hard-negative violation"
                        ),
                    )

            # Error message sanity: the packager's existing fail-closed
            # path emits "Live-proof artifact missing or invalid for
            # deployment/config-dependent draft". Accept that exact
            # wording OR any message containing both "Live" and "missing"
            # (loose-match for future error-message rewrites).
            combined = proc.stdout + proc.stderr
            has_missing_marker = (
                "Live-proof artifact missing" in combined
                or ("Live" in combined and "missing" in combined.lower())
            )
            self.assertTrue(
                has_missing_marker,
                msg=(
                    "packager output must signal 'Live ... missing' when "
                    "source live-topology artifact is absent; "
                    f"stdout={proc.stdout}\nstderr={proc.stderr}"
                ),
            )


class SourceOnlyPreMainnetOverrideTest(unittest.TestCase):
    """Source-only/pre-mainnet drafts should not require live-proof row IDs."""

    def test_packager_accepts_source_only_pre_mainnet_without_live_rows(self) -> None:
        body = """# Source-only pre-mainnet finding

**Severity:** High

## Summary

This source-level finding mentions mainnet and a deployment topology because
the production impact is bridge finality, but the affected contracts are
pre-mainnet and have no L1 deployment to fork.

## Finding Description

The vulnerable source path references `owner()` and a future mainnet
deployment, which intentionally trips the live-proof heuristic.

## Live Proof

**Live Proof evidence: N/A** — source-only rationale. Base Azul contracts are
pre-mainnet at time of submission; no L1 deployment exists yet to fork
against. `live proof not required` for this finding.
"""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), with_live_topology=False)
            draft = _write_draft(ws, "source_only_pre_mainnet.md", body)
            _write_scope_review(ws, "source_only_pre_mainnet")

            proc = _run_packager(ws, draft, skip_gates=True)

            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager should accept explicit source-only override; stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            bundle = _find_bundle(ws)
            result = json.loads(proc.stdout)
            self.assertEqual(
                result["live_proof"]["proof_status"],
                "source-only",
            )
            self.assertFalse(
                (bundle / "live_topology_checks.json").exists(),
                "source-only override must not synthesize bundle live_topology_checks.json",
            )


class ScopeReviewAliasTest(unittest.TestCase):
    """FN staging drafts may reuse review artifacts generated for final names."""

    def test_pre_submit_accepts_fn_prefixed_scope_review_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / "submissions" / "staging").mkdir(parents=True)
            (ws / "scope_review").mkdir()
            (ws / "OOS_CHECKLIST.md").write_text("# oos\n", encoding="utf-8")
            draft = ws / "submissions" / "staging" / "FN1-draft.md"
            draft.write_text(
                "# Alias scope review\n\n"
                "**Severity:** Medium\n\n"
                "Plain source-level finding used to exercise Check 11.\n",
                encoding="utf-8",
            )
            (ws / "scope_review" / "FN1-IMMUNEFI-SUBMISSION.heuristic-review.md").write_text(
                SCOPE_REVIEW_FIXTURE,
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Medium"],
                capture_output=True,
                text=True,
            )

            self.assertNotIn("❌ 11.", result.stdout, result.stdout + result.stderr)
            self.assertIn("✅ 11. Scope-review VERDICT: NOVEL", result.stdout)


if __name__ == "__main__":
    unittest.main()
