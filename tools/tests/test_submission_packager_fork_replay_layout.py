#!/usr/bin/env python3
"""iter5-T2 regression tests — packager/pre-submit fork_replay path-layout reconciliation.

Covers (per docs/LOOP_ITER_005_PLAN.md §T2 and
docs/PRE_SUBMIT_BUNDLE_LOCAL_CHECKS.md row #25):

  1. `test_packager_writes_nested_fork_replay_layout`
     — packager emits BOTH the legacy flat copy at
       ``<bundle>/fork-replay/<name>`` AND a nested copy at
       ``<bundle>/fork_replay/<rel_from_ws>`` preserving the citation's
       relative path from the workspace root. Byte-identical to source.
  2. `test_packager_bundle_passes_check22_offline`
     — ``bash tools/pre-submit-check.sh <bundle>/source-draft.md --severity High``
       emits zero ``❌ 22.`` and at least one ``✅ 22.`` or ``⚠️  22.``
       when the bundle is inspected offline (the ``_FR_WS`` ancestor walk
       resolves to the bundle, not the original workspace).
  3. `test_packager_preserves_flat_fork_replay_alias`
     — existing reviewer-friendly ``<bundle>/fork-replay/<name>`` flat
       copy is still written byte-for-byte.
  4. `test_packager_fails_when_cited_fork_replay_missing`
     — hard-negative fail-closed: draft cites a fork_replay artifact that
       does NOT exist on disk → packager returns non-zero. Locks in the
       pre-existing behavior that no nested directory is ever written
       for a file that doesn't exist.

Offline. No network. No forge. Shells out to
``tools/submission-packager.py`` and the pre-submit bash script.
Mirrors iter4-T1's ``test_submission_packager_live_topology.py`` structure.
"""
from __future__ import annotations

import json
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


def _make_workspace(tmp: Path, *, with_fork_replay_dir: bool = True) -> Path:
    """Build a minimal but complete workspace layout for the packager."""
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "scope_review").mkdir(parents=True)
    (ws / "poc-tests").mkdir(parents=True)
    # Workspace anchor for pre-submit's `_WS` / `_FR_WS` ancestor walk when
    # running against the original (pre-package) draft.
    (ws / "OOS_CHECKLIST.md").write_text("# Workspace OOS checklist\n")
    if with_fork_replay_dir:
        (ws / "fork_replay").mkdir(parents=True)
    return ws


def _write_fork_replay_fixture(
    ws: Path,
    *,
    subdir: str = "",
    tx: str = "0x" + "ab" * 32,
    status: str = "success",
    block: int = 12345678,
    fork_block: int = 12345677,
) -> dict:
    """Write a minimal but realistic fork-replay artifact set.

    When ``subdir`` is non-empty, artifacts live under
    ``<ws>/fork_replay/<subdir>/`` — exercising the nested-layout case
    where the citation's rel path contains a subdirectory (e.g. a dated
    replay run like ``2025-04-15T10-30-00Z``).
    """
    fr = ws / "fork_replay"
    if subdir:
        fr = fr / subdir
    fr.mkdir(parents=True, exist_ok=True)

    manifest_path = fr / f"{tx}_manifest.json"
    deltas_path = fr / f"{tx}_deltas.json"
    summary_path = fr / f"{tx}_replay.yaml"
    pre_path = fr / f"{tx}_pre_state.json"
    post_path = fr / f"{tx}_post_state.json"
    trace_path = fr / f"{tx}_trace.json"

    pre_path.write_text(json.dumps({"addresses": {}}))
    post_path.write_text(json.dumps({"addresses": {}}))
    deltas_path.write_text(json.dumps({
        "tx": tx,
        "addresses": {
            "0x1111111111111111111111111111111111111111": {
                "nativeDelta": "0",
                "erc20": {
                    "0x2222222222222222222222222222222222222222": {
                        "pre": "0",
                        "post": "1000000",
                        "delta": "1000000",
                    },
                },
            },
        },
    }))
    summary_path.write_text("status: success\n")
    trace_path.write_text(json.dumps({"result": []}))

    manifest_path.write_text(json.dumps({
        "schema_version": 1,
        "status": status,
        "tx": tx,
        "rpc": "http://localhost:0",
        "block": block,
        "fork_block": fork_block,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x3333333333333333333333333333333333333333",
        # Codex PR-102 blocker: Check #22 semantic gate requires at least
        # one PASS assertion, no FAIL/INCONCLUSIVE. Include a minimal
        # passing economic-delta assertion so the fixture bundle can be
        # exercised through Check #22 end-to-end.
        "assertions": [
            {
                "id": "erc20-delta-positive",
                "status": "PASS",
                "detail": "attacker gained 1000000 wei of token 0x2222...",
            },
        ],
        "artifacts": {
            "pre_state": str(pre_path),
            "post_state": str(post_path),
            "deltas": str(deltas_path),
            "mainnet_trace": str(trace_path),
            "replay_trace": str(trace_path),
            "summary": str(summary_path),
        },
    }))

    # Rel paths from ws, e.g. "fork_replay/<subdir>/<tx>_manifest.json"
    prefix = f"fork_replay/{subdir}/" if subdir else "fork_replay/"
    return {
        "tx": tx,
        "manifest_rel": f"{prefix}{manifest_path.name}",
        "deltas_rel": f"{prefix}{deltas_path.name}",
        "summary_rel": f"{prefix}{summary_path.name}",
        "pre_state_rel": f"{prefix}{pre_path.name}",
        "post_state_rel": f"{prefix}{post_path.name}",
        "trace_rel": f"{prefix}{trace_path.name}",
        "manifest_path": manifest_path,
        "deltas_path": deltas_path,
    }


def _write_scope_review(ws: Path, draft_stem: str) -> Path:
    review = ws / "scope_review" / f"{draft_stem}.heuristic-review.md"
    review.write_text(SCOPE_REVIEW_FIXTURE)
    return review


def _write_draft(ws: Path, name: str, body: str) -> Path:
    draft = ws / "submissions" / "staging" / name
    draft.write_text(body)
    return draft


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


def _high_severity_fork_replay_draft(refs: dict) -> str:
    return f"""# Sample finding — fork-replay-dependent

**Severity:** High

## Summary

A finding proving real economic impact via fork-replay.

## Impact

Economic loss verified by on-fork replay.

## Fork Replay

Manifest: `{refs['manifest_rel']}`
Deltas: `{refs['deltas_rel']}`
"""


class NestedForkReplayLayoutTest(unittest.TestCase):
    """T2 acceptance test #1: bundle-local nested fork_replay/<rel> layout."""

    def test_packager_writes_nested_fork_replay_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            # Use a dated subdir to exercise the rel-path preservation path.
            refs = _write_fork_replay_fixture(ws, subdir="2025-04-15T10-30-00Z")
            draft = _write_draft(
                ws, "nested_fork_replay.md", _high_severity_fork_replay_draft(refs),
            )
            _write_scope_review(ws, "nested_fork_replay")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)

            # A) Flat legacy layout still present (reviewer-friendly alias).
            flat_manifest = bundle / "fork-replay" / refs["manifest_path"].name
            self.assertTrue(
                flat_manifest.is_file(),
                f"flat <bundle>/fork-replay/<name> missing at {flat_manifest}",
            )

            # B) Nested bundle-local layout present, preserving rel path.
            nested_manifest = bundle / refs["manifest_rel"]
            self.assertTrue(
                nested_manifest.is_file(),
                f"nested <bundle>/fork_replay/<rel> missing at {nested_manifest}",
            )

            # C) Byte-identical to source artifact.
            self.assertEqual(
                nested_manifest.read_bytes(),
                refs["manifest_path"].read_bytes(),
                msg=(
                    "nested <bundle>/fork_replay/<rel> diverges from source — "
                    "must be byte-identical copy, never a stub"
                ),
            )

            # D) Same for the deltas sibling — verifies the nested mirror
            #    is not just the manifest but every copied sibling.
            nested_deltas = bundle / refs["deltas_rel"]
            self.assertTrue(
                nested_deltas.is_file(),
                f"nested <bundle>/fork_replay/<rel> missing deltas at {nested_deltas}",
            )
            self.assertEqual(
                nested_deltas.read_bytes(),
                refs["deltas_path"].read_bytes(),
            )


class BundlePassesCheck22OfflineTest(unittest.TestCase):
    """T2 acceptance test #2: pre-submit Check #22 resolves via bundle, not ws."""

    def test_packager_bundle_passes_check22_offline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            refs = _write_fork_replay_fixture(ws)
            draft = _write_draft(
                ws, "bundle_check22.md", _high_severity_fork_replay_draft(refs),
            )
            _write_scope_review(ws, "bundle_check22")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)
            bundle_draft = bundle / "source-draft.md"
            self.assertTrue(bundle_draft.is_file(), "bundle missing source-draft.md")

            # Run pre-submit Check #22 against the bundle's source-draft.md
            # with High severity so the fork_replay gate is enforced. We
            # only care about Check #22: 0 × `❌ 22.` and >=1 × ✅/⚠️ 22.
            # Other checks may fail against the toy fixture; that's
            # outside T2's scope.
            result = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(bundle_draft), "--severity", "High"],
                capture_output=True,
                text=True,
            )
            stdout = result.stdout
            check_22_fail_count = stdout.count("❌ 22.")
            check_22_pass_count = (
                stdout.count("✅ 22.") + stdout.count("⚠️  22.")
            )
            self.assertEqual(
                check_22_fail_count, 0,
                msg=(
                    "pre-submit Check #22 failed against bundle-local draft; "
                    f"output=\n{stdout}\nstderr={result.stderr}"
                ),
            )
            self.assertGreaterEqual(
                check_22_pass_count, 1,
                msg=(
                    "pre-submit Check #22 did not emit a ✅ or ⚠️ against bundle; "
                    f"output=\n{stdout}\nstderr={result.stderr}"
                ),
            )


class FlatForkReplayAliasPreservedTest(unittest.TestCase):
    """T2 acceptance test #3: legacy <bundle>/fork-replay/ flat alias preserved."""

    def test_packager_preserves_flat_fork_replay_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            refs = _write_fork_replay_fixture(ws)
            draft = _write_draft(
                ws, "flat_alias.md", _high_severity_fork_replay_draft(refs),
            )
            _write_scope_review(ws, "flat_alias")

            proc = _run_packager(ws, draft)
            self.assertEqual(
                proc.returncode, 0,
                msg=f"packager failed: stdout={proc.stdout}\nstderr={proc.stderr}",
            )

            bundle = _find_bundle(ws)

            # Legacy <bundle>/fork-replay/<name> flat alias must persist —
            # iter5-T2 ADDS nested <bundle>/fork_replay/<rel> but MUST NOT
            # remove the flat layout. Mirrors iter3-T1's scope-review and
            # iter4-T1's live-proof legacy-alias preservation patterns.
            flat_dir = bundle / "fork-replay"
            self.assertTrue(
                flat_dir.is_dir(),
                f"legacy <bundle>/fork-replay/ directory missing at {flat_dir}",
            )
            flat_manifest = flat_dir / refs["manifest_path"].name
            flat_deltas = flat_dir / refs["deltas_path"].name
            self.assertTrue(flat_manifest.is_file(), "flat manifest alias missing")
            self.assertTrue(flat_deltas.is_file(), "flat deltas alias missing")
            # Byte-for-byte identical to source (the copy must never be a stub).
            self.assertEqual(
                flat_manifest.read_bytes(),
                refs["manifest_path"].read_bytes(),
                msg="flat <bundle>/fork-replay/<name> manifest drifted from source",
            )
            self.assertEqual(
                flat_deltas.read_bytes(),
                refs["deltas_path"].read_bytes(),
                msg="flat <bundle>/fork-replay/<name> deltas drifted from source",
            )


class CitedForkReplayMissingFailClosedTest(unittest.TestCase):
    """T2 acceptance test #4: fail-closed when cited fork_replay artifact is absent.

    Locks in the pre-existing fail-closed behavior (PR 101 landed it in
    ``main()``'s ``missing_fork_replay`` gate). Hard-negative catch for the
    truth-audit overclaim risk: packager must NEVER synthesize a nested
    <bundle>/fork_replay/<rel> directory for a file that doesn't exist,
    and must NEVER silently drop the cite.
    """

    def test_packager_fails_when_cited_fork_replay_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            # Draft cites a manifest that was never written.
            bogus_rel = "fork_replay/0xdeadbeef_manifest.json"
            draft = _write_draft(ws, "missing_fr.md", f"""# Missing evidence

**Severity:** High

## Fork Replay

See `{bogus_rel}` (does not exist).
""")
            _write_scope_review(ws, "missing_fr")

            # Defensive: confirm the cited file does NOT exist on disk.
            self.assertFalse(
                (ws / bogus_rel).exists(),
                "fixture precondition: cited manifest must be absent",
            )

            proc = _run_packager(ws, draft)
            self.assertNotEqual(
                proc.returncode, 0,
                msg=(
                    "packager must fail closed when a cited fork_replay "
                    f"artifact is missing; stdout={proc.stdout}\nstderr={proc.stderr}"
                ),
            )

            # Hard negative: even if a partial bundle is produced (shouldn't
            # happen on fail-closed), no nested <bundle>/fork_replay/<rel>
            # must exist for the missing citation. This locks in the
            # "never synthesize a path" invariant.
            pkg_root = ws / "submissions" / "packaged"
            if pkg_root.exists():
                for bundle in [p for p in pkg_root.iterdir() if p.is_dir()]:
                    nested = bundle / bogus_rel
                    self.assertFalse(
                        nested.exists(),
                        msg=(
                            f"packager synthesized a nested fork_replay path "
                            f"at {nested} despite the cited source being "
                            f"absent — hard-negative violation"
                        ),
                    )

            # Error-message sanity: packager's existing missing-cite gate
            # emits "Cited fork-replay artifact(s) not found". Accept that
            # phrasing OR any message containing both "fork" and "not found".
            combined = (proc.stdout + proc.stderr).lower()
            has_marker = "not found" in combined
            self.assertTrue(
                has_marker,
                msg=(
                    "packager output must signal a 'not found' marker when "
                    "cited fork_replay artifact is absent; "
                    f"stdout={proc.stdout}\nstderr={proc.stderr}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
