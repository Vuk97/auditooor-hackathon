#!/usr/bin/env python3
"""PR 101 tests — submission-packager bundles fork-replay evidence.

Covers:
  - Package copies every cited fork-replay artifact (manifest + siblings).
  - Package root manifest records fork-replay entries with tx/block/status.
  - Missing or malformed cited deltas fail the packager closed.
  - Bundle omission when the draft cites no fork-replay at all.

No network. No real RPC. No real forge. We shell out to
`tools/submission-packager.py` with `--skip-gates` so the pre-submit /
variant / quality / scope gates don't touch the isolated fixtures.
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
TOOL = ROOT / "tools" / "submission-packager.py"


def _make_workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "fork_replay").mkdir(parents=True)
    (ws / "poc-tests").mkdir(parents=True)
    return ws


def _write_fork_replay_fixture(
    ws: Path,
    tx: str = "0x" + "ab" * 32,
    *,
    status: str = "success",
    block: int = 12345678,
    fork_block: int = 12345677,
    assertions: list | None = None,
) -> dict:
    """Write a minimal but realistic fork-replay artifact set. Returns rel paths."""
    fr = ws / "fork_replay"
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

    if assertions is None:
        assertions = [{"id": "attacker-token-gain", "status": "PASS"}]

    manifest_path.write_text(json.dumps({
        "schema_version": 1,
        "status": status,
        "tx": tx,
        "rpc": "http://localhost:0",
        "block": block,
        "fork_block": fork_block,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x3333333333333333333333333333333333333333",
        "assertions": assertions,
        "artifacts": {
            "pre_state": str(pre_path),
            "post_state": str(post_path),
            "deltas": str(deltas_path),
            "mainnet_trace": str(trace_path),
            "replay_trace": str(trace_path),
            "summary": str(summary_path),
        },
    }))

    return {
        "tx": tx,
        "manifest": f"fork_replay/{manifest_path.name}",
        "deltas": f"fork_replay/{deltas_path.name}",
        "summary": f"fork_replay/{summary_path.name}",
        "pre_state": f"fork_replay/{pre_path.name}",
        "post_state": f"fork_replay/{post_path.name}",
        "trace": f"fork_replay/{trace_path.name}",
    }


def _run_packager(ws: Path, draft_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), str(ws), str(draft_path), "--skip-gates", "--json"],
        capture_output=True,
        text=True,
    )


class ForkReplayPackageTest(unittest.TestCase):
    def _write_draft(self, ws: Path, body: str, *, name: str = "ft.md") -> Path:
        draft = ws / "submissions" / "staging" / name
        draft.write_text(body)
        return draft

    def test_cited_artifacts_are_copied_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            refs = _write_fork_replay_fixture(ws)

            draft = self._write_draft(ws, f"""# Example finding

**Severity:** High

## Fork Replay

This draft cites real replay evidence at `{refs['manifest']}` showing the
attacker drains the adaptor. Deltas are recorded at `{refs['deltas']}` for
the same transaction.
""")

            result = _run_packager(ws, draft)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

            pkg_dirs = list((ws / "submissions" / "packaged").iterdir())
            self.assertEqual(len(pkg_dirs), 1, "expected exactly one package dir")
            pkg_dir = pkg_dirs[0]

            fork_dir = pkg_dir / "fork-replay"
            self.assertTrue(fork_dir.exists(), "fork-replay/ must exist in bundle")

            expected_copies = {
                Path(refs["manifest"]).name,
                Path(refs["deltas"]).name,
                Path(refs["summary"]).name,
                Path(refs["pre_state"]).name,
                Path(refs["post_state"]).name,
                Path(refs["trace"]).name,
            }
            found = {p.name for p in fork_dir.iterdir()}
            self.assertEqual(
                expected_copies - found, set(),
                msg=f"missing: {expected_copies - found}; found: {found}",
            )

            manifest = json.loads((pkg_dir / "manifest.json").read_text())
            fr = manifest.get("fork_replay", {})
            self.assertIn("entries", fr)
            self.assertEqual(len(fr["entries"]), 1)
            entry = fr["entries"][0]
            self.assertEqual(entry["tx"], refs["tx"])
            self.assertEqual(entry["block"], 12345678)
            self.assertEqual(entry["fork_block"], 12345677)
            self.assertEqual(entry["status"], "success")
            self.assertEqual(entry["assertions"][0]["status"], "PASS")
            self.assertGreaterEqual(len(entry.get("copied_files", [])), 5)
            self.assertEqual(fr.get("missing"), [])
            self.assertEqual(fr.get("malformed"), [])

    def test_missing_cited_fork_replay_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            # draft cites a manifest that was never written
            draft = self._write_draft(ws, """# Missing evidence

## Fork Replay

See `fork_replay/0xdeadbeef_manifest.json` (does not exist).
""")
            result = _run_packager(ws, draft)
            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("not found", combined.lower())

    def test_malformed_cited_deltas_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            tx = "0x" + "cc" * 32
            deltas_path = ws / "fork_replay" / f"{tx}_deltas.json"
            deltas_path.write_text("{ not-json")

            draft = self._write_draft(ws, f"""# Malformed deltas

## Fork Replay

Cited at `fork_replay/{deltas_path.name}`.
""")
            result = _run_packager(ws, draft)
            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("parse", combined.lower())

    def test_no_fork_replay_cite_leaves_bundle_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            draft = self._write_draft(ws, """# No replay cited

Ordinary finding body. No fork-replay reference.
""")
            result = _run_packager(ws, draft)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

            pkg_dirs = list((ws / "submissions" / "packaged").iterdir())
            self.assertEqual(len(pkg_dirs), 1)
            pkg_dir = pkg_dirs[0]
            # No fork-replay directory should be created when nothing is cited.
            self.assertFalse((pkg_dir / "fork-replay").exists())

            manifest = json.loads((pkg_dir / "manifest.json").read_text())
            fr = manifest.get("fork_replay", {})
            self.assertEqual(fr.get("referenced"), [])
            self.assertEqual(fr.get("entries"), [])

    def test_deltas_only_cite_discovers_and_copies_sibling_artifacts(self) -> None:
        """Codex PR-102 blocker 6: when only the deltas are cited, discover
        the sibling manifest / YAML / pre_state / post_state / traces by
        shared stem and copy them all into the bundle. Also back-fill the
        manifest's tx/status/block/fork_block into the package manifest
        entry so the evidence matrix can verify pin + status."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            refs = _write_fork_replay_fixture(
                ws, tx="0x" + "cd" * 32, status="executed",
            )
            draft = self._write_draft(ws, f"""# Deltas-only cite

**Severity:** High

## Fork Replay

Only the deltas are explicitly referenced: `{refs['deltas']}`.
All other replay artifacts should be discovered + copied by stem.
""")
            result = _run_packager(ws, draft)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

            pkg_dirs = list((ws / "submissions" / "packaged").iterdir())
            self.assertEqual(len(pkg_dirs), 1)
            pkg_dir = pkg_dirs[0]
            fork_dir = pkg_dir / "fork-replay"
            self.assertTrue(fork_dir.exists(), "fork-replay/ must exist when a delta is cited")

            found = {p.name for p in fork_dir.iterdir()}
            # Manifest must be discovered even though only deltas were cited.
            self.assertIn(Path(refs["manifest"]).name, found)
            # Sibling YAML + states + mainnet trace also discovered.
            self.assertIn(Path(refs["summary"]).name, found)
            self.assertIn(Path(refs["pre_state"]).name, found)
            self.assertIn(Path(refs["post_state"]).name, found)
            self.assertIn(Path(refs["trace"]).name, found)

            manifest = json.loads((pkg_dir / "manifest.json").read_text())
            fr = manifest.get("fork_replay", {})
            entries = fr.get("entries") or []
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            # Discovered sibling manifest must back-fill semantic fields.
            self.assertEqual(entry["tx"], refs["tx"])
            self.assertEqual(entry["status"], "executed")
            self.assertEqual(entry["block"], 12345678)
            self.assertEqual(entry["fork_block"], 12345677)
            self.assertEqual(entry["assertions"][0]["status"], "PASS")
            self.assertEqual(fr.get("missing"), [])
            self.assertEqual(fr.get("malformed"), [])

    def test_summary_only_cite_discovers_and_validates_sibling_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            refs = _write_fork_replay_fixture(
                ws, tx="0x" + "de" * 32, status="executed",
            )
            draft = self._write_draft(ws, f"""# Summary-only cite

**Severity:** High

## Fork Replay

Only the YAML replay summary is referenced: `{refs['summary']}`.
""")
            result = _run_packager(ws, draft)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

            pkg_dir = next((ws / "submissions" / "packaged").iterdir())
            manifest = json.loads((pkg_dir / "manifest.json").read_text())
            entry = manifest["fork_replay"]["entries"][0]
            self.assertEqual(entry["status"], "executed")
            self.assertEqual(entry["assertions"][0]["status"], "PASS")

    def test_manifest_without_assertions_fails_semantic_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            refs = _write_fork_replay_fixture(
                ws, tx="0x" + "df" * 32, status="executed", assertions=[],
            )
            draft = self._write_draft(ws, f"""# Replay without assertions

**Severity:** High

## Fork Replay

Replay manifest is cited at `{refs['manifest']}`.
""")
            result = _run_packager(ws, draft)
            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("semantic validation", combined.lower())
            self.assertIn("assertions-empty", combined.lower())

    def test_path_traversal_cite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            # Attempt to cite something outside fork_replay/ via traversal.
            draft = self._write_draft(ws, """# Path traversal attempt

## Fork Replay

See `fork_replay/../../etc/passwd_manifest.json` (rejected).
""")
            # Either the regex does not match (clean pass with no cites), or
            # the resolver rejects it (counted as missing and fails closed).
            # Both are acceptable; the crucial invariant is "no bundle copy
            # outside fork_replay/".
            result = _run_packager(ws, draft)
            # If the packager accepts the draft (no cite matched), verify
            # nothing outside fork_replay/ was copied.
            if result.returncode == 0:
                pkg_dirs = list((ws / "submissions" / "packaged").iterdir())
                if pkg_dirs:
                    fork_dir = pkg_dirs[0] / "fork-replay"
                    if fork_dir.exists():
                        for p in fork_dir.iterdir():
                            self.assertTrue(
                                p.name.endswith((
                                    "_manifest.json",
                                    "_deltas.json",
                                    "_replay.yaml",
                                    "_pre_state.json",
                                    "_post_state.json",
                                    "_trace.json",
                                    "_replay_trace.json",
                                )),
                                msg=f"unexpected copied file: {p.name}",
                            )


if __name__ == "__main__":
    unittest.main()
