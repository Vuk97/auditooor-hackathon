"""Unit tests for Rule 77 external-dependency-behavior gate.

Anchor: zebra batch over-claim (2026-06-02). A HIGH finding claimed
"one HTTP JSON-RPC batch launches K concurrent scans" - an amplification
mechanism resting on jsonrpsee batch behavior that was ASSUMED, not read. The
real jsonrpsee-server source processes a batch SEQUENTIALLY. The over-claim
survived every gate (R76 only checks workspace source-existence). R77 catches
the external-dependency-behavior class mechanically.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "external-dependency-behavior-check.py"
_spec = importlib.util.spec_from_file_location("external_dependency_behavior_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r77_extdep_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


# --- the load-bearing zebra over-claim, no source citation ----------------
ZEBRA_ASSUMED = """Severity: High

## Summary
A single unauthenticated HTTP JSON-RPC batch request amplifies into K concurrent
wallet scans, exhausting CPU on the node.

## Details
The amplification rests on jsonrpsee batch handling: one batch fans out so that
each call in the batch is processed concurrently by the jsonrpsee server, so a
batch of 5000 calls launches 5000 concurrent scan tasks in parallel.
"""

# --- same claim, WITH the real jsonrpsee server.rs:1318 source quote -------
ZEBRA_SOURCE_CITED = """Severity: High

## Summary
A single unauthenticated HTTP JSON-RPC batch request fans out into K scans.

## Details
The amplification rests on jsonrpsee batch handling: each call in the batch is
processed concurrently. I verified this against the real crate source at
~/.cargo/registry/src/index.crates.io-6f17d22bba15001f/jsonrpsee-server-0.24.10/src/server.rs:1318
which shows:

    for call in batch { rpc_service.call(req).await }

NOTE: this is actually SEQUENTIAL (an awaited for-loop), not concurrent - so the
amplification claim is bounded. (Included here to exercise the source-cited path.)
"""

# --- HIGH finding with NO external-dep behavioral claim --------------------
NO_DEP_CLAIM = """Severity: High

## Summary
The bridge payout function omits a consumed-once gate, so the attacker replays
the same Merkle proof to drain custody funds.

## Details
At src/bridge/payout.rs:142 the leaf hash does not bind exportId; the workspace
code path mints to attacker-chosen (recipient, amount) tuples. Direct fund loss.
"""

# --- MEDIUM draft (out of scope) -------------------------------------------
MEDIUM_DRAFT = """Severity: Medium

## Details
A jsonrpsee batch is processed concurrently by the server, amplifying load.
"""

# --- rebuttal --------------------------------------------------------------
REBUTTAL_DRAFT = """Severity: High

## Details
The jsonrpsee server processes each batch call concurrently, amplifying the
attack K-fold.

<!-- r77-rebuttal: behavior documented in jsonrpsee 0.24 CHANGELOG batch-concurrency note, cited inline -->
"""


class R77ScopeTests(unittest.TestCase):
    def test_medium_is_out_of_scope(self) -> None:
        rc, payload = mod.run(_write(MEDIUM_DRAFT, filename="draft-MEDIUM.md"))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_override_to_low_is_out_of_scope(self) -> None:
        rc, payload = mod.run(_write(ZEBRA_ASSUMED), severity_override="LOW")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


class R77FailTests(unittest.TestCase):
    def test_zebra_assumed_behavior_fails(self) -> None:
        rc, payload = mod.run(_write(ZEBRA_ASSUMED))
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-external-dep-behavior-assumed")
        hits = payload["evidence"]["trigger_hits"]
        self.assertTrue(any("jsonrpsee" in h["dependency"].lower() for h in hits))

    def test_cli_override_high_triggers_fail(self) -> None:
        # severity comes from the header as High; override confirms gate fires
        rc, payload = mod.run(_write(ZEBRA_ASSUMED), severity_override="HIGH")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")


class R77PassTests(unittest.TestCase):
    def test_zebra_with_source_citation_passes(self) -> None:
        rc, payload = mod.run(_write(ZEBRA_SOURCE_CITED))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-external-dep-behavior-source-cited")
        self.assertTrue(payload["evidence"]["source_citations"])

    def test_executed_test_transcript_passes(self) -> None:
        body = ZEBRA_ASSUMED + "\n\n```\ncargo test --test batch_behavior\n--- PASS: test_batch_is_sequential\ntest result: ok. 1 passed\n```\n"
        rc, payload = mod.run(_write(body))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-external-dep-behavior-source-cited")
        self.assertTrue(payload["evidence"]["executed_test_transcript"])

    def test_no_external_dep_behavior_claim_passes(self) -> None:
        rc, payload = mod.run(_write(NO_DEP_CLAIM))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-external-dep-behavior-claim")

    def test_rebuttal_accepted(self) -> None:
        rc, payload = mod.run(_write(REBUTTAL_DRAFT))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


class R77LowFPTests(unittest.TestCase):
    def test_dep_named_without_behavior_does_not_fire(self) -> None:
        # tokio/jsonrpsee are named as deps, but the load-bearing amplification
        # line below is about the WORKSPACE loop, not a dependency behavior.
        body = ("Severity: High\n\n## Details\nThe project depends on tokio and "
                "jsonrpsee.\n\nThe amplification comes from the workspace loop at "
                "src/scan.rs:88 spawning one scan task per address.\n")
        rc, payload = mod.run(_write(body))
        self.assertEqual(rc, 0)
        # workspace-own behavioral claim; no external dep on the load-bearing line
        self.assertEqual(payload["verdict"], "pass-no-external-dep-behavior-claim")

    def test_behavioral_claim_about_own_workspace_does_not_fire(self) -> None:
        body = ("Severity: High\n\n## Details\nOur handler at src/rpc.rs:200 "
                "processes each request concurrently via join_all, amplifying "
                "K-fold. The bug is in our own fan-out, not a dependency.\n")
        rc, payload = mod.run(_write(body))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-external-dep-behavior-claim")

    def test_negative_scope_line_ignored(self) -> None:
        body = ("Severity: High\n\n## Details\nHypothetically, if jsonrpsee "
                "processed each batch call concurrently it would amplify K-fold; "
                "we do not claim that here.\n")
        rc, payload = mod.run(_write(body))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-external-dep-behavior-claim")

    def test_package_cache_path_alone_is_external(self) -> None:
        body = ("Severity: High\n\n## Details\nThe amplification: each call in a "
                "batch is processed concurrently per node_modules/express handler, "
                "fanning out K-fold per request.\n")
        rc, payload = mod.run(_write(body))
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-external-dep-behavior-assumed")


class R77CliTests(unittest.TestCase):
    def test_cli_json_output_and_exit_codes(self) -> None:
        draft = _write(ZEBRA_ASSUMED)
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "fail-external-dep-behavior-assumed")
        self.assertEqual(payload["schema_version"], "auditooor.r77_external_dependency_behavior.v1")
        self.assertEqual(payload["gate"], "R77-EXTERNAL-DEP-BEHAVIOR")

    def test_cli_pass_exit_zero(self) -> None:
        draft = _write(NO_DEP_CLAIM)
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)

    def test_error_on_missing_file(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "/nonexistent/draft.md", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)


class R77EnvHookTests(unittest.TestCase):
    def test_env_dep_name_extension(self) -> None:
        import os
        body = ("Severity: High\n\n## Details\nThe amplification: mycustomdep "
                "processes each batch call concurrently, fanning out K-fold.\n")
        draft = _write(body)
        env = dict(os.environ, AUDITOOOR_R77_DEP_NAME_PATTERNS="mycustomdep")
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--json"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout)["verdict"],
                         "fail-external-dep-behavior-assumed")


if __name__ == "__main__":
    unittest.main()
