#!/usr/bin/env python3
"""PR #526 gap #1 — scope-reasoner DLT/Engine-API exception path.

The legacy `unproven_bad_game_prereq` pattern was written against
Base-Azul FN-5/FN-6 Solidity dispute-game prerequisite reports
(`FaultDisputeGame`, `AnchorStateRegistry`, `OptimismPortal`). When a
Rust DLT report rooted in Engine API payload validation
(`engine_newPayloadV4`, `OpEngineValidator`,
`validate_block_post_execution_with_hashed_state`) hits the regex, the
warn fires with `likely_oos:unproven_bad_game_prereq` even though the
draft has no Solidity dispute game whatsoever.

These tests lock the new exception-path behaviour:

1. `test_solidity_fn5_shape_still_warns` — a Solidity dispute-game
   prerequisite draft (FaultDisputeGame, defender_wins, AnchorStateRegistry)
   still fires the warn. Regression check on the legacy FN5/FN6 path.

2. `test_rust_dlt_engine_api_draft_does_not_warn` — a synthetic FN7-shape
   draft citing `engine_newPayloadV4` + `OpEngineValidator` +
   `validate_block_post_execution_with_hashed_state` is suppressed. The
   `unproven_bad_game_prereq` flag must NOT appear in `flags`, but the
   suppression record MUST appear in `suppressed_flags` for transparency.

3. `test_mixed_dispute_and_engine_api_still_warns` — boundary case: a
   draft mentioning BOTH dispute-game and Engine API still fires the
   warn (conservative — operator must adjudicate). Locks the
   exclude_pattern semantics.

Hermetic: each draft is generated in a `tempfile.TemporaryDirectory` so
`derive_scope_path` cannot walk up into the real repo.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scope-reasoner.py"


def _run_tool(draft: Path, scope: Path | None = None) -> dict:
    cmd = [sys.executable, str(TOOL), "--draft", str(draft)]
    if scope is not None:
        cmd += ["--scope", str(scope)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


class DltEngineApiExceptionTests(unittest.TestCase):
    def test_solidity_fn5_shape_still_warns(self) -> None:
        """Regression: a Solidity FN5/FN6-shape draft (privileged dispute
        game prerequisite) must STILL fire `unproven_bad_game_prereq`.
        If this regresses, the new exception path has over-suppressed.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            draft = ws / "fn5_solidity_draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Finding: bridge drain via fraudulent FaultDisputeGame

                    The exploit chain assumes a fraudulent dispute game has been
                    resolved with `defender_wins` status, after which the
                    AnchorStateRegistry treats the bad root as canonical. Once
                    the bad game is resolved, OptimismPortal accepts the
                    poisoned root and a malicious withdrawal proof finalizes.

                    Root cause: the assumption that the FaultDisputeGame can
                    only resolve to a valid state is broken because a
                    privileged proposer can post any output_root. Even after
                    the invalid proposal exists, Base does not blacklist or
                    retire it within the 7-day window.

                    PoC: deploy a MockDisputeGame that returns defender_wins
                    unconditionally, register it as an authorized game, then
                    drive `OptimismPortal.proveWithdrawalTransaction`.
                    """
                ).strip()
                + "\n"
            )

            result = _run_tool(draft)
            flag_names = [f["pattern_name"] for f in result.get("flags", [])]
            suppressed_names = [
                f["pattern_name"] for f in result.get("suppressed_flags", [])
            ]
            self.assertIn(
                "unproven_bad_game_prereq",
                flag_names,
                f"FN5 Solidity regression: warn should fire. flags={flag_names} "
                f"suppressed={suppressed_names} raw={result}",
            )
            self.assertNotIn(
                "unproven_bad_game_prereq",
                suppressed_names,
                "FN5 Solidity draft must not be suppressed",
            )

    def test_rust_dlt_engine_api_draft_does_not_warn(self) -> None:
        """Primary fix: an FN7-shape draft citing Rust Engine API
        entrypoints (engine_newPayloadV4, OpEngineValidator,
        validate_block_post_execution_with_hashed_state) must NOT fire
        `unproven_bad_game_prereq`. The suppression record should appear
        in `suppressed_flags`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            draft = ws / "fn7_rust_dlt_draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Finding: Isthmus withdrawals_root validator silently
                    passes invalid blocks when parent is in-memory only

                    backend: rust

                    ## Production path

                    `engine_newPayloadV4(parent P)` inserts P into Reth's
                    in-memory tree_state. Background persistence is queued but
                    not yet flushed. Immediately after, `engine_newPayloadV4(child C)`
                    where `C.parent_hash = P.hash` and
                    `C.withdrawals_root = 0xdead...dead` reaches
                    `validate_block_post_execution_with_hashed_state` via
                    `OpEngineValidator`. The validator passes silently because
                    its DB-only lookup misses the in-memory parent.

                    ## Components touched

                    - `EngineApiTreeHandler` accepts the malformed child
                    - `BaseEngineValidator::validate_block_post_execution_with_hashed_state`
                      returns `Ok(())` despite the wrong withdrawals_root
                    - `engine_forkchoiceUpdatedV3` then promotes the bad child
                      to `head`, `safe`, and `finalized`

                    Once the bad state has been resolved through this path the
                    invalid block state is finalized on the chain head, even
                    though the withdrawals_root is fraudulent. The Rust
                    EngineApi tree handler is the sole acceptance surface for
                    the malformed payload — propagation is via Engine API
                    JSON-RPC frames, not via any L1 catch-net contract.
                    """
                ).strip()
                + "\n"
            )

            result = _run_tool(draft)
            flag_names = [f["pattern_name"] for f in result.get("flags", [])]
            suppressed = result.get("suppressed_flags", [])
            suppressed_names = [s["pattern_name"] for s in suppressed]

            self.assertNotIn(
                "unproven_bad_game_prereq",
                flag_names,
                f"FN7 Rust DLT draft should NOT fire warn. flags={flag_names} "
                f"suppressed={suppressed_names} raw={result}",
            )
            self.assertIn(
                "unproven_bad_game_prereq",
                suppressed_names,
                f"FN7 Rust DLT draft should record a suppression. flags={flag_names} "
                f"suppressed={suppressed_names}",
            )

            # The suppression record must carry the dlt_engine_api exception
            # name so downstream tooling can audit why the warn was hidden.
            dlt_recs = [
                s
                for s in suppressed
                if s["pattern_name"] == "unproven_bad_game_prereq"
            ]
            self.assertEqual(len(dlt_recs), 1, dlt_recs)
            self.assertEqual(
                dlt_recs[0].get("exception_name"),
                "dlt_engine_api",
                dlt_recs[0],
            )
            self.assertTrue(
                dlt_recs[0].get("include_hits"),
                "include_hits should record at least one DLT/Engine-API "
                "marker line for transparency",
            )
            self.assertEqual(
                dlt_recs[0].get("exclude_hits"),
                [],
                "FN7 draft has no Solidity dispute-game markers",
            )

    def test_mixed_dispute_and_engine_api_still_warns(self) -> None:
        """Conservative boundary: a draft that mentions BOTH dispute-game
        and Engine API still fires the warn. Author must adjudicate
        rather than silently inheriting suppression. Locks the
        exclude_pattern semantics.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            draft = ws / "mixed_dispute_and_engine_api_draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Finding: Engine API + FaultDisputeGame combined drain

                    backend: rust + solidity

                    The exploit starts when `engine_newPayloadV4` accepts a
                    bad child block under `OpEngineValidator`, then propagates
                    to the Solidity FaultDisputeGame contract, which finalizes
                    a fraudulent state via AnchorStateRegistry and OptimismPortal.

                    Once the bad game is resolved with defender_wins, the
                    poisoned root is accepted on L1 and the bridge can be drained.

                    The Engine API surface (engine_newPayloadV4,
                    EngineApiTreeHandler) is one half of the chain; the
                    Solidity dispute game (FaultDisputeGame, defender_wins,
                    AnchorStateRegistry) is the other.
                    """
                ).strip()
                + "\n"
            )

            result = _run_tool(draft)
            flag_names = [f["pattern_name"] for f in result.get("flags", [])]
            suppressed_names = [
                f["pattern_name"] for f in result.get("suppressed_flags", [])
            ]
            self.assertIn(
                "unproven_bad_game_prereq",
                flag_names,
                f"Mixed-class draft should still fire warn (conservative). "
                f"flags={flag_names} suppressed={suppressed_names} raw={result}",
            )
            self.assertNotIn(
                "unproven_bad_game_prereq",
                suppressed_names,
                "Mixed-class draft must NOT be suppressed",
            )


if __name__ == "__main__":
    unittest.main()
