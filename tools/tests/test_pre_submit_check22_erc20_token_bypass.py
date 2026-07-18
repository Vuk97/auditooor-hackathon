#!/usr/bin/env python3
"""Codex PR-104 re-review blocker 2 — ERC20-token-as-actor bypass in the
`pre-submit-check.sh` Check #22 impact-bound gate.

Context
-------
FIX-3 patched `tools/fork-replay-assert.py:selector_addresses()` so an
`erc20:<token>:<holder>` key no longer contributes the token contract as an
actor candidate. `pre-submit-check.sh` has TWO inline Python heredocs that
re-implement the same actor-extraction shape (primary-manifest path at
~L1265 and sibling-manifest path at ~L1399). Codex flagged that FIX-3
missed the shell wrapper — a draft that claims `protocol=<TOKEN_ADDR>` with
an `erc20:<TOKEN_ADDR>:<UNRELATED_HOLDER>` PASS key still impact-bound.

This regression locks the fix in the shell wrapper path. We feed a manifest
through `pre-submit-check.sh` that, pre-fix, would have green-lit Check #22
and, post-fix, hard-fails with `assertion-not-impact-bound`.

Two tests are written:

1. `test_primary_manifest_token_address_does_not_impact_bind` — cites the
   full manifest directly. Hits the primary-manifest heredoc (L1265).
2. `test_sibling_manifest_token_address_does_not_impact_bind` — cites only
   the deltas file; pre-submit-check.sh discovers the sibling manifest by
   stem and runs the second heredoc (L1399) over it.

Both use the same bug shape so a one-sided fix (only primary, only
sibling, or just the helper) fails exactly one of these tests.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "pre-submit-check.sh"

TOKEN = "0x" + "aa" * 20  # claimed as `protocol` in the draft.
UNRELATED = "0x" + "cc" * 20  # unrelated holder; pre-fix leaked through.
VICTIM = "0x" + "bb" * 20
ATTACKER = "0x" + "dd" * 20


def _make_ws(tmp: Path) -> Path:
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "fork_replay").mkdir(parents=True)
    (ws / "OOS_CHECKLIST.md").write_text("stub\n")
    return ws


def _write_manifest(ws: Path, tx: str, selector: str) -> dict:
    """Write a manifest whose only PASS assertion has the given selector.

    The manifest `selector` field is in the stripped form — `erc20:<token>:
    <holder>` WITHOUT a trailing `:op:amount`. fork-replay-assert persists
    this stripped form after it parses the CLI spec. Callers that want to
    exercise the impact-bound gate must use the stripped form.
    """
    fr = ws / "fork_replay"
    manifest_path = fr / f"{tx}_manifest.json"
    deltas_path = fr / f"{tx}_deltas.json"
    payload = {
        "tx": tx,
        "status": "executed",
        "block": 101,
        "fork_block": 100,
        "assertions": [
            {
                "selector": selector,
                "status": "PASS",
            }
        ],
    }
    manifest_path.write_text(json.dumps(payload))
    deltas_path.write_text(json.dumps({"tx": tx, "addresses": {}}))
    return {
        "tx": tx,
        "manifest": f"fork_replay/{manifest_path.name}",
        "deltas": f"fork_replay/{deltas_path.name}",
    }


def _draft_body(cite: str) -> str:
    # Use the per-role marker form `**Claimed victim:** 0x…` — that's what
    # the extractor at pre-submit-check.sh L1014 parses. The combined form
    # `victim/attacker/protocol: A / B / C` is not matched by its regex.
    return (
        "# ERC20 token-as-actor regression\n\n"
        "**Severity:** High\n\n"
        f"**Claimed victim:** {VICTIM}\n"
        f"**Claimed attacker:** {ATTACKER}\n"
        f"**Claimed protocol:** {TOKEN}\n\n"
        f"Cited: `{cite}`.\nPoC: poc-tests/x.t.sol.\n"
    )


def _run(sub: Path, severity: str = "High") -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT), str(sub), "--severity", severity],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )


def _check22_lines(out: str) -> list[str]:
    lines = []
    for raw in out.splitlines():
        s = raw.strip()
        if (
            s.startswith("22.")
            or s.startswith("✅ 22.")
            or s.startswith("❌ 22.")
            or s.startswith("⚠️  22.")
            or s.startswith("⚠️ 22.")
        ):
            lines.append(raw)
    return lines


class PreSubmitCheck22ErcTokenBypass(unittest.TestCase):
    """The shell wrapper's Check #22 impact-bound gate must not let an
    `erc20:<TOKEN>:<UNRELATED>` assertion satisfy a `protocol=<TOKEN>`
    claim.
    """

    def test_primary_manifest_token_address_does_not_impact_bind(self) -> None:
        """Primary-manifest heredoc (pre-submit-check.sh L1265)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "11" * 32,
                selector=f"erc20:{TOKEN}:{UNRELATED}",
            )
            draft = ws / "submissions" / "staging" / "erc20_bypass_primary.md"
            draft.write_text(_draft_body(refs["manifest"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "❌ 22.",
                c22,
                msg=(
                    "primary-manifest path must hard-fail when the sole PASS "
                    "assertion references `erc20:<TOKEN>:<UNRELATED>` and the "
                    "draft claims `protocol=<TOKEN>`:\n" + c22
                ),
            )
            self.assertIn("assertion-not-impact-bound", combined.lower())

    def test_sibling_manifest_token_address_does_not_impact_bind(self) -> None:
        """Sibling-manifest heredoc (pre-submit-check.sh L1399). The draft
        cites only the deltas file; the sibling manifest is discovered by
        stem and runs the second heredoc against the same bug shape."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "22" * 32,
                selector=f"erc20:{TOKEN}:{UNRELATED}",
            )
            draft = ws / "submissions" / "staging" / "erc20_bypass_sibling.md"
            # Cite ONLY the deltas file so the sibling-manifest branch runs.
            draft.write_text(_draft_body(refs["deltas"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "❌ 22.",
                c22,
                msg=(
                    "sibling-manifest path must hard-fail identically to "
                    "the primary path for the same bug shape:\n" + c22
                ),
            )
            self.assertIn("assertion-not-impact-bound", combined.lower())

    def test_claimed_holder_still_impact_binds(self) -> None:
        """Non-regression: if the PASS assertion key's HOLDER half matches
        the claimed victim, the gate must still go green — the fix must
        not over-tighten."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            # Holder half is the claimed VICTIM → must still impact-bind
            # post-fix. Token half is also the claimed `protocol=<TOKEN>`
            # but the fix makes the token half a non-actor — binding now
            # comes solely from the holder half.
            refs = _write_manifest(
                ws,
                tx="0x" + "33" * 32,
                selector=f"erc20:{TOKEN}:{VICTIM}",
            )
            draft = ws / "submissions" / "staging" / "erc20_holder_ok.md"
            draft.write_text(_draft_body(refs["manifest"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "✅ 22.",
                c22,
                msg=(
                    "claimed-holder match must still impact-bind — fix must "
                    "not over-tighten:\n" + c22
                ),
            )
            self.assertNotIn("assertion-not-impact-bound", combined.lower())


if __name__ == "__main__":
    unittest.main()
