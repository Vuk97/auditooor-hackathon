#!/usr/bin/env python3
"""Codex PR-104 re-review blocker FIX-7A — manifest-layer `draft_claims`
fallback for the `pre-submit-check.sh` Check #22 impact-bound gate.

Context
-------
`tools/pre-submit-check.sh` has TWO inline Python heredocs that enforce the
impact-bound gate over cited fork-replay manifests: a primary-manifest path
(~L1265) and a sibling-manifest path (~L1399, reached when only a deltas
file or replay YAML is cited). Before FIX-7A, both heredocs only consulted
`FR_CLAIMS_JSON` — the markdown-marker extract from the draft body. A High
draft with NO `**Claimed victim/attacker/protocol:**` markers therefore
bypassed the gate entirely, even when the cited manifest persisted
`draft_claims={"victim": ...}` and the sole PASS assertion had
`impact_bound:false`. Codex local repro on `7ade76e6` printed `✅ 22.`
green.

The fix (per Codex spec):
  1. Keep reading `FR_CLAIMS_JSON` first (markdown authoritative).
  2. If empty, fall back to manifest `payload["draft_claims"]`.
  3. If any claim actor exists, require at least one PASS with
     `impact_bound` True (trust persisted signal first).
  4. If `impact_bound` absent, recompute with iter-v3-4 FIX-3 +
     iter-v3-5 FIX-6 actor semantics:
       * `native:<addr>` → actor
       * `erc20:<token>:<holder>` → holder only, never token
       * `matched_row.holder` / `matched_row.address` only, never `token`.
  5. On failure, print `assertion-not-impact-bound` (vocabulary unchanged).

These 5 regressions lock the fix in both heredocs + the recompute path.
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

VICTIM = "0x" + "bb" * 20
ATTACKER = "0x" + "dd" * 20
TOKEN = "0x" + "aa" * 20
UNRELATED = "0x" + "cc" * 20


def _make_ws(tmp: Path) -> Path:
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "fork_replay").mkdir(parents=True)
    (ws / "OOS_CHECKLIST.md").write_text("stub\n")
    return ws


def _write_manifest(
    ws: Path,
    tx: str,
    assertions: list[dict],
    draft_claims: dict | None = None,
) -> dict:
    fr = ws / "fork_replay"
    manifest_path = fr / f"{tx}_manifest.json"
    deltas_path = fr / f"{tx}_deltas.json"
    payload: dict = {
        "tx": tx,
        "status": "executed",
        "block": 101,
        "fork_block": 100,
        "assertions": assertions,
    }
    if draft_claims is not None:
        payload["draft_claims"] = draft_claims
    manifest_path.write_text(json.dumps(payload))
    deltas_path.write_text(json.dumps({"tx": tx, "addresses": {}}))
    return {
        "tx": tx,
        "manifest": f"fork_replay/{manifest_path.name}",
        "deltas": f"fork_replay/{deltas_path.name}",
    }


def _draft_body_no_markers(cite: str) -> str:
    """High draft body WITHOUT any `**Claimed …:**` markdown markers.

    This is the core pre-condition for FIX-7A: the markdown layer yields
    zero claim addresses, so the gate must fall back to manifest
    `draft_claims`.
    """
    return (
        "# FIX-7A regression — manifest draft_claims fallback\n\n"
        "**Severity:** High\n\n"
        "A High finding that cites a fork-replay manifest but does NOT\n"
        "declare claimed-actor markers in the draft body.\n\n"
        f"Cited: `{cite}`.\n"
        "PoC: poc-tests/x.t.sol.\n"
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


class PreSubmitCheck22ManifestDraftClaims(unittest.TestCase):
    """FIX-7A: manifest `draft_claims` must drive the impact-bound gate
    when the draft omits markdown claim markers. Recompute path must still
    honour iter-v3-4 FIX-3 + iter-v3-5 FIX-6 actor semantics.
    """

    def test_high_manifest_draft_claims_unbound_pass_fails_check22_without_markdown_markers(
        self,
    ) -> None:
        """Primary-manifest heredoc — bug shape from Codex local repro.

        Draft has no `**Claimed …:**` markers. Manifest persists
        `draft_claims={"victim": VICTIM}` and a sole PASS with
        `impact_bound:false` on an unrelated selector. Expect
        `❌ 22. … assertion-not-impact-bound`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "11" * 32,
                assertions=[
                    {
                        "selector": f"native:{UNRELATED}",
                        "status": "PASS",
                        "impact_bound": False,
                    }
                ],
                draft_claims={"victim": VICTIM},
            )
            draft = ws / "submissions" / "staging" / "fix7a_primary.md"
            draft.write_text(_draft_body_no_markers(refs["manifest"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "❌ 22.",
                c22,
                msg=(
                    "primary-manifest path must hard-fail when the "
                    "manifest's draft_claims claim a victim but the sole "
                    "PASS assertion has impact_bound:false:\n" + c22
                ),
            )
            self.assertIn("assertion-not-impact-bound", combined.lower())

    def test_high_sibling_manifest_draft_claims_unbound_fails_check22_without_markdown_markers(
        self,
    ) -> None:
        """Sibling-manifest heredoc — same bug shape, deltas-only cite.

        Draft cites only the deltas file, forcing pre-submit-check.sh down
        the sibling-manifest branch. Both heredocs must stay in lock-step.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "22" * 32,
                assertions=[
                    {
                        "selector": f"native:{UNRELATED}",
                        "status": "PASS",
                        "impact_bound": False,
                    }
                ],
                draft_claims={"victim": VICTIM},
            )
            draft = ws / "submissions" / "staging" / "fix7a_sibling.md"
            # Cite ONLY the deltas file.
            draft.write_text(_draft_body_no_markers(refs["deltas"]))
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

    def test_high_manifest_draft_claims_bound_passes_check22_without_markdown_markers(
        self,
    ) -> None:
        """Non-regression — an `impact_bound:true` PASS must still pass.

        Same shape as test #1 but with `impact_bound:true`. The fix must
        not over-tighten: a persisted True signal is the strongest evidence
        the replay covered the claimed actor.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "33" * 32,
                assertions=[
                    {
                        "selector": f"native:{VICTIM}",
                        "status": "PASS",
                        "impact_bound": True,
                    }
                ],
                draft_claims={"victim": VICTIM},
            )
            draft = ws / "submissions" / "staging" / "fix7a_bound.md"
            draft.write_text(_draft_body_no_markers(refs["manifest"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "✅ 22.",
                c22,
                msg=(
                    "impact_bound:true must still earn Check #22 green — "
                    "fix must not over-tighten:\n" + c22
                ),
            )
            self.assertNotIn("assertion-not-impact-bound", combined.lower())

    def test_high_manifest_erc20_token_address_does_not_bind_protocol_claim_without_impact_bound_key(
        self,
    ) -> None:
        """Recompute path honours iter-v3-4 FIX-3 + iter-v3-5 FIX-6.

        Manifest `draft_claims={"protocol": TOKEN}`, assertion selector
        `erc20:<TOKEN>:<UNRELATED>` with NO `impact_bound` field. The
        recomputation must NOT treat `<TOKEN>` (the ERC20 contract) as an
        actor — only `<UNRELATED>` (the holder), and UNRELATED ≠ claimed
        protocol, so the gate must fail.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "44" * 32,
                assertions=[
                    {
                        "selector": f"erc20:{TOKEN}:{UNRELATED}",
                        "status": "PASS",
                        # Deliberately no `impact_bound` key — exercises
                        # the recompute path.
                    }
                ],
                draft_claims={"protocol": TOKEN},
            )
            draft = ws / "submissions" / "staging" / "fix7a_erc20_tok.md"
            draft.write_text(_draft_body_no_markers(refs["manifest"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "❌ 22.",
                c22,
                msg=(
                    "recompute path must NOT treat the ERC20 token half "
                    "as an actor — FIX-3 locks `<token>` as a contract, "
                    "never an actor:\n" + c22
                ),
            )
            self.assertIn("assertion-not-impact-bound", combined.lower())

    def test_high_manifest_erc20_holder_address_binds_claim_without_impact_bound_key(
        self,
    ) -> None:
        """Recompute path accepts the ERC20 holder half.

        Manifest `draft_claims={"victim": VICTIM}`, assertion selector
        `erc20:<TOKEN>:<VICTIM>` with NO `impact_bound` field. The
        recomputation must treat `<VICTIM>` (the holder) as an actor and
        bind the claim.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_manifest(
                ws,
                tx="0x" + "55" * 32,
                assertions=[
                    {
                        "selector": f"erc20:{TOKEN}:{VICTIM}",
                        "status": "PASS",
                        # No `impact_bound` — exercises recompute.
                    }
                ],
                draft_claims={"victim": VICTIM},
            )
            draft = ws / "submissions" / "staging" / "fix7a_erc20_hold.md"
            draft.write_text(_draft_body_no_markers(refs["manifest"]))
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn(
                "✅ 22.",
                c22,
                msg=(
                    "recompute path must accept `<holder>` as an actor — "
                    "iter-v3-4 FIX-3 locks only `<token>` as non-actor:\n"
                    + c22
                ),
            )
            self.assertNotIn("assertion-not-impact-bound", combined.lower())


if __name__ == "__main__":
    unittest.main()
