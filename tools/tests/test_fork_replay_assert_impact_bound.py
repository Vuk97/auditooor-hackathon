#!/usr/bin/env python3
"""Regression tests for --draft-claims impact-bound assertion binding.

Capability-v3 iter-001 T2 (Codex roadmap #1): replay PASS must bind to the
draft's claimed victim/protocol/attacker economic impact, not just any numeric
delta. See tools/fork-replay-assert.py for the spec.

Three covered scenarios:
  1. Assertion selector references the claimed victim → PASS + exit 0.
  2. Assertion selector references an unrelated address → error code
     `assertion-not-impact-bound` + non-zero exit.
  3. Without --draft-claims, the tool behaves exactly as the legacy path
     (hard-negative backward-compat check).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "fork-replay-assert.py"

TX = "0x" + "cd" * 32
TX_FROM = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VICTIM = "0x1111111111111111111111111111111111111111"
ATTACKER = "0x2222222222222222222222222222222222222222"
TOKEN = "0x3333333333333333333333333333333333333333"
UNRELATED = "0x9999999999999999999999999999999999999999"
# Codex PR 104 blocker #6: the ERC20 role-distinction regressions use
# `PROTOCOL` as a "protocol" actor that is ALSO the ERC20 contract in the
# collision case. The pre-fix bug: `erc20:<PROTOCOL>:<UNRELATED>` was
# impact-binding because PROTOCOL appeared in the key (as the token), even
# though PROTOCOL is a contract, not the holder whose balance moved.
PROTOCOL = "0x4444444444444444444444444444444444444444"


def _make_fixture(tmp: Path) -> tuple[Path, Path]:
    """Manifest + deltas with a victim drain AND an unrelated address gain.

    The unrelated address (UNRELATED) having a positive ERC20 delta is the
    whole point of the hard-negative test — it proves the "someone else
    gained Y" PASS cannot be substituted for "victim lost X".
    """
    manifest = {
        "schema_version": 1,
        "status": "executed",
        "tx": TX,
        "rpc": "https://mock-rpc.local",
        "block": 1001,
        "fork_block": 1000,
        "from": TX_FROM,
        "to": VICTIM,
        "artifacts": {},
    }
    deltas = {
        "schema_version": 1,
        "pre_block_number": "1000",
        "post_block_number": "1001",
        "addresses": {
            VICTIM: {
                "nativeWei": {"pre": "100", "post": "50", "delta": "-50"},
                "erc20": {
                    TOKEN: {
                        "pre": "1000000",
                        "post": "750000",
                        "delta": "-250000",
                    }
                },
            },
            ATTACKER: {
                "nativeWei": {"pre": "10", "post": "200", "delta": "190"},
                "erc20": {
                    TOKEN: {"pre": "0", "post": "250000", "delta": "250000"}
                },
            },
            # The unrelated address has a real gain. A caller could (wrongly)
            # prove this and mark a replay PASS without touching the victim.
            # Two ERC20 rows on UNRELATED:
            #   - TOKEN:   used by the legacy hard-negative test (#2).
            #   - PROTOCOL: used by the PR 104 blocker #6 role-collision
            #     regression — a draft with `protocol=PROTOCOL` must NOT
            #     impact-bind on `erc20:PROTOCOL:UNRELATED`, since PROTOCOL
            #     is the TOKEN contract, not the holder.
            UNRELATED: {
                "nativeWei": {"pre": "0", "post": "0", "delta": "0"},
                "erc20": {
                    TOKEN: {"pre": "0", "post": "500000", "delta": "500000"},
                    PROTOCOL: {
                        "pre": "0",
                        "post": "123456",
                        "delta": "123456",
                    },
                },
            },
        },
        "targeted_watches": [
            {
                "label": "victim",
                "kind": "erc20",
                "token": TOKEN,
                "holder": VICTIM,
                "pre": "1000000",
                "post": "750000",
                "delta": "-250000",
                "error": None,
            },
            {
                "label": "noise",
                "kind": "erc20",
                "token": TOKEN,
                "holder": UNRELATED,
                "pre": "0",
                "post": "500000",
                "delta": "500000",
                "error": None,
            },
        ],
    }
    mp = tmp / f"{TX}_manifest.json"
    dp = tmp / f"{TX}_deltas.json"
    mp.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    dp.write_text(json.dumps(deltas, indent=2, sort_keys=True))
    return mp, dp


def _write_claims(tmp: Path, **kwargs: str) -> Path:
    """Dump a draft-claims JSON payload to a temp file and return its path."""
    cp = tmp / "claims.json"
    cp.write_text(json.dumps(kwargs, indent=2, sort_keys=True))
    return cp


def _run(
    manifest: Path,
    deltas: Path,
    specs: list[str],
    *,
    claims: Path | None = None,
) -> subprocess.CompletedProcess:
    args = [
        sys.executable,
        str(TOOL),
        "--manifest",
        str(manifest),
        "--deltas",
        str(deltas),
    ]
    for s in specs:
        args += ["--assert-delta", s]
    if claims is not None:
        args += ["--draft-claims", str(claims)]
    return subprocess.run(args, capture_output=True, text=True)


class ImpactBoundTest(unittest.TestCase):
    # ---------------------------------------------------------------------
    # 1. Happy path: an assertion that references the claimed victim PASSES
    # and the exit code is 0.
    # ---------------------------------------------------------------------
    def test_assertion_bound_to_victim_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            mp, dp = _make_fixture(tmp_p)
            cp = _write_claims(
                tmp_p,
                victim=VICTIM,
                attacker=ATTACKER,
                direction="loss",
                min_magnitude="100000",
            )
            proc = _run(
                mp,
                dp,
                # selector references the victim address AND the claim has
                # victim=VICTIM → this assertion IS impact-bound.
                [f"erc20:{TOKEN}:{VICTIM}:lt:0"],
                claims=cp,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            self.assertNotIn("assertion-not-impact-bound", proc.stderr)
            # The tool persists impact_bound + draft_claims into the manifest.
            manifest_doc = json.loads(mp.read_text())
            (assertion,) = manifest_doc["assertions"]
            self.assertEqual(assertion["status"], "PASS")
            self.assertTrue(assertion["impact_bound"])
            self.assertEqual(
                manifest_doc["draft_claims"]["victim"], VICTIM.lower()
            )
            # And into the deltas file.
            deltas_doc = json.loads(dp.read_text())
            self.assertTrue(deltas_doc["assertions"][0]["impact_bound"])
            self.assertIn("draft_claims", deltas_doc)

    # ---------------------------------------------------------------------
    # 2. Hard negative: draft claims "victim loses X" but the only PASS
    # assertion proves "unrelated_addr gains Y" → assertion-not-impact-bound.
    # ---------------------------------------------------------------------
    def test_assertion_bound_to_unrelated_address_fails_as_not_impact_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            mp, dp = _make_fixture(tmp_p)
            cp = _write_claims(tmp_p, victim=VICTIM, attacker=ATTACKER)
            proc = _run(
                mp,
                dp,
                # selector references UNRELATED (not victim / attacker /
                # protocol in the claims file) → should PASS as numeric
                # assertion BUT be flagged not-impact-bound.
                [f"erc20:{TOKEN}:{UNRELATED}:gt:0"],
                claims=cp,
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            self.assertIn("assertion-not-impact-bound", proc.stderr)
            manifest_doc = json.loads(mp.read_text())
            (assertion,) = manifest_doc["assertions"]
            # The numeric comparison itself still PASSES — the gate is on
            # impact_bound, not on the assertion's PASS/FAIL verdict.
            self.assertEqual(assertion["status"], "PASS")
            self.assertFalse(assertion["impact_bound"])

    # ---------------------------------------------------------------------
    # 3. Backward compat: without --draft-claims, legacy behavior is intact.
    # Same fixture, same selector: the tool must NOT error on impact-bound,
    # must NOT write `impact_bound` or `draft_claims` keys, and must exit 0.
    # ---------------------------------------------------------------------
    def test_no_draft_claims_falls_back_to_legacy_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            mp, dp = _make_fixture(tmp_p)
            proc = _run(
                mp,
                dp,
                # Same "unrelated address" selector as test (2) — under legacy
                # mode this must be a clean PASS with no impact-bound gate.
                [f"erc20:{TOKEN}:{UNRELATED}:gt:0"],
                claims=None,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            self.assertNotIn("assertion-not-impact-bound", proc.stderr)
            manifest_doc = json.loads(mp.read_text())
            deltas_doc = json.loads(dp.read_text())
            (assertion,) = manifest_doc["assertions"]
            self.assertEqual(assertion["status"], "PASS")
            # Legacy mode MUST NOT add new top-level keys or the
            # per-assertion `impact_bound` flag — backward compatibility is
            # enforced at the artifact level, not just at exit-code level.
            self.assertNotIn("impact_bound", assertion)
            self.assertNotIn("draft_claims", manifest_doc)
            self.assertNotIn("draft_claims", deltas_doc)
            for a in deltas_doc["assertions"]:
                self.assertNotIn("impact_bound", a)

    # ---------------------------------------------------------------------
    # 4. Codex PR 104 blocker #6 (ERC20 role-collision): draft claims
    # `protocol=<TOKEN_ADDR>`, assertion key is `erc20:<TOKEN_ADDR>:<unrelated>`.
    # Pre-fix: the TOKEN address in the key matched `protocol`, so the tool
    # treated the unrelated holder's gain as impact-bound.
    # Post-fix: only the HOLDER side of `erc20:<token>:<holder>` counts as an
    # actor candidate; the TOKEN side is a contract, not an actor. The
    # assertion must therefore NOT impact-bind, and the tool must emit
    # `assertion-not-impact-bound`.
    # ---------------------------------------------------------------------
    def test_check22_erc20_token_address_does_not_match_protocol_actor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            mp, dp = _make_fixture(tmp_p)
            # Claim protocol = the ERC20 contract address (PROTOCOL). This is
            # the exact configuration Codex flagged: a protocol-as-token
            # address collides with the ERC20 key's token slot.
            cp = _write_claims(
                tmp_p, victim=VICTIM, attacker=ATTACKER, protocol=PROTOCOL
            )
            proc = _run(
                mp,
                dp,
                # Key: token=PROTOCOL, holder=UNRELATED. Numeric assertion
                # will PASS (UNRELATED gained 123456 of PROTOCOL), but the
                # holder UNRELATED is NOT a claimed actor — so impact-bound
                # must be FALSE and the tool must hard-error.
                [f"erc20:{PROTOCOL}:{UNRELATED}:gt:0"],
                claims=cp,
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            self.assertIn("assertion-not-impact-bound", proc.stderr)
            manifest_doc = json.loads(mp.read_text())
            (assertion,) = manifest_doc["assertions"]
            # The numeric assertion itself still PASSES (delta > 0).
            self.assertEqual(assertion["status"], "PASS")
            # The role-distinction fix: impact_bound must be FALSE — the
            # TOKEN address (PROTOCOL) must not satisfy the actor match.
            self.assertFalse(
                assertion["impact_bound"],
                msg=(
                    "regression: ERC20 token address leaked into actor "
                    "matching — `protocol=<TOKEN>` must not bind an "
                    "unrelated holder's delta"
                ),
            )

    # ---------------------------------------------------------------------
    # 5. Codex PR 104 blocker #6 companion: confirm the HOLDER side of
    # `erc20:<token>:<holder>` still correctly impact-binds when the holder
    # matches a claimed actor. This is the non-regression half of the
    # role-distinction fix — tightening token matching must not break the
    # legitimate "victim lost X of some token" case.
    # ---------------------------------------------------------------------
    def test_check22_erc20_holder_address_matching_actor_does_impact_bind(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            mp, dp = _make_fixture(tmp_p)
            # Claim only the victim. The assertion selector references the
            # victim as the HOLDER of some token — this is the canonical
            # "victim's ERC20 balance moved" shape and must impact-bind.
            cp = _write_claims(tmp_p, victim=VICTIM)
            proc = _run(
                mp,
                dp,
                [f"erc20:{TOKEN}:{VICTIM}:lt:0"],
                claims=cp,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"stdout={proc.stdout}\nstderr={proc.stderr}",
            )
            self.assertNotIn("assertion-not-impact-bound", proc.stderr)
            manifest_doc = json.loads(mp.read_text())
            (assertion,) = manifest_doc["assertions"]
            self.assertEqual(assertion["status"], "PASS")
            self.assertTrue(
                assertion["impact_bound"],
                msg=(
                    "regression: holder-side ERC20 actor match was broken "
                    "by the token-side exclusion fix"
                ),
            )


if __name__ == "__main__":
    unittest.main()
