"""Hermetic tests for tools/novel-hypothesis-probe.py (PR #126 MVP).

Per `docs/PLAN_NOVEL_HYPOTHESIS_GENERATOR.md` MVP requirements:

  * 5 fixtures, one per hypothesis shape, each emitting expected JSON
    sidecar fields.
  * One "no candidates" fixture → empty briefs + clean exit.
  * One "missing CCIA evidence" fixture → confidence resolves to
    `needs_review` / `unknown` (NOT `high`).
  * One "stale-config narrowed" fixture: a generic centralization signal
    alone MUST NOT fire (Codex narrowing).
  * One "economic grief without attacker-cost evidence" fixture MUST NOT
    fire (Codex narrowing).

These tests do NOT touch the real corpus on disk — every fixture is
materialised inside a tempdir. Shell-outs are disabled via
`--no-shell-out` so they remain deterministic on CI.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "novel-hypothesis-probe.py"


def _load_module():
    """Load the probe by file path (filename has a dash, can't normal-import)."""
    if "novel_hypothesis_probe" in sys.modules:
        return sys.modules["novel_hypothesis_probe"]
    spec = importlib.util.spec_from_file_location("novel_hypothesis_probe", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Python 3.14 dataclasses resolution requires the module to be in
    # sys.modules at exec time (it walks sys.modules to resolve KW_ONLY).
    sys.modules["novel_hypothesis_probe"] = module
    spec.loader.exec_module(module)
    return module


def _seed(
    shape: str,
    *,
    title: str = "",
    contract: str = "",
    function: str = "",
    interaction: str = "",
    rationale: str = "",
    body: str = "",
    ccia_angle_id: str = "",
    ccia_reachable=None,
    ccia_rationale: str = "",
    extra_evidence: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    seed: Dict[str, Any] = {
        "shape": shape,
        "title": title,
        "contract": contract,
        "function": function,
        "interaction": interaction,
        "rationale": rationale,
        "body": body,
    }
    if ccia_angle_id:
        seed["ccia_angle_id"] = ccia_angle_id
    if ccia_reachable is not None:
        seed["ccia_reachable"] = ccia_reachable
    if ccia_rationale:
        seed["ccia_rationale"] = ccia_rationale
    if extra_evidence:
        seed["extra_evidence"] = extra_evidence
    return seed


def _write_workspace(
    tmp: str,
    seeds: List[Dict[str, Any]],
    *,
    ccia_angles: List[Dict[str, Any]] | None = None,
    write_ccia: bool = True,
) -> Path:
    ws = Path(tmp) / "ws"
    ws.mkdir()
    (ws / "novel_hypothesis_seeds.json").write_text(json.dumps({"seeds": seeds}))
    if write_ccia:
        ccia_payload = {
            "ccia": {"target": "fixture"},
            "attack_angles": ccia_angles or [],
        }
        (ws / "ccia_report.json").write_text(json.dumps(ccia_payload))
    return ws


def _run_probe(ws: Path, *, top: int = 10) -> dict:
    mod = _load_module()
    return mod.run_probe(ws, top=top, no_shell_out=True)


def _read_sidecar(out_dir: Path, idx: int = 1) -> Dict[str, Any]:
    """Read the brief_NNN_*.json file at the given rank."""
    for p in sorted(out_dir.glob(f"brief_{idx:03d}_*.json")):
        return json.loads(p.read_text())
    raise FileNotFoundError(f"no brief_{idx:03d}_*.json in {out_dir}")


# ---------------------------------------------------------------------------
# 5 hypothesis-shape fixtures (Codex requirement #1).
# ---------------------------------------------------------------------------

class FiveShapeFixtureTest(unittest.TestCase):
    def _good_extra_evidence(self) -> Dict[str, Any]:
        return {
            "variant_detector_score": 0,
            "anti_pattern_26_clear": True,
            "anti_pattern_25_clear": True,
            "centralization_risk": False,
        }

    def test_trust_boundary_emits_required_sidecar_fields(self) -> None:
        seed = _seed(
            "trust_boundary",
            title="Vault.takeFromBuyer drains escrow via 1271 callback",
            contract="Vault",
            function="takeFromBuyer",
            interaction="ERC1271 isValidSignature",
            rationale="(caller=ERC1271-signer, callee=Vault.escrow) pair "
                      "is not exercised by any reentrancy/auth detector.",
            ccia_reachable=True,
            ccia_rationale="reachable from signMessage path",
            extra_evidence=self._good_extra_evidence(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 1)
            self.assertEqual(summary["counts"]["rejected"], 0)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            for f in (
                "novelty_shape",
                "negative_space_evidence",
                "corpus_distance_evidence",
                "ccai_or_ccia_reachability",
                "dedup_evidence",
                "scope_oos_evidence",
                "confidence",
            ):
                self.assertIn(f, sc, f"sidecar missing required field: {f}")
            self.assertEqual(sc["novelty_shape"], "trust_boundary")
            self.assertIn("A-AUTH", sc["negative_space_evidence"]["covered_classes_checked"])
            self.assertEqual(sc["confidence"], "high")

    def test_external_callback_ordering_emits_required_sidecar_fields(self) -> None:
        seed = _seed(
            "external_callback_ordering",
            title="Router.swap drains pool via call-after-state-write reorder",
            contract="Router",
            function="swap",
            interaction="external token.transfer after state write",
            rationale="cross-checked vs reentrancy-family DSL patterns; "
                      "no near-twin found.",
            ccia_reachable=True,
            extra_evidence=self._good_extra_evidence(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            _run_probe(ws)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            self.assertEqual(sc["novelty_shape"], "external_callback_ordering")
            self.assertIn("A-REENT", sc["negative_space_evidence"]["covered_classes_checked"])
            self.assertTrue(sc["corpus_distance_evidence"]["is_empty"])

    def test_cross_domain_replay_emits_required_sidecar_fields(self) -> None:
        seed = _seed(
            "cross_domain_replay",
            title="Bridge.relay replays signedPayload across chainId via cached domainSeparator",
            contract="Bridge",
            function="relay",
            interaction="EIP-712 domain separator does not pin chainId",
            rationale="extends EIP-712 cached-domain class — sibling chain "
                      "with same address can replay signedPayload.",
            ccia_reachable=True,
            extra_evidence=self._good_extra_evidence(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            _run_probe(ws)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            self.assertEqual(sc["novelty_shape"], "cross_domain_replay")
            self.assertEqual(sc["confidence"], "high")

    def test_stale_config_narrowed_with_concrete_state_slot_passes(self) -> None:
        body = textwrap.dedent("""
            After admin.pause(asset), the rateOracle.lastQuote mapping for
            that asset is left un-reconciled. The non-admin user-facing
            BorrowRouter.borrow() reader path reads it via a state slot
            keyed by asset id. Reachable secondary state confirmed —
            mapping(asset => RateQuote) outlives the pause.
        """).strip()
        seed = _seed(
            "stale_config_after_admin_op",
            title="RateOracle.pause leaves lastQuote mapping reachable to non-admin borrowers",
            contract="RateOracle",
            function="pause",
            interaction="non-admin BorrowRouter.borrow read path",
            rationale="pause leaves RateOracle.lastQuote unreconciled",
            body=body,
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 5,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 1)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            self.assertEqual(sc["novelty_shape"], "stale_config_after_admin_op")

    def test_economic_grief_with_cost_math_passes(self) -> None:
        body = (
            "Attacker spends $5 in calldata gas to spam refund; "
            "defender loses $500 collateral per invocation. "
            "Attacker cost vs defender loss ratio < 1."
        )
        seed = _seed(
            "economic_grief",
            title="OrderBook.refund drains maker collateral via partial-fill replay",
            contract="OrderBook",
            function="refund",
            interaction="partial-fill replay over 100 small orders",
            rationale="attacker cost vs defender loss math attached",
            body=body,
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 1)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            self.assertEqual(sc["novelty_shape"], "economic_grief")


# ---------------------------------------------------------------------------
# Edge-case fixtures (Codex requirements #2-#5).
# ---------------------------------------------------------------------------

class EmptyAndMissingEvidenceTest(unittest.TestCase):
    def test_no_candidates_clean_exit(self) -> None:
        """Empty seed list → no briefs, no rejections, index.json written."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["raw"], 0)
            self.assertEqual(summary["counts"]["accepted"], 0)
            self.assertEqual(summary["counts"]["rejected"], 0)
            out = ws / "swarm" / "novel_hypothesis_briefs"
            self.assertTrue((out / "index.json").exists())
            self.assertEqual(list(out.glob("brief_*.md")), [])
            self.assertEqual(list(out.glob("brief_*.json")), [])

    def test_missing_ccia_evidence_demotes_to_unknown(self) -> None:
        """No CCIA report + ccia_reachable unset → confidence becomes
        `unknown` (or `needs_review`), explicitly NOT `high`.
        """
        seed = _seed(
            "trust_boundary",
            title="Vault.takeFromBuyer drains escrow via 1271 callback",
            contract="Vault",
            function="takeFromBuyer",
            interaction="ERC1271",
            rationale="caller-callee pair not exercised",
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed], write_ccia=False)
            _run_probe(ws)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            self.assertNotEqual(sc["confidence"], "high")
            self.assertNotEqual(sc["confidence"], "medium")
            self.assertIn(sc["confidence"], ("needs_review", "unknown"))


class StaleConfigNarrowingTest(unittest.TestCase):
    """Codex narrowing: generic centralization alone MUST NOT fire."""

    def test_generic_centralization_alone_is_rejected(self) -> None:
        seed = _seed(
            "stale_config_after_admin_op",
            title="Owner can drain Vault via setFeeRecipient",
            contract="Vault",
            function="setFeeRecipient",
            interaction="centralization",
            rationale="trusted admin / centralization risk — owner can drain",
            body="admin can rug; trusted admin holds keys; centralization risk.",
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": True,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 0)
            self.assertEqual(summary["counts"]["rejected"], 1)
            r = summary["rejected"][0]
            self.assertEqual(r["shape"], "stale_config_after_admin_op")
            self.assertIn("generic centralization", r["reason"])

    def test_admin_op_without_state_slot_is_rejected(self) -> None:
        """An admin op named correctly but no concrete state slot still
        rejects (we don't accept signal-only matches)."""
        seed = _seed(
            "stale_config_after_admin_op",
            title="Pause leaves the system in a weird state",
            contract="Pauser",
            function="pause",
            interaction="(no slot)",
            rationale="paused but stuff is left over",
            body="something is stale after pause is called",
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 0)
            self.assertEqual(summary["counts"]["rejected"], 1)


class EconomicGriefNarrowingTest(unittest.TestCase):
    """Codex narrowing: hand-wavy grief MUST NOT fire."""

    def test_grief_without_cost_math_is_rejected(self) -> None:
        seed = _seed(
            "economic_grief",
            title="OrderBook.refund is annoying to mitigate via gas",
            contract="OrderBook",
            function="refund",
            interaction="griefing",
            rationale="this costs gas to mitigate, it is annoying",
            body="users have to spend gas to clean it up, annoying.",
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 0)
            self.assertEqual(summary["counts"]["rejected"], 1)
            self.assertIn("hand-wavy", summary["rejected"][0]["reason"])

    def test_grief_with_dollar_pair_math_passes(self) -> None:
        seed = _seed(
            "economic_grief",
            title="OrderBook.refund drains maker collateral via partial-fill replay",
            contract="OrderBook",
            function="refund",
            interaction="partial-fill replay",
            rationale="cost asymmetry $5 vs $500",
            body="attacker spends $5 vs defender loses $500 — ratio < 1.",
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["accepted"], 1)


# ---------------------------------------------------------------------------
# Confidence-rule + advisory-only invariants.
# ---------------------------------------------------------------------------

class ConfidenceAdvisoryOnlyTest(unittest.TestCase):
    def test_variant_detector_high_score_demotes_to_needs_review(self) -> None:
        seed = _seed(
            "trust_boundary",
            title="Vault.takeFromBuyer drains escrow via 1271 callback",
            contract="Vault",
            function="takeFromBuyer",
            interaction="ERC1271",
            rationale="...",
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 75,  # HIGH dupe-risk band
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            _run_probe(ws)
            sc = _read_sidecar(ws / "swarm" / "novel_hypothesis_briefs")
            self.assertEqual(sc["confidence"], "needs_review")

    def test_run_summary_records_advisory_only_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [])
            summary = _run_probe(ws)
            self.assertEqual(summary["mvp_invariants"]["auto_dispatch"], False)
            self.assertEqual(
                summary["mvp_invariants"]["confidence_consumed_by_gate"], False
            )

    def test_probe_does_not_import_engage_or_dispatch(self) -> None:
        """Code-level invariant: the probe MUST NOT import engage.py or any
        dispatch helper. Plan correction #4: confidence is advisory only.
        """
        text = TOOL.read_text()
        for forbidden in ("import engage", "from engage", "dispatch_brief"):
            self.assertNotIn(
                forbidden, text,
                f"novel-hypothesis-probe.py must not reference {forbidden!r} — "
                "MVP invariant: read-only probe, no auto-dispatch.",
            )


# ---------------------------------------------------------------------------
# I-09 (PR #158): explicit loader_status in summary so unprepared workspaces
# stop returning a silent zero.
# ---------------------------------------------------------------------------

class LoaderStatusTest(unittest.TestCase):
    def test_no_seeds_file_emits_no_seeds_file_found(self) -> None:
        """Unprepared workspace: no `novel_hypothesis_seeds.json`, no
        `--seeds`. The probe must surface `no_seeds_file_found` so operators
        can tell apart "I-09 silent zero" from "all candidates rejected".
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["raw"], 0)
            self.assertEqual(summary["counts"]["accepted"], 0)
            self.assertEqual(summary["counts"]["rejected"], 0)
            self.assertEqual(summary["loader_status"], "no_seeds_file_found")
            # And the index.json on disk records it too.
            idx = json.loads(
                (ws / "swarm" / "novel_hypothesis_briefs" / "index.json").read_text()
            )
            self.assertEqual(idx["loader_status"], "no_seeds_file_found")

    def test_seeds_loaded_when_seeds_produce_candidates(self) -> None:
        seed = _seed(
            "trust_boundary",
            title="Vault.takeFromBuyer drains escrow via 1271 callback",
            contract="Vault",
            function="takeFromBuyer",
            interaction="ERC1271 isValidSignature",
            rationale="r",
            ccia_reachable=True,
            extra_evidence={
                "variant_detector_score": 0,
                "anti_pattern_26_clear": True,
                "anti_pattern_25_clear": True,
                "centralization_risk": False,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [seed])
            summary = _run_probe(ws)
            self.assertEqual(summary["loader_status"], "seeds_loaded")

    def test_empty_seeds_file_emits_seeds_file_empty_or_invalid(self) -> None:
        """File is present but contains zero usable candidates."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [])
            summary = _run_probe(ws)
            self.assertEqual(summary["counts"]["raw"], 0)
            self.assertEqual(summary["loader_status"], "seeds_file_empty_or_invalid")


# ---------------------------------------------------------------------------
# CLI smoke test.
# ---------------------------------------------------------------------------

class CliSmokeTest(unittest.TestCase):
    def test_cli_runs_clean_with_empty_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _write_workspace(tmp, [])
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws), "--no-shell-out"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("[novel-probe]", proc.stdout)
            self.assertIn("loader=", proc.stdout)

    def test_cli_emits_hint_when_no_seeds_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws), "--no-shell-out"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("loader=no_seeds_file_found", proc.stdout)
            self.assertIn("no novel_hypothesis_seeds.json", proc.stderr)


if __name__ == "__main__":
    unittest.main()
