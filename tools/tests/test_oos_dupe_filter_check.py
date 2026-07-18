#!/usr/bin/env python3
"""Tests for tools/oos-dupe-filter-check.py.

Hermetic: each test builds a throwaway workspace under ``tempfile`` and
seeds a synthetic ``.auditooor/invariant_ledger.json`` and synthetic
drafts under ``submissions/staging/``.

Coverage map (PR #511 Slice 4 follow-up, Wave 5 QQ):

    test_no_ledger_returns_advisory_rc2
    test_ledger_present_but_no_oos_row_returns_rc2
    test_ledger_with_unparseable_artifacts_returns_rc2
    test_clean_draft_no_class_match_returns_rc0
    test_match_without_rebuttal_blocks_with_rationale
    test_match_with_rebuttal_comment_passes
    test_multiple_matches_in_single_draft_all_reported
    test_short_alias_rebuttal_accepted (POLY-182 alias rather than full id)
    test_explicit_draft_argument_overrides_staging_glob
    test_json_mode_emits_machine_readable_summary
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib import util as importlib_util
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MODULE_PATH = _REPO_ROOT / "tools" / "oos-dupe-filter-check.py"


def _load_module():
    name = "oos_dupe_filter_check_under_test"
    spec = importlib_util.spec_from_file_location(name, str(_MODULE_PATH))
    assert spec and spec.loader
    module = importlib_util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec so dataclass introspection in
    # Python 3.14 (which calls sys.modules.get(cls.__module__).__dict__)
    # does not crash on a not-yet-installed module.
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


_MOD = _load_module()


# Encoded classes copied verbatim from
# docs/POLYMARKET_LEDGER_RESEARCH_2026-04-29.md (Kimi's Wave 4 deliverable).
_ENCODED_ARTIFACTS = [
    "Encoded rejected classes (minimum 6):",
    (
        "1. OFF.A-CollateralOfframp-missing-WRAPPER_ROLE -- rejected as "
        "duplicate AND falsified by live state at block 86009972 "
        "(rolesOf returns 2). Resubmissions must pin a block where "
        "rolesOf=0."
    ),
    (
        "2. POLY-182 / R77-12 CTFExchange.pauseTrading does not halt "
        "adapter ops -- rejected: architectural-domain-separation-by-design "
        "(independent pause + fully-collateralized siblings, no "
        "market-price extraction)."
    ),
    (
        "3. POLY-49 CtfCollateralAdapter.splitPosition Unwrapped event "
        "misattribution -- rejected: adapter must hold USDCE; user "
        "attribution reconstructible from subsequent ERC1155.TransferBatch."
    ),
    (
        "4. POLY-46 Auth.renounceOperatorRole emits "
        "RemovedOperator(operator,operator) -- rejected: event-only "
        "cosmetic; isOperator mapping correctly updated (FM-class POLY-46)."
    ),
    (
        "5. POLY-45 / D14 _updateOrderStatus uint248 pack overflow -- "
        "rejected: makerAmount >= 2^248 unrealistic given token supply "
        "(FM-class POLY-45)."
    ),
    (
        "6. OOS_R41-E2 maxFeeRate up to 9999bps via admin+operator -- "
        "OOS: admin+operator collusion = centralization-by-design."
    ),
    (
        "7. OOS_R41-S2 preapproval survives signer rotation -- OOS: "
        "requires operator cooperation, classed centralization-adjacent."
    ),
    (
        "8. OOS_R41-T1 timestamp-zombie orders -- OOS: operator "
        "stale-match, classed centralization-adjacent."
    ),
    (
        "9. ProxyFactory.gsnModule no code-length check -- OOS: "
        "onlyOwner setter (centralization)."
    ),
    (
        "10. CollateralToken UUPS storage-gap -- OOS: best-practice "
        "recommendation."
    ),
]


def _make_workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "submissions" / "staging").mkdir(parents=True)
    return ws


def _write_ledger(ws: Path, payload: object) -> Path:
    path = ws / ".auditooor" / "invariant_ledger.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_draft(ws: Path, name: str, body: str) -> Path:
    path = ws / "submissions" / "staging" / name
    path.write_text(body, encoding="utf-8")
    return path


def _run_main(*argv: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _MOD.main(list(argv))
    return rc, buf.getvalue()


class OosDupeFilterCheckTests(unittest.TestCase):

    # --- advisory paths (rc=2) -----------------------------------------

    def test_no_ledger_returns_advisory_rc2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            # No ledger written.
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 2)
            self.assertIn("no invariant ledger", out)

    def test_ledger_present_but_no_oos_row_returns_rc2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {"id": "POLY-FOO", "invariant_family": "fee_bounds_no_donation_loss"},
            ])
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 2)
            self.assertIn("no OOS-duplicate-filter row", out)

    def test_ledger_with_unparseable_artifacts_returns_rc2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": [
                        "no leading number, no -- separator",
                        "/some/path/to/file.md",
                    ],
                }
            ])
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 2)
            self.assertIn("no parseable encoded classes", out)

    # --- happy / clean paths -------------------------------------------

    def test_clean_draft_no_class_match_returns_rc0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            _write_draft(
                ws,
                "FN42-novel-vault-share-inflation-draft.md",
                "# FN42 Novel ERC4626 vault share inflation\n\n"
                "Severity: Medium. Rounding-direction asymmetry on first "
                "deposit lets attacker inflate share price.\n",
            )
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 0, msg=out)
            self.assertIn("no draft matches encoded classes", out)

    # --- block paths ----------------------------------------------------

    def test_match_without_rebuttal_blocks_with_rationale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            # Draft re-claims POLY-182 / R77-12 verbatim.
            _write_draft(
                ws,
                "FN50-pausetrading-does-not-halt-adapter-draft.md",
                "# CTFExchange pauseTrading does not halt adapter ops\n\n"
                "POLY-182 / R77-12 — when CTFExchange.pauseTrading is "
                "called, NegRiskCtfCollateralAdapter.convertPositions "
                "still succeeds. Adapter ops keep running through paused "
                "trading, so we have a market-price extraction window.\n",
            )
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 1, msg=out)
            # Cites the rejection rationale.
            self.assertIn("architectural-domain-separation-by-design", out)
            # Block tag and class id present.
            self.assertIn("[BLOCK]", out)
            self.assertIn("POLY-182", out)
            # Mentions the rebuttal escape hatch.
            self.assertIn("oos-dupe-rebuttal", out)

    def test_match_with_rebuttal_comment_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            body = (
                "# CTFExchange pauseTrading does not halt adapter ops\n\n"
                "POLY-182 / R77-12 — when CTFExchange.pauseTrading is "
                "called, NegRiskCtfCollateralAdapter.convertPositions "
                "still succeeds. We exhibit a market-price extraction "
                "primitive that the original architectural-domain-"
                "separation argument did NOT cover.\n\n"
                "<!-- oos-dupe-rebuttal: POLY-182 "
                "fixed-ratio-extraction-shown via priced-conversion "
                "primitive (see PoC test L42-L88) -->\n"
            )
            _write_draft(
                ws,
                "FN51-pausetrading-extraction-rebutted-draft.md",
                body,
            )
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 0, msg=out)
            self.assertIn("[REBUTTED]", out)
            self.assertIn("all 1 match(es)", out)

    def test_multiple_matches_in_single_draft_all_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            # Single draft that re-claims POLY-182 (#2) AND OOS_R41-E2 (#6).
            body = (
                "# Combined regression: pauseTrading + 99% maxFee\n\n"
                "We resurrect POLY-182 / R77-12 — pauseTrading does not "
                "halt adapter convertPositions ops despite the original "
                "architectural-domain-separation framing.\n\n"
                "And we also resurrect OOS_R41-E2 — admin+operator "
                "collusion sets maxFeeRate to 9999bps.\n"
            )
            _write_draft(ws, "FN99-combined-resubmit-draft.md", body)
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 1, msg=out)
            self.assertIn("POLY-182", out)
            self.assertIn("OOS_R41-E2", out)
            # Two BLOCK sections (one per matched class).
            self.assertGreaterEqual(out.count("[BLOCK]"), 2)

    def test_short_alias_rebuttal_accepted(self) -> None:
        """Operator may rebut with a short alias such as ``POLY-182``."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            body = (
                "# OOS_R41-E2 99pct maxFee resurrected with non-privileged path\n\n"
                "Admin+operator collusion is no longer required because "
                "rounding asymmetry on a permissionless taker call also "
                "drives maxFeeRate violation. centralization-by-design "
                "framing is rebutted.\n\n"
                "<!-- oos-dupe-rebuttal: OOS_R41-E2 non-privileged-path-shown -->\n"
            )
            _write_draft(ws, "FN77-r41e2-non-privileged-draft.md", body)
            rc, out = _run_main("--workspace", str(ws))
            self.assertEqual(rc, 0, msg=out)
            self.assertIn("[REBUTTED]", out)

    # --- CLI ergonomics -------------------------------------------------

    def test_explicit_draft_argument_overrides_staging_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            # A clean draft in staging would otherwise be picked up.
            _write_draft(
                ws,
                "FN10-clean-draft.md",
                "# Clean novel finding\n\nNothing to do with the encoded classes.\n",
            )
            # Targeted dirty draft outside staging.
            outside = Path(tmp) / "elsewhere.md"
            outside.write_text(
                "# OOS_R41-E2 99% maxFee resurrected\n"
                "admin+operator collusion ... centralization-by-design.\n",
                encoding="utf-8",
            )
            rc, out = _run_main(
                "--workspace", str(ws),
                "--draft", str(outside),
            )
            self.assertEqual(rc, 1, msg=out)
            self.assertIn("OOS_R41-E2", out)
            # Clean staging draft should NOT have been scanned.
            self.assertNotIn("FN10-clean-draft.md", out)

    def test_json_mode_emits_machine_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _write_ledger(ws, [
                {
                    "id": "POLY-OOS-DUPE-FILTER",
                    "invariant_family": "oos_duplicate_filter",
                    "artifacts": _ENCODED_ARTIFACTS,
                }
            ])
            _write_draft(
                ws,
                "FN60-pausetrading-resubmit-draft.md",
                "# CTFExchange pauseTrading does not halt adapter ops\n\n"
                "POLY-182 / R77-12 architectural-domain-separation rebut "
                "attempt without a real new primitive.\n",
            )
            rc, out = _run_main("--workspace", str(ws), "--json")
            self.assertEqual(rc, 1, msg=out)
            payload = json.loads(out.strip().splitlines()[-1])
            self.assertEqual(payload["status"], "blocked")
            self.assertGreaterEqual(payload["encoded_classes"], 6)
            classes = {m["class_id"] for m in payload["matches"]}
            self.assertTrue(any("POLY-182" in c for c in classes))


if __name__ == "__main__":
    unittest.main()
