# r36-rebuttal: funnel-enforcement-gates-AB
"""Gate A source-existence enforcement tests.

Validates that hunt-sidecar-bridge.py drops / downgrades hallucinated
candidates (applies_to_target=yes with no real file_line) and passes
candidates with real source anchors.

Morpho-midnight failure cases this gate must kill:
  - mimo_harness_morpho-midnight_0456: exitMarket() caller (nonexistent fn)
  - mimo_harness_morpho-midnight_0454: ERC-4626 vault (nonexistent contract)
  - mimo_harness_morpho-midnight_0009: hardcoded chainId (actually block.chainid)
  All three: applies_to_target=yes, file_line='', code_excerpt=''

Morpho-midnight REAL case that must pass:
  - A candidate citing a real .sol function (e.g. _isSolvent) with a valid
    file_line -> must NOT be downgraded.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_BRIDGE_PATH = ROOT / "tools" / "hunt-sidecar-bridge.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("hunt_sidecar_bridge", _BRIDGE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_bridge = _load_bridge()
r76_check = _bridge.r76_source_existence_check
apply_downgrade = _bridge._apply_r76_downgrade
bridge_fn = _bridge.bridge


def _make_sidecar(applies: str, file_line: str, code_excerpt: str = "",
                  file_path_hint: str = "", confidence: str = "high",
                  workspace: str = "test-ws") -> dict:
    inner = {
        "applies_to_target": applies,
        "confidence": confidence,
        "file_line": file_line,
        "code_excerpt": code_excerpt,
        "file_path_hint": file_path_hint,
        "candidate_finding": "test finding",
    }
    return {
        "status": "ok",
        "task_id": "test-task",
        "workspace": workspace,
        "result": json.dumps(inner),
    }


class TestR76CheckUnit(unittest.TestCase):
    """Unit tests for r76_source_existence_check() in isolation."""

    def _ws_with_file(self, tmp: Path, rel_path: str, content: str) -> Path:
        ws = tmp / "ws"
        ws.mkdir(exist_ok=True)
        dst = ws / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8")
        return ws

    # --- bad cases (must fail gate) ---

    def test_yes_empty_file_line_no_hint_fails(self) -> None:
        """applies=yes, file_line='', no file_path_hint -> gate fail."""
        inner = {"applies_to_target": "yes", "file_line": "", "confidence": "high"}
        result = r76_check(inner, ws=None)
        self.assertFalse(result["pass_gate"], result)
        self.assertEqual(result["applies_override"], "no")
        self.assertIn("r76-empty-file-line", result["reason"])

    def test_yes_hallucination_phrase_file_line_fails(self) -> None:
        """applies=yes, file_line='N/A conceptual' -> gate fail."""
        inner = {"applies_to_target": "yes",
                 "file_line": "N/A conceptual pattern", "confidence": "high"}
        result = r76_check(inner, ws=None)
        self.assertFalse(result["pass_gate"], result)
        self.assertEqual(result["applies_override"], "no")

    def test_yes_nonexistent_sol_file_fails(self) -> None:
        """applies=yes, file_line cites a .sol that does not exist -> fail."""
        with tempfile.TemporaryDirectory(prefix="gate-a-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "ws"
            ws.mkdir()
            # Write ONLY Midnight.sol - cite ExitMarket.sol which does not exist
            (ws / "Midnight.sol").write_text(
                "contract Midnight { function _isSolvent() internal {} }\n",
                encoding="utf-8",
            )
            inner = {
                "applies_to_target": "yes",
                "file_line": "src/ExitMarket.sol:42",
                "confidence": "high",
                "code_excerpt": "",
            }
            result = r76_check(inner, ws=ws)
            self.assertFalse(result["pass_gate"], result)
            self.assertEqual(result["applies_override"], "no")
            self.assertIn("r76-file-not-in-workspace", result["reason"])

    def test_yes_excerpt_not_in_source_soft_downgrades(self) -> None:
        """applies=yes, the cited FILE exists but the code_excerpt is not verbatim
        in it -> SOFT R76 downgrade (not a hard source-existence fail).

        Updated for the soft-excerpt design (commit 6700ff881a, independently
        pinned by test_hunt_sidecar_bridge_soft_excerpt.py): once Rule 2 has
        verified the cited file is real, a non-matching excerpt is almost always
        abridged, so it must NOT bury the function as hollow. The gate still
        blocks promotion (pass_gate=False + applies_override='no'); coverage is
        preserved because the function was genuinely examined at a real file:line.
        The only HARD fail is a hallucinated cite (missing file / N/A line)."""
        with tempfile.TemporaryDirectory(prefix="gate-a-excerpt-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = self._ws_with_file(
                tmp, "Foo.sol",
                "contract Foo { function real() external {} }\n"
            )
            inner = {
                "applies_to_target": "yes",
                "file_line": "Foo.sol:1",
                "confidence": "high",
                "code_excerpt": "function exitMarket() external { selfdestruct(payable(msg.sender)); }",
            }
            result = r76_check(inner, ws=ws)
            self.assertFalse(result["pass_gate"], result)          # still blocks promotion
            self.assertEqual(result["applies_override"], "no")     # yes -> no downgrade
            self.assertIn("r76-excerpt-unverified", result["reason"])
            self.assertTrue(result.get("soft_excerpt_fail"))       # SOFT, coverage preserved
            self.assertNotIn("r76-excerpt-not-in-source", result["reason"])

    def test_maybe_high_conf_empty_file_line_fails(self) -> None:
        """applies=maybe + confidence=high with empty file_line -> also fails."""
        inner = {
            "applies_to_target": "maybe",
            "confidence": "high",
            "file_line": "",
        }
        result = r76_check(inner, ws=None)
        self.assertFalse(result["pass_gate"], result)
        self.assertEqual(result["applies_override"], "no")

    # --- good cases (must pass gate) ---

    def test_no_applies_always_passes(self) -> None:
        """applies=no (honest negative) must always pass."""
        inner = {"applies_to_target": "no", "file_line": "", "confidence": "high"}
        result = r76_check(inner, ws=None)
        self.assertTrue(result["pass_gate"], result)
        self.assertIsNone(result["applies_override"])

    def test_maybe_low_conf_passes(self) -> None:
        """applies=maybe + confidence=low is not gated (not a confident positive)."""
        inner = {"applies_to_target": "maybe", "confidence": "low", "file_line": ""}
        result = r76_check(inner, ws=None)
        self.assertTrue(result["pass_gate"], result)

    def test_yes_real_file_line_passes(self) -> None:
        """applies=yes + file_line pointing to a REAL file -> gate passes."""
        with tempfile.TemporaryDirectory(prefix="gate-a-real-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = self._ws_with_file(
                tmp, "Midnight.sol",
                "contract Midnight { function _isSolvent() internal {} }\n"
            )
            inner = {
                "applies_to_target": "yes",
                "file_line": "Midnight.sol:1",
                "confidence": "high",
                "code_excerpt": "",
            }
            result = r76_check(inner, ws=ws)
            self.assertTrue(result["pass_gate"], result)
            self.assertIsNone(result["applies_override"])

    def test_yes_real_file_line_with_matching_excerpt_passes(self) -> None:
        """applies=yes + real file_line + excerpt that grep-matches -> pass."""
        with tempfile.TemporaryDirectory(prefix="gate-a-exc-") as tmp_raw:
            tmp = Path(tmp_raw)
            fn_body = "function _isSolvent(address user) internal view returns (bool) {"
            ws = self._ws_with_file(
                tmp, "Midnight.sol",
                f"contract Midnight {{ {fn_body} return true; }} }}\n"
            )
            inner = {
                "applies_to_target": "yes",
                "file_line": "Midnight.sol:1",
                "confidence": "high",
                "code_excerpt": fn_body,
            }
            result = r76_check(inner, ws=ws)
            self.assertTrue(result["pass_gate"], result)

    def test_yes_empty_file_line_but_hint_resolves_passes(self) -> None:
        """applies=yes + empty file_line but file_path_hint resolves -> pass."""
        with tempfile.TemporaryDirectory(prefix="gate-a-hint-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = self._ws_with_file(
                tmp, "Midnight.sol",
                "contract Midnight { function lock() external {} }\n"
            )
            inner = {
                "applies_to_target": "yes",
                "file_line": "",
                "file_path_hint": "Midnight.sol",
                "confidence": "high",
                "code_excerpt": "",
            }
            result = r76_check(inner, ws=ws)
            self.assertTrue(result["pass_gate"], result)

    def test_yes_empty_file_line_hint_does_not_exist_fails(self) -> None:
        """applies=yes + empty file_line + hint cites nonexistent file -> fail."""
        with tempfile.TemporaryDirectory(prefix="gate-a-hfail-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "ws"
            ws.mkdir()
            # No files in the workspace
            inner = {
                "applies_to_target": "yes",
                "file_line": "",
                "file_path_hint": "src/ExitMarket.sol",
                "confidence": "high",
                "code_excerpt": "",
            }
            result = r76_check(inner, ws=ws)
            self.assertFalse(result["pass_gate"], result)
            self.assertEqual(result["applies_override"], "no")


class TestApplyDowngrade(unittest.TestCase):
    """Tests for _apply_r76_downgrade()."""

    def test_downgrade_flips_applies_and_adds_reason(self) -> None:
        d = _make_sidecar("yes", "")
        check = {
            "pass_gate": False,
            "reason": "r76-empty-file-line: applies_to_target=yes but file_line=''",
            "applies_override": "no",
        }
        out = apply_downgrade(d, check)
        inner = json.loads(out["result"])
        self.assertEqual(inner["applies_to_target"], "no")
        self.assertTrue(inner["r76_source_existence_fail"])
        self.assertIn("r76-empty-file-line", inner["r76_source_existence_reason"])

    def test_non_mimo_sidecar_passes_through_unchanged(self) -> None:
        """A sidecar with no 'result' string is not a MIMO sidecar - pass through."""
        d = {"status": "ok", "task_id": "x", "workspace": "ws"}
        check = {"pass_gate": False, "reason": "r76-test", "applies_override": "no"}
        out = apply_downgrade(d, check)
        self.assertIs(out, d)


class TestBridgeGateA(unittest.TestCase):
    """Integration tests: bridge() with Gate A enabled or disabled."""

    def _make_derived_dir(self, tmp: Path, ws_name: str,
                          candidates: list) -> Path:
        """Write sidecar files into a derived/ dir that bridge() will scan."""
        derived = tmp / "derived" / f"mimo_harness_{ws_name}"
        derived.mkdir(parents=True)
        for i, sidecar in enumerate(candidates):
            (derived / f"mimo_harness_{ws_name}_{i:04d}.json").write_text(
                json.dumps(sidecar), encoding="utf-8"
            )
        return tmp / "derived"

    def test_hallucinated_candidate_is_downgraded_not_dropped(self) -> None:
        """Bad case: applies=yes, file_line='', nonexistent function -> downgraded to no."""
        with tempfile.TemporaryDirectory(prefix="bridge-bad-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "morpho-midnight"
            ws.mkdir()
            # A minimal .sol file in the workspace
            (ws / "Midnight.sol").write_text(
                "contract Midnight { function _isSolvent() internal {} }\n",
                encoding="utf-8",
            )
            # Hallucinated candidate: exitMarket() does not exist
            bad = _make_sidecar(
                applies="yes",
                file_line="",
                code_excerpt="",
                workspace="morpho-midnight",
            )
            derived = self._make_derived_dir(tmp, "morpho-midnight", [bad])
            res = bridge_fn(ws, derived, enforce_r76=True)
            self.assertEqual(res["matched"], 1)
            self.assertEqual(res["r76_downgraded"], 1)
            # Read the written sidecar and verify downgrade
            out_files = list((ws / ".auditooor" / "hunt_findings_sidecars").glob("*.json"))
            self.assertEqual(len(out_files), 1)
            written = json.loads(out_files[0].read_text())
            inner = json.loads(written["result"])
            self.assertEqual(inner["applies_to_target"], "no",
                             "Hallucinated candidate must be downgraded to applies=no")
            self.assertTrue(inner.get("r76_source_existence_fail"),
                            "Downgraded sidecar must carry r76_source_existence_fail=True")

    def test_real_candidate_passes_through_unchanged(self) -> None:
        """Good case: applies=yes, file_line cites a REAL file -> passes unchanged."""
        with tempfile.TemporaryDirectory(prefix="bridge-good-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "morpho-midnight"
            ws.mkdir()
            (ws / "Midnight.sol").write_text(
                "contract Midnight {\n"
                "    function _isSolvent(address user) internal view returns (bool) {\n"
                "        return true;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            good = _make_sidecar(
                applies="yes",
                file_line="Midnight.sol:2",
                code_excerpt="",
                workspace="morpho-midnight",
            )
            derived = self._make_derived_dir(tmp, "morpho-midnight", [good])
            res = bridge_fn(ws, derived, enforce_r76=True)
            self.assertEqual(res["matched"], 1)
            self.assertEqual(res["r76_downgraded"], 0,
                             "Real candidate must NOT be downgraded")
            out_files = list((ws / ".auditooor" / "hunt_findings_sidecars").glob("*.json"))
            self.assertEqual(len(out_files), 1)
            written = json.loads(out_files[0].read_text())
            inner = json.loads(written["result"])
            self.assertEqual(inner["applies_to_target"], "yes",
                             "Real candidate must preserve applies=yes")
            self.assertFalse(inner.get("r76_source_existence_fail", False))

    def test_morpho_midnight_exitmarket_hallucination(self) -> None:
        """Morpho-midnight failure case: exitMarket() does not exist -> downgraded."""
        with tempfile.TemporaryDirectory(prefix="bridge-mm-exit-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "morpho-midnight"
            ws.mkdir()
            (ws / "Midnight.sol").write_text(
                "contract Midnight { function borrow() external {} }\n",
                encoding="utf-8",
            )
            # This is the real morpho-midnight_0456 shape
            bad = _make_sidecar(
                applies="yes",
                file_line="",
                code_excerpt="",
                workspace="morpho-midnight",
            )
            # Manually add candidate_finding to mirror real sidecar
            inner = json.loads(bad["result"])
            inner["candidate_finding"] = (
                "Reentrancy via native token transfer before debt state update, "
                "exitMarket() callable in callback"
            )
            bad["result"] = json.dumps(inner)
            derived = self._make_derived_dir(tmp, "morpho-midnight", [bad])
            res = bridge_fn(ws, derived, enforce_r76=True)
            self.assertEqual(res["r76_downgraded"], 1,
                             "exitMarket hallucination must be downgraded")

    def test_morpho_midnight_erc4626_hallucination(self) -> None:
        """Morpho-midnight failure case: ERC-4626 vault does not exist -> downgraded."""
        with tempfile.TemporaryDirectory(prefix="bridge-mm-erc-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "morpho-midnight"
            ws.mkdir()
            (ws / "Midnight.sol").write_text(
                "contract Midnight { function supply() external {} }\n",
                encoding="utf-8",
            )
            bad = _make_sidecar(
                applies="yes",
                file_line="",
                code_excerpt="",
                workspace="morpho-midnight",
            )
            inner = json.loads(bad["result"])
            inner["candidate_finding"] = (
                "ERC-4626 vault redeem/mint temporal inconsistency in share-to-asset conversion"
            )
            bad["result"] = json.dumps(inner)
            derived = self._make_derived_dir(tmp, "morpho-midnight", [bad])
            res = bridge_fn(ws, derived, enforce_r76=True)
            self.assertEqual(res["r76_downgraded"], 1,
                             "ERC-4626 hallucination must be downgraded")

    def test_no_r76_flag_copies_all_unchanged(self) -> None:
        """--no-r76 disables gate: bad candidate is copied as-is (testing bypass)."""
        with tempfile.TemporaryDirectory(prefix="bridge-nor76-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "morpho-midnight"
            ws.mkdir()
            bad = _make_sidecar("yes", "", workspace="morpho-midnight")
            derived = self._make_derived_dir(tmp, "morpho-midnight", [bad])
            res = bridge_fn(ws, derived, enforce_r76=False)
            self.assertEqual(res["matched"], 1)
            self.assertEqual(res["r76_downgraded"], 0)
            out_files = list((ws / ".auditooor" / "hunt_findings_sidecars").glob("*.json"))
            inner = json.loads(json.loads(out_files[0].read_text())["result"])
            # Without gate, applies_to_target stays "yes"
            self.assertEqual(inner["applies_to_target"], "yes")

    def test_negative_candidate_not_downgraded(self) -> None:
        """applies=no sidecars are honest negatives and must NOT be touched."""
        with tempfile.TemporaryDirectory(prefix="bridge-neg-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "morpho-midnight"
            ws.mkdir()
            neg = _make_sidecar("no", "", workspace="morpho-midnight")
            derived = self._make_derived_dir(tmp, "morpho-midnight", [neg])
            res = bridge_fn(ws, derived, enforce_r76=True)
            self.assertEqual(res["matched"], 1)
            self.assertEqual(res["r76_downgraded"], 0,
                             "Negative candidates must never be downgraded")


if __name__ == "__main__":
    unittest.main()
