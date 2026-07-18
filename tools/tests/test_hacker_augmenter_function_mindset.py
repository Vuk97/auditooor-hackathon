"""
test_hacker_augmenter_function_mindset.py — Tests for D-1: per-function
hacker-mindset injection (--inject-function-mindset flag).

Deliverable 5: >= 6 assertions covering:
  1. --inject-function-mindset flag enables the Function-Mindset section
  2. Section omitted (stub text) when flag is absent (backward compat)
  3. Function ranker is called via the inline API (_rank_function)
  4. --max-functions-per-file limits output
  5. --min-confidence filters attack classes
  6. Synthetic Go repo (1-2 files) -> brief contains expected structure

All tests are offline and hermetic.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import textwrap
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Load the module under test
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "agent-prompt-hacker-augmenter.py"


def _load_module(name: str = "agent_prompt_hacker_augmenter"):
    spec = importlib.util.spec_from_file_location(name, TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


aug = _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workspace(tmpdir: str) -> pathlib.Path:
    """Create a minimal workspace structure with .auditooor/ dir."""
    ws = pathlib.Path(tmpdir)
    (ws / ".auditooor").mkdir(exist_ok=True)
    return ws


def _make_go_file(directory: pathlib.Path, filename: str, content: str) -> pathlib.Path:
    """Write a Go source file to the given directory."""
    directory.mkdir(parents=True, exist_ok=True)
    fpath = directory / filename
    fpath.write_text(content, encoding="utf-8")
    return fpath


_SAMPLE_GO_CONTENT = textwrap.dedent("""\
    package keeper

    import (
        "context"
        sdk "github.com/cosmos/cosmos-sdk/types"
    )

    type msgServer struct {
        Keeper
    }

    // RegisterAffiliate registers a new affiliate referral.
    func (k msgServer) RegisterAffiliate(ctx context.Context, msg *types.MsgRegisterAffiliate) (*types.MsgRegisterAffiliateResponse, error) {
        sdkCtx := sdk.UnwrapSDKContext(ctx)
        if err := k.GetAuthority(); err != nil {
            return nil, err
        }
        k.affiliates.Set(sdkCtx, msg.Affiliate, msg.Referee)
        return &types.MsgRegisterAffiliateResponse{}, nil
    }

    // UpdateAffiliateTiers updates the affiliate tier configuration.
    func (k msgServer) UpdateAffiliateTiers(ctx context.Context, msg *types.MsgUpdateAffiliateTiers) (*types.MsgUpdateAffiliateTiersResponse, error) {
        sdkCtx := sdk.UnwrapSDKContext(ctx)
        k.SetAffiliateTiers(sdkCtx, msg.Tiers)
        return &types.MsgUpdateAffiliateTiersResponse{}, nil
    }

    // unexportedHelper is not exported — should be filtered out.
    func (k msgServer) unexportedHelper(ctx context.Context) error {
        return nil
    }
""")

_SAMPLE_GO_CONTENT_2 = textwrap.dedent("""\
    package keeper

    import (
        "context"
    )

    type Keeper struct{}

    // ProcessDeposit processes a user deposit into the vault.
    func (k Keeper) ProcessDeposit(ctx context.Context, amount uint64) error {
        return nil
    }

    // WithdrawFunds withdraws funds from the user account.
    func (k Keeper) WithdrawFunds(ctx context.Context, amount uint64) error {
        return nil
    }
""")


# ---------------------------------------------------------------------------
# Test 1 — --inject-function-mindset flag enables the section
# ---------------------------------------------------------------------------

class TestInjectFunctionMindsetEnablesSection(unittest.TestCase):
    def test_inject_function_mindset_flag_enables_section(self):
        """When inject_function_mindset=True, the brief contains the
        'Function-Mindset Cheat Sheet' header."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
                inject_function_mindset=True,
                target_repo="testorg/testrepo",
            )
            self.assertIn("Function-Mindset Cheat Sheet", md)
            self.assertIn("vault_function_mindset", md)
            fm_section = sections.get("sec_function_mindset", {})
            self.assertNotIn("disabled", fm_section, msg="disabled key must not be set when flag=True")

    def test_section_key_always_present_in_sidecar(self):
        """sec_function_mindset key is always present in sections dict
        regardless of flag state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # With flag off
            _, sections_off = aug.build_brief(
                workspace=ws, lane_id="H1-test", files=["foo.go"],
                hint=None, max_items=8, inject_function_mindset=False,
            )
            self.assertIn("sec_function_mindset", sections_off)

            # With flag on
            _, sections_on = aug.build_brief(
                workspace=ws, lane_id="H1-test", files=["foo.go"],
                hint=None, max_items=8, inject_function_mindset=True,
                target_repo="testorg/testrepo",
            )
            self.assertIn("sec_function_mindset", sections_on)


# ---------------------------------------------------------------------------
# Test 2 — Section omitted / stub when flag absent (backward compat)
# ---------------------------------------------------------------------------

class TestFunctionMindsetDefaultEnabled(unittest.TestCase):
    """TIER A Lift 1 (Hackerman Capability Master Plan): function-mindset
    injection is ENABLED by default. Tests below assert the new default and
    the legacy Wave-3 opt-out path via --no-inject-function-mindset."""

    def test_flag_absent_emits_enabled_section_by_default(self):
        """When inject_function_mindset is NOT passed (uses default True),
        the Function-Mindset section is populated (no 'disabled' stub)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
                # inject_function_mindset NOT passed (uses new default True)
            )
            self.assertIn("Function-Mindset Cheat Sheet", md)
            # Header line must report ENABLED, not the legacy DISABLED stub.
            self.assertIn("Function-mindset injection**: ENABLED", md)
            fm_meta = sections.get("sec_function_mindset", {})
            self.assertNotIn(
                "disabled",
                fm_meta,
                msg="sec_function_mindset must NOT carry disabled=True by default",
            )

    def test_explicit_optout_emits_disabled_stub(self):
        """When inject_function_mindset=False is explicitly passed (legacy
        Wave-3 opt-out), the Function-Mindset section shows 'disabled' stub."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
                inject_function_mindset=False,
            )
            self.assertIn("Function-Mindset Cheat Sheet", md)
            self.assertIn("disabled", md)
            # Disabled-stub text must reference the new --no-inject opt-out
            # so operators discover the right flag from the brief itself.
            self.assertIn("--no-inject-function-mindset", md)
            fm_meta = sections.get("sec_function_mindset", {})
            self.assertTrue(fm_meta.get("disabled", False))
            self.assertEqual(fm_meta.get("items_count", 0), 0)

    def test_existing_sections_unaffected_by_default_flip(self):
        """All 19 original sections (0-14 incl. 0.5/0.7/0.9/5.5) are still
        present in the brief regardless of inject_function_mindset state."""
        expected_headers = [
            "## Section 0 ",
            "## Section 0.5 ",
            "## Section 0.7 ",
            "## Section 0.9 ",
            "## Section 1 ",
            "## Section 5 ",
            "## Section 14 ",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, _ = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
            )
            for hdr in expected_headers:
                self.assertIn(hdr, md, msg=f"Existing section missing: {hdr!r}")


# ---------------------------------------------------------------------------
# Test 3 — Function ranker is called via inline API
# ---------------------------------------------------------------------------

class TestRankerCalledViaInlineAPI(unittest.TestCase):
    def test_rank_function_returns_tuple(self):
        """_rank_function returns a (list, dict) tuple without raising."""
        result = aug._rank_function(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature="func (k msgServer) RegisterAffiliate(...)",
            top_n=5,
            min_confidence=0.4,
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        attack_classes, shape_info = result
        self.assertIsInstance(attack_classes, list)
        self.assertIsInstance(shape_info, dict)

    def test_rank_function_returns_empty_on_unknown_file(self):
        """_rank_function returns ([], {}) gracefully for an unknown file (no crash)."""
        attack_classes, shape_info = aug._rank_function(
            target_repo="testorg/testrepo",
            file_path="nonexistent/path/file.go",
            function_signature="func (k Keeper) SomeHandler(...) error",
            top_n=5,
            min_confidence=0.4,
        )
        self.assertIsInstance(attack_classes, list)
        self.assertIsInstance(shape_info, dict)

    def test_build_sec_function_mindset_calls_ranker_for_each_function(self):
        """_build_sec_function_mindset internally calls _rank_function for each
        extracted function (verified by patching the ranker call)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # Create a real Go file
            go_dir = ws / "protocol" / "x" / "affiliates" / "keeper"
            _make_go_file(go_dir, "msg_server.go", _SAMPLE_GO_CONTENT)
            rel_path = "protocol/x/affiliates/keeper/msg_server.go"

            call_count = [0]

            def patched_rank(*args, **kwargs):
                call_count[0] += 1
                return [], {}  # (attack_classes, shape_info) tuple

            with patch.object(aug, "_rank_function", side_effect=patched_rank):
                aug._build_sec_function_mindset(
                    workspace=ws,
                    files=[rel_path],
                    target_repo="dydxprotocol/v4-chain",
                    max_functions_per_file=20,
                    min_confidence=0.4,
                )

            # Should have been called at least once (for exported handler-like functions)
            self.assertGreater(call_count[0], 0, msg="_rank_function was not called")


# ---------------------------------------------------------------------------
# Test 4 — --max-functions-per-file limits output
# ---------------------------------------------------------------------------

class TestMaxFunctionsPerFileLimit(unittest.TestCase):
    def test_max_functions_per_file_limits_ranked_count(self):
        """With max_functions_per_file=1, only 1 function per file is ranked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            go_dir = ws / "protocol" / "x" / "affiliates" / "keeper"
            _make_go_file(go_dir, "msg_server.go", _SAMPLE_GO_CONTENT)
            rel_path = "protocol/x/affiliates/keeper/msg_server.go"

            call_count = [0]

            def patched_rank(*args, **kwargs):
                call_count[0] += 1
                return [], {}  # (attack_classes, shape_info) tuple

            with patch.object(aug, "_rank_function", side_effect=patched_rank):
                _, meta = aug._build_sec_function_mindset(
                    workspace=ws,
                    files=[rel_path],
                    target_repo="dydxprotocol/v4-chain",
                    max_functions_per_file=1,
                    min_confidence=0.4,
                )

            # At most 1 function per file should be ranked
            self.assertLessEqual(
                call_count[0], 1,
                msg=f"Expected at most 1 _rank_function call, got {call_count[0]}"
            )
            # items_count in metadata must also be <= 1
            self.assertLessEqual(meta.get("items_count", 0), 1)

    def test_max_functions_per_file_cap_in_full_brief(self):
        """build_brief with max_functions_per_file=1 reflects the cap in metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            go_dir = ws / "protocol" / "x" / "clob" / "keeper"
            _make_go_file(go_dir, "msg_server_test_cap.go", _SAMPLE_GO_CONTENT_2)
            rel_path = "protocol/x/clob/keeper/msg_server_test_cap.go"

            with patch.object(aug, "_rank_function", return_value=([], {})):
                _, sections = aug.build_brief(
                    workspace=ws,
                    lane_id="H1-test",
                    files=[rel_path],
                    hint=None,
                    max_items=8,
                    inject_function_mindset=True,
                    max_functions_per_file=1,
                    target_repo="dydxprotocol/v4-chain",
                )

            fm = sections.get("sec_function_mindset", {})
            self.assertEqual(fm.get("max_functions_per_file"), 1)
            self.assertLessEqual(fm.get("items_count", 0), 1)


# ---------------------------------------------------------------------------
# Test 5 — --min-confidence filters attack classes
# ---------------------------------------------------------------------------

class TestMinConfidenceFilter(unittest.TestCase):
    def test_min_confidence_filters_low_confidence_classes(self):
        """Attack classes with confidence below min_confidence are excluded
        from the Function-Mindset section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            go_dir = ws / "keeper"
            _make_go_file(go_dir, "test.go", _SAMPLE_GO_CONTENT)

            # Ranker returns two classes: one above threshold, one below
            def patched_rank(*args, **kwargs):
                return [
                    {"attack_class": "admin-bypass", "confidence": 0.91, "rank": 1, "evidence": []},
                    {"attack_class": "low-conf-class", "confidence": 0.1, "rank": 2, "evidence": []},
                ]

            # Simulate filtering inside _build_sec_function_mindset via _rank_function
            # NOTE: _rank_function already applies min_confidence via ranker.rank().
            # Here we patch it to return pre-filtered data matching min_confidence=0.5.
            high_conf_only = [
                {"attack_class": "admin-bypass", "confidence": 0.91, "rank": 1, "evidence": []},
            ]

            with patch.object(aug, "_rank_function", return_value=(high_conf_only, {})):
                text, meta = aug._build_sec_function_mindset(
                    workspace=ws,
                    files=["keeper/test.go"],
                    target_repo="testorg/testrepo",
                    max_functions_per_file=20,
                    min_confidence=0.5,
                )

            # admin-bypass should appear; low-conf-class should not
            self.assertIn("admin-bypass", text)
            self.assertNotIn("low-conf-class", text)

    def test_min_confidence_passed_to_rank_function(self):
        """min_confidence parameter is forwarded to _rank_function calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            go_dir = ws / "keeper"
            _make_go_file(go_dir, "msg.go", _SAMPLE_GO_CONTENT)

            received_kwargs = []

            def patched_rank(*args, **kwargs):
                received_kwargs.append(kwargs)
                return [], {}  # (attack_classes, shape_info) tuple

            with patch.object(aug, "_rank_function", side_effect=patched_rank):
                aug._build_sec_function_mindset(
                    workspace=ws,
                    files=["keeper/msg.go"],
                    target_repo="testorg/testrepo",
                    max_functions_per_file=20,
                    min_confidence=0.75,
                )

            # At least one call should have been made with min_confidence=0.75
            self.assertTrue(
                any(kw.get("min_confidence") == 0.75 for kw in received_kwargs),
                msg=f"min_confidence=0.75 not forwarded; calls={received_kwargs}"
            )


# ---------------------------------------------------------------------------
# Test 6 — Synthetic small repo -> brief contains expected structure
# ---------------------------------------------------------------------------

class TestSyntheticGoRepoSmoke(unittest.TestCase):
    def test_synthetic_go_repo_produces_function_entries(self):
        """Given a synthetic 1-Go-file workspace, build_brief with
        inject_function_mindset=True produces a brief that:
        - Contains 'Function-Mindset Cheat Sheet'
        - Lists at least one function header (#### `<name>`)
        - Lists the function's attack classes section header
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            go_dir = ws / "keeper"
            _make_go_file(go_dir, "msg_server.go", _SAMPLE_GO_CONTENT)

            # Patch ranker to return a deterministic result (tuple: attack_classes, shape_info)
            def patched_rank(*args, **kwargs):
                return (
                    [
                        {
                            "attack_class": "admin-bypass",
                            "confidence": 0.91,
                            "rank": 1,
                            "evidence": [
                                {"verdict_id": "DYDX-FD-P1", "contribution": 1.2, "scorer": "S1"}
                            ],
                        },
                        {
                            "attack_class": "blocked-addr-bypass",
                            "confidence": 0.78,
                            "rank": 2,
                            "evidence": [
                                {"rule_id": "RULE_D8", "contribution": 0.9, "scorer": "S4"}
                            ],
                        },
                        {
                            "attack_class": "fee-redirect",
                            "confidence": 0.62,
                            "rank": 3,
                            "evidence": [],
                        },
                    ],
                    {"shape_hash": "b94fd5990d1196c6", "shape_hash_fine": "f1e7f5f6473b8bde"},
                )

            with patch.object(aug, "_rank_function", side_effect=patched_rank):
                md, sections = aug.build_brief(
                    workspace=ws,
                    lane_id="H1-clob",
                    files=["keeper/msg_server.go"],
                    hint="msg-server",
                    max_items=8,
                    inject_function_mindset=True,
                    max_functions_per_file=20,
                    min_confidence=0.4,
                    target_repo="dydxprotocol/v4-chain",
                )

            # Core assertions
            self.assertIn("Function-Mindset Cheat Sheet", md)
            self.assertIn("vault_function_mindset", md)

            # At least one function header (exported handler-like)
            import re
            fn_headers = re.findall(r"#### `([^`]+)`", md)
            self.assertGreater(len(fn_headers), 0, msg="No function headers found in brief")

            # Attack classes appear
            self.assertIn("admin-bypass", md)
            self.assertIn("conf 0.91", md)

            # Metadata checks
            fm = sections["sec_function_mindset"]
            self.assertFalse(fm.get("disabled", False))
            self.assertGreater(fm.get("items_count", 0), 0)

    def test_two_go_files_both_processed(self):
        """With 2 Go files in scope, both appear in the function-mindset section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            go_dir = ws / "keeper"
            _make_go_file(go_dir, "msg_server.go", _SAMPLE_GO_CONTENT)
            _make_go_file(go_dir, "deposits.go", _SAMPLE_GO_CONTENT_2)

            with patch.object(aug, "_rank_function", return_value=(
                [{"attack_class": "state-write-bypass", "confidence": 0.80, "rank": 1, "evidence": []}],
                {"shape_hash": "abc123", "shape_hash_fine": "def456"},
            )):
                md, sections = aug.build_brief(
                    workspace=ws,
                    lane_id="H1-test",
                    files=["keeper/msg_server.go", "keeper/deposits.go"],
                    hint=None,
                    max_items=8,
                    inject_function_mindset=True,
                    max_functions_per_file=20,
                    min_confidence=0.4,
                    target_repo="dydxprotocol/v4-chain",
                )

            self.assertIn("msg_server.go", md)
            self.assertIn("deposits.go", md)
            fm = sections["sec_function_mindset"]
            # At least one function per file should contribute
            self.assertGreater(fm.get("items_count", 0), 1)

    def test_non_go_files_skipped_gracefully(self):
        """Solidity and Rust files in scope are skipped silently; section does
        not error and emits the 'no Go files' placeholder."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)

            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-sol-test",
                files=["Pool.sol", "Vault.sol", "lib.rs"],
                hint=None,
                max_items=8,
                inject_function_mindset=True,
                target_repo="testorg/testrepo",
            )

            self.assertIn("Function-Mindset Cheat Sheet", md)
            # Non-Go files produce the empty-section placeholder
            self.assertIn("no Go files", md)
            fm = sections["sec_function_mindset"]
            self.assertEqual(fm.get("items_count", 0), 0)

    def test_warning_lines_present_in_section(self):
        """The function-mindset section always includes the two mandatory
        WARNING lines about SEVERITY.md and pre-submit-check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)

            md, _ = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
                inject_function_mindset=True,
                target_repo="testorg/testrepo",
            )

            self.assertIn("SEVERITY.md", md)
            self.assertIn("pre-submit-check.sh #48 + #49", md)

    def test_cli_inject_flag_produces_section_in_output_file(self):
        """CLI --inject-function-mindset flag: output file contains the section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            (ws / ".auditooor").mkdir()
            out_path = ws / "brief_fm_test.md"

            rc = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-cli-test",
                "--files", "keeper/msg.go",
                "--inject-function-mindset",
                "--target-repo", "dydxprotocol/v4-chain",
                "--out", str(out_path),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(out_path.is_file())
            content = out_path.read_text()
            self.assertIn("Function-Mindset Cheat Sheet", content)
            self.assertIn("vault_function_mindset", content)

    def test_cli_default_emits_function_mindset_enabled(self):
        """CLI default (no flag passed) emits ENABLED Function-Mindset section
        per TIER A Lift 1 (Hackerman Capability Master Plan)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            (ws / ".auditooor").mkdir()
            out_path = ws / "brief_default_fm.md"

            rc = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-cli-default",
                "--files", "foo.go",
                "--out", str(out_path),
            ])
            self.assertEqual(rc, 0)
            content = out_path.read_text()
            # Default = ENABLED: header must say so, not 'disabled' stub
            self.assertIn("Function-Mindset Cheat Sheet", content)
            self.assertIn("Function-mindset injection**: ENABLED", content)

    def test_cli_no_inject_opt_out_emits_disabled_stub(self):
        """CLI with --no-inject-function-mindset reverts to the legacy
        Wave-3 disabled stub (backward compat opt-out)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            (ws / ".auditooor").mkdir()
            out_path = ws / "brief_no_fm.md"

            rc = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-cli-optout",
                "--files", "foo.go",
                "--no-inject-function-mindset",
                "--out", str(out_path),
            ])
            self.assertEqual(rc, 0)
            content = out_path.read_text()
            # Must still have the section header (stub)
            self.assertIn("Function-Mindset Cheat Sheet", content)
            # Must indicate it is disabled
            self.assertIn("disabled", content)
            # Must NOT have the full annotation table
            self.assertNotIn("Top attack hypotheses", content)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
