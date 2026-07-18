from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-dex-fix-history.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures mimicking gh api response shapes for one Curve and one Uniswap
# repo, so we can run the full pipeline without live network. Real-source
# discipline is preserved by the live mining run; these tests only exercise
# the ETL logic.
# ---------------------------------------------------------------------------

_FIX_COMMIT_LIST = [
    {
        "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "commit": {
            "message": "fix: add reentrancy guard to swap callback",
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
    },
    {
        "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "commit": {
            "message": "audit: validate min-out on swap to prevent slippage bypass",
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
    },
    {
        "sha": "cccccccccccccccccccccccccccccccccccccccc",
        "commit": {
            "message": "revert: rollback gas-optimisation that broke fee accounting",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
    },
    {
        "sha": "dddddddddddddddddddddddddddddddddddddddd",
        "commit": {
            "message": "docs: typo in README",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
    {
        "sha": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "commit": {
            "message": "chore: prettier formatting",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
]

_FIX_COMMIT_DETAILS: Dict[str, Dict[str, Any]] = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
        "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "parents": [{"sha": "0000000000000000000000000000000000000000"}],
        "commit": {
            "message": "fix: add reentrancy guard to swap callback",
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
        "files": [
            {
                "filename": "contracts/Pool.sol",
                "status": "modified",
                "additions": 4,
                "deletions": 1,
                "patch": (
                    "@@ -10,6 +10,9 @@\n"
                    "-    function swap(uint256 amountIn) external {\n"
                    "+    function swap(uint256 amountIn) external nonReentrant {\n"
                    "+        require(amountIn > 0);\n"
                ),
            },
        ],
    },
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
        "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "parents": [{"sha": "1111111111111111111111111111111111111111"}],
        "commit": {
            "message": "audit: validate min-out on swap to prevent slippage bypass",
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
        "files": [
            {
                "filename": "contracts/Router.vy",
                "status": "modified",
                "additions": 2,
                "deletions": 0,
                "patch": (
                    "@@ -1,3 +1,5 @@\n"
                    "+def swap_exact_in(amount_in: uint256, min_out: uint256):\n"
                    "+    assert min_out > 0\n"
                ),
            },
        ],
    },
    "cccccccccccccccccccccccccccccccccccccccc": {
        "sha": "cccccccccccccccccccccccccccccccccccccccc",
        "parents": [{"sha": "2222222222222222222222222222222222222222"}],
        "commit": {
            "message": "revert: rollback gas-optimisation that broke fee accounting",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "contracts/Fee.sol",
                "status": "modified",
                "additions": 1,
                "deletions": 5,
                "patch": (
                    "@@ -1,5 +1,1 @@\n"
                    "-    unchecked {\n"
                    "-        fee = base * rate / 1e18;\n"
                    "-    }\n"
                    "+    fee = base * rate / 1e18;\n"
                ),
            },
        ],
    },
}


class _FakeGhApiState:
    """Capture all gh_api / list_commits / get_commit_detail traffic.

    The fake serves the commit list and per-commit detail for one
    project, irrespective of the repo string passed.
    """

    def __init__(self) -> None:
        self.calls: List[str] = []

    def gh_api(self, path: str, paginate: bool = False) -> Any:  # noqa: D401
        self.calls.append(path)
        # Commits-list endpoint.
        if "/commits?per_page" in path:
            # Page 1 returns fixtures; page>=2 returns empty.
            if "page=1" in path or "page=" not in path:
                return _FIX_COMMIT_LIST
            return []
        # Per-commit detail endpoint.
        for sha, detail in _FIX_COMMIT_DETAILS.items():
            if path.endswith(f"/commits/{sha}"):
                return detail
        return None


class HackermanEtlFromDexFixHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_dex_fix_history")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_dex_fix_history")
        # Patch gh_api so tests never reach the network.
        self.fake = _FakeGhApiState()
        self._orig_gh_api = self.tool.gh_api
        self.tool.gh_api = self.fake.gh_api  # type: ignore[assignment]

    def tearDown(self) -> None:
        self.tool.gh_api = self._orig_gh_api  # type: ignore[assignment]

    # -----------------------------------------------------------------
    # 1. Schema validation: dry-run emits records with zero validator errors.
    # -----------------------------------------------------------------
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dex-fix-dry-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["Uniswap/v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=5,
                detail_cap=10,
            )
        self.assertEqual(summary["errors"], [], f"errors={summary['errors']}")
        self.assertGreater(summary["records_valid"], 0)
        self.assertEqual(summary["records_total"], summary["records_valid"])

    # -----------------------------------------------------------------
    # 2. Negative filter drops doc / typo / chore commits.
    # -----------------------------------------------------------------
    def test_negative_filter_drops_non_protocol_churn(self) -> None:
        self.assertFalse(self.tool.is_fix_shape("docs: typo in README", "x"))
        self.assertFalse(self.tool.is_fix_shape("chore: prettier formatting", "x"))
        # Keyword present but trapped by negative filter.
        self.assertFalse(self.tool.is_fix_shape("ci: fix lint workflow", "x"))

    def test_positive_filter_admits_fix_shapes(self) -> None:
        self.assertTrue(self.tool.is_fix_shape("fix: prevent reentrancy", "x"))
        self.assertTrue(self.tool.is_fix_shape("audit: validate min-out", "x"))
        self.assertTrue(self.tool.is_fix_shape("revert: rollback prior change", "x"))
        self.assertTrue(self.tool.is_fix_shape("security: patch oracle stale-read", "x"))

    # -----------------------------------------------------------------
    # 3. Detector seed extraction recognises require/modifier/unchecked.
    # -----------------------------------------------------------------
    def test_detector_seed_extracts_require(self) -> None:
        patch = "+    require(amountIn > 0);"
        seed = self.tool.extract_detector_seed(patch, "fix: validate amount")
        self.assertIn("added require(amountIn > 0)", seed)

    def test_detector_seed_extracts_modifier(self) -> None:
        patch = "+    function swap() external nonReentrant {"
        seed = self.tool.extract_detector_seed(patch, "fix: reentrancy")
        self.assertIn("nonReentrant modifier", seed)

    def test_detector_seed_extracts_removed_unchecked(self) -> None:
        patch = "-    unchecked {\n-        fee = a * b;\n-    }"
        seed = self.tool.extract_detector_seed(patch, "revert: rollback")
        self.assertIn("removed unchecked block", seed)

    def test_detector_seed_fallback_is_nonempty(self) -> None:
        seed = self.tool.extract_detector_seed("@@ no body @@\n", "merge pr 1")
        self.assertTrue(seed)
        self.assertGreater(len(seed), 3)

    # -----------------------------------------------------------------
    # 4. Record shape: every required field present, source_audit_ref is
    #    git-mining:<repo>@<full-sha>, commit URL embedded in action seq.
    # -----------------------------------------------------------------
    def test_record_shape_has_source_audit_ref_and_url(self) -> None:
        detail = _FIX_COMMIT_DETAILS["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        rec = self.tool.commit_to_record("Uniswap/v3-core", detail)
        assert rec is not None
        self.assertTrue(rec["source_audit_ref"].startswith("git-mining:Uniswap/v3-core@"))
        self.assertTrue(rec["record_id"].startswith("git-mining:uniswap-v3-core:"))
        self.assertIn(
            "https://github.com/Uniswap/v3-core/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            rec["attacker_action_sequence"],
        )
        # Schema validates.
        schema = self.validator.load_schema()
        verrs = self.validator.validate_doc(rec, schema)
        self.assertEqual(verrs, [])

    def test_record_classifies_reentrancy_and_slippage(self) -> None:
        rec_a = self.tool.commit_to_record(
            "Uniswap/v3-core",
            _FIX_COMMIT_DETAILS["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )
        assert rec_a is not None
        self.assertEqual(rec_a["bug_class"], "reentrancy")

        rec_b = self.tool.commit_to_record(
            "curvefi/curve-stablecoin",
            _FIX_COMMIT_DETAILS["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        )
        assert rec_b is not None
        self.assertEqual(rec_b["bug_class"], "slippage-bypass")
        # Vyper file -> target_language = vyper.
        self.assertEqual(rec_b["target_language"], "vyper")

    # -----------------------------------------------------------------
    # 5. End-to-end pipeline writes record.{yaml,json} pairs that round-trip.
    # -----------------------------------------------------------------
    def test_end_to_end_writes_json_and_yaml_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dex-fix-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                out_dir,
                dry_run=False,
                repos=["Uniswap/v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=5,
                detail_cap=10,
            )
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["records_valid"], 0)
            # Every emitted yaml has a json sidecar.
            yaml_files = list(out_dir.rglob("record.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for yp in yaml_files:
                self.assertTrue((yp.parent / "record.json").exists())

    # -----------------------------------------------------------------
    # 6. Files with no protocol source extension (.sol/.vy) are skipped.
    # -----------------------------------------------------------------
    def test_non_protocol_only_commit_is_skipped(self) -> None:
        detail = {
            "sha": "ffffffffffffffffffffffffffffffffffffffff",
            "parents": [{"sha": "1234567890123456789012345678901234567890"}],
            "commit": {
                "message": "fix: typo in subgraph helper",
                "author": {"date": "2024-01-01T00:00:00Z"},
                "committer": {"date": "2024-01-01T00:00:00Z"},
            },
            "files": [
                {
                    "filename": "subgraph/mapping.ts",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 1,
                    "patch": "-old\n+new",
                },
            ],
        }
        rec = self.tool.commit_to_record("Uniswap/v3-core", detail)
        self.assertIsNone(rec)

    # -----------------------------------------------------------------
    # 7. verification_tier in summary is the realtime-api tier.
    # -----------------------------------------------------------------
    def test_summary_has_verification_tier_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dex-fix-tier-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["Uniswap/v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=5,
                detail_cap=10,
            )
        self.assertEqual(summary["verification_tier"], "tier-1-verified-realtime-api")

    # -----------------------------------------------------------------
    # 8. Schema version pinned to v1.
    # -----------------------------------------------------------------
    def test_schema_version_is_v1(self) -> None:
        rec = self.tool.commit_to_record(
            "Uniswap/v3-core",
            _FIX_COMMIT_DETAILS["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )
        assert rec is not None
        self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1")


if __name__ == "__main__":
    unittest.main()
