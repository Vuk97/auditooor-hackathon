from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-major-defi-fix-history.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures mimicking gh api response shapes for one Aave-like and one
# Seaport-like repo, so we can run the full pipeline without live network.
# Real-source discipline is preserved by the live mining run; these tests
# only exercise the ETL logic deterministically.
# ---------------------------------------------------------------------------

_FIX_COMMIT_LIST = [
    {
        "sha": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "commit": {
            "message": "fix: add reentrancy guard to flash-loan callback",
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
    },
    {
        "sha": "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "commit": {
            "message": "audit: validate min-out on swap to prevent slippage bypass",
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
    },
    {
        "sha": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
        "commit": {
            "message": "revert: rollback rounding-direction change that broke shares math",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
    },
    {
        "sha": "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
        "commit": {
            "message": "docs: typo in README",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
    {
        "sha": "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
        "commit": {
            "message": "chore: prettier formatting",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
    {
        "sha": "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
        "commit": {
            "message": "security: patch underflow in interest accrual",
            "author": {"date": "2024-06-01T08:00:00Z"},
            "committer": {"date": "2024-06-01T08:00:00Z"},
        },
    },
]

_FIX_COMMIT_DETAILS: Dict[str, Dict[str, Any]] = {
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1": {
        "sha": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "parents": [{"sha": "0000000000000000000000000000000000000000"}],
        "commit": {
            "message": "fix: add reentrancy guard to flash-loan callback",
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
                    "-    function flashLoan(uint256 amount) external {\n"
                    "+    function flashLoan(uint256 amount) external nonReentrant {\n"
                    "+        require(amount > 0);\n"
                ),
            },
        ],
    },
    "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2": {
        "sha": "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "parents": [{"sha": "1111111111111111111111111111111111111111"}],
        "commit": {
            "message": "audit: validate min-out on swap to prevent slippage bypass",
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
        "files": [
            {
                "filename": "contracts/Router.sol",
                "status": "modified",
                "additions": 2,
                "deletions": 0,
                "patch": (
                    "@@ -1,3 +1,5 @@\n"
                    "+    function swapExactIn(uint256 amountIn, uint256 minOut) external {\n"
                    "+        require(minOut > 0);\n"
                ),
            },
        ],
    },
    "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3": {
        "sha": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
        "parents": [{"sha": "2222222222222222222222222222222222222222"}],
        "commit": {
            "message": "revert: rollback rounding-direction change that broke shares math",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "contracts/Vault.sol",
                "status": "modified",
                "additions": 1,
                "deletions": 5,
                "patch": (
                    "@@ -1,5 +1,1 @@\n"
                    "-    unchecked {\n"
                    "-        shares = assets * 1e18 / totalAssets;\n"
                    "-    }\n"
                    "+    shares = assets * 1e18 / totalAssets;\n"
                ),
            },
        ],
    },
    "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6": {
        "sha": "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
        "parents": [{"sha": "3333333333333333333333333333333333333333"}],
        "commit": {
            "message": "security: patch underflow in interest accrual",
            "author": {"date": "2024-06-01T08:00:00Z"},
            "committer": {"date": "2024-06-01T08:00:00Z"},
        },
        "files": [
            {
                "filename": "contracts/Interest.sol",
                "status": "modified",
                "additions": 3,
                "deletions": 1,
                "patch": (
                    "@@ -3,4 +3,6 @@\n"
                    "+    require(borrowIndex >= prev);\n"
                    "+    rate = SafeMath.sub(borrowIndex, prev);\n"
                ),
            },
        ],
    },
}


class _FakeGhApiState:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def gh_api(self, path: str, paginate: bool = False) -> Any:
        self.calls.append(path)
        if "/commits?per_page" in path:
            if "page=1" in path or "page=" not in path:
                return _FIX_COMMIT_LIST
            return []
        for sha, detail in _FIX_COMMIT_DETAILS.items():
            if path.endswith(f"/commits/{sha}"):
                return detail
        return None


class HackermanEtlFromMajorDefiFixHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_major_defi_fix_history")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_major_defi_fix_history")
        self.fake = _FakeGhApiState()
        self._orig_gh_api = self.tool.gh_api
        self.tool.gh_api = self.fake.gh_api  # type: ignore[assignment]

    def tearDown(self) -> None:
        self.tool.gh_api = self._orig_gh_api  # type: ignore[assignment]

    # 1. Dry-run emits records with zero validator errors.
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="major-defi-dry-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["aave/aave-v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=5,
                detail_cap=10,
            )
        self.assertEqual(summary["errors"], [], f"errors={summary['errors']}")
        self.assertGreater(summary["records_valid"], 0)
        self.assertEqual(summary["records_total"], summary["records_valid"])

    # 2. Negative filter drops doc / typo / chore commits.
    def test_negative_filter_drops_non_protocol_churn(self) -> None:
        self.assertFalse(self.tool.is_fix_shape("docs: typo in README", "x"))
        self.assertFalse(self.tool.is_fix_shape("chore: prettier formatting", "x"))
        self.assertFalse(self.tool.is_fix_shape("ci: fix lint workflow", "x"))

    # 3. Positive filter admits the extended keyword set.
    def test_positive_filter_admits_extended_keywords(self) -> None:
        self.assertTrue(self.tool.is_fix_shape("fix: prevent reentrancy", "x"))
        self.assertTrue(self.tool.is_fix_shape("audit: validate min-out", "x"))
        self.assertTrue(self.tool.is_fix_shape("security: patch underflow", "x"))
        self.assertTrue(self.tool.is_fix_shape("guard against price manipulation", "x"))
        self.assertTrue(self.tool.is_fix_shape("rounding direction in shares math", "x"))
        self.assertTrue(self.tool.is_fix_shape("overflow in fee math", "x"))

    # 4. Detector seed extracts require/modifier/unchecked.
    def test_detector_seed_extracts_require(self) -> None:
        patch = "+    require(amountIn > 0);"
        seed = self.tool.extract_detector_seed(patch, "fix: validate amount")
        self.assertIn("added require(amountIn > 0)", seed)

    def test_detector_seed_extracts_modifier(self) -> None:
        patch = "+    function flashLoan() external nonReentrant {"
        seed = self.tool.extract_detector_seed(patch, "fix: reentrancy")
        self.assertIn("nonReentrant modifier", seed)

    def test_detector_seed_extracts_removed_unchecked(self) -> None:
        patch = "-    unchecked {\n-        x = a * b;\n-    }"
        seed = self.tool.extract_detector_seed(patch, "revert: rollback")
        self.assertIn("removed unchecked block", seed)

    def test_detector_seed_fallback_is_nonempty(self) -> None:
        seed = self.tool.extract_detector_seed("@@ no body @@\n", "merge pr 1")
        self.assertTrue(seed)
        self.assertGreater(len(seed), 3)

    # 5. Record shape: source_audit_ref + commit URL embedded in action seq.
    def test_record_shape_has_source_audit_ref_and_url(self) -> None:
        detail = _FIX_COMMIT_DETAILS["a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"]
        rec = self.tool.commit_to_record("aave/aave-v3-core", detail)
        assert rec is not None
        self.assertTrue(rec["source_audit_ref"].startswith("git-mining:aave/aave-v3-core@"))
        self.assertTrue(rec["record_id"].startswith("git-mining:aave-aave-v3-core:"))
        self.assertIn(
            "https://github.com/aave/aave-v3-core/commit/a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            rec["attacker_action_sequence"],
        )
        schema = self.validator.load_schema()
        verrs = self.validator.validate_doc(rec, schema)
        self.assertEqual(verrs, [])

    # 6. Bug-class classification for new keyword paths.
    def test_record_classifies_reentrancy_slippage_underflow(self) -> None:
        rec_a = self.tool.commit_to_record(
            "aave/aave-v3-core",
            _FIX_COMMIT_DETAILS["a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"],
        )
        assert rec_a is not None
        self.assertEqual(rec_a["bug_class"], "reentrancy")
        self.assertEqual(rec_a["target_domain"], "lending")

        rec_b = self.tool.commit_to_record(
            "ProjectOpenSea/seaport",
            _FIX_COMMIT_DETAILS["b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"],
        )
        assert rec_b is not None
        self.assertEqual(rec_b["bug_class"], "slippage-bypass")
        # Schema enum mapping: seaport -> 'nft'.
        self.assertEqual(rec_b["target_domain"], "nft")

        rec_f = self.tool.commit_to_record(
            "compound-finance/comet",
            _FIX_COMMIT_DETAILS["f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"],
        )
        assert rec_f is not None
        self.assertEqual(rec_f["bug_class"], "arithmetic-underflow")
        self.assertEqual(rec_f["target_domain"], "lending")

    # 7. End-to-end pipeline writes record.{yaml,json} pairs.
    def test_end_to_end_writes_json_and_yaml_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="major-defi-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                out_dir,
                dry_run=False,
                repos=["aave/aave-v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=5,
                detail_cap=10,
            )
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["records_valid"], 0)
            yaml_files = list(out_dir.rglob("record.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for yp in yaml_files:
                self.assertTrue((yp.parent / "record.json").exists())

    # 8. Non-protocol-only commit is skipped.
    def test_non_protocol_only_commit_is_skipped(self) -> None:
        detail = {
            "sha": "9999999999999999999999999999999999999999",
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
        rec = self.tool.commit_to_record("aave/aave-v3-core", detail)
        self.assertIsNone(rec)

    # 9. verification_tier in summary is the realtime-api tier.
    def test_summary_has_verification_tier_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="major-defi-tier-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["aave/aave-v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=5,
                detail_cap=10,
            )
        self.assertEqual(summary["verification_tier"], "tier-1-verified-realtime-api")

    # 10. Schema version pinned to v1.
    def test_schema_version_is_v1(self) -> None:
        rec = self.tool.commit_to_record(
            "aave/aave-v3-core",
            _FIX_COMMIT_DETAILS["a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"],
        )
        assert rec is not None
        self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1")

    # 11. Per-repo domain mapping covers every default repo.
    def test_repo_domain_mapping_covers_all_default_repos(self) -> None:
        for repo in self.tool.REPOS:
            self.assertIn(repo, self.tool.REPO_DOMAIN, f"missing domain for {repo}")
            self.assertTrue(self.tool.REPO_DOMAIN[repo])

    # 12. Negative-verdict threshold for major-defi is >=100.
    def test_negative_verdict_threshold(self) -> None:
        with tempfile.TemporaryDirectory(prefix="major-defi-neg-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["aave/aave-v3-core"],
                pages=1,
                per_page=10,
                max_records_per_repo=2,
                detail_cap=10,
            )
        # With one repo and 4 fix-shape fixtures (3 distinct details), we
        # emit fewer than 100 records → negative_verdict must be True.
        self.assertTrue(summary["negative_verdict"])


if __name__ == "__main__":
    unittest.main()
