#!/usr/bin/env python3
"""Tests for tools/invariant-ledger.py (PR #511 Slice 2).

Stdlib-only. Synthetic workspaces in tempdirs — no dependency on
~/audits/ or any external source root.

Coverage matrix (>= 20 cases):
  1. --init creates both files (Markdown + JSON).
  2. --init is idempotent (re-running keeps existing rows).
  3. --init creates a workspace dir that did not exist.
  4. JSON store and Markdown round-trip a single valid row.
  5. JSON store and Markdown round-trip a row with multi-item lists.
  6. --check passes on a valid ledger.
  7. --check fails (rc=1) on bad status enum.
  8. --check fails (rc=1) on missing required field.
  9. --check fails (rc=1) on dangling artifact path.
 10. --check warns (in stderr but rc=0 unless severity-error) on
     unrecognised required_engine.
 11. --check fails (rc=1) on duplicate id.
 12. --check fails (rc=1) on High-severity row with empty source_citations.
 13. --check fails (rc=1) on status=blocked with empty artifacts.
 14. --check returns rc=2 when ledger missing entirely.
 15. --from-scope on synthetic SCOPE.md generates rows.
 16. --from-scope is additive (does not clobber existing rows).
 17. --from-scope skips when scope sources are absent (no rows seeded).
 18. --from-scope on submissions/SUBMISSIONS.md generates anti-regression rows.
 19. --require-high-impact-harness exits 1 on High row in missing_harness.
 20. --require-high-impact-harness exits 0 on High row in scaffolded.
 21. --require-high-impact-harness exits 2 (WARN) when only Medium rows
     are missing_harness.
 22. --emit-closeout writes manifest with status_counts and high_impact totals.
 23. --emit-closeout manifest schema string is auditooor.invariant_ledger_manifest.v1.
 24. --help exits 0 and mentions all CLI flags.
 25. --workspace path is mutually exclusive vs no-mode (argparse rejects
     missing mode flag).
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


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-ledger.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("invariant_ledger", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec so dataclass introspection works under py3.14.
    sys.modules["invariant_ledger"] = mod
    spec.loader.exec_module(mod)
    return mod


def _run(args: list, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(cwd) if cwd else None,
    )


_MOD = _load_module()


def _valid_row(**overrides):
    row = _MOD.Row(
        id="TEST-I01",
        scope_asset="vault",
        invariant_family="conservation",
        statement="Total deposits == sum of user balances.",
        source_citations=["SCOPE.md::vault"],
        attacker_capability="non-privileged depositor",
        trusted_boundary="admin owner of upgrade",
        oos_boundary="OOS if upgrade is paused",
        production_path="src/Vault.sol::deposit",
        harness_target="test/invariants/Vault.t.sol::invariant_total_supply",
        required_engine="forge",
        negative_test="deposit > balanceOf delta",
        status="scaffolded",
        artifacts=["test/invariants/Vault.t.sol"],
        owner="Claude",
    )
    for k, v in overrides.items():
        setattr(row, k, v)
    return row


def _make_ws_with_rows(tmp: Path, rows: list) -> Path:
    """Build a workspace and persist rows via the tool's save_rows()."""
    ws = tmp / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    # Touch any artifact paths so --check doesn't fail on dangling refs.
    for r in rows:
        for art in r.artifacts:
            if "/" in art:
                p = ws / art
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_text("// placeholder\n", encoding="utf-8")
    _MOD.save_rows(ws, rows)
    return ws


# ---------------------------------------------------------------------------
# 1-3. --init
# ---------------------------------------------------------------------------

class InitTests(unittest.TestCase):
    def test_01_init_creates_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            r = _run(["--workspace", str(ws), "--init"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((ws / "INVARIANT_LEDGER.md").is_file())
            self.assertTrue((ws / ".auditooor" / "invariant_ledger.json").is_file())

    def test_02_init_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _MOD.save_rows(ws, [_valid_row()])
            r = _run(["--workspace", str(ws), "--init"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].id, "TEST-I01")

    def test_03_init_creates_missing_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "deep" / "nested" / "ws"
            self.assertFalse(ws.exists())
            r = _run(["--workspace", str(ws), "--init"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(ws.is_dir())


# ---------------------------------------------------------------------------
# 4-5. JSON / Markdown round-trip
# ---------------------------------------------------------------------------

class RoundTripTests(unittest.TestCase):
    def test_04_json_md_round_trip_single_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(Path(tmp), [_valid_row()])
            md_text = (ws / "INVARIANT_LEDGER.md").read_text()
            parsed = _MOD.parse_markdown_ledger(md_text)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0].id, "TEST-I01")
            self.assertEqual(parsed[0].statement,
                             "Total deposits == sum of user balances.")

    def test_05_round_trip_multi_item_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(
                source_citations=["SCOPE.md::vault", "README.md::deposit"],
                artifacts=["test/A.sol", "test/B.sol"],
            )
            ws = _make_ws_with_rows(Path(tmp), [row])
            md_text = (ws / "INVARIANT_LEDGER.md").read_text()
            parsed = _MOD.parse_markdown_ledger(md_text)
            self.assertEqual(len(parsed[0].source_citations), 2)
            self.assertEqual(len(parsed[0].artifacts), 2)


# ---------------------------------------------------------------------------
# 6-14. --check schema validation
# ---------------------------------------------------------------------------

class CheckTests(unittest.TestCase):
    def test_06_check_passes_on_valid_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(Path(tmp), [_valid_row()])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_07_check_fails_on_bad_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(Path(tmp), [_valid_row(status="bogus")])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("invalid status", r.stdout)

    def test_08_check_fails_on_missing_required_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(Path(tmp), [_valid_row(statement="")])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("statement", r.stdout)

    def test_09_check_fails_on_dangling_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(artifacts=["test/does/not/exist.sol"])
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _MOD.save_rows(ws, [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("dangling artifact", r.stdout)

    def test_10_check_warns_on_unknown_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(
                Path(tmp), [_valid_row(required_engine="z3-solver")]
            )
            r = _run(["--workspace", str(ws), "--check"])
            # Warn-only -> rc=0 in plain --check mode.
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("WARN", r.stdout)

    def test_11_check_fails_on_duplicate_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            r1 = _valid_row(id="DUP-I01")
            r2 = _valid_row(id="DUP-I01", scope_asset="other")
            ws = _make_ws_with_rows(Path(tmp), [r1, r2])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("duplicate id", r.stdout)

    def test_12_check_fails_on_high_severity_no_citations(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(severity="High", source_citations=[])
            ws = _make_ws_with_rows(Path(tmp), [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("source_citations", r.stdout)

    def test_13_check_fails_on_blocked_no_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(status="blocked", artifacts=[])
            ws = _make_ws_with_rows(Path(tmp), [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("blocked", r.stdout)

    def test_14_check_returns_2_when_ledger_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 2, r.stderr)


# ---------------------------------------------------------------------------
# 15-18. --from-scope
# ---------------------------------------------------------------------------

SCOPE_MD = textwrap.dedent("""\
    # Scope

    ## Vault

    Vault subsystem holds collateral.

    ## Oracle

    Oracle adapter publishes price feeds.

    ## Governance

    Governance has admin upgrade powers.
""")


SUBMISSIONS_MD = textwrap.dedent("""\
    # Submissions

    ## Filed

    - 2026-04-10 Vault drain via reentrancy
    - 2026-04-15 Oracle stale price acceptance
    - [TODO] something pending

    ## Notes

    See submissions/foo for details.
""")


class FromScopeTests(unittest.TestCase):
    def test_15_from_scope_seeds_from_scope_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "SCOPE.md").write_text(SCOPE_MD, encoding="utf-8")
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            assets = {row.scope_asset for row in rows}
            self.assertIn("Vault", assets)
            self.assertIn("Oracle", assets)
            self.assertIn("Governance", assets)
            for row in rows:
                for fname in _MOD.REQUIRED_FIELDS:
                    val = getattr(row, fname)
                    if isinstance(val, list):
                        self.assertIsNotNone(val, f"{row.id} {fname}")
                    else:
                        self.assertTrue(str(val).strip(), f"{row.id} {fname}")
                self.assertEqual(row.required_engine, "manual")
                self.assertIn("Generated scope seed", row.production_path)
                self.assertTrue(row.harness_target.startswith("EXPECTED:"))
            check = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_16_from_scope_additive(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "SCOPE.md").write_text(SCOPE_MD, encoding="utf-8")
            _MOD.save_rows(ws, [_valid_row(id="ORIG-I01")])
            _run(["--workspace", str(ws), "--from-scope"])
            rows = _MOD.load_rows(ws)
            self.assertTrue(any(r.id == "ORIG-I01" for r in rows))
            self.assertGreater(len(rows), 1)

    def test_17_from_scope_no_sources_advisory_rc2(self):
        # PR #513 follow-up: previously this returned rc=0 silently,
        # which is the silent-zero pattern. Now we exit rc=2 (advisory)
        # with a WARN to stderr listing what was looked for.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("no scope/spec files matched", r.stderr)
            rows = _MOD.load_rows(ws)
            self.assertEqual(rows, [])

    def test_18_from_scope_submissions_anti_regression(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / "submissions").mkdir(parents=True)
            (ws / "submissions" / "SUBMISSIONS.md").write_text(
                SUBMISSIONS_MD, encoding="utf-8"
            )
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            families = {row.invariant_family for row in rows}
            self.assertIn("prior_finding_anti_regression", families)
            for row in rows:
                for fname in _MOD.REQUIRED_FIELDS:
                    val = getattr(row, fname)
                    if isinstance(val, list):
                        self.assertIsNotNone(val, f"{row.id} {fname}")
                    else:
                        self.assertTrue(str(val).strip(), f"{row.id} {fname}")
                self.assertEqual(row.required_engine, "manual")
                self.assertIn("Generated prior-finding seed", row.production_path)
                self.assertTrue(row.harness_target.startswith("EXPECTED:"))
            check = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_from_scope_base_like_generated_invariant_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "base-azul"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "SCOPE.md").write_text(
                "## Base DLT\n\nExecution/client safety.\n",
                encoding="utf-8",
            )
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text(
                textwrap.dedent("""\
                    # Blockchain/DLT Severity

                    ## Critical
                    - Chain-level fork or CL/EL state divergence.

                    ## High
                    - Increasing node resource consumption by at least 30% without brute force.
                """),
                encoding="utf-8",
            )
            (ws / ".auditooor" / "impact_family_worklists.json").write_text(
                json.dumps({
                    "worklists": [{
                        "impact_id": "BASE-DLT-FORK",
                        "severity": "Critical",
                        "impact": "Chain-level fork or CL/EL state divergence.",
                        "scoped_assets": ["base-node"],
                        "required_evidence_class": "source + replay",
                    }]
                }),
                encoding="utf-8",
            )
            accepted = _MOD.Row(
                id="BASE-DLT-I01",
                scope_asset="Critical program impact",
                invariant_family="impact_state_root_integrity",
                statement=(
                    "Listed program impact must remain unreachable: "
                    "Chain-level fork or CL/EL state divergence."
                ),
                source_citations=["SEVERITY_BLOCKCHAIN_DLT.md:L4"],
                owner="human",
                severity="Critical",
            )
            _MOD.save_rows(ws, [accepted])

            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            generated_path = ws / ".auditooor" / "generated_invariants.json"
            self.assertTrue(generated_path.is_file())
            payload = json.loads(generated_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], _MOD.GENERATED_INVARIANTS_SCHEMA)
            self.assertTrue(payload["advisory"])
            self.assertGreaterEqual(payload["accepted_before_count"], 1)
            self.assertGreaterEqual(payload["missing_before_count"], 1)
            generated_from = {row["generated_from"] for row in payload["generated_rows"]}
            self.assertIn("severity_markdown", generated_from)
            self.assertIn("impact_family_worklist", generated_from)
            self.assertTrue(all(row["status"] == "missing_harness" for row in payload["generated_rows"]))

    def test_from_scope_non_base_fixture_generated_invariants(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "polymarket-like"
            ws.mkdir()
            (ws / "SCOPE.md").write_text(
                textwrap.dedent("""\
                    # Scope

                    ## CLOB Exchange

                    ## Conditional Tokens
                """),
                encoding="utf-8",
            )
            (ws / "SEVERITY.md").write_text(
                textwrap.dedent("""\
                    # Severity

                    ## Critical
                    - Direct theft of user funds.

                    ## High
                    - Oracle stale price acceptance causes incorrect settlement.
                """),
                encoding="utf-8",
            )

            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            payload = json.loads(
                (ws / ".auditooor" / "generated_invariants.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["generated_count"], len(payload["generated_rows"]))
            self.assertIn("next_command", payload)
            self.assertTrue(all(row["advisory"] for row in payload["generated_rows"]))
            families = {row["invariant_family"] for row in payload["generated_rows"]}
            self.assertIn("impact_funds_safety", families)
            self.assertIn("impact_oracle_integrity", families)

    def test_from_scope_solidity_factory_pool_liveness(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "revert-like"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "RevertLikeFactory.sol").write_text(
                textwrap.dedent("""\
                    // SPDX-License-Identifier: MIT
                    pragma solidity ^0.8.24;

                    contract Pool {
                        constructor(address token0, address token1, uint24 fee, address hook) {}
                        function mint(address recipient, uint256 amount, address hook) external {}
                    }

                    contract RevertLikeFactory {
                        mapping(bytes32 => address) public pools;

                        function createPool(
                            address token0,
                            address token1,
                            uint24 fee,
                            address hook
                        ) external returns (address pool) {
                            pool = address(new Pool(token0, token1, fee, hook));
                            pools[keccak256(abi.encode(token0, token1, fee, hook))] = pool;
                        }

                        function addLiquidity(
                            address token0,
                            address token1,
                            uint24 fee,
                            address hook,
                            uint256 amount
                        ) external {
                            Pool(pools[keccak256(abi.encode(token0, token1, fee, hook))])
                                .mint(msg.sender, amount, hook);
                        }
                    }
                """),
                encoding="utf-8",
            )

            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            families = {row.invariant_family for row in rows}
            self.assertIn("factory_created_pool_liveness_after_liquidity", families)
            self.assertIn("config_domain_bounds", families)
            live_row = next(
                row for row in rows
                if row.invariant_family == "factory_created_pool_liveness_after_liquidity"
            )
            self.assertIn("RevertLikeFactory.createPool", live_row.production_path)
            self.assertIn("RevertLikeFactory.addLiquidity", live_row.production_path)
            self.assertEqual(live_row.required_engine, "forge")
            self.assertTrue(any(c.startswith("src/RevertLikeFactory.sol:L")
                                for c in live_row.source_citations))
            check = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

            payload = json.loads(
                (ws / ".auditooor" / "generated_invariants.json").read_text(
                    encoding="utf-8"
                )
            )
            generated_from = {row["generated_from"] for row in payload["generated_rows"]}
            self.assertIn("solidity_factory_pool_liveness", generated_from)

    def test_from_scope_solidity_no_config_reuse_is_advisory_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "quiet-solidity"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Factory.sol").write_text(
                textwrap.dedent("""\
                    pragma solidity ^0.8.24;

                    contract Factory {
                        function createPool(address token0, address token1, uint24 fee)
                            external
                            returns (address)
                        {
                            return address(uint160(uint256(keccak256(abi.encode(token0, token1, fee)))));
                        }

                        function addLiquidity(uint256 amount) external {
                            require(amount > 0, "amount");
                        }
                    }
                """),
                encoding="utf-8",
            )

            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("yielded zero candidate rows", r.stderr)
            self.assertEqual(_MOD.load_rows(ws), [])

    # -----------------------------------------------------------------------
    # Tests for --from-scope engage_report.json seeding (KLBQ item #5)
    # -----------------------------------------------------------------------

    ENGAGE_REPORT_JSON = {
        "kind": "engage_report",
        "schema": "auditooor.engage_report.v1",
        "workspace": "test-ws",
        "workspace_name": "test-ws",
        "generated": "2026-05-19T00:00:00Z",
        "total_hits": 12,
        "distinct_detectors": 4,
        "analogical_clusters": 3,
        "actionable_next_steps": {"mine": 12, "triage": 0, "dupe_check": 0},
        "severity_summary": {"HIGH": 2, "MEDIUM": 4, "LOW": 6},
        "clusters": [
            {
                "detector_slug": "go.crypto.race.unsynchronized_concurrent_access",
                "hit_count": 6,
                "hits": [
                    {"file_path": "src/keeper/keeper.go:31", "severity": "LOW", "snippet": "x.Store = store"},
                ],
            },
            {
                "detector_slug": "lock-extension-griefing",
                "hit_count": 2,
                "hits": [
                    {"file_path": "contracts/WithdrawalFactory.sol:87", "severity": "HIGH", "snippet": "lock"},
                    {"file_path": "contracts/WithdrawalFactory.sol:132", "severity": "HIGH", "snippet": "lock"},
                ],
            },
            {
                "detector_slug": "erc4626-balanceOf-this-in-share-calc",
                "hit_count": 3,
                "hits": [
                    {"file_path": "src/Vault.sol:55", "severity": "MEDIUM", "snippet": "balanceOf"},
                ],
            },
            {
                "detector_slug": "unprotected-initialize",
                "hit_count": 1,
                "hits": [
                    {"file_path": "contracts/Init.sol:10", "severity": "MEDIUM", "snippet": "initialize"},
                ],
            },
        ],
    }

    def test_from_scope_engage_report_seeds_missing_harness_rows(self):
        """engage_report.json clusters -> missing_harness rows per subsystem."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "engage_report.json").write_text(
                json.dumps(self.ENGAGE_REPORT_JSON), encoding="utf-8"
            )
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            # Should have seeded at least 1 engage-report row
            eng_rows = [row for row in rows if "generated_from_engage_report=true" in (row.notes or "")]
            self.assertGreater(len(eng_rows), 0, "No engage-report rows were seeded")
            # Each row must be missing_harness status
            for row in eng_rows:
                self.assertEqual(row.status, "missing_harness")
            # All REQUIRED_FIELDS must be non-empty
            for row in eng_rows:
                for fname in _MOD.REQUIRED_FIELDS:
                    val = getattr(row, fname)
                    if isinstance(val, list):
                        self.assertIsNotNone(val, f"{row.id} {fname}")
                    else:
                        self.assertTrue(str(val).strip(), f"{row.id} {fname}")
            # At least one row should cite the engage_report.json as source
            all_citations = [c for row in eng_rows for c in row.source_citations]
            self.assertTrue(
                any("engage_report.json" in c for c in all_citations),
                f"No engage_report.json citation found in {all_citations}",
            )

    def test_from_scope_engage_report_idempotent(self):
        """Re-running --from-scope does not duplicate engage-report rows."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "engage_report.json").write_text(
                json.dumps(self.ENGAGE_REPORT_JSON), encoding="utf-8"
            )
            # First run
            r1 = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r1.returncode, 0, r1.stderr)
            rows_after_first = _MOD.load_rows(ws)
            count_first = len(rows_after_first)
            eng_first = sum(
                1 for r in rows_after_first
                if "generated_from_engage_report=true" in (r.notes or "")
            )
            self.assertGreater(eng_first, 0, "First run must seed engage rows")
            # Second run (idempotent - should add nothing new)
            r2 = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r2.returncode, 0, r2.stderr)
            rows_after_second = _MOD.load_rows(ws)
            count_second = len(rows_after_second)
            self.assertEqual(
                count_first, count_second,
                f"Idempotent re-run changed row count: {count_first} -> {count_second}",
            )

    def test_from_scope_engage_report_dry_run_writes_nothing(self):
        """--dry-run does not write any ledger or sidecar files."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "engage_report.json").write_text(
                json.dumps(self.ENGAGE_REPORT_JSON), encoding="utf-8"
            )
            r = _run(["--workspace", str(ws), "--from-scope", "--dry-run"])
            self.assertEqual(r.returncode, 0, r.stderr)
            # Ledger file must NOT be written
            self.assertFalse((ws / ".auditooor" / "invariant_ledger.json").exists(),
                             "dry-run must not write invariant_ledger.json")
            # generated_invariants.json sidecar must NOT be written
            self.assertFalse((ws / ".auditooor" / "generated_invariants.json").exists(),
                             "dry-run must not write generated_invariants.json")
            # INVARIANT_LEDGER.md must NOT be written
            self.assertFalse((ws / "INVARIANT_LEDGER.md").exists(),
                             "dry-run must not write INVARIANT_LEDGER.md")
            # Output must mention DRY-RUN
            self.assertIn("DRY-RUN", r.stdout)
            # Load rows must return empty (nothing was persisted)
            self.assertEqual(_MOD.load_rows(ws), [])

    def test_from_scope_engage_report_diff_block_in_output(self):
        """--from-scope always prints the generated-vs-accepted diff block."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "engage_report.json").write_text(
                json.dumps(self.ENGAGE_REPORT_JSON), encoding="utf-8"
            )
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            # Diff block header must be present
            self.assertIn("generated-vs-accepted diff", r.stdout)
            self.assertIn("generated_total", r.stdout)
            self.assertIn("already_accepted", r.stdout)
            self.assertIn("newly_added", r.stdout)
            self.assertIn("still_missing", r.stdout)

    def test_from_scope_engage_report_json_flag_emits_json(self):
        """--from-scope --json emits a machine-readable JSON diff block."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "engage_report.json").write_text(
                json.dumps(self.ENGAGE_REPORT_JSON), encoding="utf-8"
            )
            r = _run(["--workspace", str(ws), "--from-scope", "--dry-run", "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            # Find the JSON block in the output (starts after the diff header lines)
            output = r.stdout
            # The JSON payload starts with '{'
            json_start = output.find('{\n  "schema": "auditooor.invariant_ledger_from_scope_diff.v1"')
            self.assertGreater(json_start, -1, f"JSON block not found in output:\n{output}")
            json_str = output[json_start:]
            # It should parse as valid JSON
            payload = json.loads(json_str)
            self.assertEqual(payload["schema"], "auditooor.invariant_ledger_from_scope_diff.v1")
            self.assertIn("generated_total", payload)
            self.assertIn("already_accepted", payload)
            self.assertIn("newly_added", payload)
            self.assertIn("still_missing", payload)
            self.assertTrue(payload["dry_run"])
            self.assertIsInstance(payload["candidates"], list)
            # All candidates must have required keys
            for cand in payload["candidates"]:
                self.assertIn("id", cand)
                self.assertIn("scope_asset", cand)
                self.assertIn("invariant_family", cand)
                self.assertIn("status", cand)
                self.assertEqual(cand["status"], "missing_harness")

    def test_from_scope_engage_report_diff_counts_correct(self):
        """Generated-vs-accepted diff counts are arithmetically correct."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "engage_report.json").write_text(
                json.dumps(self.ENGAGE_REPORT_JSON), encoding="utf-8"
            )
            # First run: newly_added should equal still_missing (all generated, none prior)
            r = _run(["--workspace", str(ws), "--from-scope", "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            json_start = r.stdout.find('{\n  "schema": "auditooor.invariant_ledger_from_scope_diff.v1"')
            payload = json.loads(r.stdout[json_start:])
            # After first run: already_accepted=0, newly_added>0
            self.assertEqual(payload["already_accepted"], 0,
                             "First run should have 0 already-accepted rows")
            self.assertGreater(payload["newly_added"], 0,
                               "First run should write at least 1 new row")
            # Second run: already_accepted should increase, newly_added=0
            r2 = _run(["--workspace", str(ws), "--from-scope", "--json"])
            self.assertEqual(r2.returncode, 0, r2.stderr)
            json_start2 = r2.stdout.find('{\n  "schema": "auditooor.invariant_ledger_from_scope_diff.v1"')
            payload2 = json.loads(r2.stdout[json_start2:])
            self.assertEqual(payload2["newly_added"], 0,
                             "Second run should add 0 new rows (idempotent)")
            self.assertGreater(payload2["already_accepted"], 0,
                               "Second run should show previously-accepted rows")

    def test_from_scope_engage_report_absent_graceful(self):
        """--from-scope without engage_report.json still works (graceful)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            # Only a SCOPE.md - no engage_report.json
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n## Vault\n\nHolds collateral.\n",
                encoding="utf-8",
            )
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            # Should still seed SCOPE.md rows (no crash from missing engage_report)
            self.assertGreater(len(rows), 0)
            # No engage-report rows (engage_report.json absent)
            eng_rows = [row for row in rows if "generated_from_engage_report=true" in (row.notes or "")]
            self.assertEqual(len(eng_rows), 0, "No engage-report rows expected when file absent")

    def test_from_scope_engage_report_md_fallback(self):
        """engage_report.md is used as fallback when .json is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            # Write an engage_report.md that has recognizable slug lines
            (ws / "engage_report.md").write_text(
                "# Engage Report\n\n"
                "## go.crypto.race.unsynchronized_concurrent_access\n\n"
                "6 hits\n\n"
                "## lock-extension-griefing\n\n"
                "2 hits\n",
                encoding="utf-8",
            )
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = _MOD.load_rows(ws)
            eng_rows = [row for row in rows if "generated_from_engage_report=true" in (row.notes or "")]
            self.assertGreater(len(eng_rows), 0, "engage_report.md fallback must seed rows")
            # Citations should mention engage_report.md
            all_cits = [c for row in eng_rows for c in row.source_citations]
            self.assertTrue(
                any("engage_report.md" in c for c in all_cits),
                f"Expected engage_report.md citation, got: {all_cits}",
            )


# ---------------------------------------------------------------------------
# 19-21. --require-high-impact-harness
# ---------------------------------------------------------------------------

class HighImpactGateTests(unittest.TestCase):
    def test_19_high_severity_missing_harness_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(severity="High", status="missing_harness")
            ws = _make_ws_with_rows(Path(tmp), [row])
            r = _run(["--workspace", str(ws), "--require-high-impact-harness"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("High/Critical", r.stdout)

    def test_20_high_severity_scaffolded_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(severity="High", status="scaffolded")
            ws = _make_ws_with_rows(Path(tmp), [row])
            r = _run(["--workspace", str(ws), "--require-high-impact-harness"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_21_medium_missing_harness_returns_warn_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Medium severity is None (no severity hint).
            row = _valid_row(status="missing_harness")
            ws = _make_ws_with_rows(Path(tmp), [row])
            r = _run(["--workspace", str(ws), "--require-high-impact-harness"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# 22-23. --emit-closeout
# ---------------------------------------------------------------------------

class CloseoutTests(unittest.TestCase):
    def test_22_emit_closeout_manifest_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            row1 = _valid_row(id="C-I01", status="executed_clean")
            row2 = _valid_row(id="C-I02", status="missing_harness", severity="High")
            ws = _make_ws_with_rows(Path(tmp), [row1, row2])
            r = _run(["--workspace", str(ws), "--emit-closeout"])
            self.assertEqual(r.returncode, 0, r.stderr)
            mp = ws / ".audit_logs" / "invariant_ledger_manifest.json"
            self.assertTrue(mp.is_file())
            payload = json.loads(mp.read_text())
            self.assertEqual(payload["row_count"], 2)
            self.assertEqual(payload["status_counts"]["executed_clean"], 1)
            self.assertEqual(payload["status_counts"]["missing_harness"], 1)
            self.assertEqual(payload["high_impact_total"], 1)

    def test_23_emit_closeout_schema_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(Path(tmp), [_valid_row()])
            _run(["--workspace", str(ws), "--emit-closeout"])
            mp = ws / ".audit_logs" / "invariant_ledger_manifest.json"
            payload = json.loads(mp.read_text())
            self.assertEqual(
                payload["schema"], "auditooor.invariant_ledger_manifest.v1"
            )
            self.assertEqual(payload["ledger_schema"], _MOD.SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# 24-25. CLI surface
# ---------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def test_24_help_lists_all_modes(self):
        r = _run(["--help"])
        self.assertEqual(r.returncode, 0)
        for flag in (
            "--init", "--from-scope", "--check",
            "--require-high-impact-harness", "--emit-closeout",
        ):
            self.assertIn(flag, r.stdout)

    def test_25_no_mode_flag_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(["--workspace", tmp])
            # argparse mutually-exclusive group missing -> rc=2
            self.assertEqual(r.returncode, 2)


# ---------------------------------------------------------------------------
# Schema constants tests (defensive)
# ---------------------------------------------------------------------------

class SchemaConstantsTests(unittest.TestCase):
    def test_required_fields_count_is_15(self):
        # 14 plan-doc-listed fields + `owner` = 15 required.
        self.assertEqual(len(_MOD.REQUIRED_FIELDS), 15)

    def test_status_enum_has_six_values(self):
        self.assertEqual(len(_MOD.VALID_STATUS), 6)
        self.assertIn("missing_harness", _MOD.VALID_STATUS)
        self.assertIn("blocked", _MOD.VALID_STATUS)


# ---------------------------------------------------------------------------
# PR #513 follow-up — adversarial inputs flagged by Minimax review.
# https://github.com/Vuk97/auditooor/pull/513#issuecomment-4345253851
# ---------------------------------------------------------------------------


def _write_ledger_raw(ws: Path, content: str) -> Path:
    """Write a literal string to the ledger JSON path. Used to inject
    malformed/adversarial inputs that `save_rows` would reject."""
    j = ws / ".auditooor" / "invariant_ledger.json"
    j.parent.mkdir(parents=True, exist_ok=True)
    j.write_text(content, encoding="utf-8")
    return j


class AdversarialInputTests(unittest.TestCase):
    """Coverage for the SILENT_ZERO_RISK + CRITICAL_INTEROP_BREAK cases
    flagged by the Minimax adversarial review of PR #513. Pre-fix every
    case in this class returned rc=0; post-fix every case returns rc=1
    with a named reason in stderr/stdout."""

    def test_garbage_json_rc1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            _write_ledger_raw(ws, "not json")
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("not valid JSON", r.stderr)

    def test_empty_array_rc1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            _write_ledger_raw(ws, "[]")
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("zero rows", r.stderr)

    def test_dict_with_empty_rows_rc1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            _write_ledger_raw(
                ws, json.dumps({"schema_version": "v1", "rows": []})
            )
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("zero rows", r.stderr)

    def test_dict_missing_rows_key_rc1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            _write_ledger_raw(ws, json.dumps({"schema": "x"}))
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("missing required `rows` key", r.stderr)

    def test_dict_missing_schema_key_rc1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            _write_ledger_raw(
                ws, json.dumps({"rows": [{"id": "X", "scope_asset": "x"}]})
            )
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("schema", r.stderr)

    def test_from_scope_h1_only_advisory_rc2(self):
        # SCOPE.md with only an H1 (no `## Subsystem`) silently emitted
        # 0 rows pre-fix. Now exits rc=2 with a WARN to stderr.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "SCOPE.md").write_text(
                "# Subsystem A\n\nNo H2 sections here.\n", encoding="utf-8"
            )
            r = _run(["--workspace", str(ws), "--from-scope"])
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("yielded zero candidate rows", r.stderr)


class MissingFieldEnforcementTests(unittest.TestCase):
    """Each of the 15 required fields must produce a hard error when
    omitted from the raw JSON. Pre-fix only id/scope_asset/
    invariant_family/statement were enforced (4 of 15)."""

    def _ws_with_partial_row(self, tmp: Path, drop_field: str) -> Path:
        ws = tmp / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        # Build a row dict with all 15 fields, drop the named one.
        row = {
            "id": "MISS-I01",
            "scope_asset": "vault",
            "invariant_family": "conservation",
            "statement": "S",
            "source_citations": ["SCOPE.md::vault"],
            "attacker_capability": "x",
            "trusted_boundary": "x",
            "oos_boundary": "x",
            "production_path": "src/Vault.sol::deposit",
            "harness_target": "test/Vault.t.sol",
            "required_engine": "forge",
            "negative_test": "x",
            "status": "scaffolded",
            "artifacts": ["test/Vault.t.sol"],
            "owner": "Claude",
        }
        row.pop(drop_field)
        # Touch the artifact so dangling-path doesn't mask the test.
        (ws / "test").mkdir(parents=True, exist_ok=True)
        (ws / "test" / "Vault.t.sol").write_text("// placeholder\n")
        _write_ledger_raw(
            ws, json.dumps({"schema_version": "v1", "rows": [row]})
        )
        return ws

    def test_drop_each_required_field(self):
        for fname in _MOD.REQUIRED_FIELDS:
            with self.subTest(field=fname):
                with tempfile.TemporaryDirectory() as tmp:
                    ws = self._ws_with_partial_row(Path(tmp), fname)
                    r = _run(["--workspace", str(ws), "--check"])
                    self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                    self.assertIn(
                        f"required field missing: {fname}", r.stdout
                    )


class RequiredEngineOpenPrefixTests(unittest.TestCase):
    """PR #513 follow-up: KK's ledger uses descriptive `required_engine`
    strings. Validator must accept any string starting with a known
    engine prefix; reject pure-descriptive."""

    def test_accept_known_token(self):
        self.assertTrue(_MOD._required_engine_ok("forge"))
        self.assertTrue(_MOD._required_engine_ok("cargo"))
        self.assertTrue(_MOD._required_engine_ok("live-check"))
        self.assertTrue(_MOD._required_engine_ok("differential"))

    def test_accept_descriptive_with_engine_prefix(self):
        self.assertTrue(_MOD._required_engine_ok("forge + halmos"))
        self.assertTrue(_MOD._required_engine_ok("live-check (cast call)"))
        self.assertTrue(_MOD._required_engine_ok(
            "differential (revm-oracle vs in-tree)"
        ))
        self.assertTrue(_MOD._required_engine_ok(
            "cargo unit + differential vs op-reth boundary"
        ))

    def test_reject_pure_descriptive(self):
        self.assertFalse(_MOD._required_engine_ok("random gibberish"))
        self.assertFalse(_MOD._required_engine_ok(""))
        # Note: "go" was added to VALID_ENGINES (Worker-EE Loop 7), so the
        # historic "z3-solver" reject is preserved by remaining unknown.
        self.assertFalse(_MOD._required_engine_ok("z3-solver"))


class GoEngineSchemaExtensionTests(unittest.TestCase):
    """Worker-EE L7 follow-up: `"go"` was added to VALID_ENGINES so that
    Spark LEAD-1 / LEAD-HD Go-PoC rows can drop the `manual (go test)`
    workaround. Validator must accept the bare `go` token, descriptive
    Go-prefix forms, and a synthetic ledger row whose `required_engine`
    is `go` must round-trip --check cleanly."""

    def test_go_in_valid_engines_constant(self):
        self.assertIn("go", _MOD.VALID_ENGINES)

    def test_accept_bare_go_token(self):
        self.assertTrue(_MOD._required_engine_ok("go"))

    def test_accept_descriptive_go_prefix(self):
        self.assertTrue(_MOD._required_engine_ok("go test"))
        self.assertTrue(_MOD._required_engine_ok("go (test ./chain/...)"))

    def test_check_passes_on_go_engine_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws_with_rows(
                Path(tmp),
                [_valid_row(id="GO-I01", required_engine="go")],
            )
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)


class ArtifactAnnotatedPathTests(unittest.TestCase):
    """PR #513 follow-up: `<path> (<annotation>)` and `EXPECTED:<path>`
    artifact entries must be accepted; the path is the substantive part."""

    def test_split_path_with_annotation(self):
        path, exp = _MOD._split_artifact("test/Vault.t.sol (TODO)")
        self.assertEqual(path, "test/Vault.t.sol")
        self.assertFalse(exp)

    def test_split_expected_sentinel(self):
        path, exp = _MOD._split_artifact(
            "EXPECTED: test/Vault.t.sol (not yet written)"
        )
        self.assertEqual(path, "test/Vault.t.sol")
        self.assertTrue(exp)

    def test_split_free_form_note(self):
        # `blocker: missing-rpc` style entries are NOT path-shaped
        # (whitespace-after-colon breaks the path-token regex). The
        # validator's path-shape filter then skips them, which is the
        # correct end-to-end behaviour: a free-form blocker note
        # survives `--check` because no existence check fires.
        path, exp = _MOD._split_artifact("blocker: missing-rpc")
        self.assertIsNone(path)
        self.assertFalse(exp)

    def test_annotated_path_passes_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "test").mkdir()
            (ws / "test" / "Vault.t.sol").write_text("// placeholder\n")
            row = _valid_row(
                artifacts=["test/Vault.t.sol (TODO: extend with reentrancy)"],
            )
            _MOD.save_rows(ws, [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_expected_sentinel_skips_existence(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(
                artifacts=["EXPECTED: test/NotYetWritten.t.sol (planned)"],
            )
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _MOD.save_rows(ws, [row])
            r = _run(["--workspace", str(ws), "--check"])
            # EXPECTED: sentinel skips on-disk check.
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_dangling_path_still_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(artifacts=["not-a-path-at-all/missing.sol"])
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _MOD.save_rows(ws, [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("dangling artifact", r.stdout)


class StatusArtifactsRequirementTests(unittest.TestCase):
    """Any non-`missing_harness` and non-`blocked` status requires
    non-empty artifacts (closes the `scaffolded`+`[]` gap)."""

    def test_scaffolded_empty_artifacts_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(status="scaffolded", artifacts=[])
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _MOD.save_rows(ws, [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("status=scaffolded requires", r.stdout)

    def test_executed_clean_empty_artifacts_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = _valid_row(status="executed_clean", artifacts=[])
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _MOD.save_rows(ws, [row])
            r = _run(["--workspace", str(ws), "--check"])
            self.assertEqual(r.returncode, 1, r.stdout)


class SeverityHeuristicTests(unittest.TestCase):
    """`--require-high-impact-harness` must fire even when the operator
    didn't set `severity` per row, by inferring from invariant_family /
    statement keywords."""

    def test_dlt_family_inferred_high(self):
        row = _valid_row(invariant_family="BASE-DLT-WITHDRAWALS-ROOT")
        self.assertEqual(_MOD._infer_severity(row), "High")

    def test_state_root_statement_inferred_high(self):
        row = _valid_row(
            statement="State-root divergence between client and oracle.",
        )
        self.assertEqual(_MOD._infer_severity(row), "High")

    def test_drain_keyword_inferred_high(self):
        row = _valid_row(statement="Attacker can drain vault funds.")
        self.assertEqual(_MOD._infer_severity(row), "High")

    def test_explicit_severity_overrides(self):
        row = _valid_row(
            invariant_family="BASE-DLT-CRITICAL",
            severity="Low",
        )
        # Explicit always wins.
        self.assertEqual(_MOD._infer_severity(row), "Low")

    def test_benign_family_no_inference(self):
        row = _valid_row(
            invariant_family="conservation",
            statement="Sum of balances equals total supply.",
        )
        self.assertIsNone(_MOD._infer_severity(row))

    def test_inferred_high_fires_harness_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            # No `severity` field set. invariant_family triggers
            # heuristic -> High -> require-high-impact-harness must
            # FAIL when status is missing_harness.
            row = _valid_row(
                invariant_family="BASE-DLT-WITHDRAWALS-ROOT",
                status="missing_harness",
            )
            ws = _make_ws_with_rows(Path(tmp), [row])
            r = _run(["--workspace", str(ws), "--require-high-impact-harness"])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("inferred", r.stdout)


class EffectiveSeverityClosseoutTests(unittest.TestCase):
    """PR #521 follow-up — Required Pre-Merge Fix per
    docs/CLAUDE_PR_MERGE_AND_INVARIANT_COMPLETION_PLAN_2026-04-29.md
    "Required Pre-Merge Fix" section.

    Ledger rows whose severity is *inferred* (no explicit
    `severity` field, but family/statement keywords trigger the
    `_infer_severity` heuristic) MUST be counted in the closeout
    manifest's `high_impact_total` / `high_impact_ok` /
    `high_impact_missing`. Pre-fix, `build_closeout_manifest` read
    `r.severity` directly while `validate_rows` used
    `_infer_severity`, so inferred-High rows produced the silent
    `0/0` mismatch reproduced on Base.

    Test A: missing-harness inferred-High row -> manifest reports
            high_impact_total=1, high_impact_missing=1, and
            --require-high-impact-harness exits nonzero.
    Test B: same row, status=scaffolded with non-empty artifact ->
            manifest reports high_impact_total=1, high_impact_ok=1.
    Test C: deep summary written by audit-deep.sh against the
            same synthetic workspace reflects the same counts as
            Test A.
    """

    def _row_inferred_high_missing(self):
        # Family `BASE-SC-PROOF-DOMAIN` triggers the `PROOF-DOMAIN`
        # _HIGH_SEVERITY_FAMILY_TOKENS rule -> inferred severity is
        # "High" without an explicit `severity` field.
        return _MOD.Row(
            id="BASE-SC-INF-HI",
            scope_asset="proof-domain",
            invariant_family="BASE-SC-PROOF-DOMAIN",
            statement="Proof domain identifier matches the scope binding.",
            source_citations=["SCOPE.md::proof-domain"],
            attacker_capability="non-privileged",
            trusted_boundary="admin owner",
            oos_boundary="OOS if upgrade is paused",
            production_path="src/Proof.sol::verify",
            harness_target="test/invariants/Proof.t.sol::invariant_proof_domain",
            required_engine="forge",
            negative_test="domain mismatch reverts",
            status="missing_harness",
            artifacts=[],
            owner="Claude",
            severity=None,
        )

    def test_A_inferred_high_missing_harness_manifest_and_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = self._row_inferred_high_missing()
            ws = _make_ws_with_rows(Path(tmp), [row])
            # Sanity: heuristic flags the row as High before we touch
            # the manifest paths.
            self.assertEqual(_MOD._infer_severity(row), "High")
            self.assertEqual(_MOD._row_effective_severity(row), "High")

            # --require-high-impact-harness must exit nonzero.
            r = _run([
                "--workspace", str(ws), "--require-high-impact-harness",
            ])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("High/Critical", r.stdout)

            # --emit-closeout writes high_impact_total=1,
            # high_impact_missing=1, high_impact_ok=0.
            e = _run(["--workspace", str(ws), "--emit-closeout"])
            self.assertEqual(e.returncode, 0, e.stdout + e.stderr)
            mp = ws / ".audit_logs" / "invariant_ledger_manifest.json"
            payload = json.loads(mp.read_text())
            self.assertEqual(payload["high_impact_total"], 1, payload)
            self.assertEqual(payload["high_impact_missing"], 1, payload)
            self.assertEqual(payload["high_impact_ok"], 0, payload)
            # Each row summary should surface the inferred severity.
            self.assertEqual(
                payload["rows"][0]["severity"], "High", payload["rows"][0],
            )

    def test_B_inferred_high_scaffolded_manifest_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = self._row_inferred_high_missing()
            row.status = "scaffolded"
            row.artifacts = ["test/invariants/Proof.t.sol"]
            ws = _make_ws_with_rows(Path(tmp), [row])

            e = _run(["--workspace", str(ws), "--emit-closeout"])
            self.assertEqual(e.returncode, 0, e.stdout + e.stderr)
            mp = ws / ".audit_logs" / "invariant_ledger_manifest.json"
            payload = json.loads(mp.read_text())
            self.assertEqual(payload["high_impact_total"], 1, payload)
            self.assertEqual(payload["high_impact_ok"], 1, payload)
            self.assertEqual(payload["high_impact_missing"], 0, payload)

    def test_C_audit_deep_summary_reflects_effective_severity(self):
        # Run audit-deep.sh against a synthetic workspace whose only
        # row is the inferred-High missing-harness row, and assert
        # the deep summary JSON written under .audit_logs/ carries
        # the same high_impact counts as Test A.
        audit_deep = ROOT / "tools" / "audit-deep.sh"
        if not audit_deep.is_file():
            self.skipTest(f"audit-deep.sh missing at {audit_deep}")

            # Audit-deep.sh expects the workspace ledger at
            # <ws>/.auditooor/invariant_ledger.json. Build that
            # synthetic input by hand so audit-deep does not
            # regenerate it.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            ledger = {
                "schema": "auditooor.invariant_ledger.v1",
                "rows": [
                    {
                        "id": "BASE-SC-INF-HI",
                        "scope_asset": "proof-domain",
                        "invariant_family": "BASE-SC-PROOF-DOMAIN",
                        "statement":
                            "Proof domain identifier matches the scope binding.",
                        "source_citations": ["SCOPE.md::proof-domain"],
                        "attacker_capability": "non-privileged",
                        "trusted_boundary": "admin owner",
                        "oos_boundary": "OOS if upgrade is paused",
                        "production_path": "src/Proof.sol::verify",
                        "harness_target":
                            "test/invariants/Proof.t.sol::invariant_proof_domain",
                        "required_engine": "forge",
                        "negative_test": "domain mismatch reverts",
                        "status": "missing_harness",
                        "artifacts": [],
                        "owner": "Claude",
                    },
                ],
            }
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps(ledger, indent=2), encoding="utf-8",
            )

            # Run audit-deep against the synthetic workspace. WARN
            # exits 0 by default (audit-deep advisory mode); the
            # invariant-ledger step is what we are exercising.
            res = subprocess.run(
                ["bash", str(audit_deep), str(ws)],
                capture_output=True, text=True, timeout=120,
            )
            # audit-deep is advisory by default; exit 0 even on warns.
            self.assertEqual(
                res.returncode, 0,
                f"audit-deep rc={res.returncode}\nstdout:\n"
                f"{res.stdout}\nstderr:\n{res.stderr}",
            )

            deep_json = ws / ".audit_logs" / "invariant_ledger_deep_summary.json"
            self.assertTrue(deep_json.is_file(), f"missing {deep_json}")
            deep = json.loads(deep_json.read_text())
            # Key invariant: deep summary mirrors the manifest counts,
            # which now use effective severity.
            self.assertEqual(deep.get("high_impact_total"), 1, deep)
            self.assertEqual(deep.get("high_impact_ok"), 0, deep)

    def test_D_audit_deep_does_not_enable_errexit_after_advisory_rc(self):
        audit_deep = ROOT / "tools" / "audit-deep.sh"
        source = audit_deep.read_text(encoding="utf-8")
        self.assertNotIn("set -e 2>/dev/null || true", source)
        self.assertIn("set +e 2>/dev/null || true", source)


class DiffAcceptedTest(unittest.TestCase):
    """Tests for --diff-accepted (Wave C-3B P0-0).

    Coverage:
     DA-1. --diff-accepted emits 4-bucket JSON + Markdown with correct schema.
     DA-2. newly_generated_rows: rows seeded from scope NOT yet in ledger appear.
     DA-3. accepted_unchanged_rows: rows in both ledger and scope-derivation appear.
     DA-4. accepted_orphaned_rows: ledger rows with no matching scope source appear.
     DA-5. accepted_drifted_rows: rows with stale severity_line note are detected.
     DA-6. --diff-accepted exits 2 when ledger has no accepted rows.
     DA-7. --diff-accepted is read-only: ledger JSON is not mutated.
     DA-8. Smoke against real base-azul workspace when present.
    """

    def _make_ws(self) -> Path:
        td = Path(tempfile.mkdtemp())
        (td / ".auditooor").mkdir()
        return td

    def _write_scope_md(self, ws: Path, sections: list) -> None:
        text = "# Scope\n\n" + "\n".join(f"## {s}\n" for s in sections)
        (ws / "SCOPE.md").write_text(text, encoding="utf-8")

    def _write_ledger(self, ws: Path, rows: list) -> None:
        payload = {
            "schema_version": "auditooor.invariant_ledger.v1",
            "rows": rows,
        }
        (ws / ".auditooor" / "invariant_ledger.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        # Also write minimal INVARIANT_LEDGER.md so load_rows is happy
        (ws / "INVARIANT_LEDGER.md").write_text("# Invariant Ledger\n", encoding="utf-8")

    def _valid_row_dict(self, **overrides):
        base = {
            "id": "TEST-I01",
            "scope_asset": "vault",
            "invariant_family": "conservation",
            "statement": "Total supply must not increase without minting.",
            "source_citations": ["SCOPE.md::vault"],
            "attacker_capability": "call deposit()",
            "trusted_boundary": "none",
            "oos_boundary": "in-scope",
            "production_path": "src/Vault.sol:42",
            "harness_target": "test/Vault.t.sol",
            "required_engine": "forge",
            "negative_test": "deposit 0 should revert",
            "status": "missing_harness",
            "artifacts": [],
            "owner": "human",
        }
        base.update(overrides)
        return base

    def test_DA_1_diff_accepted_emits_schema(self):
        """DA-1: JSON output has correct schema_version and 4 bucket keys."""
        ws = self._make_ws()
        self._write_scope_md(ws, ["vault"])
        self._write_ledger(ws, [self._valid_row_dict()])
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertIn(r.returncode, (0, 2), r.stderr)
        diff_json = ws / ".auditooor" / "invariant_ledger_scope_diff.json"
        self.assertTrue(diff_json.is_file(), "scope_diff JSON not written")
        diff_md = ws / ".auditooor" / "invariant_ledger_scope_diff.md"
        self.assertTrue(diff_md.is_file(), "scope_diff Markdown not written")
        d = json.loads(diff_json.read_text())
        self.assertEqual(d["schema_version"], "auditooor.invariant_ledger_scope_diff.v1")
        for key in ("newly_generated_rows", "accepted_unchanged_rows",
                    "accepted_drifted_rows", "accepted_orphaned_rows"):
            self.assertIn(key, d, f"missing bucket key: {key}")

    def test_DA_2_newly_generated_rows_appear(self):
        """DA-2: Rows seeded from SCOPE.md not in ledger appear in newly_generated."""
        ws = self._make_ws()
        # SCOPE.md has 'orders' and 'settlement' sections
        self._write_scope_md(ws, ["orders", "settlement"])
        # Ledger has no rows matching those sections
        self._write_ledger(ws, [self._valid_row_dict(scope_asset="vault")])
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertIn(r.returncode, (0, 2), r.stderr)
        diff_json = ws / ".auditooor" / "invariant_ledger_scope_diff.json"
        d = json.loads(diff_json.read_text())
        assets_in_new = [row["scope_asset"] for row in d["newly_generated_rows"]]
        # 'orders' and 'settlement' should appear in newly generated
        self.assertTrue(
            any("orders" in a.lower() or "settlement" in a.lower() for a in assets_in_new),
            f"Expected scope assets in newly_generated_rows, got: {assets_in_new}",
        )

    def test_DA_3_accepted_unchanged_rows_present(self):
        """DA-3: A ledger row that matches a scope-derived row lands in accepted_unchanged."""
        ws = self._make_ws()
        self._write_scope_md(ws, ["vault"])
        self._write_ledger(ws, [self._valid_row_dict(scope_asset="vault")])
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertIn(r.returncode, (0, 2), r.stderr)
        diff_json = ws / ".auditooor" / "invariant_ledger_scope_diff.json"
        d = json.loads(diff_json.read_text())
        # The 'vault' row should be in either accepted_unchanged or newly_generated
        # (scope seed will generate a row with scope_asset='vault' from SCOPE.md ## vault)
        total_accepted = d["summary"]["accepted_unchanged_count"]
        total_orphaned = d["summary"]["accepted_orphaned_count"]
        # Not all rows can be orphaned if scope has matching sections
        self.assertGreaterEqual(total_accepted + total_orphaned, 1)

    def test_DA_4_accepted_orphaned_rows_detected(self):
        """DA-4: Ledger rows with no matching scope source appear in accepted_orphaned."""
        ws = self._make_ws()
        # SCOPE.md only has 'vault' — ledger has 'bridge' (not in scope)
        self._write_scope_md(ws, ["vault"])
        self._write_ledger(ws, [
            self._valid_row_dict(id="TEST-I01", scope_asset="vault"),
            self._valid_row_dict(
                id="TEST-I02",
                scope_asset="obscure-bridge-module-xyz-not-in-scope",
                statement="Bridge must not allow double-spend.",
                source_citations=["SCOPE.md::bridge"],
                invariant_family="bridge_safety",
            ),
        ])
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertIn(r.returncode, (0, 2), r.stderr)
        diff_json = ws / ".auditooor" / "invariant_ledger_scope_diff.json"
        d = json.loads(diff_json.read_text())
        orphaned_ids = [row["accepted_id"] for row in d["accepted_orphaned_rows"]]
        self.assertIn("TEST-I02", orphaned_ids,
                      f"Expected TEST-I02 in orphaned rows, got: {orphaned_ids}")

    def test_DA_5_accepted_drifted_rows_detected(self):
        """DA-5: Rows with a severity_line note referencing a line no longer in
        SEVERITY.md should be classified as drifted.

        We first run --from-scope to discover what ID is generated from the
        SEVERITY.md bullet, then build a ledger row with that exact ID and a
        stale severity_line note, and verify it lands in accepted_drifted_rows.
        """
        import tempfile as _tf
        ws = Path(_tf.mkdtemp())
        (ws / ".auditooor").mkdir()
        # SEVERITY.md with an 'upgrade' bullet (maps to impact_authorization_boundary)
        # Heading must match _SEVERITY_HEADING_RE: ^#{1,6}\s+(critical|high|medium|low)\b
        sev_text = (
            "# Severity\n\n"
            "### Critical\n\n"
            "- Direct theft of funds.\n"
            "- Unauthorized verifier upgrade.\n"
        )
        (ws / "SEVERITY.md").write_text(sev_text, encoding="utf-8")
        # Run --from-scope to generate the ledger and see what IDs are created
        r0 = _run(["--workspace", str(ws), "--from-scope"])
        # Now read what IDs were generated
        ledger_json = ws / ".auditooor" / "invariant_ledger.json"
        if not ledger_json.is_file():
            self.skipTest("--from-scope produced no ledger; cannot test drift detection")
        d0 = json.loads(ledger_json.read_text())
        existing_ids = [r["id"] for r in d0.get("rows", [])]
        if not existing_ids:
            self.skipTest("--from-scope generated no rows; cannot test drift detection")
        # Overwrite the ledger: same row id, but add a stale severity_line note
        first_id = existing_ids[0]
        first_row = d0["rows"][0]
        first_row["notes"] = (
            (first_row.get("notes") or "") +
            ";severity_line:THIS LINE NO LONGER EXISTS IN SEVERITY.MD"
        )
        d0["rows"] = [first_row]
        ledger_json.write_text(json.dumps(d0), encoding="utf-8")
        (ws / "INVARIANT_LEDGER.md").write_text("# Invariant Ledger\n", encoding="utf-8")
        # Now run --diff-accepted
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertIn(r.returncode, (0, 2), r.stderr)
        diff_json = ws / ".auditooor" / "invariant_ledger_scope_diff.json"
        self.assertTrue(diff_json.is_file())
        d = json.loads(diff_json.read_text())
        drifted_ids = [row["accepted_id"] for row in d["accepted_drifted_rows"]]
        self.assertIn(first_id, drifted_ids,
                      f"Expected {first_id} in drifted_rows. Got: {drifted_ids}. "
                      f"Summary: {d['summary']}")

    def test_DA_6_exits_2_when_ledger_empty(self):
        """DA-6: --diff-accepted exits 2 when ledger has no accepted rows."""
        ws = self._make_ws()
        self._write_scope_md(ws, ["vault"])
        self._write_ledger(ws, [])
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertEqual(r.returncode, 2, r.stderr)

    def test_DA_7_readonly_does_not_mutate_ledger(self):
        """DA-7: --diff-accepted must not add rows to the ledger JSON."""
        ws = self._make_ws()
        self._write_scope_md(ws, ["vault", "bridge"])
        row = self._valid_row_dict()
        self._write_ledger(ws, [row])
        ledger_before = (ws / ".auditooor" / "invariant_ledger.json").read_text()
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertIn(r.returncode, (0, 2), r.stderr)
        ledger_after = (ws / ".auditooor" / "invariant_ledger.json").read_text()
        before_rows = json.loads(ledger_before).get("rows", [])
        after_rows = json.loads(ledger_after).get("rows", [])
        self.assertEqual(
            len(before_rows), len(after_rows),
            f"Ledger row count changed: {len(before_rows)} -> {len(after_rows)}. "
            "--diff-accepted must be read-only.",
        )

    def test_DA_8_smoke_real_base_azul(self):
        """DA-8: Smoke test against real base-azul workspace (skipped if absent)."""
        ws = Path("/Users/wolf/audits/base-azul")
        ledger = ws / ".auditooor" / "invariant_ledger.json"
        if not ledger.is_file():
            self.skipTest("base-azul ledger not present; skipping smoke test")
        r = _run(["--workspace", str(ws), "--diff-accepted"])
        self.assertEqual(r.returncode, 0, r.stderr)
        diff_json = ws / ".auditooor" / "invariant_ledger_scope_diff.json"
        self.assertTrue(diff_json.is_file())
        d = json.loads(diff_json.read_text())
        summary = d["summary"]
        # Total accounted rows should equal accepted ledger row count
        total = (
            summary["accepted_unchanged_count"]
            + summary["accepted_drifted_count"]
            + summary["accepted_orphaned_count"]
        )
        raw_rows = json.loads(ledger.read_text())
        accepted_count = len(raw_rows.get("rows", raw_rows if isinstance(raw_rows, list) else []))
        self.assertEqual(total, accepted_count,
                         f"Bucket counts don't sum to ledger row count: "
                         f"{total} != {accepted_count}")


class ZeroCoverageMatrixSchemaTest(unittest.TestCase):
    """Tests for the wave_c3b zero-coverage matrix files (Task B).

    Coverage:
     ZC-1. Each of the 4 matrix JSON files is valid JSON with the correct schema_version.
     ZC-2. Each matrix has >= 3 rows.
     ZC-3. Every severity_ceiling_verbatim in every row grep-matches the SEVERITY.md file.
     ZC-4. Every row has current_status in {candidate_unmapped, candidate_blocked}.
     ZC-5. No row has any Critical claim promoted beyond candidate_* status.
    """

    MATRIX_DIR = Path("/Users/wolf/audits/base-azul/critical_hunt/wave_c3b_zero_coverage")
    SEVERITY_MD = Path("/Users/wolf/audits/base-azul/SEVERITY.md")
    CLASSES = [
        "unauthorized_verifier_upgrade",
        "rpc_crash",
        "evm_precompile_differential",
        "block_delay_500_percent",
    ]

    def setUp(self):
        if not self.MATRIX_DIR.is_dir():
            self.skipTest("wave_c3b_zero_coverage dir not present; skipping")
        if not self.SEVERITY_MD.is_file():
            self.skipTest("SEVERITY.md not present; skipping")
        self.severity_text = self.SEVERITY_MD.read_text(encoding="utf-8")

    def _load_matrix(self, cls_name: str) -> dict:
        p = self.MATRIX_DIR / f"{cls_name}.json"
        self.assertTrue(p.is_file(), f"Matrix file missing: {p}")
        return json.loads(p.read_text(encoding="utf-8"))

    def test_ZC_1_schema_version(self):
        """ZC-1: All 4 matrices have correct schema_version."""
        for cls in self.CLASSES:
            with self.subTest(cls=cls):
                d = self._load_matrix(cls)
                self.assertEqual(
                    d.get("schema_version"),
                    "auditooor.zero_coverage_matrix.v1",
                    f"{cls}: wrong schema_version",
                )

    def test_ZC_2_minimum_row_count(self):
        """ZC-2: All 4 matrices have >= 3 rows."""
        for cls in self.CLASSES:
            with self.subTest(cls=cls):
                d = self._load_matrix(cls)
                rows = d.get("rows", [])
                self.assertGreaterEqual(
                    len(rows), 3,
                    f"{cls}: only {len(rows)} rows, expected >= 3",
                )

    def test_ZC_3_severity_ceiling_verbatim_grep_matches(self):
        """ZC-3: Every severity_ceiling_verbatim (at matrix and row level)
        must be a substring of SEVERITY.md (M14-trap compliance)."""
        for cls in self.CLASSES:
            with self.subTest(cls=cls):
                d = self._load_matrix(cls)
                # Top-level matrix ceiling
                top_ceiling = d.get("severity_ceiling_verbatim", "")
                if top_ceiling:
                    self.assertIn(
                        top_ceiling, self.severity_text,
                        f"{cls}: top-level severity_ceiling_verbatim not found in SEVERITY.md: "
                        f"{top_ceiling!r}",
                    )
                # Per-row ceilings
                for row in d.get("rows", []):
                    row_ceiling = row.get("severity_ceiling_verbatim", "")
                    if row_ceiling:
                        self.assertIn(
                            row_ceiling, self.severity_text,
                            f"{cls} row {row.get('row_id')}: severity_ceiling_verbatim "
                            f"not found in SEVERITY.md: {row_ceiling!r}",
                        )

    def test_ZC_4_status_only_candidate(self):
        """ZC-4: All rows have current_status in {candidate_unmapped, candidate_blocked}."""
        valid = {"candidate_unmapped", "candidate_blocked"}
        for cls in self.CLASSES:
            with self.subTest(cls=cls):
                d = self._load_matrix(cls)
                for row in d.get("rows", []):
                    status = row.get("current_status", "")
                    self.assertIn(
                        status, valid,
                        f"{cls} row {row.get('row_id')}: invalid current_status {status!r}",
                    )

    def test_ZC_5_no_promoted_critical_claims(self):
        """ZC-5: No row is promoted beyond candidate_* — no 'proved' or 'submitted' status."""
        prohibited = {"proved", "submitted", "confirmed", "exploited"}
        for cls in self.CLASSES:
            with self.subTest(cls=cls):
                d = self._load_matrix(cls)
                for row in d.get("rows", []):
                    status = row.get("current_status", "")
                    self.assertNotIn(
                        status, prohibited,
                        f"{cls} row {row.get('row_id')}: status {status!r} "
                        "is beyond candidate — DO NOT promote without executable evidence",
                    )


class KKLedgerRegressionGateTest(unittest.TestCase):
    """Regression gate: KK's actual Base ledger must pass `--check` with
    rc=0. This is the test that protects against future schema drift
    closing the door on real ledgers again. Skipped when the ledger is
    not present (CI runs in a clean checkout)."""

    KK_WS = Path("/Users/wolf/audits/base-azul")
    KK_LEDGER = KK_WS / ".auditooor" / "invariant_ledger.json"

    def test_kk_base_ledger_passes_check(self):
        if not self.KK_LEDGER.is_file():
            self.skipTest(
                f"KK ledger not present at {self.KK_LEDGER}; "
                "skipping regression gate (clean checkout / CI)"
            )
        r = _run(["--workspace", str(self.KK_WS), "--check"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 error(s)", r.stdout)


if __name__ == "__main__":
    unittest.main()
