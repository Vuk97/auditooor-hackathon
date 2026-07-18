#!/usr/bin/env python3
"""Tests for tools/live-target-intelligence-report.py - P5 MVP1.

Each test builds an isolated fake workspace under a temp dir so no real
workspace is touched. Offline. Stdlib only.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_VAULT_TOOL_PATH = _HERE.parent / "vault-mcp-server.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


def _load_vault_mcp_module():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_live_target_report_test", _VAULT_TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _seed_workspace(
    root: Path,
    *,
    audit_pin_sha: str = "5ee9766351ef864856a309a971b13fdd98cae2c5",
    n_hits_per_cluster: int = 3,
    include_prior: bool = False,
    include_submissions: bool = False,
    bad_audit_pin_sha: str | None = None,
) -> None:
    """Seed a fake workspace with engage_report.json + INTAKE_BASELINE.json + .auditooor/."""
    root.mkdir(parents=True, exist_ok=True)
    auditooor = root / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    # commit_lifecycle_ledger.json - canonical source
    ledger = {
        "schema": "auditooor.commit_lifecycle_ledger.v1",
        "audit_pin_sha": bad_audit_pin_sha or audit_pin_sha,
        "head_sha": "",
    }
    (auditooor / "commit_lifecycle_ledger.json").write_text(json.dumps(ledger))
    # Fallback: a brief that contains the 40-hex SHA so the fallback works
    # when commit_lifecycle_ledger.json has a bad / "main" sha.
    (auditooor / "fake_brief.md").write_text(
        f"Audit-pin: `{audit_pin_sha}` for fake-target.\n"
    )
    # INTAKE_BASELINE.json
    intake = {
        "schema": "auditooor.intake_baseline.v1",
        "workspace": str(root),
        "assets_in_scope": ["Blockchain/DLT"],
        "file_extension_counts": {
            ".go": 200,
            ".rs": 50,
            ".sol": 30,
            ".md": 10,
        },
    }
    (root / "INTAKE_BASELINE.json").write_text(json.dumps(intake))
    # engage_report.json
    engage = {
        "actionable_next_steps": {"dupe_check": 0, "mine": 100, "triage": 0},
        "analogical_clusters": 2,
        "clusters": [
            {
                "detector_slug": "go.crypto.race.unsynchronized_concurrent_access",
                "hit_count": n_hits_per_cluster,
                "hits": [
                    {
                        "file_path": f"external/v4-chain/protocol/x/clob/types/operations_to_propose.go:{100 + i}",
                        "severity": "LOW",
                        "snippet": "o.OperationsQueue = append(...)",
                    }
                    for i in range(n_hits_per_cluster)
                ],
            },
            {
                "detector_slug": "go.go.panic.dereference_before_nil_check",
                "hit_count": n_hits_per_cluster,
                "hits": [
                    {
                        "file_path": f"share/cantina-202-triager-evidence/setup_rootmulti/main.go:{140 + i}",
                        "severity": "LOW",
                        "snippet": "kv := rs.GetKVStore(key)",
                    }
                    for i in range(n_hits_per_cluster)
                ],
            },
        ],
    }
    (root / "engage_report.json").write_text(json.dumps(engage))
    # PRIOR_CONCERNS.md (optional)
    if include_prior:
        (root / "PRIOR_CONCERNS.md").write_text(
            "## Acknowledged by design\n\n"
            "- `go.crypto.race.unsynchronized_concurrent_access` family in x/clob "
            "is acknowledged-by-design per prior audit; do not refile.\n"
        )
    # SCOPE.md + SEVERITY.md (minimal)
    (root / "SCOPE.md").write_text("# Scope\n\nIn-scope: external/v4-chain/protocol\n")
    (root / "SEVERITY.md").write_text(
        "# Severity\n\nCritical: loss of funds\nHigh: degradation\nMedium: minor\nLow: info\n"
    )
    # Existing submissions (optional)
    if include_submissions:
        subs = root / "submissions" / "filed" / "previous-finding"
        subs.mkdir(parents=True, exist_ok=True)
        (subs / "previous-finding.md").write_text(
            "# Previous finding cites detector `go.crypto.race.unsynchronized_concurrent_access`.\n"
        )


def _seed_uniform_top30_workspace(root: Path) -> None:
    """Seed >30 same-score hits so CAP-014 top-band closure can be tested."""
    root.mkdir(parents=True, exist_ok=True)
    auditooor = root / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "commit_lifecycle_ledger.json").write_text(
        json.dumps({"audit_pin_sha": "abcdef0123456789abcdef0123456789abcdef01"})
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps({"file_extension_counts": {".sol": 40}})
    )
    src = root / "src"
    src.mkdir()
    clusters = []
    for i in range(35):
        name = f"Gateway{i}.sol" if i % 2 == 0 else f"Helper{i}.sol"
        line = 20 + i
        source = (
            "contract GatewayCore {\n"
            "  mapping(address => uint256) public balances;\n"
            "  address public owner;\n"
            "  function initialize(address admin) external {\n"
            "    balances[admin] = 1;\n"
            "    owner = admin;\n"
            "  }\n"
            "}\n"
            if i % 2 == 0
            else
            "contract Helper {\n"
            "  function configure(address admin) external {\n"
            "    admin;\n"
            "  }\n"
            "}\n"
        )
        snippet = (
            "function initialize(address admin) external"
            if i % 2 == 0
            else
            "function configure(address admin) external"
        )
        (src / name).write_text(
            source
        )
        clusters.append(
            {
                "detector_slug": f"constructor-no-zero-address-check-{i}",
                "hit_count": 1,
                "hits": [
                    {
                        "file_path": f"src/{name}:{line}",
                        "severity": "LOW",
                        "snippet": snippet,
                    }
                ],
            }
        )
    (root / "engage_report.json").write_text(json.dumps({"clusters": clusters}))


def _seed_superearn_oos_workspace(root: Path) -> None:
    """Seed SuperEarn-like OOS rows and two high-priority detector hits."""
    root.mkdir(parents=True, exist_ok=True)
    auditooor = root / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "commit_lifecycle_ledger.json").write_text(
        json.dumps({"audit_pin_sha": "1234567890abcdef1234567890abcdef12345678"})
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps({"file_extension_counts": {".sol": 2, ".md": 1}})
    )
    bounty_dir = root / "src" / "superearn"
    bounty_dir.mkdir(parents=True, exist_ok=True)
    (bounty_dir / "BUG_BOUNTY.md").write_text(
        "\n".join(
            [
                "# SuperEarn Bug Bounty",
                "",
                "## AI-Tool False-Positive Patterns",
                "",
                "| Row | Pattern | Rationale |",
                "| --- | --- | --- |",
                "| 42 | Front-running / sandwich / MEV via public mempool against contracts using 2-step request/claim or minOut | OOS without extension-distinct evidence |",
                "",
                "## Trust Assumptions",
                "",
                (
                    "Stablecoin issuers are trusted. Fee-on-transfer, freeze, "
                    "blacklist, depeg, or issuer-imposed transfer fee behavior "
                    "requires an extension-distinct argument."
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    vaults = root / "src" / "vaults"
    vaults.mkdir(parents=True, exist_ok=True)
    (vaults / "OriginVaultBase.sol").write_text(
        "\n".join(
            [
                "contract OriginVaultBase {",
                "  function requestDeposit(uint256 assets) external {",
                "    assets;",
                "  }",
                "  function claimDeposit(uint256 shares) external {",
                "    shares;",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    (vaults / "CooldownVault.sol").write_text(
        "\n".join(
            [
                "contract CooldownVault {",
                "  address public stablecoin;",
                "  function deposit(uint256 assets) external {",
                "    // stablecoin transfer path, fee-on-transfer detector candidate",
                "    assets;",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    engage = {
        "clusters": [
            {
                "detector_slug": "erc4626-functions-no-slippage",
                "hit_count": 1,
                "hits": [
                    {
                        "file_path": "src/vaults/OriginVaultBase.sol:2",
                        "severity": "HIGH",
                        "snippet": "request/claim ERC4626 flow lacks minOut or slippage guard",
                    }
                ],
            },
            {
                "detector_slug": "fee-on-transfer-not-accounted",
                "hit_count": 1,
                "hits": [
                    {
                        "file_path": "src/vaults/CooldownVault.sol:3",
                        "severity": "HIGH",
                        "snippet": "stablecoin fee-on-transfer not accounted before share mint",
                    }
                ],
            },
        ]
    }
    (root / "engage_report.json").write_text(json.dumps(engage), encoding="utf-8")
    (root / "SCOPE.md").write_text("# Scope\n\nIn-scope: src/\n", encoding="utf-8")
    (root / "SEVERITY.md").write_text(
        "# Severity\n\nCritical: loss of funds\nHigh: loss of funds\n",
        encoding="utf-8",
    )


class LiveTargetIntelReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "fake_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- 1. missing workspace ----------------------------------------------
    def test_missing_workspace_strict_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            ltir_mod.build_report(
                Path(self._tmp.name) / "does_not_exist",
                strict=True,
            )

    def test_missing_workspace_lenient_emits_error(self) -> None:
        report = ltir_mod.build_report(
            Path(self._tmp.name) / "does_not_exist",
            strict=False,
        )
        self.assertIn("workspace_not_found", "|".join(report["errors"]))
        self.assertEqual(report["schema"], ltir_mod.SCHEMA)

    # --- 2. missing engage_report ------------------------------------------
    def test_missing_engage_report_strict_raises(self) -> None:
        self.ws.mkdir(parents=True, exist_ok=True)
        (self.ws / "INTAKE_BASELINE.json").write_text(
            json.dumps({"file_extension_counts": {".go": 10}})
        )
        with self.assertRaises(FileNotFoundError):
            ltir_mod.build_report(self.ws, strict=True)

    def test_missing_engage_report_lenient_emits_error(self) -> None:
        self.ws.mkdir(parents=True, exist_ok=True)
        report = ltir_mod.build_report(self.ws, strict=False)
        self.assertIn(
            "engage_report_missing_or_empty", "|".join(report["errors"])
        )
        self.assertEqual(report["entry_points"], [])

    # --- 3. MVP2 anti-pattern IDs: real P3 ID OR documented no-P3-match -----
    def test_anti_pattern_ids_real_or_documented_gap(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        self.assertTrue(report["entry_points"])
        # MVP2 must emit either a real `solidity.<slug>` / `rust.<slug>` /
        # `go.<slug>` pattern_id, OR the documented `no-P3-match:<cat>:<lang>`
        # sentinel when the target lang has no P3 yaml for the cluster's
        # category yet. The old `TBD-P3-*` placeholder is REMOVED in V2.
        for ep in report["entry_points"]:
            for ap in ep["matched_anti_patterns"]:
                self.assertFalse(
                    ap.startswith("TBD-P3-"),
                    f"MVP2 must NOT emit V1 TBD-P3-* placeholder, got: {ap}",
                )
                # Must be either a real pattern_id (lang.slug shape) OR
                # the documented gap sentinel.
                is_real_pid = re.match(r"^[a-z]+\.[a-z0-9_\-]+", ap) is not None
                is_gap = ap.startswith("no-P3-match:")
                self.assertTrue(
                    is_real_pid or is_gap,
                    f"unexpected anti-pattern id shape in V2: {ap}",
                )

    # --- 4. severity rank composition ---------------------------------------
    def test_severity_rank_composition(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        eps = report["entry_points"]
        # Real-code hit (external/v4-chain/...) must rank higher than
        # share/cantina-202-triager-evidence/ scaffolding hit.
        real = [e for e in eps if e["file_line"].startswith("external/")]
        scaffolding = [e for e in eps if "cantina-202-triager-evidence" in e["file_line"]]
        self.assertTrue(real, "expected real-code entry points")
        self.assertTrue(scaffolding, "expected scaffolding entry points")
        max_real = max(e["engage_severity_score"] for e in real)
        max_scaffold = max(e["engage_severity_score"] for e in scaffolding)
        self.assertGreater(
            max_real, max_scaffold,
            "real external/ hits must outrank cantina-202-triager-evidence scaffolding",
        )

    # --- 5. top-N ordering --------------------------------------------------
    def test_top_n_ordering(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=3)
        eps = report["entry_points"]
        self.assertLessEqual(len(eps), 3)
        # Descending score.
        for i in range(len(eps) - 1):
            self.assertGreaterEqual(
                eps[i]["engage_severity_score"],
                eps[i + 1]["engage_severity_score"],
            )

    def test_uniform_top30_scores_are_split_within_band(self) -> None:
        _seed_uniform_top30_workspace(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=35)
        top30_scores = [
            ep["engage_severity_score"]
            for ep in report["entry_points"][:30]
        ]
        self.assertGreater(
            len(set(top30_scores)),
            1,
            "top-30 must not remain a single engage_severity_score band",
        )
        diff = report["summary_card"]["score_band_differentiator"]
        self.assertTrue(diff["applied"])
        self.assertGreaterEqual(diff["top30_unique_scores_after"], 2)
        for ep in report["entry_points"][:30]:
            self.assertIn("band_differentiator", ep)

    def test_score_band_differentiator_uses_per_finding_source_signals(self) -> None:
        entries = [
            {
                "file_line": "src/Vault.sol:20",
                "cluster_id": "signature-without-nonce",
                "cluster_size": 3,
                "snippet": "ECDSA.recover(digest, sig); _payee.call{value: amount}(\"\");",
                "engage_severity_score": 50.0,
                "hunt_priority": "MEDIUM-PRIORITY",
                "hunt_priority_base": "MEDIUM-PRIORITY",
                "matched_anti_patterns": ["solidity.signature-replay"],
                "p1_match_tier": "SEMANTIC-MATCH",
                "semantic_p1_invariants": ["INV-UNI-002"],
                "topical_p1_invariants": [],
                "accepted_p1_source_proof_matches": [],
                "composability_score": 2,
                "false_positive_suppression": {"suppressed": False, "reasons": [], "score_penalty": 0.0},
                "source_context_excerpt": (
                    "contract Vault { mapping(address => uint256) balances; "
                    "function permitWithdraw(bytes calldata sig) external { "
                    "balances[msg.sender] -= amount; _payee.call{value: amount}(\"\"); } }"
                ),
            },
            {
                "file_line": "src/Math.sol:12",
                "cluster_id": "division-by-zero",
                "cluster_size": 3,
                "snippet": "return total / SCALE;",
                "engage_severity_score": 50.0,
                "hunt_priority": "MEDIUM-PRIORITY",
                "hunt_priority_base": "MEDIUM-PRIORITY",
                "matched_anti_patterns": ["no-P3-match:bounds:solidity"],
                "p1_match_tier": "TOPICAL-MATCH",
                "semantic_p1_invariants": [],
                "topical_p1_invariants": ["INV-BND-004"],
                "accepted_p1_source_proof_matches": [],
                "composability_score": 0,
                "false_positive_suppression": {
                    "suppressed": True,
                    "reasons": ["CAP-005: divisor is literal/constant or guarded by prior modulo"],
                    "score_penalty": ltir_mod.DOCUMENTED_FP_SCORE_PENALTY,
                },
                "source_context_excerpt": "contract Math { uint256 constant SCALE = 1e18; }",
            },
            {
                "file_line": "src/PlainA.sol:1",
                "cluster_id": "plain-a",
                "cluster_size": 3,
                "snippet": "uint256 x = y;",
                "engage_severity_score": 50.0,
                "hunt_priority": "MEDIUM-PRIORITY",
                "hunt_priority_base": "MEDIUM-PRIORITY",
                "matched_anti_patterns": [],
                "p1_match_tier": "NO-MATCH",
                "semantic_p1_invariants": [],
                "topical_p1_invariants": [],
                "accepted_p1_source_proof_matches": [],
                "composability_score": 0,
                "false_positive_suppression": {"suppressed": False, "reasons": [], "score_penalty": 0.0},
                "source_context_excerpt": "contract PlainA { function f() external {} }",
            },
            {
                "file_line": "src/PlainB.sol:1",
                "cluster_id": "plain-b",
                "cluster_size": 3,
                "snippet": "uint256 x = y;",
                "engage_severity_score": 50.0,
                "hunt_priority": "MEDIUM-PRIORITY",
                "hunt_priority_base": "MEDIUM-PRIORITY",
                "matched_anti_patterns": [],
                "p1_match_tier": "NO-MATCH",
                "semantic_p1_invariants": [],
                "topical_p1_invariants": [],
                "accepted_p1_source_proof_matches": [],
                "composability_score": 0,
                "false_positive_suppression": {"suppressed": False, "reasons": [], "score_penalty": 0.0},
                "source_context_excerpt": "contract PlainB { function f() external {} }",
            },
        ]

        diagnostics = ltir_mod._apply_score_band_differentiator(entries)
        by_cluster = {entry["cluster_id"]: entry for entry in entries}
        ranked = sorted(entries, key=lambda entry: entry["engage_severity_score"], reverse=True)

        self.assertTrue(diagnostics["applied"])
        self.assertEqual(diagnostics["top30_unique_scores_before"], 1)
        self.assertGreaterEqual(diagnostics["top30_unique_scores_after"], 3)
        self.assertEqual(ranked[0]["cluster_id"], "signature-without-nonce")
        self.assertEqual(ranked[-1]["cluster_id"], "division-by-zero")
        self.assertGreater(by_cluster["signature-without-nonce"]["engage_severity_score"], 50.0)
        self.assertLess(by_cluster["division-by-zero"]["engage_severity_score"], 50.0)
        self.assertEqual(
            by_cluster["plain-a"]["engage_severity_score"],
            by_cluster["plain-b"]["engage_severity_score"],
            "identical no-signal rows must not be split by lexical rank position",
        )
        self.assertEqual(by_cluster["division-by-zero"]["p1_match_tier"], "TOPICAL-MATCH")
        self.assertEqual(by_cluster["division-by-zero"]["semantic_p1_invariants"], [])

    # --- 6. --if-stale-only flag --------------------------------------------
    def test_if_stale_only_skip_on_fresh(self) -> None:
        _seed_workspace(self.ws)
        out = self.ws / "docs" / "LIVE_TARGET_REPORT.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("stale report body")
        # is_stale should be False for a fresh file
        self.assertFalse(ltir_mod._is_stale(out, threshold_seconds=3600))

    def test_if_stale_only_regenerate_on_missing(self) -> None:
        out = self.ws / "docs" / "LIVE_TARGET_REPORT.md"
        self.assertTrue(ltir_mod._is_stale(out, threshold_seconds=3600))

    def test_report_freshness_rejects_old_tool_version(self) -> None:
        stale = {
            "schema": ltir_mod.SCHEMA,
            "tool_version": "0.3.0",
            "provenance": {"tool_version": "0.3.0"},
        }
        freshness = ltir_mod.live_target_report_freshness(stale)
        self.assertEqual(freshness["status"], "stale_tool_version")
        self.assertFalse(freshness["safe_to_treat_as_current"])
        self.assertEqual(freshness["expected_tool_version"], ltir_mod.TOOL_VERSION)
        self.assertEqual(freshness["report_tool_version"], "0.3.0")

    def test_if_stale_only_regenerates_when_json_version_is_old(self) -> None:
        _seed_workspace(self.ws)
        docs = self.ws / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        out_md = docs / "LIVE_TARGET_REPORT.md"
        out_json = docs / "LIVE_TARGET_REPORT.json"
        out_md.write_text("fresh markdown body from older run\n", encoding="utf-8")
        out_json.write_text(
            json.dumps(
                {
                    "schema": ltir_mod.SCHEMA,
                    "tool_version": "0.3.0",
                    "provenance": {"tool_version": "0.3.0"},
                    "entry_points": [
                        {
                            "file_line": "stale.sol:1",
                            "hunt_priority": "HIGH-PRIORITY-HUNT",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        proc = subprocess.run(
            [
                sys.executable,
                str(_TOOL_PATH),
                "--workspace",
                str(self.ws),
                "--output",
                str(out_md),
                "--output-json",
                str(out_json),
                "--if-stale-only",
                "--top-n",
                "3",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("refresh (not-current)", proc.stdout)
        regenerated = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(regenerated["tool_version"], ltir_mod.TOOL_VERSION)
        self.assertNotEqual(
            regenerated["entry_points"][0]["file_line"],
            "stale.sol:1",
        )

    # --- 7. --strict mode ---------------------------------------------------
    def test_strict_with_complete_workspace_succeeds(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws, strict=True)
        self.assertEqual(report["schema"], ltir_mod.SCHEMA)
        self.assertTrue(report["entry_points"])

    # --- 8. schema validity -------------------------------------------------
    def test_schema_validity(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        # Required top-level fields per auditooor.live_target_intelligence.v1
        for required in (
            "schema",
            "tool_version",
            "workspace",
            "audit_pin",
            "summary_card",
            "entry_points",
            "prioritized_hunt_list",
            "coverage_gaps",
            "prior_audit_deltas",
            "operator_action_queue",
            "provenance",
            "errors",
        ):
            self.assertIn(required, report, f"missing required field: {required}")
        # Each entry point should have the documented fields
        for ep in report["entry_points"]:
            for required in (
                "file_line",
                "cluster_id",
                "engage_severity_score",
                "hunt_priority",
                "matched_anti_patterns",
            ):
                self.assertIn(required, ep)
        # Provenance hash is stable for same workspace state
        report2 = ltir_mod.build_report(self.ws)
        self.assertEqual(
            report["provenance"]["workspace_state_hash"],
            report2["provenance"]["workspace_state_hash"],
        )

    # --- 9. coverage gaps + prior-audit deltas -----------------------------
    def test_coverage_gaps_and_prior_deltas(self) -> None:
        _seed_workspace(self.ws, include_prior=True, include_submissions=True)
        report = ltir_mod.build_report(self.ws)
        # 'go.crypto.race...' is in submissions -> should NOT be a coverage gap
        gaps = report["coverage_gaps"]
        self.assertNotIn(
            "go.crypto.race.unsynchronized_concurrent_access", gaps,
            "cluster covered by existing submission should not be a coverage gap",
        )
        # 'go.go.panic.dereference_before_nil_check' is NOT in submissions -> gap
        self.assertIn("go.go.panic.dereference_before_nil_check", gaps)
        # Prior-audit deltas should pick up the prior-acknowledged cluster
        self.assertIn(
            "go.crypto.race.unsynchronized_concurrent_access",
            report["prior_audit_deltas"],
        )

    # --- 10. audit-pin: reject 'main' / invalid SHA, accept 40-hex ---------
    def test_audit_pin_rejects_branch_name_uses_fallback(self) -> None:
        # ledger has audit_pin_sha='main' -> rejected -> fallback reads
        # .auditooor/fake_brief.md which contains the 40-char SHA.
        _seed_workspace(self.ws, bad_audit_pin_sha="main")
        report = ltir_mod.build_report(self.ws)
        sha = report["audit_pin"].get("sha")
        self.assertIsNotNone(sha)
        self.assertEqual(len(sha), 40)
        # All hex
        int(sha, 16)

    def test_audit_pin_accepts_valid_40_hex(self) -> None:
        valid_sha = "deadbeef" * 5
        _seed_workspace(self.ws, audit_pin_sha=valid_sha)
        report = ltir_mod.build_report(self.ws)
        self.assertEqual(report["audit_pin"]["sha"], valid_sha)

    # --- 11. markdown rendering -------------------------------------------
    def test_markdown_rendering(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        md = ltir_mod.render_markdown(report)
        self.assertIn("# Live-Target Intelligence Report", md)
        self.assertIn("## Hunt prioritization", md)
        self.assertIn("## Coverage gaps", md)
        self.assertIn("## Prior-audit deltas", md)
        self.assertIn("## Operator action queue", md)
        self.assertIn("## P4 triager precheck (MVP3)", md)
        self.assertIn("## Provenance", md)

    def test_bug_bounty_oos_downranks_superearn_front_running_and_trusted_stablecoin(self) -> None:
        _seed_superearn_oos_workspace(self.ws)
        report = ltir_mod.build_report(
            self.ws,
            top_n=10,
            triager_precheck_budget=0,
        )
        index_path = self.ws / ".auditooor" / "bug_bounty_oos_index.json"
        self.assertTrue(index_path.is_file())
        index = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(index["schema"], "auditooor.bug_bounty_oos_index.v1")
        self.assertGreaterEqual(index["row_count"], 2)
        self.assertIn("src/superearn/BUG_BOUNTY.md", index["source_paths"])

        by_cluster = {ep["cluster_id"]: ep for ep in report["entry_points"]}
        front = by_cluster["erc4626-functions-no-slippage"]
        fot = by_cluster["fee-on-transfer-not-accounted"]

        self.assertEqual(front["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY)
        self.assertEqual(fot["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY)
        self.assertEqual(
            front["hunt_priority_before_bug_bounty_oos"],
            "HIGH-PRIORITY-HUNT",
        )
        self.assertEqual(
            fot["hunt_priority_before_bug_bounty_oos"],
            "HIGH-PRIORITY-HUNT",
        )
        self.assertEqual(front["bug_bounty_oos_match"]["clause_id"], "AI-FP-row-42")
        self.assertGreaterEqual(front["bug_bounty_oos_match"]["confidence"], 0.7)
        self.assertIn(
            "front-running-public-mempool",
            front["bug_bounty_oos_match"]["semantic_tags"],
        )
        self.assertGreaterEqual(fot["bug_bounty_oos_match"]["confidence"], 0.7)
        self.assertIn(
            "stablecoin-trust",
            fot["bug_bounty_oos_match"]["semantic_tags"],
        )

        dist = report["summary_card"]["hunt_priority_distribution"]
        self.assertEqual(dist[ltir_mod.BUG_BOUNTY_OOS_PRIORITY], 2)
        self.assertEqual(report["operator_action_queue"], [])
        self.assertEqual(report["summary_card"]["bug_bounty_oos"]["entries_downranked"], 2)

        md = ltir_mod.render_markdown(report)
        self.assertIn("BUG_BOUNTY OOS cross-check", md)
        self.assertIn("AI-FP-row-42", md)
        self.assertIn(ltir_mod.BUG_BOUNTY_OOS_PRIORITY, md)

    def test_markdown_renders_all_prioritized_entries(self) -> None:
        report = {
            "workspace": str(self.ws),
            "tool_version": "test",
            "audit_pin": {"report_generated": "2026-05-24T00:00:00Z"},
            "summary_card": {
                "files_indexed": 1,
                "languages": ["solidity"],
                "engage_report_hit_count": 55,
                "clusters_count": 55,
                "engage_severity": {"engage_report_source": "json", "available": False},
                "hunt_priority_distribution": {
                    "HIGH-PRIORITY-HUNT": 55,
                    "MEDIUM-PRIORITY": 0,
                    "LOW-PRIORITY": 0,
                },
                "coverage_gap_count": 0,
                "prior_audit_delta_count": 0,
            },
            "coverage_gaps": [],
            "prior_audit_deltas": [],
            "operator_action_queue": [],
            "provenance": {"mvp_phase": "MVP3"},
            "prioritized_hunt_list": [
                {
                    "engage_severity_score": 90 - (idx / 100),
                    "composability_score": 1,
                    "hunt_priority": "HIGH-PRIORITY-HUNT",
                    "file_line": f"src/C{idx}.sol:{idx}",
                    "cluster_id": f"cluster-{idx}",
                    "p1_match_tier": "TOPICAL-MATCH",
                    "matched_p1_invariants": ["INV-AUTH-001"],
                    "matched_anti_patterns": ["solidity.test-pattern"],
                    "p4_triager_precheck": {"status": "budget-skipped"},
                }
                for idx in range(1, 56)
            ],
        }

        md = ltir_mod.render_markdown(report)

        self.assertIn("| 55 |", md)
        self.assertIn("`src/C55.sol:55`", md)

    # --- 12. MVP3: triager-precheck-budget runs local P4 rules only -------
    def test_triager_precheck_budget_runs_local_rules_only(self) -> None:
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws, triager_precheck_budget=1)
        p4_summary = report["summary_card"]["p4_triager_precheck"]
        self.assertTrue(p4_summary["available"])
        self.assertEqual(p4_summary["state"], "completed")
        self.assertEqual(p4_summary["entries_prechecked"], 1)
        self.assertGreaterEqual(p4_summary["entries_budget_skipped"], 1)
        self.assertFalse(p4_summary["provider_backed"])
        self.assertFalse(p4_summary["provider_call_made"])
        self.assertFalse(p4_summary["predicted_verdict_supported"])

        prechecked = [
            ep["p4_triager_precheck"]
            for ep in report["entry_points"]
            if ep["p4_triager_precheck"]["status"] == "completed"
        ]
        self.assertEqual(len(prechecked), 1)
        p4 = prechecked[0]
        self.assertEqual(p4["mode"], "rules_mvp")
        self.assertIn("local_rules_status", p4)
        self.assertIn("provider_status", p4)
        self.assertFalse(p4["provider_backed"])
        self.assertFalse(p4["provider_call_made"])
        self.assertFalse(p4["predicted_verdict_supported"])
        self.assertIsNone(p4["predicted_verdict"])
        self.assertFalse(p4["triager_verdict_or_clearance"])
        self.assertIn("recommended_action", p4)

    def test_triager_precheck_draft_receives_p1_gap_context(self) -> None:
        """MVP3 compose: P4 precheck input must include P1 semantic gaps."""
        _seed_workspace(self.ws)
        captured: dict[str, str] = {}

        class FakeP4:
            @staticmethod
            def build_precheck(
                draft_path: Path,
                workspace_path: Path,
                severity: str | None = None,
            ) -> dict:
                captured["draft"] = draft_path.read_text(encoding="utf-8")
                captured["workspace"] = str(workspace_path)
                captured["severity"] = severity or ""
                return {
                    "schema": "auditooor.triager_precheck.v1",
                    "mode": "rules_mvp",
                    "local_rules_status": {},
                    "provider_status": {},
                    "capability_boundary": {},
                    "recommended_action": "review_matched_triager_patterns_before_filing",
                    "warnings": [],
                    "matched_patterns": [],
                    "class_votes": {},
                    "silent_kill_predictions": [],
                    "silent_kill_summary": {},
                    "disposition_evidence": {},
                    "source_refs": [str(draft_path)],
                }

        original_loader = ltir_mod._load_p4_triager_precheck
        ltir_mod._load_p4_triager_precheck = lambda: FakeP4
        try:
            report = ltir_mod.build_report(self.ws, triager_precheck_budget=1)
        finally:
            ltir_mod._load_p4_triager_precheck = original_loader

        self.assertIn("draft", captured)
        prechecked = [
            ep for ep in report["entry_points"]
            if ep["p4_triager_precheck"]["status"] == "completed"
        ]
        self.assertEqual(len(prechecked), 1)
        self.assertTrue(prechecked[0]["p1_semantic_invariant_gaps"])
        draft = captured["draft"]
        self.assertIn("P1 semantic invariants:", draft)
        self.assertIn("P1 semantic invariant gaps:", draft)
        self.assertIn('"status": "topical-only"', draft)
        self.assertIn("P3 anti-pattern IDs:", draft)
        self.assertIn("deterministic local P4 precheck only", draft)
        self.assertFalse(prechecked[0]["p4_triager_precheck"]["provider_backed"])
        self.assertFalse(prechecked[0]["p4_triager_precheck"]["provider_call_made"])

    # --- 13. hunt-priority buckets -----------------------------------------
    def test_hunt_priority_buckets(self) -> None:
        self.assertEqual(ltir_mod._bucket_for(99), "HIGH-PRIORITY-HUNT")
        self.assertEqual(ltir_mod._bucket_for(70), "HIGH-PRIORITY-HUNT")
        self.assertEqual(ltir_mod._bucket_for(69), "MEDIUM-PRIORITY")
        self.assertEqual(ltir_mod._bucket_for(40), "MEDIUM-PRIORITY")
        self.assertEqual(ltir_mod._bucket_for(39), "LOW-PRIORITY")
        self.assertEqual(ltir_mod._bucket_for(0), "LOW-PRIORITY")

    # --- 14a. MVP2 compose: P1 invariant injection per category ------------
    def test_mvp2_p1_invariant_injection_per_category(self) -> None:
        """A cluster whose category maps to P1 invariants must surface
        real INV-* IDs in the entry's ``matched_p1_invariants`` field.

        Uses the real repo P1 corpus (500 entries) which has go/any
        coverage in every category. The seeded cluster
        ``go.crypto.race.unsynchronized_concurrent_access`` -> atomicity,
        and the P1 corpus has 12 go/any atomicity invariants.
        """
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        race_eps = [
            e for e in report["entry_points"]
            if e["cluster_id"] == "go.crypto.race.unsynchronized_concurrent_access"
        ]
        self.assertTrue(race_eps, "expected race-cluster entry points")
        # At least one race entry must surface real INV-* IDs
        with_p1 = [e for e in race_eps if e["matched_p1_invariants"]]
        self.assertTrue(
            with_p1,
            "MVP2 must inject real P1 INV-* IDs for the atomicity-mapped cluster",
        )
        for ep in with_p1:
            for inv_id in ep["matched_p1_invariants"]:
                self.assertTrue(
                    inv_id.startswith("INV-"),
                    f"P1 hit must be a real INV-* ID, got: {inv_id}",
                )

    # --- 14b. MVP2 compose: P3 pattern injection per category --------------
    def test_mvp2_p3_pattern_injection_per_category(self) -> None:
        """A cluster whose category resolves to a P3 anti-pattern catalog
        category must surface either real pattern_id strings (when the
        target lang has yaml for the category) OR the documented
        ``no-P3-match:<cat>:<lang>`` sentinel.

        After the sibling P3-go-prescaff lane landed, the race cluster's
        P3 category resolves to ``atomicity-and-ordering`` which has 3
        Go yamls shipped, so we expect REAL ``go.*`` pattern_ids here.
        """
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        race_eps = [
            e for e in report["entry_points"]
            if e["cluster_id"] == "go.crypto.race.unsynchronized_concurrent_access"
        ]
        self.assertTrue(race_eps)
        for ep in race_eps:
            aps = ep["matched_anti_patterns"]
            self.assertTrue(aps, "race cluster must produce at least one anti-pattern row")
            # Each row must be either a real go.* pid or the gap sentinel.
            for ap in aps:
                self.assertTrue(
                    ap.startswith("go.") or ap.startswith("no-P3-match:"),
                    f"unexpected anti-pattern shape: {ap}",
                )
            # At least one REAL pid must fire (atomicity-and-ordering has
            # 3 Go yamls shipped by lane-P3-GO-PRESCAFF).
            real_pids = [ap for ap in aps if not ap.startswith("no-P3-match:")]
            self.assertGreater(
                len(real_pids), 0,
                "race -> atomicity-and-ordering must match real Go P3 pattern_ids",
            )

    # --- 14b-sentinel: gap path verified via deliberately unmapped lang ----
    def test_mvp2_no_p3_match_sentinel_for_missing_lang(self) -> None:
        """The ``no-P3-match:<cat>:<lang>`` sentinel must fire whenever
        a cluster resolves to a P3 category that has zero yamls for the
        cluster's lang. Uses the ``_match_p3_for_cluster`` helper with a
        synthetic 'cairo'-suffixed slug to force a no-match.
        """
        p3_index = ltir_mod._load_p3_patterns()
        # Synthesize a cluster slug that resolves to a real P3 cat but
        # whose lang has no yaml. Cairo is not in any v2 yaml subdir.
        synthetic = "cairo.crypto.race.unsync"
        result = ltir_mod._match_p3_for_cluster(synthetic, p3_index=p3_index)
        self.assertEqual(len(result), 1)
        self.assertTrue(
            result[0].startswith("no-P3-match:"),
            f"missing-lang cluster must emit gap sentinel, got: {result}",
        )

    # --- 14c. MVP2 compose: composability_score computation ----------------
    def test_mvp2_composability_score_correct(self) -> None:
        """``composability_score`` equals len(real_p3) + len(semantic_p1).

        no-P3-match sentinels and topical-only P1 hits do NOT count toward
        the score.
        """
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        for ep in report["entry_points"]:
            real_p3 = [
                pid for pid in ep["matched_anti_patterns"]
                if not pid.startswith("no-P3-match")
            ]
            expected = len(real_p3) + len(ep["semantic_p1_invariants"])
            self.assertEqual(
                ep["composability_score"], expected,
                f"composability_score mismatch for {ep['cluster_id']}: "
                f"got {ep['composability_score']}, expected {expected} "
                f"(real_p3={len(real_p3)}, semantic_p1={len(ep['semantic_p1_invariants'])})",
            )

    # --- 14d. MVP2 compose: bucket bump on high composability --------------
    def test_mvp2_composability_bucket_bump(self) -> None:
        """When composability_score >= threshold, an entry must be bumped
        one priority bucket up (LOW -> MEDIUM, MEDIUM -> HIGH-PRIORITY-HUNT).
        """
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        bumped = [
            e for e in report["entry_points"]
            if e.get("composability_bucket_bumped")
        ]
        for ep in bumped:
            self.assertGreaterEqual(
                ep["composability_score"],
                ltir_mod.COMPOSABILITY_BUMP_THRESHOLD,
                "bucket_bumped entries must meet the threshold",
            )
            base = ep["hunt_priority_base"]
            now = ep["hunt_priority"]
            # base LOW -> now MEDIUM, or base MEDIUM -> now HIGH
            valid_promotions = {
                ("LOW-PRIORITY", "MEDIUM-PRIORITY"),
                ("MEDIUM-PRIORITY", "HIGH-PRIORITY-HUNT"),
            }
            self.assertIn(
                (base, now), valid_promotions,
                f"unexpected bump path: {base} -> {now}",
            )

    # --- 14e. MVP2 schema validity (v2 superset of v1) ---------------------
    def test_mvp2_schema_v2_validity(self) -> None:
        """Schema bumped to v3; v2 fields plus P1/P4 compose fields present."""
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        self.assertEqual(report["schema"], "auditooor.live_target_intelligence.v3")
        self.assertEqual(ltir_mod.SCHEMA, "auditooor.live_target_intelligence.v3")
        self.assertEqual(ltir_mod.SCHEMA_V2, "auditooor.live_target_intelligence.v2")
        # V2/V3-canonical entry-level fields
        for ep in report["entry_points"]:
            for required in (
                "matched_p1_invariants",
                "semantic_p1_invariants",
                "topical_p1_invariants",
                "p1_match_tier",
                "p1_semantic_invariant_gaps",
                "composability_score",
                "composability_bucket_bumped",
                "hunt_priority_base",
                "p4_triager_precheck",
                "false_positive_suppression",
            ):
                self.assertIn(
                    required, ep,
                    f"V3 entry missing required field: {required}",
                )
        # V1-compat fields still present per superset contract
        for ep in report["entry_points"]:
            for v1_required in (
                "file_line", "cluster_id", "engage_severity_score",
                "hunt_priority", "matched_anti_patterns", "p1_invariant_hits",
            ):
                self.assertIn(v1_required, ep)
        # Summary card composability stats present
        comp = report["summary_card"].get("composability")
        self.assertIsNotNone(comp, "summary_card.composability must exist in V2")
        for cs_field in (
            "p1_corpus_size", "p3_catalog_size", "composability_score_max",
            "composability_score_min", "composability_score_avg",
            "entries_bucket_bumped", "composability_bump_threshold",
            "p1_match_tier_counts", "p1_semantic_gap_counts",
            "documented_fp_suppressed_entries",
        ):
            self.assertIn(cs_field, comp)
        self.assertIn("p4_triager_precheck", report["summary_card"])
        # Provenance mvp_phase bumped
        self.assertEqual(report["provenance"]["mvp_phase"], "MVP3")

    # --- 14f. MVP1 callers still get all v1 fields (backward-compat) -------
    def test_v1_backward_compat_field_presence(self) -> None:
        """A V1-era consumer reading the v2 output must still find every
        v1 field (entry-level + top-level). v1 schema-id is still exposed
        as SCHEMA_V1 for callers that want a fallback constant.
        """
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws)
        self.assertEqual(
            ltir_mod.SCHEMA_V1, "auditooor.live_target_intelligence.v1",
            "SCHEMA_V1 must be exposed for downstream-fallback callers",
        )
        # All v1 top-level required fields present
        for required in (
            "schema", "tool_version", "workspace", "audit_pin", "summary_card",
            "entry_points", "prioritized_hunt_list", "coverage_gaps",
            "prior_audit_deltas", "operator_action_queue", "provenance", "errors",
        ):
            self.assertIn(required, report)

    # --- 14. CLI smoke ------------------------------------------------------
    def test_cli_json_smoke(self) -> None:
        _seed_workspace(self.ws)
        import subprocess
        import sys as _sys
        proc = subprocess.run(
            [
                _sys.executable,
                str(_TOOL_PATH),
                "--workspace",
                str(self.ws),
                "--json",
                "--top-n",
                "3",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # First line should be a no-op markdown line; locate the JSON.
        out = proc.stdout.strip()
        # We emit JSON then markdown; parse the JSON object
        json_end = out.rindex("}") + 1
        # Find the matching opening brace
        json_start = out.index("{")
        data = json.loads(out[json_start:json_end])
        self.assertEqual(data["schema"], ltir_mod.SCHEMA)


class VaultLiveTargetReportCallableTest(unittest.TestCase):
    """Test the vault_live_target_report MCP callable wiring.

    The callable should be a thin reader: load an existing report from disk
    if present, otherwise generate one fresh. Supports filters: min_priority,
    cluster_id, limit.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "fake_workspace"
        _seed_workspace(self.ws)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_callable_via_module_function(self) -> None:
        """Verify the callable shape directly via build_report.

        The MCP server wraps build_report; we test the shape contract here
        since the MCP server import is heavy and tested separately in the
        live MCP integration test.
        """
        report = ltir_mod.build_report(self.ws, top_n=10)
        # Filter limit=2 applied client-side simulates the MCP callable
        limited = report["entry_points"][:2]
        self.assertLessEqual(len(limited), 2)
        # Min-priority filter
        high_only = [e for e in report["entry_points"]
                     if e["hunt_priority"] == "HIGH-PRIORITY-HUNT"]
        self.assertEqual(
            sum(1 for e in high_only if e["hunt_priority"] != "HIGH-PRIORITY-HUNT"),
            0,
        )
        # Cluster-id filter
        cluster_id = "go.go.panic.dereference_before_nil_check"
        filtered = [e for e in report["entry_points"] if e["cluster_id"] == cluster_id]
        for e in filtered:
            self.assertEqual(e["cluster_id"], cluster_id)

    def test_mcp_callable_regenerates_stale_cached_json(self) -> None:
        docs = self.ws / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        (docs / "LIVE_TARGET_REPORT.json").write_text(
            json.dumps(
                {
                    "schema": ltir_mod.SCHEMA,
                    "tool_version": "0.3.0",
                    "provenance": {
                        "tool_version": "0.3.0",
                        "mvp_phase": "MVP2",
                    },
                    "summary_card": {},
                    "entry_points": [
                        {
                            "file_line": "stale.sol:1",
                            "cluster_id": "stale",
                            "hunt_priority": "HIGH-PRIORITY-HUNT",
                            "engage_severity_score": 999,
                        }
                    ],
                    "coverage_gaps": [],
                    "prior_audit_deltas": [],
                    "operator_action_queue": [],
                }
            ),
            encoding="utf-8",
        )

        vault_mod = _load_vault_mcp_module()
        vault_dir = Path(self._tmp.name) / "vault"
        vault_dir.mkdir()
        vault = vault_mod.VaultQuery(vault_dir, repo_root=_HERE.parents[1])
        result = vault.vault_live_target_report(workspace_path=str(self.ws), limit=5)

        self.assertFalse(result["degraded"], result.get("reason"))
        self.assertEqual(result["tool_version"], ltir_mod.TOOL_VERSION)
        self.assertEqual(result["report_freshness"]["status"], "regenerated_from_stale_cache")
        self.assertEqual(result["report_freshness"]["cached_status"], "stale_tool_version")
        self.assertTrue(result["report_freshness"]["safe_to_treat_as_current"])
        self.assertFalse(
            any(ep.get("file_line") == "stale.sol:1" for ep in result["entry_points"]),
            "MCP callable must not serve stale cached CAP-007/CAP-015 report rows",
        )


def _seed_workspace_md_only(
    root: Path,
    audit_pin_sha: str = "5ee9766351ef864856a309a971b13fdd98cae2c5",
) -> None:
    """Seed a workspace with engage_report.md but NO engage_report.json.

    Mirrors the polymarket / morpho real-world workspace shape that
    triggered the P5 MVP1.1 .md-fallback work (lane P5-MVP1.1-MD-FALLBACK,
    2026-05-23). The .md schema follows the polymarket emit:
        ### Cluster: `<slug>` (<n> hits)
        - **[<SEV>] `<slug>`** -- `<file:line>`
          - snippet: `...`
    """
    root.mkdir(parents=True, exist_ok=True)
    auditooor = root / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "commit_lifecycle_ledger.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.commit_lifecycle_ledger.v1",
                "audit_pin_sha": audit_pin_sha,
                "head_sha": "",
            }
        )
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.intake_baseline.v1",
                "workspace": str(root),
                "assets_in_scope": ["solidity"],
                "file_extension_counts": {".sol": 12, ".md": 4},
            }
        )
    )
    # polymarket-shape engage_report.md
    md_body = (
        "# Engagement Report -- fake-workspace\n"
        "\n"
        f"- Workspace: `{root}`\n"
        "- Total hits: **3**\n"
        "- Severity: HIGH=0  MEDIUM=0  LOW=3\n"
        "\n"
        "## Clusters\n"
        "\n"
        "### Cluster: `eip-712-missing-addressthis-in-domain` (2 hits)\n"
        "\n"
        "- **[LOW] `eip-712-missing-addressthis-in-domain`** "
        "-- `src/factories/SafeFactory.sol:21`\n"
        "  - snippet: `bytes32 public constant DOMAIN_TYPEHASH = keccak256(`\n"
        "  - dupe-risk: **SKIPPED**\n"
        "- **[LOW] `eip-712-missing-addressthis-in-domain`** "
        "-- `src/factories/SafeFactory.sol:47`\n"
        "  - snippet: `DOMAIN_TYPEHASH,`\n"
        "\n"
        "### Cluster: `delegatecall-to-state-variable` (1 hits)\n"
        "\n"
        "- **[LOW] `delegatecall-to-state-variable`** "
        "-- `src/factories/ProxyFactory.sol:55`\n"
        "  - snippet: `(bool ok, ) = lib.delegatecall(...);`\n"
        "\n"
        "## No close historical match (best mining candidates)\n"
        "\n"
        "- **[LOW] `eip-712-missing-addressthis-in-domain`** "
        "-- `src/factories/SafeFactory.sol:21`\n"
        "  - bytes32 public constant DOMAIN_TYPEHASH = keccak256(\n"
    )
    (root / "engage_report.md").write_text(md_body)
    (root / "SCOPE.md").write_text("# Scope\n\nIn-scope: src/\n")
    (root / "SEVERITY.md").write_text(
        "# Severity\n\nCritical: loss of funds\nHigh: degradation\n"
        "Medium: minor\nLow: info\n"
    )


class EngageReportMdFallbackTest(unittest.TestCase):
    """MVP1.1 - engage_report.md fallback parser.

    Lane: lane-P5-MVP1.1-MD-FALLBACK (v3 iter18 phase A, 2026-05-23).
    Anchors the polymarket + morpho workspaces (which ship .md only)
    flipping from 0-candidate to N-candidate when this fallback fires.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "fake_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_md_fallback_when_json_absent(self) -> None:
        """polymarket-shape: .md present, .json absent -> fallback fires."""
        _seed_workspace_md_only(self.ws)
        report = ltir_mod.build_report(self.ws)
        # Hits come from the 3 rows in the '## Clusters' section ONLY.
        # The 'best mining candidates' tail duplicates rows and must be
        # excluded by the parser's section-gate.
        self.assertEqual(report["summary_card"]["engage_report_hit_count"], 3)
        # MVP1.1 telemetry must flag this as a .md-fallback path.
        es = report["summary_card"]["engage_severity"]
        self.assertEqual(es["engage_report_source"], "md")
        self.assertTrue(es["engage_report_md_fallback"])
        self.assertFalse(es["engage_report_json_present"])
        self.assertTrue(es["engage_report_md_present"])
        # Entries must be ranked with the same shape as the .json path:
        # cluster_id + file:line + severity present.
        eps = report["entry_points"]
        self.assertTrue(eps, "fallback must emit > 0 entries")
        for ep in eps:
            self.assertTrue(ep["cluster_id"])
            self.assertTrue(ep["file_line"])
            self.assertIn(ep["severity_from_engage"], {"LOW", "MEDIUM", "HIGH", "INFO", "CRITICAL"})
        # Two clusters declared, both surfaced.
        cluster_ids = {ep["cluster_id"] for ep in eps}
        self.assertIn("eip-712-missing-addressthis-in-domain", cluster_ids)
        self.assertIn("delegatecall-to-state-variable", cluster_ids)

    def test_json_only_existing_behavior_unchanged(self) -> None:
        """.json present + .md absent -> v1/v2 behavior preserved, no fallback flag."""
        _seed_workspace(self.ws)  # creates engage_report.json, no .md
        report = ltir_mod.build_report(self.ws)
        self.assertGreater(report["summary_card"]["engage_report_hit_count"], 0)
        es = report["summary_card"]["engage_severity"]
        self.assertEqual(es["engage_report_source"], "json")
        self.assertFalse(es["engage_report_md_fallback"])
        self.assertTrue(es["engage_report_json_present"])
        self.assertFalse(es["engage_report_md_present"])
        # Strict mode must still succeed (regression check on signature change).
        report_strict = ltir_mod.build_report(self.ws, strict=True)
        self.assertEqual(report_strict["schema"], ltir_mod.SCHEMA)

    def test_both_present_json_wins(self) -> None:
        """Both .json and .md present -> .json is canonical; .md is ignored."""
        _seed_workspace(self.ws)  # writes .json with 2 clusters / 4 hits total
        # Now also drop a .md with a DIFFERENT cluster id so we can prove
        # the .json path beat it.
        (self.ws / "engage_report.md").write_text(
            "## Clusters\n\n"
            "### Cluster: `should-not-appear-md-only-cluster` (1 hits)\n\n"
            "- **[LOW] `should-not-appear-md-only-cluster`** "
            "-- `src/Foo.sol:1`\n"
            "  - snippet: `not the canonical source`\n"
        )
        report = ltir_mod.build_report(self.ws)
        es = report["summary_card"]["engage_severity"]
        self.assertEqual(es["engage_report_source"], "json")
        self.assertFalse(es["engage_report_md_fallback"])
        self.assertTrue(es["engage_report_json_present"])
        self.assertTrue(es["engage_report_md_present"])
        # The .md-only cluster must NOT bleed into entry_points.
        cluster_ids = {ep["cluster_id"] for ep in report["entry_points"]}
        self.assertNotIn("should-not-appear-md-only-cluster", cluster_ids)

    def test_md_fallback_strict_mode_succeeds(self) -> None:
        """Strict mode must accept .md-only workspaces (not just .json)."""
        _seed_workspace_md_only(self.ws)
        report = ltir_mod.build_report(self.ws, strict=True)
        self.assertEqual(report["schema"], ltir_mod.SCHEMA)
        self.assertGreater(len(report["entry_points"]), 0)

    def test_both_absent_emits_zero_entries(self) -> None:
        """No .json AND no .md -> zero entries + telemetry flags both absent."""
        self.ws.mkdir(parents=True, exist_ok=True)
        (self.ws / "INTAKE_BASELINE.json").write_text(
            json.dumps({"file_extension_counts": {".sol": 1}})
        )
        report = ltir_mod.build_report(self.ws, strict=False)
        self.assertEqual(report["entry_points"], [])
        es = report["summary_card"]["engage_severity"]
        self.assertEqual(es["engage_report_source"], "none")
        self.assertFalse(es["engage_report_md_fallback"])
        self.assertFalse(es["engage_report_json_present"])
        self.assertFalse(es["engage_report_md_present"])


# ---------------------------------------------------------------------------
# CAP-001 (score-uniformity tiebreaker) + CAP-003 (P1 invariant matcher
# loosened for descriptive kebab-case cluster slugs). Anchored to the live
# Hyperbridge dogfood failure mode where 30 entries all scored 51.9 and
# p1_invariant_hits was empty for every one.
# ---------------------------------------------------------------------------


def _seed_workspace_uniform_low_clusters(
    root: Path,
    n_clusters: int = 12,
    *,
    vary_sizes: bool = False,
) -> None:
    """Seed a workspace whose engage_report mimics the Hyperbridge shape:

    - Every cluster carries the SAME severity (LOW); raw rank score thus
      collapses to a single value (the CAP-001 anchor).
    - Cluster slugs use descriptive kebab-case (no lang prefix dots) so
      the token-based resolver would produce (None, None) without the
      CAP-003 keyword fallback.
    - File paths are all .sol so the file-hint lang derivation can fire.
    - All clusters have the SAME hit_count=3 by default (the exact
      Hyperbridge dogfood shape that collapsed to 51.9 uniform).
    - When ``vary_sizes=True`` cluster sizes vary (1/2/3/5/8/15) so the
      density tiebreaker has something to grade. Used by the
      coverage-gap-isolation test where the density signal is held equal
      across covered vs uncovered groups.
    """
    root.mkdir(parents=True, exist_ok=True)
    auditooor = root / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "commit_lifecycle_ledger.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.commit_lifecycle_ledger.v1",
                "audit_pin_sha": "70c8429d9b5c7c3260e37c02714c4026601dabd3",
            }
        )
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.intake_baseline.v1",
                "workspace": str(root),
                "assets_in_scope": ["Blockchain/DLT"],
                "file_extension_counts": {".sol": 100, ".rs": 50},
            }
        )
    )
    descriptive_slugs = [
        "external-call-before-state-update",
        "unchecked-low-level-call",
        "division-by-zero",
        "downcast-uint256-to-smaller",
        "unbounded-loop-external-call",
        "constructor-no-zero-address-check",
        "missing-unpause-function",
        "delete-enumerable-set-struct",
        "fee-on-transfer-not-accounted",
        "pausable-no-unpause-exposed",
        "named-return-shadows-storage",
        "erc-2771-msgSender-forgery",
        "transfer-return-not-checked",
        "state-variable-shadowing",
        "uniswap-v4-poolkey-no-whitelist",
    ][:n_clusters]
    sizes_cycle = [1, 2, 3, 5, 8, 15, 3, 3, 3, 3, 3, 3, 3, 3, 3] if vary_sizes else [3] * 15
    clusters = []
    for idx, slug in enumerate(descriptive_slugs):
        size = sizes_cycle[idx % len(sizes_cycle)]
        # Two clusters share the SAME file path for the file-overlap signal
        # (only when vary_sizes is enabled so the uniform-shape test isn't
        # contaminated by the overlap signal).
        if vary_sizes and idx in (1, 2):
            shared_file = "src/shared/Common.sol"
        else:
            shared_file = f"src/contracts/{slug}.sol"
        clusters.append(
            {
                "detector_slug": slug,
                "hit_count": size,
                "hits": [
                    {
                        "file_path": f"{shared_file}:{100 + i}",
                        "severity": "LOW",
                        "snippet": f"// {slug} pattern instance {i}",
                    }
                    for i in range(min(size, 3))  # cap to 3 per MAX_ENTRIES_PER_CLUSTER
                ],
            }
        )
    (root / "engage_report.json").write_text(json.dumps({"clusters": clusters}))
    (root / "SEVERITY.md").write_text(
        "# Severity\n\nCritical: loss of funds\nHigh: degradation\n"
    )


class Cap001ScoreUniformityTiebreakerTest(unittest.TestCase):
    """CAP-001: stddev tiebreaker spreads scores when ranking collapses."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "uniform_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_stddev_tiebreaker_activates_on_uniform_scored_workspace(self) -> None:
        """Uniform LOW + uniform cluster size -> tiebreaker MUST fire,
        AND ANY discriminating signal (here: 2 of 12 covered by prior
        submission, the other 10 uncovered) produces a measurable spread.
        """
        _seed_workspace_uniform_low_clusters(self.ws, n_clusters=12)
        # Add 2 covered + 10 uncovered to give the coverage signal a target.
        sub_dir = self.ws / "submissions" / "filed" / "covered"
        sub_dir.mkdir(parents=True, exist_ok=True)
        (sub_dir / "covered.md").write_text(
            "# Prior finding cites `division-by-zero` and "
            "`unchecked-low-level-call`.\n"
        )
        report = ltir_mod.build_report(self.ws, top_n=30)
        tb = report["summary_card"]["score_tiebreaker"]
        # The hyperbridge anchor: ranking collapsed -> tiebreaker active.
        self.assertTrue(
            tb["applied"],
            f"tiebreaker MUST activate on uniform-scored workspace; got {tb}",
        )
        self.assertEqual(tb["reason"], "stddev_below_threshold")
        # Score spread after tiebreaker MUST be measurably larger.
        # Coverage signal alone: +8 uncovered vs -4 covered = 12 pt swing.
        self.assertGreaterEqual(
            tb["score_spread_after"],
            10.0,
            f"score spread post-tiebreaker too small: {tb}",
        )
        # And the stddev itself must have grown.
        self.assertGreater(tb["stddev_after"], tb["stddev_before"])

    def test_stddev_tiebreaker_skipped_on_already_spread_workspace(self) -> None:
        """Mixed severity / cluster sizes -> tiebreaker MUST NOT fire."""
        _seed_workspace(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=30)
        tb = report["summary_card"]["score_tiebreaker"]
        # Baseline seed has 2 clusters with already-different penalties
        # (one is test-evidence path -> -25; the other is external/ -> +5),
        # so the raw stddev is well above threshold and the tiebreaker
        # should skip.
        self.assertFalse(
            tb["applied"],
            f"tiebreaker MUST skip on well-spread workspace; got {tb}",
        )
        self.assertEqual(tb["reason"], "stddev_above_threshold")

    def test_stddev_tiebreaker_uses_coverage_gaps(self) -> None:
        """Tiebreaker rewards clusters with NO existing submission.

        We compare the AVERAGE score across covered vs uncovered entries;
        with the coverage_delta of (+8 uncovered, -4 covered) the means
        must diverge by ~12 points per-cluster when the rest of the
        signal is held equal. We add a controlled set of uncovered
        clusters with the same density profile as the covered ones to
        prove the coverage signal alone moves the needle.
        """
        _seed_workspace_uniform_low_clusters(self.ws, n_clusters=10, vary_sizes=True)
        # Stamp 2 of the 10 clusters as already-covered submissions.
        # Pick clusters at idx 5 and 6 ("constructor-no-zero-address-check",
        # "missing-unpause-function") - both UNIQUE files (no overlap
        # bonus), so coverage_delta is the only differentiating signal.
        covered_slugs = ("constructor-no-zero-address-check", "missing-unpause-function")
        sub_dir = self.ws / "submissions" / "filed" / "covered"
        sub_dir.mkdir(parents=True, exist_ok=True)
        (sub_dir / "covered.md").write_text(
            f"# Prior finding cites detector `{covered_slugs[0]}` and "
            f"`{covered_slugs[1]}`.\n"
        )
        report = ltir_mod.build_report(self.ws, top_n=30)
        # Compare ONLY entries that share the same density+overlap profile
        # (unique-file, same cluster_size bucket) so the coverage signal
        # is the sole differentiator. The fixture's idx 5 cluster has
        # cluster_size=15 (-10 density), idx 6 has size=3 (+5 density).
        # Build per-cluster average to isolate coverage signal.
        per_cluster: dict = {}
        for ep in report["entry_points"]:
            per_cluster.setdefault(ep["cluster_id"], []).append(ep["engage_severity_score"])
        # Average of the 2 covered clusters MUST be strictly less than
        # the average of the 8 uncovered clusters.
        covered_avg_per_cluster = [sum(v) / len(v) for k, v in per_cluster.items() if k in covered_slugs]
        uncovered_avg_per_cluster = [sum(v) / len(v) for k, v in per_cluster.items() if k not in covered_slugs]
        self.assertTrue(covered_avg_per_cluster)
        self.assertTrue(uncovered_avg_per_cluster)
        avg_uncov = sum(uncovered_avg_per_cluster) / len(uncovered_avg_per_cluster)
        avg_cov = sum(covered_avg_per_cluster) / len(covered_avg_per_cluster)
        self.assertGreater(
            avg_uncov, avg_cov,
            f"uncovered avg {avg_uncov} must exceed covered avg {avg_cov}; "
            f"per_cluster={per_cluster}",
        )


class Cap003P1MatcherLoosenedTest(unittest.TestCase):
    """CAP-003: P1 matcher resolves descriptive cluster slugs."""

    def test_keyword_resolver_maps_hyperbridge_slugs(self) -> None:
        """Descriptive kebab-case slugs MUST resolve to a category."""
        cases = [
            ("external-call-before-state-update", "ordering", "external-call-handling"),
            ("unchecked-low-level-call",          "ordering", "external-call-handling"),
            ("division-by-zero",                  "bounds",   "bounds-and-bounds-checks"),
            ("constructor-no-zero-address-check", "authorization", "authorization"),
            ("erc-2771-msgSender-forgery",        "authorization", "authorization"),
            ("uniswap-v4-poolkey-no-whitelist",   "authorization", "authorization"),
            ("ecrecover-without-zero-check",       "uniqueness", "authorization"),
            ("return-bomb-low-level-call",         "return-bomb", "external-call-handling"),
            ("erc4626-asset-not-pulled",           "erc4626", "custody-and-accounting"),
            ("deprecated-safeApprove",             "custody", "custody-and-accounting"),
        ]
        for slug, exp_p1, exp_p3 in cases:
            p1, p3 = ltir_mod._resolve_cluster_category(slug)
            self.assertEqual(
                p1, exp_p1,
                f"slug={slug!r}: expected p1={exp_p1!r}, got {p1!r}",
            )
            self.assertEqual(
                p3, exp_p3,
                f"slug={slug!r}: expected p3={exp_p3!r}, got {p3!r}",
            )

    def test_cluster_lang_falls_back_to_file_extension(self) -> None:
        """When the slug has no lang prefix, derive from file extension."""
        self.assertEqual(
            ltir_mod._cluster_lang("external-call-before-state-update",
                                   file_hint="src/foo.sol:100"),
            "solidity",
        )
        self.assertEqual(
            ltir_mod._cluster_lang("some-descriptive-slug",
                                   file_hint="external/v4-chain/foo.go:42"),
            "go",
        )
        self.assertEqual(
            ltir_mod._cluster_lang("another-slug",
                                   file_hint="crates/some.rs:10"),
            "rust",
        )
        # No file hint and no prefix -> "any" (current behaviour).
        self.assertEqual(
            ltir_mod._cluster_lang("descriptive-slug", file_hint=None),
            "any",
        )

    def test_loosened_p1_matcher_returns_invariants_for_descriptive_slug(self) -> None:
        """The hyperbridge dogfood: P1 matcher returns >=1 invariant per slug.

        Uses a fake p1_index with one invariant in `ordering|solidity` to
        prove the keyword fallback + file_hint lang derivation compose.
        """
        fake_p1_index = {
            "ordering|solidity": ["INV-ORD-001", "INV-ORD-002"],
            "ordering|any": ["INV-ORD-003"],
            "authorization|solidity": ["INV-AUTH-001", "INV-AUTH-002"],
        }
        # Descriptive slug + .sol file -> ordering|solidity hits.
        ids = ltir_mod._match_p1_for_cluster(
            "external-call-before-state-update",
            p1_index=fake_p1_index,
            file_hint="src/foo.sol:100",
        )
        self.assertIn("INV-ORD-001", ids)
        self.assertIn("INV-ORD-002", ids)
        # The any-lang bucket should also surface.
        self.assertIn("INV-ORD-003", ids)
        # Authorization-class slug -> authorization|solidity hits.
        auth_ids = ltir_mod._match_p1_for_cluster(
            "constructor-no-zero-address-check",
            p1_index=fake_p1_index,
            file_hint="src/foo.sol:100",
        )
        self.assertIn("INV-AUTH-001", auth_ids)

    def test_p1_match_count_nonzero_on_hyperbridge_like_workspace(self) -> None:
        """End-to-end: at least 1 entry per cluster carries >=1 P1 invariant.

        Uses the live P1 corpus loaded by build_report; the audited library
        has ordering/authorization/bounds entries for solidity, so the
        hyperbridge-shaped workspace should now surface P1 hits.
        """
        _seed_workspace_uniform_low_clusters(self.ws, n_clusters=10)
        report = ltir_mod.build_report(self.ws, top_n=30)
        # Count entries with non-empty p1 invariant hits.
        entries_with_p1 = sum(
            1 for ep in report["entry_points"]
            if (ep.get("matched_p1_invariants") or ep.get("p1_invariant_hits"))
        )
        # ALL 10 cluster slugs here resolve (ordering/authorization/bounds);
        # ALL have at-least-one matching P1 invariant in the audited corpus.
        # Acceptance bar: at least half the entries must surface P1 hits.
        self.assertGreater(
            entries_with_p1, 0,
            f"FAIL: 0 entries with P1 hits (expected >0 post-CAP-003)",
        )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "uniform_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()


def _seed_workspace_cap_quality(root: Path) -> None:
    """Seed a Solidity workspace for CAP-004..007/CAP-014/CAP-015 checks."""
    root.mkdir(parents=True, exist_ok=True)
    (root / ".auditooor").mkdir(parents=True, exist_ok=True)
    (root / ".auditooor" / "commit_lifecycle_ledger.json").write_text(
        json.dumps({"audit_pin_sha": "1234567890abcdef1234567890abcdef12345678"})
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps({"file_extension_counts": {".sol": 20}})
    )
    src = root / "src"
    src.mkdir()
    (src / "SP1Beefy.sol").write_text(
        "interface IConsensusV2 {\n"
        "  function verify(bytes calldata proof) external returns "
        "(bytes memory, IntermediateState[] memory, uint256);\n"
        "}\n"
        "contract SP1Beefy is IConsensusV2 {\n"
        "  ISP1Verifier verifier;\n"
        "  function verify(bytes calldata proof) external returns "
        "(bytes memory, IntermediateState[] memory, uint256) {\n"
        "    verifier.verifyProof(proof);\n"
        "    return (proof, new IntermediateState[](0), 0);\n"
        "  }\n"
        "}\n"
    )
    (src / "NibbleSlice.sol").write_text(
        "contract NibbleSlice {\n"
        "  uint256 constant NIBBLE_PER_BYTE = 2;\n"
        "  function at(uint256 i) external pure returns (uint256) {\n"
        "    return i / NIBBLE_PER_BYTE;\n"
        "  }\n"
        "}\n"
    )
    (src / "VWAPOracle.sol").write_text(
        "import \"@openzeppelin/contracts/utils/Context.sol\";\n"
        "contract VWAPOracle is Context {\n"
        "  function update() external { address sender = _msgSender(); sender; }\n"
        "}\n"
    )
    (src / "Withdraw.sol").write_text(
        "contract Withdraw {\n"
        "  mapping(address => uint256) internal balances;\n"
        "  function withdraw(uint256 amount) external {\n"
        "    balances[msg.sender] -= amount;\n"
        "    (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
        "    require(ok);\n"
        "  }\n"
        "}\n"
    )
    (src / "PermitVault.sol").write_text(
        "contract PermitVault {\n"
        "  bytes32 public DOMAIN_SEPARATOR;\n"
        "  function permit(address owner, bytes calldata sig) external {\n"
        "    address signer = ECDSA.recover(DOMAIN_SEPARATOR, sig);\n"
        "    require(signer == owner);\n"
        "  }\n"
        "}\n"
    )
    (src / "BroadAuth.sol").write_text(
        "import \"@openzeppelin/contracts/access/Ownable.sol\";\n"
        "contract BroadAuth is Ownable {\n"
        "  function check(bytes32 hash, bytes calldata sig) external onlyOwner {\n"
        "    address signer = ECDSA.recover(hash, sig);\n"
        "    require(signer != address(0));\n"
        "  }\n"
        "}\n"
    )
    clusters = [
        ("inverted-verify-return", "src/SP1Beefy.sol:6", "verifier.verifyProof(proof);"),
        ("division-by-zero", "src/NibbleSlice.sol:4", "return i / NIBBLE_PER_BYTE;"),
        ("erc-2771-msgSender-forgery", "src/VWAPOracle.sol:3", "_msgSender()"),
        ("external-call-before-state-update", "src/Withdraw.sol:5", "balances[msg.sender] -= amount;"),
        ("signature-without-nonce", "src/PermitVault.sol:4", "function permit(address owner, bytes calldata sig)"),
        ("pausable-no-unpause-exposed", "src/BroadAuth.sol:3", "function check(bytes32 hash, bytes calldata sig) external onlyOwner"),
    ]
    (root / "engage_report.json").write_text(
        json.dumps(
            {
                "clusters": [
                    {
                        "detector_slug": slug,
                        "hit_count": 1,
                        "hits": [
                            {
                                "file_path": file_line,
                                "severity": "LOW",
                                "snippet": snippet,
                            }
                        ],
                    }
                    for slug, file_line, snippet in clusters
                ]
            }
        )
    )


def _seed_workspace_cap_018_019(root: Path) -> None:
    """Seed Solidity source-shape regressions for CAP-018/CAP-019."""
    root.mkdir(parents=True, exist_ok=True)
    (root / ".auditooor").mkdir(parents=True, exist_ok=True)
    (root / ".auditooor" / "commit_lifecycle_ledger.json").write_text(
        json.dumps({"audit_pin_sha": "70c8429d9b5c7c3260e37c02714c4026601dabd3"})
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps({"file_extension_counts": {".sol": 10}})
    )
    src = root / "src"
    src.mkdir()

    endpoint_lines = [
        "contract HyperbridgeLzEndpoint {",
        "  error LzV1Disabled();",
        "  bool private paused;",
        "  modifier onlyOwner() { _; }",
        "  modifier whenNotPaused() { require(!paused); _; }",
        "  function pause() external onlyOwner {",
        "    paused = true;",
        "  }",
        "  function unpause() external onlyOwner {",
        "    paused = false;",
        "  }",
    ]
    endpoint_lines.extend(f"  // filler keeps unpause() outside the default source window {i}" for i in range(70))
    endpoint_lines.extend(
        [
            "  function submit(bytes calldata payload) external whenNotPaused {",
            "    payload;",
            "  }",
            "  function lzReceive(uint16, bytes calldata, uint64, bytes calldata) external payable {",
            "    revert LzV1Disabled();",
            "  }",
            "}",
        ]
    )
    submit_line = endpoint_lines.index(
        "  function submit(bytes calldata payload) external whenNotPaused {"
    ) + 1
    tombstone_line = endpoint_lines.index(
        "  function lzReceive(uint16, bytes calldata, uint64, bytes calldata) external payable {"
    ) + 1
    (src / "HyperbridgeLzEndpoint.sol").write_text("\n".join(endpoint_lines) + "\n")

    sibling_lines = [
        "contract AdminController {",
        "  function unpause() external {}",
        "}",
        "contract MissingUnpauseGateway {",
        "  bool private paused;",
        "  modifier whenNotPaused() { require(!paused); _; }",
        "  function pause() external {",
        "    paused = true;",
        "  }",
        "  function submit(bytes calldata payload) external whenNotPaused {",
        "    payload;",
        "  }",
        "}",
    ]
    sibling_line = sibling_lines.index(
        "  function submit(bytes calldata payload) external whenNotPaused {"
    ) + 1
    (src / "SiblingUnpause.sol").write_text("\n".join(sibling_lines) + "\n")

    live_lz_lines = [
        "contract LiveLzReceiver {",
        "  uint256 public nonce;",
        "  function lzReceive(uint16, bytes calldata, uint64, bytes calldata payload) external payable {",
        "    nonce += payload.length;",
        "  }",
        "}",
    ]
    live_lz_line = live_lz_lines.index(
        "  function lzReceive(uint16, bytes calldata, uint64, bytes calldata payload) external payable {"
    ) + 1
    (src / "LiveLzReceiver.sol").write_text("\n".join(live_lz_lines) + "\n")

    clusters = [
        (
            "pausable-no-unpause-exposed-hyperbridge",
            f"src/HyperbridgeLzEndpoint.sol:{submit_line}",
            "function submit(bytes calldata payload) external whenNotPaused",
        ),
        (
            "pausable-no-unpause-exposed-sibling",
            f"src/SiblingUnpause.sol:{sibling_line}",
            "function submit(bytes calldata payload) external whenNotPaused",
        ),
        (
            "lzReceive-no-sender-check-tombstone",
            f"src/HyperbridgeLzEndpoint.sol:{tombstone_line}",
            "revert LzV1Disabled();",
        ),
        (
            "lzReceive-no-sender-check-live",
            f"src/LiveLzReceiver.sol:{live_lz_line}",
            "nonce += payload.length;",
        ),
    ]
    (root / "engage_report.json").write_text(
        json.dumps(
            {
                "clusters": [
                    {
                        "detector_slug": slug,
                        "hit_count": 1,
                        "hits": [
                            {
                                "file_path": file_line,
                                "severity": "LOW",
                                "snippet": snippet,
                            }
                        ],
                    }
                    for slug, file_line, snippet in clusters
                ]
            }
        )
    )


def _seed_workspace_cap_007_remaining(root: Path) -> None:
    """Seed CAP-007 precision cases from Hyperbridge live-target output."""
    root.mkdir(parents=True, exist_ok=True)
    (root / ".auditooor").mkdir(parents=True, exist_ok=True)
    (root / ".auditooor" / "commit_lifecycle_ledger.json").write_text(
        json.dumps({"audit_pin_sha": "70c8429d9b5c7c3260e37c02714c4026601dabd3"})
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps({"file_extension_counts": {".sol": 10}})
    )
    src = root / "src"
    src.mkdir()

    intents_lines = [
        "contract IntentsBaseLike {",
        "  mapping(bytes32 => mapping(address => uint256)) internal _orders;",
        "  bytes32 internal constant TRANSACTION_FEES = bytes32(uint256(1));",
        "  error InsufficientNativeToken();",
        "  struct WithdrawalRequest { bytes32 commitment; address[] tokens; uint256[] amounts; address beneficiary; }",
        "  function _withdraw(WithdrawalRequest memory body, bool finalize) internal {",
        "    address beneficiary = body.beneficiary;",
        "    for (uint256 i; i < body.tokens.length; i++) {",
        "      address token = body.tokens[i];",
        "      uint256 amount = body.amounts[i];",
        "      uint256 escrowed = _orders[body.commitment][token];",
        "      _orders[body.commitment][token] = escrowed - amount;",
        "      if (token == address(0)) {",
        "        (bool sent,) = beneficiary.call{value: amount}(\"\");",
        "        if (!sent) revert InsufficientNativeToken();",
        "      }",
        "    }",
        "    if (finalize) {",
        "      delete _orders[body.commitment][TRANSACTION_FEES];",
        "    }",
        "  }",
        "}",
    ]
    predebit_line = intents_lines.index(
        "        (bool sent,) = beneficiary.call{value: amount}(\"\");"
    ) + 1
    (src / "IntentsBaseLike.sol").write_text("\n".join(intents_lines) + "\n")

    sweep_lines = [
        "contract SweepDustLike {",
        "  event DustSwept(address token, uint256 amount, address beneficiary);",
        "  error InsufficientNativeToken();",
        "  struct SweepDust { address beneficiary; address[] tokens; uint256[] amounts; }",
        "  function _sweepDust(SweepDust memory req) internal {",
        "    for (uint256 i; i < req.tokens.length;) {",
        "      address token = req.tokens[i];",
        "      uint256 amount = req.amounts[i];",
        "      if (token == address(0)) {",
        "        (bool sent,) = req.beneficiary.call{value: amount}(\"\");",
        "        if (!sent) revert InsufficientNativeToken();",
        "      }",
        "      unchecked { ++i; }",
        "      emit DustSwept(token, amount, req.beneficiary);",
        "    }",
        "  }",
        "}",
    ]
    sweep_line = sweep_lines.index(
        "        (bool sent,) = req.beneficiary.call{value: amount}(\"\");"
    ) + 1
    (src / "SweepDustLike.sol").write_text("\n".join(sweep_lines) + "\n")

    vulnerable_lines = [
        "contract VulnerableWithdraw {",
        "  mapping(address => uint256) internal balances;",
        "  function withdraw(uint256 amount) external {",
        "    (bool sent,) = msg.sender.call{value: amount}(\"\");",
        "    require(sent);",
        "    balances[msg.sender] -= amount;",
        "  }",
        "}",
    ]
    vulnerable_line = vulnerable_lines.index(
        "    (bool sent,) = msg.sender.call{value: amount}(\"\");"
    ) + 1
    (src / "VulnerableWithdraw.sol").write_text("\n".join(vulnerable_lines) + "\n")

    clusters = [
        (
            "external-call-before-state-update-predebit",
            f"src/IntentsBaseLike.sol:{predebit_line}",
            "(bool sent,) = beneficiary.call{value: amount}(\"\");",
        ),
        (
            "external-call-before-state-update-no-post-write",
            f"src/SweepDustLike.sol:{sweep_line}",
            "(bool sent,) = req.beneficiary.call{value: amount}(\"\");",
        ),
        (
            "external-call-before-state-update-real",
            f"src/VulnerableWithdraw.sol:{vulnerable_line}",
            "(bool sent,) = msg.sender.call{value: amount}(\"\");",
        ),
    ]
    (root / "engage_report.json").write_text(
        json.dumps(
            {
                "clusters": [
                    {
                        "detector_slug": slug,
                        "hit_count": 1,
                        "hits": [
                            {
                                "file_path": file_line,
                                "severity": "LOW",
                                "snippet": snippet,
                            }
                        ],
                    }
                    for slug, file_line, snippet in clusters
                ]
            }
        )
    )


class CapPhaseAQualityFixesTest(unittest.TestCase):
    """Phase A fixes scoped to live-target report pipeline."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "quality_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_documented_detector_false_positives_are_suppressed(self) -> None:
        _seed_workspace_cap_quality(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=20)
        suppressed = {
            ep["cluster_id"]: ep
            for ep in report["entry_points"]
            if (ep["false_positive_suppression"] or {}).get("suppressed")
        }
        for slug in (
            "inverted-verify-return",
            "division-by-zero",
            "erc-2771-msgSender-forgery",
            "external-call-before-state-update",
        ):
            self.assertIn(slug, suppressed)
            self.assertTrue(suppressed[slug]["false_positive_suppression"]["reasons"])
            self.assertLess(suppressed[slug]["engage_severity_score"], 55)
        comp = report["summary_card"]["composability"]
        self.assertEqual(comp["documented_fp_suppressed_entries"], 4)

    def test_cap007_suppression_stays_in_cited_function_window(self) -> None:
        source_context = """
        function unrelated(bytes32 id, address token, uint256 amount) internal {
          _orders[id][token] = amount;
        }

        function sweep(SweepDust memory req) internal {
          uint256 amount = req.amount;
          (bool sent,) = req.beneficiary.call{value: amount}("");
          require(sent);
        }
        """
        contract_context = """
        contract IntentsBase {
          // session key validation lives elsewhere in this contract
        """
        contract_context += source_context + "}"

        suppression = ltir_mod._detector_false_positive_suppression(
            "external-call-before-state-update",
            file_line="src/IntentsBase.sol:8",
            snippet='(bool sent,) = req.beneficiary.call{value: amount}("");',
            source_context=source_context,
            source_contract_context=contract_context,
        )

        self.assertTrue(suppression["suppressed"])
        self.assertEqual(
            suppression["reasons"],
            ["CAP-007: no post-call storage mutation in cited function window"],
        )

    def test_cap004_tuple_verify_uses_contract_context_but_bool_verify_is_live(self) -> None:
        source_context = """
          function verify(bytes calldata proof) external returns (bytes memory, IntermediateState[] memory, uint256) {
            verifier.verifyProof(proof);
            return (proof, new IntermediateState[](0), 0);
          }
        """
        contract_context = """
        interface IConsensusV2 {
          function verify(bytes calldata proof) external returns (bytes memory, IntermediateState[] memory, uint256);
        }
        contract SP1Beefy is IConsensusV2 {
        """ + source_context + "}"

        suppression = ltir_mod._detector_false_positive_suppression(
            "inverted-verify-return",
            file_line="src/SP1Beefy.sol:80",
            snippet="verifier.verifyProof(proof);",
            source_context=source_context,
            source_contract_context=contract_context,
        )
        self.assertTrue(suppression["suppressed"])

        bool_context = """
        contract BoolVerifier {
          function verifyProof(bytes calldata proof) external returns (bool);
          function check(bytes calldata proof) external {
            require(verifier.verifyProof(proof));
          }
        }
        """
        live = ltir_mod._detector_false_positive_suppression(
            "inverted-verify-return",
            file_line="src/BoolVerifier.sol:5",
            snippet="require(verifier.verifyProof(proof));",
            source_context=bool_context,
            source_contract_context=bool_context,
        )
        self.assertFalse(live["suppressed"])

    def test_cap005_constant_suppression_requires_matching_divisor(self) -> None:
        unrelated_constant = """
        contract Ratios {
          uint256 internal constant SCALE = 1e18;
          function quote(uint256 total, uint256 denominator) external pure returns (uint256) {
            return total / denominator;
          }
        }
        """
        live = ltir_mod._detector_false_positive_suppression(
            "division-by-zero",
            file_line="src/Ratios.sol:5",
            snippet="return total / denominator;",
            source_context=unrelated_constant,
            source_contract_context=unrelated_constant,
        )
        self.assertFalse(live["suppressed"])

        nearby_literal = """
        contract Ratios {
          function quote(uint256 total, uint256 denominator) external pure returns (uint256) {
            uint256 scaled = total / 1e18;
            return total / denominator;
          }
        }
        """
        unsafe_reported_divisor = ltir_mod._detector_false_positive_suppression(
            "division-by-zero",
            file_line="src/Ratios.sol:5",
            snippet="return total / denominator;",
            source_context=nearby_literal,
            source_contract_context=nearby_literal,
        )
        self.assertFalse(unsafe_reported_divisor["suppressed"])

        named_constant = """
        contract NibbleSlice {
          uint256 internal constant NIBBLE_PER_BYTE = 2;
          function at(uint256 i) external pure returns (uint256) {
            return i / NIBBLE_PER_BYTE;
          }
        }
        """
        safe_constant = ltir_mod._detector_false_positive_suppression(
            "division-by-zero",
            file_line="src/NibbleSlice.sol:5",
            snippet="return i / NIBBLE_PER_BYTE;",
            source_context=named_constant,
            source_contract_context=named_constant,
        )
        self.assertTrue(safe_constant["suppressed"])

        modulo_guard = """
        function purchase(uint256 total18d, uint256 scale) external pure returns (uint256) {
          if (total18d % scale != 0) revert PriceNotRepresentable();
          return total18d / scale;
        }
        """
        safe_guard = ltir_mod._detector_false_positive_suppression(
            "division-by-zero",
            file_line="src/BandwidthManager.sol:4",
            snippet="return total18d / scale;",
            source_context=modulo_guard,
            source_contract_context=modulo_guard,
        )
        self.assertTrue(safe_guard["suppressed"])

    def test_cap006_erc2771_forwarder_scope_is_not_suppressed_as_plain_context(self) -> None:
        erc2771_context = """
        import "@openzeppelin/contracts/metatx/ERC2771Context.sol";
        contract Forwarded is ERC2771Context {
          function update() external { address sender = _msgSender(); sender; }
        }
        """
        suppression = ltir_mod._detector_false_positive_suppression(
            "erc-2771-msgSender-forgery",
            file_line="src/Forwarded.sol:4",
            snippet="_msgSender()",
            source_context=erc2771_context,
            source_contract_context=erc2771_context,
        )
        self.assertFalse(suppression["suppressed"])

    def test_semantic_vs_topical_p1_tiers_are_exposed(self) -> None:
        _seed_workspace_cap_quality(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=20)
        semantic = [
            ep for ep in report["entry_points"]
            if ep["cluster_id"] == "signature-without-nonce"
        ][0]
        self.assertEqual(semantic["p1_match_tier"], "SEMANTIC-MATCH")
        self.assertTrue(semantic["semantic_p1_invariants"])
        topical = [
            ep for ep in report["entry_points"]
            if ep["cluster_id"] == "division-by-zero"
        ][0]
        self.assertEqual(topical["p1_match_tier"], "TOPICAL-MATCH")
        broad = [
            ep for ep in report["entry_points"]
            if ep["cluster_id"] == "pausable-no-unpause-exposed"
        ][0]
        self.assertEqual(broad["p1_match_tier"], "TOPICAL-MATCH")
        self.assertEqual(broad["semantic_p1_invariants"], [])
        md = ltir_mod.render_markdown(report)
        self.assertIn("P1 match tiers", md)
        self.assertIn("SEMANTIC-MATCH", md)

    def test_ranking_prioritizes_semantic_over_documented_fp(self) -> None:
        _seed_workspace_cap_quality(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=20)
        ranks = {ep["cluster_id"]: idx for idx, ep in enumerate(report["entry_points"], start=1)}
        self.assertLess(ranks["signature-without-nonce"], ranks["inverted-verify-return"])
        self.assertLess(ranks["signature-without-nonce"], ranks["erc-2771-msgSender-forgery"])

    def test_no_silent_tbd_p3_placeholders(self) -> None:
        _seed_workspace_cap_quality(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=20)
        all_p3 = [
            p3
            for ep in report["entry_points"]
            for p3 in ep["matched_anti_patterns"]
        ]
        self.assertTrue(all_p3)
        self.assertFalse(any(p3.startswith("TBD-P3-") for p3 in all_p3))


class Cap020PredicateLevelP1MatcherTest(unittest.TestCase):
    """CAP-020: semantic P1 requires invariant predicate shape evidence."""

    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "cap020-direct",
            matched_p1=[inv_id],
            file_line="src/Cap020.sol:1",
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_predicate_table_covers_explicit_audited_ids(self) -> None:
        expected = {
                "INV-AUTH-001",
                "INV-AUTH-002",
                "INV-AUTH-003",
                "INV-AUTH-006",
                "INV-AUTH-007",
                "INV-AUTH-008",
                "INV-AUTH-009",
                "INV-ATOM-004",
                "INV-BND-003",
                "INV-BND-004",
                "INV-BND-005",
                "INV-BND-008",
                "INV-BND-010",
                "INV-BRIDGE-001",
                "INV-BRIDGE-002",
                "INV-BRIDGE-003",
                "INV-BRIDGE-004",
                "INV-BRIDGE-005",
                "INV-CON-009",
                "INV-CUST-001",
                "INV-CUST-002",
                "INV-CUST-003",
                "INV-CUST-004",
                "INV-CUST-005",
                "INV-CUST-006",
                "INV-CUST-010",
                "INV-CUST-008",
                "INV-CUST-009",
                "INV-DEFI-001",
                "INV-DEFI-002",
                "INV-DEFI-003",
                "INV-ERC4626-001",
                "INV-RET-001",
                "INV-DET-001",
                "INV-DET-005",
                "INV-DET-008",
                "INV-FRESH-008",
                "INV-FRESH-010",
                "INV-MON-001",
                "INV-MON-003",
                "INV-MON-004",
                "INV-MON-006",
                "INV-MON-008",
                "INV-MON-010",
                "INV-COSMOS-001",
                "INV-COSMOS-002",
                "INV-COSMOS-003",
                "INV-COSMOS-004",
                "INV-ORD-003",
                "INV-ORD-004",
                "INV-ORD-006",
                "INV-ORD-007",
                "INV-ORD-009",
                "INV-L2-001",
                "INV-L2-002",
                "INV-L2-003",
                "INV-L2-004",
                "INV-SUB-001",
                "INV-SUB-002",
                "INV-SUB-003",
                "INV-UNI-002",
                "INV-UNI-010",
                "INV-LN-001",
                "INV-LN-002",
                "INV-LN-003",
                "INV-LN-004",
                "INV-MOVE-001",
                "INV-MOVE-002",
                "INV-MOVE-003",
                "INV-SOL-001",
                "INV-SOL-002",
                "INV-SOL-003",
                "INV-ZK-001",
                "INV-ZK-002",
                "INV-ZK-003",
            }
        self.assertTrue(
            expected.issubset(set(ltir_mod.P1_INVARIANT_PREDICATES)),
            "predicate table must at least include requested CAP-020/021 IDs",
        )

    def test_semantic_p1_rejects_broad_auth_category_evidence(self) -> None:
        broad_auth_context = """
        import "@openzeppelin/contracts/access/Ownable.sol";
        import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
        contract BroadAuth is Ownable {
          function check(bytes32 hash, bytes calldata sig) external onlyOwner {
            address signer = ECDSA.recover(hash, sig);
            require(signer != address(0));
          }
        }
        """

        self.assertEqual(
            ltir_mod._semantic_p1_matches(
                "constructor-no-zero-address-check",
                matched_p1=["INV-AUTH-001", "INV-AUTH-002", "INV-AUTH-003"],
                file_line="src/BroadAuth.sol:4",
                snippet="import Ownable; ECDSA.recover(hash, sig); onlyOwner",
                source_context=broad_auth_context,
                source_contract_context=broad_auth_context,
            ),
            [],
            "Ownable/onlyOwner/ECDSA category evidence must stay topical-only",
        )

    def test_semantic_p1_accepts_missing_nonce_predicate(self) -> None:
        missing_nonce_context = """
        contract MissingNonceSignature {
          bytes32 public DOMAIN_SEPARATOR;
          function verify(address owner, bytes calldata sig) external view returns (bool) {
            address signer = ECDSA.recover(DOMAIN_SEPARATOR, sig);
            return signer == owner;
          }
        }
        """

        self.assertEqual(
            ltir_mod._semantic_p1_matches(
                "signature-without-nonce",
                matched_p1=["INV-UNI-002"],
                file_line="src/MissingNonceSignature.sol:4",
                snippet="ECDSA.recover(DOMAIN_SEPARATOR, sig)",
                source_context=missing_nonce_context,
            ),
            ["INV-UNI-002"],
            "EIP-712/ECDSA signature paths without nonce advancement are semantic for INV-UNI-002",
        )

    def test_semantic_p1_accepts_erc4626_no_slippage_predicate(self) -> None:
        source = """
        contract Vault {
          function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
            shares = manager.deposit(assets, receiver, msg.sender);
            asset.safeTransferFrom(msg.sender, address(this), assets);
          }
        }
        """
        self.assertEqual(self._semantic("INV-ERC4626-001", source), ["INV-ERC4626-001"])

    def test_semantic_p1_accepts_return_bomb_decode_predicate(self) -> None:
        source = """
        library SafeERC20Lib {
          function safeTransfer(address token, address to, uint256 amount) internal {
            (, bytes memory returndata) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
            require(returndata.length == 0 || abi.decode(returndata, (bool)));
          }
        }
        """
        self.assertEqual(self._semantic("INV-RET-001", source), ["INV-RET-001"])

    def test_semantic_p1_missing_nonce_not_masked_by_sibling_nonce_bump(self) -> None:
        mixed_nonce_context = """
        contract MixedNonceSignature {
          bytes32 public DOMAIN_SEPARATOR;
          mapping(address => uint256) public nonces;
          function verifyMissing(address owner, bytes calldata sig) external view returns (bool) {
            address signer = ECDSA.recover(DOMAIN_SEPARATOR, sig);
            return signer == owner;
          }
          function consumeElsewhere(address owner) external {
            nonces[owner]++;
          }
        }
        """

        self.assertEqual(
            ltir_mod._semantic_p1_matches(
                "signature-without-nonce",
                matched_p1=["INV-UNI-002"],
                file_line="src/MixedNonceSignature.sol:5",
                snippet="ECDSA.recover(DOMAIN_SEPARATOR, sig)",
                source_context=mixed_nonce_context,
                source_contract_context=mixed_nonce_context,
            ),
            ["INV-UNI-002"],
        )

    def test_semantic_p1_rejects_nonce_consumed_signature_path(self) -> None:
        nonce_consumption_context = """
        contract PermitVault {
          bytes32 public DOMAIN_SEPARATOR;
          mapping(address => uint256) public nonces;
          function permit(address owner, bytes calldata sig) external {
            address signer = ECDSA.recover(DOMAIN_SEPARATOR, sig);
            require(signer == owner);
            nonces[owner]++;
          }
        }
        """

        self.assertEqual(
            ltir_mod._semantic_p1_matches(
                "signature-without-nonce",
                matched_p1=["INV-UNI-002", "INV-AUTH-001"],
                file_line="src/PermitVault.sol:5",
                snippet="nonces[owner]++; ECDSA.recover(DOMAIN_SEPARATOR, sig)",
                source_context=nonce_consumption_context,
            ),
            [],
            "Nonce advancement satisfies the invariant and must not be flagged as semantic violation",
        )

    def test_predicate_positive_shapes_become_semantic(self) -> None:
        cases = {
            "INV-AUTH-001": (
                "contract BadUUPS is UUPSUpgradeable {\n"
                "  function _authorizeUpgrade(address) internal override {}\n"
                "}\n"
            ),
            "INV-AUTH-002": (
                "contract Bad1271 {\n"
                "  bytes4 constant MAGICVALUE = 0x1626ba7e;\n"
                "  function validate(address wallet, bytes32 hash, bytes calldata sig) external view returns (bool) {\n"
                "    return IERC1271(wallet).isValidSignature(hash, sig) == MAGICVALUE;\n"
                "  }\n"
                "}\n"
            ),
            "INV-AUTH-003": (
                "contract MutableGov {\n"
                "  struct Proposal { address[] targets; uint256[] values; bytes[] calldatas; }\n"
                "  mapping(uint256 => Proposal) proposals;\n"
                "  function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas) external {}\n"
                "  function execute(uint256 proposalId) external {}\n"
                "  function updateProposalTargets(uint256 proposalId, address[] calldata targets) external {\n"
                "    proposals[proposalId].targets = targets;\n"
                "  }\n"
                "}\n"
            ),
            "INV-ATOM-004": (
                "contract StandalonePermit {\n"
                "  function permit(address owner, bytes calldata sig) external { owner; sig; }\n"
                "}\n"
            ),
            "INV-BND-004": (
                "contract BadLeverage {\n"
                "  function openPosition(uint256 leverage) external { positions[msg.sender] = leverage; }\n"
                "}\n"
            ),
            "INV-BND-008": (
                "contract BadSubtract {\n"
                "  mapping(address => uint256) balances;\n"
                "  function withdraw(uint256 amount) external { balances[msg.sender] -= amount; }\n"
                "}\n"
            ),
        }
        for inv_id, source in cases.items():
            self.assertEqual(self._semantic(inv_id, source), [inv_id], inv_id)

    def test_safe_or_unsupported_ids_remain_topical(self) -> None:
        safe_uups = (
            "contract SafeUUPS is UUPSUpgradeable {\n"
            "  function _authorizeUpgrade(address) internal override onlyOwner {}\n"
            "}\n"
        )
        self.assertEqual(self._semantic("INV-AUTH-001", safe_uups), [])

        matched = ["INV-UNI-003", "INV-UNI-004"]
        self.assertTrue(all(inv_id not in ltir_mod.P1_INVARIANT_PREDICATES for inv_id in matched))
        semantic = ltir_mod._semantic_p1_matches(
            "external-call-before-state-update",
            matched_p1=matched,
            file_line="src/TopicalOnly.sol:1",
            snippet="swap and allowance words are topical only",
            source_context="contract TopicalOnly { function transferFrom(address,address,uint256) external {} }",
            source_contract_context="contract TopicalOnly { function transferFrom(address,address,uint256) external {} }",
        )
        self.assertEqual(semantic, [])
        self.assertEqual(
            ltir_mod._p1_match_tier(matched_p1=matched, semantic_p1=semantic),
            "TOPICAL-MATCH",
        )

    def test_hyperbridge_call_shape_does_not_make_ordering_slug_semantic(self) -> None:
        hyperbridge_call_context = """
        contract HyperbridgeWithdraw {
          mapping(address => uint256) balances;
          mapping(address => uint256) paidOut;
          function withdraw(uint256 amount) external {
            (bool sent,) = msg.sender.call{value: amount}("");
            require(sent);
            balances[msg.sender] -= amount;
            paidOut[msg.sender] = amount;
          }
        }
        """

        matched = ["INV-ORD-004", "INV-ORD-006", "INV-ORD-001"]
        semantic = ltir_mod._semantic_p1_matches(
            "external-call-before-state-update",
            matched_p1=matched,
            file_line="src/HyperbridgeWithdraw.sol:6",
            snippet='(bool sent,) = msg.sender.call{value: amount}("");',
            source_context=hyperbridge_call_context,
            source_contract_context=hyperbridge_call_context,
        )

        self.assertEqual(
            semantic,
            [],
            "Hyperbridge ordering rows need an invariant predicate/source proof, not just a call-shaped slug hit",
        )
        self.assertEqual(
            ltir_mod._p1_match_tier(matched_p1=matched, semantic_p1=semantic),
            "TOPICAL-MATCH",
        )


class AcceptedP1SourceProofSemanticMatchTest(unittest.TestCase):
    """Accepted local-review P1 source proofs can add semantic P1 evidence."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "accepted_p1_sourceproof_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _seed(self) -> None:
        self.ws.mkdir(parents=True, exist_ok=True)
        auditooor = self.ws / ".auditooor"
        auditooor.mkdir(parents=True, exist_ok=True)
        (auditooor / "commit_lifecycle_ledger.json").write_text(
            json.dumps({"audit_pin_sha": "abcdef0123456789abcdef0123456789abcdef01"})
        )
        (self.ws / "INTAKE_BASELINE.json").write_text(
            json.dumps({"file_extension_counts": {".sol": 1}})
        )
        src = self.ws / "src"
        src.mkdir()
        (src / "Wrapper.sol").write_text(
            "contract Wrapper {\n"
            "  address immutable _deployer;\n"
            "  function swapETHForExactTokens(uint256 amountOut) external payable returns (uint256[] memory amounts) {\n"
            "    PoolKey memory poolKey = _createPoolKey(amountOut);\n"
            "    uint256 spent = amountOut;\n"
            "    if (spent < msg.value) {\n"
            "      uint256 refund = msg.value - spent;\n"
            "      (bool success,) = _deployer.call{value: refund}(\"\");\n"
            "      require(success);\n"
            "    }\n"
            "    amounts = new uint256[](2);\n"
            "  }\n"
            "  function quote(uint256 amountOut) external view returns (uint256) {\n"
            "    PoolKey memory poolKey = _createPoolKey(amountOut);\n"
            "    return amountOut;\n"
            "  }\n"
            "}\n"
        )
        proof_dir = self.ws / "source_proofs" / "accepted-refund"
        proof_dir.mkdir(parents=True)
        proof = {
            "candidate_id": "accepted-refund",
            "final_verdict": "proved_executed_poc",
            "blockers": [],
            "impact_contract": {
                "source_refs": ["src/Wrapper.sol:6-9"],
            },
        }
        (proof_dir / "source_proof.json").write_text(json.dumps(proof))
        sidecar = {
            "schema": "auditooor.p1_invariant_attribution_sidecar.v1",
            "mappings": [
                {
                    "candidate_id": "accepted-refund",
                    "p1_invariant_id": "INV-CUST-011",
                    "attribution_status": "accepted_by_local_review",
                    "evidence_refs": ["source_proofs/accepted-refund/source_proof.json"],
                }
            ],
        }
        (auditooor / "p1_invariant_attribution_sidecar.json").write_text(json.dumps(sidecar))
        clusters = [
            {
                "detector_slug": "uniswap-v4-poolkey-no-whitelist",
                "hit_count": 1,
                "hits": [
                    {
                        "file_path": "src/Wrapper.sol:8",
                        "severity": "LOW",
                        "snippet": "(bool success,) = _deployer.call{value: refund}(\"\");",
                    }
                ],
            },
            {
                "detector_slug": "uniswap-v4-poolkey-no-whitelist-safe",
                "hit_count": 1,
                "hits": [
                    {
                        "file_path": "src/Wrapper.sol:14",
                        "severity": "LOW",
                        "snippet": "PoolKey memory poolKey = _createPoolKey(amountOut);",
                    }
                ],
            },
        ]
        (self.ws / "engage_report.json").write_text(json.dumps({"clusters": clusters}))

    def test_source_proof_exact_line_overlap_promotes_accepted_mapping(self) -> None:
        self._seed()
        report = ltir_mod.build_report(self.ws, top_n=10)
        by_line = {entry["file_line"]: entry for entry in report["entry_points"]}

        semantic = by_line["src/Wrapper.sol:8"]
        self.assertEqual(semantic["p1_match_tier"], "SEMANTIC-MATCH")
        self.assertIn("INV-CUST-011", semantic["matched_p1_invariants"])
        self.assertIn("INV-CUST-011", semantic["semantic_p1_invariants"])
        self.assertTrue(semantic["accepted_p1_source_proof_matches"])
        self.assertEqual(
            semantic["accepted_p1_source_proof_matches"][0]["basis"],
            "accepted_by_local_review_source_proof",
        )

        unrelated = by_line["src/Wrapper.sol:14"]
        self.assertNotIn("INV-CUST-011", unrelated["semantic_p1_invariants"])
        self.assertFalse(unrelated["accepted_p1_source_proof_matches"])

    def test_rejected_or_blocked_source_proof_does_not_promote(self) -> None:
        self._seed()
        sidecar_path = self.ws / ".auditooor" / "p1_invariant_attribution_sidecar.json"
        sidecar = json.loads(sidecar_path.read_text())
        sidecar["mappings"][0]["attribution_status"] = "suggested_only"
        sidecar_path.write_text(json.dumps(sidecar))

        report = ltir_mod.build_report(self.ws, top_n=10)
        first = {entry["file_line"]: entry for entry in report["entry_points"]}["src/Wrapper.sol:8"]
        self.assertNotIn("INV-CUST-011", first["semantic_p1_invariants"])
        self.assertFalse(first["accepted_p1_source_proof_matches"])

        sidecar["mappings"][0]["attribution_status"] = "accepted_by_local_review"
        sidecar_path.write_text(json.dumps(sidecar))
        proof_path = self.ws / "source_proofs" / "accepted-refund" / "source_proof.json"
        proof = json.loads(proof_path.read_text())
        proof["blockers"] = ["operator_review_pending"]
        proof_path.write_text(json.dumps(proof))

        blocked_report = ltir_mod.build_report(self.ws, top_n=10)
        blocked_first = {
            entry["file_line"]: entry for entry in blocked_report["entry_points"]
        }["src/Wrapper.sol:8"]
        self.assertNotIn("INV-CUST-011", blocked_first["semantic_p1_invariants"])
        self.assertFalse(blocked_first["accepted_p1_source_proof_matches"])


class ShapeClusterPredicateCandidateSchemaConsumerTest(unittest.TestCase):
    """II.17: legacy and parent shape-cluster candidate schemas are consumed safely."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "shape_cluster_candidate_schema_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _seed_base_workspace(self) -> None:
        self.ws.mkdir(parents=True, exist_ok=True)
        auditooor = self.ws / ".auditooor"
        auditooor.mkdir(parents=True, exist_ok=True)
        (auditooor / "commit_lifecycle_ledger.json").write_text(
            json.dumps({"audit_pin_sha": "abcdef0123456789abcdef0123456789abcdef01"})
        )
        (self.ws / "INTAKE_BASELINE.json").write_text(
            json.dumps({"file_extension_counts": {".sol": 2}})
        )
        src = self.ws / "src"
        src.mkdir()
        (src / "Live.sol").write_text(
            "contract Live {\n"
            "  mapping(address => uint256) balances;\n"
            "  function withdrawLive(uint256 amount) external {\n"
            "    (bool sent,) = msg.sender.call{value: amount}(\"\");\n"
            "    require(sent);\n"
            "    balances[msg.sender] = amount;\n"
            "  }\n"
            "}\n"
        )
        (src / "Miss.sol").write_text(
            "contract Miss {\n"
            "  function withdrawMiss(uint256 amount) external {\n"
            "    (bool sent,) = msg.sender.call{value: amount}(\"\");\n"
            "    require(sent);\n"
            "  }\n"
            "}\n"
        )
        (self.ws / "engage_report.json").write_text(
            json.dumps(
                {
                    "clusters": [
                        {
                            "detector_slug": "external-call-before-state-update-live",
                            "hit_count": 1,
                            "hits": [
                                {
                                    "file_path": "src/Live.sol:4",
                                    "severity": "LOW",
                                    "snippet": '(bool sent,) = msg.sender.call{value: amount}("");',
                                }
                            ],
                        },
                        {
                            "detector_slug": "external-call-before-state-update-miss",
                            "hit_count": 1,
                            "hits": [
                                {
                                    "file_path": "src/Miss.sol:3",
                                    "severity": "LOW",
                                    "snippet": '(bool sent,) = msg.sender.call{value: amount}("");',
                                }
                            ],
                        },
                    ]
                }
            )
        )

    def _run_with_candidates(self, rows: list[dict[str, object]]) -> dict[str, object]:
        candidates_path = self.ws / "shape_candidates.jsonl"
        candidates_path.write_text(
            "\n".join(json.dumps(row) for row in rows),
            encoding="utf-8",
        )
        original = os.environ.get("AUDITOOOR_P5_SHAPE_CLUSTER_PREDICATE_CANDIDATES")
        os.environ["AUDITOOOR_P5_SHAPE_CLUSTER_PREDICATE_CANDIDATES"] = str(candidates_path)
        try:
            return ltir_mod.build_report(self.ws, top_n=20)
        finally:
            if original is None:
                os.environ.pop("AUDITOOOR_P5_SHAPE_CLUSTER_PREDICATE_CANDIDATES", None)
            else:
                os.environ["AUDITOOOR_P5_SHAPE_CLUSTER_PREDICATE_CANDIDATES"] = original

    def test_legacy_schema_candidate_promotes_only_when_signature_context_matches(self) -> None:
        self._seed_base_workspace()
        report = self._run_with_candidates(
            [
                {
                    "candidate_id": "legacy-live",
                    "cluster_id": "external-call-before-state-update-live",
                    "invariant_id": "INV-ORD-004",
                    "candidate_status": "pending-live-target-dogfood",
                    "function_signature": "function withdrawLive(uint256 amount) external",
                    "predicate_expression": "balances[msg.sender] = amount",
                    "source_ref": "src/Live.sol:3-6",
                },
                {
                    "candidate_id": "legacy-miss",
                    "cluster_id": "external-call-before-state-update-miss",
                    "invariant_id": "INV-ORD-004",
                    "candidate_status": "pending-live-target-dogfood",
                    "function_signature": "function withdrawElse(uint256 amount) external",
                    "predicate_expression": "balances[msg.sender] = amount",
                },
            ]
        )

        by_cluster = {entry["cluster_id"]: entry for entry in report["entry_points"]}
        live = by_cluster["external-call-before-state-update-live"]
        self.assertEqual(live["p1_match_tier"], "SEMANTIC-MATCH")
        self.assertIn("INV-ORD-004", live["semantic_p1_invariants"])
        self.assertTrue(live["shape_cluster_predicate_matches"])
        self.assertIn(
            "signature",
            live["shape_cluster_predicate_matches"][0]["evidence"],
        )

        miss = by_cluster["external-call-before-state-update-miss"]
        self.assertEqual(miss["p1_match_tier"], "TOPICAL-MATCH")
        self.assertFalse(miss["shape_cluster_predicate_matches"])

    def test_parent_schema_fanout_uses_source_evidence_not_cluster_key_only(self) -> None:
        self._seed_base_workspace()
        report = self._run_with_candidates(
            [
                {
                    "candidate_id": "parent-live",
                    "shape_cluster_key": "ast-shape-live-not-the-p3-slug",
                    "support_invariant_ids": ["INV-ORD-004", "INV-UNI-002"],
                    "function_signature_sample": "function withdrawLive(uint256 amount) external",
                    "predicate_expression": 'shape_cluster_key == "ast-shape-live-not-the-p3-slug"',
                    "validation_status": "pending-live-target-dogfood",
                    "source_ref": "src/Live.sol:3-6",
                },
                {
                    "candidate_id": "parent-miss",
                    "shape_cluster_key": "external-call-before-state-update-miss",
                    "support_invariant_ids": ["INV-ORD-004"],
                    "predicate_expression": 'shape_cluster_key == "external-call-before-state-update-miss"',
                    "validation_status": "candidate",
                },
            ]
        )

        by_cluster = {entry["cluster_id"]: entry for entry in report["entry_points"]}
        live = by_cluster["external-call-before-state-update-live"]
        self.assertEqual(live["p1_match_tier"], "SEMANTIC-MATCH")
        self.assertIn("INV-ORD-004", live["semantic_p1_invariants"])
        self.assertIn("INV-UNI-002", live["semantic_p1_invariants"])
        self.assertEqual(len(live["shape_cluster_predicate_matches"]), 2)
        for match in live["shape_cluster_predicate_matches"]:
            self.assertNotIn("expression", match["evidence"])

        miss = by_cluster["external-call-before-state-update-miss"]
        self.assertEqual(miss["p1_match_tier"], "TOPICAL-MATCH")
        self.assertNotIn("INV-ORD-004", miss["semantic_p1_invariants"])
        self.assertFalse(miss["shape_cluster_predicate_matches"])


class Cap018019SourceShapePrecisionTest(unittest.TestCase):
    """CAP-018/CAP-019 source-shape suppressions for live-target precision."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "cap_018_019_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unpause_same_contract_and_revert_tombstone_are_suppressed(self) -> None:
        _seed_workspace_cap_018_019(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=20)
        by_cluster = {ep["cluster_id"]: ep for ep in report["entry_points"]}

        cap018 = by_cluster["pausable-no-unpause-exposed-hyperbridge"]
        cap018_suppression = cap018["false_positive_suppression"]
        self.assertTrue(cap018_suppression["suppressed"])
        self.assertTrue(any("CAP-018" in reason for reason in cap018_suppression["reasons"]))

        sibling = by_cluster["pausable-no-unpause-exposed-sibling"]
        self.assertFalse(sibling["false_positive_suppression"]["suppressed"])

        cap019 = by_cluster["lzReceive-no-sender-check-tombstone"]
        cap019_suppression = cap019["false_positive_suppression"]
        self.assertTrue(cap019_suppression["suppressed"])
        self.assertTrue(any("CAP-019" in reason for reason in cap019_suppression["reasons"]))

        live_lz = by_cluster["lzReceive-no-sender-check-live"]
        self.assertFalse(live_lz["false_positive_suppression"]["suppressed"])

        comp = report["summary_card"]["composability"]
        self.assertEqual(comp["documented_fp_suppressed_entries"], 2)

    def test_unpause_suppression_requires_external_effective_unpause(self) -> None:
        template = """
        contract PausableLike {{
          bool private paused;
          modifier whenNotPaused() {{ require(!paused); _; }}
          function pause() external {{ paused = true; }}
          {unpause}
          function submit() external whenNotPaused {{}}
        }}
        """
        cases = [
            "function unpause() internal { paused = false; }",
            "function unpause() private { paused = false; }",
            "function unpause() external { }",
            "function unpause() external { paused = true; }",
            "function unpause() external { other = false; }",
        ]
        for unpause in cases:
            source = template.format(unpause=unpause)
            suppression = ltir_mod._detector_false_positive_suppression(
                "pausable-no-unpause-exposed",
                file_line="src/PausableLike.sol:7",
                snippet="function submit() external whenNotPaused",
                source_context=source,
                source_contract_context=source,
            )
            self.assertFalse(suppression["suppressed"], unpause)

        effective = template.format(unpause="function unpause() external { paused = false; }")
        suppression = ltir_mod._detector_false_positive_suppression(
            "pausable-no-unpause-exposed",
            file_line="src/PausableLike.sol:7",
            snippet="function submit() external whenNotPaused",
            source_context=effective,
            source_contract_context=effective,
        )
        self.assertTrue(suppression["suppressed"])

    def test_lzreceive_tombstone_does_not_suppress_unvalidated_sibling_call(self) -> None:
        contract_context = """
        contract Endpoint {
          function forward(address receiverAddr, Origin calldata origin, bytes32 guid, bytes calldata message) external {
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
          }

          function lzReceive(Origin calldata, bytes32, bytes calldata, address, bytes calldata) external payable {
            revert("disabled");
          }
        }
        """
        suppression = ltir_mod._detector_false_positive_suppression(
            "lzReceive-no-sender-check",
            file_line="src/Endpoint.sol:4",
            snippet='ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");',
            source_context=contract_context,
            source_contract_context=contract_context,
        )

        self.assertFalse(suppression["suppressed"])

    def test_lzreceive_delivery_after_source_and_nonce_validation_is_suppressed(self) -> None:
        contract_context = """
        contract Endpoint {
          function onAccept(IncomingPostRequest calldata incoming) external override onlyHost whenNotPaused {
            PostRequest calldata request = incoming.request;
            if (keccak256(request.from) != keccak256(abi.encodePacked(address(this)))) revert UnknownSource();
            uint32 expectedEid = _stateMachineToEid[keccak256(request.source)];
            if (expectedEid == 0 || expectedEid != srcEid) revert UnknownSource();
            uint64 expectedNonce = _inboundNonce[receiverAddr][srcEid][sender] + 1;
            if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
            _inboundNonce[receiverAddr][srcEid][sender] = nonce;
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
          }

          function lzReceive(Origin calldata, bytes32, bytes calldata, address, bytes calldata) external payable {
            revert("disabled");
          }
        }
        """
        suppression = ltir_mod._detector_false_positive_suppression(
            "lzReceive-no-sender-check",
            file_line="src/Endpoint.sol:10",
            snippet='ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");',
            source_context=contract_context,
            source_contract_context=contract_context,
        )

        self.assertTrue(suppression["suppressed"])
        self.assertEqual(
            suppression["reasons"],
            ["CAP-019: OApp lzReceive delivery follows source and nonce validation"],
        )

    def test_lzreceive_tombstone_requires_cited_function_context(self) -> None:
        contract_context = """
        contract Endpoint {
          function forward(address receiverAddr, Origin calldata origin, bytes32 guid, bytes calldata message) external {
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
          }

          function lzReceive(Origin calldata, bytes32, bytes calldata, address, bytes calldata) external payable {
            revert("disabled");
          }
        }
        """
        suppression = ltir_mod._detector_false_positive_suppression(
            "lzReceive-no-sender-check",
            file_line="src/Endpoint.sol:4",
            snippet='ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "") /* stale snippet */;',
            source_context=contract_context,
            source_contract_context=contract_context,
        )

        self.assertFalse(suppression["suppressed"])

    def test_lzreceive_oapp_delivery_requires_pre_call_validation(self) -> None:
        post_call_validation = """
        contract Endpoint {
          function onAccept(IncomingPostRequest calldata incoming) external override onlyHost whenNotPaused {
            PostRequest calldata request = incoming.request;
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
            if (keccak256(request.from) != keccak256(abi.encodePacked(address(this)))) revert UnknownSource();
            uint32 expectedEid = _stateMachineToEid[keccak256(request.source)];
            if (expectedEid == 0 || expectedEid != srcEid) revert UnknownSource();
            uint64 expectedNonce = _inboundNonce[receiverAddr][srcEid][sender] + 1;
            if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
            _inboundNonce[receiverAddr][srcEid][sender] = nonce;
          }
        }
        """
        comments_only = """
        contract Endpoint {
          function onAccept(IncomingPostRequest calldata incoming) external override onlyHost whenNotPaused {
            PostRequest calldata request = incoming.request;
            // request.from request.source _stateMachineToEid _inboundNonce nonce expectedNonce
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
          }
        }
        """
        unused_tokens = """
        contract Endpoint {
          function onAccept(IncomingPostRequest calldata incoming) external override onlyHost whenNotPaused {
            PostRequest calldata request = incoming.request;
            bytes memory from = request.from;
            bytes memory source = request.source;
            uint64 expectedNonce = _inboundNonce[receiverAddr][srcEid][sender] + 1;
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
          }
        }
        """
        for contract_context in (post_call_validation, comments_only, unused_tokens):
            suppression = ltir_mod._detector_false_positive_suppression(
                "lzReceive-no-sender-check",
                file_line="src/Endpoint.sol:5",
                snippet='ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");',
                source_context=contract_context,
                source_contract_context=contract_context,
            )
            self.assertFalse(suppression["suppressed"])


class Cap007RemainingPrecisionTest(unittest.TestCase):
    """CAP-007 remaining source-shape suppressions for live-target precision."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "cap_007_remaining_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_predebit_and_no_post_storage_write_are_suppressed_only(self) -> None:
        _seed_workspace_cap_007_remaining(self.ws)
        report = ltir_mod.build_report(self.ws, top_n=20)
        by_cluster = {ep["cluster_id"]: ep for ep in report["entry_points"]}

        predebit = by_cluster["external-call-before-state-update-predebit"]
        self.assertTrue(predebit["false_positive_suppression"]["suppressed"])
        self.assertTrue(
            any(
                "same-ledger debit" in reason
                for reason in predebit["false_positive_suppression"]["reasons"]
            )
        )

        no_post_write = by_cluster["external-call-before-state-update-no-post-write"]
        self.assertTrue(no_post_write["false_positive_suppression"]["suppressed"])
        self.assertTrue(
            any(
                "no post-call storage mutation" in reason
                for reason in no_post_write["false_positive_suppression"]["reasons"]
            )
        )

        real = by_cluster["external-call-before-state-update-real"]
        self.assertFalse(real["false_positive_suppression"]["suppressed"])

        comp = report["summary_card"]["composability"]
        self.assertEqual(comp["documented_fp_suppressed_entries"], 2)

    def test_unrelated_pre_call_debit_and_bare_post_call_write_stay_live(self) -> None:
        unrelated_predebit = """
        contract Withdraw {
          mapping(address => uint256) credits;
          mapping(address => uint256) balances;
          function withdraw(uint256 fee, uint256 amount) external {
            credits[msg.sender] -= fee;
            (bool sent,) = msg.sender.call{value: amount}("");
            require(sent);
            balances[msg.sender] -= amount;
          }
        }
        """
        unrelated = ltir_mod._detector_false_positive_suppression(
            "external-call-before-state-update",
            file_line="src/Withdraw.sol:7",
            snippet='(bool sent,) = msg.sender.call{value: amount}("");',
            source_context=unrelated_predebit,
            source_contract_context=unrelated_predebit,
        )
        self.assertFalse(unrelated["suppressed"])

        bare_post_write = """
        contract Burn {
          uint256 totalSupply;
          function burn(uint256 amount) external {
            (bool sent,) = msg.sender.call{value: amount}("");
            require(sent);
            totalSupply -= amount;
          }
        }
        """
        bare = ltir_mod._detector_false_positive_suppression(
            "external-call-before-state-update",
            file_line="src/Burn.sol:5",
            snippet='(bool sent,) = msg.sender.call{value: amount}("");',
            source_context=bare_post_write,
            source_contract_context=bare_post_write,
        )
        self.assertFalse(bare["suppressed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
