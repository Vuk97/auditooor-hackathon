"""End-to-end integration tests for the Wave-1 hackerman MCP callable surface.

PR #726 (``wave-1-hackerman-capability-lift``). Builds a single synthetic
corpus of 50 records (mix of tier-1/2/3/4/5 across multiple subtrees /
attack classes / domains / repos / languages) and then drives the chain of
Wave-1 callables end-to-end against it. The intent is *cross-callable
consistency*: each individual callable already has a focused test file
(``test_vault_corpus_search_callable.py``,
``test_vault_attack_class_taxonomy_callable.py``,
``test_vault_severity_calibration_callable.py``,
``test_vault_corpus_lineage_callable.py``,
``test_vault_mcp_callables_v2.py``,
``test_vault_mcp_callables_v3.py``); this file proves they all see the
*same* corpus the same way.

Cases (12, per the integration spec):

1. synthetic corpus shape (50 records, tier mix);
2. ``vault_corpus_subtree_summary`` returns expected record counts;
3. ``vault_attack_class_taxonomy`` enumerates all classes in the
   pre-built inventory JSON;
4. ``vault_corpus_search`` filters by predicates correctly;
5. ``vault_attack_class_evidence_v2`` returns tier-ordered results;
6. ``vault_hacker_brief_for_lane_v2`` returns brief records with the
   tier filter applied;
7. ``vault_dupe_advisory_check`` finds duplicates by CVE / GHSA /
   source_url;
8. ``vault_severity_calibration`` returns the expected severity
   distribution;
9. ``vault_attack_class_orphan_report`` flags single-subtree orphans;
10. ``vault_corpus_lineage`` traces a corpus record back to its
    origin / etl_miner / corpus_index / attribution_trail chain;
11. cross-callable consistency: sum of per-subtree records from
    ``vault_corpus_subtree_summary`` equals the in-tree record total
    seen by ``vault_corpus_search`` (excluding quarantine);
12. envelope-shape contract: every Wave-1 callable emits
    ``schema`` / ``context_pack_id`` / ``context_pack_hash`` (64 hex).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_hackerman_integration_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


# ---------------------------------------------------------------------------
# Synthetic corpus builders
# ---------------------------------------------------------------------------


# Tier tag strings (mirrors hackerman-apply-verification-tier.py output).
TIER_TAGS = {
    1: "verification_tier:tier-1-verified-realtime-api",
    2: "verification_tier:tier-2-verified-public-archive",
    3: "verification_tier:tier-3-synthetic-taxonomy-anchored",
    4: "verification_tier:tier-4-bundled-fixture",
    5: "verification_tier:tier-5-quarantine",
}

# ---- Corpus layout (50 records across 5 subtrees) ------------------------
#
# subtree                        | tier-1 | tier-2 | tier-3 | tier-4 | tier-5 | total
# lending_protocols              |   6    |   4    |   2    |   1    |   1    |  14
# oracle_advisories              |   3    |   3    |   1    |   1    |   0    |   8
# bridge_incidents               |   4    |   2    |   1    |   1    |   1    |   9
# cosmos_sdk_ibc                 |   2    |   2    |   3    |   0    |   0    |   7
# _QUARANTINE_FABRICATED_CVE     |   0    |   0    |   0    |   0    |  12    |  12
#                                  ===     ===     ===     ===     ===     ====
#                                  15      11       7       3      14       50
#
# 50 records total. 36 non-quarantine + 14 quarantine.

# Attack-class plan:
#   - reentrancy-external-call (cross-subtree, well-covered)
#   - oracle-manipulation       (cross-subtree, well-covered)
#   - signature-replay          (cross-subtree, mixed)
#   - novel-cosmos-fork-bug     (single subtree, orphan)
#   - bridge-proof-forgery      (cross-subtree)
#   - fabricated-class          (quarantine-only)

CORPUS_PLAN: list[dict[str, Any]] = [
    # ---- lending_protocols (14) ----
    {"subtree": "lending_protocols", "id": "lend-r01", "tier": 1, "ac": "reentrancy-external-call",
     "sev": "critical", "domain": "lending", "lang": "solidity",
     "repo": "aave/aave-v3-core",
     "src": "https://github.com/aave/aave-v3-core/security/advisories/GHSA-aaaa-bbbb-cccc",
     "ext": {"cve_id": "CVE-2024-10001"}},
    {"subtree": "lending_protocols", "id": "lend-r02", "tier": 1, "ac": "reentrancy-external-call",
     "sev": "high", "domain": "lending", "lang": "solidity",
     "repo": "aave/aave-v3-core",
     "src": "https://github.com/aave/aave-v3-core/security/advisories/GHSA-aaaa-bbbb-ddee"},
    {"subtree": "lending_protocols", "id": "lend-r03", "tier": 1, "ac": "oracle-manipulation",
     "sev": "high", "domain": "lending", "lang": "solidity",
     "repo": "compound-finance/compound-protocol",
     "src": "https://github.com/compound-finance/compound-protocol/issues/3001"},
    {"subtree": "lending_protocols", "id": "lend-r04", "tier": 1, "ac": "reentrancy-external-call",
     "sev": "high", "domain": "lending", "lang": "solidity",
     "repo": "morpho-org/morpho-blue",
     "src": "https://github.com/morpho-org/morpho-blue/issues/100"},
    {"subtree": "lending_protocols", "id": "lend-r05", "tier": 1, "ac": "oracle-manipulation",
     "sev": "medium", "domain": "lending", "lang": "solidity",
     "repo": "aave/aave-v3-core",
     "src": "https://example.com/audits/lend-r05"},
    {"subtree": "lending_protocols", "id": "lend-r06", "tier": 1, "ac": "signature-replay",
     "sev": "medium", "domain": "lending", "lang": "solidity",
     "repo": "compound-finance/compound-protocol",
     "src": "https://example.com/audits/lend-r06"},
    {"subtree": "lending_protocols", "id": "lend-r07", "tier": 2, "ac": "reentrancy-external-call",
     "sev": "medium", "domain": "lending", "lang": "solidity",
     "repo": "aave/aave-v3-core",
     "src": "https://example.com/audits/lend-r07"},
    {"subtree": "lending_protocols", "id": "lend-r08", "tier": 2, "ac": "oracle-manipulation",
     "sev": "medium", "domain": "lending", "lang": "solidity",
     "repo": "compound-finance/compound-protocol",
     "src": "https://example.com/audits/lend-r08"},
    {"subtree": "lending_protocols", "id": "lend-r09", "tier": 2, "ac": "reentrancy-external-call",
     "sev": "low", "domain": "lending", "lang": "solidity",
     "repo": "morpho-org/morpho-blue",
     "src": "https://example.com/audits/lend-r09"},
    {"subtree": "lending_protocols", "id": "lend-r10", "tier": 2, "ac": "signature-replay",
     "sev": "low", "domain": "lending", "lang": "solidity",
     "repo": "aave/aave-v3-core",
     "src": "https://example.com/audits/lend-r10"},
    {"subtree": "lending_protocols", "id": "lend-r11", "tier": 3, "ac": "reentrancy-external-call",
     "sev": "low", "domain": "lending", "lang": "solidity",
     "repo": "aave/aave-v3-core",
     "src": "https://example.com/audits/lend-r11"},
    {"subtree": "lending_protocols", "id": "lend-r12", "tier": 3, "ac": "oracle-manipulation",
     "sev": "info", "domain": "lending", "lang": "solidity",
     "repo": "compound-finance/compound-protocol",
     "src": "https://example.com/audits/lend-r12"},
    {"subtree": "lending_protocols", "id": "lend-r13", "tier": 4, "ac": "signature-replay",
     "sev": "info", "domain": "lending", "lang": "solidity",
     "repo": "morpho-org/morpho-blue",
     "src": "https://example.com/audits/lend-r13"},
    {"subtree": "lending_protocols", "id": "lend-r14", "tier": 5, "ac": "fabricated-class",
     "sev": "critical", "domain": "lending", "lang": "solidity",
     "repo": "fabricated/lending-repo",
     "src": "https://example.invalid/fabricated/lend-r14"},

    # ---- oracle_advisories (8) ----
    {"subtree": "oracle_advisories", "id": "orac-r01", "tier": 1, "ac": "oracle-manipulation",
     "sev": "critical", "domain": "oracle", "lang": "solidity",
     "repo": "smartcontractkit/chainlink",
     "src": "https://github.com/smartcontractkit/chainlink/security/advisories/GHSA-dddd-eeee-ffff"},
    {"subtree": "oracle_advisories", "id": "orac-r02", "tier": 1, "ac": "oracle-manipulation",
     "sev": "high", "domain": "oracle", "lang": "solidity",
     "repo": "smartcontractkit/chainlink",
     "src": "https://github.com/smartcontractkit/chainlink/security/advisories/GHSA-1111-2222-3333"},
    {"subtree": "oracle_advisories", "id": "orac-r03", "tier": 1, "ac": "signature-replay",
     "sev": "high", "domain": "oracle", "lang": "solidity",
     "repo": "pyth-network/pyth-client",
     "src": "https://example.com/audits/orac-r03"},
    {"subtree": "oracle_advisories", "id": "orac-r04", "tier": 2, "ac": "oracle-manipulation",
     "sev": "medium", "domain": "oracle", "lang": "solidity",
     "repo": "smartcontractkit/chainlink",
     "src": "https://example.com/audits/orac-r04"},
    {"subtree": "oracle_advisories", "id": "orac-r05", "tier": 2, "ac": "oracle-manipulation",
     "sev": "medium", "domain": "oracle", "lang": "solidity",
     "repo": "pyth-network/pyth-client",
     "src": "https://example.com/audits/orac-r05"},
    {"subtree": "oracle_advisories", "id": "orac-r06", "tier": 2, "ac": "signature-replay",
     "sev": "low", "domain": "oracle", "lang": "solidity",
     "repo": "pyth-network/pyth-client",
     "src": "https://example.com/audits/orac-r06"},
    {"subtree": "oracle_advisories", "id": "orac-r07", "tier": 3, "ac": "oracle-manipulation",
     "sev": "low", "domain": "oracle", "lang": "solidity",
     "repo": "smartcontractkit/chainlink",
     "src": "https://example.com/audits/orac-r07"},
    {"subtree": "oracle_advisories", "id": "orac-r08", "tier": 4, "ac": "oracle-manipulation",
     "sev": "info", "domain": "oracle", "lang": "solidity",
     "repo": "pyth-network/pyth-client",
     "src": "https://example.com/audits/orac-r08"},

    # ---- bridge_incidents (9) ----
    {"subtree": "bridge_incidents", "id": "brg-r01", "tier": 1, "ac": "bridge-proof-forgery",
     "sev": "critical", "domain": "bridge", "lang": "solidity",
     "repo": "optimism/optimism",
     "src": "https://github.com/optimism/optimism/security/advisories/GHSA-bbbb-cccc-dddd"},
    {"subtree": "bridge_incidents", "id": "brg-r02", "tier": 1, "ac": "bridge-proof-forgery",
     "sev": "high", "domain": "bridge", "lang": "solidity",
     "repo": "optimism/optimism",
     "src": "https://example.com/audits/brg-r02"},
    {"subtree": "bridge_incidents", "id": "brg-r03", "tier": 1, "ac": "reentrancy-external-call",
     "sev": "high", "domain": "bridge", "lang": "solidity",
     "repo": "arbitrum/nitro",
     "src": "https://example.com/audits/brg-r03"},
    {"subtree": "bridge_incidents", "id": "brg-r04", "tier": 1, "ac": "bridge-proof-forgery",
     "sev": "medium", "domain": "bridge", "lang": "rust",
     "repo": "wormhole-foundation/wormhole",
     "src": "https://example.com/audits/brg-r04"},
    {"subtree": "bridge_incidents", "id": "brg-r05", "tier": 2, "ac": "signature-replay",
     "sev": "medium", "domain": "bridge", "lang": "solidity",
     "repo": "optimism/optimism",
     "src": "https://example.com/audits/brg-r05"},
    {"subtree": "bridge_incidents", "id": "brg-r06", "tier": 2, "ac": "bridge-proof-forgery",
     "sev": "medium", "domain": "bridge", "lang": "rust",
     "repo": "wormhole-foundation/wormhole",
     "src": "https://example.com/audits/brg-r06"},
    {"subtree": "bridge_incidents", "id": "brg-r07", "tier": 3, "ac": "bridge-proof-forgery",
     "sev": "low", "domain": "bridge", "lang": "solidity",
     "repo": "arbitrum/nitro",
     "src": "https://example.com/audits/brg-r07"},
    {"subtree": "bridge_incidents", "id": "brg-r08", "tier": 4, "ac": "signature-replay",
     "sev": "info", "domain": "bridge", "lang": "rust",
     "repo": "wormhole-foundation/wormhole",
     "src": "https://example.com/audits/brg-r08"},
    {"subtree": "bridge_incidents", "id": "brg-r09", "tier": 5, "ac": "fabricated-class",
     "sev": "critical", "domain": "bridge", "lang": "rust",
     "repo": "fabricated/bridge-repo",
     "src": "https://example.invalid/fabricated/brg-r09"},

    # ---- cosmos_sdk_ibc (7) - exempt subtree, tier-3-by-design + orphan attack-class ----
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r01", "tier": 1, "ac": "signature-replay",
     "sev": "high", "domain": "ibc", "lang": "go",
     "repo": "cosmos/ibc-go",
     "src": "https://github.com/cosmos/ibc-go/security/advisories/GHSA-eeee-1111-2222"},
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r02", "tier": 1, "ac": "signature-replay",
     "sev": "medium", "domain": "ibc", "lang": "go",
     "repo": "cosmos/cosmos-sdk",
     "src": "https://example.com/audits/ibc-r02"},
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r03", "tier": 2, "ac": "signature-replay",
     "sev": "medium", "domain": "ibc", "lang": "go",
     "repo": "cosmos/ibc-go",
     "src": "https://example.com/audits/ibc-r03"},
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r04", "tier": 2, "ac": "novel-cosmos-fork-bug",
     "sev": "medium", "domain": "ibc", "lang": "go",
     "repo": "cosmos/cosmos-sdk",
     "src": "https://example.com/audits/ibc-r04"},
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r05", "tier": 3, "ac": "novel-cosmos-fork-bug",
     "sev": "low", "domain": "ibc", "lang": "go",
     "repo": "cosmos/cosmos-sdk",
     "src": "https://example.com/audits/ibc-r05"},
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r06", "tier": 3, "ac": "novel-cosmos-fork-bug",
     "sev": "low", "domain": "ibc", "lang": "go",
     "repo": "cosmos/ibc-go",
     "src": "https://example.com/audits/ibc-r06"},
    {"subtree": "cosmos_sdk_ibc", "id": "ibc-r07", "tier": 3, "ac": "novel-cosmos-fork-bug",
     "sev": "info", "domain": "ibc", "lang": "go",
     "repo": "cosmos/cosmos-sdk",
     "src": "https://example.com/audits/ibc-r07"},

    # ---- _QUARANTINE_FABRICATED_CVE (12, all tier-5) ----
    # All quarantine entries share a CVE so the dupe-advisory cross-corpus
    # filter has multiple hits to exclude.
    *[
        {"subtree": "_QUARANTINE_FABRICATED_CVE", "id": f"quar-r{idx:02d}", "tier": 5,
         "ac": "fabricated-class", "sev": "critical", "domain": "lending",
         "lang": "solidity", "repo": "fabricated/synthetic-repo",
         "src": f"https://example.invalid/quarantine/quar-r{idx:02d}",
         "ext": {"cve_id": "CVE-2099-99999"}}
        for idx in range(1, 13)
    ],
]


# Sanity check at import time so a typo in the plan is caught fast.
assert len(CORPUS_PLAN) == 50, f"plan must have 50 records, got {len(CORPUS_PLAN)}"


def _record_dict(entry: dict[str, Any]) -> dict[str, Any]:
    """Materialise a plan row into a hackerman record dict."""
    rec: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": entry["id"],
        "source_audit_ref": entry["src"],
        "target_repo": entry["repo"],
        "target_domain": entry["domain"],
        "target_language": entry["lang"],
        "attack_class": entry["ac"],
        "bug_class": entry["ac"],
        "severity_at_finding": entry["sev"],
        "function_shape": {
            "raw_signature": f"synthetic-{entry['id']}",
            "shape_tags": [
                entry["subtree"],
                TIER_TAGS[entry["tier"]],
            ],
        },
        "year": 2024,
    }
    if entry.get("ext"):
        rec["extensions"] = dict(entry["ext"])
    return rec


def _yaml_dump(data: dict[str, Any]) -> str:
    try:
        import yaml  # type: ignore

        return yaml.safe_dump(data, sort_keys=False)
    except Exception:  # noqa: BLE001
        return json.dumps(data, indent=2)


def _build_inventory(plan: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive a per-attack-class inventory JSON in the shape
    ``hackerman-attack-class-inventory.py`` emits."""
    subtrees: dict[str, dict[str, Any]] = {}
    classes: dict[str, dict[str, Any]] = {}

    for entry in plan:
        sub = entry["subtree"]
        ac = entry["ac"]
        tier = entry["tier"]
        tier_key = f"tier-{tier}"

        sub_row = subtrees.setdefault(sub, {
            "total_records": 0,
            "distinct_classes_set": set(),
            "tier_counts": {},
            "tier1_count": 0,
            "tier2_count": 0,
        })
        sub_row["total_records"] += 1
        sub_row["distinct_classes_set"].add(ac)
        sub_row["tier_counts"][tier_key] = sub_row["tier_counts"].get(tier_key, 0) + 1
        if tier == 1:
            sub_row["tier1_count"] += 1
        elif tier == 2:
            sub_row["tier2_count"] += 1

        cls_row = classes.setdefault(ac, {
            "attack_class": ac,
            "total_records": 0,
            "subtrees_set": set(),
            "tier_counts": {},
            "tier1_count": 0,
            "tier2_count": 0,
        })
        cls_row["total_records"] += 1
        cls_row["subtrees_set"].add(sub)
        cls_row["tier_counts"][tier_key] = cls_row["tier_counts"].get(tier_key, 0) + 1
        if tier == 1:
            cls_row["tier1_count"] += 1
        elif tier == 2:
            cls_row["tier2_count"] += 1

    classes_out: list[dict[str, Any]] = []
    for row in classes.values():
        total = row["total_records"]
        t12 = row["tier1_count"] + row["tier2_count"]
        pct = (t12 / total) * 100.0 if total else 0.0
        classes_out.append({
            "attack_class": row["attack_class"],
            "total_records": total,
            "subtrees": sorted(row["subtrees_set"]),
            "tier_counts": row["tier_counts"],
            "tier1_count": row["tier1_count"],
            "tier2_count": row["tier2_count"],
            "tier12_count": t12,
            "tier12_pct": round(pct, 2),
        })

    per_subtree_out: dict[str, dict[str, Any]] = {}
    for sub_name, row in subtrees.items():
        total = row["total_records"]
        t12 = row["tier1_count"] + row["tier2_count"]
        pct = (t12 / total) * 100.0 if total else 0.0
        per_subtree_out[sub_name] = {
            "total_records": total,
            "distinct_classes": len(row["distinct_classes_set"]),
            "tier_counts": row["tier_counts"],
            "tier1_count": row["tier1_count"],
            "tier2_count": row["tier2_count"],
            "tier12_count": t12,
            "tier12_pct": round(pct, 2),
        }

    return {
        "schema": "auditooor.hackerman_attack_class_taxonomy.v1",
        "tags_dir": "/synthetic/tags",
        "total_records": len(plan),
        "subtrees": sorted(subtrees),
        "classes": classes_out,
        "per_subtree": per_subtree_out,
    }


# ---------------------------------------------------------------------------
# Test fixture
# ---------------------------------------------------------------------------


class HackermanIntegrationCorpus:
    """Builds the on-disk corpus once and exposes a configured VaultQuery."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-integration-")
        self.root = Path(self.tmp.name)
        # Mirrors production layout used by vault-mcp-server's _hackerman_query_paths
        # (audit/corpus_tags/tags and audit/corpus_tags/index).
        self.audit_root = self.root / "audit" / "corpus_tags"
        self.tags_dir = self.audit_root / "tags"
        self.tags_dir.mkdir(parents=True)
        self.index_dir = self.audit_root / "index"
        self.index_dir.mkdir(parents=True)
        self.derived_dir = self.audit_root / "derived"
        self.derived_dir.mkdir(parents=True)

        # Workspace + vault dirs (VaultQuery contract).
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "SCOPE.md").write_text("synthetic-integration", encoding="utf-8")
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()

        # Materialise records + by_attack_class index rows.
        index_rows: list[dict[str, Any]] = []
        for entry in CORPUS_PLAN:
            rec = _record_dict(entry)
            rec_dir = self.tags_dir / entry["subtree"] / entry["id"]
            rec_dir.mkdir(parents=True, exist_ok=True)
            # JSON form (the walker accepts both record.{json,yaml}).
            (rec_dir / "record.json").write_text(json.dumps(rec), encoding="utf-8")
            # Also emit the by_attack_class index row consumed by the v2
            # evidence / brief callables.
            index_rows.append({
                "attack_class": entry["ac"],
                "bug_class": entry["ac"],
                "key": entry["ac"],
                "record_id": entry["id"],
                "severity_at_finding": entry["sev"],
                "source_audit_ref": entry["src"],
                "tag_file": str(rec_dir / "record.json"),
                "target_domain": entry["domain"],
                "target_language": entry["lang"],
                "target_repo": entry["repo"],
                "year": 2024,
            })

        with (self.index_dir / "by_attack_class.jsonl").open(
            "w", encoding="utf-8"
        ) as fh:
            for row in index_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        for axis in ("by_language", "by_target_domain", "by_target_repo"):
            (self.index_dir / f"{axis}.jsonl").write_text("", encoding="utf-8")

        # Optional sidecars consumed by the v2 helpers.
        (self.derived_dir / "record_quality.jsonl").write_text("", encoding="utf-8")
        (self.derived_dir / "proof_hardening.jsonl").write_text("", encoding="utf-8")
        (self.derived_dir / "cross_language_analogues.jsonl").write_text("", encoding="utf-8")

        # Inventory JSON (vault_attack_class_taxonomy /
        # vault_attack_class_orphan_report consume this).
        self.inventory_path = self.derived_dir / "attack_class_taxonomy.json"
        self.inventory_path.write_text(
            json.dumps(_build_inventory(CORPUS_PLAN)), encoding="utf-8"
        )

        # Acceptance exemptions (vault_corpus_subtree_summary joins this).
        self.exemptions_path = self.audit_root / "acceptance_exemptions.yaml"
        self.exemptions_path.write_text(
            _yaml_dump({
                "schema": "auditooor.hackerman_corpus_acceptance_exemptions.v1",
                "exemptions": [
                    {
                        "corpus_dir": "cosmos_sdk_ibc",
                        "category": "B",
                        "reason": "mixed-wave anchor + fan-out",
                        "review_at": "indefinite",
                    }
                ],
            }),
            encoding="utf-8",
        )

        # ---- Lineage fixture (vault_corpus_lineage walks these paths) ----
        # The lineage callable's default corpus_root is repo_root /
        # reference/corpus_mined; mirror the layout so the test record
        # ``lend-r01`` resolves to a corpus_index entry + an etl_miner
        # registry record + an attribution_trail markdown.
        self.corpus_mined = self.root / "reference" / "corpus_mined"
        self.corpus_mined.mkdir(parents=True)
        (self.corpus_mined / "INDEX.md").write_text(
            "# Corpus mining consolidated index\n\n"
            "| Slice | slug |\n"
            "| --- | --- |\n"
            "| aave-lending | lend-r01 |\n",
            encoding="utf-8",
        )
        (self.corpus_mined / "lending_protocols_catalog.md").write_text(
            "# Lending protocols catalog\n\n"
            "## lend-r01\n"
            "Title: Aave v3 core reentrancy variant.\n"
            "attack_class: reentrancy-external-call\n"
            "Severity: CRITICAL\n",
            encoding="utf-8",
        )
        etl_dir = self.root / "tools" / "audit" / "etl_miner_registry"
        etl_dir.mkdir(parents=True)
        (etl_dir / "lending_protocols.json").write_text(
            json.dumps({
                "miner": "lending_protocols",
                "run_id": "2026-05-16T00:00Z-integration",
                "input_records_count": 200,
                "output_records_count": 50,
                "records": [{"slug": "lend-r01", "year": 2024}],
            }),
            encoding="utf-8",
        )
        case_dir = self.root / "auditooor-mcp" / "case_study"
        case_dir.mkdir(parents=True)
        (case_dir / "lending_protocols_catalog.md").write_text(
            "# Lending protocols catalog citation\n\n"
            "Citation: Aave Labs (2024). v3-core reentrancy. Aave.\n\n"
            "Primary: https://github.com/aave/aave-v3-core\n"
            "Record id: lend-r01\n",
            encoding="utf-8",
        )

        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def cleanup(self) -> None:
        self.tmp.cleanup()


# Tier rollup the assertions below cross-check against. Computed once from
# CORPUS_PLAN so a future edit to the plan flows through automatically.
NON_QUARANTINE_RECORDS = sum(1 for e in CORPUS_PLAN if e["tier"] != 5)
QUARANTINE_RECORDS = sum(1 for e in CORPUS_PLAN if e["tier"] == 5)
TOTAL_RECORDS = len(CORPUS_PLAN)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class WaveOneHackermanIntegrationTests(unittest.TestCase):
    """12 cases covering the Wave-1 hackerman MCP callable surface."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fx = HackermanIntegrationCorpus()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fx.cleanup()

    # ---- helpers --------------------------------------------------------

    def _envelope_ok(self, result: dict[str, Any], schema_const: str) -> None:
        """Common envelope-shape contract."""
        self.assertEqual(result["schema"], schema_const)
        self.assertTrue(
            result["context_pack_id"].startswith(schema_const),
            msg=f"context_pack_id for {schema_const}: {result.get('context_pack_id')}",
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        # SHA-256 hex is lowercase.
        self.assertTrue(
            all(c in "0123456789abcdef" for c in result["context_pack_hash"]),
            msg=f"hash not hex: {result['context_pack_hash']}",
        )

    # ------------------------------------------------------------------
    # 1. synthetic corpus shape
    # ------------------------------------------------------------------
    def test_01_synthetic_corpus_50_records_tier_mix(self):
        # On-disk record count must equal the plan length.
        all_record_files = list(self.fx.tags_dir.rglob("record.json"))
        self.assertEqual(len(all_record_files), TOTAL_RECORDS)
        self.assertEqual(TOTAL_RECORDS, 50)
        # Tier mix sanity check.
        self.assertEqual(NON_QUARANTINE_RECORDS + QUARANTINE_RECORDS, TOTAL_RECORDS)
        self.assertEqual(QUARANTINE_RECORDS, 14)
        # 5 subtrees on disk.
        subtrees_on_disk = {p.relative_to(self.fx.tags_dir).parts[0]
                            for p in all_record_files}
        self.assertEqual(subtrees_on_disk, {
            "lending_protocols",
            "oracle_advisories",
            "bridge_incidents",
            "cosmos_sdk_ibc",
            "_QUARANTINE_FABRICATED_CVE",
        })
        # Index file has one row per record.
        idx_lines = (self.fx.index_dir / "by_attack_class.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertEqual(len(idx_lines), TOTAL_RECORDS)

    # ------------------------------------------------------------------
    # 2. vault_corpus_subtree_summary
    # ------------------------------------------------------------------
    def test_02_corpus_subtree_summary_record_counts(self):
        result = self.fx.vault.vault_corpus_subtree_summary(
            workspace_path=str(self.fx.workspace),
            tags_dir=str(self.fx.tags_dir),
            exemptions_path=str(self.fx.exemptions_path),
        )
        self._envelope_ok(result, vault_mcp_server.CORPUS_SUBTREE_SUMMARY_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["total_records"], TOTAL_RECORDS)
        per_subtree = {row["subtree"]: row for row in result["subtrees"]}
        # Counts mirror the plan exactly.
        self.assertEqual(per_subtree["lending_protocols"]["records"], 14)
        self.assertEqual(per_subtree["oracle_advisories"]["records"], 8)
        self.assertEqual(per_subtree["bridge_incidents"]["records"], 9)
        self.assertEqual(per_subtree["cosmos_sdk_ibc"]["records"], 7)
        self.assertEqual(per_subtree["_QUARANTINE_FABRICATED_CVE"]["records"], 12)
        # The exemption for cosmos_sdk_ibc surfaces in the row.
        self.assertIsNotNone(per_subtree["cosmos_sdk_ibc"]["exemption"])
        self.assertEqual(per_subtree["cosmos_sdk_ibc"]["exemption"]["category"], "B")
        # Subtrees that should not carry an exemption.
        self.assertIsNone(per_subtree["lending_protocols"]["exemption"])

    # ------------------------------------------------------------------
    # 3. vault_attack_class_taxonomy
    # ------------------------------------------------------------------
    def test_03_attack_class_taxonomy_enumerates_all_classes(self):
        result = self.fx.vault.vault_attack_class_taxonomy(
            workspace_path=str(self.fx.workspace),
            inventory_path=str(self.fx.inventory_path),
            limit=50,
        )
        self._envelope_ok(result, vault_mcp_server.ATTACK_CLASS_TAXONOMY_SCHEMA)
        self.assertFalse(result["degraded"])
        names = {row["attack_class"] for row in result["classes"]}
        # All 6 attack classes from the plan must surface.
        self.assertEqual(names, {
            "reentrancy-external-call",
            "oracle-manipulation",
            "signature-replay",
            "novel-cosmos-fork-bug",
            "bridge-proof-forgery",
            "fabricated-class",
        })
        # Per-subtree map mirrors the inventory.
        self.assertEqual(result["per_subtree"]["lending_protocols"]["total_records"], 14)

    # ------------------------------------------------------------------
    # 4. vault_corpus_search predicate filtering
    # ------------------------------------------------------------------
    def test_04_corpus_search_predicates(self):
        # Predicate: attack_class. tier-5 quarantine excluded by default; the
        # remaining reentrancy-external-call records are spread across
        # lending_protocols + bridge_incidents.
        result = self.fx.vault.vault_corpus_search(
            workspace_path=str(self.fx.workspace),
            query={"attack_class": "reentrancy-external-call"},
            tags_dir=str(self.fx.tags_dir),
            limit=50,
        )
        self._envelope_ok(result, vault_mcp_server.CORPUS_SEARCH_SCHEMA)
        self.assertFalse(result["degraded"])
        ids = [r["record_id"] for r in result["records"]]
        # Plan: lending r01..r02, r04, r07, r09, r11 + bridge r03 = 7 records,
        # all tier <= 4 (none of the reentrancy entries are tier-5).
        expected_reentrancy = {
            "lend-r01", "lend-r02", "lend-r04",
            "lend-r07", "lend-r09", "lend-r11",
            "brg-r03",
        }
        self.assertEqual(set(ids), expected_reentrancy)
        # Quarantine fabricated-class records must be excluded by default
        # under the orthogonal exclude_quarantine guard.
        none_quarantine = self.fx.vault.vault_corpus_search(
            workspace_path=str(self.fx.workspace),
            query={"attack_class": "fabricated-class"},
            tags_dir=str(self.fx.tags_dir),
            limit=50,
        )
        self.assertEqual(none_quarantine["total_records_matched"], 0)

        # Predicate AND-composition: language=go AND target_domain=ibc.
        ibc_go = self.fx.vault.vault_corpus_search(
            workspace_path=str(self.fx.workspace),
            query={"language": "go", "target_domain": "ibc"},
            tags_dir=str(self.fx.tags_dir),
            limit=50,
        )
        # 7 cosmos_sdk_ibc records.
        self.assertEqual(ibc_go["total_records_matched"], 7)

    # ------------------------------------------------------------------
    # 5. vault_attack_class_evidence_v2 tier-ordered
    # ------------------------------------------------------------------
    def test_05_attack_class_evidence_v2_tier_order(self):
        result = self.fx.vault.vault_attack_class_evidence_v2(
            workspace_path=str(self.fx.workspace),
            attack_class="reentrancy-external-call",
            index_dir=str(self.fx.index_dir),
            tags_dir=str(self.fx.tags_dir),
            limit=20,
        )
        self._envelope_ok(result, vault_mcp_server.ATTACK_CLASS_EVIDENCE_V2_SCHEMA)
        self.assertFalse(result.get("degraded", False))
        # All returned records share the requested attack class.
        for rec in result["records"]:
            self.assertEqual(rec.get("attack_class"), "reentrancy-external-call")
        # Tiers are monotonically non-decreasing (1 strongest -> 4 weakest).
        tiers = [r.get("verification_tier") for r in result["records"]
                 if isinstance(r.get("verification_tier"), int)]
        self.assertEqual(tiers, sorted(tiers))
        # Tier-5 quarantine never appears.
        self.assertNotIn(5, tiers)
        # First record (if any) must be tier-1.
        if tiers:
            self.assertEqual(tiers[0], 1)

    # ------------------------------------------------------------------
    # 6. vault_hacker_brief_for_lane_v2 with tier filter
    # ------------------------------------------------------------------
    def test_06_hacker_brief_for_lane_v2_with_tier_filter(self):
        result = self.fx.vault.vault_hacker_brief_for_lane_v2(
            workspace_path=str(self.fx.workspace),
            lane_id="W1-integration-lane",
            files=["SCOPE.md"],
            attack_class="reentrancy-external-call",
            index_dir=str(self.fx.index_dir),
            tags_dir=str(self.fx.tags_dir),
            min_verification_tier=2,
            limit=20,
        )
        self._envelope_ok(result, vault_mcp_server.HACKER_BRIEF_FOR_LANE_V2_SCHEMA)
        self.assertFalse(result.get("degraded", False))
        # All records honour the tier floor and exclude quarantine.
        for rec in result["records"]:
            tier = rec.get("verification_tier")
            self.assertIsInstance(tier, int)
            self.assertLessEqual(tier, 2)
            self.assertNotEqual(tier, 5)
        # Brief surfaces the records_by_attack_class partition.
        self.assertIn("records_by_attack_class", result)

    # ------------------------------------------------------------------
    # 7. vault_dupe_advisory_check finds dupes
    # ------------------------------------------------------------------
    def test_07_dupe_advisory_check_finds_dupes(self):
        # CVE-2024-10001 was attached to ONLY lend-r01 (non-quarantine).
        # Quarantine entries carry CVE-2099-99999.
        result = self.fx.vault.vault_dupe_advisory_check(
            workspace_path=str(self.fx.workspace),
            tags_dir=str(self.fx.tags_dir),
            cve_id="CVE-2024-10001",
        )
        self._envelope_ok(result, vault_mcp_server.DUPE_ADVISORY_CHECK_SCHEMA)
        self.assertFalse(result["degraded"])
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(ids, ["lend-r01"])

        # Quarantine-attached CVE: default-exclude returns zero records.
        result_qcve = self.fx.vault.vault_dupe_advisory_check(
            workspace_path=str(self.fx.workspace),
            tags_dir=str(self.fx.tags_dir),
            cve_id="CVE-2099-99999",
        )
        self.assertFalse(result_qcve["degraded"])
        self.assertEqual(result_qcve["records"], [])

        # GHSA id present on orac-r01.
        result_ghsa = self.fx.vault.vault_dupe_advisory_check(
            workspace_path=str(self.fx.workspace),
            tags_dir=str(self.fx.tags_dir),
            ghsa_id="GHSA-DDDD-EEEE-FFFF",
        )
        self.assertEqual(
            [r["record_id"] for r in result_ghsa["records"]],
            ["orac-r01"],
        )

    # ------------------------------------------------------------------
    # 8. vault_severity_calibration distribution
    # ------------------------------------------------------------------
    def test_08_severity_calibration_distribution(self):
        # reentrancy-external-call under default min_verification_tier=2
        # (drops tier-3/4; tier-5 always dropped):
        #   lend-r01 critical (tier-1)
        #   lend-r02 high     (tier-1)
        #   lend-r04 high     (tier-1)
        #   brg-r03  high     (tier-1)
        #   lend-r07 medium   (tier-2)
        #   lend-r09 low      (tier-2)
        # = 6 records: 1 critical, 3 high, 1 medium, 1 low, 0 info.
        result = self.fx.vault.vault_severity_calibration(
            workspace_path=str(self.fx.workspace),
            attack_class="reentrancy-external-call",
            tags_dir=str(self.fx.tags_dir),
        )
        self._envelope_ok(result, vault_mcp_server.SEVERITY_CALIBRATION_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["total_records"], 6)
        self.assertEqual(result["severity_distribution"], {
            "critical": 1, "high": 3, "medium": 1, "low": 1, "info": 0,
        })
        # top_5_examples capped at 5 records, critical -> info ordering.
        top = result["top_5_examples"]
        self.assertLessEqual(len(top), 5)
        # First example must be the critical record.
        self.assertEqual(top[0]["severity"], "critical")

    # ------------------------------------------------------------------
    # 9. vault_attack_class_orphan_report flags orphans
    # ------------------------------------------------------------------
    def test_09_attack_class_orphan_report(self):
        result = self.fx.vault.vault_attack_class_orphan_report(
            workspace_path=str(self.fx.workspace),
            inventory_path=str(self.fx.inventory_path),
        )
        self._envelope_ok(
            result, vault_mcp_server.ATTACK_CLASS_ORPHAN_REPORT_SCHEMA
        )
        self.assertFalse(result["degraded"])
        orphan_names = {row["attack_class"] for row in result["orphans"]}
        # ``novel-cosmos-fork-bug`` only appears in cosmos_sdk_ibc.
        self.assertIn("novel-cosmos-fork-bug", orphan_names)
        # ``reentrancy-external-call`` spans >=2 subtrees (lending + bridge);
        # not an orphan.
        self.assertNotIn("reentrancy-external-call", orphan_names)
        # ``oracle-manipulation`` spans lending + oracle subtrees -> not
        # an orphan either.
        self.assertNotIn("oracle-manipulation", orphan_names)
        # Orphan-summary present.
        self.assertIn("orphan_summary", result)
        self.assertGreaterEqual(result["orphan_summary"]["total_orphan_classes"], 1)

    # ------------------------------------------------------------------
    # 10. vault_corpus_lineage trace
    # ------------------------------------------------------------------
    def test_10_corpus_lineage_traces_record_back(self):
        result = self.fx.vault.vault_corpus_lineage(
            workspace_path=str(self.fx.workspace),
            record_id="lend-r01",
            max_depth=6,
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_LINEAGE_SCHEMA
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["record_id"], "lend-r01")
        kinds = {entry["kind"] for entry in result["lineage_chain"]}
        # All 4 lineage kinds must appear when the full corpus tree is
        # populated.
        self.assertIn("origin", kinds)
        self.assertIn("etl_miner", kinds)
        self.assertIn("corpus_index", kinds)
        self.assertIn("attribution_trail", kinds)
        self.assertEqual(len(result["context_pack_hash"]), 64)
        # Levels strictly non-decreasing.
        levels = [entry["level"] for entry in result["lineage_chain"]]
        self.assertEqual(levels, sorted(levels))

    # ------------------------------------------------------------------
    # 11. Cross-callable consistency: subtree-summary total ==
    #     corpus-search non-quarantine count + quarantine count
    # ------------------------------------------------------------------
    def test_11_cross_callable_consistency_record_counts(self):
        summary = self.fx.vault.vault_corpus_subtree_summary(
            workspace_path=str(self.fx.workspace),
            tags_dir=str(self.fx.tags_dir),
            exemptions_path=str(self.fx.exemptions_path),
        )
        per_subtree_total = sum(row["records"] for row in summary["subtrees"])
        # Equal to the total in the summary envelope.
        self.assertEqual(per_subtree_total, summary["total_records"])

        # vault_corpus_search defaults to exclude_quarantine=True. The
        # unfiltered, quarantine-included corpus_search total must equal
        # the subtree-summary total.
        full_search = self.fx.vault.vault_corpus_search(
            workspace_path=str(self.fx.workspace),
            query={"exclude_quarantine": False},
            tags_dir=str(self.fx.tags_dir),
            limit=200,
        )
        # An open search (no predicate, quarantine included) hits every
        # record on disk.
        self.assertEqual(full_search["total_records_matched"], TOTAL_RECORDS)

        # Default exclude_quarantine=True drops the 14 tier-5 records.
        default_search = self.fx.vault.vault_corpus_search(
            workspace_path=str(self.fx.workspace),
            query={},
            tags_dir=str(self.fx.tags_dir),
            limit=200,
        )
        self.assertEqual(
            default_search["total_records_matched"], NON_QUARANTINE_RECORDS
        )

        # And the inventory total agrees too.
        tax = self.fx.vault.vault_attack_class_taxonomy(
            workspace_path=str(self.fx.workspace),
            inventory_path=str(self.fx.inventory_path),
            limit=200,
        )
        inv_per_subtree = sum(
            row["total_records"] for row in tax["per_subtree"].values()
        )
        self.assertEqual(inv_per_subtree, TOTAL_RECORDS)

    # ------------------------------------------------------------------
    # 12. Envelope-shape contract for every Wave-1 callable
    # ------------------------------------------------------------------
    def test_12_envelope_shape_contract_all_callables(self):
        # Drive every Wave-1 callable once and assert the universal
        # envelope shape: schema + context_pack_id (prefixed by schema) +
        # 64-char hex context_pack_hash.
        calls: list[tuple[str, dict[str, Any]]] = [
            ("vault_corpus_subtree_summary", {
                "workspace_path": str(self.fx.workspace),
                "tags_dir": str(self.fx.tags_dir),
                "exemptions_path": str(self.fx.exemptions_path),
            }),
            ("vault_attack_class_taxonomy", {
                "workspace_path": str(self.fx.workspace),
                "inventory_path": str(self.fx.inventory_path),
            }),
            ("vault_corpus_search", {
                "workspace_path": str(self.fx.workspace),
                "query": {"attack_class": "reentrancy-external-call"},
                "tags_dir": str(self.fx.tags_dir),
                "limit": 5,
            }),
            ("vault_attack_class_evidence_v2", {
                "workspace_path": str(self.fx.workspace),
                "attack_class": "reentrancy-external-call",
                "index_dir": str(self.fx.index_dir),
                "tags_dir": str(self.fx.tags_dir),
                "limit": 5,
            }),
            ("vault_hacker_brief_for_lane_v2", {
                "workspace_path": str(self.fx.workspace),
                "lane_id": "W1-envelope-lane",
                "files": ["SCOPE.md"],
                "attack_class": "reentrancy-external-call",
                "index_dir": str(self.fx.index_dir),
                "tags_dir": str(self.fx.tags_dir),
                "limit": 5,
            }),
            ("vault_dupe_advisory_check", {
                "workspace_path": str(self.fx.workspace),
                "tags_dir": str(self.fx.tags_dir),
                "cve_id": "CVE-2024-10001",
            }),
            ("vault_severity_calibration", {
                "workspace_path": str(self.fx.workspace),
                "attack_class": "reentrancy-external-call",
                "tags_dir": str(self.fx.tags_dir),
            }),
            ("vault_attack_class_orphan_report", {
                "workspace_path": str(self.fx.workspace),
                "inventory_path": str(self.fx.inventory_path),
            }),
            ("vault_corpus_lineage", {
                "workspace_path": str(self.fx.workspace),
                "record_id": "lend-r01",
            }),
        ]
        schema_constants = {
            "vault_corpus_subtree_summary":
                vault_mcp_server.CORPUS_SUBTREE_SUMMARY_SCHEMA,
            "vault_attack_class_taxonomy":
                vault_mcp_server.ATTACK_CLASS_TAXONOMY_SCHEMA,
            "vault_corpus_search":
                vault_mcp_server.CORPUS_SEARCH_SCHEMA,
            "vault_attack_class_evidence_v2":
                vault_mcp_server.ATTACK_CLASS_EVIDENCE_V2_SCHEMA,
            "vault_hacker_brief_for_lane_v2":
                vault_mcp_server.HACKER_BRIEF_FOR_LANE_V2_SCHEMA,
            "vault_dupe_advisory_check":
                vault_mcp_server.DUPE_ADVISORY_CHECK_SCHEMA,
            "vault_severity_calibration":
                vault_mcp_server.SEVERITY_CALIBRATION_SCHEMA,
            "vault_attack_class_orphan_report":
                vault_mcp_server.ATTACK_CLASS_ORPHAN_REPORT_SCHEMA,
            "vault_corpus_lineage":
                vault_mcp_server.CORPUS_LINEAGE_SCHEMA,
        }
        for name, kwargs in calls:
            with self.subTest(callable=name):
                fn = getattr(self.fx.vault, name)
                result = fn(**kwargs)
                schema_const = schema_constants[name]
                self.assertEqual(result["schema"], schema_const)
                self.assertTrue(
                    result["context_pack_id"].startswith(schema_const),
                    msg=f"{name}: bad context_pack_id {result.get('context_pack_id')}",
                )
                # 64-char lowercase hex SHA-256.
                pack_hash = result["context_pack_hash"]
                self.assertEqual(len(pack_hash), 64, msg=f"{name}: {pack_hash}")
                self.assertTrue(
                    all(c in "0123456789abcdef" for c in pack_hash),
                    msg=f"{name}: non-hex {pack_hash}",
                )


if __name__ == "__main__":
    unittest.main()
