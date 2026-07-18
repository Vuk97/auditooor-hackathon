import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


class VaultMcpServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-vault-mcp-test-")
        self.root = Path(self.tmp.name)
        self._old_projects_dir = os.environ.get(vault_mcp_server.CLAUDE_PROJECTS_DIR_ENV)
        os.environ[vault_mcp_server.CLAUDE_PROJECTS_DIR_ENV] = str(self.root / "claude-projects")
        self.vault_dir = self.root / "obsidian-vault"
        (self.vault_dir / "anti-patterns").mkdir(parents=True)
        (self.vault_dir / "goals").mkdir()
        (self.vault_dir / "_archive").mkdir()
        (self.vault_dir / "_privacy_quarantine").mkdir()
        (self.vault_dir / ".privacy").mkdir()
        (self.root / "reference").mkdir()

        (self.vault_dir / "NEXT_LOOP.md").write_text(
            "---\ntitle: Next loop\nstatus: active\nsource_ref: docs/CONTINUATION_PLAN.md\n---\n"
            "## G8 limitation-fix-priority\n"
            "- Fix the highest-yield blocker. status: active source: tools/vault-mcp-server.py\n"
            "- Already merged cleanup. status: merged source: docs/OLD.md\n"
            "```bash\n"
            "python3 tools/vault-mcp-server.py --self-test\n"
            "rm -rf /tmp/not-safe\n"
            "```\n",
            encoding="utf-8",
        )
        (self.vault_dir / "INDEX.md").write_text(
            "---\ntitle: Vault index\nstatus: active\n---\n# Index\n\nRead `NEXT_LOOP.md` first.\n",
            encoding="utf-8",
        )
        (self.vault_dir / "INDEX_active.md").write_text(
            "---\ntitle: Active index\nstatus: in_flight\n---\n# Active\n\n- Resume MCP context packs. status: in_flight\n",
            encoding="utf-8",
        )
        (self.vault_dir / "leaky.md").write_text(
            "---\n"
            "title: Leaky note\n"
            "status: active\n"
            "source_ref: docs/CONTINUATION_PLAN.md\n"
            "terminal_artifact: _archive/private.md\n"
            "owner_note: /Users/wolf/secret.txt\n"
            "plain_word: active\n"
            "safe_source_ref: docs/CONTINUATION_PLAN.md\n"
            "---\n"
            "# Leaky note\n\n- Keep metadata bounded. status: active source: active\n"
            "```bash\n"
            "make vault-refresh\n"
            "make deploy-production\n"
            "python3 tools/vault-mcp-server.py --self-test\n"
            "python3 tools/llm-dispatch.py --provider kimi\n"
            "tools/private-runner.sh\n"
            "```\n",
            encoding="utf-8",
        )
        (self.vault_dir / "dispatch").mkdir()
        (self.vault_dir / "dispatch" / "next_dispatch_manifest.json").write_text(
            json.dumps(
                {
                    "slots": [
                        {
                            "gap_id": "G8-1",
                            "status": "active",
                            "title": "Dispatch-only slot",
                            "owned_paths": ["tools/vault-mcp-server.py"],
                        }
                    ],
                    "items": [
                        {
                            "gap_id": "G8-old",
                            "status": "active",
                            "title": "Legacy fallback item",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.vault_dir / "_privacy_quarantine" / "quarantined.md").write_text(
            "# Quarantined\n\nThis note must not be readable.\n",
            encoding="utf-8",
        )
        (self.vault_dir / "anti-patterns" / "m14.md").write_text(
            "---\n"
            "title: M14 fixture trap\n"
            "recommendation: true\n"
            "sample_size: 2\n"
            "last_validated_at: 2026-05-05\n"
            "confidence: medium\n"
            "counter_examples: 1\n"
            "---\n"
            "# M14 fixture trap\n\nAvoid fixture-shaped prompts when evaluating exploit candidates.\n",
            encoding="utf-8",
        )
        (self.vault_dir / "goals" / "current.md").write_text(
            "---\n"
            "objective: Capability lift through memory\n"
            "status: active\n"
            "loop: perpetual\n"
            "terminal_condition: never\n"
            "next_action: run next loop\n"
            "terminal_artifact: iteration ledger row only\n"
            "---\n"
            "# Current goal\n",
            encoding="utf-8",
        )
        (self.vault_dir / "goals" / "done.md").write_text(
            "---\n"
            "objective: Old landed task\n"
            "status: merged\n"
            "terminal_artifact: https://github.com/Vuk97/auditooor/pull/611\n"
            "---\n"
            "# Done goal\n\n- Old terminal row. status: merged\n",
            encoding="utf-8",
        )
        (self.vault_dir / "_archive" / "old.md").write_text("# Old\n", encoding="utf-8")
        (self.vault_dir / ".privacy" / "hidden.md").write_text("# Hidden\n\nDo not expose.\n", encoding="utf-8")
        (self.vault_dir / "secret.md").write_text("api_secret: do-not-return\n", encoding="utf-8")
        (self.root / "reference" / "outcomes.jsonl").write_text(
            json.dumps(
                {
                    "workspace": "morpho",
                    "platform": "cantina",
                    "outcome": "rejected",
                    "rejection_reason": "unknown:no decline reason provided by platform",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (self.root / "reports").mkdir(exist_ok=True)
        (self.root / "reports" / "goal_loop_status_2026-05-05.json").write_text(
            json.dumps(
                {
                    "goal_policy": {
                        "status": "active_continuous_loop",
                        "terminal_completion_allowed": False,
                        "loop_back_phase": "recall_memory",
                    },
                    "next_operational_rule": (
                        "Choose bounded queue items, dispatch work, verify locally, write back memory, and then repeat."
                    ),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.exploit_ws = self._seed_exploit_memory_brief()
        self._seed_harness_failure_report()
        self._seed_knowledge_gap_ledger()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def test_default_stub_vault_falls_back_to_active_shared_vault(self):
        stub_vault = self.root / "stub-vault"
        stub_vault.mkdir()
        shared_vault = self.root / "shared-vault"
        shared_vault.mkdir()
        (shared_vault / "INDEX.md").write_text("# Index\n", encoding="utf-8")
        (shared_vault / "INDEX_active.md").write_text("# Active\n", encoding="utf-8")
        (shared_vault / "NEXT_LOOP.md").write_text("## Next\n", encoding="utf-8")

        original_default = vault_mcp_server.DEFAULT_VAULT
        original_shared = vault_mcp_server.DEFAULT_SHARED_VAULT
        try:
            vault_mcp_server.DEFAULT_VAULT = stub_vault
            vault_mcp_server.DEFAULT_SHARED_VAULT = shared_vault
            vault, note = vault_mcp_server.resolve_vault_dir(str(stub_vault), argv=[])
        finally:
            vault_mcp_server.DEFAULT_VAULT = original_default
            vault_mcp_server.DEFAULT_SHARED_VAULT = original_shared

        self.assertEqual(vault, shared_vault.resolve())
        self.assertIn("using active vault", note)

    def test_explicit_vault_dir_does_not_fallback_to_shared_vault(self):
        explicit_vault = self.root / "explicit-vault"
        explicit_vault.mkdir()
        shared_vault = self.root / "shared-vault"
        shared_vault.mkdir()
        (shared_vault / "INDEX.md").write_text("# Index\n", encoding="utf-8")
        (shared_vault / "INDEX_active.md").write_text("# Active\n", encoding="utf-8")
        (shared_vault / "NEXT_LOOP.md").write_text("## Next\n", encoding="utf-8")

        original_shared = vault_mcp_server.DEFAULT_SHARED_VAULT
        try:
            vault_mcp_server.DEFAULT_SHARED_VAULT = shared_vault
            vault, note = vault_mcp_server.resolve_vault_dir(
                str(explicit_vault),
                argv=["--vault-dir", str(explicit_vault)],
            )
        finally:
            vault_mcp_server.DEFAULT_SHARED_VAULT = original_shared

        self.assertEqual(vault, explicit_vault.resolve())
        self.assertIsNone(note)

    def tearDown(self):
        if self._old_projects_dir is None:
            os.environ.pop(vault_mcp_server.CLAUDE_PROJECTS_DIR_ENV, None)
        else:
            os.environ[vault_mcp_server.CLAUDE_PROJECTS_DIR_ENV] = self._old_projects_dir
        self.tmp.cleanup()

    def _seed_exploit_memory_brief(self) -> Path:
        reports = self.root / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "cross_workspace_finding_graph.json").write_text("{}\n", encoding="utf-8")
        ws = self.root / "audit-ws"
        (ws / "src").mkdir(parents=True)
        (ws / ".auditooor").mkdir()
        (ws / "submissions" / "hardened").mkdir(parents=True)
        (ws / "gates").mkdir()
        (ws / "SCOPE.md").write_text("# Scope\n\nsrc/Vault.sol is in scope.\n", encoding="utf-8")
        (ws / "submissions" / "SUBMISSIONS.md").write_text(
            "\n".join(
                [
                    "# Submissions",
                    "",
                    "| ID | Date | Severity | Status | Title | Source |",
                    "|---|---|---|---|---|---|",
                    "| amp-zero-medium-2026-05-06 | 2026-05-06 | Medium | hardened / fileable_signal=fileable / pre-submit rc=0 with warnings | Zero amp validation gap | `submissions/hardened/amp-zero-medium-2026-05-06.md` |",
                    "| dynamic-fee-sentinel-medium-2026-05-06 | 2026-05-06 | Medium | hardened / fileable_signal=fileable / pre-submit rc=0 with warnings | Dynamic fee sentinel validation gap | `submissions/hardened/dynamic-fee-sentinel-medium-2026-05-06.md` |",
                    "| amp-zero-medium | 2026-05-02 | Medium | superseded by hardened 2026-05-06 copy | Old copy | `submissions/paste_ready/amp-zero-medium.md` |",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (ws / "submissions" / "hardened" / "amp-zero-medium-2026-05-06.md").write_text(
            "# Hardened amp-zero\n", encoding="utf-8"
        )
        (ws / "submissions" / "hardened" / "dynamic-fee-sentinel-medium-2026-05-06.md").write_text(
            "# Hardened dynamic fee sentinel\n", encoding="utf-8"
        )
        (ws / "gates" / "2026-05-06.amp-zero-medium.pre-submit.log").write_text("rc=0\n", encoding="utf-8")
        (ws / "gates" / "2026-05-06.amp-zero-medium.oos-dupe-filter.json").write_text("{}\n", encoding="utf-8")
        (ws / "gates" / "2026-05-06.dynamic-fee-sentinel-medium.pre-submit.log").write_text(
            "rc=0\n", encoding="utf-8"
        )
        (ws / ".auditooor" / "live_topology_proof_requirements.json").write_text(
            json.dumps({"schema": "auditooor.live_topology_proof_requirements.v1", "requirements": []}) + "\n",
            encoding="utf-8",
        )
        (ws / "src" / "Vault.sol").write_text(
            "\n".join(
                [
                    "contract Vault {",
                    "  uint256 public totalAssets;",
                    "  function withdraw(uint256 shares) external {",
                    "    totalAssets -= shares;",
                    "  }",
                    "  function callOut(address target) external {",
                    "    target.call(\"\");",
                    "  }",
                    "}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        angle_classes = [
            "reentrancy",
            "integer-overflow",
            "signature-replay",
            "fund-lock",
            "share-inflation-first-deposit",
        ]
        angles = []
        for idx, bug_class in enumerate(angle_classes, start=1):
            angles.append(
                {
                    "angle_id": f"angle-{idx:03d}",
                    "title": f"{bug_class} test angle",
                    "recommendation_status": "recommended",
                    "protocol_family": "vault",
                    "bug_class_id": bug_class,
                    "target_files": ["src/Vault.sol"],
                    "source_refs": [f"workspace:src/Vault.sol:{idx + 1}"],
                    "live_prerequisites": ["collect proof pair"],
                    "hypothesis": "Check production path with scope evidence.",
                    "attack_surface": "src/Vault.sol",
                    "ranking_rationale": "score=10 source_signal=3 source_matches=1 accepted=0 duplicates=0",
                    "prior_outcome_signal": {
                        "accepted_count": 0,
                        "duplicate_count": 0,
                        "rejected_count": 0,
                        "sample_size": 0,
                    },
                    "nearest_prior_workspaces": [],
                    "duplicate_guard": {
                        "status": "clear",
                        "material_distinction": "",
                        "evidence_chain": ["repo:reference/outcomes.jsonl"],
                    },
                    "oos_guard": {
                        "status": "scope_artifact_present_manual_review",
                        "clause_refs": ["workspace:SCOPE.md"],
                        "rationale": "Scope artifact present; per-finding OOS gate still required.",
                    },
                    "proof_prerequisites": [
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                    "required_artifacts_for_high_critical": ["source citations", "OOS gate"],
                    "source_signal_score": 3.0,
                    "evidence_chain": [
                        f"workspace:src/Vault.sol:{idx + 1}",
                        "repo:reference/outcomes.jsonl",
                        "repo:reports/cross_workspace_finding_graph.json",
                        "workspace:SCOPE.md",
                        "workspace:.auditooor/live_topology_proof_requirements.json",
                    ],
                    "confidence": "medium",
                    "sample_size": 0,
                    "last_validated_at": "2026-05-05",
                    "counter_examples": [],
                    "recommended_next_command": "bash tools/candidate-escalation-loop.sh --workspace <ws> --finding <draft.md>",
                    "not_submit_ready_until": ["pre-submit gate passes", "proof artifacts execute"],
                    "outcome_semantics": {
                        "unknown_reason_declines_learning_scope": "platform_base_rate_only",
                        "cause_learning_allowed": False,
                    },
                }
            )
        source_snapshot_paths = [
            ("repo:reference/outcomes.jsonl", self.root / "reference" / "outcomes.jsonl"),
            ("repo:reports/cross_workspace_finding_graph.json", reports / "cross_workspace_finding_graph.json"),
            ("workspace:SCOPE.md", ws / "SCOPE.md"),
            (
                "workspace:.auditooor/live_topology_proof_requirements.json",
                ws / ".auditooor" / "live_topology_proof_requirements.json",
            ),
        ]
        payload = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace": "audit-ws",
            "workspace_path": str(ws),
            "workspace_posture": "active_or_operator_selected",
            "generated_at": "2026-05-05T00:00:00+00:00",
            "brief_hash": "a" * 64,
            "source_snapshot": [
                {"ref": ref, "sha256_16": hashlib.sha256(path.read_bytes()).hexdigest()[:16]}
                for ref, path in source_snapshot_paths
            ],
            "run_policy": {
                "offline_only": True,
                "llm_used": False,
                "network_used": False,
                "unknown_reason_declines": "platform_base_rate_only_only",
                "submission_ready": False,
            },
            "impact_contract_preflight": {
                "schema_version": "auditooor.impact_contract_preflight.v1",
                "route": "exploit-memory",
                "artifact_class": "planning",
                "artifact_path": None,
                "impact_contract": {
                    "explicit": False,
                    "fields": {},
                    "actor_fields_present": [],
                    "anchor_fields_present": [],
                    "missing": [
                        "impacted actor/surface (victim/protocol/contract/asset)",
                        "evidence anchor (source-proof/harness-scaffold/exploit-memory)",
                    ],
                },
                "decision": {
                    "code": "planning-artifact-advisory-bypass",
                    "blocked": False,
                    "advisory_bypass": True,
                    "summary": "planning artifact bypassed; route remains advisory",
                },
            },
            "summary": {
                "status": "ok",
                "protocol_family": "vault",
                "recommended_angle_count": 5,
                "base_rate_only_rejections": 1,
            },
            "nearest_prior_workspaces": [],
            "bug_class_weights": [
                {
                    "bug_class_id": bug_class,
                    "label": bug_class,
                    "score": 10.0,
                    "source_match_count": 1,
                    "source_signal_score": 3.0,
                    "accepted_count": 0,
                    "duplicate_count": 0,
                    "rejected_count": 0,
                    "sample_size": 0,
                    "graph_count": 0,
                    "evidence_chain": ["repo:reference/outcomes.jsonl"],
                }
                for bug_class in angle_classes
            ],
            "saturated_detector_classes": [],
            "duplicate_risks": [],
            "oos_risks": [],
            "proof_requirements": [
                {
                    "artifact": ".auditooor/live_topology_proof_requirements.json",
                    "status": "required",
                    "summary": "collect proof pair",
                    "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                }
            ],
            "harness_memory": [],
            "knowledge_gap_refs": ["KG-20260505-001"],
            "angles": angles,
            "deferred_items": ["live proof collection"],
        }
        (ws / ".auditooor" / "exploit_memory_brief.json").write_text(
            json.dumps(payload, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return ws

    def _write_finalization_manifest(self, workspace: Path, payload: dict) -> Path:
        manifest_path = workspace / ".auditooor" / "finalization" / "current_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        return manifest_path

    def _seed_buildable_exploit_workspace(self) -> Path:
        reports = self.root / "reports"
        (reports / "protocol_similarity_graph.json").write_text(
            json.dumps({"nodes": [], "edges": []}) + "\n",
            encoding="utf-8",
        )
        ws = self.root / "lazy-exploit-ws"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "submissions" / "paste_ready").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "finding.md").write_text(
            "# Local paste-ready text\n\nDo not infer platform status.\n",
            encoding="utf-8",
        )
        (ws / "SCOPE.md").write_text("# Scope\n\nsrc/*.sol is in scope.\n", encoding="utf-8")
        (ws / ".auditooor" / "live_topology_proof_requirements.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_proof_requirements.v1",
                    "requirements": [
                        {
                            "requirement_id": "LTPR-001",
                            "status": "required_not_collected",
                            "summary": "collect same-block proof pair before any live-proof claim",
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (ws / ".auditooor" / "semantic_live_depth_blockers.json").write_text(
            json.dumps(
                {
                    "advisory_only": True,
                    "coverage_claim": "none_source_shape_only",
                    "evidence_class": "generated_hypothesis",
                    "promotion_allowed": False,
                    "items": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        src = ws / "src"
        src.mkdir()
        (src / "Vault.sol").write_text(
            "contract Vault { uint256 public totalAssets; function deposit(uint256 assets) external returns (uint256 shares) { return convertToShares(assets); } function convertToShares(uint256 assets) public view returns (uint256 shares) { return assets; } }\n",
            encoding="utf-8",
        )
        (src / "Oracle.sol").write_text(
            "contract Oracle { function price() external view returns (uint256) { return 1; } }\n",
            encoding="utf-8",
        )
        (src / "Auth.sol").write_text(
            "contract Auth { address public admin; modifier onlyOwner(){_;} function authorize(address role) external onlyOwner {} }\n",
            encoding="utf-8",
        )
        (src / "Reward.sol").write_text(
            "contract Reward { function claim(address recipient) external { recipient.call(\"\"); } }\n",
            encoding="utf-8",
        )
        (src / "Pool.sol").write_text(
            "contract Pool { function swap(uint256 amountOut, uint256 minAmount) external {} }\n",
            encoding="utf-8",
        )
        (src / "Lending.sol").write_text(
            "contract Lending { function liquidate(address borrower, uint256 collateral) external {} }\n",
            encoding="utf-8",
        )
        return ws

    def _seed_harness_failure_report(self) -> None:
        (self.root / "docs").mkdir(exist_ok=True)
        (self.root / "tools" / "tests").mkdir(parents=True, exist_ok=True)
        (self.root / "docs" / "HARNESS.md").write_text("# Harness notes\n", encoding="utf-8")
        (self.root / "tools" / "tests" / "test_harness_scaffold_emitter.py").write_text(
            "# fixture guard\n",
            encoding="utf-8",
        )
        rows = [
            {
                "schema": "auditooor.harness_failure_root.v1",
                "root_cause_id": "active-proof-harness-missing",
                "title": "Active proof harness missing project setup",
                "status": "active",
                "severity": "high",
                "symptom": "Candidate proof work cannot execute because project-specific setup is absent.",
                "first_seen": "2026-05-05",
                "last_seen": "2026-05-05",
                "occurrence_count": 3,
                "tools_affected": ["tools/live-topology-proof-executor.py", "forge"],
                "known_fix": "Create a project-specific setup fixture before promoting the candidate.",
                "guard": "make live-topology-proof-test",
                "counter_example_links": ["docs/HARNESS.md"],
                "source_paths": ["reports/harness_failures.jsonl", "docs/HARNESS.md"],
                "last_validated_at": "2026-05-05",
            },
            {
                "schema": "auditooor.harness_failure_root.v1",
                "root_cause_id": "m14-prompt-shape-regression",
                "title": "M14 prompt-shape regression produced smoke-passing fake detectors",
                "status": "mitigated",
                "severity": "high",
                "symptom": "LLM dispatch optimized for fixture shape instead of bug-class semantics.",
                "first_seen": "2026-05-04",
                "last_seen": "2026-05-04",
                "occurrence_count": 91,
                "tools_affected": ["tools/agent-dispatch-prompt-lint.py"],
                "known_fix": "Require semantic bug-class anchoring and prompt lint before promotion.",
                "guard": "make memory-next-loop-test",
                "counter_example_links": ["tools/tests/test_harness_scaffold_emitter.py"],
                "source_paths": ["tools/tests/test_harness_scaffold_emitter.py"],
                "last_validated_at": "2026-05-05",
            },
            {
                "schema": "auditooor.harness_failure_root.v1",
                "root_cause_id": "forge-std-resolution",
                "title": "Recon harnesses need deterministic forge-std resolution",
                "status": "watch",
                "severity": "medium",
                "symptom": "Harness scaffolds become non-portable when remappings do not resolve forge-std.",
                "first_seen": "2026-04-29",
                "last_seen": "2026-05-04",
                "occurrence_count": 2,
                "tools_affected": ["tools/chimera-scaffold.py", "forge"],
                "known_fix": "Write remappings.txt when a workspace has lib/forge-std.",
                "guard": "tools/tests/test_chimera_scaffold.py",
                "counter_example_links": ["docs/HARNESS.md"],
                "source_paths": ["docs/HARNESS.md"],
                "last_validated_at": "2026-05-05",
            },
        ]
        report = self.root / "reports" / "harness_failures.jsonl"
        report.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

    def _knowledge_gap_row(
            self,
            *,
            gap_id: str,
            event_type: str,
            status: str,
            occurred_at: str,
            title: str,
            area: str = "memory",
            gap_type: str = "missing_context_pack",
            severity: str = "high",
            resolution: bool = False) -> dict[str, object]:
        return {
            "schema": "auditooor.knowledge_gap_event.v1",
            "event_id": f"{gap_id}:{event_type}:{occurred_at.replace('+00:00', 'Z').replace('-', '').replace(':', '')}",
            "event_type": event_type,
            "gap_id": gap_id,
            "candidate_gap_id": f"G8-{gap_id}",
            "status": status,
            "occurred_at": occurred_at,
            "actor": "codex",
            "area": area,
            "gap_type": gap_type,
            "severity": severity,
            "title": title,
            "question": f"What evidence closes {gap_id}?",
            "description": "Fixture missing-truth row for context-pack tests.",
            "evidence": "docs/KG.md",
            "remediation": "Collect direct evidence before inferring.",
            "blocked_by_artifacts": ["docs/KG.md"],
            "downstream_blocked_tasks": ["MFL-7"],
            "source_paths": ["reports/knowledge_gaps.jsonl", "docs/KG.md"],
            "analyzer_target_paths": ["docs/KG.md"],
            "yield_estimate": "high",
            "effort_estimate": "low",
            "heuristic_fp_risk": "May be resolved by existing docs.",
            "heuristic_fn_risk": "Other consumers may still miss the truth.",
            "resolution_summary": "Resolved by fixture evidence." if resolution else "",
            "resolution_evidence_paths": ["docs/KG.md"] if resolution else [],
            "terminal_artifact": "docs/KG.md" if resolution else "",
            "verification": {
                "commands": [{"command": "make knowledge-gap-test", "exit_code": 0}],
                "passed": True,
            } if resolution else {"commands": [], "passed": False},
            "reopen_reason": "",
        }

    def _seed_knowledge_gap_ledger(self) -> None:
        (self.root / "docs").mkdir(exist_ok=True)
        (self.root / "docs" / "KG.md").write_text("# KG fixture\n", encoding="utf-8")
        rows = [
            self._knowledge_gap_row(
                gap_id="KG-20260505-001",
                event_type="opened",
                status="open",
                occurred_at="2026-05-05T00:00:00+00:00",
                title="Mandatory context-pack consumption is not enforced",
            ),
            self._knowledge_gap_row(
                gap_id="KG-20260505-001",
                event_type="resolved",
                status="resolved",
                occurred_at="2026-05-05T01:00:00+00:00",
                title="Mandatory context-pack consumption is not enforced",
                resolution=True,
            ),
            self._knowledge_gap_row(
                gap_id="KG-20260505-002",
                event_type="opened",
                status="open",
                occurred_at="2026-05-05T02:00:00+00:00",
                title="Harness proof root is unknown",
                area="harness",
                gap_type="harness_root_cause_unknown",
                severity="medium",
            ),
        ]
        ledger = self.root / "reports" / "knowledge_gaps.jsonl"
        ledger.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

    def test_search_returns_bounded_metadata(self):
        result = self.vault.vault_search("fixture trap", category="anti-patterns", limit=1000)
        self.assertEqual(result["limit"], vault_mcp_server.MAX_LIMIT)
        self.assertEqual(len(result["hits"]), 1)
        hit = result["hits"][0]
        self.assertEqual(hit["path"], "anti-patterns/m14.md")
        self.assertEqual(hit["sample_size"], "2")
        self.assertEqual(hit["last_validated_at"], "2026-05-05")
        self.assertEqual(hit["confidence"], "medium")
        self.assertEqual(hit["counter_examples"], "1")

    def test_search_prioritizes_exact_workspace_path_and_title_over_large_incidental_notes(self):
        findings = self.vault_dir / "findings" / "revert-stableswap-hooks"
        findings.mkdir(parents=True)
        (findings / "amp-zero-medium.md").write_text(
            "# Factory accepts zero amplification pools\n\n"
            "Revert stableswap hooks amp-zero hardened submission is fileable after OOS gate.\n",
            encoding="utf-8",
        )
        bug_classes = self.vault_dir / "bug-classes"
        bug_classes.mkdir()
        (bug_classes / "flow-bypass.md").write_text(
            "# Flow bypass\n\n" + ("borrow_against_collateral_after_withdraw_revert " * 500),
            encoding="utf-8",
        )

        result = self.vault.vault_search("revert stableswap hooks amp zero", limit=2)

        self.assertEqual(result["hits"][0]["path"], "findings/revert-stableswap-hooks/amp-zero-medium.md")
        self.assertNotEqual(result["hits"][0]["path"], "bug-classes/flow-bypass.md")

    def test_search_skips_notes_that_require_privacy_refusal(self):
        result = self.vault.vault_search("api_secret", limit=10)
        self.assertEqual(result["hits"], [])

    def test_search_indexes_codified_rules_digest_source(self):
        digest = self.root / "reference" / "codified_rules_digest.md"
        digest.write_text(
            "# Codified Rules Digest\n\n"
            "## R29 - commitment-point-vs-validation-gap\n\n"
            "For cooperative-exit findings, the paste-ready must show the "
            "commitment point and validation gap so sender-attacks-receiver "
            "rules are discoverable.\n",
            encoding="utf-8",
        )

        result = self.vault.vault_search("commitment point validation gap", limit=10)

        paths = [hit["path"] for hit in result["hits"]]
        self.assertIn("reference/codified_rules_digest.md", paths)
        hit = next(hit for hit in result["hits"] if hit["path"] == "reference/codified_rules_digest.md")
        self.assertEqual(hit["category"], "reference")
        self.assertEqual(hit["title"], "Codified Rules Digest")
        self.assertIn("commitment-point-vs-validation-gap", hit["excerpt"])

        scoped = self.vault.vault_search("sender attacks receiver", category="reference", limit=5)
        self.assertEqual(scoped["hits"][0]["path"], "reference/codified_rules_digest.md")

    def test_search_and_get_include_project_memory_namespace(self):
        memory_dir = self.vault._project_memory_dir()
        memory_dir.mkdir(parents=True)
        (memory_dir / "lesson.md").write_text(
            "---\n"
            "title: Project recall lesson\n"
            "description: Search should see project memory\n"
            "type: project\n"
            "---\n"
            "# Project recall lesson\n\n"
            "Project memory contains a searchable banana stand lesson.\n",
            encoding="utf-8",
        )

        result = self.vault.vault_search("banana stand lesson", limit=10)

        self.assertEqual(result["hits"][0]["path"], "project-memory/lesson.md")
        self.assertEqual(result["hits"][0]["category"], "project-memory")

        scoped = self.vault.vault_search("banana stand", category="project-memory", limit=10)
        self.assertEqual([hit["path"] for hit in scoped["hits"]], ["project-memory/lesson.md"])

        note = self.vault.vault_get("project-memory/lesson.md")
        self.assertEqual(note["title"], "Project recall lesson")
        self.assertIn("searchable banana stand lesson", note["body"])
        self.assertEqual(note["frontmatter"]["type"], "project")

    def test_project_memory_refuses_escape_symlink_and_secrets(self):
        memory_dir = self.vault._project_memory_dir()
        memory_dir.mkdir(parents=True)
        (memory_dir / "secret.md").write_text("api_secret: do-not-return\n", encoding="utf-8")
        (self.root / "outside-memory.md").write_text("# Outside\n\nprivate\n", encoding="utf-8")
        alias = memory_dir / "alias.md"
        try:
            alias.symlink_to(self.root / "outside-memory.md")
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")

        escaped = self.vault.vault_get("project-memory/../outside-memory.md")
        self.assertEqual(escaped["error"], "invalid_path")

        secret_search = self.vault.vault_search("api_secret", category="project-memory", limit=10)
        self.assertEqual(secret_search["hits"], [])

        secret = self.vault.vault_get("project-memory/secret.md")
        self.assertEqual(secret["error"], "privacy_refusal")

        symlink = self.vault.vault_get("project-memory/alias.md")
        self.assertEqual(symlink["error"], "privacy_refusal")

    def test_search_refuses_invalid_category_paths(self):
        absolute = self.vault.vault_search("fixture", category=str(self.root))
        self.assertEqual(absolute["hits"], [])

        escaped = self.vault.vault_search("fixture", category="../")
        self.assertEqual(escaped["hits"], [])

        archive = self.vault.vault_search("old", category="_archive")
        self.assertEqual(archive["hits"], [])

        quarantine = self.vault.vault_search("quarantined", category="_privacy_quarantine")
        self.assertEqual(quarantine["hits"], [])

    def test_get_refuses_archive_escape_and_secrets(self):
        archive = self.vault.vault_get("_archive/old.md")
        self.assertEqual(archive["error"], "privacy_refusal")

        quarantine = self.vault.vault_get("_privacy_quarantine/quarantined.md")
        self.assertEqual(quarantine["error"], "privacy_refusal")

        escaped = self.vault.vault_get("../outside.md")
        self.assertEqual(escaped["error"], "invalid_path")

        secret = self.vault.vault_get("secret.md")
        self.assertEqual(secret["error"], "privacy_refusal")

    def test_get_refuses_symlink_aliases(self):
        alias = self.vault_dir / "alias.md"
        try:
            alias.symlink_to(self.vault_dir / ".privacy" / "hidden.md")
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")

        result = self.vault.vault_get("alias.md")
        self.assertEqual(result["error"], "privacy_refusal")

    def test_next_loop_and_goal_state_keep_global_goal_perpetual(self):
        next_loop = self.vault.vault_next_loop(limit=2)
        self.assertEqual(next_loop["items"][0], "## G8 limitation-fix-priority")

        goal = self.vault.vault_goal_state("current")
        self.assertEqual(goal["status"], "found")
        self.assertEqual(goal["loop_policy"]["global_goal"], "perpetual")
        self.assertEqual(goal["loop_policy"]["terminal_condition"], "never")
        self.assertEqual(goal["loop_policy"]["completion_scope"], "iterations_only")
        self.assertEqual(goal["goal"]["frontmatter"]["loop"], "perpetual")

    def test_outcome_context_keeps_unknown_declines_unknown(self):
        result = self.vault.vault_outcome_context(workspace="morpho", platform="cantina")
        self.assertEqual(len(result["rows"]), 1)
        self.assertIn("Unknown-reason declines", result["policy"])
        self.assertEqual(
            result["rows"][0]["rejection_reason"],
            "unknown:no decline reason provided by platform",
        )

    def test_exploit_context_reads_validated_brief_without_raw_source(self):
        first = self.vault.vault_exploit_context(workspace_path=str(self.exploit_ws), limit=3)
        second = self.vault.vault_exploit_context(
            brief_path=str(self.exploit_ws / ".auditooor" / "exploit_memory_brief.json"),
            limit=3,
        )

        self.assertEqual(first["schema"], vault_mcp_server.EXPLOIT_CONTEXT_SCHEMA)
        self.assertEqual(first["kind"], "exploit")
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])
        self.assertEqual(first["validation"]["brief_validated"], True)
        self.assertEqual(first["run_policy"]["offline_only"], True)
        self.assertEqual(first["run_policy"]["llm_used"], False)
        self.assertEqual(first["run_policy"]["network_used"], False)
        self.assertEqual(first["run_policy"]["submission_ready"], False)
        self.assertEqual(first["run_policy"]["unknown_reason_declines"], "platform_base_rate_only_only")
        self.assertEqual(first["summary"]["recommended_angle_count"], 5)
        self.assertEqual(len(first["angles"]), 3)
        self.assertIn("workspace:src/Vault.sol:2", first["source_refs"])
        self.assertIn("repo:reference/outcomes.jsonl", first["source_refs"])
        self.assertEqual(first["knowledge_gap_refs"], ["KG-20260505-001"])
        self.assertTrue(first["privacy_guards"]["raw_workspace_source_not_returned"])
        self.assertNotIn("contract Vault", json.dumps(first))
        for angle in first["angles"]:
            self.assertEqual(
                angle["outcome_semantics"]["unknown_reason_declines_learning_scope"],
                "platform_base_rate_only",
            )
            self.assertFalse(angle["outcome_semantics"]["cause_learning_allowed"])
            self.assertTrue(angle["target_files"])
            self.assertTrue(angle["proof_prerequisites"])

    def test_exploit_context_builds_missing_workspace_brief_from_discovered_inputs(self):
        ws = self._seed_buildable_exploit_workspace()

        result = self.vault.vault_exploit_context(workspace_path=str(ws), limit=2)

        self.assertEqual(result["schema"], vault_mcp_server.EXPLOIT_CONTEXT_SCHEMA)
        self.assertTrue((ws / ".auditooor" / "exploit_memory_brief.json").is_file())
        self.assertTrue((ws / ".auditooor" / "exploit_memory_brief.md").is_file())
        self.assertEqual(result["validation"]["brief_validated"], True)
        self.assertEqual(result["run_policy"]["offline_only"], True)
        self.assertEqual(result["run_policy"]["submission_ready"], False)
        self.assertEqual(len(result["angles"]), 2)
        self.assertIn("workspace:submissions/paste_ready/finding.md", result["source_refs"])
        self.assertIn("workspace:.auditooor/semantic_live_depth_blockers.json", result["source_refs"])
        self.assertTrue(
            any(
                "advisory metadata only" in row["summary"]
                for row in result["proof_requirements"]
            )
        )
        self.assertNotIn("contract Vault", json.dumps(result))

    def test_exploit_context_rebuilds_stale_workspace_brief_on_snapshot_hash_mismatch(self):
        ws = self._seed_buildable_exploit_workspace()
        first = self.vault.vault_exploit_context(workspace_path=str(ws), limit=2)
        self.assertEqual(first["schema"], vault_mcp_server.EXPLOIT_CONTEXT_SCHEMA)
        brief_path = ws / ".auditooor" / "exploit_memory_brief.json"
        old_hash = first["brief_hash"]

        (ws / ".auditooor" / "live_topology_proof_requirements.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_proof_requirements.v1",
                    "requirements": [
                        {
                            "requirement_id": "LTPR-001",
                            "status": "required_not_collected",
                            "summary": "collect same-block proof pair before any live-proof claim",
                        },
                        {
                            "requirement_id": "LTPR-002",
                            "status": "required_not_collected",
                            "summary": "new requirement added after brief generation",
                        },
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        refreshed = self.vault.vault_exploit_context(workspace_path=str(ws), limit=2)
        payload = json.loads(brief_path.read_text(encoding="utf-8"))

        self.assertEqual(refreshed["schema"], vault_mcp_server.EXPLOIT_CONTEXT_SCHEMA)
        self.assertNotEqual(refreshed["brief_hash"], old_hash)
        self.assertTrue(
            any(
                row["artifact"] == "LTPR-002"
                for row in refreshed["proof_requirements"]
            )
        )
        self.assertEqual(refreshed["brief_hash"], payload["brief_hash"])

    def test_explicit_exploit_brief_path_fails_closed_on_snapshot_hash_mismatch(self):
        ws = self._seed_buildable_exploit_workspace()
        first = self.vault.vault_exploit_context(workspace_path=str(ws), limit=2)
        self.assertEqual(first["schema"], vault_mcp_server.EXPLOIT_CONTEXT_SCHEMA)
        brief_path = ws / ".auditooor" / "exploit_memory_brief.json"

        (ws / ".auditooor" / "live_topology_proof_requirements.json").write_text(
            json.dumps({"schema": "auditooor.live_topology_proof_requirements.v1", "requirements": []}) + "\n",
            encoding="utf-8",
        )

        result = self.vault.vault_exploit_context(brief_path=str(brief_path), limit=2)

        self.assertEqual(result["error"], "invalid_brief")
        self.assertIn("source snapshot hash mismatch", result["message"])

    def test_exploit_context_fails_closed_on_invalid_or_missing_brief(self):
        missing = self.vault.vault_exploit_context(workspace_path=str(self.root / "missing-ws"))
        self.assertEqual(missing["error"], "not_found")

        explicit_missing = self.vault.vault_exploit_context(
            brief_path=str(self.root / "missing-ws" / ".auditooor" / "exploit_memory_brief.json")
        )
        self.assertEqual(explicit_missing["error"], "not_found")

        payload_path = self.exploit_ws / ".auditooor" / "exploit_memory_brief.json"
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        payload["angles"][0]["source_refs"] = ["workspace:src/Missing.sol:1"]
        payload_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

        invalid = self.vault.vault_exploit_context(workspace_path=str(self.exploit_ws))
        self.assertEqual(invalid["error"], "invalid_brief")
        self.assertIn("source ref file missing", invalid["message"])

    def test_harness_context_reads_validated_report_stable_bounded(self):
        first = self.vault.vault_harness_context(limit=2)
        second = self.vault.vault_harness_context(limit=2)

        self.assertEqual(first["schema"], vault_mcp_server.HARNESS_CONTEXT_SCHEMA)
        self.assertEqual(first["kind"], "harness")
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])
        self.assertEqual(first["validation"]["report_validated"], True)
        self.assertEqual(first["validation"]["validator"], "tools/harness-failure-memory.py")
        self.assertEqual(first["report_path"], "reports/harness_failures.jsonl")
        self.assertEqual(first["summary"]["root_cause_count"], 3)
        self.assertEqual(first["summary"]["returned_count"], 2)
        self.assertEqual(first["summary"]["active_or_watch_count"], 2)
        self.assertEqual(first["summary"]["status_counts"]["active"], 1)
        self.assertEqual(first["summary"]["status_counts"]["watch"], 1)
        self.assertGreater(first["token_estimate"], 0)
        self.assertIn("reports/harness_failures.jsonl", first["source_refs"])
        self.assertIn("docs/HARNESS.md", first["source_refs"])
        self.assertTrue(first["privacy_guards"]["raw_harness_logs_not_returned"])

        ids = [row["root_cause_id"] for row in first["root_causes"]]
        self.assertEqual(ids, ["active-proof-harness-missing", "forge-std-resolution"])
        active = first["root_causes"][0]
        self.assertEqual(active["severity"], "high")
        self.assertIn("project-specific setup", active["known_fix"])
        self.assertIn("make live-topology-proof-test", active["guard"])
        self.assertIn("forge", active["tools_affected"])
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_harness_context_filters_by_status_severity_and_tool(self):
        watch = self.vault.vault_harness_context(status="watch", severity="medium", tool="forge", limit=5)

        self.assertEqual(watch["summary"]["returned_count"], 1)
        self.assertEqual(watch["filters"], {
            "status": "watch",
            "severity": "medium",
            "tool": "forge",
            "root_cause_id": "",
        })
        self.assertEqual(watch["root_causes"][0]["root_cause_id"], "forge-std-resolution")
        self.assertEqual(watch["root_causes"][0]["status"], "watch")
        self.assertEqual(watch["root_causes"][0]["severity"], "medium")

        exact = self.vault.vault_harness_context(root_cause_id="active-proof-harness-missing", limit=5)
        self.assertEqual(exact["summary"]["returned_count"], 1)
        self.assertEqual(exact["filters"]["root_cause_id"], "active-proof-harness-missing")
        self.assertEqual(exact["root_causes"][0]["root_cause_id"], "active-proof-harness-missing")

    def test_harness_context_status_all_and_any_are_no_op_sentinels(self):
        # Regression for the "literal-string filter" bug: status="all" used to
        # compare row.status == "all" and drop every row. The fix maps
        # all/any to the no-status-filter case so operators get the full set.
        baseline = self.vault.vault_harness_context(limit=10)
        all_pack = self.vault.vault_harness_context(status="all", limit=10)
        any_pack = self.vault.vault_harness_context(status="any", limit=10)
        any_severity_pack = self.vault.vault_harness_context(severity="all", limit=10)

        self.assertEqual(all_pack["summary"]["returned_count"], baseline["summary"]["returned_count"])
        self.assertEqual(any_pack["summary"]["returned_count"], baseline["summary"]["returned_count"])
        self.assertEqual(all_pack["context_pack_hash"], baseline["context_pack_hash"])
        self.assertEqual(any_pack["context_pack_hash"], baseline["context_pack_hash"])
        self.assertEqual(any_severity_pack["context_pack_hash"], baseline["context_pack_hash"])
        # Sentinels normalize to empty string in the echoed filters block so
        # downstream operators can tell "all" was intentional.
        self.assertEqual(all_pack["filters"]["status"], "")
        self.assertEqual(any_pack["filters"]["status"], "")
        self.assertEqual(any_severity_pack["filters"]["severity"], "")
        # Real status values still filter strictly.
        active_pack = self.vault.vault_harness_context(status="active", limit=10)
        self.assertEqual(active_pack["summary"]["returned_count"], 1)
        self.assertEqual(active_pack["root_causes"][0]["root_cause_id"], "active-proof-harness-missing")

    def test_harness_context_fails_closed_on_missing_invalid_or_secret_report(self):
        # R36 pathspec compliance: GAP-FIX-2-44 (tools/agent-pathspec-register.py).
        # Gap #44 (2026-05-26) updated the invalid-report path to emit an
        # honest-degraded pack instead of a bare error dict so consumers
        # can detect drift while still receiving schema + context_pack_id +
        # context_pack_hash. The missing / secret paths still fail closed.
        report = self.root / "reports" / "harness_failures.jsonl"
        report.unlink()
        missing = self.vault.vault_harness_context()
        self.assertEqual(missing["error"], "not_found")

        report.write_text("{not-json}\n", encoding="utf-8")
        invalid = self.vault.vault_harness_context()
        # Gap #44 contract: invalid-report path now returns degraded pack, not
        # a bare error envelope. Consumers MUST get a valid schema envelope.
        self.assertEqual(invalid.get("degraded"), True)
        self.assertEqual(invalid.get("degraded_reason"), "invalid_report")
        self.assertIn("schema", invalid)
        self.assertIn("context_pack_id", invalid)
        self.assertIn("context_pack_hash", invalid)

        report.write_text("api_secret: do-not-return\n", encoding="utf-8")
        secret = self.vault.vault_harness_context()
        self.assertEqual(secret["error"], "privacy_refusal")

    def test_knowledge_gap_context_reads_latest_open_states_stable_bounded(self):
        first = self.vault.vault_knowledge_gap_context(limit=3)
        second = self.vault.vault_knowledge_gap_context(limit=3)

        self.assertEqual(first["schema"], vault_mcp_server.KNOWLEDGE_GAP_CONTEXT_SCHEMA)
        self.assertEqual(first["kind"], "knowledge_gap")
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])
        self.assertEqual(first["validation"]["ledger_validated"], True)
        self.assertEqual(first["validation"]["latest_state_only"], True)
        self.assertEqual(first["ledger_path"], "reports/knowledge_gaps.jsonl")
        self.assertEqual(first["filters"]["status"], "open")
        self.assertEqual(first["summary"]["gap_count"], 2)
        self.assertEqual(first["summary"]["open_count"], 1)
        self.assertEqual(first["summary"]["resolved_count"], 1)
        self.assertEqual(first["summary"]["returned_count"], 1)
        self.assertEqual(first["knowledge_gap_refs"], ["KG-20260505-002"])
        self.assertIn("reports/knowledge_gaps.jsonl", first["source_refs"])
        self.assertIn("docs/KG.md", first["source_refs"])
        self.assertTrue(first["privacy_guards"]["raw_transcripts_not_returned"])
        self.assertNotIn(str(self.root), json.dumps(first))

        gap = first["gaps"][0]
        self.assertEqual(gap["gap_id"], "KG-20260505-002")
        self.assertEqual(gap["status"], "open")
        self.assertEqual(gap["area"], "harness")
        self.assertEqual(gap["gap_type"], "harness_root_cause_unknown")
        self.assertEqual(gap["verification"], {"passed": False, "commands": []})

    def test_knowledge_gap_context_can_include_resolved_and_filter(self):
        all_rows = self.vault.vault_knowledge_gap_context(status="all", limit=5)
        self.assertEqual([gap["gap_id"] for gap in all_rows["gaps"]], ["KG-20260505-002", "KG-20260505-001"])

        resolved = self.vault.vault_knowledge_gap_context(status="resolved", area="memory", severity="high", limit=5)
        self.assertEqual(resolved["summary"]["returned_count"], 1)
        self.assertEqual(resolved["filters"], {
            "status": "resolved",
            "area": "memory",
            "gap_type": "",
            "severity": "high",
            "gap_id": "",
            "candidate_gap_id": "",
        })
        gap = resolved["gaps"][0]
        self.assertEqual(gap["gap_id"], "KG-20260505-001")
        self.assertEqual(gap["status"], "resolved")
        self.assertEqual(gap["terminal_artifact"], "docs/KG.md")
        self.assertEqual(gap["verification"]["passed"], True)
        self.assertEqual(gap["verification"]["commands"][0]["exit_code"], 0)

        exact = self.vault.vault_knowledge_gap_context(
            status="all",
            candidate_gap_id="G8-KG-20260505-002",
            limit=5,
        )
        self.assertEqual(exact["knowledge_gap_refs"], ["KG-20260505-002"])
        self.assertEqual(exact["filters"]["candidate_gap_id"], "G8-KG-20260505-002")

    def test_knowledge_gap_context_fails_closed_on_missing_invalid_or_secret_ledger(self):
        # R36 pathspec compliance: GAP-FIX-2-44 (tools/agent-pathspec-register.py).
        # Gap #44 (2026-05-26) updated the invalid-ledger path to emit an
        # honest-degraded pack instead of a bare error dict. Missing / secret
        # paths still fail closed.
        ledger = self.root / "reports" / "knowledge_gaps.jsonl"
        ledger.unlink()
        missing = self.vault.vault_knowledge_gap_context()
        self.assertEqual(missing["error"], "not_found")

        ledger.write_text("{not-json}\n", encoding="utf-8")
        invalid = self.vault.vault_knowledge_gap_context()
        # Gap #44 contract: invalid-ledger path now returns degraded pack.
        self.assertEqual(invalid.get("degraded"), True)
        self.assertEqual(invalid.get("degraded_reason"), "invalid_ledger")
        self.assertIn("schema", invalid)
        self.assertIn("context_pack_id", invalid)
        self.assertIn("context_pack_hash", invalid)

        ledger.write_text("api_secret: do-not-return\n", encoding="utf-8")
        secret = self.vault.vault_knowledge_gap_context()
        self.assertEqual(secret["error"], "privacy_refusal")

    def test_json_rpc_tools_call(self):
        response = vault_mcp_server.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "vault_goal_state",
                    "arguments": {"goal_id": "current"},
                },
            },
        )
        self.assertEqual(response["id"], 7)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["loop_policy"]["global_goal"], "perpetual")

    def test_dispatch_context_pack_is_stable_bounded_and_filters_terminal_status(self):
        args = {
            "paths": ["INDEX.md", "INDEX_active.md", "NEXT_LOOP.md", "goals/done.md"],
            "limit": 6,
            "knowledge_gap_refs": ["KG-20260505-001", "bad"],
            "source_refs": ["reports/knowledge_gaps.jsonl", "/Users/wolf/private.md"],
        }
        first = self.vault.vault_dispatch_context(**args)
        second = self.vault.vault_dispatch_context(**args)

        self.assertEqual(first["schema"], vault_mcp_server.CONTEXT_PACK_SCHEMA)
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])
        self.assertLessEqual(first["notes_read"], vault_mcp_server.MAX_CONTEXT_NOTES)
        self.assertLessEqual(len(first["items"]), 6)
        self.assertLessEqual(len(first["commands"]), 6)
        self.assertGreater(first["token_estimate"], 0)
        self.assertIn("vault://NEXT_LOOP.md", first["source_refs"])
        self.assertIn("docs/CONTINUATION_PLAN.md", first["source_refs"])
        self.assertIn("reports/knowledge_gaps.jsonl", first["source_refs"])
        self.assertEqual(first["knowledge_gap_refs"], ["KG-20260505-001"])
        self.assertIn("python3 tools/vault-mcp-server.py --self-test", first["commands"])
        self.assertNotIn("rm -rf /tmp/not-safe", first["commands"])
        self.assertNotIn("goals/done.md", [note["path"] for note in first["notes"]])
        self.assertTrue(any(row["reason"] == "filtered_terminal_status" for row in first["filtered"]))
        self.assertTrue(all(item["status_class"] != "terminal" for item in first["items"]))

    def test_dispatch_context_reads_slots_before_legacy_items(self):
        result = self.vault.vault_dispatch_context(paths=[], limit=6)

        item_texts = [item["text"] for item in result["items"]]
        self.assertIn("Dispatch-only slot", item_texts)
        self.assertNotIn("Legacy fallback item", item_texts)

    def test_context_pack_sanitizes_frontmatter_refs_and_commands(self):
        result = self.vault.vault_dispatch_context(paths=["leaky.md"], limit=8)
        note = result["notes"][0]

        self.assertEqual(note["frontmatter"]["title"], "Leaky note")
        self.assertEqual(note["frontmatter"]["status"], "active")
        self.assertEqual(note["frontmatter"]["source_ref"], "docs/CONTINUATION_PLAN.md")
        self.assertNotIn("terminal_artifact", note["frontmatter"])
        self.assertNotIn("owner_note", note["frontmatter"])
        self.assertNotIn("safe_source_ref", note["frontmatter"])
        self.assertIn("docs/CONTINUATION_PLAN.md", result["source_refs"])
        self.assertNotIn("active", result["source_refs"])
        self.assertNotIn("_archive/private.md", result["source_refs"])
        self.assertNotIn("/Users/wolf/secret.txt", result["source_refs"])
        self.assertIn("make vault-refresh", result["commands"])
        self.assertIn("python3 tools/vault-mcp-server.py --self-test", result["commands"])
        self.assertNotIn("make deploy-production", result["commands"])
        self.assertNotIn("python3 tools/llm-dispatch.py --provider kimi", result["commands"])
        self.assertNotIn("tools/private-runner.sh", result["commands"])

    def test_toolsite_context_filters_generated_workflows_without_raw_doc_dump(self):
        tools_dir = self.root / "tools"
        tools_dir.mkdir(exist_ok=True)
        (tools_dir / "hackerman-tooling-index.py").write_text(
            "def build_index():\n"
            "    return {\n"
            "        'workflows': [\n"
            "            {\n"
            "                'id': 'make-audit',\n"
            "                'section': 'make audit',\n"
            "                'summary': 'Canonical first pass for a workspace.',\n"
            "                'tasks': ['start audit', 'new workspace first pass'],\n"
            "                'commands': ['make audit WS=~/audits/<project>'],\n"
            "                'callables': ['vault_engage_report_context'],\n"
            "            },\n"
            "            {\n"
            "                'id': 'brain-prime',\n"
            "                'section': 'Brain-prime',\n"
            "                'summary': 'Prime ranked hunt lanes.',\n"
            "                'tasks': ['brain prime', 'brain-prime'],\n"
            "                'commands': ['make brain-prime WS=~/audits/<project>'],\n"
            "                'callables': ['vault_brain_prime_context'],\n"
            "            },\n"
            "            {\n"
            "                'id': 'high-impact-execution-bridge',\n"
            "                'section': 'High-impact execution bridge',\n"
            "                'summary': 'Bridge high impact invariants into execution records.',\n"
            "                'tasks': ['high-impact-execution-bridge', 'execution bridge'],\n"
            "                'commands': ['make high-impact-execution-bridge WS=~/audits/<project> JSON=1'],\n"
            "                'callables': ['vault_high_impact_execution_bridge_context'],\n"
            "            },\n"
            "            {\n"
            "                'id': 'loop-finalization-check',\n"
            "                'section': 'Loop finalization gate',\n"
            "                'summary': 'Validate closeout manifests.',\n"
            "                'tasks': ['finalize a loop', 'loop finalize'],\n"
            "                'commands': ['make loop-finalization-check MANIFEST=<path>'],\n"
            "                'callables': ['vault_loop_finalization_check'],\n"
            "            },\n"
            "            {\n"
            "                'id': 'known-limitations-burndown',\n"
            "                'section': 'Known-limitations burndown',\n"
            "                'summary': 'Inspect capability blockers.',\n"
            "                'tasks': ['inspect known limitations'],\n"
            "                'commands': ['make known-limitations-burndown WS=~/audits/<project> JSON=1'],\n"
            "                'callables': ['vault_knowledge_gap_context'],\n"
            "            },\n"
            "        ],\n"
            "    }\n",
            encoding="utf-8",
        )

        result = self.vault.vault_toolsite_context(task="start audit", limit=1)

        self.assertEqual(result["schema"], vault_mcp_server.TOOLSITE_CONTEXT_SCHEMA)
        self.assertEqual(result["kind"], "toolsite_context")
        self.assertFalse(result["degraded"])
        self.assertEqual(result["workflows_returned"], 1)
        self.assertEqual(result["workflows"][0]["id"], "make-audit")
        self.assertIn("start audit", result["workflows"][0]["tasks"])
        self.assertIn("make audit WS=~/audits/<project>", result["workflows"][0]["commands"])
        self.assertIn("vault_engage_report_context", result["workflows"][0]["callables"])
        self.assertEqual(result["recommended_first_steps"][0], "make audit WS=~/audits/<project>")
        self.assertLess(
            result["recommended_first_steps"].index("vault_engage_report_context"),
            result["recommended_first_steps"].index("make session-start"),
        )
        self.assertTrue(result["privacy_guards"]["raw_doc_dump_blocked"])
        self.assertTrue(result["context_pack_id"].startswith(vault_mcp_server.TOOLSITE_CONTEXT_SCHEMA))

        via_dispatch = self.vault.call("vault_toolsite_context", {"task": "loop finalize", "limit": 1})
        self.assertEqual(via_dispatch["workflows"][0]["id"], "loop-finalization-check")

        brain_prime = self.vault.call("vault_toolsite_context", {"task": "brain-prime", "limit": 1})
        self.assertEqual(brain_prime["workflows"][0]["id"], "brain-prime")
        self.assertEqual(brain_prime["recommended_first_steps"][0], "make brain-prime WS=~/audits/<project>")
        self.assertLess(
            brain_prime["recommended_first_steps"].index("vault_brain_prime_context"),
            brain_prime["recommended_first_steps"].index("make session-start"),
        )

        execution_bridge = self.vault.call(
            "vault_toolsite_context",
            {"task": "high-impact-execution-bridge", "limit": 1},
        )
        self.assertEqual(execution_bridge["workflows"][0]["id"], "high-impact-execution-bridge")
        self.assertEqual(
            execution_bridge["recommended_first_steps"][0],
            "make high-impact-execution-bridge WS=~/audits/<project> JSON=1",
        )
        self.assertLess(
            execution_bridge["recommended_first_steps"].index("vault_high_impact_execution_bridge_context"),
            execution_bridge["recommended_first_steps"].index("make session-start"),
        )

        known_limitations = self.vault.call(
            "vault_toolsite_context",
            {"task": "inspect known limitations", "limit": 1},
        )
        self.assertEqual(known_limitations["workflows"][0]["id"], "known-limitations-burndown")
        self.assertIn("inspect known limitations", known_limitations["workflows"][0]["tasks"])

    def test_resume_and_finalization_do_not_include_dispatch_manifest_items(self):
        resume = self.vault.vault_resume_context(paths=["INDEX_active.md"], limit=5)
        finalization = self.vault.vault_finalization_context(paths=["goals/current.md"], limit=5)

        self.assertNotIn("Dispatch-only slot", [item["text"] for item in resume["items"]])
        self.assertNotIn("Dispatch-only slot", [item["text"] for item in finalization["items"]])

    def test_context_pack_makes_next_loop_and_current_goal_first_class(self):
        result = self.vault.vault_resume_context(paths=["INDEX_active.md"], limit=5)

        self.assertEqual(result["next_loop"]["status"], "found")
        self.assertEqual(result["next_loop"]["path"], "NEXT_LOOP.md")
        self.assertIn("## G8 limitation-fix-priority", result["next_loop"]["items"])
        self.assertEqual(result["current_goal"]["status"], "found")
        self.assertEqual(result["current_goal"]["objective"], "Capability lift through memory")
        self.assertEqual(result["current_goal"]["status_class"], "live")
        self.assertEqual(result["current_goal"]["loop_policy"]["global_goal"], "perpetual")

    def test_context_pack_keeps_missing_next_loop_and_goal_first_class(self):
        (self.vault_dir / "NEXT_LOOP.md").unlink()
        (self.vault_dir / "goals" / "current.md").unlink()
        (self.vault_dir / "goals" / "done.md").unlink()

        result = self.vault.vault_resume_context(paths=["INDEX_active.md"], limit=5)

        self.assertEqual(result["next_loop"]["status"], "missing")
        self.assertEqual(result["next_loop"]["error"], "not_found")
        self.assertEqual(result["current_goal"]["status"], "found")
        self.assertEqual(result["current_goal"]["objective"], vault_mcp_server.DEFAULT_PERPETUAL_GOAL_OBJECTIVE)
        self.assertEqual(result["current_goal"]["goal_status"], "active_continuous_loop")

    def test_goal_state_falls_back_to_goal_loop_report_when_goals_are_missing(self):
        (self.vault_dir / "goals" / "current.md").unlink()
        (self.vault_dir / "goals" / "done.md").unlink()

        result = self.vault.vault_goal_state("current")

        self.assertEqual(result["status"], "found")
        self.assertEqual(result["source"], "goal_loop_status_report_fallback")
        self.assertEqual(result["goal"]["path"], "INDEX_active.md")
        self.assertEqual(result["goal"]["frontmatter"]["loop"], "perpetual")
        self.assertEqual(result["goal"]["frontmatter"]["status"], "active_continuous_loop")
        self.assertEqual(
            result["goal"]["frontmatter"]["source_report"],
            "reports/goal_loop_status_2026-05-05.json",
        )

    def test_goal_state_stays_missing_without_goals_or_goal_loop_report(self):
        (self.vault_dir / "goals" / "current.md").unlink()
        (self.vault_dir / "goals" / "done.md").unlink()
        (self.root / "reports" / "goal_loop_status_2026-05-05.json").unlink()

        result = self.vault.vault_goal_state("current")

        self.assertEqual(result["status"], "missing_category")
        self.assertIn("No goals/ notes found", result["message"])

    def test_context_pack_workspace_path_adds_bounded_fileable_submission_context(self):
        for idx in range(12):
            (self.exploit_ws / "gates" / f"2026-05-06.amp-zero-medium.extra-{idx:02d}.log").write_text(
                "rc=0\n", encoding="utf-8"
            )

        result = self.vault.vault_resume_context(paths=[], workspace_path=str(self.exploit_ws), limit=5)
        workspace = result["workspace_context"]

        self.assertEqual(workspace["status"], "found")
        self.assertEqual(workspace["workspace"], "audit-ws")
        self.assertFalse(workspace["exploit_brief"]["submission_ready"])
        submissions = workspace["hardened_fileable_submissions"]
        self.assertEqual([row["id"] for row in submissions], [
            "amp-zero-medium-2026-05-06",
            "dynamic-fee-sentinel-medium-2026-05-06",
        ])
        self.assertEqual(submissions[0]["fileable_signal"], "fileable")
        self.assertEqual(submissions[0]["source_ref"], "workspace:submissions/hardened/amp-zero-medium-2026-05-06.md")
        self.assertTrue(all(ref.startswith("workspace:gates/2026-05-06.amp-zero-medium.") for ref in submissions[0]["gate_refs"]))
        self.assertLessEqual(len(workspace["source_refs"]), vault_mcp_server.MAX_CONTEXT_ITEMS)
        self.assertEqual(
            workspace["source_refs"][:3],
            [
                "workspace:submissions/SUBMISSIONS.md",
                "workspace:submissions/hardened/amp-zero-medium-2026-05-06.md",
                "workspace:submissions/hardened/dynamic-fee-sentinel-medium-2026-05-06.md",
            ],
        )
        self.assertIn(
            "workspace:submissions/hardened/dynamic-fee-sentinel-medium-2026-05-06.md",
            workspace["source_refs"],
        )
        self.assertTrue(all(ref.startswith("workspace:") for ref in workspace["source_refs"]))
        self.assertFalse(any("/Users/wolf" in ref or ".." in ref for ref in workspace["source_refs"]))
        self.assertNotIn("contract Vault", json.dumps(workspace))

    def test_context_pack_workspace_path_surfaces_candidate_submission_tables(self):
        (self.exploit_ws / "submissions" / "final_cantina_paste").mkdir(parents=True)
        (self.exploit_ws / "submissions" / "packaged" / "rg-01").mkdir(parents=True)
        (self.exploit_ws / "poc_execution" / "rg-01").mkdir(parents=True)
        (self.exploit_ws / "external" / "repo" / "test").mkdir(parents=True)
        (self.exploit_ws / "submissions" / "final_cantina_paste" / "rg-01.md").write_text(
            "# Paste-ready RG-01\n", encoding="utf-8"
        )
        (self.exploit_ws / "submissions" / "packaged" / "rg-01" / "package_index.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (self.exploit_ws / "submissions" / "packaged" / "rg-01" / "README.md").write_text(
            "# Package\n", encoding="utf-8"
        )
        (self.exploit_ws / "poc_execution" / "rg-01" / "execution_manifest.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (self.exploit_ws / "external" / "repo" / "test" / "RG01.t.sol").write_text(
            "contract RG01 {}\n", encoding="utf-8"
        )
        (self.exploit_ws / "gates" / "rg-01-high.pre-submit.log").write_text(
            "ALL 38 CHECKS PASSED\n", encoding="utf-8"
        )
        (self.exploit_ws / "submissions" / "SUBMISSIONS.md").write_text(
            "\n".join(
                [
                    "# Submissions",
                    "",
                    "| id | severity | status | title | artifacts |",
                    "|---|---|---|---|---|",
                    "| RG-01 | High candidate | candidate | Governance capture chain | `submissions/final_cantina_paste/rg-01.md`, `external/repo/test/RG01.t.sol` |",
                    "| RG-KILL | N/A | killed | Dead lane | `submissions/held/dead.md` |",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.vault.vault_resume_context(paths=[], workspace_path=str(self.exploit_ws), limit=8)
        workspace = result["workspace_context"]
        submissions = workspace["fileable_submissions"]

        self.assertEqual([row["id"] for row in submissions], ["RG-01"])
        self.assertEqual(submissions[0]["fileable_signal"], "candidate")
        self.assertEqual(submissions[0]["severity"], "High candidate")
        self.assertEqual(submissions[0]["source_ref"], "workspace:submissions/final_cantina_paste/rg-01.md")
        self.assertIn("workspace:submissions/final_cantina_paste/rg-01.md", submissions[0]["source_refs"])
        self.assertIn("workspace:external/repo/test/RG01.t.sol", submissions[0]["source_refs"])
        self.assertIn("workspace:submissions/packaged/rg-01/package_index.json", submissions[0]["source_refs"])
        self.assertIn("workspace:submissions/packaged/rg-01/README.md", submissions[0]["source_refs"])
        self.assertIn("workspace:poc_execution/rg-01/execution_manifest.json", submissions[0]["source_refs"])
        self.assertEqual(
            submissions[0]["source_refs"].count("workspace:submissions/final_cantina_paste/rg-01.md"),
            1,
        )
        self.assertIn("workspace:gates/rg-01-high.pre-submit.log", submissions[0]["gate_refs"])
        self.assertIn(
            "workspace:submissions/packaged/rg-01/package_index.json",
            workspace["source_refs"],
        )
        self.assertIn(
            "workspace:poc_execution/rg-01/execution_manifest.json",
            workspace["source_refs"],
        )
        self.assertEqual(
            submissions[0]["gate_refs"].count("workspace:gates/rg-01-high.pre-submit.log"),
            1,
        )
        self.assertEqual(workspace["hardened_fileable_submissions"], submissions)

    def test_context_pack_workspace_path_resolves_current_triager_facing_bare_sources(self):
        (self.exploit_ws / "submissions" / "final_cantina_paste").mkdir(parents=True)
        package_dir = self.exploit_ws / "submissions" / "packaged" / "validation-gap-title-slug"
        package_dir.mkdir(parents=True)
        (self.exploit_ws / "submissions" / "final_cantina_paste" / "amp-zero-medium.md").write_text(
            "# Amp zero\n", encoding="utf-8"
        )
        (self.exploit_ws / "submissions" / "staging").mkdir(parents=True)
        (self.exploit_ws / "submissions" / "staging" / "amp-zero-medium.md").write_text(
            "# Amp zero staging\n", encoding="utf-8"
        )
        (package_dir / "manifest.json").write_text(
            json.dumps({"draft": str(self.exploit_ws / "submissions" / "staging" / "amp-zero-medium.md")}) + "\n",
            encoding="utf-8",
        )
        (package_dir / "source-draft.md").write_text("# Amp zero package\n", encoding="utf-8")
        (package_dir / "pre-submit.log").write_text("4c. substantive inline PoC/test code is present\n", encoding="utf-8")
        (package_dir / "poc.t.sol").write_text("contract AmpZeroPoC {}\n", encoding="utf-8")
        (self.exploit_ws / "submissions" / "SUBMISSIONS.md").write_text(
            "\n".join(
                [
                    "# Submissions",
                    "",
                    "| ID | Date | Severity | Status | Title | Source |",
                    "|---|---|---|---|---|---|",
                    "| amp-zero-medium-2026-05-06 | 2026-05-06 | Medium | current triager-facing body | Zero amp validation gap | `amp-zero-medium.md` |",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.vault.vault_resume_context(paths=[], workspace_path=str(self.exploit_ws), limit=8)
        submissions = result["workspace_context"]["fileable_submissions"]

        self.assertEqual([row["id"] for row in submissions], ["amp-zero-medium-2026-05-06"])
        self.assertEqual(submissions[0]["fileable_signal"], "candidate")
        self.assertEqual(submissions[0]["source_ref"], "workspace:submissions/final_cantina_paste/amp-zero-medium.md")
        self.assertIn("workspace:submissions/staging/amp-zero-medium.md", submissions[0]["source_refs"])
        self.assertIn("workspace:submissions/packaged/validation-gap-title-slug/manifest.json", submissions[0]["source_refs"])
        self.assertIn("workspace:submissions/packaged/validation-gap-title-slug/pre-submit.log", submissions[0]["source_refs"])
        self.assertIn("workspace:submissions/packaged/validation-gap-title-slug/poc.t.sol", submissions[0]["source_refs"])

    def test_context_pack_workspace_path_keeps_package_refs_with_many_artifacts(self):
        (self.exploit_ws / "submissions" / "final_cantina_paste").mkdir(parents=True)
        (self.exploit_ws / "submissions" / "packaged" / "rg-01").mkdir(parents=True)
        (self.exploit_ws / "poc_execution" / "rg-01").mkdir(parents=True)
        (self.exploit_ws / "agent_outputs" / "rg-01").mkdir(parents=True)
        (self.exploit_ws / "submissions" / "final_cantina_paste" / "rg-01.md").write_text(
            "# Paste-ready RG-01\n", encoding="utf-8"
        )
        (self.exploit_ws / "submissions" / "packaged" / "rg-01" / "package_index.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (self.exploit_ws / "submissions" / "packaged" / "rg-01" / "README.md").write_text(
            "# Package\n", encoding="utf-8"
        )
        (self.exploit_ws / "poc_execution" / "rg-01" / "execution_manifest.json").write_text(
            "{}\n", encoding="utf-8"
        )
        artifact_refs = ["`submissions/final_cantina_paste/rg-01.md`"]
        for idx in range(18):
            rel = f"agent_outputs/rg-01/report-{idx:02d}.md"
            (self.exploit_ws / rel).write_text(f"# Report {idx}\n", encoding="utf-8")
            artifact_refs.append(f"`{rel}`")
        (self.exploit_ws / "submissions" / "SUBMISSIONS.md").write_text(
            "\n".join(
                [
                    "# Submissions",
                    "",
                    "| id | severity | status | title | artifacts |",
                    "|---|---|---|---|---|",
                    f"| RG-01 | High candidate | candidate | Governance capture chain | {', '.join(artifact_refs)} |",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.vault.vault_resume_context(paths=[], workspace_path=str(self.exploit_ws), limit=8)
        source_refs = result["workspace_context"]["fileable_submissions"][0]["source_refs"]

        self.assertLessEqual(len(source_refs), vault_mcp_server.MAX_WORKSPACE_SUBMISSION_REFS)
        self.assertIn("workspace:submissions/packaged/rg-01/package_index.json", source_refs)
        self.assertIn("workspace:submissions/packaged/rg-01/README.md", source_refs)
        self.assertIn("workspace:poc_execution/rg-01/execution_manifest.json", source_refs)

    def test_context_pack_workspace_path_redacts_secret_submission_index(self):
        (self.exploit_ws / "submissions" / "SUBMISSIONS.md").write_text(
            "api_secret: do-not-return\n", encoding="utf-8"
        )

        result = self.vault.vault_resume_context(paths=[], workspace_path=str(self.exploit_ws), limit=5)

        self.assertEqual(result["workspace_context"]["hardened_fileable_submissions"], [])
        self.assertEqual(result["workspace_context"]["fileable_submissions"], [])
        self.assertEqual(
            result["workspace_context"]["filtered"],
            [{"path": "submissions/SUBMISSIONS.md", "reason": "privacy_refusal"}],
        )

    def test_context_pack_workspace_path_surfaces_closeout_blockers(self):
        audit_logs = self.exploit_ws / ".audit_logs"
        audit_logs.mkdir()
        (audit_logs / "audit_closeout_manifest.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.audit_closeout.v1",
                    "checks": [
                        {"check": "canonical-audit", "status": "PASS", "reason": "ok"},
                        {"check": "fp-calibration", "status": "WARN", "reason": "6 rows missing"},
                        {"check": "strict-proof", "status": "FAIL", "reason": "missing replay"},
                    ],
                    "summary": {"pass": 1, "warn": 1, "fail": 1},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.vault.vault_resume_context(paths=[], workspace_path=str(self.exploit_ws), limit=8)
        closeout = result["workspace_context"]["audit_closeout"]

        self.assertEqual(closeout["status"], "fail")
        self.assertEqual(closeout["summary"], {"pass": 1, "warn": 1, "fail": 1})
        self.assertEqual(closeout["manifest_ref"], "workspace:.audit_logs/audit_closeout_manifest.json")
        self.assertEqual(
            closeout["unresolved"],
            [
                {"check": "fp-calibration", "status": "warn", "reason": "6 rows missing"},
                {"check": "strict-proof", "status": "fail", "reason": "missing replay"},
            ],
        )
        self.assertIn("workspace:.audit_logs/audit_closeout_manifest.json", result["workspace_context"]["source_refs"])
        self.assertNotIn(str(self.exploit_ws), json.dumps(closeout))

    def test_resume_context_refuses_private_paths_and_secret_notes(self):
        result = self.vault.vault_resume_context(paths=["INDEX_active.md", "_archive/old.md", "secret.md"], limit=5)

        self.assertEqual(result["notes_read"], 1)
        self.assertEqual(result["notes"][0]["path"], "INDEX_active.md")
        reasons = {row["path"]: row["reason"] for row in result["filtered"]}
        self.assertEqual(reasons["_archive/old.md"], "invalid_or_private_path")
        self.assertEqual(reasons["secret.md"], "privacy_refusal")
        self.assertTrue(result["privacy_guards"]["secret_patterns_blocked"])

    def test_finalization_context_keeps_terminal_rows_classified_not_live(self):
        result = self.vault.vault_finalization_context(paths=["goals/current.md", "goals/done.md"], limit=5)

        statuses = {note["path"]: note["status_class"] for note in result["notes"]}
        self.assertEqual(statuses["goals/current.md"], "live")
        self.assertEqual(statuses["goals/done.md"], "terminal")
        self.assertIn("https://github.com/Vuk97/auditooor/pull/611", result["source_refs"])
        self.assertEqual(result["status_filter"]["mode"], "classify_terminal_and_live")

    def test_finalization_context_workspace_surfaces_missing_manifest_summary(self):
        result = self.vault.vault_finalization_context(
            paths=["goals/current.md"],
            workspace_path=str(self.exploit_ws),
            limit=6,
        )

        manifest = result["workspace_context"]["finalization_manifest"]
        self.assertIsInstance(manifest, dict)
        self.assertFalse(manifest["manifest_found"])
        self.assertEqual(manifest["status"], "missing")
        self.assertEqual(manifest["artifact_count"], 0)
        self.assertEqual(manifest["agent_output_count"], 0)
        self.assertEqual(manifest["tests_count"], 0)
        self.assertEqual(manifest["mcp_update"]["status"], "missing")
        self.assertNotIn("finalization_state", result["workspace_context"])
        self.assertIn("workspace:.auditooor/finalization/current_manifest.json", result["workspace_context"]["source_refs"])

    def test_finalization_context_workspace_surfaces_pass_manifest_summary(self):
        self._write_finalization_manifest(
            self.exploit_ws,
            {
                "schema": "auditooor.finalization_manifest.v1",
                "schema_version": 1,
                "workspace_path": str(self.exploit_ws),
                "generated_at_utc": "2026-05-17T12:00:00Z",
                "artifact_paths": ["reports/finalization_manifest_mcp_reader_phase_b_2026-05-17.md"],
                "handoff_or_ledger_paths": ["reports/task_finalization.jsonl"],
                "agent_output_paths": ["agent_outputs/finalization/summary.md", "agent_outputs/finalization/checks.json"],
                "tests_or_logs": {
                    "commands": ["python3 -m pytest tools/tests/test_vault_mcp_server.py -k finalization_manifest"],
                    "logs": ["reports/finalization_manifest_smoke.log"],
                },
                "mcp_task_update_evidence": {
                    "mcp_paths": [".auditooor/finalization/current_manifest.json"],
                    "task_update_paths": ["reports/finalization_manifest_mcp_reader_phase_b_2026-05-17.md"],
                    "notes": ["reader wired into MCP"],
                },
            },
        )

        result = self.vault.vault_finalization_context(
            paths=["goals/current.md"],
            workspace_path=str(self.exploit_ws),
            limit=6,
        )

        manifest = result["workspace_context"]["finalization_manifest"]
        self.assertTrue(manifest["manifest_found"])
        self.assertEqual(manifest["status"], "pass")
        self.assertEqual(manifest["tool_schema"], "auditooor.finalization_manifest.v1")
        self.assertEqual(manifest["artifact_count"], 1)
        self.assertEqual(manifest["agent_output_count"], 2)
        self.assertEqual(manifest["tests_count"], 2)
        self.assertEqual(manifest["mcp_update"]["status"], "pass")
        self.assertEqual(manifest["mcp_update"]["mcp_path_count"], 1)
        self.assertEqual(manifest["mcp_update"]["task_update_path_count"], 1)
        self.assertEqual(manifest["mcp_update"]["note_count"], 1)
        self.assertNotIn("artifact_paths", manifest)
        self.assertNotIn("mcp_task_update_evidence", manifest)
        state = result["workspace_context"]["finalization_state"]
        self.assertEqual(state["source"], "canonical_finalization_manifest")
        self.assertEqual(state["status"], "pass")
        self.assertEqual(state["state_class"], "ready")
        self.assertEqual(state["mcp_update_status"], "pass")
        self.assertEqual(result["items"][0]["source_ref"], "tools/finalization-manifest.py")
        self.assertEqual(result["items"][0]["status_class"], "live")
        self.assertTrue(result["items"][0]["text"].startswith("Canonical finalization manifest state: pass"))
        self.assertIn("workspace:.auditooor/finalization/current_manifest.json", result["workspace_context"]["source_refs"])

    def test_finalization_context_workspace_classifies_fail_manifest_before_prose_items(self):
        self._write_finalization_manifest(
            self.exploit_ws,
            {
                "schema": "auditooor.finalization_manifest.v1",
                "schema_version": 1,
                "workspace_path": str(self.exploit_ws),
                "generated_at_utc": "2026-05-17T12:00:00Z",
                "artifact_paths": ["reports/finalization_manifest_mcp_reader_phase_b_2026-05-17.md"],
                "handoff_or_ledger_paths": ["reports/task_finalization.jsonl"],
                "agent_output_paths": ["agent_outputs/finalization/summary.md"],
                "tests_or_logs": {"commands": [], "logs": []},
                "mcp_task_update_evidence": {"mcp_paths": [], "task_update_paths": [], "notes": []},
            },
        )

        result = self.vault.vault_finalization_context(
            paths=["goals/current.md"],
            workspace_path=str(self.exploit_ws),
            limit=6,
        )

        state = result["workspace_context"]["finalization_state"]
        self.assertEqual(state["status"], "fail")
        self.assertEqual(state["state_class"], "blocked")
        self.assertEqual(state["mcp_update_status"], "missing")
        self.assertEqual(result["items"][0]["source_ref"], "tools/finalization-manifest.py")
        self.assertEqual(result["items"][0]["status_class"], "terminal")
        self.assertTrue(result["items"][0]["text"].startswith("Canonical finalization manifest state: fail"))

    def test_finalization_manifest_context_returns_missing_for_absent_manifest(self):
        workspace = self.root / "workspace-missing"
        workspace.mkdir()

        result = self.vault.vault_finalization_manifest_context(workspace_path=str(workspace))

        self.assertEqual(result["schema"], vault_mcp_server.FINALIZATION_MANIFEST_CONTEXT_SCHEMA)
        self.assertFalse(result["manifest_found"])
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["artifact_count"], 0)
        self.assertEqual(result["agent_output_count"], 0)
        self.assertEqual(result["tests_count"], 0)
        self.assertEqual(result["mcp_update"]["status"], "missing")
        self.assertIn("workspace:.auditooor/finalization/current_manifest.json", result["source_refs"])

    def test_finalization_manifest_context_returns_pass_summary_for_valid_manifest(self):
        workspace = self.root / "workspace-pass"
        workspace.mkdir()
        self._write_finalization_manifest(
            workspace,
            {
                "schema": "auditooor.finalization_manifest.v1",
                "schema_version": 1,
                "workspace_path": str(workspace),
                "generated_at_utc": "2026-05-17T12:00:00Z",
                "artifact_paths": ["reports/finalization_manifest_mcp_reader_phase_b_2026-05-17.md"],
                "handoff_or_ledger_paths": ["reports/task_finalization.jsonl"],
                "agent_output_paths": ["agent_outputs/finalization/summary.md", "agent_outputs/finalization/checks.json"],
                "tests_or_logs": {
                    "commands": ["python3 -m pytest tools/tests/test_vault_mcp_server.py -k finalization_manifest"],
                    "logs": ["reports/finalization_manifest_smoke.log"],
                },
                "mcp_task_update_evidence": {
                    "mcp_paths": [".auditooor/finalization/current_manifest.json"],
                    "task_update_paths": ["reports/finalization_manifest_mcp_reader_phase_b_2026-05-17.md"],
                    "notes": ["reader wired into MCP"],
                },
            },
        )

        result = self.vault.vault_finalization_manifest_context(workspace_path=str(workspace))

        self.assertTrue(result["manifest_found"])
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["agent_output_count"], 2)
        self.assertEqual(result["tests_count"], 2)
        self.assertEqual(result["mcp_update"]["status"], "pass")
        self.assertEqual(result["mcp_update"]["mcp_path_count"], 1)
        self.assertEqual(result["mcp_update"]["task_update_path_count"], 1)
        self.assertEqual(result["mcp_update"]["note_count"], 1)
        self.assertEqual(result["errors"], [])

    def test_finalization_manifest_context_returns_fail_and_error_for_invalid_or_malformed_manifest(self):
        workspace_fail = self.root / "workspace-fail"
        workspace_fail.mkdir()
        self._write_finalization_manifest(
            workspace_fail,
            {
                "schema": "auditooor.finalization_manifest.v1",
                "schema_version": 1,
                "workspace_path": str(workspace_fail),
                "generated_at_utc": "2026-05-17T12:00:00Z",
                "artifact_paths": ["reports/finalization_manifest_mcp_reader_phase_b_2026-05-17.md"],
                "handoff_or_ledger_paths": ["reports/task_finalization.jsonl"],
                "agent_output_paths": ["agent_outputs/finalization/summary.md"],
                "tests_or_logs": {"commands": [], "logs": []},
                "mcp_task_update_evidence": {"mcp_paths": [], "task_update_paths": [], "notes": []},
            },
        )

        fail_result = self.vault.vault_finalization_manifest_context(workspace_path=str(workspace_fail))
        self.assertEqual(fail_result["status"], "fail")
        self.assertTrue(fail_result["manifest_found"])
        self.assertIn("tests_or_logs must include non-empty commands or logs", fail_result["errors"])
        self.assertEqual(fail_result["mcp_update"]["status"], "missing")

        workspace_bad = self.root / "workspace-bad"
        bad_manifest = workspace_bad / ".auditooor" / "finalization" / "current_manifest.json"
        bad_manifest.parent.mkdir(parents=True, exist_ok=True)
        bad_manifest.write_text("{not-json}\n", encoding="utf-8")

        error_result = self.vault.vault_finalization_manifest_context(workspace_path=str(workspace_bad))
        self.assertEqual(error_result["status"], "error")
        self.assertTrue(error_result["manifest_found"])
        self.assertTrue(error_result["errors"])
        self.assertEqual(error_result["mcp_update"]["status"], "error")

    def test_json_rpc_lists_and_calls_context_pack_tools(self):
        listed = vault_mcp_server.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 8, "method": "tools/list"},
        )
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("vault_dispatch_context", names)
        self.assertIn("vault_resume_context", names)
        self.assertIn("vault_finalization_context", names)
        self.assertIn("vault_exploit_context", names)
        self.assertIn("vault_harness_context", names)
        self.assertIn("vault_knowledge_gap_context", names)
        self.assertIn("vault_finalization_manifest_context", names)
        self.assertIn("vault_toolsite_context", names)
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        for name in ("vault_dispatch_context", "vault_resume_context", "vault_finalization_context"):
            props = by_name[name]["inputSchema"]["properties"]
            self.assertIn("source_refs", props)
            self.assertIn("knowledge_gap_refs", props)
            self.assertIn("workspace_path", props)
        self.assertIn("workspace_path", by_name["vault_finalization_manifest_context"]["inputSchema"]["properties"])
        self.assertIn("manifest_path", by_name["vault_finalization_manifest_context"]["inputSchema"]["properties"])
        self.assertIn("task", by_name["vault_toolsite_context"]["inputSchema"]["properties"])
        self.assertIn("workspace_path", by_name["vault_exploit_context"]["inputSchema"]["properties"])
        self.assertIn("status", by_name["vault_harness_context"]["inputSchema"]["properties"])
        self.assertIn("root_cause_id", by_name["vault_harness_context"]["inputSchema"]["properties"])
        self.assertIn("area", by_name["vault_knowledge_gap_context"]["inputSchema"]["properties"])

        response = vault_mcp_server.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "vault_dispatch_context",
                    "arguments": {"paths": ["NEXT_LOOP.md"], "limit": 2},
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["kind"], "dispatch")
        self.assertTrue(payload["context_pack_id"].startswith(vault_mcp_server.CONTEXT_PACK_SCHEMA))

        exploit_response = vault_mcp_server.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "vault_exploit_context",
                    "arguments": {"workspace_path": str(self.exploit_ws), "limit": 1},
                },
            },
        )
        exploit_payload = json.loads(exploit_response["result"]["content"][0]["text"])
        self.assertEqual(exploit_payload["kind"], "exploit")
        self.assertEqual(len(exploit_payload["angles"]), 1)

        harness_response = vault_mcp_server.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "vault_harness_context",
                    "arguments": {"status": "watch", "limit": 1},
                },
            },
        )
        harness_payload = json.loads(harness_response["result"]["content"][0]["text"])
        self.assertEqual(harness_payload["kind"], "harness")
        self.assertEqual(len(harness_payload["root_causes"]), 1)

        kg_response = vault_mcp_server.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "vault_knowledge_gap_context",
                    "arguments": {"status": "open", "limit": 1},
                },
            },
        )
        kg_payload = json.loads(kg_response["result"]["content"][0]["text"])
        self.assertEqual(kg_payload["kind"], "knowledge_gap")
        self.assertEqual(len(kg_payload["gaps"]), 1)


class VaultMcpServerCallTelemetryTest(unittest.TestCase):
    """Adoption telemetry wrapper around VaultQuery.call().

    Schema verified:
      {"ts","workspace","callable","args_hash","verdict","duration_ms","degraded"}
    Per-workspace log: <workspace>/.auditooor/mcp_call_log.jsonl when
    workspace_path is detected, falling back to $TMPDIR/mcp_call_log.jsonl.
    Kill-switch: AUDITOOOR_MCP_TELEMETRY_DISABLE=1 skips logging.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-mcp-telemetry-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        (self.vault_dir / "INDEX.md").write_text(
            "---\ntitle: index\nstatus: active\n---\n# Index\n",
            encoding="utf-8",
        )
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)
        # Default to fallback path so leftover env doesn't contaminate.
        self._saved_env = {
            k: os.environ.get(k)
            for k in (
                "AUDITOOOR_MCP_TELEMETRY_DISABLE",
                "AUDITOOOR_WORKSPACE",
            )
        }
        os.environ.pop("AUDITOOOR_MCP_TELEMETRY_DISABLE", None)
        os.environ.pop("AUDITOOOR_WORKSPACE", None)

    def tearDown(self) -> None:
        self.tmp.cleanup()
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_unknown_tool_still_records_telemetry_under_workspace(self) -> None:
        # workspace_path in args -> log lands in <ws>/.auditooor/mcp_call_log.jsonl.
        result = self.vault.call(
            "vault_does_not_exist",
            {"workspace_path": str(self.workspace), "extra": 42},
        )
        self.assertEqual(result.get("error"), "unknown_tool")
        log = self.workspace / ".auditooor" / "mcp_call_log.jsonl"
        self.assertTrue(log.is_file(), "telemetry log not created under workspace")
        rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        for key in ("ts", "workspace", "callable", "args_hash", "verdict", "duration_ms", "degraded"):
            self.assertIn(key, row, f"missing key {key}")
        self.assertEqual(row["callable"], "vault_does_not_exist")
        self.assertEqual(row["verdict"], "error")
        self.assertEqual(row["workspace"], str(self.workspace))
        self.assertEqual(len(row["args_hash"]), 8)
        self.assertIsInstance(row["duration_ms"], int)

    def test_kill_switch_disables_telemetry(self) -> None:
        os.environ["AUDITOOOR_MCP_TELEMETRY_DISABLE"] = "1"
        self.vault.call(
            "vault_does_not_exist",
            {"workspace_path": str(self.workspace)},
        )
        log = self.workspace / ".auditooor" / "mcp_call_log.jsonl"
        self.assertFalse(log.is_file(), "telemetry log written despite kill-switch")

    def test_env_workspace_fallback_writes_log(self) -> None:
        env_ws = self.root / "envws"
        env_ws.mkdir()
        os.environ["AUDITOOOR_WORKSPACE"] = str(env_ws)
        self.vault.call("vault_does_not_exist", {})
        log = env_ws / ".auditooor" / "mcp_call_log.jsonl"
        self.assertTrue(log.is_file())

    def test_no_workspace_falls_back_to_tmpdir(self) -> None:
        # Use a private fallback path via tempfile-style override.
        # We can not redirect _TELEMETRY_FALLBACK_LOG without monkey-patching;
        # instead check that the call does NOT raise and does NOT create a
        # workspace-side log when workspace is absent.
        result = self.vault.call("vault_does_not_exist", {"no_workspace_here": True})
        self.assertEqual(result.get("error"), "unknown_tool")
        # The fallback log path is /tmp/mcp_call_log.jsonl by module default;
        # we don't assert on its content (shared mutable), only that it exists
        # OR that the call returned without raising.
        # Just verify no per-workspace dir was created spuriously.
        self.assertFalse((self.workspace / ".auditooor").exists())

    def test_relative_workspace_never_creates_stub_under_cwd(self) -> None:
        # Regression: a bare RELATIVE workspace name (e.g. "dydx") must NOT be
        # resolved against the process CWD (the tooling repo) and auto-vivify a
        # near-empty stub dir <cwd>/dydx/.auditooor/mcp_call_log.jsonl. The
        # relative name must no-op (fall back to the /tmp log), never mkdir a
        # stub under the repo. (tools/ws-resolve-guard.sh guarded the symptom;
        # this locks the root-cause fix in the telemetry logger.)
        rel_name = "dydx-regression-stub"
        # Run from a sandboxed CWD so a leak would be observable and isolated.
        prev_cwd = os.getcwd()
        os.chdir(self.root)
        try:
            self.assertIsNone(
                vault_mcp_server._telemetry_resolve_workspace(
                    {"workspace_path": rel_name}
                ),
                "relative workspace name must resolve to None, not a CWD-relative path",
            )
            # End-to-end: a real call with a relative workspace must not leak a dir.
            result = self.vault.call(
                "vault_does_not_exist", {"workspace_path": rel_name}
            )
            self.assertEqual(result.get("error"), "unknown_tool")
        finally:
            os.chdir(prev_cwd)
        leaked = self.root / rel_name
        self.assertFalse(
            leaked.exists(),
            f"relative workspace auto-vivified a stub dir: {leaked}",
        )
        # And _telemetry_log_path defends in depth: a relative value falls back.
        self.assertEqual(
            vault_mcp_server._telemetry_log_path(rel_name),
            vault_mcp_server._TELEMETRY_FALLBACK_LOG,
        )
        self.assertFalse((self.root / rel_name).exists())

    def test_dispatch_routes_through_call_wrapper(self) -> None:
        # vault_get on a missing path returns a structured error-like result
        # but the dispatch should still be exercised. The important check is
        # that telemetry logged ONE row under the workspace.
        self.vault.call(
            "vault_get",
            {"path": "nonexistent.md", "workspace_path": str(self.workspace)},
        )
        log = self.workspace / ".auditooor" / "mcp_call_log.jsonl"
        self.assertTrue(log.is_file())
        rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callable"], "vault_get")


# r36-rebuttal: bugfix-inventory-claude-20260610 registered in agent_pathspec.json
class FileableSignalWordBoundaryTest(unittest.TestCase):
    """Guard against substring false-positives in _fileable_signal (bug-inventory-claude-20260610 Bug 1)."""

    def test_notfileable_is_not_classified_as_fileable(self):
        # 'fileable' is a substring of 'notfileable' - plain 'in' check is wrong
        result = vault_mcp_server._fileable_signal("NOTFILEABLE")
        self.assertEqual(result, "", "NOTFILEABLE should NOT match as fileable - word-boundary required")

    def test_unfileable_is_not_classified_as_fileable(self):
        result = vault_mcp_server._fileable_signal("unfileable")
        self.assertEqual(result, "", "unfileable should NOT match as fileable")

    def test_nonfileable_is_not_classified_as_fileable(self):
        result = vault_mcp_server._fileable_signal("nonfileable")
        self.assertEqual(result, "", "nonfileable should NOT match as fileable")

    def test_notfileable_in_context_sentence_is_not_classified(self):
        result = vault_mcp_server._fileable_signal("status: notfileable - oos finding")
        self.assertEqual(result, "", "notfileable in a status sentence should NOT match")

    def test_fileable_alone_still_returns_possible_fileable(self):
        result = vault_mcp_server._fileable_signal("fileable")
        self.assertEqual(result, "possible_fileable")

    def test_is_fileable_candidate_still_returns_possible_fileable(self):
        result = vault_mcp_server._fileable_signal("is fileable candidate")
        self.assertEqual(result, "possible_fileable")

    def test_fileable_signal_equals_fileable_returns_fileable_not_possible(self):
        result = vault_mcp_server._fileable_signal("fileable_signal=fileable")
        self.assertEqual(result, "fileable")


if __name__ == "__main__":
    unittest.main()
