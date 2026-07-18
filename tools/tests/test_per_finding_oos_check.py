#!/usr/bin/env python3
"""Tests for tools/per-finding-oos-check.py.

Hermetic: each test builds a throwaway workspace under ``tempfile`` and
seeds an OOS_PASTED.md manifest by hand (so we exercise the per-finding
checker without depending on the importer end-to-end).

Coverage map (Wave-2 / I24):

  heuristic mode (default)
    test_heuristic_admin_match              clause + finding both privileged
    test_heuristic_no_match_in_scope        non-overlapping vocabulary
    test_heuristic_multiple_clauses_mixed   mix of MATCH and NO_MATCH

  llm mode (hermetic via in-process import + mock dispatch_runner)
    test_llm_match_via_mock_runner
    test_llm_no_match_via_mock_runner
    test_llm_inconclusive_on_unparseable_response

  manual mode
    test_manual_emits_checklist_and_inconclusive

  artifact shape
    test_canonical_json_artifact_path       <ws>/.auditooor/oos_check_<sha>.json
    test_top_verdict_resolution             match/no_match/inc → 3 verdicts

  legacy fallback
    test_reads_legacy_pasted_without_manifest_block

  failure modes
    test_missing_workspace_fails
    test_missing_finding_fails
    test_no_oos_pasted_fails
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools" / "per-finding-oos-check.py"


def _import_checker():
    """Import the per-finding-oos-check module by file path (hyphen-safe)."""
    spec = importlib.util.spec_from_file_location(
        "per_finding_oos_check", str(CHECKER)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _seed_pasted(workspace: Path, clauses: list[dict[str, str]]) -> Path:
    """Write a minimal OOS_PASTED.md with a JSON manifest fence."""
    payload = {
        "schema": "auditooor.oos_pasted.v1",
        "date": "2026-04-29T00:00:00Z",
        "source_url": "test://oos",
        "project": "test",
        "note": "",
        "clauses_hash": hashlib.sha256(
            "\n".join(f"{c['id']}\t{c['text']}" for c in clauses).encode()
        ).hexdigest(),
        "clauses": clauses,
    }
    body = (
        "# Operator-Pasted OOS\n\n"
        "## Manifest\n\n"
        "<!-- OOS_PASTED_MANIFEST_BEGIN\n"
        + json.dumps(payload, indent=2)
        + "\nOOS_PASTED_MANIFEST_END -->\n"
    )
    out = workspace / "OOS_PASTED.md"
    out.write_text(body, encoding="utf-8")
    return out


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(CHECKER), *args],
        text=True,
        capture_output=True,
    )


class HeuristicModeTests(unittest.TestCase):
    def test_heuristic_admin_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {
                        "id": "C1",
                        "text": "Impacts requiring privileged admin "
                                "action are out of scope.",
                    }
                ],
            )
            finding = ws / "draft.md"
            finding.write_text(
                "The admin can call rebalance(); onlyOwner gates the call."
            )
            r = _run_cli(
                ["--workspace", str(ws), "--finding", str(finding)]
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=matches-oos", r.stdout)
            payload = json.loads(
                next((ws / ".auditooor").glob("oos_check_*.json")).read_text()
            )
            self.assertEqual(payload["mode"], "heuristic")
            self.assertEqual(payload["verdict"], "matches-oos")
            self.assertEqual(payload["clauses_checked"][0]["verdict"], "MATCH")

    def test_heuristic_sybil_neutral_language_match(self) -> None:
        # Gap 2 (Obyte friend-aa 2026-07-09): a Sybil-farming finding written in
        # sybil-NEUTRAL language must still match the "Sybil attacks" OOS clause via
        # the new sybil/multi-identity class.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {
                        "id": "C1",
                        "text": "Basic economic / governance attacks. "
                                "Sybil attacks. Centralization risks.",
                    }
                ],
            )
            finding = ws / "draft.md"
            finding.write_text(
                "A whale farms the uncapped reward daily by pairing with a "
                "fresh disposable counterparty account each day (a new address "
                "each day), never naming the mechanism literally."
            )
            r = _run_cli(["--workspace", str(ws), "--finding", str(finding)])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=matches-oos", r.stdout)
            payload = json.loads(
                next((ws / ".auditooor").glob("oos_check_*.json")).read_text()
            )
            self.assertEqual(payload["verdict"], "matches-oos")

    def test_heuristic_no_match_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {
                        "id": "C1",
                        "text": "Cross-chain bridge issues are out of scope.",
                    }
                ],
            )
            finding = ws / "draft.md"
            finding.write_text(
                "An off-by-one in `_calculateFee` causes a 0.01% under-charge."
            )
            r = _run_cli(
                ["--workspace", str(ws), "--finding", str(finding)]
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=in-scope", r.stdout)

    def test_heuristic_negated_oos_term_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(ws, [{"id": "C1", "text": "Centralization risks"}])
            finding = ws / "draft.md"
            finding.write_text(
                "This is not centralization/admin abuse. The root cause is "
                "a public src validation bug that later users can reach."
            )

            r = _run_cli(["--workspace", str(ws), "--finding", str(finding)])

            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=in-scope", r.stdout)

    def test_self_created_admin_and_poc_hygiene_terms_do_not_match(self) -> None:
        """NUVA-style self-created vault admin is not a privileged-key OOS hit.

        The draft may mention an Admin role, third-party depositors, and test
        files while explaining production reachability. Those terms are not
        exploit prerequisites matching privileged-address, oracle/dependency,
        or test/config-only OOS clauses.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {
                        "id": "C1",
                        "text": "Incorrect data supplied by third party oracles",
                    },
                    {
                        "id": "C2",
                        "text": "Impacts involving centralization risks",
                    },
                    {
                        "id": "C3",
                        "text": "Impacts caused by attacks requiring access to privileged addresses",
                    },
                    {
                        "id": "C4",
                        "text": "Impacts on test files and configuration files",
                    },
                ],
            )
            finding = ws / "draft.md"
            finding.write_text(
                "The attacker is a fresh non-privileged account that creates "
                "its own vault and self-grants Admin over that attacker-created "
                "vault only. The victim is a third-party depositor. The PoC "
                "adds one external Go test file under poc-tests/ but the root cause is in "
                "production vault interest math. oos_traps: centralization-risk, "
                "test-or-config-files, privileged-address-required. Negative "
                "rates are supported by design; the bug is the unsafe math.",
                encoding="utf-8",
            )

            r = _run_cli(["--workspace", str(ws), "--finding", str(finding)])

            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=in-scope", r.stdout)

    def test_heuristic_unnegated_oos_term_still_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(ws, [{"id": "C1", "text": "Centralization risks"}])
            finding = ws / "draft.md"
            finding.write_text(
                "The impact is centralization risk because only the trusted "
                "owner can choose whether to rescue users."
            )

            r = _run_cli(["--workspace", str(ws), "--finding", str(finding)])

            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=matches-oos", r.stdout)

    def test_privileged_clause_does_not_match_guardian_impact_alone(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {
                        "id": "C1",
                        "text": "Privileged-role trust issues are out of scope.",
                    }
                ],
            )
            finding = ws / "draft.md"
            finding.write_text(
                "A lock owner using a public reward-accounting bug can restore enough guardian "
                "voting power to change a governance veto outcome.",
                encoding="utf-8",
            )

            r = _run_cli(["--workspace", str(ws), "--finding", str(finding)])

            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=in-scope", r.stdout)

    def test_heuristic_multiple_clauses_mixed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {"id": "C1", "text": "Best practice recommendations."},
                    {"id": "C2", "text": "Privileged admin compromise."},
                    {"id": "C3", "text": "Cross-chain bridge issues."},
                ],
            )
            finding = ws / "draft.md"
            finding.write_text(
                "The admin / onlyOwner role can drain funds via rebalance(); "
                "no cross-chain or bridge logic involved; the finding is a "
                "concrete reentrancy."
            )
            r = _run_cli(
                ["--workspace", str(ws), "--finding", str(finding)]
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=matches-oos", r.stdout)
            payload = json.loads(
                next((ws / ".auditooor").glob("oos_check_*.json")).read_text()
            )
            verdicts = {
                r["id"]: r["verdict"] for r in payload["clauses_checked"]
            }
            self.assertEqual(verdicts["C2"], "MATCH")
            # C1 best-practice and C3 cross-chain don't share class tokens
            # with the finding text → NO_MATCH.
            self.assertEqual(verdicts["C1"], "NO_MATCH")
            self.assertEqual(verdicts["C3"], "NO_MATCH")


class LlmModeTests(unittest.TestCase):
    def test_llm_match_via_mock_runner(self) -> None:
        mod = _import_checker()
        verdict, evidence = mod.llm_check(
            clause={"id": "C1", "text": "admin compromise OOS"},
            finding_text="The owner key is leaked allowing minting.",
            repo_root=ROOT,
            dispatch_runner=lambda prompt: (
                "VERDICT: MATCH — owner key leak == admin compromise"
            ),
        )
        self.assertEqual(verdict, "MATCH")
        self.assertIn("admin compromise", evidence)

    def test_llm_no_match_via_mock_runner(self) -> None:
        mod = _import_checker()
        verdict, evidence = mod.llm_check(
            clause={"id": "C1", "text": "best-practice recommendations OOS"},
            finding_text="A reentrancy in withdraw() drains the vault.",
            repo_root=ROOT,
            dispatch_runner=lambda prompt: (
                "VERDICT: NO_MATCH — concrete exploit, not a recommendation"
            ),
        )
        self.assertEqual(verdict, "NO_MATCH")

    def test_llm_inconclusive_on_unparseable_response(self) -> None:
        mod = _import_checker()
        verdict, evidence = mod.llm_check(
            clause={"id": "C1", "text": "anything"},
            finding_text="some finding",
            repo_root=ROOT,
            dispatch_runner=lambda prompt: "I cannot answer this question.",
        )
        self.assertEqual(verdict, "INCONCLUSIVE")
        self.assertIn("unparseable", evidence)


class ManualModeTests(unittest.TestCase):
    def test_manual_emits_checklist_and_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [
                    {"id": "C1", "text": "Privileged admin OOS."},
                    {"id": "C2", "text": "Best-practice recommendations."},
                ],
            )
            finding = ws / "draft.md"
            finding.write_text("Some finding text.")
            r = _run_cli(
                [
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(finding),
                    "--manual",
                ]
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=inconclusive", r.stdout)
            md = (finding.with_name("OOS_CHECK.md")).read_text()
            self.assertIn("- [ ] **C1**", md)
            self.assertIn("- [ ] **C2**", md)


class ArtifactShapeTests(unittest.TestCase):
    def test_canonical_json_artifact_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(
                ws,
                [{"id": "C1", "text": "Cross-chain bridge issues OOS."}],
            )
            finding = ws / "draft.md"
            finding.write_text("Reentrancy in withdraw().")
            r = _run_cli(
                ["--workspace", str(ws), "--finding", str(finding)]
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            sha = hashlib.sha256(
                finding.read_text().encode()
            ).hexdigest()
            expected = ws / ".auditooor" / f"oos_check_{sha}.json"
            self.assertTrue(expected.is_file())

    def test_top_verdict_resolution(self) -> None:
        mod = _import_checker()
        only_no = [
            {"id": "C1", "verdict": "NO_MATCH", "text": "x", "evidence": "x"},
            {"id": "C2", "verdict": "NO_MATCH", "text": "x", "evidence": "x"},
        ]
        any_match = [
            {"id": "C1", "verdict": "NO_MATCH", "text": "x", "evidence": "x"},
            {"id": "C2", "verdict": "MATCH", "text": "x", "evidence": "x"},
        ]
        any_inc = [
            {"id": "C1", "verdict": "NO_MATCH", "text": "x", "evidence": "x"},
            {
                "id": "C2",
                "verdict": "INCONCLUSIVE",
                "text": "x",
                "evidence": "x",
            },
        ]
        self.assertEqual(mod.resolve_top_verdict(only_no), "in-scope")
        self.assertEqual(mod.resolve_top_verdict(any_match), "matches-oos")
        self.assertEqual(mod.resolve_top_verdict(any_inc), "inconclusive")


class LegacyFallbackTests(unittest.TestCase):
    def test_manifest_metadata_with_plain_oos_bullets(self) -> None:
        # Cantina prompt captures can have a manifest fence for provenance but
        # leave the clauses as normal Markdown bullets under "Out Of Scope".
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            manifest = {
                "schema": "auditooor.oos_pasted_manifest.v1",
                "source": "operator_supplied_prompt",
                "competition": "example",
            }
            (ws / "OOS_PASTED.md").write_text(
                "# Program Scope\n\n"
                "<!-- OOS_PASTED_MANIFEST_BEGIN\n"
                + json.dumps(manifest, indent=2)
                + "\nOOS_PASTED_MANIFEST_END -->\n\n"
                "## Out Of Scope\n\n"
                "- Files outside `contracts/` as root-cause filing targets.\n"
                "- Centralization-only or gas-only issues unless a concrete\n"
                "  in-scope Medium/High impact is proven.\n",
                encoding="utf-8",
            )
            finding = ws / "draft.md"
            finding.write_text(
                "A reward accounting bug in contracts/StakingVault.sol lets "
                "locked unstakers capture active rewards.",
                encoding="utf-8",
            )

            r = _run_cli(["--workspace", str(ws), "--finding", str(finding)])

            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=in-scope", r.stdout)
            payload = json.loads(
                next((ws / ".auditooor").glob("oos_check_*.json")).read_text()
            )
            self.assertEqual(len(payload["clauses_checked"]), 2)
            self.assertIn(
                "in-scope Medium/High",
                payload["clauses_checked"][1]["text"],
            )
            self.assertTrue(payload["oos_pasted_clauses_hash"])

    def test_reads_legacy_pasted_without_manifest_block(self) -> None:
        # Older OOS_PASTED.md (pre-Wave-2) only had `- OOS-N: ...` lines and
        # no fenced JSON manifest. The checker still parses those lines.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            (ws / "OOS_PASTED.md").write_text(
                "# Operator-Pasted OOS\n\n"
                "## Extracted Clauses\n\n"
                "- OOS-1: Privileged admin compromise is out of scope.\n"
                "- OOS-2: Best practice recommendations.\n"
            )
            finding = ws / "draft.md"
            finding.write_text(
                "The admin role can rebalance() and drain funds."
            )
            r = _run_cli(
                ["--workspace", str(ws), "--finding", str(finding)]
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("verdict=matches-oos", r.stdout)


class FailureModeTests(unittest.TestCase):
    def test_missing_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            finding = Path(td) / "draft.md"
            finding.write_text("x")
            r = _run_cli(
                [
                    "--workspace",
                    str(Path(td) / "no-such-ws"),
                    "--finding",
                    str(finding),
                ]
            )
            self.assertEqual(r.returncode, 1)

    def test_missing_finding_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            _seed_pasted(ws, [{"id": "C1", "text": "anything"}])
            r = _run_cli(
                [
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(ws / "ghost.md"),
                ]
            )
            self.assertEqual(r.returncode, 1)

    def test_no_oos_pasted_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            finding = ws / "draft.md"
            finding.write_text("x")
            r = _run_cli(
                ["--workspace", str(ws), "--finding", str(finding)]
            )
            self.assertEqual(r.returncode, 1)


class ForwardRefutationWindowTest(unittest.TestCase):
    """Rank-6(c): ``_has_unnegated_token`` gains a FORWARD refutation-cue window.

    A token that is explicitly refuted *after* it (same clause) no longer counts
    as an unnegated OOS token, while a genuine reliance sentence - even one that
    later contains an unrelated negation - still fires.
    """

    def setUp(self):
        self.mod = _import_checker()

    def test_plain_reliance_still_fires(self):
        # Control / true-positive: genuine reliance on the token.
        text = "the exploit relies on the guardian role to unlock the vault"
        self.assertTrue(self.mod._has_unnegated_token(text, "guardian"))

    def test_backward_negation_still_suppressed(self):
        # Pre-existing behavior preserved.
        text = "this does not require the guardian at all"
        self.assertFalse(self.mod._has_unnegated_token(text, "guardian"))

    def test_forward_refutation_is_suppressed(self):
        # False-positive suppressed: token then refuted downstream in the clause.
        text = "any reliance on the guardian is refuted because the path is permissionless"
        self.assertFalse(self.mod._has_unnegated_token(text, "guardian"))

    def test_forward_does_not_apply_is_suppressed(self):
        text = "the guardian assumption does not apply here; the account is self-created"
        self.assertFalse(self.mod._has_unnegated_token(text, "guardian"))

    def test_unrelated_forward_negation_still_fires(self):
        # Narrowness guard: a later unrelated "cannot" is NOT a refutation cue,
        # so a genuine reliance sentence still fires.
        text = "the exploit relies on the guardian to sign, and cannot be prevented by users"
        self.assertTrue(self.mod._has_unnegated_token(text, "guardian"))


if __name__ == "__main__":
    unittest.main()
