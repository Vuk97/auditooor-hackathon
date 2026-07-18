"""tests/test_chain_verify_persist.py - Unit tests for chain-verify-persist.py

4+ cases:
  1. no-synthesis-file verdict
  2. mock chain that refutes -> pass-all-refuted, KDE entry written
  3. mock chain that holds -> pass-confirmed-chains-persisted, GCT entry written
  4. idempotent re-run: second persist of same chain is deduped (no double-write)

LLM dispatch is mocked via --mock-llm flag; no real network calls.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "chain-verify-persist.py"

MOCK_CHAIN_REFUTED = {
    "task_id": "test-chain-refute-001",
    "narrative": {
        "hops": [
            {
                "invariant_id": "INV-TEST-001",
                "function": "Vault.deposit",
                "target": "Vault.deposit",
                "commit_point": "deposit_before_balance_update",
                "precondition": "User calls deposit",
                "produces_state": "state:funds_held",
            }
        ],
        "attack_class": "reentrancy",
        "composite_impact": "drain vault",
    },
}

MOCK_CHAIN_HOLDS = {
    "task_id": "test-chain-holds-001",
    "narrative": {
        "hops": [
            {
                "invariant_id": "INV-TEST-002",
                "function": "Oracle.getPrice",
                "target": "Oracle.getPrice",
                "commit_point": "price_read_no_staleness",
                "precondition": "Price is stale",
                "produces_state": "state:stale_price_accepted",
            },
            {
                "invariant_id": "INV-TEST-003",
                "function": "Lending.borrow",
                "target": "Lending.borrow",
                "commit_point": "collateral_calc_with_stale_price",
                "precondition": "Stale price inflates collateral",
                "produces_state": "state:undercollateralized_borrow",
            },
        ],
        "attack_class": "oracle-price-manipulation",
        "composite_impact": "undercollateralized borrow",
    },
}


def _run_tool(args: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run the tool with given args; return (returncode, stdout, stderr)."""
    cmd = [sys.executable, str(TOOL)] + args
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(cwd or TOOL.parent.parent),
    )
    return proc.returncode, proc.stdout, proc.stderr


def _make_synthesis(chains: list[dict], tmpdir: Path) -> Path:
    """Create a fake chain_synthesis_2026-05-28.json in tmpdir/.auditooor/."""
    auditooor = tmpdir / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "auditooor.chain_synthesis_report.v1",
        "generated_at": "2026-05-28T00:00:00Z",
        "workspace": str(tmpdir),
        "broken_invariant_ids": ["INV-TEST-001"],
        "matched_templates": 1,
        "chains_synthesized": len(chains),
        "dry_run": False,
        "status": "complete",
        "narratives": chains,
    }
    path = auditooor / "chain_synthesis_2026-05-28.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _load_mod():
    """Import the tool as a module."""
    spec = importlib.util.spec_from_file_location("chain_verify_persist", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Test 1: no synthesis file
# ---------------------------------------------------------------------------
def test_no_synthesis_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir) / "workspace"
        ws.mkdir()
        rc, stdout, _ = _run_tool(["--workspace", str(ws), "--json", "--mock-llm"])
        assert rc == 0, f"expected rc=0, got {rc}"
        data = json.loads(stdout)
        assert data["verdict"] == "pass-no-synthesis-file", data
        assert data["chains_verified"] == 0


# ---------------------------------------------------------------------------
# Test 2: mock chain that refutes -> KDE entry written (module-API, no subprocess)
# ---------------------------------------------------------------------------
def test_refuted_chain_writes_kde() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        _make_synthesis([MOCK_CHAIN_REFUTED], ws)

        # Use ws as repo_root so KDE/GCT stay in temp dir, not real repo
        gct_path = ws / "audit" / "corpus_tags" / "derived" / "global_chain_templates.jsonl"
        gct_path.parent.mkdir(parents=True, exist_ok=True)
        kde_path = ws / "reports" / "known_dead_ends.jsonl"
        kde_path.parent.mkdir(parents=True, exist_ok=True)

        mod = _load_mod()
        synth = ws / ".auditooor" / "chain_synthesis_2026-05-28.json"
        chains = mod._load_chains(synth)
        verdicts = mod.verify_chains(chains, mock=True)
        confirmed = [v for v in verdicts if v["holds"]]
        refuted = [v for v in verdicts if not v["holds"]]

        assert len(confirmed) == 0
        assert len(refuted) == 1

        ts = "2026-05-28T00:00:00Z"
        for v in refuted:
            mod.persist_refuted(v, ws.name, ws, ts, dry_run=False)

        kde_lines = [l for l in kde_path.read_text().splitlines() if l.strip()]
        assert len(kde_lines) == 1, f"expected 1 KDE line, got {len(kde_lines)}"
        kde_row = json.loads(kde_lines[0])
        assert kde_row["kill_verdict"] == "CHAIN-REFUTED"
        assert "test-chain-refute" in kde_row["candidate_id"]

        # GCT file may not even be created if no confirmed chains
        if gct_path.exists():
            gct_content = gct_path.read_text().strip()
            assert gct_content == "", f"GCT should be empty for refuted chain, got: {gct_content}"


# ---------------------------------------------------------------------------
# Test 3: mock chain that holds -> GCT entry written
# ---------------------------------------------------------------------------
def test_confirmed_chain_writes_gct() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        _make_synthesis([MOCK_CHAIN_HOLDS], ws)

        gct_path = ws / "audit" / "corpus_tags" / "derived" / "global_chain_templates.jsonl"
        gct_path.parent.mkdir(parents=True, exist_ok=True)
        kde_path = ws / "reports" / "known_dead_ends.jsonl"
        kde_path.parent.mkdir(parents=True, exist_ok=True)

        mod = _load_mod()

        def _always_confirm(prompt: str, mock: bool = False) -> dict:
            return {
                "holds": True,
                "blocking_defense": "",
                "reasoning": "No blocking defense found.",
                "question_verdicts": {
                    "reachability": "pass",
                    "defense_between_hops": "pass",
                    "cross_contract_trust": "pass",
                    "one_attacker_feasibility": "pass",
                },
            }

        mod._dispatch_verifier = _always_confirm

        synth = ws / ".auditooor" / "chain_synthesis_2026-05-28.json"
        chains = mod._load_chains(synth)
        verdicts = mod.verify_chains(chains, mock=False)

        confirmed = [v for v in verdicts if v["holds"]]
        assert len(confirmed) == 1

        for v in confirmed:
            gct_id = mod.persist_confirmed(
                v, ws.name, ws, "2026-05-28T00:00:00Z", dry_run=False
            )
            assert gct_id is not None

        gct_lines = [l for l in gct_path.read_text().splitlines() if l.strip()]
        assert len(gct_lines) == 1, f"expected 1 GCT line, got {gct_lines}"
        gct_row = json.loads(gct_lines[0])
        assert gct_row["schema_version"] == "auditooor.global_chain_template.v1"
        assert gct_row["source"] == "confirmed-novel-chain"
        assert gct_row["origin_workspace"] == ws.name
        assert gct_row["confirmed_at"] == "2026-05-28T00:00:00Z"


# ---------------------------------------------------------------------------
# Test 4: idempotent re-run (dedup)
# ---------------------------------------------------------------------------
def test_idempotent_persist() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        kde_path = ws / "reports" / "known_dead_ends.jsonl"
        kde_path.parent.mkdir(parents=True, exist_ok=True)

        mod = _load_mod()

        verdict = {
            "task_id": "dedup-test-chain-001",
            "holds": False,
            "blocking_defense": "some-guard",
            "reasoning": "Blocked at hop 1.",
            "question_verdicts": {},
            "raw_chain": {"task_id": "dedup-test-chain-001", "narrative": {}},
        }

        ts = "2026-05-28T00:00:00Z"
        id1 = mod.persist_refuted(verdict, ws.name, ws, ts, dry_run=False)
        id2 = mod.persist_refuted(verdict, ws.name, ws, ts, dry_run=False)

        assert id1 == id2, "IDs should match"
        lines = [l for l in kde_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 1, f"expected 1 KDE line after dedup, got {len(lines)}"


def test_stale_synthesis_older_than_source_mined_queue_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        synth = _make_synthesis([MOCK_CHAIN_REFUTED], ws)
        _write_json(
            ws / ".auditooor" / "exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "generated_at": "2026-05-31T00:00:00Z",
                "queue": [{"lead_id": "EQ-NEW", "broken_invariant_ids": ["INV-NEW"]}],
            },
        )

        rc, stdout, _ = _run_tool([
            "--workspace", str(ws),
            "--synthesis-file", str(synth),
            "--json",
            "--mock-llm",
        ])

        assert rc == 1, f"expected stale synthesis failure, got rc={rc}"
        data = json.loads(stdout)
        assert data["verdict"] == "fail-stale-synthesis-report", data
        assert data["chains_verified"] == 0
        stale_paths = [row["path"] for row in data["input_freshness"]["stale_inputs"]]
        assert ".auditooor/exploit_queue.source_mined.json" in stale_paths
        assert not list((ws / ".auditooor").glob("chain_verdicts_*.json"))


def test_current_synthesis_with_queue_input_passes_empty_chain_report() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        _write_json(
            ws / ".auditooor" / "exploit_queue.json",
            {
                "schema": "auditooor.exploit_queue.v1",
                "generated_at": "2026-05-30T00:00:00Z",
                "queue": [{"lead_id": "EQ-OLD", "broken_invariant_ids": ["INV-OLD"]}],
            },
        )
        _write_json(
            ws / ".auditooor" / "chain_synthesis_2026-05-31.json",
            {
                "schema": "auditooor.chain_synthesis_report.v1",
                "generated_at": "2026-05-31T00:00:00Z",
                "workspace": str(ws),
                "status": "no-invariant-ids",
                "narratives": [],
            },
        )

        rc, stdout, _ = _run_tool(["--workspace", str(ws), "--json", "--mock-llm"])

        assert rc == 0, f"expected current synthesis pass, got rc={rc}"
        data = json.loads(stdout)
        assert data["verdict"] == "pass-all-refuted", data
        assert data["input_freshness"]["verdict"] == "pass-synthesis-current"


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for fn in (
        test_no_synthesis_file,
        test_refuted_chain_writes_kde,
        test_confirmed_chain_writes_gct,
        test_idempotent_persist,
        test_stale_synthesis_older_than_source_mined_queue_fails,
        test_current_synthesis_with_queue_input_passes_empty_chain_report,
    ):
        suite.addTest(unittest.FunctionTestCase(fn))
    return suite


if __name__ == "__main__":
    test_no_synthesis_file()
    print("test_no_synthesis_file PASS")
    test_refuted_chain_writes_kde()
    print("test_refuted_chain_writes_kde PASS")
    test_confirmed_chain_writes_gct()
    print("test_confirmed_chain_writes_gct PASS")
    test_idempotent_persist()
    print("test_idempotent_persist PASS")
    test_stale_synthesis_older_than_source_mined_queue_fails()
    print("test_stale_synthesis_older_than_source_mined_queue_fails PASS")
    test_current_synthesis_with_queue_input_passes_empty_chain_report()
    print("test_current_synthesis_with_queue_input_passes_empty_chain_report PASS")
    print("All 6 tests PASS")
