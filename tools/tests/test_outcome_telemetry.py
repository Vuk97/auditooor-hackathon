#!/usr/bin/env python3
"""Smoke tests for tools/outcome-telemetry.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "outcome-telemetry.py"


def write_fixture(workspace: Path) -> None:
    submissions = workspace / "submissions"
    submissions.mkdir(parents=True)
    (submissions / "SUBMISSIONS.md").write_text(
        """# Test Submissions

| Cantina # | Date | Severity | Status | Title |
|---:|---|---|---|---|
| **1** | 2026-01-01 | High | Paid | Accepted high |
| **2** | 2026-01-02 | Medium | Duplicate | Duplicate medium |
| **3** | 2026-01-03 | Low | Rejected | Rejected low |
| **4** | 2026-01-04 | Low | In Review | Review low |
| **5** | 2026-01-05 | Medium | Pending | Pending medium |
""",
    )
    reference = workspace / "reference"
    reference.mkdir()
    rows = [
        {
            "report_id": "1",
            "outcome": "paid",
            "lane": "source-mine",
            "model_route": "kimi->minimax->codex",
            "proof_artifact": "submissions/packaged/accepted-high",
            "production_path_status": "poc_ready",
        },
        {
            "report_id": "2",
            "outcome": "duplicate",
            "lane": "audit-deep",
        },
    ]
    (reference / "outcomes.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp) / "fixture-audit"
        write_fixture(workspace)
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(workspace), "--json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            return proc.returncode

        data = json.loads(proc.stdout)
        summary = data["summary"]
        assert summary["total_records"] == 5
        assert summary["resolved_count"] == 3
        assert summary["outcomes"]["accepted"] == 1
        assert summary["outcomes"]["duplicate"] == 1
        assert summary["outcomes"]["rejected"] == 1
        assert summary["outcomes"]["in_review"] == 1
        assert summary["outcomes"]["pending"] == 1
        assert summary["acceptance_rate"] == 1 / 3
        linkage = summary["outcome_linkage"]
        assert linkage["records_with_outcome_row"] == 2
        assert linkage["missing_outcome_row"] == 3
        assert linkage["missing_lane"] == 3
        assert linkage["missing_model_route"] == 4
        assert linkage["missing_proof_artifact"] == 4
        assert linkage["missing_production_path_status"] == 4
        by_id = {record["finding_id"]: record for record in data["records"]}
        assert by_id["1"]["lane"] == "source-mine"
        assert by_id["1"]["model_route"] == "kimi->minimax->codex"
        assert by_id["1"]["proof_artifact"] == "submissions/packaged/accepted-high"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
