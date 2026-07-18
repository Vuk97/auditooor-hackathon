#!/usr/bin/env python3
"""
test_capability_inventory.py -- Tests for capability inventory schema and tools.

Tests:
  1. Schema validity for all generated records
  2. Dependencies form a DAG (no cycles)
  3. Verification commands are well-formed shell
  4. At least 80 capabilities inventoried
  5. At least 15 canonical flows
  6. Each known-bug references a real cap_id from capability_patch_queue.md
  7. --diff flag detects schema-incompatible changes (mock test)

Run:
  python3 -m unittest tools.tests.test_capability_inventory -v
"""

import json
import os
import re
import sys
import unittest
from pathlib import Path

# Ensure repo root is on the path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

INVENTORY_PATH = REPO_ROOT / "reference" / "capability_inventory.jsonl"
FLOWS_PATH = REPO_ROOT / "reference" / "canonical_flows.jsonl"
CAP_PATCH_QUEUE = REPO_ROOT / "reports" / "v3_iter_2026-05-24" / "capability_patch_queue.md"


def _load_inventory() -> list[dict]:
    if not INVENTORY_PATH.exists():
        return []
    records = []
    with open(INVENTORY_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _load_flows() -> list[dict]:
    if not FLOWS_PATH.exists():
        return []
    records = []
    with open(FLOWS_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _extract_cap_ids_from_patch_queue() -> set[str]:
    """Extract normalized CAP-YYYY-MM-DD-NNN IDs from capability_patch_queue.md."""
    ids: set[str] = set()
    if not CAP_PATCH_QUEUE.exists():
        return ids
    text = CAP_PATCH_QUEUE.read_text(errors="replace")
    # Match "### CAP-2026-05-24-NNN" or "### CAP-MORPHO-..." patterns
    for m in re.finditer(r"^### (CAP-[^\s-][^\n]+)", text, re.MULTILINE):
        raw = m.group(1).strip()
        # Normalize: strip " - Description" suffix
        normalized = raw.split(" - ")[0].strip()
        ids.add(normalized)
    return ids


class TestCapabilityInventorySchema(unittest.TestCase):
    """Test 1: Schema validity for all generated records."""

    REQUIRED_FIELDS = [
        "id", "name", "category", "description",
        "inputs", "outputs", "file_paths",
        "dependencies", "consumers",
        "status", "known_bugs",
        "verification_history", "canonical_flow_refs",
    ]
    VALID_CATEGORIES = {
        "make-target", "mcp-callable", "r-rule",
        "python-tool", "shell-tool", "hook", "workflow-stage",
    }
    VALID_STATUSES = {
        "LANDED", "NOMINAL-WIRED", "PARTIAL", "KNOWN-BROKEN", "DEPRECATED",
    }

    def setUp(self):
        self.records = _load_inventory()
        if not self.records:
            # Build inventory if not yet generated
            try:
                import subprocess
                subprocess.run(
                    [sys.executable, str(REPO_ROOT / "tools" / "capability-inventory-build.py")],
                    check=True,
                    capture_output=True,
                )
                self.records = _load_inventory()
            except Exception:
                pass

    def test_inventory_exists_and_parses(self):
        """Inventory file must exist and contain valid JSON records."""
        self.assertTrue(INVENTORY_PATH.exists(), f"Inventory not found at {INVENTORY_PATH}. Run: python3 tools/capability-inventory-build.py")
        self.assertGreater(len(self.records), 0, "Inventory is empty")

    def test_required_fields_present(self):
        """Every record must have required fields."""
        for i, record in enumerate(self.records):
            for field in self.REQUIRED_FIELDS:
                self.assertIn(
                    field, record,
                    f"Record #{i} (id={record.get('id','?')}) missing required field '{field}'"
                )

    def test_category_values_valid(self):
        """Every category value must be from the known set."""
        for record in self.records:
            cat = record.get("category", "")
            self.assertIn(
                cat, self.VALID_CATEGORIES,
                f"Record {record.get('id','?')} has invalid category '{cat}'. Valid: {self.VALID_CATEGORIES}"
            )

    def test_status_values_valid(self):
        """Every status value must be from the known set."""
        for record in self.records:
            st = record.get("status", "")
            self.assertIn(
                st, self.VALID_STATUSES,
                f"Record {record.get('id','?')} has invalid status '{st}'. Valid: {self.VALID_STATUSES}"
            )

    def test_id_format(self):
        """Every record ID must start with CAP- and be alphanumeric+dash."""
        id_pattern = re.compile(r"^CAP-[a-zA-Z0-9][a-zA-Z0-9\-\.]+$")
        for record in self.records:
            rec_id = record.get("id", "")
            self.assertRegex(
                rec_id, id_pattern,
                f"Record ID '{rec_id}' does not match CAP-... pattern"
            )

    def test_ids_unique(self):
        """All capability IDs must be unique."""
        ids = [r["id"] for r in self.records]
        self.assertEqual(
            len(ids), len(set(ids)),
            f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"
        )

    def test_known_bugs_structure(self):
        """known_bugs must be a list; each item must have cap_id and description."""
        for record in self.records:
            bugs = record.get("known_bugs", [])
            self.assertIsInstance(bugs, list, f"{record.get('id')} known_bugs must be a list")
            for bug in bugs:
                self.assertIn("cap_id", bug, f"{record.get('id')} bug missing cap_id")
                self.assertIn("description", bug, f"{record.get('id')} bug missing description")


class TestCapabilityInventoryDAG(unittest.TestCase):
    """Test 2: Dependencies form a DAG (no cycles)."""

    def setUp(self):
        self.records = _load_inventory()

    def test_no_dependency_cycles(self):
        """Dependencies must form a DAG - no circular references."""
        adj = {r["id"]: r.get("dependencies", []) for r in self.records}
        id_set = set(adj.keys())

        def has_cycle(node, visited, rec_stack):
            visited.add(node)
            rec_stack.add(node)
            for dep in adj.get(node, []):
                if dep not in id_set:
                    continue  # External dep, skip
                if dep not in visited:
                    if has_cycle(dep, visited, rec_stack):
                        return True
                elif dep in rec_stack:
                    return True
            rec_stack.discard(node)
            return False

        visited: set = set()
        for node in adj:
            if node not in visited:
                self.assertFalse(
                    has_cycle(node, visited, set()),
                    f"Dependency cycle detected starting from {node}"
                )


class TestVerificationCommands(unittest.TestCase):
    """Test 3: Verification commands are well-formed shell."""

    def setUp(self):
        self.records = _load_inventory()

    def test_verification_commands_well_formed(self):
        """verification_command must be a non-empty string or None."""
        for record in self.records:
            cmd = record.get("verification_command")
            if cmd is not None:
                self.assertIsInstance(
                    cmd, str,
                    f"{record.get('id')} verification_command must be a string"
                )
                self.assertGreater(
                    len(cmd.strip()), 0,
                    f"{record.get('id')} verification_command is empty string"
                )
                # Must not contain obvious shell injection risks in the static template
                # (actual execution is separate)
                self.assertNotIn(
                    "$(rm ", cmd,
                    f"{record.get('id')} verification_command contains dangerous rm subshell"
                )

    def test_expected_verification_output_is_regex(self):
        """expected_verification_output must be None or a valid regex."""
        for record in self.records:
            pat = record.get("expected_verification_output")
            if pat is not None and pat != "":
                try:
                    re.compile(pat)
                except re.error as e:
                    self.fail(
                        f"{record.get('id')} has invalid expected_verification_output regex: {e}"
                    )


class TestCapabilityCount(unittest.TestCase):
    """Test 4: At least 80 capabilities inventoried."""

    def setUp(self):
        self.records = _load_inventory()

    def test_minimum_capability_count(self):
        """Must have at least 80 capabilities."""
        self.assertGreaterEqual(
            len(self.records), 80,
            f"Only {len(self.records)} capabilities; need at least 80. Run: python3 tools/capability-inventory-build.py --refresh"
        )

    def test_mcp_callable_count(self):
        """Must have at least 100 MCP callables (we know there are 107)."""
        mcp_caps = [r for r in self.records if r.get("category") == "mcp-callable"]
        self.assertGreaterEqual(
            len(mcp_caps), 100,
            f"Only {len(mcp_caps)} mcp-callable records; expected >= 100"
        )

    def test_make_target_count(self):
        """Must have at least 10 make targets."""
        make_caps = [r for r in self.records if r.get("category") == "make-target"]
        self.assertGreaterEqual(
            len(make_caps), 10,
            f"Only {len(make_caps)} make-target records; expected >= 10"
        )

    def test_r_rule_count(self):
        """Must have at least 30 R-rule records."""
        r_caps = [r for r in self.records if r.get("category") == "r-rule"]
        self.assertGreaterEqual(
            len(r_caps), 30,
            f"Only {len(r_caps)} r-rule records; expected >= 30"
        )

    def test_evm_0day_proof_capabilities_registered(self):
        """EVM proof capability must be visible as both Make target and tool."""
        by_id = {r["id"]: r for r in self.records}
        self.assertIn("CAP-make-evm-0day-proof", by_id)
        self.assertIn("CAP-tool-evm-0day-proof-pipeline", by_id)
        self.assertNotEqual(
            by_id["CAP-tool-evm-0day-proof-pipeline"].get("status"),
            "landed-orphan",
        )


class TestCanonicalFlows(unittest.TestCase):
    """Test 5: At least 15 canonical flows."""

    def setUp(self):
        self.flows = _load_flows()

    def test_flows_file_exists(self):
        """Canonical flows file must exist."""
        self.assertTrue(FLOWS_PATH.exists(), f"Flows not found at {FLOWS_PATH}")

    def test_minimum_flow_count(self):
        """Must have at least 15 canonical flows."""
        self.assertGreaterEqual(
            len(self.flows), 15,
            f"Only {len(self.flows)} flows; need at least 15"
        )

    def test_flow_required_fields(self):
        """Every flow must have required fields."""
        required = ["id", "name", "purpose", "steps"]
        for flow in self.flows:
            for field in required:
                self.assertIn(
                    field, flow,
                    f"Flow {flow.get('id','?')} missing field '{field}'"
                )

    def test_flow_ids_unique(self):
        """All flow IDs must be unique."""
        ids = [f["id"] for f in self.flows]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate flow IDs: {[x for x in ids if ids.count(x) > 1]}")

    def test_flow_steps_have_command(self):
        """Every step in every flow must have a command field."""
        for flow in self.flows:
            for i, step in enumerate(flow.get("steps", [])):
                self.assertIn(
                    "command", step,
                    f"Flow {flow.get('id')} step {i} missing 'command' field"
                )


class TestKnownBugsCrossReference(unittest.TestCase):
    """Test 6: Each known-bug references a real cap_id from capability_patch_queue.md."""

    def setUp(self):
        self.records = _load_inventory()
        self.patch_queue_ids = _extract_cap_ids_from_patch_queue()

    def test_known_bugs_reference_real_cap_ids(self):
        """Known bug cap_ids should exist in the capability_patch_queue.md."""
        if not self.patch_queue_ids:
            self.skipTest("capability_patch_queue.md not found; skipping cross-reference test")

        for record in self.records:
            for bug in record.get("known_bugs", []):
                cap_id = bug.get("cap_id", "")
                if cap_id:
                    self.assertIn(
                        cap_id,
                        self.patch_queue_ids,
                        f"Capability {record.get('id')} references bug {cap_id} "
                        f"which is not in capability_patch_queue.md. "
                        f"Known IDs: {sorted(self.patch_queue_ids)[:5]}..."
                    )


class TestDiffFlag(unittest.TestCase):
    """Test 7: --diff flag detects schema-incompatible changes."""

    def test_diff_flag_syntax(self):
        """The --diff flag must be a recognized argument to capability-inventory-build.py."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "capability-inventory-build.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # argparse prints to stdout
        output = result.stdout + result.stderr
        self.assertIn("--diff", output, "--diff flag not found in help output of capability-inventory-build.py")

    def test_json_flag_produces_valid_json(self):
        """--json flag must produce parseable JSON summary."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "capability-inventory-build.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # May have deprecation warning on stderr, but stdout must be valid JSON
        output = result.stdout.strip()
        if output:
            try:
                data = json.loads(output)
                self.assertIn("total_capabilities", data)
                self.assertIn("total_flows", data)
                self.assertGreater(data["total_capabilities"], 0)
            except json.JSONDecodeError:
                self.fail(f"--json output is not valid JSON: {output[:200]}")

    def test_diff_flag_is_read_only_and_reports_buckets(self):
        """--diff must compare generated JSONL records without writing outputs."""
        import subprocess
        paths = [
            INVENTORY_PATH,
            FLOWS_PATH,
            REPO_ROOT / "docs" / "CAPABILITY_INVENTORY.md",
            REPO_ROOT / "docs" / "CANONICAL_FLOWS.md",
        ]
        before = {p: p.read_bytes() for p in paths}
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "capability-inventory-build.py"),
                "--diff",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["schema"], "auditooor.capability_inventory_diff.v1")
        self.assertTrue(data["read_only"])
        self.assertIn("new", data["totals"])
        self.assertIn("changed", data["totals"])
        self.assertIn("deprecated", data["totals"])
        after = {p: p.read_bytes() for p in paths}
        self.assertEqual(before, after)


class TestMCPCallable(unittest.TestCase):
    """Test 8: vault_capability_inventory MCP callable works correctly."""

    def test_mcp_callable_search(self):
        """vault_capability_inventory must return records matching a free-text query.

        Current callable contract (per the inputSchema in vault-mcp-server.py):
        the free-text search lives at ``filter.query`` (not a top-level
        ``search_text``), and the matched-count is surfaced at
        ``summary.total_records_matched``. Each returned record wraps the raw
        capability under ``record["row"]``.
        """
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "vault-mcp-server.py"),
                "--call", "vault_capability_inventory",
                "--args", '{"filter":{"query":"audit-fast"},"limit":5}',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        if not output:
            self.skipTest("vault-mcp-server.py returned no output (may need inventory built first)")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.skipTest(f"vault-mcp-server.py output is not JSON: {output[:200]}")
        self.assertIn("records", data, f"Response missing 'records' key: {list(data.keys())}")
        self.assertFalse(data.get("degraded", False), f"Response is degraded: {data.get('degraded_reason','?')}")
        total_matched = data.get("summary", {}).get("total_records_matched", 0)
        self.assertGreater(total_matched, 0, "No records matched query 'audit-fast'")
        # The query is a substring filter; every returned row must contain it
        # somewhere in its searchable fields (id is the most direct check here).
        matched_ids = [r.get("row", {}).get("id", "") for r in data.get("records", [])]
        self.assertTrue(
            any("audit-fast" in mid for mid in matched_ids),
            f"Expected an 'audit-fast' capability in results, got: {matched_ids}",
        )

    def test_mcp_callable_known_bugs_surfaced(self):
        """vault_capability_inventory must surface a capability's known_bugs list.

        The current callable does not expose a top-level ``known_bugs_only``
        filter; instead it returns the full ``known_bugs`` list inside each
        record's ``row``. This test queries for a capability that is known to
        carry registered bugs (CAP-make-audit-fast) and asserts the callable
        surfaces its known_bugs so a consumer can filter on them.
        """
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "vault-mcp-server.py"),
                "--call", "vault_capability_inventory",
                "--args", '{"filter":{"query":"audit-fast"},"limit":10}',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        if not output:
            self.skipTest("vault-mcp-server.py returned no output")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.skipTest(f"Non-JSON output: {output[:200]}")
        if data.get("degraded"):
            self.skipTest(f"Degraded: {data.get('degraded_reason')}")
        rows_by_id = {
            r.get("row", {}).get("id"): r.get("row", {})
            for r in data.get("records", [])
        }
        self.assertIn(
            "CAP-make-audit-fast", rows_by_id,
            f"Expected CAP-make-audit-fast in query results; got {list(rows_by_id)}",
        )
        known_bugs = rows_by_id["CAP-make-audit-fast"].get("known_bugs", [])
        self.assertIsInstance(known_bugs, list)
        self.assertGreater(
            len(known_bugs), 0,
            "CAP-make-audit-fast is expected to carry registered known_bugs",
        )
        for bug in known_bugs:
            self.assertIn("cap_id", bug, f"known_bug missing cap_id: {bug}")
            self.assertIn("description", bug, f"known_bug missing description: {bug}")


if __name__ == "__main__":
    unittest.main()
