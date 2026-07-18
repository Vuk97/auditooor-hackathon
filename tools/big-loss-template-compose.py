#!/usr/bin/env python3
"""Big-Loss Exploit Path Template Composer — Wave C-1A (P0-6a).

Reads a workspace invariant_ledger.json + impact_contracts.json, evaluates
applicable_when predicates against each row, selects the matching
big_loss_template, and emits a composed_attempt_manifest JSON per row.

CLI shape matches tools/rust-decode-bomb-scan.py (--workspace, --strict,
--print-json, --out). Stdlib-only, offline-safe.

Schema emitted: auditooor.big_loss_template_composed.v1

Examples
--------

    python3 tools/big-loss-template-compose.py --workspace ~/audits/base-azul --print-json
    python3 tools/big-loss-template-compose.py --workspace ~/audits/base-azul --row BASE-SC-I01
    python3 tools/big-loss-template-compose.py --workspace ~/audits/base-azul --template bridge_proof_domain --strict
    python3 tools/big-loss-template-compose.py --workspace ~/audits/base-azul --out /tmp/manifests.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION_IN = "auditooor.big_loss_template.v1"
SCHEMA_VERSION_OUT = "auditooor.big_loss_template_composed.v1"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _REPO_ROOT / "reference" / "big_loss_templates"
_INDEX_PATH = _TEMPLATES_DIR / "INDEX.json"


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> Any:
    with path.open() as fh:
        return json.load(fh)


def _load_templates() -> dict[str, dict]:
    """Return {template_id: template_dict} from all *.json files in templates dir."""
    index = _load_json(_INDEX_PATH)
    templates: dict[str, dict] = {}
    for entry in index.get("templates", []):
        tid = entry["template_id"]
        tfile = _REPO_ROOT / entry["file"]
        if tfile.exists():
            templates[tid] = _load_json(tfile)
    return templates


def _load_ledger(ws: Path) -> list[dict]:
    ledger_path = ws / ".auditooor" / "invariant_ledger.json"
    if not ledger_path.exists():
        return []
    data = _load_json(ledger_path)
    return data.get("rows", [])


def _load_impact_contracts(ws: Path) -> dict:
    ic_path = ws / ".auditooor" / "impact_contracts.json"
    if not ic_path.exists():
        return {}
    return _load_json(ic_path)


# ---------------------------------------------------------------------------
# OOS clause detection
# ---------------------------------------------------------------------------

_OOS_TOKENS_TO_FIELD_PATTERNS: dict[str, list[str]] = {
    "private_key_compromise": [
        r"private.?key", r"signer.?compromise", r"key.?leak",
    ],
    "off_chain_infra_compromise": [
        r"off.?chain.?infra", r"aws.?nitro", r"sequencer.?host",
    ],
    "social_engineering": [
        r"social.?engin", r"phishing",
    ],
    "requires_signing_key_compromise": [
        r"signing.?key",
    ],
    "requires_off_chain_infra_compromise": [
        r"off.?chain.?infra",
    ],
    "single_client_only_no_divergence": [
        r"single.?client", r"no.?diverge",
    ],
    "downstream_recompute_catches": [
        r"downstream.?recomput",
    ],
    "upstream_op_stack_code_not_base_modification": [
        r"op.?stack.?upstream", r"op-reth(?!.*base)",
    ],
    "proof_bytes_require_live_tee_attestation_unavailable_to_attacker": [
        r"live.?tee.?attest",
    ],
    "dispute_game_window_cannot_be_deterministically_bypassed_and_no_freezing": [
        r"cannot.?bypass",
    ],
}


def _check_oos(row: dict, exclude_clauses: list[str]) -> str | None:
    """Return the first triggered OOS clause token, or None."""
    # Do NOT check oos_boundary — that field lists what is OOS by design and routinely
    # mentions clause names like "private-key compromise" as documentation, not requirements.
    # Check only attacker_capability and trusted_boundary for actual attacker assumptions.
    text_to_check = " ".join([
        row.get("attacker_capability", ""),
        row.get("trusted_boundary", ""),
    ]).lower()
    for clause in exclude_clauses:
        patterns = _OOS_TOKENS_TO_FIELD_PATTERNS.get(clause, [])
        for pat in patterns:
            if re.search(pat, text_to_check, re.I):
                return clause
    return None


# ---------------------------------------------------------------------------
# Template matching
# ---------------------------------------------------------------------------

def _match_template(row: dict, templates: dict[str, dict], force_template: str | None) -> dict | None:
    """Return the first matching template for the row, or None."""
    if force_template:
        return templates.get(force_template)

    inv_family = row.get("invariant_family", "")
    prod_path = row.get("production_path", "")

    for tid, tpl in templates.items():
        aw = tpl.get("applicable_when", {})
        fam_regex = aw.get("invariant_family_regex", "")
        path_regex = aw.get("scope_path_regex", "")
        sev_set = aw.get("severity_set", [])
        row_sev = row.get("severity", row.get("raw_severity", ""))

        fam_match = bool(re.search(fam_regex, inv_family, re.I)) if fam_regex else True
        path_match = bool(re.search(path_regex, prod_path, re.I)) if path_regex else True
        # If the row has no severity field, skip severity gating (match all templates)
        sev_match = (not sev_set) or (not row_sev) or any(
            s.lower() in row_sev.lower() for s in sev_set
        )

        if fam_match and path_match and sev_match:
            return tpl
    return None


# ---------------------------------------------------------------------------
# Severity line verification (M14-trap)
# ---------------------------------------------------------------------------

def _verify_severity_line(ws: Path, verbatim_line: str) -> bool:
    """Run grep -F against the workspace SEVERITY.md. Return True if found."""
    sev_path = ws / "SEVERITY.md"
    if not sev_path.exists():
        return False
    try:
        result = subprocess.run(
            ["grep", "-qF", verbatim_line, str(sev_path)],
            capture_output=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        # grep not available — fallback to Python
        text = sev_path.read_text(errors="replace")
        return verbatim_line in text


# ---------------------------------------------------------------------------
# Placeholder substitution
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"<row:([^>]+)>")


def _substitute(value: Any, row: dict, impact_contracts: dict) -> Any:
    """Recursively substitute <row:fieldname> and <placeholder> tokens."""
    if isinstance(value, str):
        def _repl(m: re.Match) -> str:
            field = m.group(1)
            return str(row.get(field, m.group(0)))

        value = _PLACEHOLDER_RE.sub(_repl, value)
        # Generic <placeholder> tokens get row_id prefix
        value = re.sub(r"<placeholder>", row.get("id", "UNKNOWN"), value)
        return value
    if isinstance(value, list):
        return [_substitute(v, row, impact_contracts) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, row, impact_contracts) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# next_command builder
# ---------------------------------------------------------------------------

def _next_command(template: dict, row: dict) -> str:
    engine = template.get("harness_blueprint", {}).get("engine", "forge")
    row_id = row.get("id", "UNKNOWN")
    tid = template.get("template_id", "unknown")
    if engine == "forge":
        test_file = template["harness_blueprint"].get("test_file_pattern", "test/BigLoss.t.sol")
        test_file = _substitute(test_file, row, {})
        return (
            f"make harness-scaffold WS=<workspace> ROW={row_id} "
            f"TEMPLATE={tid} ENGINE=forge TEST_FILE={test_file}"
        )
    elif engine in ("cargo_test", "cargo_run", "engine_api_in_process"):
        test_file = template["harness_blueprint"].get("test_file_pattern", "poc-tests/<row_id>/tests/test.rs")
        test_file = _substitute(test_file, row, {})
        return (
            f"make harness-scaffold WS=<workspace> ROW={row_id} "
            f"TEMPLATE={tid} ENGINE={engine} TEST_FILE={test_file}"
        )
    return f"make harness-scaffold WS=<workspace> ROW={row_id} TEMPLATE={tid}"


# ---------------------------------------------------------------------------
# Compose single row
# ---------------------------------------------------------------------------

def _compose_row(
    row: dict,
    templates: dict[str, dict],
    impact_contracts: dict,
    ws: Path,
    force_template: str | None,
) -> dict:
    row_id = row.get("id", "UNKNOWN")
    scope_status = row.get("scope_status", row.get("status", ""))

    # Auto-kill OOS rows
    if scope_status == "OOS":
        return {
            "schema_version": SCHEMA_VERSION_OUT,
            "template_id": None,
            "row_id": row_id,
            "composed_status": "blocked_no_template",
            "blocked_reason": "row.scope_status == 'OOS'",
            "actor_sequence": [],
            "harness_blueprint": {},
            "severity_promotion_rule_check": {},
            "next_command": None,
        }

    # Match template
    template = _match_template(row, templates, force_template)
    if template is None:
        return {
            "schema_version": SCHEMA_VERSION_OUT,
            "template_id": None,
            "row_id": row_id,
            "composed_status": "blocked_no_template",
            "blocked_reason": "no template matched invariant_family + production_path + severity_set",
            "actor_sequence": [],
            "harness_blueprint": {},
            "severity_promotion_rule_check": {},
            "next_command": None,
        }

    tid = template["template_id"]
    aw = template.get("applicable_when", {})
    exclude_clauses = aw.get("exclude_oos_clauses", [])

    # OOS clause check
    triggered_oos = _check_oos(row, exclude_clauses)
    if triggered_oos:
        return {
            "schema_version": SCHEMA_VERSION_OUT,
            "template_id": tid,
            "row_id": row_id,
            "composed_status": "blocked_no_template",
            "blocked_reason": f"OOS clause triggered: {triggered_oos}",
            "actor_sequence": [],
            "harness_blueprint": {},
            "severity_promotion_rule_check": {},
            "next_command": None,
        }

    # M14-trap: verify severity line
    spr = template.get("severity_promotion_rule", {})
    verbatim_line = spr.get("verbatim_severity_md_line", "")
    sev_line_verified = _verify_severity_line(ws, verbatim_line)

    if not sev_line_verified:
        return {
            "schema_version": SCHEMA_VERSION_OUT,
            "template_id": tid,
            "row_id": row_id,
            "composed_status": "blocked_severity_line_not_verified",
            "blocked_reason": (
                f"M14-trap: verbatim_severity_md_line not found in {ws}/SEVERITY.md via grep -F. "
                f"Line: {verbatim_line!r}"
            ),
            "actor_sequence": [],
            "harness_blueprint": {},
            "severity_promotion_rule_check": {
                "verbatim_severity_md_line": verbatim_line,
                "severity_md_line_verified": False,
            },
            "next_command": None,
        }

    # Concretize actor_sequence
    actor_seq = _substitute(
        [dict(step) for step in template.get("actor_sequence", [])],
        row,
        impact_contracts,
    )

    # Concretize harness_blueprint
    hb = _substitute(dict(template.get("harness_blueprint", {})), row, impact_contracts)

    # Build severity promotion rule check
    spr_check = {
        "verbatim_severity_md_line": verbatim_line,
        "section_header": spr.get("section_header", ""),
        "promotion_precondition": spr.get("promotion_precondition", ""),
        "kill_conditions": spr.get("kill_conditions", []),
        "severity_md_line_verified": True,
    }

    return {
        "schema_version": SCHEMA_VERSION_OUT,
        "template_id": tid,
        "row_id": row_id,
        "composed_status": "composed",
        "actor_sequence": actor_seq,
        "harness_blueprint": hb,
        "severity_promotion_rule_check": spr_check,
        "next_command": _next_command(template, row),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Compose big-loss exploit-path attempt manifests from workspace ledger rows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--workspace", required=True, metavar="WS",
                   help="Path to workspace root (must contain .auditooor/invariant_ledger.json).")
    p.add_argument("--row", metavar="ROW_ID", default=None,
                   help="Compose only this ledger row id (default: all rows).")
    p.add_argument("--template", metavar="TEMPLATE_ID", default=None,
                   help="Force-override template selection for all rows.")
    p.add_argument("--strict", action="store_true",
                   help="Exit non-zero if any row is blocked or severity-line fails.")
    p.add_argument("--print-json", action="store_true",
                   help="Print JSON output to stdout.")
    p.add_argument("--out", metavar="PATH", default=None,
                   help="Write JSON output to file (use '-' for stdout).")
    return p.parse_args(argv)


def run(argv: list[str] | None = None) -> dict:
    args = _parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[big-loss-template-compose] ERR workspace not found: {ws}", file=sys.stderr)
        sys.exit(2)

    templates = _load_templates()
    rows = _load_ledger(ws)
    impact_contracts = _load_impact_contracts(ws)

    if not rows:
        print(f"[big-loss-template-compose] WARN no rows found in {ws}/.auditooor/invariant_ledger.json",
              file=sys.stderr)

    if args.row:
        rows = [r for r in rows if r.get("id") == args.row]
        if not rows:
            print(f"[big-loss-template-compose] ERR row not found: {args.row}", file=sys.stderr)
            sys.exit(2)

    manifests = []
    blocked_count = 0
    for row in rows:
        manifest = _compose_row(row, templates, impact_contracts, ws, args.template)
        manifests.append(manifest)
        if manifest["composed_status"] != "composed":
            blocked_count += 1

    result = {
        "schema_version": SCHEMA_VERSION_OUT,
        "workspace": str(ws),
        "total_rows": len(rows),
        "composed": sum(1 for m in manifests if m["composed_status"] == "composed"),
        "blocked_no_template": sum(1 for m in manifests if m["composed_status"] == "blocked_no_template"),
        "blocked_severity_line_not_verified": sum(
            1 for m in manifests if m["composed_status"] == "blocked_severity_line_not_verified"
        ),
        "manifests": manifests,
    }

    json_out = json.dumps(result, indent=2)

    if args.print_json:
        print(json_out)

    if args.out:
        if args.out == "-":
            print(json_out)
        else:
            Path(args.out).write_text(json_out)
            print(f"[big-loss-template-compose] wrote {len(manifests)} manifests to {args.out}",
                  file=sys.stderr)

    if not args.print_json and not args.out:
        # Default human summary
        print(f"[big-loss-template-compose] {ws.name}: "
              f"{result['composed']} composed, "
              f"{result['blocked_no_template']} blocked_no_template, "
              f"{result['blocked_severity_line_not_verified']} blocked_severity_line_not_verified "
              f"(of {result['total_rows']} rows)")

    if args.strict and blocked_count > 0:
        print(f"[big-loss-template-compose] STRICT: {blocked_count} blocked rows", file=sys.stderr)
        sys.exit(1)

    return result


if __name__ == "__main__":
    run()
