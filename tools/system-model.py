#!/usr/bin/env python3
"""HACKERMAN_V3 Lane L1 - per-workspace system-model scaffolder.

The V3 flow goes operator-truth -> commit-mining -> ``make audit`` mechanical
detector scans -> exploit-queue -> agent dispatch. There is no deliberate
"understand the system" artifact in between. ``brain-prime`` ranks functions
and ``engage_report`` clusters detector hits, but both are component-blind -
nobody draws the map. The high-value Criticals are architectural (composition,
trust-boundary, invariant-violation bugs that never appear as a single
detector shape); the Rule-14 opposed-trace gate also silently assumes a map of
protocol-owned defenses already exists.

This tool builds that map. It writes ``<ws>/.auditooor/system_model.json`` and
a sibling ``.md`` with eight spec sections:

  1. ``components``            - name, path, one-line responsibility
  2. ``asset_value_flows``     - where funds enter, are custodied, exit
  3. ``trust_boundaries``      - component A assumes component B validated X
  4. ``privileged_roles``      - role + capabilities
  5. ``external_dependencies`` - dep + assumptions
  6. ``protocol_owned_defenses`` - race/rescue/refund/liquidate/slash/pause/
       challenge/watchtower/finalize paths. THIS list is the canonical source
       the Rule-14 opposed-trace gate consumes (see ``read_protocol_owned_defenses``).
  7. ``claimed_invariants``    - invariants the protocol claims to hold
  8. ``state_machines``        - key state machines

Honesty contract: the tool MECHANICALLY extracts what it can from the
workspace ``src/`` tree (component/file enumeration, access-control
roles/modifiers/keepers, external-call sites, defense-verb keyword hits).
Architecture-reasoning fields that mechanical extraction cannot fill carry a
typed ``needs_operator_or_agent_review`` placeholder. The artifact is
reviewable and is NOT proof by itself.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.system_model.v1"

# Build-output / vendored / VCS dirs that must never be treated as source.
_SKIP_DIR_PARTS = {
    "out",
    "cache",
    "crytic-export",
    "lib",
    "node_modules",
    ".git",
    ".github",
    "target",
    "artifacts",
    "build",
    "dist",
    "docs",
    "audits",
    "test",
    "tests",
    "simtests",
    "integration-tests",
    "__pycache__",
    "generated",
    "bindings",
    "mock",
    "mocks",
}

_SOURCE_EXT = {".sol": "solidity", ".rs": "rust", ".go": "go", ".vy": "vyper"}

# Access-control / privileged-role signal patterns (language-agnostic-ish).
_ROLE_PATTERNS = [
    re.compile(r"\bmodifier\s+(\w+)"),
    re.compile(r"\bonly(\w+)\b"),
    re.compile(r"\b(\w*[Rr]ole)\b"),
    re.compile(r"hasRole\(\s*([A-Z_]{3,})"),
    re.compile(r"\b([A-Z][A-Z0-9_]{4,})_ROLE\b"),
    re.compile(r"ensure_(root|signed|none)\b"),  # substrate origins
    re.compile(r"T::(\w+Origin)"),
]

# External-call / cross-contract / cross-chain dispatch sites.
_EXTERNAL_CALL_PATTERNS = [
    re.compile(r"\.call\{"),
    re.compile(r"\.call\("),
    re.compile(r"\.delegatecall\("),
    re.compile(r"\.staticcall\("),
    re.compile(r"\btransferFrom\("),
    re.compile(r"\bsafeTransfer\w*\("),
    re.compile(r"\bdispatch\w*\("),
    re.compile(r"\boracle\b", re.IGNORECASE),
    re.compile(r"\bconsensusClient\b", re.IGNORECASE),
]

# State-machine / state-keyword signals.
_STATE_PATTERNS = [
    re.compile(r"\benum\s+(\w*[Ss]tate\w*)"),
    re.compile(r"\benum\s+(\w*[Ss]tatus\w*)"),
    re.compile(r"\benum\s+(\w*[Pp]hase\w*)"),
    re.compile(r"\b(Pending|Active|Frozen|Settled|Finalized|Closed|Open)\b"),
]

# Defense-verb -> canonical protocol-owned-defense family. This is the L3
# canonical taxonomy; the Rule-14 opposed-trace gate consumes the family names.
DEFENSE_VERBS: dict[str, str] = {
    "race": "race",
    "rescue": "rescue",
    "refund": "refund",
    "liquidate": "liquidate",
    "liquidation": "liquidate",
    "slash": "slash",
    "pause": "pause",
    "freeze": "pause",
    "unfreeze": "pause",
    "challenge": "challenge",
    "dispute": "challenge",
    "veto": "challenge",
    "watchtower": "watchtower",
    "watcher": "watchtower",
    "finalize": "finalize",
    "finalise": "finalize",
    "timeout": "timeout",
    "withdraw": "withdraw",
    "claim": "claim",
}

# Asset/value-flow signal verbs.
_FLOW_INGRESS = re.compile(r"\b(deposit|fund|mint|stake|lock|escrow)\w*\(", re.IGNORECASE)
_FLOW_EGRESS = re.compile(r"\b(withdraw|redeem|burn|unstake|unlock|release|payout)\w*\(", re.IGNORECASE)

_REVIEW_PLACEHOLDER = "needs_operator_or_agent_review"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _review(detail: str) -> dict[str, str]:
    """Typed placeholder for a field mechanical extraction cannot fill."""
    return {"status": _REVIEW_PLACEHOLDER, "detail": detail}


def _is_skippable(rel_parts: tuple[str, ...]) -> bool:
    return any(part in _SKIP_DIR_PARTS for part in rel_parts)


def _resolve_src_root(workspace: Path) -> Path:
    """Prefer ``<ws>/src`` if present, else the workspace itself."""
    src = workspace / "src"
    if src.is_dir():
        return src
    return workspace


def _iter_source_files(src_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(src_root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in _SOURCE_EXT:
            continue
        rel_parts = path.relative_to(src_root).parts
        if _is_skippable(rel_parts):
            continue
        files.append(path)
    return files


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _component_name(path: Path, src_root: Path) -> str:
    return path.relative_to(src_root).as_posix()


def _one_line_responsibility(text: str, suffix: str) -> str:
    """Best-effort one-line responsibility from doc comments / declarations."""
    if suffix == ".sol":
        m = re.search(r"@(?:title|notice|dev)\s+([^\n*]{6,140})", text)
        if m:
            return m.group(1).strip()
        m = re.search(r"\b(contract|library|interface|abstract contract)\s+(\w+)", text)
        if m:
            return f"{m.group(1)} {m.group(2)}"
    elif suffix == ".rs":
        m = re.search(r"^//!\s*(.{6,140})$", text, re.MULTILINE)
        if m:
            return m.group(1).strip()
        m = re.search(r"#\[pallet::pallet\]", text)
        if m:
            return "substrate pallet"
    return _REVIEW_PLACEHOLDER


def _extract_components(files: list[Path], src_root: Path) -> tuple[list[dict[str, Any]], int]:
    components: list[dict[str, Any]] = []
    truncated = 0
    limit = 400
    for path in files:
        if len(components) >= limit:
            truncated += 1
            continue
        text = _read_text(path)
        components.append(
            {
                "name": path.stem,
                "path": _component_name(path, src_root),
                "language": _SOURCE_EXT[path.suffix],
                "responsibility": _one_line_responsibility(text, path.suffix),
                "loc": text.count("\n") + 1 if text else 0,
            }
        )
    return components, truncated


def _extract_roles(files: list[Path], src_root: Path) -> list[dict[str, Any]]:
    seen: dict[str, set[str]] = {}
    for path in files:
        text = _read_text(path)
        rel = _component_name(path, src_root)
        for pat in _ROLE_PATTERNS:
            for m in pat.finditer(text):
                role = (m.group(1) if m.groups() else m.group(0)).strip()
                if not role or len(role) < 3 or len(role) > 60:
                    continue
                seen.setdefault(role, set()).add(rel)
    roles: list[dict[str, Any]] = []
    for role, paths in sorted(seen.items()):
        roles.append(
            {
                "role": role,
                "declared_in": sorted(paths)[:8],
                "capabilities": _review(
                    "enumerate the privileged actions this role can perform"
                ),
            }
        )
    return roles


def _extract_external_dependencies(files: list[Path], src_root: Path) -> list[dict[str, Any]]:
    seen: dict[str, set[str]] = {}
    for path in files:
        text = _read_text(path)
        rel = _component_name(path, src_root)
        for pat in _EXTERNAL_CALL_PATTERNS:
            if pat.search(text):
                key = pat.pattern
                seen.setdefault(key, set()).add(rel)
    deps: list[dict[str, Any]] = []
    for pat, paths in sorted(seen.items()):
        deps.append(
            {
                "dependency_signal": pat,
                "call_sites": sorted(paths)[:12],
                "assumptions": _review(
                    "state what this workspace assumes the external dependency guarantees"
                ),
            }
        )
    return deps


def _extract_state_machines(files: list[Path], src_root: Path) -> list[dict[str, Any]]:
    seen: dict[str, set[str]] = {}
    for path in files:
        text = _read_text(path)
        rel = _component_name(path, src_root)
        for pat in _STATE_PATTERNS:
            for m in pat.finditer(text):
                token = (m.group(1) if m.groups() else m.group(0)).strip()
                if token and 3 <= len(token) <= 60:
                    seen.setdefault(token, set()).add(rel)
    machines: list[dict[str, Any]] = []
    for token, paths in sorted(seen.items()):
        machines.append(
            {
                "state_token": token,
                "observed_in": sorted(paths)[:8],
                "transitions": _review(
                    "draw the allowed transitions and the guard on each edge"
                ),
            }
        )
    return machines


def _extract_protocol_owned_defenses(
    files: list[Path], src_root: Path
) -> list[dict[str, Any]]:
    """Mechanically detect defense-family signals. L3 canonical source."""
    family_hits: dict[str, set[str]] = {}
    for path in files:
        text = _read_text(path).lower()
        rel = _component_name(path, src_root)
        for verb, family in DEFENSE_VERBS.items():
            if re.search(rf"\b{re.escape(verb)}\w*", text):
                family_hits.setdefault(family, set()).add(rel)
    defenses: list[dict[str, Any]] = []
    for family in sorted(family_hits):
        defenses.append(
            {
                "family": family,
                "source_signal_paths": sorted(family_hits[family])[:12],
                "extraction": "mechanical_keyword",
                "trace_notes": _review(
                    "confirm this is a real protocol-owned defense path "
                    "and describe the exact function(s) that implement it"
                ),
            }
        )
    return defenses


def _extract_asset_flows(files: list[Path], src_root: Path) -> dict[str, Any]:
    ingress: set[str] = set()
    egress: set[str] = set()
    for path in files:
        text = _read_text(path)
        rel = _component_name(path, src_root)
        if _FLOW_INGRESS.search(text):
            ingress.add(rel)
        if _FLOW_EGRESS.search(text):
            egress.add(rel)
    return {
        "ingress_signal_paths": sorted(ingress)[:20],
        "egress_signal_paths": sorted(egress)[:20],
        "custody_and_flow_map": _review(
            "trace where funds enter, where they are custodied, and where "
            "they exit; mechanical signals above are entry points only"
        ),
    }


def build_system_model(workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve(strict=False)
    src_root = _resolve_src_root(workspace)
    files = _iter_source_files(src_root) if src_root.exists() else []

    components, comp_truncated = _extract_components(files, src_root)
    roles = _extract_roles(files, src_root)
    deps = _extract_external_dependencies(files, src_root)
    state_machines = _extract_state_machines(files, src_root)
    protocol_defenses = _extract_protocol_owned_defenses(files, src_root)
    asset_flows = _extract_asset_flows(files, src_root)

    languages: dict[str, int] = {}
    for comp in components:
        languages[comp["language"]] = languages.get(comp["language"], 0) + 1

    model: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "workspace_path": str(workspace),
        "src_root": str(src_root),
        "extraction": {
            "source_files_indexed": len(files),
            "languages": languages,
            "components_truncated": comp_truncated,
            "mechanical_only": True,
            "is_proof": False,
            "note": (
                "Mechanically extracted: component tree, roles/modifiers, "
                "external-call sites, defense-verb signals, state tokens, "
                "asset-flow entry points. Architecture-reasoning fields carry "
                "a typed needs_operator_or_agent_review placeholder."
            ),
        },
        # --- the 8 spec sections ---
        "components": components,
        "asset_value_flows": asset_flows,
        "trust_boundaries": _review(
            "for each cross-component call, state what the caller assumes the "
            "callee already validated (e.g. EvmHost assumes the consensus "
            "client verified the state-proof before HandlerV2 acts on it)"
        ),
        "privileged_roles": roles,
        "external_dependencies": deps,
        "protocol_owned_defenses": protocol_defenses,
        "claimed_invariants": _review(
            "enumerate invariants the protocol claims hold (e.g. total minted "
            "== total locked; a request can be timed out XOR delivered, never "
            "both); cite the code or docs that claim each"
        ),
        "state_machines": state_machines,
    }
    return model


# ---------------------------------------------------------------------------
# L3 read API - the canonical source for Rule-14 protocol_defenses_enumerated.
# ---------------------------------------------------------------------------

def system_model_path(workspace: Path) -> Path:
    return workspace.expanduser().resolve(strict=False) / ".auditooor" / "system_model.json"


def load_system_model(workspace: Path) -> dict[str, Any] | None:
    """Load a workspace's emitted system_model.json, or None if absent/bad."""
    path = system_model_path(workspace)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return None
    return data


def read_protocol_owned_defenses(workspace: Path) -> list[str]:
    """Return the canonical protocol-owned-defense family names for a workspace.

    This is the L3 read API. ``source-mined-impact-contracts.py`` (Rule 14)
    can adopt it by populating an exploit-queue row's ``protocol_owned_defenses``
    field from this list, so the opposed-trace gate's
    ``protocol_defenses_enumerated`` is traceable to the system model rather
    than re-derived per row. Returns ``[]`` when no system model exists, which
    keeps a HIGH+ contract at ``opposed_trace_coverage: missing`` - the safe
    fail-closed default.

    One-line adoption (described for the coordinator, not wired here):
        from importlib import import_module
        sm = import_module("system-model")  # tools/ on sys.path
        defenses = sm.read_protocol_owned_defenses(Path(workspace))
        row.setdefault("protocol_owned_defenses", defenses)
    """
    model = load_system_model(workspace)
    if model is None:
        return []
    defenses = model.get("protocol_owned_defenses")
    if not isinstance(defenses, list):
        return []
    families: list[str] = []
    for entry in defenses:
        if isinstance(entry, dict):
            fam = entry.get("family")
        elif isinstance(entry, str):
            fam = entry
        else:
            fam = None
        if isinstance(fam, str) and fam.strip():
            families.append(fam.strip())
    # de-dup, stable order
    return list(dict.fromkeys(families))


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _render_review(value: Any) -> str:
    if isinstance(value, dict) and value.get("status") == _REVIEW_PLACEHOLDER:
        return f"_{_REVIEW_PLACEHOLDER}_: {value.get('detail', '')}"
    return ""


def render_markdown(model: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# System Model")
    lines.append("")
    lines.append(f"- Schema: `{model.get('schema')}`")
    lines.append(f"- Workspace: `{model.get('workspace_path')}`")
    lines.append(f"- Generated: `{model.get('generated_at')}`")
    ext = model.get("extraction", {})
    lines.append(f"- Source files indexed: {ext.get('source_files_indexed')}")
    lines.append(f"- Languages: {ext.get('languages')}")
    lines.append(
        "- This artifact is **mechanically scaffolded and is NOT proof**. "
        "Fields marked `needs_operator_or_agent_review` require a reasoning pass."
    )
    lines.append("")

    lines.append("## 1. Components")
    lines.append("")
    for comp in model.get("components", [])[:200]:
        lines.append(
            f"- `{comp['path']}` ({comp['language']}, {comp['loc']} loc) - "
            f"{comp['responsibility']}"
        )
    lines.append("")

    lines.append("## 2. Asset / Value Flows")
    lines.append("")
    flows = model.get("asset_value_flows", {})
    lines.append(f"- Ingress signal paths: {len(flows.get('ingress_signal_paths', []))}")
    for p in flows.get("ingress_signal_paths", []):
        lines.append(f"  - `{p}`")
    lines.append(f"- Egress signal paths: {len(flows.get('egress_signal_paths', []))}")
    for p in flows.get("egress_signal_paths", []):
        lines.append(f"  - `{p}`")
    review = _render_review(flows.get("custody_and_flow_map"))
    if review:
        lines.append(f"- {review}")
    lines.append("")

    lines.append("## 3. Trust Boundaries")
    lines.append("")
    review = _render_review(model.get("trust_boundaries"))
    lines.append(f"- {review}" if review else "- (none)")
    lines.append("")

    lines.append("## 4. Privileged Roles")
    lines.append("")
    for role in model.get("privileged_roles", [])[:120]:
        lines.append(f"- `{role['role']}` declared in: {', '.join(role['declared_in'])}")
        cap = _render_review(role.get("capabilities"))
        if cap:
            lines.append(f"  - {cap}")
    lines.append("")

    lines.append("## 5. External Dependencies")
    lines.append("")
    for dep in model.get("external_dependencies", []):
        lines.append(
            f"- signal `{dep['dependency_signal']}` at {len(dep['call_sites'])} site(s)"
        )
        a = _render_review(dep.get("assumptions"))
        if a:
            lines.append(f"  - {a}")
    lines.append("")

    lines.append("## 6. Protocol-Owned Defenses (Rule-14 canonical source)")
    lines.append("")
    for d in model.get("protocol_owned_defenses", []):
        lines.append(
            f"- **{d['family']}** ({d['extraction']}) - "
            f"signals in {len(d['source_signal_paths'])} file(s)"
        )
        t = _render_review(d.get("trace_notes"))
        if t:
            lines.append(f"  - {t}")
    if not model.get("protocol_owned_defenses"):
        lines.append("- (no defense-verb signals detected)")
    lines.append("")

    lines.append("## 7. Claimed Invariants")
    lines.append("")
    review = _render_review(model.get("claimed_invariants"))
    lines.append(f"- {review}" if review else "- (none)")
    lines.append("")

    lines.append("## 8. State Machines")
    lines.append("")
    for sm in model.get("state_machines", [])[:120]:
        lines.append(f"- `{sm['state_token']}` observed in: {', '.join(sm['observed_in'])}")
        t = _render_review(sm.get("transitions"))
        if t:
            lines.append(f"  - {t}")
    if not model.get("state_machines"):
        lines.append("- (no state-machine signals detected)")
    lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="HACKERMAN_V3 Lane L1 - per-workspace system-model scaffolder."
    )
    parser.add_argument("--workspace", required=True, help="Audit workspace path")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the system_model JSON to stdout",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Do not write artifacts to <ws>/.auditooor/ (read-only mode)",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve(strict=False)
    if not workspace.is_dir():
        print(f"system-model: workspace not found: {workspace}", file=sys.stderr)
        return 2

    model = build_system_model(workspace)

    if not args.no_write:
        out_dir = workspace / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "system_model.json").write_text(
            json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out_dir / "system_model.md").write_text(
            render_markdown(model), encoding="utf-8"
        )
        print(
            f"system-model: wrote {out_dir / 'system_model.json'} "
            f"and {out_dir / 'system_model.md'}",
            file=sys.stderr,
        )

    if args.json:
        print(json.dumps(model, indent=2, sort_keys=True))
    else:
        ext = model["extraction"]
        print(
            f"system-model: {ext['source_files_indexed']} source files, "
            f"{len(model['components'])} components, "
            f"{len(model['privileged_roles'])} roles, "
            f"{len(model['protocol_owned_defenses'])} defense families, "
            f"{len(model['state_machines'])} state tokens"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
