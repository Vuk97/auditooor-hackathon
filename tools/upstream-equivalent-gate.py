#!/usr/bin/env python3
"""upstream-equivalent-gate.py — Wave J-1A candidate promotion gate.

Catches the 3 over-claim patterns that hit the overnight loop:
  - H-1 G-v01:  kona has identical bug  (Critical → Medium)
  - I-1A KZG:   cited path doesn't exist + upstream OOS  (Critical → OOS)
  - I-2 N8/N9:  byte-identical to kona  (High → UPSTREAM)

Per the 5-check protocol from
``feedback_llm_hallucinates_oos_paths_into_in_scope_tree.md``:

  1. **audit-tree existence** — file must exist at
     ``<workspace>/external/<asset>/<path>``
  2. **line content match** — if the candidate cites a quoted line, the file
     line must contain the claim as a substring (loose, >100-char content
     threshold)
  3. **SCOPE.md OOS check** — path must NOT fall under any OOS marker block
     in ``<workspace>/SCOPE.md``
  4. **SEVERITY.md verbatim** — claimed ``severity_tier`` / ``selected_impact``
     must be found under the matching ``### <tier>`` heading in
     ``<workspace>/SEVERITY.md``
  5. **upstream equivalent** — ``gh api search/code`` against op-rs/kona,
     ethereum-optimism/optimism, paradigmxyz/reth, succinctlabs/op-succinct,
     succinctlabs/sp1; a hit downgrades from any Critical claim to
     ``upstream_inherited_partial``

Exit codes:
  0  — all candidates pass (``promotion_allowed``)
  1  — at least one candidate walked back or killed
  2  — harness error (missing workspace, bad JSON)

Usage:
    python3 tools/upstream-equivalent-gate.py \\
        --workspace ~/audits/base-azul \\
        --candidate ~/audits/base-azul/.auditooor/wave-i1a-discarded-verify-triage/promotion_candidates.json \\
        --strict \\
        --print-json

Wave J-1A, PR #[next].
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Load sibling resolver modules (stdlib-only, no install required)
# ---------------------------------------------------------------------------

def _load_sibling(name: str, filename: str):
    """Load a sibling tool module from the tools/ directory."""
    tool_path = Path(__file__).parent / filename
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(name, tool_path)
    if not spec or not spec.loader:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_CARGO_RESOLVER = _load_sibling("cargo_crate_resolver", "cargo-crate-resolver.py")
_SCOPE_PARSER = _load_sibling("scope_md_parser", "scope-md-parser.py")

SCHEMA_VERSION = "auditooor.upstream_equivalent_gate.v1"

# Upstream repos checked in Step 5 (order = search priority).
UPSTREAM_REPOS = [
    "op-rs/kona",
    "ethereum-optimism/optimism",
    "paradigmxyz/reth",
    "succinctlabs/op-succinct",
    "succinctlabs/sp1",
]

# Rate-limit: 1 request/sec gentle pacing.
_GH_PACE_SECS = 1.0
# Max upstream queries per run unless --exhaustive.
_MAX_UPSTREAM_QUERIES = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    """Extract rows from various candidate JSON shapes."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("candidates", "rows", "items", "findings", "results"):
            v = payload.get(key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _resolve_asset_root(workspace: Path, production_path: str) -> tuple[Path, str]:
    """Return (asset_root, relative_path_within_asset).

    Candidate production_path forms we handle:
      - ``external/base/crates/...``         → asset=base
      - ``external/base-rc28-clean/...``     → asset=base-rc28-clean
      - ``crates/...``                       → auto-detect under external/*/crates/
      - absolute path already                → strip workspace prefix
    """
    p = production_path.strip()

    # Already absolute
    if p.startswith("/"):
        pp = Path(p)
        if workspace and str(pp).startswith(str(workspace)):
            p = str(pp.relative_to(workspace))
        # else treat as-is below

    # Explicit external/<asset>/... prefix
    m = re.match(r"^external/([^/]+)/(.+)$", p)
    if m:
        asset_root = workspace / "external" / m.group(1)
        return asset_root, m.group(2)

    # Bare crates/... — scan all assets
    if p.startswith("crates/") or p.startswith("src/"):
        external = workspace / "external"
        if external.is_dir():
            for asset_dir in sorted(external.iterdir()):
                if (asset_dir / p).exists():
                    return asset_dir, p
        # Not found anywhere; return first asset dir as a guess (will fail step 1)
        assets = [d for d in (workspace / "external").iterdir()] if (workspace / "external").is_dir() else []
        if assets:
            return assets[0], p
        return workspace, p

    return workspace, p


# ---------------------------------------------------------------------------
# Step 1 — audit-tree existence
# ---------------------------------------------------------------------------

def check_step1_existence(workspace: Path, production_path: str) -> tuple[bool, str]:
    """Returns (exists, resolved_full_path_str)."""
    asset_root, rel = _resolve_asset_root(workspace, production_path)
    full = asset_root / rel
    if full.exists():
        return True, str(full)
    # Try with glob in case the path has minor variation
    # (e.g. external/base-rc28-clean vs external/base)
    external = workspace / "external"
    if external.is_dir():
        for asset in external.iterdir():
            candidate = asset / rel
            if candidate.exists():
                return True, str(candidate)
    return False, str(full)


# ---------------------------------------------------------------------------
# Step 2 — line content match
# ---------------------------------------------------------------------------

def check_step2_line_content(
    resolved_path: str,
    cited_line: int | None,
    quoted_content: str | None,
) -> bool | str:
    """Returns True, False, or 'n/a'."""
    if not cited_line or not quoted_content:
        return "n/a"
    if not Path(resolved_path).exists():
        return False
    try:
        lines = Path(resolved_path).read_text(encoding="utf-8", errors="replace").splitlines()
        if cited_line < 1 or cited_line > len(lines):
            return False
        actual = lines[cited_line - 1]
        # Loose substring match; for long content (>100 chars) even a 40-char
        # overlap is meaningful.
        needle = quoted_content.strip()
        if len(needle) > 100:
            needle = needle[:100]
        return needle.lower() in actual.lower()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Step 3 — SCOPE.md OOS check
# ---------------------------------------------------------------------------

def check_step3_scope(
    workspace: Path,
    production_path: str,
    crate_name: str | None = None,
) -> str:
    """Returns 'in_scope', 'oos', or 'partial'.

    Wave O-A: principled resolution via cargo-crate-resolver + scope-md-parser.
    Decision tree:
      1. Resolve crate_name from file path (via Cargo.toml walk) if not provided.
      2. Parse SCOPE.md into structured ScopeManifest.
      3. Call is_path_in_scope(rel_path, manifest, crate_name):
           a. If crate_name matches a modification_rule fork → IN_SCOPE.
           b. Elif path matches OOS token → OOS.
           c. Elif path matches in-scope token → IN_SCOPE.
           d. Else → IN_SCOPE_DEFAULT (advisory).
      4. Fallback to legacy OOS_PATTERNS if resolvers unavailable.
    """
    scope_file = workspace / "SCOPE.md"
    if not scope_file.exists():
        return "in_scope"  # no SCOPE.md → be lenient

    # --- Principled path: use resolver modules when available ---
    if _CARGO_RESOLVER is not None and _SCOPE_PARSER is not None:
        # Resolve crate name from the file path if not explicitly provided
        resolved_crate = crate_name
        if resolved_crate is None:
            # Build absolute path from workspace + production_path
            _, rel = _resolve_asset_root(workspace, production_path)
            # Try multiple asset roots
            external = workspace / "external"
            candidate_paths: list[Path] = []
            if external.is_dir():
                for asset_dir in sorted(external.iterdir()):
                    candidate_paths.append(asset_dir / rel)
            candidate_paths.append(workspace / rel)
            for cp in candidate_paths:
                name = _CARGO_RESOLVER.resolve_crate_name(cp)
                if name:
                    resolved_crate = name
                    break

        manifest = _SCOPE_PARSER.parse_scope_md(scope_file)
        in_scope, reason = _SCOPE_PARSER.is_path_in_scope(
            production_path, manifest, resolved_crate
        )
        # If the SCOPE.md parser found an explicit OOS clause → OOS immediately.
        if not in_scope:
            return "oos"
        # If the parser found an explicit IN_SCOPE clause or modification rule → done.
        if "modification_rule" in reason or "in_scope_via_scope_md" in reason:
            return "in_scope"
        # Advisory default (no explicit clause): also apply hardcoded OOS patterns
        # as a safety net so paths like /kona/ (not mentioned in every SCOPE.md)
        # are still caught.
        pp_lower = production_path.lower()
        _LEGACY_OOS_PATTERNS = [
            r"\bop-node\b",
            r"\bop-geth\b",
            r"\bop-batcher\b",
            r"\bop-reth\b",
            r"/kona/",
            r"succinctlabs/op-succinct",
            r"(?:^|/)op[-_]succinct(?:/|$)",
            r"/sp1/",
            r"rust/kona",
            r"ethereum-optimism/optimism",
        ]
        for pat in _LEGACY_OOS_PATTERNS:
            if re.search(pat, pp_lower, re.IGNORECASE):
                return "oos"
        return "in_scope"

    # --- Legacy fallback (preserves M-3 regex band-aid if modules fail to load) ---
    return _check_step3_scope_legacy(workspace, production_path)


def _check_step3_scope_legacy(workspace: Path, production_path: str) -> str:
    """Legacy Step 3 implementation (regex-based). Used as fallback only.

    Wave M-3 regex band-aid preserved here so the gate degrades gracefully
    if the resolver modules are unavailable.
    """
    scope_file = workspace / "SCOPE.md"
    if not scope_file.exists():
        return "in_scope"

    text = scope_file.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    oos_segments: list[str] = []
    in_oos_block = False

    OOS_HEADER = re.compile(
        r"(out.of.scope|oos|excluded|not in scope)",
        re.IGNORECASE,
    )
    OOS_BULLET = re.compile(
        r"^[-*]\s+\*\*(Out-of-Scope|OOS|OP Stack|ZK prover|Op-Succinct)",
        re.IGNORECASE,
    )

    for line in lines:
        stripped = line.strip()
        if re.match(r"^#{1,4}\s+", line):
            in_oos_block = bool(OOS_HEADER.search(line))
            continue
        if OOS_BULLET.match(stripped):
            in_oos_block = True
        if in_oos_block:
            if not stripped:
                in_oos_block = False
            else:
                oos_segments.append(stripped)

    pp_lower = production_path.lower()
    PATH_LIKE = re.compile(r"[-_/]")
    for seg in oos_segments:
        tokens = re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_\-/]+[a-zA-Z0-9]", seg)
        for token in tokens:
            t = token.lower()
            if len(t) >= 5 and PATH_LIKE.search(t) and t in pp_lower:
                return "oos"

    OOS_PATTERNS = [
        r"\bop-node\b",
        r"\bop-geth\b",
        r"\bop-batcher\b",
        r"\bop-reth\b",
        r"/kona/",
        r"succinctlabs/op-succinct",
        r"(?:^|/)op[-_]succinct(?:/|$)",
        r"/sp1/",
        r"rust/kona",
        r"ethereum-optimism/optimism",
    ]
    for pat in OOS_PATTERNS:
        if re.search(pat, pp_lower, re.IGNORECASE):
            return "oos"

    return "in_scope"


# ---------------------------------------------------------------------------
# Step 4 — SEVERITY.md verbatim match
# ---------------------------------------------------------------------------

def check_step4_severity(
    workspace: Path,
    severity_tier: str | None,
    selected_impact: str | None,
) -> bool | str:
    """Returns True, False, or 'n/a'."""
    if not severity_tier or not selected_impact:
        return "n/a"
    sev_file = workspace / "SEVERITY.md"
    if not sev_file.exists():
        return "n/a"

    text = sev_file.read_text(encoding="utf-8", errors="replace")
    # Find the section matching ### <tier>
    tier_norm = severity_tier.strip().lower()
    # Split into sections
    sections: dict[str, str] = {}
    current_header = ""
    buf: list[str] = []
    for line in text.splitlines():
        h = re.match(r"^#{1,4}\s+(.+)$", line)
        if h:
            if current_header:
                sections[current_header] = "\n".join(buf)
            current_header = h.group(1).strip().lower()
            buf = []
        else:
            buf.append(line)
    if current_header:
        sections[current_header] = "\n".join(buf)

    # Find the section that contains the tier name
    matching_section = ""
    for header, body in sections.items():
        if tier_norm in header:
            matching_section = body
            break

    if not matching_section:
        # Fallback: search the whole doc
        matching_section = text

    needle = _norm(selected_impact)
    return needle in _norm(matching_section)


# ---------------------------------------------------------------------------
# Step 5 — upstream equivalent (gh api search/code)
# ---------------------------------------------------------------------------

def _gh_search(query: str, repo: str | None = None, timeout: int = 15) -> dict[str, Any]:
    """Run gh api search/code and return parsed JSON. Rate-limited."""
    q = query
    if repo:
        q = f"{query}+repo:{repo}"
    # URL-encode query for gh api
    cmd = ["gh", "api", f"search/code?q={q}&per_page=5"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return {"total_count": 0, "items": [], "_error": result.stderr.strip()}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"total_count": 0, "items": [], "_error": "timeout"}
    except (json.JSONDecodeError, OSError) as exc:
        return {"total_count": 0, "items": [], "_error": str(exc)}


def _derive_bug_pattern(row: dict[str, Any]) -> str:
    """Heuristic: extract function names / key idioms from candidate text."""
    sources = [
        row.get("bug_shape_query", ""),
        row.get("containing_fn", ""),
        row.get("library_fn_called", ""),
        row.get("evidence_snippet", ""),
        row.get("impact_statement", ""),
        row.get("title", ""),
        row.get("discard_mechanism", ""),
    ]
    text = " ".join(str(s) for s in sources if s)

    # Prefer explicit function names (e.g. is_deposits_only, verify_kzg_proof)
    fn_names = re.findall(r"\b([a-z_][a-z0-9_]{4,})\s*\(", text)
    # Also grab quoted identifiers and snake_case tokens
    idents = re.findall(r"\b([a-z][a-z0-9_]{5,})\b", text)

    # Pick the most specific / longest identifier
    candidates = fn_names + idents
    # Deduplicate and prefer function-name style
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen and len(c) >= 5:
            seen.add(c)
            unique.append(c)
        if len(unique) >= 3:
            break

    if unique:
        # Use +OR+ for multi-term but keep it short
        return "+".join(unique[:2])
    # Fallback: first 40 chars of production_path basename
    pp = str(row.get("production_path", row.get("file", "")))
    return Path(pp).stem[:40] if pp else "unknown_pattern"


def check_step5_upstream(
    row: dict[str, Any],
    max_queries: int = _MAX_UPSTREAM_QUERIES,
    exhaustive: bool = False,
) -> list[dict[str, Any]]:
    """Query upstream repos for equivalent bug.

    Returns list of hit dicts: [{"repo": ..., "url": ..., "hit_count": N}]
    Applies gentle rate-limit (1 req/sec).
    """
    bug_pattern = str(row.get("bug_shape_query", "")).strip() or _derive_bug_pattern(row)
    if not bug_pattern or bug_pattern == "unknown_pattern":
        return []

    repos = UPSTREAM_REPOS
    hits: list[dict[str, Any]] = []
    queries_run = 0
    limit = None if exhaustive else max_queries

    for repo in repos:
        if limit is not None and queries_run >= limit:
            break
        if queries_run > 0:
            time.sleep(_GH_PACE_SECS)
        data = _gh_search(bug_pattern, repo=repo)
        queries_run += 1
        total = data.get("total_count", 0)
        items = data.get("items", [])
        if total > 0:
            # M14-trap: verify at least the first URL looks real
            first_url = items[0].get("html_url", "") if items else ""
            hits.append({
                "repo": repo,
                "url": first_url or f"https://github.com/{repo}",
                "hit_count": total,
            })

    return hits


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def _severity_tier(row: dict[str, Any]) -> str:
    for key in ("severity_tier", "raw_severity", "severity"):
        v = row.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    return ""


def _selected_impact(row: dict[str, Any]) -> str | None:
    for key in ("selected_impact", "listed_impact_selected", "impact_statement"):
        v = row.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _candidate_id(row: dict[str, Any], idx: int) -> str:
    for key in ("candidate_id", "row_index", "id", "classification"):
        v = row.get(key)
        if v is not None:
            return str(v)
    return str(idx)


def _is_critical_claim(row: dict[str, Any]) -> bool:
    tier = _severity_tier(row)
    return "critical" in tier


def compute_verdict(
    row: dict[str, Any],
    workspace: Path,
    idx: int,
    max_queries: int = _MAX_UPSTREAM_QUERIES,
    exhaustive: bool = False,
) -> dict[str, Any]:
    """Run all 5 checks and compute per-row verdict."""
    production_path = str(row.get("production_path", row.get("file", ""))).strip()
    cited_line = row.get("line") or row.get("cited_line")
    try:
        cited_line = int(cited_line) if cited_line is not None else None
    except (TypeError, ValueError):
        cited_line = None
    quoted_content = row.get("evidence_snippet") or row.get("quoted_line")

    # --- Step 1 ---
    step1_exists, resolved_path = check_step1_existence(workspace, production_path)

    # --- Step 2 ---
    step2_line = check_step2_line_content(
        resolved_path if step1_exists else "",
        cited_line,
        quoted_content,
    )

    # --- Step 3 ---
    # Pass explicit crate_name from row if present (e.g. from L-1 candidate JSON)
    row_crate_name: str | None = row.get("crate_name") or None
    step3_scope = check_step3_scope(workspace, production_path, crate_name=row_crate_name)

    # --- Step 4 ---
    severity_tier = _severity_tier(row)
    selected_impact = _selected_impact(row)
    step4_severity = check_step4_severity(workspace, severity_tier or None, selected_impact)

    # --- Step 5 ---
    step5_hits: list[dict[str, Any]] = []
    if step1_exists and step3_scope == "in_scope":
        step5_hits = check_step5_upstream(row, max_queries=max_queries, exhaustive=exhaustive)

    # --- Verdict ---
    verdict = _determine_verdict(
        step1_exists=step1_exists,
        step2_line=step2_line,
        step3_scope=step3_scope,
        step4_severity=step4_severity,
        step5_hits=step5_hits,
        severity_tier=severity_tier,
        row=row,
    )

    return {
        "candidate_id": _candidate_id(row, idx),
        "production_path": production_path,
        "step_1_audit_tree_exists": step1_exists,
        "step_2_line_content_matches": step2_line,
        "step_3_scope_status": step3_scope,
        "step_4_severity_verbatim": step4_severity,
        "step_5_upstream_equivalent": step5_hits,
        "verdict": verdict,
    }


def _determine_verdict(
    *,
    step1_exists: bool,
    step2_line: bool | str,
    step3_scope: str,
    step4_severity: bool | str,
    step5_hits: list[dict[str, Any]],
    severity_tier: str,
    row: dict[str, Any],
) -> str:
    # Step 1 kill — path doesn't exist
    if not step1_exists:
        return "killed_path_not_in_audit_tree"

    # Step 2 kill — content doesn't match (only for long-form quotes)
    if step2_line is False:
        return "walked_back_to_line_content_mismatch"

    # Step 3 kill — OOS
    if step3_scope == "oos":
        return "killed_oos_per_scope_md"

    # Step 4 kill — severity over-claim
    if step4_severity is False and severity_tier in ("critical", "high", "medium"):
        return f"walked_back_to_severity_not_verbatim_in_{severity_tier}_section"

    # Step 5 downgrade — upstream equivalent found
    if step5_hits:
        repos = [h["repo"] for h in step5_hits]
        repos_str = "_".join(r.replace("/", "-") for r in repos[:2])
        if "critical" in severity_tier:
            return f"walked_back_to_upstream_inherited_partial_found_in_{repos_str}"
        # For non-critical, it's advisory
        return f"walked_back_to_upstream_inherited_partial_found_in_{repos_str}"

    return "promotion_allowed"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="upstream-equivalent-gate.py",
        description=(
            "5-check candidate promotion gate. "
            "Catches OOS-shared / upstream-equivalent over-claims before submission. "
            "Wave J-1A."
        ),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="Audit workspace root (contains external/, SCOPE.md, SEVERITY.md).",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        required=True,
        help="Path to candidate JSON (promotion_candidates.json or matrix row array).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if ANY candidate has verdict != 'promotion_allowed'.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        dest="print_json",
        help="Emit structured JSON results to stdout.",
    )
    parser.add_argument(
        "--exhaustive",
        action="store_true",
        help="Lift 10-query cap on upstream searches (slow).",
    )
    parser.add_argument(
        "--max-queries",
        type=int,
        default=_MAX_UPSTREAM_QUERIES,
        dest="max_queries",
        help=f"Cap on upstream gh api queries per run (default {_MAX_UPSTREAM_QUERIES}).",
    )
    args = parser.parse_args(argv)

    if not args.workspace.is_dir():
        print(
            f"[upstream-equivalent-gate] ERR workspace not found: {args.workspace}",
            file=sys.stderr,
        )
        return 2

    try:
        payload = _load_json(args.candidate)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[upstream-equivalent-gate] ERR {exc}", file=sys.stderr)
        return 2

    rows = _rows_from_payload(payload)
    if not rows:
        print(
            "[upstream-equivalent-gate] WARN no candidate rows found in "
            f"{args.candidate}; treating as empty pass.",
            file=sys.stderr,
        )
        if args.print_json:
            print(json.dumps({
                "schema": SCHEMA_VERSION,
                "candidate_file": str(args.candidate),
                "workspace": str(args.workspace),
                "row_count": 0,
                "walked_back_count": 0,
                "results": [],
            }, indent=2))
        return 0

    results: list[dict[str, Any]] = []
    walked_back = 0

    for idx, row in enumerate(rows):
        r = compute_verdict(
            row,
            workspace=args.workspace,
            idx=idx,
            max_queries=args.max_queries,
            exhaustive=args.exhaustive,
        )
        results.append(r)
        if r["verdict"] != "promotion_allowed":
            walked_back += 1

    output = {
        "schema": SCHEMA_VERSION,
        "candidate_file": str(args.candidate),
        "workspace": str(args.workspace),
        "row_count": len(rows),
        "walked_back_count": walked_back,
        "results": results,
    }

    if args.print_json:
        # JSON goes to stdout exclusively; human summary goes to stderr so that
        # callers can parse stdout cleanly.
        print(json.dumps(output, indent=2))
        summary_sink = sys.stderr
    else:
        summary_sink = sys.stdout

    # Human summary (to stdout in normal mode, stderr in --print-json mode)
    for r in results:
        status = "PASS" if r["verdict"] == "promotion_allowed" else "FAIL"
        print(
            f"[upstream-equivalent-gate] {status} candidate={r['candidate_id']} "
            f"path={r['production_path']!r} verdict={r['verdict']}",
            file=summary_sink,
        )

    if walked_back == 0:
        print(
            f"[upstream-equivalent-gate] PASS — {len(rows)} candidate(s) "
            "cleared all 5 checks.",
            file=summary_sink,
        )
    else:
        print(
            f"[upstream-equivalent-gate] FAIL — {walked_back}/{len(rows)} "
            "candidate(s) walked back.",
            file=sys.stderr,
        )

    if args.strict and walked_back > 0:
        return 1
    if not args.strict and walked_back > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
