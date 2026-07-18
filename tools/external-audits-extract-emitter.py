#!/usr/bin/env python3
"""external-audits-extract-emitter.py — Emit per-finding markdown notes from
workspace ``prior_audits/`` files into the Obsidian vault.

Walks ``<workspace>/prior_audits/`` and extracts per-finding chunks from:
  - ``DIGEST_*.md`` files (preferred — canonical structure with
    ``### [HMLI]-NN — title`` or ``### Medium / ### Low`` section headers).
  - Raw audit-report ``*.txt`` files (heuristic fallback — splits on
    ``Severity\\s+(HIGH|MEDIUM|LOW|INFORMATIONAL)`` boundary lines and
    backfills the title from the line(s) preceding the matched block).

Output goes to the active vault's
``external-audits-extracts/<workspace>/<audit-id>-<finding-slug>.md``
with frontmatter:

    ---
    source: external-audits-extract
    workspace: <ws>
    audit_id: <derived from source filename>
    audit_year: <yyyy or "">
    finding_id: <e.g. H-04 / M-02 / Med-01>
    finding_severity: critical | high | medium | low | info
    modules: [<derived from "Involved artifacts" / paths in body>]
    status: <ACK | FIXED | UNFIXED | "">
    tags:
      - external-audit/<auditor-slug>
      - workspace/<ws>
    ---

Idempotent: tracks per-source mtime in ``<vault>/.deep_sync.json``
under the key ``external-audits-extracts/<workspace>/<source-stem>``.

Usage::

    python3 tools/external-audits-extract-emitter.py --workspace /Users/wolf/audits/dydx
    python3 tools/external-audits-extract-emitter.py --workspaces-root ~/audits        # walk all workspaces
    python3 tools/external-audits-extract-emitter.py --workspace ~/audits/dydx --vault-dir /tmp/vault --force
    python3 tools/external-audits-extract-emitter.py --workspace ~/audits/dydx --dry-run
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
DEFAULT_SHARED_VAULT = Path.home() / "Documents" / "Codex" / "auditooor" / "obsidian-vault"
AUDITS_ROOT_DEFAULT = Path.home() / "audits"

# Severity-keyword → canonical finding_severity tag.
SEVERITY_MAP = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "h": "high",
    "medium": "medium",
    "med": "medium",
    "m": "medium",
    "low": "low",
    "l": "low",
    "info": "info",
    "informational": "info",
    "i": "info",
    "observation": "info",
    "note": "info",
    "warning": "info",
    "qa": "info",
    "gas": "info",
}

# Status keywords found in audit findings.
STATUS_PATTERNS = [
    (re.compile(r"\b(acknowledged|ack|acknowledge[sd])\b", re.IGNORECASE), "ACK"),
    (re.compile(r"\bfix(ed)?\b", re.IGNORECASE), "FIXED"),
    (re.compile(r"\bresolved\b", re.IGNORECASE), "FIXED"),
    (re.compile(r"\bnot fix(ed)?\b", re.IGNORECASE), "UNFIXED"),
    (re.compile(r"\bunresolved\b", re.IGNORECASE), "UNFIXED"),
    (re.compile(r"\bopen\b", re.IGNORECASE), "UNFIXED"),
]

# Path-fragment regex used to derive ``modules:`` from a finding body.
MODULE_PATH_RE = re.compile(r"(?:^|[\s`(])(/?[a-zA-Z][a-zA-Z0-9_./\-]{2,80}\.(?:go|rs|sol|py|ts|js|move))\b")

# Capture explicit "Involved artifacts" / "Target" / "Vulnerable function" callouts.
ARTIFACT_BLOCK_RE = re.compile(
    r"^(?:\*\*)?(?:Involved artifacts|Target|Vulnerable function|Affected files?)(?:\*\*)?:?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Heading splits we recognise inside DIGEST_*.md files.
# Group 1 = ID prefix (H-01 / M-02 / L-03 / I-04 etc.), Group 2 = title text.
DIGEST_FINDING_HEADER_RE = re.compile(
    r"^###\s+([HMLICmlic][a-zA-Z]*-?\d+(?:\.\d+)?)(?:\s*\([^)]*\))?\s*[—\-:]\s*(.+?)\s*$",
    re.MULTILINE,
)
# Severity-only section header (e.g. `### Medium`, `### High`, `### Critical`)
DIGEST_SEVERITY_HEADER_RE = re.compile(
    r"^###\s+(Critical|High|Medium|Low|Info(?:rmational)?|Observation|QA|Gas)\s*$",
    re.MULTILINE,
)

# Raw-txt heuristic: lines like "Severity                         MEDIUM"
RAW_TXT_SEVERITY_LINE_RE = re.compile(
    r"^\s*Severity\s+(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Year extractor for audit_year frontmatter
YEAR_RE = re.compile(r"(20\d{2})")

# Auditor-slug heuristic from filename
AUDITOR_PATTERNS = [
    (re.compile(r"informal[\s_-]?systems", re.IGNORECASE), "informal-systems"),
    (re.compile(r"zcash[\s_-]?frost|redjubjub", re.IGNORECASE), "zcash-frost"),
    (re.compile(r"reserve[\s_-]?(security|review)", re.IGNORECASE), "reserve"),
    (re.compile(r"openzeppelin|^oz[\s_-]", re.IGNORECASE), "openzeppelin"),
    (re.compile(r"trail[\s_-]?of[\s_-]?bits", re.IGNORECASE), "trail-of-bits"),
    (re.compile(r"spearbit", re.IGNORECASE), "spearbit"),
    (re.compile(r"chainsec", re.IGNORECASE), "chainsec"),
    (re.compile(r"halborn", re.IGNORECASE), "halborn"),
    (re.compile(r"certik", re.IGNORECASE), "certik"),
    (re.compile(r"sherlock", re.IGNORECASE), "sherlock"),
    (re.compile(r"cantina", re.IGNORECASE), "cantina"),
    (re.compile(r"code4rena|c4", re.IGNORECASE), "code4rena"),
]


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _argv_has_option(argv: list[str], option: str) -> bool:
    return any(arg == option or arg.startswith(option + "=") for arg in argv)


def _active_vault_candidates() -> list[Path]:
    candidates: list[Path] = []
    for env_name in ("AUDITOOOR_VAULT_DIR", "VAULT", "VAULT_PATH"):
        raw = os.environ.get(env_name)
        if raw:
            candidates.append(Path(raw).expanduser())
    candidates.append(DEFAULT_SHARED_VAULT)

    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped


def _vault_has_resume_entrypoints(vault_dir: Path) -> bool:
    return (
        (vault_dir / "INDEX.md").is_file()
        and (vault_dir / "INDEX_active.md").is_file()
        and (vault_dir / "NEXT_LOOP.md").is_file()
    )


def resolve_vault_dir(vault_arg: str | Path, *, argv: list[str]) -> tuple[Path, str | None]:
    """Resolve the output vault with the same default semantics as MCP.

    Worktrees may contain a generated repo-local ``obsidian-vault`` mirror that
    lacks the active MCP resume entrypoints. If the operator did not explicitly
    choose a non-default vault, prefer the shared active vault when it is
    available. Explicit non-default ``--vault-dir`` keeps exact semantics.
    """
    raw_vault = Path(vault_arg).expanduser()
    vault = raw_vault.resolve()
    default_like_vault = (
        not _argv_has_option(argv, "--vault-dir")
        or vault == VAULT_DEFAULT.resolve()
        or str(raw_vault) == "obsidian-vault"
    )
    if _vault_has_resume_entrypoints(vault) or not default_like_vault:
        return vault, None
    for fallback in _active_vault_candidates():
        if _vault_has_resume_entrypoints(fallback):
            return (
                fallback,
                (
                    f"default vault {vault} is missing resume entrypoints; "
                    f"using active vault {fallback}"
                ),
            )
    return vault, None


def _slugify(text: str, max_len: int = 64) -> str:
    """Simple kebab-case slugifier — alphanumerics only, dash-separated."""
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    if len(text) > max_len:
        text = text[:max_len].rstrip("-")
    return text or "untitled"


def _audit_id(source_path: Path) -> str:
    """Derive a stable audit_id from the source filename.

    Drops common prefixes (`DIGEST_`, `prior_audits/`) and suffixes (`.txt`,
    `.md`, `-Audit-Report`), then slugifies.
    """
    stem = source_path.stem
    stem = re.sub(r"^DIGEST[_-]+", "", stem, flags=re.IGNORECASE)
    return _slugify(stem)


def _auditor_slug(source_path: Path) -> str:
    name = source_path.name
    for pat, slug in AUDITOR_PATTERNS:
        if pat.search(name):
            return slug
    return "unknown"


def _audit_year(source_path: Path, body: str = "") -> str:
    candidates = YEAR_RE.findall(source_path.name)
    if candidates:
        return candidates[0]
    candidates = YEAR_RE.findall(body[:2000])
    return candidates[0] if candidates else ""


def _normalize_severity(raw: str) -> str:
    raw = raw.strip().lower()
    return SEVERITY_MAP.get(raw, "info")


def _detect_status(body: str) -> str:
    """Best-effort fix-status detection from finding body."""
    # Look for explicit ``Fix status:`` / ``Status:`` lines first.
    explicit = re.search(
        r"^[\s*\-]*(?:\*\*)?(?:Fix\s+status|Status|Resolution)(?:\*\*)?:?\s*([A-Za-z ]{3,40})",
        body,
        re.MULTILINE,
    )
    if explicit:
        text = explicit.group(1).lower()
        for pat, label in STATUS_PATTERNS:
            if pat.search(text):
                return label
    # Fallback: scan first 20 lines.
    for line in body.splitlines()[:30]:
        for pat, label in STATUS_PATTERNS:
            if pat.search(line):
                return label
    return ""


def _extract_modules(body: str) -> list[str]:
    """Return up to 6 short module/path hints from a finding body."""
    seen: list[str] = []
    for m in MODULE_PATH_RE.finditer(body):
        path = m.group(1).lstrip("/")
        # Use only the directory or stem as a "module" — full path is too
        # noisy and may leak unintended detail; we want the shape.
        parts = [p for p in path.split("/") if p and not p.startswith(".")]
        if not parts:
            continue
        # Prefer the second-to-last directory (e.g. ``prepare`` from
        # ``protocol/app/prepare/prepare_proposal.go``); fall back to stem.
        if len(parts) >= 2:
            key = parts[-2]
        else:
            key = Path(parts[-1]).stem
        key = re.sub(r"[^a-zA-Z0-9_-]+", "", key).lower()
        if key and key not in seen:
            seen.append(key)
        if len(seen) >= 6:
            break
    return seen


def _frontmatter(**kwargs: Any) -> str:
    """Emit frontmatter compatible with the flat parser used by
    ``tools/vault-mcp-server.py:_frontmatter_and_body`` AND with normal
    YAML parsers.

    Lists are emitted in TWO forms:
      1. A flat ``<key>_csv: a,b,c`` line (parseable by the flat reader).
      2. A standard YAML block ``<key>:\\n  - a\\n  - b`` (parseable by
         strict YAML parsers; flat reader sets the key to empty string).

    This makes ``modules`` and ``tags`` recallable through both paths.
    """
    lines = ["---"]
    for k, v in kwargs.items():
        if isinstance(v, list):
            csv = ",".join(str(item) for item in v)
            lines.append(f"{k}_csv: {csv}")
            lines.append(f"{k}:")
            for item in v:
                lines.append(f"  - {item}")
        elif isinstance(v, bool):
            lines.append(f"{k}: {'true' if v else 'false'}")
        elif v == "" or v is None:
            lines.append(f"{k}: ''")
        else:
            lines.append(f"{k}: {v}")
    lines.append("---")
    return "\n".join(lines) + "\n\n"


def _split_digest_findings(text: str) -> list[tuple[str, str, str, str]]:
    """Split a DIGEST_*.md body into per-finding chunks.

    Returns ``[(finding_id, severity, title, body), ...]``.
    Recognises both styles:
      - ``### H-04 (2.5) — Title`` (id-prefixed)
      - ``### Medium`` (severity-only — synthesise per-bullet IDs)
    """
    chunks: list[tuple[str, str, str, str]] = []
    # First pass: id-prefixed headers.
    matches = list(DIGEST_FINDING_HEADER_RE.finditer(text))
    if matches:
        for i, m in enumerate(matches):
            fid_raw = m.group(1).upper().replace(".", "-")
            title = m.group(2).strip()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[start:end].strip()
            sev_letter = re.match(r"([A-Z]+)", fid_raw)
            sev = ""
            if sev_letter:
                sev = _normalize_severity(sev_letter.group(1))
            # also scan body for explicit "Severity: X"
            mexpl = re.search(r"\*\*Severity:\*\*\s*([A-Za-z]+)", body)
            if mexpl:
                sev = _normalize_severity(mexpl.group(1))
            chunks.append((fid_raw, sev, title, body))
        return chunks

    # Second pass: severity-only headers ("### Medium" → bullets are findings).
    sev_matches = list(DIGEST_SEVERITY_HEADER_RE.finditer(text))
    if sev_matches:
        for i, m in enumerate(sev_matches):
            sev = _normalize_severity(m.group(1))
            start = m.end()
            end = sev_matches[i + 1].start() if i + 1 < len(sev_matches) else len(text)
            section_body = text[start:end].strip()
            # Split this severity section on bullet boundaries (``- `` at line start).
            bullet_chunks = re.split(r"\n(?=- )", section_body)
            for j, bc in enumerate(bullet_chunks):
                bc = bc.strip()
                if not bc or len(bc) < 30:  # skip stub bullets
                    continue
                # First line of the bullet → title (strip leading "- ").
                first_line = bc.splitlines()[0].lstrip("- ").strip()
                title = first_line[:120]
                fid = f"{sev[0].upper()}-{j + 1:02d}"
                chunks.append((fid, sev, title, bc))
        return chunks
    return chunks


def _split_raw_txt_findings(text: str) -> list[tuple[str, str, str, str]]:
    """Heuristic split of a raw audit-report .txt body.

    Strategy: locate every ``Severity\\s+TIER`` line, then walk backward
    up to 8 non-blank lines to recover the finding title (first non-empty
    paragraph above). Body extends from the title-block to just before the
    next ``Severity\\s+TIER`` line (or EOF).

    This is intentionally lossy — raw .txt files are PDF extracts with no
    guaranteed structure. We aim for "good enough so a vault search returns
    the right neighborhood", not 100% finding fidelity.
    """
    sev_matches = list(RAW_TXT_SEVERITY_LINE_RE.finditer(text))
    if not sev_matches:
        return []
    chunks: list[tuple[str, str, str, str]] = []
    severity_seen: dict[str, int] = {}
    for i, m in enumerate(sev_matches):
        sev = _normalize_severity(m.group(1))
        # Find title: walk backward from match position to the first
        # non-empty line preceded by a blank line.
        sev_line_start = m.start()
        # Search for the start of the previous logical block (≤ 30 lines back).
        before = text[max(0, sev_line_start - 4000):sev_line_start]
        before_lines = before.rstrip().splitlines()
        title_lines: list[str] = []
        for line in reversed(before_lines):
            stripped = line.strip()
            if not stripped:
                if title_lines:
                    break
                continue
            if stripped.lower().startswith(("findings", "© ", "table of contents", "appendix")):
                if title_lines:
                    break
                continue
            # Skip lines that are pure dashes or whitespace
            if re.fullmatch(r"[\-=_*]+", stripped):
                if title_lines:
                    break
                continue
            title_lines.insert(0, stripped)
            if len(title_lines) >= 5:
                break
        title = " ".join(title_lines).strip()[:200]
        if not title:
            title = f"Untitled {sev.upper()} finding"

        # Body extends to just before next severity match (or EOF).
        body_start = m.start()
        body_end = sev_matches[i + 1].start() if i + 1 < len(sev_matches) else len(text)
        body = text[body_start:body_end].strip()
        # Cap body at 8KB to keep vault notes bounded.
        if len(body) > 8192:
            body = body[:8192] + "\n\n_(truncated at 8KB)_"

        # Synthesise finding-id: e.g. M-01, M-02, ...
        prefix = sev[0].upper() if sev else "X"
        idx = severity_seen.get(prefix, 0) + 1
        severity_seen[prefix] = idx
        fid = f"{prefix}-{idx:02d}"
        chunks.append((fid, sev, title, body))
    return chunks


def _emit_finding_note(
    out_dir: Path,
    workspace: str,
    audit_id: str,
    audit_year: str,
    auditor_slug: str,
    finding_id: str,
    finding_severity: str,
    title: str,
    body: str,
    source_relpath: str,
    dry_run: bool = False,
) -> tuple[Path, bool]:
    """Write one per-finding note. Returns (path, was_written)."""
    slug = _slugify(title or finding_id, max_len=48)
    note_name = f"{audit_id}-{finding_id.lower()}-{slug}.md"
    note_path = out_dir / note_name

    modules = _extract_modules(body)
    status = _detect_status(body)

    fm = _frontmatter(
        source="external-audits-extract",
        workspace=workspace,
        audit_id=audit_id,
        audit_year=audit_year,
        finding_id=finding_id,
        finding_severity=finding_severity,
        modules=modules,
        status=status,
        source_path=source_relpath,
        last_synced=_now_iso(),
        tags=[
            f"external-audit/{auditor_slug}",
            f"workspace/{workspace}",
            f"severity/{finding_severity}",
        ],
    )
    body_capped = body if len(body) <= 8192 else body[:8192] + "\n\n_(truncated at 8KB)_"
    note = fm + f"# {finding_id}: {title}\n\n" + body_capped + "\n"

    if dry_run:
        return note_path, False

    out_dir.mkdir(parents=True, exist_ok=True)
    note_path.write_text(note, encoding="utf-8")
    return note_path, True


def _load_deep_sync(vault_dir: Path) -> dict[str, Any]:
    p = vault_dir / ".deep_sync.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save_deep_sync(vault_dir: Path, state: dict[str, Any]) -> None:
    p = vault_dir / ".deep_sync.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2))


def emit_for_workspace(
    workspace_path: Path,
    vault_dir: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
    sync_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit all per-finding notes for a single workspace.

    Returns ``{workspace, sources_seen, sources_skipped, notes_written, paths[]}``.
    """
    workspace_path = workspace_path.expanduser().resolve()
    workspace = workspace_path.name
    prior_dir = workspace_path / "prior_audits"

    result = {
        "workspace": workspace,
        "workspace_path": str(workspace_path),
        "prior_audits_dir": str(prior_dir),
        "sources_seen": 0,
        "sources_skipped": 0,
        "notes_written": 0,
        "paths": [],
    }

    if not prior_dir.is_dir():
        result["error"] = "prior_audits_missing"
        return result

    if sync_state is None:
        sync_state = _load_deep_sync(vault_dir) if not dry_run else {}

    out_dir = vault_dir / "external-audits-extracts" / workspace

    sources = sorted(prior_dir.glob("*.md")) + sorted(prior_dir.glob("*.txt"))
    for src in sources:
        if src.name.startswith(".") or src.name.startswith("_"):
            continue
        result["sources_seen"] += 1
        sync_key = f"external-audits-extracts/{workspace}/{src.stem}"
        try:
            src_mtime = src.stat().st_mtime
        except OSError:
            result["sources_skipped"] += 1
            continue
        last_sync = sync_state.get(sync_key, 0.0)
        if not force and src_mtime <= last_sync:
            result["sources_skipped"] += 1
            continue

        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result["sources_skipped"] += 1
            continue

        # Choose split strategy: digests first, raw-txt fallback.
        if src.suffix.lower() == ".md" and src.name.upper().startswith("DIGEST"):
            chunks = _split_digest_findings(text)
        elif src.suffix.lower() == ".md":
            chunks = _split_digest_findings(text)
            if not chunks:
                chunks = _split_raw_txt_findings(text)
        else:
            chunks = _split_raw_txt_findings(text)

        if not chunks:
            result["sources_skipped"] += 1
            continue

        audit_id = _audit_id(src)
        auditor_slug = _auditor_slug(src)
        audit_year = _audit_year(src, text)

        try:
            source_relpath = str(src.relative_to(workspace_path))
        except ValueError:
            source_relpath = str(src)

        for fid, sev, title, body in chunks:
            note_path, written = _emit_finding_note(
                out_dir,
                workspace,
                audit_id,
                audit_year,
                auditor_slug,
                fid,
                sev,
                title,
                body,
                source_relpath,
                dry_run=dry_run,
            )
            if written or dry_run:
                result["notes_written"] += 1
                try:
                    rel = note_path.relative_to(vault_dir)
                except ValueError:
                    rel = note_path
                result["paths"].append(str(rel))

        if not dry_run:
            sync_state[sync_key] = src_mtime

    if not dry_run:
        _save_deep_sync(vault_dir, sync_state)

    return result


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Emit per-finding notes from workspace prior_audits/ into the vault.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--workspace", type=Path, help="Single workspace path (e.g. ~/audits/dydx)")
    ap.add_argument(
        "--workspaces-root",
        type=Path,
        help="Root directory of all workspaces (e.g. ~/audits) — walks every subdir with a prior_audits/",
    )
    ap.add_argument(
        "--vault-dir",
        type=Path,
        default=VAULT_DEFAULT,
        help="Vault root (default: active MCP vault when repo-local obsidian-vault lacks resume entrypoints)",
    )
    ap.add_argument("--force", action="store_true", help="Ignore mtime cache, regenerate all")
    ap.add_argument("--dry-run", action="store_true", help="Show planned notes only — no writes")
    raw_argv = sys.argv[1:]
    args = ap.parse_args(raw_argv)

    vault, vault_note = resolve_vault_dir(args.vault_dir, argv=raw_argv)
    if vault_note:
        print(f"[external-audits-extract-emitter] {vault_note}", file=sys.stderr)

    if args.workspace and args.workspaces_root:
        print("ERROR: pass either --workspace or --workspaces-root, not both", file=sys.stderr)
        sys.exit(2)

    if not args.workspace and not args.workspaces_root:
        # Default: walk ~/audits
        args.workspaces_root = AUDITS_ROOT_DEFAULT

    workspaces: list[Path] = []
    if args.workspace:
        workspaces = [args.workspace.expanduser().resolve()]
    else:
        root = args.workspaces_root.expanduser().resolve()
        if not root.is_dir():
            print(f"ERROR: workspaces root {root} not found", file=sys.stderr)
            sys.exit(2)
        for d in sorted(root.iterdir()):
            if d.is_dir() and not d.name.startswith(".") and not d.name.startswith("_"):
                if (d / "prior_audits").is_dir():
                    workspaces.append(d)

    if not workspaces:
        print("[external-audits-extract-emitter] no workspaces with prior_audits/ found")
        return

    sync_state = _load_deep_sync(vault) if not args.dry_run else {}

    grand_total = 0
    grand_sources = 0
    for ws in workspaces:
        res = emit_for_workspace(
            ws,
            vault,
            force=args.force,
            dry_run=args.dry_run,
            sync_state=sync_state,
        )
        if res.get("error"):
            print(f"  [{ws.name}] skip: {res['error']}")
            continue
        grand_total += res["notes_written"]
        grand_sources += res["sources_seen"]
        action = "would write" if args.dry_run else "wrote"
        print(
            f"  [{ws.name}] sources={res['sources_seen']} "
            f"skipped={res['sources_skipped']} {action}={res['notes_written']} notes"
        )

    if not args.dry_run:
        _save_deep_sync(vault, sync_state)

    print()
    print(
        f"[external-audits-extract-emitter] {len(workspaces)} workspaces, "
        f"{grand_sources} sources, {grand_total} {'planned' if args.dry_run else 'new/updated'} notes"
    )


if __name__ == "__main__":
    main()
