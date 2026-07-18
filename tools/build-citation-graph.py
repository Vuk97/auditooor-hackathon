#!/usr/bin/env python3
"""build-citation-graph.py — cross-audit citation graph for auditooor (R43 U6).

Scans ~/audits/*/prior_audits/DIGEST_*.md and prior_audits/*.txt across all
workspaces. Extracts every prior-audit finding as a graph node with:

  - source_audit      (e.g. "2025-02-Cantina", or the *.txt stem)
  - workspace         (e.g. "polymarket", "centrifuge-v3", "morpho")
  - finding_id        (best-effort parse: "§3.3.6", "SB-M-01", "OZ-L-01", etc.)
  - contract          (best-effort from "Target:", "Contract:", or fenced keywords)
  - function          (best-effort from "Vulnerable function:" / backticks)
  - severity          (Critical/High/Medium/Low/Info/Gas)
  - mechanism         (1-line summary — title or "Mechanism:" line)
  - protocol_type     (exchange/lending/vault/bridge/hook — inferred from workspace + text)
  - status            (fixed/acknowledged/paid/OOS — parsed from "Fix status:" or heading)
  - title             (raw finding title for display)
  - text_blob         (first ~600 chars, for similarity matching)

Writes YAML to reference/citation_graph.yaml.

Usage:
  ./tools/build-citation-graph.py                 # scan ~/audits
  ./tools/build-citation-graph.py --audit-root DIR
  ./tools/build-citation-graph.py --out PATH

Depends on PyYAML.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("[build-citation-graph] PyYAML not installed. pip install PyYAML")


# ------------------------------------------------------------
# Protocol-type inference
# ------------------------------------------------------------
WORKSPACE_PROTOCOL_HINT = {
    "polymarket": "exchange",
    "centrifuge-v3": "vault",
    "morpho": "lending",
}

PROTOCOL_KEYWORDS = {
    "exchange": [r"order\s*match", r"maker.*taker", r"CLOB", r"CTFExchange", r"orderbook"],
    "lending": [r"supply", r"borrow", r"liquidat", r"collateral", r"IRM", r"utiliz"],
    "vault": [r"ERC-?4626", r"vault", r"shares", r"assets", r"investment\s?manager"],
    "bridge": [r"cross.?chain", r"bridge", r"gateway", r"adapter.*message", r"relay"],
    "hook": [r"hook", r"callback", r"beforeSwap", r"afterSwap", r"poolManager"],
}

SEVERITY_PATTERNS = [
    ("Critical", r"(?i)\bcritical\b"),
    ("High", r"(?i)\bhigh\b"),
    ("Medium", r"(?i)\bmedium\b|\bmed\b"),
    ("Low", r"(?i)\blow\b"),
    ("Gas", r"(?i)\bgas\b"),
    ("Info", r"(?i)\binfo(?:rmational)?\b|\bnote\b"),
]

STATUS_PATTERNS = [
    ("fixed", r"(?i)fixed|resolved|patched|PR\s*#?\d+"),
    ("acknowledged", r"(?i)acknowledg|by.?design|wont.?fix|won't fix"),
    ("paid", r"(?i)\bpaid\b|confirmed finding"),
    ("OOS", r"(?i)out.of.scope|OOS|not.in.scope"),
]

SEVERITY_EMOJI_MAP = {
    "[High]": "High", "[Medium]": "Medium", "[Med]": "Medium",
    "[Low]": "Low", "[Info]": "Info", "[Critical]": "Critical",
    "[Gas]": "Gas",
}


# ------------------------------------------------------------
# Parsers
# ------------------------------------------------------------
def infer_protocol(workspace: str, text: str) -> str:
    if workspace in WORKSPACE_PROTOCOL_HINT:
        base = WORKSPACE_PROTOCOL_HINT[workspace]
    else:
        base = None

    scores = {}
    for proto, patterns in PROTOCOL_KEYWORDS.items():
        scores[proto] = sum(len(re.findall(p, text, re.IGNORECASE)) for p in patterns)
    best = max(scores, key=scores.get) if any(scores.values()) else None

    if base and (best is None or scores.get(best, 0) < 2):
        return base
    return best or base or "unknown"


def extract_severity(text: str) -> str:
    head = text[:300]
    # Bracketed-severity prefix common in digests: "[Low] ..."
    for tag, sev in SEVERITY_EMOJI_MAP.items():
        if tag in head:
            return sev
    for sev, pat in SEVERITY_PATTERNS:
        if re.search(pat, head):
            return sev
    return "Unknown"


def extract_status(text: str) -> str:
    for status, pat in STATUS_PATTERNS:
        if re.search(pat, text):
            return status
    return "unknown"


def extract_finding_id(text: str, fallback: str) -> str:
    # Strong patterns: "§3.3.6", "SB-M-01", "OZ-L-01", "H-01", "M-02", etc.
    patterns = [
        r"§\s*([\d\.]+)",
        r"\b([A-Z]{1,4}-[MHLIC]-\d+)\b",
        r"\b([MHLIC]-\d+)\b",
        r"finding\s*#?\s*(\d+)",
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m.group(1) if m.group(1).startswith(("§", "SB", "OZ")) else m.group(0).strip("§ ")
    return fallback


def extract_contract_and_function(text: str) -> tuple[str, str]:
    """Parse Target: / Contract: / Vulnerable function: lines, or backtick code-spans."""
    contract = ""
    func = ""

    m = re.search(r"(?i)\*\*Target:\*\*\s*([A-Za-z0-9_]+)", text)
    if m:
        contract = m.group(1)

    if not contract:
        m = re.search(r"(?i)\*\*Contract:\*\*\s*([A-Za-z0-9_]+)", text)
        if m:
            contract = m.group(1)

    m = re.search(r"(?i)\*\*Vulnerable function:\*\*\s*`?([A-Za-z0-9_]+)\s*\(?", text)
    if m:
        func = m.group(1)

    if not func:
        # Bullet prose: "— InvestmentManager.sol (`_processRedeem`, `claimCancelDepositRequest`)"
        m = re.search(r"`([a-z_][A-Za-z0-9_]{2,})\s*\(?`", text)
        if m:
            func = m.group(1)

    if not contract:
        # Try file:line pattern "src/.../Foo.sol#L123"
        m = re.search(r"([A-Z][A-Za-z0-9_]{2,})\.sol", text)
        if m:
            contract = m.group(1)

    return contract, func


def extract_mechanism(text: str) -> str:
    """Prefer an explicit 'Mechanism:' line; else the first sentence of body."""
    m = re.search(r"(?im)^\s*[-*]?\s*\*\*Mechanism:\*\*\s*(.{20,400})", text)
    if m:
        return m.group(1).strip().rstrip(".")

    # Fallback: the first prose line after the title
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for l in lines[1:6]:
        if len(l) > 30 and not l.startswith("#") and not l.startswith("-**") and not l.startswith("**"):
            # Strip leading markup
            clean = re.sub(r"^\s*[-*]\s*", "", l)
            return clean[:300]
    return ""


# ------------------------------------------------------------
# Digest parsing — structured per section
# ------------------------------------------------------------
def parse_digest_md(path: Path, workspace: str) -> list[dict]:
    """Parse a DIGEST_*.md — two variants:
       A) Rich format (morpho/bundler3): ### SB-M-01 — title ... field: value blocks
       B) Compact format (centrifuge): bullet-per-finding under "## Confirmed findings (paid)"
    """
    text = path.read_text(errors="ignore")
    audit_name = path.stem.replace("DIGEST_", "")
    nodes: list[dict] = []

    # ---- Variant A: "### ID — title" heading blocks --------
    heading_pat = r"\n(?=###\s+[A-Za-z0-9\-§\.]+\s+[—–\-])"
    heading_blocks = re.split(heading_pat, text)
    variant_a_start = len(nodes)
    if len(heading_blocks) >= 2:
        for block in heading_blocks[1:]:
            lines = block.splitlines()
            if not lines:
                continue
            title_line = lines[0].lstrip("# ").strip()
            # e.g. "SB-M-01 — morphoRepay() fetches borrowShares..."
            fid_m = re.match(r"([A-Za-z0-9\-§\.]+)\s+[—–\-]\s+(.+)", title_line)
            if fid_m:
                fid = fid_m.group(1).strip()
                title = fid_m.group(2).strip()
            else:
                fid = extract_finding_id(title_line, "")
                title = title_line

            if not fid and not title:
                continue

            contract, func = extract_contract_and_function(block)
            severity = extract_severity(block)
            status = extract_status(block)
            mechanism = extract_mechanism(block) or title
            protocol = infer_protocol(workspace, block)

            nodes.append({
                "source_audit": audit_name,
                "workspace": workspace,
                "finding_id": fid or f"auto-{len(nodes)+1}",
                "title": title,
                "contract": contract,
                "function": func,
                "severity": severity,
                "mechanism": mechanism,
                "protocol_type": protocol,
                "status": status,
                "text_blob": block[:600].strip(),
                "source_path": str(path),
            })
    # If Variant A produced rich results, return early (avoid double-count).
    # Threshold: 3+ heading nodes means the digest is structured per-finding.
    if len(nodes) - variant_a_start >= 3:
        return nodes

    # Otherwise, also run Variant B to catch compact bullet sections.
    # Strip any heading-block regions from text so we don't re-capture them as bullets.
    if len(nodes) > variant_a_start:
        text = re.sub(heading_pat + r".*?(?=\n##\s|\Z)", "\n", text, flags=re.DOTALL)

    # ---- Variant B: compact bullets per "##" section -----
    # Track section context ("Confirmed findings", "Acknowledged") for status hint
    section_status = "unknown"
    for section in re.split(r"(?m)^##\s+", text):
        if not section.strip():
            continue
        head = section.splitlines()[0].lower()
        if "confirmed" in head or "paid" in head:
            section_status = "paid"
        elif "acknowledg" in head or "by-design" in head or "do not re-file" in head:
            section_status = "acknowledged"
        elif "invariant" in head or "attacker angle" in head or "useful" in head:
            continue  # skip non-finding sections
        else:
            section_status = "unknown"

        # Parse bullets
        for bullet_m in re.finditer(r"(?m)^\s*[-*]\s+(.{30,2000}?)(?=\n\s*[-*]|\n\s*\n|\Z)",
                                     section, re.DOTALL):
            bullet = bullet_m.group(1).strip()
            if not bullet:
                continue
            severity = extract_severity(bullet)
            status = extract_status(bullet)
            if status == "unknown":
                status = section_status
            contract, func = extract_contract_and_function(bullet)
            # Title: after "] " and up to "—"
            title_m = re.match(r"(?:\[[A-Za-z]+\]\s*)?(.+?)(?:\s+[—–\-]\s+|$)", bullet)
            title = title_m.group(1).strip() if title_m else bullet[:160]
            title = title[:200]
            mechanism = extract_mechanism(bullet) or title
            protocol = infer_protocol(workspace, bullet)

            nodes.append({
                "source_audit": audit_name,
                "workspace": workspace,
                "finding_id": extract_finding_id(bullet, f"bullet-{len(nodes)+1}"),
                "title": title,
                "contract": contract,
                "function": func,
                "severity": severity,
                "mechanism": mechanism,
                "protocol_type": protocol,
                "status": status,
                "text_blob": bullet[:600],
                "source_path": str(path),
            })

    return nodes


def parse_prior_txt(path: Path, workspace: str) -> list[dict]:
    """Lightweight parse of raw audit .txt: extract severity-tagged sections only.
    Good for first-pass; rich structure is expected to live in digests.
    """
    text = path.read_text(errors="ignore")
    audit_name = path.stem
    nodes: list[dict] = []

    # Heuristic: look for headings or lines that start with severity tokens
    # E.g. "5.2.3 Foo bar [High]" or "# H-01 Title"
    blocks = re.split(r"\n(?=(?:##?#?\s+(?:\d+\.\d+(?:\.\d+)?|[A-Z]-\d+|[HMLIC]-\d+|§)\s|\[(?:High|Medium|Low|Critical|Info)\]))",
                       text)
    for block in blocks:
        if len(block) < 80:
            continue
        severity = extract_severity(block[:400])
        if severity == "Unknown":
            continue
        head = block.splitlines()[0][:200]
        fid = extract_finding_id(head, "")
        if not fid:
            continue
        contract, func = extract_contract_and_function(block)
        mechanism = extract_mechanism(block)
        status = extract_status(block[:800])
        protocol = infer_protocol(workspace, block[:1000])

        nodes.append({
            "source_audit": audit_name,
            "workspace": workspace,
            "finding_id": fid,
            "title": head.strip("# "),
            "contract": contract,
            "function": func,
            "severity": severity,
            "mechanism": mechanism,
            "protocol_type": protocol,
            "status": status,
            "text_blob": block[:600],
            "source_path": str(path),
        })
    return nodes


# ------------------------------------------------------------
# Driver
# ------------------------------------------------------------
def scan(audit_root: Path) -> list[dict]:
    nodes: list[dict] = []

    digests = sorted(audit_root.glob("*/prior_audits/DIGEST_*.md"))
    for d in digests:
        workspace = d.relative_to(audit_root).parts[0]
        try:
            nodes.extend(parse_digest_md(d, workspace))
        except Exception as e:
            print(f"[build-citation-graph] WARN: failed to parse {d}: {e}", file=sys.stderr)

    # Raw .txt files — only parse if they live alongside a DIGEST (i.e. prior_audits/).
    # Restrict to workspaces where DIGESTs aren't exhaustive to avoid drowning the graph.
    txts = sorted(audit_root.glob("*/prior_audits/*.txt"))
    digest_stems = {d.stem.replace("DIGEST_", "") for d in digests}
    for t in txts:
        if t.stem in digest_stems:
            continue  # digest already covers this report
        workspace = t.relative_to(audit_root).parts[0]
        try:
            got = parse_prior_txt(t, workspace)
            # Cap per-txt to keep noise down
            nodes.extend(got[:30])
        except Exception as e:
            print(f"[build-citation-graph] WARN: failed to parse {t}: {e}", file=sys.stderr)

    return nodes


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--audit-root", default=str(Path.home() / "audits"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    audit_root = Path(args.audit_root).expanduser()
    if not audit_root.is_dir():
        sys.exit(f"[build-citation-graph] {audit_root} not found")

    here = Path(__file__).resolve().parent.parent
    out_path = Path(args.out) if args.out else here / "reference" / "citation_graph.yaml"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    nodes = scan(audit_root)

    # Stats
    workspaces = sorted({n["workspace"] for n in nodes})
    severities = {}
    for n in nodes:
        severities[n["severity"]] = severities.get(n["severity"], 0) + 1

    meta = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "audit_root": str(audit_root),
        "total_nodes": len(nodes),
        "workspaces": workspaces,
        "severity_breakdown": severities,
    }

    doc = {"meta": meta, "nodes": nodes}
    out_path.write_text(yaml.safe_dump(doc, sort_keys=False, width=160, allow_unicode=True))
    print(f"[build-citation-graph] {len(nodes)} nodes from {len(workspaces)} workspaces → {out_path}")
    top_sev = ", ".join(f"{k}={v}" for k, v in sorted(severities.items(), key=lambda x: -x[1])[:5])
    print(f"[build-citation-graph] severity: {top_sev}")


if __name__ == "__main__":
    main()
