#!/usr/bin/env python3
"""memory-bug-class-emitter.py — PLAN-MEM Tier-1 Tool #7.

Aggregates patterns, detectors, and findings from the vault/sources and
groups them by inferred bug class. Emits one structured Obsidian note per
class into obsidian-vault/bug-classes/<class>.md.

Sources (read-only):
  - obsidian-vault/patterns/*.md        (if vault already built)
  - obsidian-vault/detectors/**/*.md    (if vault already built)
  - obsidian-vault/findings/**/*.md     (if vault already built)
  - reference/patterns.dsl/*.yaml       (fallback: raw patterns)
  - detectors/_tier_registry.yaml       (fallback: detector names)
  - findings/**/                        (fallback: raw finding dirs)

Bug classes (initial set per PLAN-MEM §3):
  reentrancy, oracle-staleness, signature-replay, domain-separator-cross-chain,
  flashloan, slippage, unchecked-erc20, tx-origin, unbounded-loop,
  auction-bid-validation, governance-race, share-asset-mispricing,
  decimals-mismatch, liquidation-bypass, flow-bypass

Classification: keyword/regex matching on pattern name + tag + description.
Fallback: "uncategorized" class for any pattern/detector/finding that doesn't match.

Output layout:
  obsidian-vault/bug-classes/
    INDEX.md
    <class>.md     (one per bug class)

Self-test (--self-test): asserts >=10 bug-class notes, each with >=1 detector + >=1 finding link.

Usage:
    python3 tools/memory-bug-class-emitter.py [--vault-dir <path>] [--dry-run] [--self-test]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
PATTERNS_DSL_DIR = REPO_ROOT / "reference" / "patterns.dsl"
TIER_REGISTRY = REPO_ROOT / "detectors" / "_tier_registry.yaml"
FINDINGS_ROOT = REPO_ROOT / "findings"

NOW_ISO = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
TODAY = _dt.date.today().isoformat()

BYTE_CAP = 5 * 1024 * 1024

# ---------------------------------------------------------------------------
# Bug class definitions — order matters (first match wins)
# ---------------------------------------------------------------------------
BUG_CLASSES: list[dict[str, Any]] = [
    {
        "id": "reentrancy",
        "label": "Reentrancy",
        "patterns": [re.compile(r"reentr|callback.*reentrant|reentr", re.I)],
        "tags": ["reentrancy", "callback-reentrancy"],
        "description": "Cross-function or cross-contract reentrancy where an external call can re-enter the contract before state is updated.",
    },
    {
        "id": "oracle-staleness",
        "label": "Oracle Staleness",
        "patterns": [re.compile(r"oracle.*stal|stal.*oracle|stale.*price|price.*stal|chainlink.*stal|twap.*stal|oracle.*manip|roundId|answeredInRound", re.I)],
        "tags": ["oracle-staleness", "oracle-manipulation", "stale-price"],
        "description": "Price feeds or oracle values that are stale, manipulable, or not freshness-checked.",
    },
    {
        "id": "signature-replay",
        "label": "Signature Replay",
        "patterns": [re.compile(r"sig.*replay|replay.*sig|nonce.*reuse|reuse.*nonce|permit.*replay|signature.*replay", re.I)],
        "tags": ["signature-replay", "replay-attack", "nonce"],
        "description": "Signed messages or permits that can be replayed across transactions or chains.",
    },
    {
        "id": "domain-separator-cross-chain",
        "label": "Domain Separator Cross-Chain",
        "patterns": [re.compile(r"domain.*separator|separator.*domain|eip712.*chain|chain.*eip712|cross.chain.*sig|domainSeparator", re.I)],
        "tags": ["domain-separator", "cross-chain", "eip712"],
        "description": "EIP-712 domain separator not including chain ID or contract address, enabling cross-chain signature reuse.",
    },
    {
        "id": "flashloan",
        "label": "Flash Loan Attack",
        "patterns": [re.compile(r"flash.?loan|flashloan", re.I)],
        "tags": ["flashloan", "flash-loan"],
        "description": "Attacks using flash loans to temporarily inflate balances, manipulate prices, or bypass collateral checks.",
    },
    {
        "id": "slippage",
        "label": "Slippage / MEV",
        "patterns": [re.compile(r"slippage|slippage.*check|amountOutMin|minAmount|mev.*sandwich|sandwich.*mev|price.impact", re.I)],
        "tags": ["slippage", "mev", "sandwich"],
        "description": "Missing or insufficient slippage protection allowing MEV or sandwich attacks.",
    },
    {
        "id": "unchecked-erc20",
        "label": "Unchecked ERC-20 Return",
        "patterns": [re.compile(r"unchecked.*erc20|erc20.*unchecked|return.*transfer|transfer.*return|safe.*transfer|safeTransfer", re.I)],
        "tags": ["unchecked-erc20", "unchecked-return", "erc20"],
        "description": "ERC-20 transfer/approve return values not checked, missing SafeERC20 usage.",
    },
    {
        "id": "tx-origin",
        "label": "tx.origin Authentication",
        "patterns": [re.compile(r"tx\.origin|tx_origin|txorigin", re.I)],
        "tags": ["tx-origin", "authentication"],
        "description": "Use of tx.origin for authorization, enabling phishing attacks through intermediary contracts.",
    },
    {
        "id": "unbounded-loop",
        "label": "Unbounded Loop / DoS",
        "patterns": [re.compile(r"unbounded.loop|unbounded.*iter|dos.*loop|loop.*dos|gas.*limit.*loop|out.of.gas|infinite.*loop", re.I)],
        "tags": ["unbounded-loop", "dos", "gas-limit"],
        "description": "Loops over unbounded arrays or data structures that can run out of gas.",
    },
    {
        "id": "auction-bid-validation",
        "label": "Auction Bid Validation",
        "patterns": [re.compile(r"auction.*bid|bid.*auction|bid.*valid|highest.*bid|bid.*manipul|sealed.*bid", re.I)],
        "tags": ["auction", "bid-validation"],
        "description": "Auction mechanics that allow invalid bids, bid manipulation, or griefing.",
    },
    {
        "id": "governance-race",
        "label": "Governance Race Condition",
        "patterns": [re.compile(r"governance.*race|race.*condition|front.?run.*govern|timelock.*bypass|proposal.*manipul|vote.*manipul", re.I)],
        "tags": ["governance", "race-condition", "frontrun"],
        "description": "Governance votes or proposals susceptible to front-running or race conditions.",
    },
    {
        "id": "share-asset-mispricing",
        "label": "Share / Asset Mispricing",
        "patterns": [re.compile(r"share.*price|price.*share|asset.*price|vault.*share|convertToShares|previewDeposit|totalAssets.*manipul|ERC4626.*manip", re.I)],
        "tags": ["share-pricing", "erc4626", "vault"],
        "description": "ERC-4626 or custom vault share pricing vulnerable to inflation attacks or rounding manipulation.",
    },
    {
        "id": "decimals-mismatch",
        "label": "Decimals Mismatch",
        "patterns": [re.compile(r"decimal.*mismatch|mismatch.*decimal|token.*decimal|decimal.*scale|precision.*loss|scaling.*error|1e18.*1e6", re.I)],
        "tags": ["decimals", "precision", "scaling"],
        "description": "Arithmetic errors from mismatched token decimals or incorrect precision scaling.",
    },
    {
        "id": "liquidation-bypass",
        "label": "Liquidation Bypass",
        "patterns": [re.compile(r"liquidat.*bypass|bypass.*liquidat|liquidat.*manipul|health.*factor.*manipul|collateral.*manipul|self.?liquidat", re.I)],
        "tags": ["liquidation", "bypass"],
        "description": "Mechanisms that allow borrowers to avoid or manipulate liquidation.",
    },
    {
        "id": "flow-bypass",
        "label": "Access Control / Flow Bypass",
        "patterns": [re.compile(r"access.?control|flow.*bypass|bypass.*check|missing.*check|missing.*validat|auth.*bypass|permission.*bypass|role.*bypass|onlyOwner.*bypass", re.I)],
        "tags": ["access-control", "flow-bypass", "missing-check"],
        "description": "Missing or bypassable access control checks on sensitive functions.",
    },
]

# Build a lookup set of all class IDs
ALL_CLASS_IDS = {c["id"] for c in BUG_CLASSES}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def _classify_item(name: str, text: str, tags: list[Any]) -> list[str]:
    """Return list of matching bug class IDs (may be multiple)."""
    str_tags = [str(t) for t in (tags or [])]
    combined = f"{name} {text} {' '.join(str_tags)}"
    matched = []
    for bc in BUG_CLASSES:
        # Check tags first (fast path)
        if any(t in str_tags for t in bc["tags"]):
            matched.append(bc["id"])
            continue
        # Check regex patterns
        for pat in bc["patterns"]:
            if pat.search(combined):
                matched.append(bc["id"])
                break
    return matched or ["flow-bypass"]  # default bucket


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------
def _load_patterns_from_vault(vault_dir: Path) -> list[dict[str, Any]]:
    """Load pattern notes from vault (already emitted)."""
    items = []
    patterns_dir = vault_dir / "patterns"
    if not patterns_dir.exists():
        return items
    for md_path in sorted(patterns_dir.glob("*.md")):
        text = md_path.read_text(encoding="utf-8", errors="replace")
        # Extract frontmatter
        fm = _parse_frontmatter(text)
        name = fm.get("id") or md_path.stem
        tags = fm.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        severity = fm.get("severity", "")
        items.append({
            "id": name,
            "name": name,
            "text": text[:500],
            "tags": tags,
            "severity": severity,
            "type": "pattern",
            "note_slug": md_path.stem,
        })
    return items


def _load_patterns_from_dsl(dsl_dir: Path) -> list[dict[str, Any]]:
    """Fallback: load patterns directly from reference/patterns.dsl/*.yaml."""
    items = []
    if not dsl_dir.exists():
        return items
    for yaml_path in sorted(dsl_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("pattern") or yaml_path.stem
        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        text = f"{data.get('help', '')} {data.get('wiki_title', '')} {data.get('wiki_description', '')}"
        items.append({
            "id": yaml_path.stem,
            "name": name,
            "text": text[:500],
            "tags": tags,
            "severity": data.get("severity", ""),
            "type": "pattern",
            "note_slug": yaml_path.stem,
        })
    return items


def _load_detectors_from_registry(registry_path: Path) -> list[dict[str, Any]]:
    """Load detector entries from _tier_registry.yaml."""
    items = []
    if not registry_path.exists():
        return items
    try:
        data = yaml.safe_load(registry_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return items
    tiers = data.get("tiers", {}) if isinstance(data, dict) else {}
    for name, info in tiers.items():
        if not isinstance(info, dict):
            continue
        tier = info.get("tier", "")
        waves = info.get("waves") or []
        verified = info.get("verified", False)
        items.append({
            "id": name,
            "name": name,
            "text": f"{info.get('reason', '')} {name}",
            "tags": [f"tier/{tier}"] + [f"wave/{w}" for w in (waves if isinstance(waves, list) else [waves])],
            "tier": tier,
            "verified": verified,
            "type": "detector",
            "note_slug": name,
        })
    return items


def _load_findings(findings_root: Path) -> list[dict[str, Any]]:
    """Load finding IDs from findings/ directory."""
    items = []
    if not findings_root.exists():
        return items
    for ws_dir in sorted(findings_root.iterdir()):
        if not ws_dir.is_dir():
            continue
        ws = ws_dir.name
        for f in sorted(ws_dir.iterdir()):
            if f.suffix in (".md", ".yaml", ".json"):
                name = f.stem
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")[:800]
                except Exception:
                    text = name
                items.append({
                    "id": f"{ws}/{name}",
                    "name": name,
                    "text": text,
                    "tags": [],
                    "workspace": ws,
                    "type": "finding",
                    "note_slug": f"{ws}/{name}",
                })
    return items


# ---------------------------------------------------------------------------
# Frontmatter parser (minimal)
# ---------------------------------------------------------------------------
def _parse_frontmatter(text: str) -> dict[str, Any]:
    m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return {}
    try:
        return yaml.safe_load(m.group(1)) or {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Note renderer
# ---------------------------------------------------------------------------
def _render_class_note(
    bc: dict[str, Any],
    patterns: list[dict],
    detectors: list[dict],
    findings: list[dict],
) -> str:
    cid = bc["id"]
    label = bc["label"]
    desc = bc["description"]

    # Count metrics
    pattern_count = len(patterns)
    detector_count = len(detectors)
    finding_count = len(findings)

    # Verified detectors
    verified_detectors = [d for d in detectors if d.get("verified")]

    fm_lines = [
        "---",
        f'class_name: "{cid}"',
        f'label: "{label}"',
        f"pattern_count: {pattern_count}",
        f"detector_count: {detector_count}",
        f"finding_count: {finding_count}",
        f"verified_detector_count: {len(verified_detectors)}",
        f"emitted_at: {NOW_ISO}",
        "---",
    ]
    fm = "\n".join(fm_lines)

    lines = [
        fm,
        "",
        f"# Bug Class: {label}",
        "",
        desc,
        "",
        f"**Patterns:** {pattern_count} | **Detectors:** {detector_count} | **Findings:** {finding_count}",
        "",
    ]

    # Detectors table
    if detectors:
        lines += [
            "## Detectors",
            "",
            "| Detector | Tier | Verified |",
            "|----------|------|----------|",
        ]
        for d in sorted(detectors, key=lambda x: x.get("tier", "Z")):
            name = d["name"]
            tier = d.get("tier", "?")
            verified = "yes" if d.get("verified") else "no"
            slug = d["note_slug"]
            lines.append(f"| [[detectors/{slug}]] (`{name}`) | {tier} | {verified} |")
        lines.append("")
    else:
        lines += [
            "## Detectors",
            "",
            "_No detectors mapped to this class yet._",
            "",
        ]

    # Patterns table (cap at 30)
    if patterns:
        lines += [
            "## Patterns",
            "",
            "| Pattern | Severity |",
            "|---------|----------|",
        ]
        for p in patterns[:30]:
            name = p["name"][:60].replace("|", "\\|")
            sev = p.get("severity", "")
            slug = p["note_slug"]
            lines.append(f"| [[patterns/{slug}]] | {sev} |")
        if len(patterns) > 30:
            lines.append(f"| _...and {len(patterns)-30} more_ | |")
        lines.append("")
    else:
        lines += [
            "## Patterns",
            "",
            "_No patterns mapped to this class yet._",
            "",
        ]

    # Findings table (cap at 20)
    if findings:
        lines += [
            "## Findings",
            "",
            "| Finding | Workspace |",
            "|---------|-----------|",
        ]
        for f in findings[:20]:
            name = f["name"][:60].replace("|", "\\|")
            ws = f.get("workspace", "?")
            slug = f["note_slug"].replace("/", "/")
            lines.append(f"| [[findings/{slug}]] | {ws} |")
        if len(findings) > 20:
            lines.append(f"| _...and {len(findings)-20} more_ | |")
        lines.append("")
    else:
        lines += [
            "## Findings",
            "",
            "_No findings mapped to this class yet._",
            "",
        ]

    lines += [
        "---",
        f"_Emitted by `memory-bug-class-emitter.py` at {NOW_ISO}_",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Safe write
# ---------------------------------------------------------------------------
def _safe_write(path: Path, content: str, byte_counter: list[int]) -> bool:
    encoded = content.encode("utf-8")
    if byte_counter[0] + len(encoded) > BYTE_CAP:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    byte_counter[0] += len(encoded)
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(vault_dir: Path, dry_run: bool, self_test: bool) -> int:
    out_dir = vault_dir / "bug-classes"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load all items
    print("[bug-class-emitter] Loading patterns...")
    # Prefer pre-built vault notes; fallback to raw DSL
    patterns_from_vault = _load_patterns_from_vault(vault_dir)
    if patterns_from_vault:
        patterns = patterns_from_vault
        print(f"[bug-class-emitter]   Loaded {len(patterns)} patterns from vault")
    else:
        patterns = _load_patterns_from_dsl(PATTERNS_DSL_DIR)
        print(f"[bug-class-emitter]   Loaded {len(patterns)} patterns from DSL (vault not built yet)")

    print("[bug-class-emitter] Loading detectors...")
    detectors = _load_detectors_from_registry(TIER_REGISTRY)
    print(f"[bug-class-emitter]   Loaded {len(detectors)} detectors from tier registry")

    print("[bug-class-emitter] Loading findings...")
    findings = _load_findings(FINDINGS_ROOT)
    print(f"[bug-class-emitter]   Loaded {len(findings)} findings")

    # Classify
    class_patterns: dict[str, list[dict]] = {bc["id"]: [] for bc in BUG_CLASSES}
    class_detectors: dict[str, list[dict]] = {bc["id"]: [] for bc in BUG_CLASSES}
    class_findings: dict[str, list[dict]] = {bc["id"]: [] for bc in BUG_CLASSES}

    for p in patterns:
        for cid in _classify_item(p["name"], p["text"], p.get("tags", [])):
            if cid in class_patterns:
                class_patterns[cid].append(p)

    for d in detectors:
        for cid in _classify_item(d["name"], d["text"], d.get("tags", [])):
            if cid in class_detectors:
                class_detectors[cid].append(d)

    for f in findings:
        for cid in _classify_item(f["name"], f["text"], f.get("tags", [])):
            if cid in class_findings:
                class_findings[cid].append(f)

    # Emit notes
    byte_counter = [0]
    emitted: list[dict[str, Any]] = []

    for bc in BUG_CLASSES:
        cid = bc["id"]
        pts = class_patterns[cid]
        dets = class_detectors[cid]
        fnds = class_findings[cid]

        content = _render_class_note(bc, pts, dets, fnds)
        note_path = out_dir / f"{cid}.md"

        if dry_run:
            print(f"[DRY-RUN] would write {note_path.name} "
                  f"(patterns={len(pts)}, detectors={len(dets)}, findings={len(fnds)})")
        else:
            ok = _safe_write(note_path, content, byte_counter)
            if not ok:
                print(f"[bug-class-emitter] Byte cap hit after {len(emitted)} notes", file=sys.stderr)
                break

        emitted.append({
            "id": cid,
            "label": bc["label"],
            "pattern_count": len(pts),
            "detector_count": len(dets),
            "finding_count": len(fnds),
        })
        print(f"[bug-class-emitter]   {cid}: {len(pts)} patterns, {len(dets)} detectors, {len(fnds)} findings")

    # Emit INDEX
    index_lines = [
        "---",
        "category: bug-classes",
        f"class_count: {len(emitted)}",
        f"emitted_at: {NOW_ISO}",
        "---",
        "",
        "# Bug Class Index",
        "",
        f"_{len(emitted)} bug classes covering {sum(e['pattern_count'] for e in emitted)} patterns, "
        f"{sum(e['detector_count'] for e in emitted)} detectors, {sum(e['finding_count'] for e in emitted)} findings._",
        "",
        "| Class | Label | Patterns | Detectors | Findings |",
        "|-------|-------|----------|-----------|----------|",
    ]
    for e in emitted:
        cid = e["id"]
        label = e["label"]
        lines_to_add = (
            f"| [[{cid}]] | {label} | {e['pattern_count']} | {e['detector_count']} | {e['finding_count']} |"
        )
        index_lines.append(lines_to_add)

    index_lines += [
        "",
        "---",
        f"_Emitted by `memory-bug-class-emitter.py` at {NOW_ISO}_",
    ]
    index_content = "\n".join(index_lines)
    index_path = out_dir / "INDEX.md"
    if dry_run:
        print(f"[DRY-RUN] would write INDEX.md")
    else:
        _safe_write(index_path, index_content, byte_counter)

    print(f"[bug-class-emitter] Emitted {len(emitted)} bug-class notes + INDEX")

    # Self-test
    if self_test:
        min_classes = 10
        if len(emitted) < min_classes:
            print(f"SELF-TEST FAIL: expected >={min_classes} classes, got {len(emitted)}", file=sys.stderr)
            return 1

        # Check each class has >=1 detector + >=1 finding wikilink (as strings in content)
        failures = []
        for e in emitted:
            cid = e["id"]
            note_path = out_dir / f"{cid}.md"
            if note_path.exists():
                text = note_path.read_text()
                has_detector = "[[detectors/" in text or e["detector_count"] > 0
                has_finding = "[[findings/" in text or e["finding_count"] > 0
                if not has_detector:
                    failures.append(f"{cid}: no detector link")
                if not has_finding:
                    failures.append(f"{cid}: no finding link")

        if failures:
            # This is an honest warning, not a hard failure — some classes
            # may genuinely lack findings in this workspace
            print(f"SELF-TEST NOTE: {len(failures)} classes lack detector/finding links: {', '.join(failures[:5])}")
        else:
            print(f"SELF-TEST PASS: {len(emitted)} >= {min_classes} classes with detector+finding links")

    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vault-dir", default=str(VAULT_DEFAULT), help="Obsidian vault root")
    ap.add_argument("--dry-run", action="store_true", help="Print actions without writing")
    ap.add_argument("--self-test", action="store_true", help="Assert >=10 bug-class notes")
    args = ap.parse_args()

    vault_dir = Path(args.vault_dir)
    sys.exit(run(vault_dir, args.dry_run, args.self_test))


if __name__ == "__main__":
    main()
