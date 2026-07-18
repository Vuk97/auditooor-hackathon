#!/usr/bin/env python3
"""
detector-blindspot-scan.py — find what our current detector pack MISSES.

Queries Solodit for accepted High/Critical Solidity findings, checks out each
disclosed source file at the vulnerable commit, runs ALL Tier-A/B/S/E Slither
detectors against it, and records which pattern classes are never caught.

Usage:
    python3.13 tools/detector-blindspot-scan.py --data <findings.json> [--max-findings N]
    python3.13 tools/detector-blindspot-scan.py --data /tmp/solodit.json --max-findings 10
    python3.13 tools/detector-blindspot-scan.py --data /tmp/solodit.json --max-findings 100

Outputs:
    reports/detector_gap.json                          — machine-readable rows
    docs/DETECTOR_GAP_REPORT_<date>.md                 — human-readable report

Design notes:
- Solodit MCP: findings are pre-fetched by the Claude environment and passed via --data.
- Slither: uses python3.13 which has slither-analyzer installed.
- Sparse checkout: uses git sparse-checkout at the finding's commit+path.
- Pattern classification: keyword-overlap against BUG_CLASSES taxonomy.
- Exponential backoff: retries Solodit queries up to 3 times on failure.
- Cost cap: stops after --max-findings; reports estimated cost.

Architecture:
    1. load_findings()        — load pre-fetched Solodit findings from JSON
    2. checkout_source()      — git sparse-checkout / curl raw vulnerable file
    3. run_detectors()        — run_custom.py --tier=ALL against checked-out file
    4. classify_miss()        — map finding text to bug class via BUG_CLASSES
    5. aggregate()            — group misses by pattern class
    6. emit_reports()         — write JSON + Markdown
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import io
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Optional

# ── repo layout ────────────────────────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent
DETECTORS_RUN = REPO / "detectors" / "run_custom.py"
REPORTS_DIR = REPO / "reports"
DOCS_DIR = REPO / "docs"
PYTHON = "python3.13"  # version that has slither-analyzer installed

LOG = logging.getLogger("blindspot")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
_SOURCE_REF_MANIFEST_MODULE = None

# ── bug-class taxonomy ────────────────────────────────────────────────────────
BUG_CLASSES: dict[str, list[str]] = {
    "reentrancy": [
        "reentran", "nonreentrant", "reentr", "external call before state",
        "cei violation", "lack.*nonreentrant", "reentrancy on",
    ],
    "access-control": [
        "access control", "unauthorized", "not restricted", "no.*restrict",
        "permissionless", "anyone can call", "public.*mint", "unrestricted",
        "lack.*access", "missing.*role", "missing.*auth", "not.*protected",
        "anyone can", "missing onlyowner", "unguarded",
    ],
    "input-validation": [
        "missing\\s+debt\\s+validation",
        "fails?\\s+to\\s+validate(?:\\s+\\w+){0,8}\\s+(?:debt|burn)",
        "does\\s+not\\s+validate(?:\\s+\\w+){0,8}\\s+(?:debt|burn)",
        "missing\\s+validation(?:\\s+\\w+){0,8}\\s+address",
        "guard\\s+is\\s+missing\\s+validation(?:\\s+\\w+){0,8}\\s+address",
        "insufficient\\s+input\\s+validation",
        "invalid\\s+input",
        "zero[- ]address",
    ],
    "arithmetic": [
        "overflow", "underflow", "precision", "rounding", "division before mult",
        "truncat", "wrong math", "incorrect.*calcul", "calculation.*incorrect",
        "math error", "formula.*wrong", "arithmetic", "wrong.*formula",
        "off.by.one", "incorrect.*formula",
    ],
    "oracle": [
        "oracle", "price.*manipulat", "stale price", "stale.*oracle", "price feed",
        "manipulation.*price", "manipulate.*price", "keeper.*price",
        "lp.*priced wrong", "incorrect.*price",
    ],
    "signature-auth": [
        "signature replay", "replay attack", "ecrecover", "eip712",
        "domain separator", "nonce.*missing", "partial.*signature",
        "chained.*signature", "sig.*replay",
    ],
    "storage-memory-mismatch": [
        "not persisted", "memory.*storage", "not stored.*storage", "only in memory",
        "memory copy", "written.*memory", "prevorderid", "library.*memory",
    ],
    "dos": [
        "denial of service", "griefing", "locked.*fund", "freeze.*fund",
        "unbounded loop", "revert.*always", "always.*revert", "\\bdos\\b",
        "fail.*always", "permanent.*freeze",
    ],
    "flashloan": [
        "flashloan", "flash loan", "flash.*protection", "flash action",
        "flash.*insufficient",
    ],
    "slippage": [
        "slippage", "sandwich attack", "missing.*slippage", "no.*slippage",
        "min.*amount.*out", "susceptible.*sandwich", "susceptible.*mev",
        "min-out.*missing",
    ],
    "first-depositor-inflation": [
        "inflation attack", "first deposit", "first depositor", "share.*inflat",
        "inflat.*share", "inflate.*share", "share.*price.*inflation",
        "steal.*first deposit",
    ],
    "fee-accounting": [
        "fee.*not.*account", "incorrect.*fee", "fee.*incorrect", "reward.*wrong",
        "incorrect.*accounting", "wrong.*accounting", "accounting.*incorrect",
        "fee.*calculation.*wrong", "incorrect.*reward", "stale.*balance",
        "missing.*fee", "misallocate", "overcharg", "double.*claim",
        "reward.*manipulation", "stale.*total",
    ],
    "cross-chain": [
        "cross.*chain", "from_chain", "chainid.*missing", "chain.*id.*not",
        "bridge.*stuck", "bridge.*token.*lost", "1-way.*bridge",
    ],
    "yield-vault-collateral-excluded-from-liquidation-seizure": [
        "gamma\\s+vaults?.*not\\s+considered\\s+during\\s+liquidation",
        "collateral\\s+deposited\\s+to\\s+gamma\\s+vaults?.*liquidation",
        "vault\\s+collateral.*counted.*health.*omitted.*liquidation",
        "yield\\s+vault\\s+collateral.*excluded.*liquidation",
    ],
    "perps-partial-position-decrease-pnl-fee-value-flow-mismatch": [
        "decreasing\\s+position\\s+size\\s+via\\s+leverage\\s+update",
        "decrease\\s+position\\s+size\\s+using\\s+leverage\\s+update",
        "handletradepnl.*closing\\s+fee",
        "partial\\s+profit/loss.*position\\s+size\\s+delta",
        "collateralsenttotrader",
    ],
    "exogenous-collateral-liquidation-eligibility-check-missing": [
        "missing\\s+enough\\s+exogenous\\s+collateral\\s+check",
        "insufficient\\s+exogenous\\s+collateral\\s+check",
        "exogenous\\s+collateral.*liquidat",
        "non[- ]kerosene.*collateral.*liquidat",
    ],
    "liquidation": [
        "liquidation.*fail", "cannot liquidat", "prevent.*liquidat",
        "block.*liquidat", "liquidation.*block", "liquidation.*dos",
        "lack.*liquidity.*liquidat", "no.*incentive.*liquidat",
        "liquidation.*revert", "liquidat.*always.*fail", "mix.*liquidat",
    ],
    "logic-error-flow-bypass": [
        "never set", "never increased", "never updated", "state.*not updated",
        "missing.*update", "variable.*never", "always.*null",
        "bypass.*lock", "bypass.*deregister", "bypass.*flow",
        "withdraw.*without.*deregist",
    ],
    "token-attribute-type-parameter-not-bound-to-owned-token": [
        "reroll\\s+with\\s+(?:a\\s+)?different\\s+fightertype",
        "fightertype.*bypass(?:ing)?\\s+maxrerollsallowed",
        "fightertype.*nft\\s+you\\s+own",
        "caller[- ]supplied\\s+type.*stored\\s+token",
        "type/category\\s+parameter.*owned\\s+token",
    ],
    "governance-attack": [
        "51.*attack", "51%.*majority", "governance.*hijack",
        "arbitrary.*call.*proposal", "majority.*hijack",
    ],
    "self-transfer-no-check": [
        "self-transfer", "self.*transfer.*exploit", "from.*to.*same",
        "from.*==.*to.*missing", "infinite.*points.*transfer",
    ],
    "bridge": [
        "bridge.*erc721", "bridge.*stuck", "bridge.*token.*lost",
        "bridgetoken.*allow", "bridge.*rebalance.*missing", "1-way.*bridge",
    ],
    "erc-standard": [
        "fee.*on.*transfer", "fee-on-transfer", "non.*compatible.*contract",
        "codehash.*check", "non.existent.*token.*check",
        "safeTransferFrom.*no.*code",
    ],
    "auction-bid-validation-missing": [
        "highest.*bidder.*withdraw", "bidder.*cancel", "bid.*missing.*check",
        "auction.*cancel.*no.*check",
    ],
    "l2-dispute-block-number": [
        "disputed.*l2.*block", "l2.*block.*number.*invalid",
        "l2_block_number.*wrong",
    ],
    "economic-design": [
        "no.*incentive.*liquidat", "economic.*design", "gas.*cost.*exceed",
        "liquidation.*unprofitable",
    ],
}

ACTIVE_TIERS = {"S", "E", "A"}
SEVERITY_WEIGHT = {"CRITICAL": 2.0, "HIGH": 1.0, "MEDIUM": 0.5}

# GitHub URL patterns.
#
# Solodit raw and draft text mixes commit-pinned links with named refs such as
# `blob/main/...`.  Named refs are not as replay-ready as immutable commits, but
# they are still useful source locators and can be fetched by the raw GitHub URL
# path used below.
GH_SOURCE_RE = re.compile(
    r"https?://github\.com/"
    r"(?P<repo>[^/\s#\"'\)<>]+/[^/\s#\"'\)<>]+)"
    r"/(?:blob|tree|raw)/"
    r"(?P<ref>[^/\s#\"'\)<>]+)"
    r"/(?P<filepath>[^\s#\"'\)<>]+?\.sol)"
)
GH_RAW_SOURCE_RE = re.compile(
    r"https?://raw\.githubusercontent\.com/"
    r"(?P<repo>[^/\s#\"'\)<>]+/[^/\s#\"'\)<>]+)"
    r"/(?P<ref>[^/\s#\"'\)<>]+)"
    r"/(?P<filepath>[^\s#\"'\)<>]+?\.sol)"
)


def parse_tier_filter(tier_filter: str) -> set[str]:
    tiers = {item.strip().upper() for item in tier_filter.split(",") if item.strip()}
    if not tiers or "ALL" in tiers:
        return set()
    return tiers


def tier_matches_filter(tier: str, allowed_tiers: set[str]) -> bool:
    return not allowed_tiers or tier.upper() in allowed_tiers


def classify_finding(title: str, content: str, tags: list[str]) -> str:
    """Classify a finding into a bug class using regex keyword overlap."""
    text = f"{title} {content} {' '.join(tags)}".lower()
    best = ("uncategorized", 0)
    for cls, patterns in BUG_CLASSES.items():
        score = 0
        for p in patterns:
            if re.search(p, text):
                score += 2 if re.search(p, title.lower()) else 1
        if score > best[1]:
            best = (cls, score)
    return best[0]


def extract_github_refs(content: str) -> list[dict]:
    """Extract GitHub source URLs with repo+ref+path from finding content."""
    refs = []
    seen: set[tuple] = set()
    for pattern in (GH_SOURCE_RE, GH_RAW_SOURCE_RE):
        for m in pattern.finditer(content):
            repo = m.group("repo")
            commit = m.group("ref")
            filepath = m.group("filepath")
            key = (repo, commit, filepath)
            if key in seen:
                continue
            seen.add(key)
            ref_type = (
                "commit"
                if re.fullmatch(r"[0-9a-f]{7,40}", commit)
                else "named_ref"
            )
            refs.append({
                "repo": repo,
                "commit": commit,
                "ref_type": ref_type,
                "filepath": filepath,
                "url": m.group(0),
            })
    return refs


def sparse_checkout(repo: str, commit: str, filepath: str,
                    dest_dir: Path, timeout: int = 60) -> Optional[Path]:
    """
    Try to fetch a single .sol file at a specific commit.
    Strategy 1: git archive (SSH-capable remotes only, often blocked).
    Strategy 2: raw GitHub curl download.
    Strategy 3: shallow sparse clone (last resort, slow).
    Returns checked-out path or None.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_file = dest_dir / Path(filepath).name

    # Strategy 2 (fastest for public repos): raw GitHub download
    try:
        raw_url = (f"https://raw.githubusercontent.com/"
                   f"{repo}/{commit}/{filepath}")
        result = subprocess.run(
            ["curl", "-fsSL", "--max-time", "25", raw_url],
            capture_output=True, timeout=35
        )
        if (result.returncode == 0 and result.stdout
                and b"404" not in result.stdout[:20]
                and b"Not Found" not in result.stdout[:50]):
            out_file.write_bytes(result.stdout)
            LOG.debug("curl raw ok: %s", out_file)
            return out_file
    except Exception:
        pass

    # Strategy 1: git archive
    try:
        clone_url = f"https://github.com/{repo}.git"
        result = subprocess.run(
            ["git", "archive", f"--remote={clone_url}", commit, filepath],
            capture_output=True, timeout=timeout
        )
        if result.returncode == 0 and result.stdout:
            with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".sol"):
                        f = tar.extractfile(member)
                        if f:
                            out_file.write_bytes(f.read())
                            return out_file
    except Exception:
        pass

    return None


def run_detectors_on_file(sol_file: Path, tier: str = "S,E,A,B") -> dict[str, bool]:
    """
    Run run_custom.py --tier=<tier> against sol_file.
    Returns dict: detector_argument -> fired(bool).
    """
    results: dict[str, bool] = {}
    try:
        proc = subprocess.run(
            [PYTHON, str(DETECTORS_RUN), f"--tier={tier}", str(sol_file)],
            capture_output=True, text=True, timeout=180, cwd=str(REPO)
        )
        stdout = proc.stdout + proc.stderr
        current_det: Optional[str] = None
        for line in stdout.splitlines():
            m = re.match(r"=== Running (\S+) ===", line)
            if m:
                current_det = m.group(1)
                if current_det not in results:
                    results[current_det] = False
            elif current_det and re.match(r"\s+\[", line):
                results[current_det] = True
    except subprocess.TimeoutExpired:
        LOG.warning("detector run timed out on %s", sol_file)
    except Exception as e:
        LOG.warning("detector run failed on %s: %s", sol_file, e)
    return results


def load_detector_help(detectors_dir: Path) -> dict[str, tuple[str, str]]:
    """Load detector ARGUMENT -> (tier, HELP) mapping from the detector library."""
    import importlib.util
    import inspect
    sys.path.insert(0, str(REPO))
    sys.path.insert(0, "/opt/homebrew/lib/python3.13/site-packages")
    try:
        from slither.detectors.abstract_detector import AbstractDetector
    except ImportError:
        AbstractDetector = None

    tier_registry: dict[str, str] = {}
    reg_path = detectors_dir / "_tier_registry.yaml"
    if reg_path.exists():
        try:
            import yaml
            data = yaml.safe_load(reg_path.read_text()) or {}
            tier_registry = {k: v.get("tier", "D")
                             for k, v in data.get("tiers", {}).items()}
        except Exception:
            pass

    detector_help: dict[str, tuple[str, str]] = {}
    det_files = (list(detectors_dir.glob("*.py")) +
                 list(detectors_dir.glob("wave*/*.py")))
    for py_file in det_files:
        if py_file.name.startswith("_") or py_file.name == "run_custom.py":
            continue
        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if AbstractDetector:
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if obj is AbstractDetector or not issubclass(obj, AbstractDetector):
                        continue
                    arg = getattr(obj, "ARGUMENT", py_file.stem)
                    tier = tier_registry.get(arg, "D")
                    help_text = getattr(obj, "HELP", "") or ""
                    detector_help[arg] = (tier, help_text)
        except Exception:
            pass
    return detector_help


# Keyword mapping: bug class -> detector ARGUMENT keywords that cover it
CLASS_DETECTOR_KEYWORDS: dict[str, list[str]] = {
    "reentrancy": ["reentran", "reentr", "nonreentrant", "callback", "cei"],
    "access-control": ["role", "auth", "owner", "privileg", "access", "permission",
                       "operator", "onlyowner"],
    "arithmetic": ["overflow", "underflow", "precision", "rounding", "div", "mul",
                   "decimal", "truncat", "arithmetic", "unsafe-uint"],
    "oracle": ["oracle", "twap", "price", "staleness", "stale", "chainlink", "feed"],
    "signature-auth": ["signature", "sig", "replay", "nonce", "ecrecover",
                       "eip712", "domain", "multisig"],
    "storage-memory-mismatch": ["storage", "memory", "writeback", "persist",
                                "library-memory"],
    "dos": ["dos", "unbounded", "lock", "grief", "loop", "iteration", "gas",
            "vesting-dos"],
    "flashloan": ["flash"],
    "slippage": ["slippage", "sandwich", "min-out", "min-amount"],
    "first-depositor-inflation": ["first-deposit", "first-depositor", "inflation",
                                  "share", "vault", "erc4626"],
    "fee-accounting": ["fee", "reward", "interest", "accrual", "yield", "credit",
                       "claiming", "refund", "protocol-fee"],
    "cross-chain": ["cross-chain", "l1", "l2", "bridge", "chain-id", "chainid"],
    "liquidation": ["liquidat", "health"],
    "missing-check": ["missing", "zero-address", "check", "validation", "input"],
    "logic-error-flow-bypass": ["state", "flow", "bypass", "logic"],
    "governance-attack": ["governance", "proposal", "quorum", "vote"],
    "self-transfer-no-check": ["self-transfer", "from-to"],
    "bridge": ["bridge", "cross"],
    "erc-standard": ["erc20", "erc721", "erc1155", "erc4626", "erc777",
                     "fee-on-transfer"],
    "auction-bid-validation-missing": ["auction", "bid"],
    "l2-dispute-block-number": ["l2", "dispute"],
    "economic-design": ["economic", "incentive"],
}


def detectors_cover_class(
        bug_class: str,
        detector_help: dict[str, tuple[str, str]],
        tier_filter: str = "S,E,A,B") -> list[str]:
    """Return requested-tier detector arguments that keyword-cover this bug class."""
    kws = CLASS_DETECTOR_KEYWORDS.get(bug_class, [])
    if not kws:
        return []
    allowed_tiers = parse_tier_filter(tier_filter)
    covered = []
    for arg, (tier, _) in detector_help.items():
        if not tier_matches_filter(tier, allowed_tiers):
            continue
        if any(kw in arg.lower() for kw in kws):
            covered.append(arg)
    return covered


def normalize_finding(raw: dict) -> dict:
    """Normalize a Solodit API result to our internal schema."""
    content = raw.get("content") or raw.get("description") or ""
    solodit_url = raw.get("solodit_url") or raw.get("url") or ""
    tags = raw.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return {
        "id": str(raw.get("id") or raw.get("finding_id") or "?"),
        "title": raw.get("title") or "",
        "content": content,
        "tags": tags,
        "severity": (raw.get("severity") or "HIGH").upper(),
        "solodit_url": solodit_url,
        "firm": raw.get("firm") or "",
        "protocol": raw.get("protocol") or "",
    }


def load_source_ref_manifest_module():
    """Load the hyphenated source-ref manifest helper lazily."""
    global _SOURCE_REF_MANIFEST_MODULE
    if _SOURCE_REF_MANIFEST_MODULE is not None:
        return _SOURCE_REF_MANIFEST_MODULE
    tool = REPO / "tools" / "source-ref-replay-manifest.py"
    spec = importlib.util.spec_from_file_location("source_ref_replay_manifest", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _SOURCE_REF_MANIFEST_MODULE = module
    return module


def default_source_ref_manifest_path(out_json: Path) -> Path:
    return out_json.with_name(f"{out_json.stem}_source_ref_replay_manifest.json")


def emit_source_ref_replay_manifest(
    findings: list[dict],
    out_path: Path,
    *,
    named_ref_lockfile: Path | None = None,
    local_source_root: Path | None = None,
    local_proof: Path | None = None,
) -> dict:
    """Emit the offline replay manifest from the same findings used for the gap report."""
    module = load_source_ref_manifest_module()
    manifest = module.build_manifest(
        findings,
        source_root=local_source_root,
        named_ref_locks=module.load_named_ref_lockfile(named_ref_lockfile),
        local_proofs=module.load_local_proofs(local_proof),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.info("wrote source-ref replay manifest: %s", out_path)
    return manifest


def source_ref_preservation_guard(rows: list[dict], manifest: dict) -> dict:
    """Fail closed if manifest-visible source refs would be lost in detector_gap rows."""
    return load_source_ref_manifest_module().detector_gap_source_ref_guard(rows, manifest)


def enforce_source_ref_preservation(rows: list[dict], manifest: dict) -> dict:
    return load_source_ref_manifest_module().enforce_detector_gap_source_refs(rows, manifest)


def apply_source_ref_manifest_to_rows(rows: list[dict], manifest: dict) -> dict:
    """Hydrate detector rows with manifest-backed source refs before reporting."""
    return load_source_ref_manifest_module().apply_manifest_github_refs(rows, manifest)


def analyze_finding(finding: dict, detector_help: dict,
                    scratch_dir: Path, tier: str) -> dict:
    """Full pipeline for one finding: classify → checkout → run detectors."""
    fid = finding.get("id", "?")
    title = finding.get("title", "")
    content = finding.get("content", "")
    tags = finding.get("tags", [])
    severity = finding.get("severity", "HIGH")
    solodit_url = finding.get("solodit_url", "")
    refs = extract_github_refs(content)
    used_ref: Optional[dict] = refs[0] if refs else None

    # Skip non-Solidity
    if ("Shardeum" in finding.get("protocol", "") or
            "Archiver" in title):
        return {
            "finding_id": fid, "title": title, "severity": severity,
            "bug_class": "non-solidity", "solodit_url": solodit_url,
            "status": "skipped_language", "is_blindspot": False,
            "covering_detectors": [], "github_ref": used_ref,
        }

    bug_class = classify_finding(title, content, tags)
    covering_dets = detectors_cover_class(bug_class, detector_help, tier_filter=tier)
    is_blindspot_keyword = (len(covering_dets) == 0)

    # Try to checkout source for Slither run
    sol_file: Optional[Path] = None
    slither_fired: list[str] = []
    slither_run = 0

    if refs:
        for ref in refs[:3]:
            dest = scratch_dir / f"finding_{fid}"
            checked = sparse_checkout(
                ref["repo"], ref["commit"], ref["filepath"], dest
            )
            if checked and checked.exists() and checked.stat().st_size > 50:
                sol_file = checked
                used_ref = ref
                break

        if sol_file is not None:
            det_results = run_detectors_on_file(sol_file, tier=tier)
            slither_run = len(det_results)
            slither_fired = [d for d, hit in det_results.items() if hit]
            # Override keyword analysis with actual Slither result when available
            if slither_run > 0:
                is_blindspot_keyword = (len(slither_fired) == 0)
                if slither_fired:
                    covering_dets = slither_fired

    return {
        "finding_id": fid,
        "title": title,
        "severity": severity,
        "bug_class": bug_class,
        "solodit_url": solodit_url,
        "status": "analyzed",
        "is_blindspot": is_blindspot_keyword,
        "covering_detectors": covering_dets[:5],
        "github_ref": used_ref,
        "detectors_run": slither_run,
        "slither_fired": slither_fired,
        "analysis_mode": "slither" if slither_run > 0 else "keyword-based",
    }


def emit_json_report(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(rows, indent=2))
    LOG.info("wrote JSON report: %s", out_path)


def emit_markdown_report(rows: list[dict], out_path: Path, stats: dict) -> None:
    today = date.today().isoformat()
    tier_label = stats.get("tier", "S,E,A,B")

    analyzed = [r for r in rows if r.get("status") == "analyzed"]
    blindspots = [r for r in analyzed if r.get("is_blindspot")]
    covered = [r for r in analyzed if not r.get("is_blindspot")]
    skipped = [r for r in rows if r.get("status", "").startswith("skipped")]

    class_counts: Counter[str] = Counter(r["bug_class"] for r in blindspots)
    class_weight: dict[str, float] = defaultdict(float)
    class_samples: dict[str, list[dict]] = defaultdict(list)
    for r in blindspots:
        cls = r["bug_class"]
        class_weight[cls] += SEVERITY_WEIGHT.get(r.get("severity", "HIGH"), 1.0)
        class_samples[cls].append(r)

    ranked = sorted(class_counts.keys(),
                    key=lambda c: (class_weight[c], class_counts[c]),
                    reverse=True)

    SUGGESTIONS = {
        "slippage": ("Detector: find DEX swap calls (Uniswap/Curve) where "
                     "`minAmountOut` / `amountOutMin` is 0 or absent."),
        "flashloan": ("Detector: find flash-loan callback entry points "
                      "lacking caller-authorization checks."),
        "logic-error-flow-bypass": ("Detector: find functions gated by a "
                                    "precondition (e.g. 'must deregister first') "
                                    "where a direct-call path skips the gate."),
        "self-transfer-no-check": ("Detector: find `transfer` implementations "
                                   "that do not check `from != to`."),
        "l2-dispute-block-number": ("Detector: find dispute-game contracts where "
                                    "`DISPUTED_L2_BLOCK_NUMBER` is not clamped to "
                                    "the claimed range."),
        "auction-bid-validation-missing": ("Detector: find auction `cancel*` "
                                           "functions that do not verify the "
                                           "caller is not the current highest bidder."),
        "input-validation": ("Manual review needed — split generic input-validation "
                             "hits into source-backed subclasses before writing or "
                             "promoting a detector."),
        "uncategorized": ("Manual review needed — refine BUG_CLASSES taxonomy "
                          "then assign to an existing or new detector class."),
    }

    lines = [
        f"# Detector Blindspot Report — {today}",
        "",
        ("> Auto-generated by `tools/detector-blindspot-scan.py`"),
        ("> Source: Solodit High/Critical Solidity findings (quality-sorted) "
         f"vs. auditooor requested-tier detector pack ({tier_label})."),
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Findings queried | {stats['queried']} |",
        f"| Findings analyzed (Solidity) | {len(analyzed)} |",
        f"| Covered by ≥1 requested-tier detector | {len(covered)} |",
        f"| **Blindspots (0 requested-tier detectors)** | **{len(blindspots)}** |",
        f"| Skipped (non-Solidity) | {stats.get('skipped_language', 0)} |",
        f"| Source checkout success | {stats.get('checkout_ok', 0)} |",
        f"| Source checkout failed/skipped | {stats.get('checkout_skip', 0)} |",
        f"| Source-ref replay manifest rows | {stats.get('source_ref_manifest_rows', 0)} |",
        f"| Source-ref replay manifest | `{stats.get('source_ref_manifest', '')}` |",
        f"| Avg detectors run (Slither) | {stats.get('avg_detectors_run', 0):.1f} |",
        f"| Tier filter | {stats.get('tier', 'S,E,A,B')} |",
        f"| Active detectors ({tier_label}) | {stats.get('active_detectors', 0)} |",
        f"| Total detector pack (all tiers) | {stats.get('total_detectors', 0)} |",
        f"| Analysis mode | {stats.get('mode', 'keyword-based')} |",
        f"| Estimated Solodit MCP cost | ~${stats.get('estimated_cost_usd', 0):.2f} |",
        "",
        "## Top Missed Pattern Classes",
        "",
        "Ordered by `count × severity-weight` (Critical=2.0, High=1.0).",
        "",
        "| Rank | Pattern Class | # Missed | Weight | Sample Findings |",
        "|------|---------------|----------|--------|-----------------|",
    ]

    for i, cls in enumerate(ranked[:20], 1):
        samples = class_samples[cls][:2]
        sample_text = "; ".join(
            f"[{s['title'][:55]}]({s['solodit_url']})" for s in samples
        )
        lines.append(
            f"| {i} | `{cls}` | {class_counts[cls]} | "
            f"{class_weight[cls]:.1f} | {sample_text} |"
        )

    lines += ["", "## Gap Details", ""]
    for cls in ranked[:20]:
        samples = class_samples[cls]
        lines.append(f"### `{cls}` ({class_counts[cls]} missed)")
        lines.append("")
        suggestion = SUGGESTIONS.get(cls,
                                     f"Add a Slither detector targeting `{cls}`.")
        label = "Suggested route" if cls in {"input-validation", "uncategorized"} else "Suggested detector"
        lines.append(f"**{label}:** {suggestion}")
        lines.append("")
        lines.append("**Findings:**")
        for r in samples[:5]:
            sev = r.get("severity", "HIGH")
            lines.append(
                f"- **[{sev}]** [{r['title']}]({r['solodit_url']})"
            )
            if r.get("github_ref"):
                ref = r["github_ref"]
                lines.append(
                    f"  - Source: `{ref.get('repo','?')}@"
                    f"{ref.get('commit','?')[:8]}` `{ref.get('filepath','?')}`"
                )
        lines.append("")

    lines += [
        "## Covered Findings (sample)",
        "",
        "Findings where at least one requested-tier detector argument matched the bug class.",
        "",
    ]
    for r in covered[:12]:
        dets = r.get("covering_detectors", [])
        short_dets = ", ".join(f"`{d}`" for d in dets[:2])
        lines.append(f"- [{r['title'][:70]}]({r['solodit_url']})")
        lines.append(f"  - covered by: {short_dets or '(keyword match)'}")

    lines += [
        "",
        "## Skipped Findings",
        "",
        f"- Non-Solidity (blockchain/DLT): {stats.get('skipped_language', 0)}",
        "",
        "## Methodology",
        "",
        "1. Query Solodit for High/Critical Solidity findings (quality-sorted).",
        "2. Classify each finding into a bug class using regex patterns.",
        "3. Check if any requested-tier detector ARGUMENT keyword overlaps the bug class.",
        "4. For findings with GitHub blob URLs: sparse-checkout file + run Slither.",
        "5. Aggregate blindspots by class; rank by severity weight.",
        "",
        "> **M14-trap**: If 0 blindspots reported, suspect a bug in the analysis.",
        f"> This run found {len(blindspots)} gaps requiring manual review.",
        "",
        f"*Report generated: {today}*",
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    LOG.info("wrote Markdown report: %s", out_path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run detector blindspot scan against Solodit High/Critical findings."
    )
    p.add_argument("--max-findings", type=int, default=100,
                   help="Maximum findings to process (default 100)")
    p.add_argument("--tier", default="S,E,A,B",
                   help="Detector tier filter (default: S,E,A,B)")
    p.add_argument("--data", type=Path, required=True,
                   help="Pre-fetched findings JSON from Solodit MCP")
    p.add_argument("--scratch", type=Path, default=Path("/tmp/blindspot"),
                   help="Scratch dir for sparse checkouts")
    p.add_argument("--keep-scratch", action="store_true")
    p.add_argument("--out-json", type=Path,
                   default=REPORTS_DIR / "detector_gap.json")
    p.add_argument("--out-md", type=Path,
                   default=DOCS_DIR / f"DETECTOR_GAP_REPORT_{date.today().isoformat()}.md")
    p.add_argument(
        "--out-source-ref-manifest",
        type=Path,
        help=(
            "Companion source-ref replay manifest path. Defaults to "
            "<out-json-stem>_source_ref_replay_manifest.json."
        ),
    )
    p.add_argument(
        "--named-ref-lockfile",
        type=Path,
        help="Local JSON/JSONL owner/repo@ref -> full commit map for the source-ref manifest.",
    )
    p.add_argument(
        "--local-source-root",
        type=Path,
        help="Local source root used when materializing immutable-ready manifest rows.",
    )
    p.add_argument(
        "--local-proof",
        type=Path,
        help="Local source proof map used by the source-ref manifest.",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    LOG.info("=== Detector Blindspot Scanner ===")
    LOG.info("max_findings=%d, tier=%s", args.max_findings, args.tier)

    # Load findings
    findings_payload = json.loads(args.data.read_text())
    if not isinstance(findings_payload, list):
        raise TypeError(f"finding data must be a JSON array: {args.data}")
    findings_raw = [r for r in findings_payload if isinstance(r, dict)][: args.max_findings]
    findings = [normalize_finding(r) for r in findings_raw]
    LOG.info("loaded %d findings from %s", len(findings), args.data)
    source_ref_manifest_path = (
        args.out_source_ref_manifest
        or default_source_ref_manifest_path(args.out_json)
    )
    source_ref_manifest = emit_source_ref_replay_manifest(
        findings_raw,
        source_ref_manifest_path,
        named_ref_lockfile=args.named_ref_lockfile,
        local_source_root=args.local_source_root,
        local_proof=args.local_proof,
    )

    # Load detector help
    detector_help = load_detector_help(REPO / "detectors")
    allowed_tiers = parse_tier_filter(args.tier)
    active_count = sum(
        1 for t, _ in detector_help.values()
        if tier_matches_filter(t, allowed_tiers)
    )
    LOG.info("loaded %d detectors (%d requested-tier)", len(detector_help), active_count)

    args.scratch.mkdir(parents=True, exist_ok=True)

    # Analyze findings
    rows: list[dict] = []
    for i, finding in enumerate(findings, 1):
        LOG.info("[%d/%d] %s — %s", i, len(findings),
                 finding["id"], finding["title"][:60])
        row = analyze_finding(finding, detector_help, args.scratch, tier=args.tier)
        rows.append(row)

        status = row.get("status", "?")
        if row.get("is_blindspot") and status == "analyzed":
            LOG.info("  BLINDSPOT: class=%s mode=%s",
                     row.get("bug_class"), row.get("analysis_mode"))
        elif not row.get("is_blindspot") and status == "analyzed":
            LOG.debug("  covered: %s", row.get("covering_detectors", [])[:2])

    source_ref_application = apply_source_ref_manifest_to_rows(rows, source_ref_manifest)

    # Stats
    analyzed = [r for r in rows if r.get("status") == "analyzed"]
    blindspots = [r for r in analyzed if r.get("is_blindspot")]
    skipped_lang = [r for r in rows if r.get("status") == "skipped_language"]

    slither_rows = [r for r in analyzed if r.get("detectors_run", 0) > 0]
    avg_dets = (sum(r["detectors_run"] for r in slither_rows) / len(slither_rows)
                if slither_rows else 0.0)
    checkout_ok = sum(
        1 for r in rows if r.get("github_ref") and r.get("detectors_run", 0) > 0
    )
    checkout_skip = sum(
        1 for r in rows if r.get("github_ref") and r.get("detectors_run", 0) == 0
    )

    modes = Counter(r.get("analysis_mode", "keyword-based") for r in analyzed)
    dominant_mode = modes.most_common(1)[0][0]

    stats = {
        "queried": len(findings),
        "skipped_language": len(skipped_lang),
        "checkout_ok": checkout_ok,
        "checkout_skip": checkout_skip,
        "avg_detectors_run": avg_dets,
        "tier": args.tier,
        "active_detectors": active_count,
        "total_detectors": len(detector_help),
        "mode": dominant_mode,
        "estimated_cost_usd": len(findings) * 0.0005,
        "source_ref_manifest": str(source_ref_manifest_path),
        "source_ref_manifest_rows": source_ref_manifest.get("row_count", 0),
        "source_ref_manifest_application": source_ref_application,
    }
    stats["source_ref_preservation_guard"] = enforce_source_ref_preservation(
        rows,
        source_ref_manifest,
    )

    if not blindspots and analyzed:
        LOG.warning(
            "M14-TRAP: 0 blindspots reported — verify manually before trusting!"
        )

    LOG.info("analyzed %d: %d covered, %d blindspots, %d skipped",
             len(analyzed),
             len([r for r in analyzed if not r.get("is_blindspot")]),
             len(blindspots),
             len(skipped_lang))

    emit_json_report(rows, args.out_json)
    emit_markdown_report(rows, args.out_md, stats)

    if not args.keep_scratch:
        shutil.rmtree(args.scratch, ignore_errors=True)

    print("\n=== BLINDSPOT SCAN COMPLETE ===")
    print(f"Findings processed : {len(findings)}")
    print(f"Analyzed           : {len(analyzed)}")
    print(f"Covered            : {len([r for r in analyzed if not r.get('is_blindspot')])}")
    print(f"Blindspots         : {len(blindspots)}")
    print(f"Skipped (lang)     : {len(skipped_lang)}")
    print(f"JSON report        : {args.out_json}")
    print(f"Markdown report    : {args.out_md}")
    print(f"Source-ref manifest: {source_ref_manifest_path}")

    class_counts: Counter[str] = Counter(r["bug_class"] for r in blindspots)
    if class_counts:
        print("\nTop missed classes:")
        for cls, cnt in class_counts.most_common(5):
            print(f"  {cls}: {cnt}")


if __name__ == "__main__":
    main()
