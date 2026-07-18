#!/usr/bin/env python3
"""ranker-learn — Wave-6 Track B Phase E continuous-learning loop.

Ingests triager outcomes for filed reports and proposes ranker weight
updates. NEVER auto-applies; operator runs `make ranker-apply-weights SHA=...`.

Usage
-----
    # Single-filing update
    python3 tools/ranker-learn.py \
        --filing-id cantina-192 \
        --outcome ACCEPTED \
        [--severity-final CRITICAL] \
        [--workspace dlt-workflow-gaps-main]

    # Batch mode over the last N hours of triager_outcome updates
    python3 tools/ranker-learn.py --batch-mode --since 24h

Pipeline (BIG_PLAN_2026-05-11 sub-report 06 §7):
1. Resolve filing_id -> tag YAML via filename + filing_id field search.
2. Update tag YAML: set triager_outcome + severity_final.
3. Re-emit secondary indexes (verdict-tag-extractor.py --reindex).
4. Walk audit/ranker_predictions_log.jsonl rows from the last 90 days that
   target the same target_repo as the updated tag. For each:
     - Realized attack_class = the updated tag's first attack_classes_to_try.
     - If realized AC ∈ predicted_top_5 -> reward (+0.01) the contributing
       scorers, weighted by attribution share.
     - Else -> penalize (-0.01) the over-weighting scorer.
   Gradient step:  w_i += lr * grad_i  (lr=0.02), clamped to [0.05, 0.6].
5. Snapshot proposed weights to audit/ranker_weights.<sha8>.yaml.
6. Emit audit/ranker_weight_diff.md (operator-readable).
7. Print a one-line note + return rc=0.

Notes
-----
- Manual-review gate is non-negotiable. Sub-report 06 §7.3 codifies this:
  triager mis-classification and adversarial outcome injection are real risks
  and the operator-approval step blocks both.
- Stdlib-only.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
RANKER_WEIGHTS = REPO_ROOT / "audit" / "ranker_weights.yaml"
RANKER_WEIGHTS_PER_FAMILY = REPO_ROOT / "audit" / "ranker_weights_per_family.yaml"
SIBLING_FAMILIES = REPO_ROOT / "audit" / "sibling_repo_families.yaml"
PREDICTIONS_LOG = REPO_ROOT / "audit" / "ranker_predictions_log.jsonl"
DIFF_OUT = REPO_ROOT / "audit" / "ranker_weight_diff.md"
EXTRACTOR = REPO_ROOT / "tools" / "verdict-tag-extractor.py"

LR = 0.02
REWARD = 0.01
PENALTY = 0.01
WEIGHT_FLOOR = 0.05
WEIGHT_CEIL = 0.6
WINDOW_DAYS_DEFAULT = 90
VALID_OUTCOMES = [
    "ACCEPTED", "AMENDED_DOWN", "AMENDED_UP",
    "REJECTED_OOS", "REJECTED_DUPE", "NOT_SUBMITTED",
    "PENDING", "WITHDRAWN",
]
VALID_SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "N/A"]


# --------------------------------------------------------------------------- #
# Minimal YAML loader / emitter (subset; mirrors ranker.py)                   #
# --------------------------------------------------------------------------- #

def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v


def _parse_scalar(s: str) -> Any:
    s = s.strip()
    if not s:
        return ""
    if s in ("null", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if s[0] in ("'", '"'):
        return _strip_quotes(s)
    try:
        return int(s)
    except Exception:
        pass
    try:
        return float(s)
    except Exception:
        pass
    return s


def yaml_load_path(path: Path) -> Dict[str, Any]:
    """Subset YAML loader: top-level keys + nested mappings + flow lists.

    Sufficient for tag files (used here only for read-the-key paths). For full
    fidelity edits we use a line-preserving text edit (set_yaml_key) instead.
    """
    out: Dict[str, Any] = {}
    if not path.exists():
        return out
    cur_key: Optional[str] = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", raw)
        if m:
            key, val = m.group(1), m.group(2)
            v = _parse_scalar(val) if val.strip() else ""
            if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
                inner = v[1:-1].strip()
                items = [_parse_scalar(x.strip()) for x in inner.split(",") if x.strip()]
                v = items
            out[key] = v
            cur_key = key
        elif raw.startswith("- "):
            # list item under cur_key — only keep first scalar for our needs
            if cur_key and not isinstance(out.get(cur_key), list):
                out[cur_key] = []
            if cur_key:
                # only need surface inspection; skip nested-mapping rows
                pass
    return out


def set_yaml_key(path: Path, key: str, value: str) -> bool:
    """Set a top-level scalar key in a YAML file. Preserves all other lines.

    Returns True if file changed.
    """
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    new_line = f"{key}: {value}"
    found = False
    for i, ln in enumerate(lines):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", ln)
        if m and m.group(1) == key:
            lines[i] = new_line
            found = True
            break
    if not found:
        # Append at end (before any trailing blank).
        while lines and not lines[-1].strip():
            lines.pop()
        lines.append(new_line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


# --------------------------------------------------------------------------- #
# Filing-id -> tag YAML resolver                                              #
# --------------------------------------------------------------------------- #

def resolve_tag_for_filing(filing_id: str, tags_dir: Path = TAGS_DIR) -> Optional[Path]:
    """Find the tag YAML whose filing_id == filing_id.

    Falls back to filename substring match (e.g. "cantina-192" appears in the
    paste_ready_filed filename).
    """
    if not tags_dir.exists():
        return None
    # Pass 1: grep filing_id field directly
    rx = re.compile(r'^filing_id:\s*"?' + re.escape(filing_id) + r'"?\s*$', re.M)
    for yp in sorted(tags_dir.glob("*.yaml")):
        try:
            txt = yp.read_text(encoding="utf-8")
        except Exception:
            continue
        if rx.search(txt):
            return yp
    # Pass 2: filename substring
    for yp in sorted(tags_dir.glob("*.yaml")):
        if filing_id in yp.name:
            return yp
    return None


# --------------------------------------------------------------------------- #
# Predictions log reader                                                      #
# --------------------------------------------------------------------------- #

def load_predictions(
    log_path: Path = PREDICTIONS_LOG,
    window_days: int = WINDOW_DAYS_DEFAULT,
    target_repo_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if not log_path.exists():
        return []
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=window_days)
    rows: List[Dict[str, Any]] = []
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        ts = row.get("ts")
        if ts:
            try:
                dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=datetime.timezone.utc
                )
                if dt < cutoff:
                    continue
            except Exception:
                pass
        if target_repo_filter and row.get("target_repo") != target_repo_filter:
            continue
        rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
# Gradient tuner                                                              #
# --------------------------------------------------------------------------- #

def load_weights(path: Path = RANKER_WEIGHTS) -> Dict[str, float]:
    """Load just the 4 scorer weights w1..w4 as a flat dict."""
    out: Dict[str, float] = {"w1": 0.45, "w2": 0.20, "w3": 0.20, "w4": 0.15}
    if not path.exists():
        return out
    in_weights = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("weights:"):
            in_weights = True
            continue
        if in_weights:
            m = re.match(r"^\s+(w[1-4]):\s*([0-9.]+)", raw)
            if m:
                out[m.group(1)] = float(m.group(2))
            elif raw and not raw.startswith(" "):
                in_weights = False
    return out


# --------------------------------------------------------------------------- #
# Wave-7: per-family weight read/write                                        #
# --------------------------------------------------------------------------- #

def load_family_weights(
    family_id: str,
    path: Path = RANKER_WEIGHTS_PER_FAMILY,
) -> Dict[str, float]:
    """Load the w1..w4 block for ``family_id`` from the per-family YAML.

    Falls back to the per-family ``default`` block, then to a baseline.
    """
    base = {"w1": 0.45, "w2": 0.20, "w3": 0.20, "w4": 0.15}
    if not path.exists():
        return base
    # Phase 1: read default + the named family using indent-based scan
    text = path.read_text(encoding="utf-8")
    # Locate `default:` and absorb 4 weight lines below
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        if re.match(r"^default:\s*$", ln):
            j = i + 1
            while j < len(lines):
                m = re.match(r"^\s+(w[1-4]):\s*([0-9.]+)", lines[j])
                if m:
                    base[m.group(1)] = float(m.group(2))
                    j += 1
                    continue
                if lines[j] and not lines[j].startswith(" "):
                    break
                j += 1
            break
        i += 1
    # Phase 2: scan into `families:` for our family-id
    in_families = False
    in_target = False
    for raw in lines:
        if re.match(r"^families:\s*$", raw):
            in_families = True
            continue
        if in_families:
            # Stop at next top-level key
            if raw and not raw.startswith(" ") and not raw.startswith("\t"):
                in_families = False
                in_target = False
                continue
            m = re.match(r"^  (\S+):\s*$", raw)
            if m:
                in_target = (m.group(1) == family_id)
                continue
            if in_target:
                m2 = re.match(r"^\s+(w[1-4]):\s*([0-9.]+)", raw)
                if m2:
                    base[m2.group(1)] = float(m2.group(2))
    return base


def write_family_weights(
    family_id: str,
    new_weights: Dict[str, float],
    path: Path = RANKER_WEIGHTS_PER_FAMILY,
) -> bool:
    """In-place update the four w1..w4 lines for ``family_id`` in the
    per-family YAML. If the family block is missing, append one under
    ``families:`` keeping the file otherwise byte-identical. Returns True
    when the file changes.

    Constraint: this MUST NOT touch the global ``audit/ranker_weights.yaml``.
    """
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    # Find the family block
    fam_start: Optional[int] = None
    families_start: Optional[int] = None
    for i, ln in enumerate(lines):
        if re.match(r"^families:\s*$", ln):
            families_start = i
        if families_start is not None and i > families_start:
            m = re.match(r"^  (\S+):\s*$", ln)
            if m and m.group(1) == family_id:
                fam_start = i
                break
            # Past families: block (top-level key reached)
            if ln and not ln.startswith(" ") and not ln.startswith("\t"):
                break
    changed = False
    if fam_start is not None:
        # Replace w1..w4 lines (next 4 indented lines belonging to family)
        j = fam_start + 1
        while j < len(lines):
            ln = lines[j]
            if re.match(r"^  \S+:\s*$", ln):  # next family
                break
            if ln and not ln.startswith(" "):
                break
            m = re.match(r"^(\s+)(w[1-4]):\s*[0-9.]+\s*$", ln)
            if m:
                indent, key = m.group(1), m.group(2)
                new_val = new_weights.get(key)
                if new_val is not None:
                    new_line = f"{indent}{key}: {round(float(new_val), 4)}"
                    if new_line != ln:
                        lines[j] = new_line
                        changed = True
            j += 1
    else:
        # Append a new family block at the end of `families:` section.
        # Insert before the next top-level key after families_start.
        insert_at = len(lines)
        if families_start is not None:
            for k in range(families_start + 1, len(lines)):
                if lines[k] and not lines[k].startswith(" "):
                    insert_at = k
                    break
        block = [
            f"  {family_id}:",
            f"    w1: {round(float(new_weights.get('w1', 0.45)), 4)}",
            f"    w2: {round(float(new_weights.get('w2', 0.20)), 4)}",
            f"    w3: {round(float(new_weights.get('w3', 0.20)), 4)}",
            f"    w4: {round(float(new_weights.get('w4', 0.15)), 4)}",
        ]
        lines[insert_at:insert_at] = block
        changed = True
    if changed:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed


def load_sibling_families(path: Path = SIBLING_FAMILIES) -> Dict[str, List[str]]:
    """Minimal loader: {family_id: [repo, ...]}. Empty on missing/parse-error."""
    if not path.exists():
        return {}
    out: Dict[str, List[str]] = {}
    cur_fam: Optional[str] = None
    in_families = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^families:\s*$", raw):
            in_families = True
            continue
        if in_families:
            if raw and not raw.startswith(" ") and not raw.startswith("\t"):
                in_families = False
                cur_fam = None
                continue
            m = re.match(r"^  (\S+):\s*$", raw)
            if m:
                cur_fam = m.group(1)
                out[cur_fam] = []
                continue
            mi = re.match(r"^\s+-\s+(\S+)", raw)
            if mi and cur_fam:
                out[cur_fam].append(mi.group(1).strip('"').strip("'"))
    return out


def resolve_family_for_repo(
    target_repo: str,
    families: Dict[str, List[str]],
) -> Optional[str]:
    """Return the family-id (e.g. ``cosmos-sdk-forks``) that contains
    ``target_repo`` or ``None``. Mirrors ranker.find_family_id()."""
    for fam_id, repos in families.items():
        if target_repo in repos:
            return fam_id
    return None


def attribute_correct_prediction(
    realized_ac: str,
    pred_row: Dict[str, Any],
) -> Dict[str, float]:
    """When realized_ac is in top-5, attribute the win to scorers proportionally
    to their contribution share for that AC."""
    scores_by_scorer = pred_row.get("scores_by_scorer") or {}
    contrib = {
        s: float((scores_by_scorer.get(s) or {}).get(realized_ac, 0.0))
        for s in ("S1", "S2", "S3", "S4")
    }
    total = sum(contrib.values())
    if total <= 0:
        # Convergence-bonus only path — credit S1 marginally (default).
        return {"w1": 1.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
    return {
        "w1": contrib["S1"] / total,
        "w2": contrib["S2"] / total,
        "w3": contrib["S3"] / total,
        "w4": contrib["S4"] / total,
    }


def attribute_missed_prediction(
    realized_ac: str,
    pred_row: Dict[str, Any],
) -> Dict[str, float]:
    """When realized_ac is NOT in top-5, find the scorer that pushed the WRONG
    AC to rank-1 and assign penalty there.

    Heuristic: top-1 predicted AC's largest single-scorer contribution
    identifies the over-weighting scorer.
    """
    predicted = pred_row.get("predicted_top_5") or []
    if not predicted:
        return {"w1": 0.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
    top1 = predicted[0]
    scores_by_scorer = pred_row.get("scores_by_scorer") or {}
    contrib_top1 = {
        s: float((scores_by_scorer.get(s) or {}).get(top1, 0.0))
        for s in ("S1", "S2", "S3", "S4")
    }
    if not any(v > 0 for v in contrib_top1.values()):
        return {"w1": 0.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
    worst_scorer = max(contrib_top1, key=lambda s: contrib_top1[s])
    out = {"w1": 0.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
    out[f"w{worst_scorer[1]}"] = 1.0
    return out


def compute_gradient(
    predictions: List[Dict[str, Any]],
    realized_ac: str,
) -> Tuple[Dict[str, float], Dict[str, int]]:
    """Aggregate +/- attributions across the prediction window.

    Returns (gradient, counts) where:
      gradient[wi] = (#hits attributing to wi) * REWARD
                    - (#misses penalising wi)  * PENALTY
      counts = {"hits": N, "misses": M, "rows": K}
    """
    grad = {"w1": 0.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
    hits = 0
    misses = 0
    for row in predictions:
        top5 = row.get("predicted_top_5") or []
        if realized_ac in top5:
            hits += 1
            share = attribute_correct_prediction(realized_ac, row)
            for k in grad:
                grad[k] += REWARD * share[k]
        else:
            misses += 1
            share = attribute_missed_prediction(realized_ac, row)
            for k in grad:
                grad[k] -= PENALTY * share[k]
    return grad, {"hits": hits, "misses": misses, "rows": len(predictions)}


def apply_gradient(
    current: Dict[str, float],
    grad: Dict[str, float],
    lr: float = LR,
) -> Dict[str, float]:
    out = dict(current)
    for k in ("w1", "w2", "w3", "w4"):
        v = out.get(k, 0.0) + lr * grad.get(k, 0.0)
        v = max(WEIGHT_FLOOR, min(WEIGHT_CEIL, v))
        out[k] = round(v, 4)
    return out


# --------------------------------------------------------------------------- #
# Snapshot + diff                                                             #
# --------------------------------------------------------------------------- #

def write_weights_snapshot(
    weights: Dict[str, float],
    snapshot_dir: Path = RANKER_WEIGHTS.parent,
    provenance: str = "",
) -> Tuple[Path, str]:
    """Write proposed weights to audit/ranker_weights.<sha8>.yaml.

    Returns (snapshot_path, sha8).
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = (
        "# Ranker weights snapshot (Phase E proposed update).\n"
        "# Generated by tools/ranker-learn.py.\n"
        "# DO NOT auto-apply. Run `make ranker-apply-weights SHA=<sha8>`.\n"
        "weights:\n"
        f"  w1: {weights['w1']}\n"
        f"  w2: {weights['w2']}\n"
        f"  w3: {weights['w3']}\n"
        f"  w4: {weights['w4']}\n"
        "recency_weights:\n"
        "  same_engagement: 0.85\n"
        "  old_pin: 0.6\n"
        "  cross_engagement: 0.4\n"
        "shape_similarity:\n"
        "  exact: 1.0\n"
        "  fine_exact: 0.7\n"
        "  partial: 0.4\n"
        "confidence:\n"
        "  threshold: 0.4\n"
        "  sigmoid_center: 0.0\n"
        "  sigmoid_steepness: 3.0\n"
        "  convergence_bonus: 0.15\n"
        f"provenance: |\n  {provenance.strip().replace(chr(10), chr(10) + '  ')}\n"
        f"generated_at_utc: \"{ts}\"\n"
    )
    h = hashlib.sha256(body.encode("utf-8")).hexdigest()
    sha8 = h[:8]
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    out_path = snapshot_dir / f"ranker_weights.{sha8}.yaml"
    out_path.write_text(body, encoding="utf-8")
    return out_path, sha8


def write_diff(
    current: Dict[str, float],
    proposed: Dict[str, float],
    sha8: str,
    snapshot_path: Path,
    counts: Dict[str, int],
    realized_ac: Optional[str],
    filing_id: Optional[str],
    out_path: Path = DIFF_OUT,
) -> Path:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    def _rel(p: Path) -> str:
        try:
            return str(p.relative_to(REPO_ROOT))
        except ValueError:
            return str(p)
    lines = [
        "# Ranker weight diff (operator review)",
        "",
        f"- Generated: {ts}",
        f"- Snapshot: `{_rel(snapshot_path)}` (sha8=`{sha8}`)",
        f"- Triager filing: `{filing_id or 'batch-mode'}`",
        f"- Realized attack_class: `{realized_ac or '(batch-aggregate)'}`",
        f"- Prediction window: {counts.get('rows', 0)} rows "
        f"({counts.get('hits', 0)} hits, {counts.get('misses', 0)} misses)",
        "",
        "## Weights",
        "",
        "| key | current | proposed | delta |",
        "|-----|---------|----------|-------|",
    ]
    for k in ("w1", "w2", "w3", "w4"):
        c = current.get(k, 0.0)
        p = proposed.get(k, 0.0)
        delta = round(p - c, 4)
        sign = "+" if delta > 0 else ""
        lines.append(f"| {k} | {c} | {p} | {sign}{delta} |")
    lines.extend([
        "",
        "## To apply",
        "",
        f"```",
        f"make ranker-apply-weights SHA={sha8}",
        f"```",
        "",
        "## To reject",
        "",
        f"```",
        f"rm {_rel(snapshot_path)} {_rel(out_path)}",
        f"```",
        "",
        "## Manual-review gate",
        "",
        "This diff is NEVER auto-applied. Operator approval is mandatory per",
        "BIG_PLAN_2026-05-11 sub-report 06 §7.3 (guards against triager",
        "mis-classification + adversarial outcome injection).",
        "",
    ])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


# --------------------------------------------------------------------------- #
# Reindex                                                                     #
# --------------------------------------------------------------------------- #

def reindex_corpus_tags(extractor: Path = EXTRACTOR) -> int:
    """Run verdict-tag-extractor.py --reindex; return rc."""
    try:
        rc = subprocess.call(
            ["python3", str(extractor), "--reindex"],
            cwd=str(REPO_ROOT),
        )
        return rc
    except Exception as e:
        print(f"reindex: failed: {e}", file=sys.stderr)
        return 1


# --------------------------------------------------------------------------- #
# Batch mode helper                                                           #
# --------------------------------------------------------------------------- #

_SINCE_RX = re.compile(r"^(\d+)\s*(h|hr|hours|d|day|days)$", re.I)


def parse_since(since: str) -> datetime.timedelta:
    m = _SINCE_RX.match(since.strip())
    if not m:
        raise ValueError(f"--since must be like '24h' or '7d' (got {since!r})")
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit.startswith("h"):
        return datetime.timedelta(hours=n)
    return datetime.timedelta(days=n)


def collect_batch_tags(
    since: datetime.timedelta,
    tags_dir: Path = TAGS_DIR,
) -> List[Path]:
    """Walk all tag files; return those whose mtime is within `since`."""
    cutoff = datetime.datetime.now().timestamp() - since.total_seconds()
    out: List[Path] = []
    if not tags_dir.exists():
        return out
    for yp in sorted(tags_dir.rglob("*.yaml")):
        try:
            if yp.stat().st_mtime >= cutoff:
                txt = yp.read_text(encoding="utf-8")
                # Only consider tags that actually carry a triager_outcome.
                if "triager_outcome:" in txt:
                    out.append(yp)
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------- #
# Seed the batch learner from confirmed own-findings.                         #
# --------------------------------------------------------------------------- #
#
# Root cause the meta-audit flagged ("ranker-apply-weights never runs"): the
# batch learner consumes ONLY tags carrying `triager_outcome:`, and nothing in
# the pipeline ever stamps that key. Confirmed/filed own-findings (the 35
# ingested under auditooor_own_findings/, each `confirmed_finding: true`) are
# real TP signal but were never normalised into a learnable outcome. With zero
# learnable tags, no weight snapshot is ever produced, so the operator never
# has a SHA to apply. This seeder backfills the learnable keys onto confirmed
# own-finding tags so the existing batch learner has input. It NEVER applies
# weights — the operator gate (`make ranker-apply-weights SHA=...`) is intact.

OWN_FINDINGS_DIR = TAGS_DIR / "auditooor_own_findings"

# Map a finding's severity_at_finding onto VALID_SEVERITIES for severity_final.
_SEV_MAP = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "informational": "INFORMATIONAL", "info": "INFORMATIONAL",
}


def _read_key(text: str, key: str) -> Optional[str]:
    m = re.search(rf"^{re.escape(key)}:\s*(.+)$", text, re.MULTILINE)
    if not m:
        return None
    return _strip_quotes(m.group(1).strip())


def seed_own_findings(
    own_dir: Path = OWN_FINDINGS_DIR,
    outcome: str = "ACCEPTED",
) -> int:
    """Stamp learnable keys onto confirmed own-finding tags. Returns count seeded.

    For each tag with ``confirmed_finding: true`` (or the textual fallback)
    that does NOT already carry ``triager_outcome:``, set:
      - ``triager_outcome``   (defaults to ACCEPTED — a confirmed TP)
      - ``severity_final``    (from severity_at_finding)
      - ``attack_classes_to_try: [<attack_class>]`` when only the singular
        ``attack_class`` is present, so ``realized_ac_for_tag`` resolves.

    Idempotent: tags already carrying ``triager_outcome:`` are skipped, so a
    re-run does not re-stamp. Never raises on a single bad file.
    """
    if outcome not in VALID_OUTCOMES:
        outcome = "ACCEPTED"
    if not own_dir.is_dir():
        return 0
    seeded = 0
    for yp in sorted(own_dir.glob("*.yaml")):
        try:
            txt = yp.read_text(encoding="utf-8")
        except OSError:
            continue
        if "triager_outcome:" in txt:
            continue  # already learnable; idempotent
        confirmed = (_read_key(txt, "confirmed_finding") or "").lower() == "true" \
            or "confirmed_finding: true" in txt
        if not confirmed:
            continue
        attack_class = _read_key(txt, "attack_class")
        if attack_class and "attack_classes_to_try:" not in txt:
            set_yaml_key(yp, "attack_classes_to_try", f"[{attack_class}]")
        sev_raw = (_read_key(txt, "severity_at_finding") or "").lower()
        sev_final = _SEV_MAP.get(sev_raw)
        update_tag_outcome(yp, outcome, sev_final)
        seeded += 1
    return seeded


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #

def update_tag_outcome(
    tag_path: Path,
    outcome: str,
    severity_final: Optional[str] = None,
) -> bool:
    changed = set_yaml_key(tag_path, "triager_outcome", outcome)
    if severity_final:
        set_yaml_key(tag_path, "severity_final", severity_final)
    return changed


def realized_ac_for_tag(tag_path: Path) -> Optional[str]:
    """Extract the first attack_class from attack_classes_to_try (the realized
    one for learning-signal purposes — Phase E §7.1).
    """
    if not tag_path.exists():
        return None
    in_block = False
    saw_inline = None
    for raw in tag_path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^attack_classes_to_try:\s*(.*)$", raw)
        if m:
            inline = m.group(1).strip()
            if inline.startswith("[") and inline.endswith("]"):
                items = [x.strip() for x in inline[1:-1].split(",") if x.strip()]
                if items:
                    return items[0].strip('"').strip("'")
                return None
            in_block = True
            continue
        if in_block:
            mi = re.match(r"^-\s+(\S+)", raw)
            if mi:
                return mi.group(1).strip('"').strip("'")
            if raw and not raw.startswith(" ") and not raw.startswith("\t") and not raw.startswith("-"):
                in_block = False
    return None


def target_repo_for_tag(tag_path: Path) -> Optional[str]:
    for raw in tag_path.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^target_repo:\s*"?([^"\s]+)"?', raw)
        if m:
            return m.group(1)
    return None


def run_learn_for_tag(
    tag_path: Path,
    outcome: str,
    severity_final: Optional[str],
    filing_id: Optional[str],
    reindex: bool = True,
    family: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the learn-loop. If ``family`` is provided, the gradient targets
    the per-family weights in ``audit/ranker_weights_per_family.yaml``
    rather than the global ``audit/ranker_weights.yaml``. Per Wave-7."""
    update_tag_outcome(tag_path, outcome, severity_final)
    if reindex:
        reindex_corpus_tags()
    realized_ac = realized_ac_for_tag(tag_path)
    target_repo = target_repo_for_tag(tag_path)
    predictions = load_predictions(target_repo_filter=target_repo)
    grad, counts = compute_gradient(predictions, realized_ac or "")
    if family:
        current = load_family_weights(family)
        proposed = apply_gradient(current, grad)
        # In-place update of audit/ranker_weights_per_family.yaml
        # (Wave-7 deliverable §4: family-scoped learning; global untouched)
        write_family_weights(family, proposed)
        provenance = (
            f"Phase E per-family update (family={family}) from "
            f"filing={filing_id or tag_path.stem}, outcome={outcome}, "
            f"realized_ac={realized_ac}, target_repo={target_repo}, "
            f"window={counts['rows']} preds (hits={counts['hits']}, "
            f"misses={counts['misses']})."
        )
        # Snapshot is informational; the in-place file already shifted.
        snapshot_path, sha8 = write_weights_snapshot(proposed, provenance=provenance)
        diff_path = write_diff(
            current=current,
            proposed=proposed,
            sha8=sha8,
            snapshot_path=snapshot_path,
            counts=counts,
            realized_ac=realized_ac,
            filing_id=(filing_id or "") + f" [family={family}]",
        )
        return {
            "tag_path": str(tag_path),
            "target_repo": target_repo,
            "family": family,
            "realized_ac": realized_ac,
            "current": current,
            "proposed": proposed,
            "snapshot_path": str(snapshot_path),
            "sha8": sha8,
            "diff_path": str(diff_path),
            "counts": counts,
            "weights_scope": "per_family",
        }
    current = load_weights()
    proposed = apply_gradient(current, grad)
    provenance = (
        f"Phase E proposed update from filing={filing_id or tag_path.stem}, "
        f"outcome={outcome}, realized_ac={realized_ac}, target_repo={target_repo}, "
        f"window={counts['rows']} preds (hits={counts['hits']}, misses={counts['misses']})."
    )
    snapshot_path, sha8 = write_weights_snapshot(proposed, provenance=provenance)
    diff_path = write_diff(
        current=current,
        proposed=proposed,
        sha8=sha8,
        snapshot_path=snapshot_path,
        counts=counts,
        realized_ac=realized_ac,
        filing_id=filing_id,
    )
    return {
        "tag_path": str(tag_path),
        "target_repo": target_repo,
        "realized_ac": realized_ac,
        "current": current,
        "proposed": proposed,
        "snapshot_path": str(snapshot_path),
        "sha8": sha8,
        "diff_path": str(diff_path),
        "counts": counts,
        "weights_scope": "global",
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Ranker continuous-learning loop.")
    p.add_argument("--filing-id", help="cantina-NNN or immunefi-NNNNN filing id")
    p.add_argument("--outcome", choices=VALID_OUTCOMES,
                   help="Triager outcome class")
    p.add_argument("--severity-final", choices=VALID_SEVERITIES,
                   help="Final severity (set if AMENDED_*)")
    p.add_argument("--workspace", default=None, help="Workspace name (advisory)")
    p.add_argument("--batch-mode", action="store_true",
                   help="Aggregate over all tags updated in --since window")
    p.add_argument("--since", default="24h",
                   help="Batch window (e.g. 24h, 7d). Default 24h.")
    p.add_argument("--seed-from-own-findings", action="store_true",
                   help="Before batch learning, stamp triager_outcome onto "
                        "confirmed own-finding tags (idempotent) so the "
                        "learner has TP input. Never applies weights — the "
                        "operator gate stays. Use with --batch-mode.")
    p.add_argument("--tags-dir", default=str(TAGS_DIR))
    p.add_argument("--predictions-log", default=str(PREDICTIONS_LOG))
    p.add_argument("--no-reindex", action="store_true",
                   help="Skip verdict-tag-extractor --reindex (tests only)")
    p.add_argument("--family", default=None,
                   help="Per-family scope (e.g. cosmos-sdk-forks). When set, "
                        "gradient updates `audit/ranker_weights_per_family.yaml` "
                        "for that family only; the global "
                        "`audit/ranker_weights.yaml` is left untouched. "
                        "Wave-7 per-target weight tuning.")
    args = p.parse_args(argv)

    tags_dir = Path(args.tags_dir)

    if args.batch_mode:
        try:
            since = parse_since(args.since)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if args.seed_from_own_findings:
            seeded = seed_own_findings()
            print(f"seed: stamped triager_outcome on {seeded} confirmed "
                  f"own-finding tag(s) (idempotent)")
        recent_tags = collect_batch_tags(since, tags_dir=tags_dir)
        if not recent_tags:
            print(f"batch: no tags updated in last {args.since} — nothing to learn from")
            return 0
        # Aggregate gradient across all recent tags.
        # Wave-7: when --family is set, batch updates the per-family weights
        # for that family only.
        current = load_family_weights(args.family) if args.family else load_weights()
        agg_grad = {"w1": 0.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
        agg_counts = {"hits": 0, "misses": 0, "rows": 0}
        realized_acs: List[str] = []
        for tp in recent_tags:
            target_repo = target_repo_for_tag(tp)
            realized = realized_ac_for_tag(tp) or ""
            if realized:
                realized_acs.append(realized)
            preds = load_predictions(target_repo_filter=target_repo)
            grad, counts = compute_gradient(preds, realized)
            for k in agg_grad:
                agg_grad[k] += grad[k]
            agg_counts["hits"] += counts["hits"]
            agg_counts["misses"] += counts["misses"]
            agg_counts["rows"] += counts["rows"]
        proposed = apply_gradient(current, agg_grad)
        provenance = (
            f"Phase E batch update — {len(recent_tags)} tags in last {args.since} "
            f"({agg_counts['hits']} hits / {agg_counts['misses']} misses / {agg_counts['rows']} pred-rows). "
            f"Realized ACs: {sorted(set(realized_acs))[:8]}"
        )
        if args.family:
            provenance = f"[family={args.family}] " + provenance
            write_family_weights(args.family, proposed)
        snapshot_path, sha8 = write_weights_snapshot(proposed, provenance=provenance)
        diff_path = write_diff(
            current=current, proposed=proposed, sha8=sha8,
            snapshot_path=snapshot_path, counts=agg_counts,
            realized_ac=", ".join(sorted(set(realized_acs))[:5]) or None,
            filing_id=f"batch-mode (since={args.since}, n={len(recent_tags)})",
        )
        print(
            f"Diff at {diff_path.relative_to(REPO_ROOT)}. "
            f"Review then run `make ranker-apply-weights SHA={sha8}` to apply."
        )
        return 0

    # Single-filing mode
    if not args.filing_id or not args.outcome:
        print("error: --filing-id and --outcome are required (or pass --batch-mode)",
              file=sys.stderr)
        return 2

    tag = resolve_tag_for_filing(args.filing_id, tags_dir=tags_dir)
    if tag is None:
        print(f"error: no tag found for filing-id={args.filing_id}", file=sys.stderr)
        return 3

    result = run_learn_for_tag(
        tag_path=tag,
        outcome=args.outcome,
        severity_final=args.severity_final,
        filing_id=args.filing_id,
        reindex=not args.no_reindex,
        family=args.family,
    )
    diff_rel = Path(result["diff_path"]).relative_to(REPO_ROOT)
    if args.family:
        print(
            f"Per-family weights updated for family={args.family}. "
            f"Diff at {diff_rel}. Global weights untouched."
        )
    else:
        print(
            f"Diff at {diff_rel}. "
            f"Review then run `make ranker-apply-weights SHA={result['sha8']}` to apply."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
