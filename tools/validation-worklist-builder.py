#!/usr/bin/env python3
"""validation-worklist-builder.py — produce one validation worklist
covering every paste-ready × every gate × pass/fail status.

Inputs (auto-discovered):
  - /Users/wolf/audits/*/submissions/paste_ready/current/*.md
  - /Users/wolf/audits/*/submissions/staging/*.md
  - /Users/wolf/audits/*/submissions/packaged/*/   (lists each as a bundle)

Gates (parallel, ThreadPoolExecutor cap=6):
  G1  pre-submit-check.sh <md> --severity <inferred>
  G2  per-finding-oos-check.py --workspace <ws> --finding <md>
  G3  upstream-equivalent-gate.py --finding <md>          (skipped: requires
      a JSON candidate manifest, not a raw md — recorded as `skipped` with
      reason so the operator knows it was not silently dropped)
  G4  poc-stub-coverage-checker.py <md>

Outputs (under /Users/wolf/audits/_worklist/):
  - VALIDATION_WORKLIST_<utc-ts>.md
  - VALIDATION_WORKLIST_<utc-ts>.json   (sibling, machine-readable)

Sorted: severity (Critical>High>Medium>Low>?), then by # of failures desc.
Each failure carries a fix-effort estimate ∈ {cosmetic, content, blocker}.

Read-only with respect to the audit workspaces. Only writes to _worklist/.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = REPO_ROOT / "tools"
AUDITS_ROOT = Path("/Users/wolf/audits")
WORKLIST_DIR = AUDITS_ROOT / "_worklist"

PRE_SUBMIT = TOOLS / "pre-submit-check.sh"
PER_FINDING_OOS = TOOLS / "per-finding-oos-check.py"
UPSTREAM_GATE = TOOLS / "upstream-equivalent-gate.py"
POC_STUB = TOOLS / "poc-stub-coverage-checker.py"

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}

# Heuristics for fix-effort classification on failure messages.
COSMETIC = re.compile(
    r"(rubric\s+citation|originality|grep|title\s*-?\s*schema|\bWARN\b|"
    r"event-only|incomplete-fix|dollar\s+impact|\$\s*impact|"
    r"missing\s+rubric|format)",
    re.IGNORECASE,
)
BLOCKER = re.compile(
    r"(OOS|out[-\s]?of[-\s]?scope|upstream\s+equivalent|severity\s+over[-\s]?claim|"
    r"production[-\s]?path|severity-claim-guard|program-impact-mapping|"
    r"financial-impact|fork[-\s]?replay|live\s+claim|m14|hallucinat)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def infer_severity(name: str) -> str:
    upper = name.upper()
    for tag in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if tag in upper:
            return tag.capitalize()
    return "High"  # default per spec


def workspace_for(path: Path) -> Path:
    """Return the audit workspace root for a paste-ready, e.g.
    /Users/wolf/audits/base-azul."""
    p = path.resolve()
    for parent in p.parents:
        if parent.parent == AUDITS_ROOT:
            return parent
    return p.parents[2] if len(p.parents) >= 3 else AUDITS_ROOT


def discover_paste_readies() -> list[dict]:
    out: list[dict] = []
    for md in sorted(AUDITS_ROOT.glob("*/submissions/paste_ready/current/*.md")):
        out.append({"kind": "paste_ready_current", "path": md})
    for md in sorted(AUDITS_ROOT.glob("*/submissions/staging/*.md")):
        out.append({"kind": "staging", "path": md})
    return out


def discover_packaged_bundles() -> list[Path]:
    bundles: list[Path] = []
    for d in sorted(AUDITS_ROOT.glob("*/submissions/packaged/*")):
        if d.is_dir():
            bundles.append(d)
    return bundles


# ---------------------------------------------------------------------------
# gate runners (each returns dict {gate, status, rc, summary, raw_excerpt})
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 180) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def _excerpt(text: str, lines: int = 8) -> str:
    body = text.strip().splitlines()
    if not body:
        return ""
    head = body[:lines]
    if len(body) > lines:
        head.append(f"... (+{len(body) - lines} more lines)")
    return "\n".join(head)


def _failure_summary(text: str) -> str:
    """Pick the single most useful one-line failure reason."""
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        if re.search(r"^\s*(❌|FAIL\b|\bFAIL:|ERROR\b)", s):
            return s[:200]
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("⚠️") or s.startswith("WARN"):
            return s[:200]
    return _excerpt(text, 1)[:200]


def _classify_effort(failure: str) -> str:
    if BLOCKER.search(failure):
        return "blocker"
    if COSMETIC.search(failure):
        return "cosmetic"
    return "content"


def gate_pre_submit(md: Path, severity: str) -> dict:
    rc, out, err = _run(["bash", str(PRE_SUBMIT), str(md), "--severity", severity], timeout=240)
    text = out or err
    status = "pass" if rc == 0 else "fail"
    summary = "all checks passed" if status == "pass" else _failure_summary(text)
    # Surface warnings even on pass
    warn_count = len(re.findall(r"^\s*⚠️", text, re.M))
    fail_count = len(re.findall(r"^\s*❌", text, re.M))
    return {
        "gate": "pre-submit-check",
        "status": status,
        "rc": rc,
        "summary": summary,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "excerpt": _excerpt(text, 12),
    }


def gate_per_finding_oos(md: Path, ws: Path) -> dict:
    if not (ws / "OOS_PASTED.md").exists():
        return {
            "gate": "per-finding-oos",
            "status": "skipped",
            "rc": None,
            "summary": "OOS_PASTED.md not present in workspace",
            "excerpt": "",
        }
    rc, out, err = _run(
        [
            "python3",
            str(PER_FINDING_OOS),
            "--workspace",
            str(ws),
            "--finding",
            str(md),
        ],
        timeout=120,
    )
    text = out or err
    # Verdict: tool prints `verdict: in-scope|matches-oos|inconclusive`
    verdict = None
    m = re.search(r"verdict\s*[:=]\s*([a-zA-Z\-]+)", text)
    if m:
        verdict = m.group(1).strip().lower()
    if rc != 0:
        status = "fail"
    elif verdict == "matches-oos":
        status = "fail"
    elif verdict in ("in-scope",):
        status = "pass"
    else:
        status = "warn"
    summary = f"verdict={verdict or '?'} rc={rc}"
    return {
        "gate": "per-finding-oos",
        "status": status,
        "rc": rc,
        "verdict": verdict,
        "summary": summary,
        "excerpt": _excerpt(text, 8),
    }


def gate_upstream_equivalent(md: Path, ws: Path) -> dict:
    # The tool requires --candidate JSON, not --finding. Build a minimal
    # one-row candidate JSON in a tmp file when possible. If the md doesn't
    # name a production_path we can extract, mark skipped.
    text = ""
    try:
        text = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    # Look for an external/<asset>/... or crates/... reference.
    paths = re.findall(r"(external/[\w\-./]+\.(?:rs|sol|go|toml))", text)
    if not paths:
        paths = re.findall(r"(crates/[\w\-./]+\.(?:rs|sol|go|toml))", text)
    if not paths:
        return {
            "gate": "upstream-equivalent",
            "status": "skipped",
            "rc": None,
            "summary": "no production_path (external/* or crates/*) reference found in md",
            "excerpt": "",
        }
    cand_path = paths[0]
    sev = infer_severity(md.name)
    candidate = [
        {
            "id": md.stem,
            "production_path": cand_path,
            "severity_tier": sev.lower(),
            "selected_impact": "(unknown — auto-extracted by validation-worklist-builder)",
        }
    ]
    tmp_dir = WORKLIST_DIR / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_json = tmp_dir / f"cand_{md.stem}_{abs(hash(str(md))) % 10**8}.json"
    try:
        tmp_json.write_text(json.dumps(candidate, indent=2))
    except OSError as exc:
        return {
            "gate": "upstream-equivalent",
            "status": "skipped",
            "rc": None,
            "summary": f"could not write tmp candidate: {exc}",
            "excerpt": "",
        }
    rc, out, err = _run(
        [
            "python3",
            str(UPSTREAM_GATE),
            "--workspace",
            str(ws),
            "--candidate",
            str(tmp_json),
            "--print-json",
            "--max-queries",
            "0",  # cheap: skip network gh-api calls
        ],
        timeout=60,
    )
    text = out or err
    # Status interpretation:
    #   rc 0 => promotion_allowed (all 5 checks pass)
    #   rc 1 => walked back / killed
    #   rc 2 => harness error
    if rc == 0:
        status = "pass"
    elif rc == 2:
        status = "skipped"
    else:
        status = "fail"
    return {
        "gate": "upstream-equivalent",
        "status": status,
        "rc": rc,
        "summary": _failure_summary(text) or f"rc={rc}",
        "excerpt": _excerpt(text, 8),
    }


def gate_poc_stub(md: Path) -> dict:
    rc, out, err = _run(["python3", str(POC_STUB), str(md)], timeout=30)
    text = out or err
    if rc == 0:
        status = "pass"
    elif rc == 2:
        status = "skipped"
    else:
        status = "fail"
    return {
        "gate": "poc-stub-coverage",
        "status": status,
        "rc": rc,
        "summary": _failure_summary(text) or f"rc={rc}",
        "excerpt": _excerpt(text, 6),
    }


# ---------------------------------------------------------------------------
# per-paste-ready driver
# ---------------------------------------------------------------------------

def run_all_gates(item: dict) -> dict:
    md: Path = item["path"]
    ws = workspace_for(md)
    severity = infer_severity(md.name)
    results: list[dict] = []
    results.append(gate_pre_submit(md, severity))
    results.append(gate_per_finding_oos(md, ws))
    results.append(gate_upstream_equivalent(md, ws))
    results.append(gate_poc_stub(md))

    # Annotate each failed gate with fix-effort.
    for r in results:
        if r["status"] == "fail":
            r["fix_effort"] = _classify_effort(r.get("summary", "") + " " + r.get("excerpt", ""))
        else:
            r["fix_effort"] = None

    fail_count = sum(1 for r in results if r["status"] == "fail")
    warn_count = sum(1 for r in results if r["status"] == "warn")
    return {
        "kind": item["kind"],
        "path": str(md),
        "name": md.name,
        "workspace": str(ws),
        "severity": severity,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "gate_clean": fail_count == 0,
        "gates": results,
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_md(payload: dict) -> str:
    rows = payload["rows"]
    lines: list[str] = []
    lines.append(f"# Validation Worklist — {payload['generated_at']}")
    lines.append("")
    lines.append(
        f"Scanned **{payload['total_rows']}** paste-readies "
        f"(paste_ready/current + staging) across **{payload['workspaces_seen']}** workspace(s). "
        f"**{payload['gate_clean_count']}** are gate-clean. "
        f"Packaged bundle dirs noted: **{payload['bundle_count']}** (informational only)."
    )
    lines.append("")
    lines.append("Gates run per paste-ready:")
    lines.append("- G1 `pre-submit-check.sh` — 35-check umbrella (severity inferred from filename)")
    lines.append("- G2 `per-finding-oos-check.py` — workspace OOS-clause match")
    lines.append("- G3 `upstream-equivalent-gate.py` — synthetic candidate built from md production_path")
    lines.append("- G4 `poc-stub-coverage-checker.py` — Stub/Mock coverage doc")
    lines.append("")
    lines.append("Statuses: `pass` / `fail` / `warn` / `skipped`. Fix-effort: `cosmetic` / `content` / `blocker`.")
    lines.append("")

    # Summary table
    lines.append("## Summary by paste-ready (sorted: severity, then fail_count desc)")
    lines.append("")
    lines.append("| # | severity | fails | warns | clean? | name | workspace |")
    lines.append("|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        clean = "yes" if r["gate_clean"] else "NO"
        ws = Path(r["workspace"]).name
        lines.append(
            f"| {i} | {r['severity']} | {r['fail_count']} | {r['warn_count']} | "
            f"{clean} | `{r['name']}` | {ws} |"
        )
    lines.append("")

    # Top-3 most-broken
    most_broken = sorted(rows, key=lambda r: (-r["fail_count"], SEV_ORDER.get(r["severity"], 9)))[:3]
    lines.append("## Top 3 most-broken paste-readies")
    lines.append("")
    for r in most_broken:
        lines.append(f"### `{r['name']}` ({r['severity']}, {r['fail_count']} failures)")
        lines.append(f"- path: `{r['path']}`")
        for g in r["gates"]:
            if g["status"] == "fail":
                eff = g.get("fix_effort") or "?"
                lines.append(f"- FAIL [{eff}] `{g['gate']}` — {g['summary']}")
        lines.append("")

    # Per-paste-ready detail
    lines.append("## Per-paste-ready detail")
    lines.append("")
    for r in rows:
        lines.append(f"### `{r['name']}` — {r['severity']} — fails={r['fail_count']}, warns={r['warn_count']}")
        lines.append(f"- path: `{r['path']}`")
        lines.append(f"- workspace: `{r['workspace']}`")
        for g in r["gates"]:
            badge = {"pass": "OK", "fail": "FAIL", "warn": "WARN", "skipped": "SKIP"}[g["status"]]
            eff = f" [{g['fix_effort']}]" if g.get("fix_effort") else ""
            lines.append(f"- {badge}{eff} `{g['gate']}` (rc={g['rc']}) — {g['summary']}")
            if g["status"] == "fail" and g.get("excerpt"):
                lines.append("")
                lines.append("  ```")
                for ln in g["excerpt"].splitlines():
                    lines.append("  " + ln)
                lines.append("  ```")
        lines.append("")

    # Final summary
    lines.append("## Final summary")
    lines.append("")
    lines.append(f"- Total paste-readies scanned: **{payload['total_rows']}**")
    lines.append(f"- Gate-clean (zero failures across G1..G4): **{payload['gate_clean_count']}**")
    sev_breakdown = payload["severity_breakdown"]
    lines.append(
        "- By severity: "
        + ", ".join(f"{k}={sev_breakdown.get(k, 0)}" for k in ("Critical", "High", "Medium", "Low"))
    )
    fix_total = payload["fix_effort_totals"]
    lines.append(
        "- Failures by fix-effort: "
        + f"blocker={fix_total['blocker']}, content={fix_total['content']}, cosmetic={fix_total['cosmetic']}"
    )
    lines.append("- Packaged bundles (not re-validated, listed for operator awareness):")
    for b in payload["bundles"]:
        lines.append(f"  - `{b}`")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Validation worklist builder (PR603 V-* support)")
    ap.add_argument("--max-workers", type=int, default=6)
    ap.add_argument("--out-dir", default=str(WORKLIST_DIR))
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    items = discover_paste_readies()
    bundles = [str(b) for b in discover_packaged_bundles()]

    print(f"[validation-worklist] discovered {len(items)} paste-readies, {len(bundles)} packaged bundles")
    print(f"[validation-worklist] running gates with up to {args.max_workers} workers...")

    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_item = {pool.submit(run_all_gates, item): item for item in items}
        for fut in as_completed(future_to_item):
            item = future_to_item[fut]
            try:
                rows.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                rows.append({
                    "kind": item["kind"],
                    "path": str(item["path"]),
                    "name": item["path"].name,
                    "workspace": str(workspace_for(item["path"])),
                    "severity": infer_severity(item["path"].name),
                    "fail_count": 99,
                    "warn_count": 0,
                    "gate_clean": False,
                    "gates": [{
                        "gate": "harness", "status": "fail", "rc": -1,
                        "summary": f"runner crashed: {exc}", "excerpt": "",
                        "fix_effort": "blocker",
                    }],
                })

    rows.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), -r["fail_count"], r["name"]))

    sev_breakdown: dict[str, int] = {}
    fix_totals = {"blocker": 0, "content": 0, "cosmetic": 0}
    for r in rows:
        sev_breakdown[r["severity"]] = sev_breakdown.get(r["severity"], 0) + 1
        for g in r["gates"]:
            if g["status"] == "fail":
                eff = g.get("fix_effort") or "content"
                fix_totals[eff] = fix_totals.get(eff, 0) + 1

    payload = {
        "schema": "auditooor.validation_worklist.v1",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_rows": len(rows),
        "workspaces_seen": len({r["workspace"] for r in rows}),
        "bundle_count": len(bundles),
        "bundles": bundles,
        "gate_clean_count": sum(1 for r in rows if r["gate_clean"]),
        "severity_breakdown": sev_breakdown,
        "fix_effort_totals": fix_totals,
        "rows": rows,
    }

    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = out_dir / f"VALIDATION_WORKLIST_{ts}.md"
    json_path = out_dir / f"VALIDATION_WORKLIST_{ts}.json"

    md_path.write_text(render_md(payload))
    json_path.write_text(json.dumps(payload, indent=2))

    print(f"[validation-worklist] wrote {md_path}")
    print(f"[validation-worklist] wrote {json_path}")
    print(
        f"[validation-worklist] total={payload['total_rows']} "
        f"gate_clean={payload['gate_clean_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
