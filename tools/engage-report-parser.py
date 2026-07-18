#!/usr/bin/env python3
"""engage-report-parser — parse <ws>/engage_report.md into structured JSON.

Produced by `make audit WS=<ws>` (tools/engage.py).  This parser handles
the format variations that have evolved across loop iterations while keeping
zero external dependencies (stdlib regex only).

Usage:
    python3 tools/engage-report-parser.py <ws>/engage_report.md [--out parsed.json]

Output schema (auditooor.engage_report_parsed.v1):
{
  "schema": "auditooor.engage_report_parsed.v1",
  "workspace": "/Users/wolf/audits/morpho",
  "total_hits": 50,
  "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 50},
  "distinct_detectors": 24,
  "clusters": [
    {
      "cluster_name": "setters-with-no-access-control",
      "hits": [
        {
          "severity": "LOW",
          "detector_id": "setters-with-no-access-control",
          "file_path": "/Users/wolf/audits/morpho/src/vault-v2/src/VaultV2.sol",
          "line": 306,
          "snippet": "function setOwner(address newOwner) external {",
          "dupe_risk": "SKIPPED",
          "cross_ws": null
        }
      ]
    }
  ]
}

Backward-compat:
  - Missing file → returns empty struct (no crash).
  - Missing header fields → defaults to 0 / empty.
  - Cluster with no parseable hits → cluster retained with empty hits list.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Regex patterns for the engage_report.md format variants
# ---------------------------------------------------------------------------

# Header: "- Workspace: `/Users/wolf/audits/morpho`"
RX_WORKSPACE = re.compile(r"^[-*]\s*Workspace:\s*`?(.+?)`?\s*$", re.MULTILINE)

# Header: "- Total hits: **50**"
RX_TOTAL_HITS = re.compile(r"Total hits:\s*\*{0,2}(\d+)\*{0,2}", re.MULTILINE)

# Header: "- Severity: HIGH=0  MEDIUM=0  LOW=50"
RX_SEVERITY = re.compile(
    r"Severity:\s+HIGH=(\d+)\s+MEDIUM=(\d+)\s+LOW=(\d+)",
    re.MULTILINE,
)

# Header: "- Distinct detectors: 24"
RX_DISTINCT_DETECTORS = re.compile(
    r"Distinct detectors:\s*\*{0,2}(\d+)\*{0,2}",
    re.MULTILINE,
)

# Cluster header variant A: "### Cluster: `setters-with-no-access-control` (3 hits)"
# Cluster header variant B: "### Cluster: setters-with-no-access-control (3 hits)"
RX_CLUSTER_HEADER = re.compile(
    r"^###\s+Cluster:\s+`?([^`\n(]+?)`?\s*\((\d+)\s+hits?\)",
    re.MULTILINE,
)

# Hit line: "- **[LOW] `setters-with-no-access-control`** — `/path/file.sol:306`"
#   or:      "- **[HIGH] `detector-id`** — `/path/file.sol:10`"
RX_HIT_LINE = re.compile(
    r"^\s*[-*]\s+\*{0,2}\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\]"
    r"\s+`(?P<detector>[^`]+)`\*{0,2}"
    r"\s+[-—]+\s+"
    r"`(?P<file_path>[^`:]+):(?P<line>\d+)`",
    re.MULTILINE,
)

# Hit line alt: no detector id bracket style, just severity:
# "- [LOW] `/path/file.sol:306` — snippet..."
RX_HIT_LINE_ALT = re.compile(
    r"^\s*[-*]\s+\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\]\s+"
    r"`(?P<file_path>[^`:]+):(?P<line>\d+)`",
    re.MULTILINE,
)

# Snippet line: "  - snippet: `function setOwner(...)`"
#   or:         "  - snippet: function setOwner(...)"
RX_SNIPPET = re.compile(
    r"^\s*[-*]\s+snippet:\s+`?(.+?)`?\s*$",
    re.MULTILINE,
)

# Dupe-risk line: "  - dupe-risk: **SKIPPED**"
RX_DUPE_RISK = re.compile(
    r"^\s*[-*]\s+dupe[-_ ]risk:\s+\*{0,2}([^\*\n]+?)\*{0,2}\s*$",
    re.MULTILINE,
)

# Cross-ws line: "  - cross-ws: (lookup SKIPPED)"  OR  "- cross-ws: /path..."
RX_CROSS_WS = re.compile(
    r"^\s*[-*]\s+cross[-_ ]ws:\s+(.+?)\s*$",
    re.MULTILINE,
)


def _clean_cross_ws(val: str) -> Optional[str]:
    """Return None for empty / SKIPPED / parenthetical placeholder."""
    val = val.strip()
    if not val:
        return None
    if re.match(r"^\(.*SKIPPED.*\)$", val, re.IGNORECASE):
        return None
    if val.lower() in ("none", "null", "~", "(none)", "(n/a)"):
        return None
    return val


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_engage_report(path: Path) -> Dict[str, Any]:
    """Parse engage_report.md at `path`.  Returns empty struct on missing file."""
    empty = {
        "schema": "auditooor.engage_report_parsed.v1",
        "workspace": "",
        "total_hits": 0,
        "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "distinct_detectors": 0,
        "clusters": [],
        "source_path": str(path),
        "parse_ok": False,
    }
    if not path.exists():
        empty["error"] = "file not found"
        return empty

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        empty["error"] = str(e)
        return empty

    # ---- Header fields ----
    ws_m = RX_WORKSPACE.search(text)
    workspace = ws_m.group(1).strip() if ws_m else ""

    hits_m = RX_TOTAL_HITS.search(text)
    total_hits = int(hits_m.group(1)) if hits_m else 0

    sev_m = RX_SEVERITY.search(text)
    if sev_m:
        by_severity = {
            "HIGH": int(sev_m.group(1)),
            "MEDIUM": int(sev_m.group(2)),
            "LOW": int(sev_m.group(3)),
        }
    else:
        by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    det_m = RX_DISTINCT_DETECTORS.search(text)
    distinct_detectors = int(det_m.group(1)) if det_m else 0

    # ---- Clusters ----
    # Strip the "No close historical match" trailing section so its
    # de-duplicated hit list doesn't bleed into cluster parsing.
    # The section begins with "## No close historical match" (exact) or
    # similar H2 headers that are not "## Clusters".
    _TRAILING_SECTION_RX = re.compile(
        r"^##\s+No\s+close\s+historical|^##\s+Recommended",
        re.MULTILINE,
    )
    _trail_m = _TRAILING_SECTION_RX.search(text)
    cluster_text = text[: _trail_m.start()] if _trail_m else text

    # Split text into per-cluster chunks by finding cluster-header positions.
    cluster_starts = [
        (m.start(), m.end(), m.group(1).strip(), int(m.group(2)))
        for m in RX_CLUSTER_HEADER.finditer(cluster_text)
    ]

    clusters: List[Dict[str, Any]] = []

    for idx, (start, header_end, cluster_name, expected_hits) in enumerate(cluster_starts):
        # Text segment for this cluster: from header_end to next cluster_start (or EOF)
        seg_end = cluster_starts[idx + 1][0] if idx + 1 < len(cluster_starts) else len(cluster_text)
        segment = cluster_text[header_end:seg_end]

        hits: List[Dict[str, Any]] = []

        # Find all hit lines in this segment
        for hm in RX_HIT_LINE.finditer(segment):
            severity = hm.group("severity").upper()
            # Normalize INFORMATIONAL / INFO → LOW (engage.py always emits LOW)
            if severity in ("INFO", "INFORMATIONAL"):
                severity = "LOW"
            detector_id = hm.group("detector").strip()
            file_path = hm.group("file_path").strip()
            line_num = int(hm.group("line"))

            # Look for snippet + dupe-risk + cross-ws in the lines immediately
            # following this hit (within ~200 chars to avoid bleeding).
            after = segment[hm.end(): hm.end() + 400]

            snippet_m = RX_SNIPPET.search(after)
            snippet = snippet_m.group(1).strip() if snippet_m else ""

            dupe_m = RX_DUPE_RISK.search(after)
            dupe_risk = dupe_m.group(1).strip() if dupe_m else None

            cws_m = RX_CROSS_WS.search(after)
            cross_ws = _clean_cross_ws(cws_m.group(1)) if cws_m else None

            hits.append({
                "severity": severity,
                "detector_id": detector_id,
                "file_path": file_path,
                "line": line_num,
                "snippet": snippet,
                "dupe_risk": dupe_risk,
                "cross_ws": cross_ws,
            })

        # Fallback: alt hit format (no detector-id bracket)
        if not hits:
            for hm in RX_HIT_LINE_ALT.finditer(segment):
                severity = hm.group("severity").upper()
                if severity in ("INFO", "INFORMATIONAL"):
                    severity = "LOW"
                file_path = hm.group("file_path").strip()
                line_num = int(hm.group("line"))
                after = segment[hm.end(): hm.end() + 400]
                snippet_m = RX_SNIPPET.search(after)
                hits.append({
                    "severity": severity,
                    "detector_id": cluster_name,
                    "file_path": file_path,
                    "line": line_num,
                    "snippet": snippet_m.group(1).strip() if snippet_m else "",
                    "dupe_risk": None,
                    "cross_ws": None,
                })

        clusters.append({
            "cluster_name": cluster_name,
            "expected_hits": expected_hits,
            "hits": hits,
        })

    # Recompute by_severity from parsed hits (more reliable than header when
    # the header has rounding issues across format versions).
    if clusters:
        recounted: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        actual_hits = 0
        for cl in clusters:
            for h in cl["hits"]:
                sev = h["severity"]
                recounted[sev] = recounted.get(sev, 0) + 1
                actual_hits += 1
        # Prefer header total_hits (includes clusters we may not have parsed
        # in the "No close historical match" section duplicates), but use
        # recounted severity breakdowns for accuracy.
        by_severity = recounted

    return {
        "schema": "auditooor.engage_report_parsed.v1",
        "workspace": workspace,
        "total_hits": total_hits,
        "by_severity": by_severity,
        "distinct_detectors": distinct_detectors,
        "clusters": clusters,
        "source_path": str(path),
        "parse_ok": True,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    import argparse as _ap
    p = _ap.ArgumentParser(
        description="Parse engage_report.md into structured JSON.",
    )
    p.add_argument("report_path",
                   help="Path to <ws>/engage_report.md")
    p.add_argument("--out", default=None,
                   help="Output JSON path (default: stdout)")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    result = parse_engage_report(Path(args.report_path))
    output = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"[engage-report-parser] wrote {args.out}")
    else:
        print(output)
    return 0 if result.get("parse_ok") else 1


if __name__ == "__main__":
    sys.exit(main())
