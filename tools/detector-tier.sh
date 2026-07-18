#!/usr/bin/env bash
# detector-tier.sh — manage detector promotion ladder (Issue #76)
#
# Tiers:
#   S — Shipped: real-target wins, default-run
#   E — Evaluated: has fixtures, opt-in via --tier=E
#   D — Draft: unvalidated, opt-in via --tier=D
#
# Usage:
#   ./tools/detector-tier.sh list [S|E|D|all]       # list detectors by tier
#   ./tools/detector-tier.sh show <detector>         # tier + reason + ledger
#   ./tools/detector-tier.sh promote <detector>     # D→E (requires fixtures)
#   ./tools/detector-tier.sh ship <detector>        # E→S (requires real catch)
#   ./tools/detector-tier.sh demote <detector>     # S→E or E→D
#   ./tools/detector-tier.sh audit                  # auto-promote/demote by ledger
#   ./tools/detector-tier.sh stats                  # counts per tier
#
# Reads _tier_registry.yaml + _hits_ledger.yaml.

set -uo pipefail
AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REGISTRY="$AUDITOOOR_DIR/detectors/_tier_registry.yaml"
LEDGER="$AUDITOOOR_DIR/detectors/_hits_ledger.yaml"
DET_DIR="$AUDITOOOR_DIR/detectors"

# Require python3 with yaml
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "[error] PyYAML required. Run: pip3 install pyyaml" >&2
    exit 1
fi

CMD="${1:-stats}"
shift 2>/dev/null || true

_list_argument_names() {
    # Extract every detector's ARGUMENT = "..." line across active wave*/ dirs.
    # Exclude wave_graveyard/ and *_broken/ so they don't count against tiers.
    find "$DET_DIR" -maxdepth 2 -name "*.py" \
        -not -path "*wave_graveyard*" \
        -not -path "*_broken*" \
        -not -name "_*" \
        2>/dev/null | xargs grep -hE '^\s*ARGUMENT\s*=\s*"' 2>/dev/null | \
        sed -E 's/^\s*ARGUMENT\s*=\s*"([^"]+)".*/\1/' | sort -u
}

_py() {
    # Invoke python with the registry + ledger already loaded.
    # $1 = names file (list of detector ARGUMENT names, one per line)
    python3 - "$REGISTRY" "$LEDGER" "$@" <<'PY'
import sys, yaml
from pathlib import Path

registry_path = Path(sys.argv[1])
ledger_path = Path(sys.argv[2])
names_file = Path(sys.argv[3]) if len(sys.argv) > 3 else None
subcmd = sys.argv[4] if len(sys.argv) > 4 else ""
args = sys.argv[5:]

registry = yaml.safe_load(registry_path.read_text()) if registry_path.exists() else {"version": 1, "tiers": {}}
ledger = yaml.safe_load(ledger_path.read_text()) if ledger_path.exists() else {"version": 1, "detectors": {}}

tiers = registry.get("tiers", {}) or {}
dets_ledger = ledger.get("detectors", {}) or {}

def get_tier(name):
    entry = tiers.get(name)
    return entry["tier"] if entry else "D"

def get_reason(name):
    entry = tiers.get(name)
    return entry.get("reason", "") if entry else "default (unlisted = Draft)"

def precision_of(name):
    l = dets_ledger.get(name)
    if not l:
        return None
    return l.get("precision", 0.0)

def caught_count(name):
    l = dets_ledger.get(name)
    if not l:
        return 0
    return len(l.get("real_catches", []))

if subcmd == "show":
    name = args[0]
    tier = get_tier(name)
    reason = get_reason(name)
    prec = precision_of(name)
    catches = caught_count(name)
    print(f"  Detector: {name}")
    print(f"  Tier:     {tier}")
    print(f"  Reason:   {reason}")
    if prec is not None:
        l = dets_ledger[name]
        print(f"  Ledger:   {l.get('tp',0)} TP / {l.get('fp',0)} FP / {l.get('unknown',0)} unknown  (precision={prec:.2f})")
    else:
        print(f"  Ledger:   no triage data yet")
    print(f"  Catches:  {catches} real-target wins")
    sys.exit(0)

if subcmd == "list":
    filt = args[0].upper() if args else "ALL"
    # All detector names
    from subprocess import run, PIPE
    # Get names from registry + ledger + scan detector files via shell caller
    all_names = set(tiers.keys()) | set(dets_ledger.keys())
    # Also read names file for the unlisted-D count
    if names_file and names_file.exists():
        for n in names_file.read_text().strip().split("\n"):
            if n:
                all_names.add(n)
    rows = []
    for n in sorted(all_names):
        t = get_tier(n)
        if filt != "ALL" and t != filt:
            continue
        prec = precision_of(n) or 0.0
        catches = caught_count(n)
        rows.append((t, n, f"{prec:.2f}", str(catches)))
    # Print as table
    widths = [1, max((len(r[1]) for r in rows), default=20), 4, 2]
    print(f"  {'T':<{widths[0]}}  {'DETECTOR':<{widths[1]}}  {'PREC':<{widths[2]}}  {'WINS'}")
    print(f"  {'-'*widths[0]}  {'-'*widths[1]}  {'-'*widths[2]}  ----")
    for r in rows:
        print(f"  {r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}")
    print(f"\n  {len(rows)} detectors shown")
    sys.exit(0)

if subcmd == "stats":
    counts = {"S": 0, "E": 0, "D": 0}
    known = set(tiers.keys())
    # Named in registry
    for name, e in tiers.items():
        counts[e["tier"]] = counts.get(e["tier"], 0) + 1
    all_names_pipe = []
    if names_file and names_file.exists():
        all_names_pipe = [n for n in names_file.read_text().strip().split("\n") if n]
    unlisted = [n for n in all_names_pipe if n not in known]
    counts["D"] += len(unlisted)
    total = sum(counts.values())
    print(f"  Tier S (Shipped):   {counts['S']:4d}")
    print(f"  Tier E (Evaluated): {counts['E']:4d}")
    print(f"  Tier D (Draft):     {counts['D']:4d}  ({len(tiers.keys()) - counts['S'] - counts['E']} listed + {len(unlisted)} unlisted)")
    print(f"  Total detectors:    {total:4d}")
    sys.exit(0)

if subcmd in ("promote", "ship", "demote"):
    name = args[0]
    cur = get_tier(name)
    new = None
    if subcmd == "promote":
        if cur == "D":
            new = "E"
        elif cur == "E":
            new = "S"
        else:
            print(f"  [error] {name} is already Tier S — cannot promote further")
            sys.exit(1)
    elif subcmd == "ship":
        new = "S"
    elif subcmd == "demote":
        if cur == "S":
            new = "E"
        elif cur == "E":
            new = "D"
        else:
            # Removing from registry falls back to D default
            if name in tiers:
                del tiers[name]
            registry["tiers"] = tiers
            registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))
            print(f"  [ok] {name} removed from registry (default = D)")
            sys.exit(0)
    if new:
        reason = args[1] if len(args) > 1 else f"promoted by detector-tier.sh to {new}"
        entry = tiers.get(name) or {}
        entry["tier"] = new
        entry.setdefault("reason", reason)
        entry["reason"] = reason  # always update
        import datetime
        entry["last_promoted"] = datetime.date.today().isoformat()
        tiers[name] = entry
        registry["tiers"] = tiers
        registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))
        print(f"  [ok] {name}: {cur} → {new}  ({reason})")
    sys.exit(0)

if subcmd == "audit":
    # Auto-promote/demote based on ledger precision.
    import datetime
    thresholds = registry.get("promotion_thresholds", {
        "S": {"min_precision": 0.5, "min_triaged": 3, "min_real_catches": 1},
        "E": {"requires_fixture_pair": True, "min_fires_on_target": 1},
    })
    changed = 0
    for name, lentry in dets_ledger.items():
        cur = get_tier(name)
        tp = lentry.get("tp", 0)
        fp = lentry.get("fp", 0)
        triaged = tp + fp
        prec = (tp / triaged) if triaged > 0 else 0.0
        catches = len(lentry.get("real_catches", []))
        new = cur
        # Promote to S?
        sth = thresholds["S"]
        if (prec >= sth["min_precision"] and
            triaged >= sth["min_triaged"] and
            catches >= sth["min_real_catches"] and
            cur != "S"):
            new = "S"
        # Demote to D if precision tanks
        elif triaged >= 5 and prec < 0.1 and cur != "D":
            new = "D"
        if new != cur:
            entry = tiers.get(name) or {}
            entry["tier"] = new
            entry["reason"] = f"auto-audit: precision={prec:.2f}, triaged={triaged}, catches={catches}"
            entry["last_promoted"] = datetime.date.today().isoformat()
            tiers[name] = entry
            changed += 1
            print(f"  [auto] {name}: {cur} → {new}  (prec={prec:.2f}, triaged={triaged}, catches={catches})")
    if changed:
        registry["tiers"] = tiers
        registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))
        print(f"\n  [ok] {changed} tier changes applied")
    else:
        print(f"  [ok] no changes — all detectors at correct tier per ledger")
    sys.exit(0)

print(f"Unknown subcommand: {subcmd}")
sys.exit(2)
PY
}

case "$CMD" in
    list|show|stats|promote|ship|demote|audit)
        # Dump detector argument names to a temp file for the python side.
        NAMES_FILE=$(mktemp -t auditooor_names.XXXXXX)
        trap "rm -f $NAMES_FILE" EXIT
        _list_argument_names > "$NAMES_FILE"
        _py "$NAMES_FILE" "$CMD" "$@"
        ;;
    help|--help|-h)
        sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
        ;;
    *)
        echo "Unknown command: $CMD" >&2
        echo "Run: $0 help" >&2
        exit 1
        ;;
esac
