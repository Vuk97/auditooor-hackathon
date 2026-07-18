#!/usr/bin/env bash
# install-privacy-audit-launchd.sh — ACT-20
#
# Wire a daily 03:00 local privacy audit run as a macOS launchd LaunchAgent.
# The audit scans obsidian-vault/ for leaked secrets and writes a report to
# reports/vault_privacy_audit_<date>.json.
#
# Usage:
#   bash tools/install-privacy-audit-launchd.sh [--repo-root <path>]
#
# Default repo root: the directory containing this script's parent (i.e.
# the auditooor repo root).  Override with --repo-root.
#
# Idempotent: running twice replaces the existing plist.
#
# To uninstall:
#   launchctl unload ~/Library/LaunchAgents/com.auditooor.privacy-audit.plist
#   rm ~/Library/LaunchAgents/com.auditooor.privacy-audit.plist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLIST_LABEL="com.auditooor.privacy-audit"
PLIST_PATH="${HOME}/Library/LaunchAgents/${PLIST_LABEL}.plist"
LOG_DIR="/tmp/auditooor-privacy-audit"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# Resolve paths
PYTHON3="$(command -v python3)"
TOOL="${REPO_ROOT}/tools/memory-privacy-audit.py"
VAULT="${REPO_ROOT}/obsidian-vault"
WHITELIST="${REPO_ROOT}/reports/privacy_audit_whitelist.yaml"

echo "Repo root  : ${REPO_ROOT}"
echo "Tool       : ${TOOL}"
echo "Vault      : ${VAULT}"
echo "Plist      : ${PLIST_PATH}"
echo "Log dir    : ${LOG_DIR}"

mkdir -p "${LOG_DIR}"
mkdir -p "$(dirname "${PLIST_PATH}")"

# Unload existing if present (ignore errors)
launchctl unload "${PLIST_PATH}" 2>/dev/null || true

cat > "${PLIST_PATH}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON3}</string>
        <string>${TOOL}</string>
        <string>--vault</string>
        <string>${VAULT}</string>
        <string>--whitelist</string>
        <string>${WHITELIST}</string>
    </array>

    <!-- Daily at 03:00 local time -->
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>3</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>

    <key>WorkingDirectory</key>
    <string>${REPO_ROOT}</string>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/stdout.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/stderr.log</string>

    <!-- Run missed jobs when machine wakes (e.g. if 03:00 was during sleep) -->
    <key>RunAtLoad</key>
    <false/>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>
</dict>
</plist>
PLIST

launchctl load "${PLIST_PATH}"
echo ""
echo "Installed: ${PLIST_PATH}"
echo "Scheduled: daily at 03:00 local time"
echo "Logs     : ${LOG_DIR}/stdout.log + stderr.log"
echo ""
echo "To test immediately:"
echo "  launchctl start ${PLIST_LABEL}"
echo "To uninstall:"
echo "  launchctl unload ${PLIST_PATH} && rm ${PLIST_PATH}"
