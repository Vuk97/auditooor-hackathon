#!/usr/bin/env bash
# install-pipeline-supervision.sh — T-08.
#
# Install OS-level cron supervision (launchd on macOS, systemd-user/cron on
# Linux) for any auditooor pipeline that runs longer than 1 hour. Scripts
# tracked by supervision MUST live in TCC-unprotected paths on macOS
# (/private/tmp/, /usr/local/bin/) — NOT ~/Documents/.
#
# Usage:
#   bash tools/install-pipeline-supervision.sh \
#     --label com.auditooor.heartbeat \
#     --script /private/tmp/auditooor-overnight/heartbeat.sh \
#     --interval 300 \
#     [--linux]   # force Linux mode
#
# Idempotent: if a unit/plist already exists, replaces it.

set -uo pipefail

LABEL=""
SCRIPT=""
INTERVAL=300
FORCE_LINUX=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)    LABEL="$2"; shift 2 ;;
    --script)   SCRIPT="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --linux)    FORCE_LINUX=1; shift ;;
    -h|--help)
      echo "Usage: $0 --label <com.example.task> --script <abs-path> --interval <seconds> [--linux]"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$LABEL" ]] && { echo "missing --label" >&2; exit 2; }
[[ -z "$SCRIPT" ]] && { echo "missing --script" >&2; exit 2; }
[[ ! -x "$SCRIPT" ]] && { echo "script not executable: $SCRIPT" >&2; exit 2; }

OS="$(uname -s)"
if [[ "$FORCE_LINUX" -eq 1 ]] || [[ "$OS" == "Linux" ]]; then
  # ----- Linux: prefer systemd-user, fall back to cron -----
  if command -v systemctl >/dev/null 2>&1 && systemctl --user --version >/dev/null 2>&1; then
    UNIT_DIR="${HOME}/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/${LABEL}.service" <<EOF
[Unit]
Description=auditooor pipeline supervision: $LABEL

[Service]
Type=oneshot
ExecStart=$SCRIPT
EOF
    cat > "$UNIT_DIR/${LABEL}.timer" <<EOF
[Unit]
Description=auditooor pipeline supervision timer: $LABEL

[Timer]
OnUnitActiveSec=${INTERVAL}s
OnBootSec=${INTERVAL}s
Unit=${LABEL}.service

[Install]
WantedBy=timers.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "${LABEL}.timer"
    echo "[install] systemd-user timer enabled: ${LABEL}.timer (every ${INTERVAL}s)"
    echo "[install] check status: systemctl --user list-timers ${LABEL}.timer"
  else
    # cron fallback
    LINE="*/$((INTERVAL / 60)) * * * * $SCRIPT"
    if [[ "$INTERVAL" -lt 60 ]]; then
      echo "[install] WARN: cron min granularity is 1 minute; using every-minute schedule" >&2
      LINE="* * * * * $SCRIPT"
    fi
    # Idempotent: drop any existing line with same script path, re-add
    (crontab -l 2>/dev/null | grep -vF "$SCRIPT"; echo "$LINE") | crontab -
    echo "[install] cron line installed: $LINE"
    echo "[install] check: crontab -l"
  fi
  exit 0
fi

# ----- macOS: launchd -----
PLIST_DIR="${HOME}/Library/LaunchAgents"
mkdir -p "$PLIST_DIR"
PLIST="$PLIST_DIR/${LABEL}.plist"

# Compute log paths inside the same dir as the script (must be TCC-unprotected)
SCRIPT_DIR="$(dirname "$SCRIPT")"
STDOUT_LOG="$SCRIPT_DIR/$(basename "$SCRIPT" .sh).launchd.log"
STDERR_LOG="$SCRIPT_DIR/$(basename "$SCRIPT" .sh).launchd.err"

# Verify script path is TCC-unprotected
case "$SCRIPT" in
  "$HOME"/Documents/*|"$HOME"/Desktop/*|"$HOME"/Downloads/*)
    echo "[install] WARN: script lives in TCC-protected dir ($SCRIPT)." >&2
    echo "[install] launchd may fail with 'Operation not permitted' unless this app has Full Disk Access." >&2
    echo "[install] RECOMMENDED: copy the script to /private/tmp/<workdir>/ or /usr/local/bin/ first." >&2 ;;
esac

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${SCRIPT}</string>
    </array>
    <key>StartInterval</key>
    <integer>${INTERVAL}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${STDOUT_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${STDERR_LOG}</string>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>
</dict>
</plist>
EOF

# Reload (unload existing, then load)
launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load "$PLIST"
echo "[install] launchd plist installed: $PLIST"
echo "[install] check status: launchctl list | grep $LABEL"
echo "[install] check fires:  tail $STDOUT_LOG"
