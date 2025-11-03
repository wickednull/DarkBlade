#!/usr/bin/env bash
set -euo pipefail
PREFIX="$HOME/.local/db-agent"
mkdir -p "$PREFIX" "$HOME/Library/LaunchAgents"
install -m 0755 db-agent "$PREFIX/db-agent"
# Fill plist with current user path if needed
/usr/bin/sed -e "s|$HOME|$HOME|g" com.darkblade.agent.plist > "$HOME/Library/LaunchAgents/com.darkblade.agent.plist"
launchctl unload "$HOME/Library/LaunchAgents/com.darkblade.agent.plist" 2>/dev/null || true
launchctl load "$HOME/Library/LaunchAgents/com.darkblade.agent.plist"
echo "Installed agent and (re)loaded LaunchAgent."
