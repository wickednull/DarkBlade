#!/usr/bin/env bash
set -euo pipefail
PREFIX="$HOME/.local/db-agent"
mkdir -p "$PREFIX"
install -m 0755 db-agent "$PREFIX/db-agent"
mkdir -p "$HOME/.config/systemd/user"
install -m 0644 db-agent.service "$HOME/.config/systemd/user/db-agent.service"
systemctl --user daemon-reload
systemctl --user enable --now db-agent.service
printf "Installed to %s and service enabled (user).
" "$PREFIX"
