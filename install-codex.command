#!/bin/zsh
set -euo pipefail

ROOT_DIR="${0:A:h}"

python3 "$ROOT_DIR/scripts/install_codex.py"

if [[ "${1:-}" != "--yes" ]]; then
  printf "Install Agent Content Firewall for Codex only? [y/N] "
  read -r reply
  if [[ "$reply" != "y" && "$reply" != "Y" ]]; then
    printf "Installation cancelled.\n"
    exit 0
  fi
fi

python3 "$ROOT_DIR/scripts/install_codex.py" --apply
printf "Installation complete. Fully quit and restart Codex, then open a new task.\n"
