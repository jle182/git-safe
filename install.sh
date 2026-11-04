#!/bin/sh
# git-safe installer — puts the `git-safe` executable on your PATH.
# `git-safe` on PATH == `git safe` in your terminal (git subcommand magic).
set -eu

REPO="${GITSAFE_REPO:-jle182/git-safe}"
DEST="${GITSAFE_DEST:-$HOME/.local/bin}"
URL="https://github.com/$REPO/releases/latest/download/git-safe.pyz"

command -v curl >/dev/null 2>&1 || { echo "curl is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 (3.9+) is required"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required"; exit 1; }

mkdir -p "$DEST"
echo "downloading git-safe from $URL"
curl -fsSL "$URL" -o "$DEST/git-safe"
chmod +x "$DEST/git-safe"

case ":$PATH:" in
  *":$DEST:"*) ;;
  *) echo "note: add $DEST to your PATH — add this to ~/.bashrc or ~/.zshrc:"
     echo "      export PATH=\"$DEST:\$PATH\"" ;;
esac

echo
echo "installed: $DEST/git-safe"
echo "try it:    git safe owner/repo"
