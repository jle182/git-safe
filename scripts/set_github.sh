#!/usr/bin/env bash
# One-time: replace the jle182 placeholder everywhere.
# usage: ./scripts/set_github.sh your-github-username
set -euo pipefail
[ "$#" -eq 1 ] || { echo "usage: $0 <github-username>"; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
U="$1"
grep -rl 'jle182' "$ROOT" --include='*.py' --include='*.sh' --include='*.md' --include='*.js' --include='*.html' |
  while read -r f; do sed -i "s/jle182/$U/g" "$f"; echo "updated: ${f#$ROOT/}"; done
echo "done — repo is now github.com/$U/git-safe"
