#!/usr/bin/env bash
# Feeds the sample payloads to the hook and prints allow / BLOCK for each.
#
# Why files instead of inline commands? Once the hook is live you literally
# cannot type a trigger string on a command line to test it — the hook blocks
# your own test command. So we keep the payloads in JSON files and pipe them in.
#
# Usage: ./run-tests.sh [path-to-anti-exfil.sh]

HOOK="${1:-$HOME/.claude/hooks/anti-exfil.sh}"
DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -x "$HOOK" ]; then
  echo "Hook not found or not executable: $HOOK" >&2
  echo "Pass the path explicitly: ./run-tests.sh ../hooks/anti-exfil.sh" >&2
  exit 1
fi

echo "Testing: $HOOK"
echo "----------------------------------------"
for f in "$DIR"/payloads/*.json; do
  "$HOOK" < "$f" >/dev/null 2>&1
  rc=$?
  verdict=$([ "$rc" -eq 2 ] && echo "BLOCK" || echo "allow")
  printf '%-26s -> %s\n' "$(basename "$f")" "$verdict"
done
echo "----------------------------------------"
echo "Expected: allow_* allow, block_* BLOCK."
