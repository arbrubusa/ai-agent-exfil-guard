#!/usr/bin/env bash
# webfetch-allowlist.sh — PreToolUse guardrail for the WebFetch tool (Claude Code).
#
# Fetching a page from a domain that isn't on your allowlist requires human
# confirmation (permissionDecision: "ask"). This shrinks the indirect-prompt-
# injection surface: the agent can't silently pull arbitrary web content — and
# any instructions hidden inside it — without you deciding to.
#
# Register with matcher "WebFetch".
#
# >>> Edit the ALLOW list to match the domains you trust by default. <<<

INPUT=$(cat)
URL=$(printf '%s' "$INPUT" | jq -r '.tool_input.url // empty')
[ -z "$URL" ] && exit 0

HOST=$(printf '%s' "$URL" \
        | sed -E 's#^[a-zA-Z]+://##' \
        | sed -E 's#[/?#].*##' \
        | sed -E 's#:.*##' \
        | tr '[:upper:]' '[:lower:]')

# Domains fetched silently. Everything else asks for confirmation.
ALLOW='(^|\.)(amazonaws\.com|aws\.amazon\.com|github\.com|githubusercontent\.com|hashicorp\.com|terraform\.io|pypi\.org|python\.org|kubernetes\.io|docker\.com|anthropic\.com|claude\.com|stackoverflow\.com|developer\.mozilla\.org)$'

if echo "$HOST" | grep -qiE -- "$ALLOW"; then
  exit 0
fi

cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"WebFetch to a non-allowlisted domain ($HOST). Confirm you trust the source before reading it (prompt-injection / exfiltration risk via page content)."}}
EOF
exit 0
