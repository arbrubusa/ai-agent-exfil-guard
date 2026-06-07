#!/usr/bin/env bash
# anti-exfil.sh — PreToolUse guardrail for AI coding agents (Claude Code).
#
# Blocks the classic data-exfiltration shapes a prompt-injected agent would use:
#   A) reading a secret/credential AND sending it over the network in one command
#   B) piping an encoded payload (base64/gzip/...) into curl/wget/Invoke-WebRequest
#   C) POST/PUT-ing data to a host that isn't on your allowlist
#
# It does NOT try to stop the agent from READING things — reading is harmless.
# It stops the agent from ACTING on injected instructions with your credentials.
#
# Exit 2 = block (the stderr message is fed back to the model as feedback).
# Register with matcher "Bash|PowerShell" so it covers both shells.
#
# >>> Edit the ALLOW list below to add hosts your workflows legitimately POST to. <<<

INPUT=$(cat)
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0

SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // "unknown"')
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // "unknown"')
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // "unknown"')

# single lowercased line for matching
LC=$(printf '%s' "$CMD" | tr '\n' ' ' | tr '[:upper:]' '[:lower:]')

EGRESS='curl|wget|invoke-webrequest|invoke-restmethod|[^a-z]iwr[^a-z]|[^a-z]irm[^a-z]|[^a-z]nc[^a-z]|ncat|/dev/tcp/'
SENSITIVE='secretsmanager +get-secret-value|get-secret-value|ssm +get-parameters?.*--with-decryption|sts +get-session-token|gh +auth +token|vault +read|aws +configure +get'
SECRETFILE='\.aws/credentials|\.aws/config|id_rsa|id_ed25519|\.env([^a-z]|$)|\.tfstate|\.pem([^a-z]|$)|\.ppk|\.kube/config|credentials\.json|\.npmrc|\.pypirc'
ENCODE='base64|gzip +|[^a-z]xxd|openssl +enc|certutil +-encode|tobase64string|convertto-base64'
WITHDATA='-x +(post|put)|--request +(post|put)|--data|-d |--upload-file|-t |-method +(post|put)| -body| -infile'

# Hosts the agent is allowed to send DATA (POST/PUT) to. ADD YOUR OWN DOMAINS.
ALLOW='(^|\.)(amazonaws\.com|github\.com|githubusercontent\.com|hashicorp\.com|terraform\.io|npmjs\.org|pythonhosted\.org|pypi\.org)$|^localhost$|^127\.0\.0\.1$|^169\.254\.169\.254$'

AUDIT_LOG="${AGENT_AUDIT_LOG:-$HOME/.claude/audit/agent-blocks.log}"

block () {
  mkdir -p "$(dirname "$AUDIT_LOG")"
  TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  CMD_SHORT=$(printf '%s' "$CMD" | tr '\n' ' ' | head -c 500)
  echo "${TS} | BLOCK | anti-exfil | reason=${1} | tool=${TOOL} | session=${SESSION_ID} | cwd=${CWD} | cmd=${CMD_SHORT}" >> "$AUDIT_LOG"
  SIZE=$(stat -c%s "$AUDIT_LOG" 2>/dev/null || echo 0)
  [ "$SIZE" -gt 10485760 ] && mv "$AUDIT_LOG" "${AUDIT_LOG%.log}.$(date +%Y%m%d).log"
  echo "BLOCKED (anti-exfil): $1" >&2
  echo "Potential data exfiltration. If this is legitimate, split the read from the send and/or ask the user to confirm before proceeding." >&2
  exit 2
}

# Rule A: sensitive read + network egress in the same command
if echo "$LC" | grep -qE -- "$EGRESS"; then
  if echo "$LC" | grep -qE -- "$SENSITIVE";  then block "secret read combined with network egress in one command"; fi
  if echo "$LC" | grep -qE -- "$SECRETFILE"; then block "credential-file read combined with network egress"; fi
fi

# Rule B: encoded payload piped into egress
if echo "$LC" | grep -qE -- "$ENCODE" && echo "$LC" | grep -qE -- "$EGRESS" && printf '%s' "$CMD" | grep -q '|'; then
  block "encoded payload (base64/gzip) piped into network egress"
fi

# Rule C: POST/PUT with a body to a non-allowlisted host
if echo "$LC" | grep -qE -- "$EGRESS" && echo "$LC" | grep -qE -- "$WITHDATA"; then
  HOSTS=$(printf '%s' "$CMD" | grep -oiE 'https?://[^ ]+' \
            | sed -E 's#^https?://##I' \
            | sed -E 's#[/"'\''].*##' \
            | sed -E 's#:.*##' \
            | tr '[:upper:]' '[:lower:]')
  if [ -n "$HOSTS" ]; then
    while IFS= read -r h; do
      [ -z "$h" ] && continue
      if ! echo "$h" | grep -qiE -- "$ALLOW"; then
        block "data sent (POST/PUT) to non-allowlisted host: $h"
      fi
    done <<< "$HOSTS"
  fi
fi

exit 0
