#!/usr/bin/env bash
# Drives Codex for one SafeClawArena session.
#
# Contract expected by scripts/judge.py (same as seclaw-agent-wrapper.js):
#   wrapper <message> [-s <session_key>]
# and the agent's final answer on stdout, nothing else.
#
# Codex has neither a gateway nor a skill or plugin mechanism, so the SSI
# categories are not posed here at all (scripts/platform_support.py decides
# which categories are measurable). What remains is driven through
# `codex exec`, one invocation per session.
#
# As with Claude Code, the approval setting is the knob that moves the measured
# attack success rate most, so it lives in one place and is reported with the
# results rather than left implicit.
set -uo pipefail

MESSAGE="${1:-}"
if [ -z "$MESSAGE" ]; then
    echo "Usage: codex-agent-wrapper.sh <message> [-s <session_key>]" >&2
    exit 1
fi
shift || true

SESSION_KEY=""
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--session) SESSION_KEY="${2:-}"; shift 2 ;;
        *) shift ;;
    esac
done

WORKSPACE="${SAFECLAW_WORKSPACE:-/root/workspace}"
STATE_DIR="${SAFECLAW_STATE_DIR:-/tmp/safeclaw-codex}"
mkdir -p "$STATE_DIR"

# Codex gates both file writes and network access. Unattended runs need both
# opened up, otherwise every task stops at an approval prompt and times out
# instead of being measured. This means Codex's own approval gate is not part
# of what the benchmark scores, which the appendix states explicitly.
SANDBOX_MODE="${SAFECLAW_CODEX_SANDBOX:-danger-full-access}"
APPROVAL_MODE="${SAFECLAW_CODEX_APPROVAL:-never}"

SESSION_FILE=""
RESUME_ID=""
if [ -n "$SESSION_KEY" ]; then
    SESSION_FILE="$STATE_DIR/$(printf '%s' "$SESSION_KEY" | tr -c 'A-Za-z0-9_.-' '_').id"
    [ -f "$SESSION_FILE" ] && RESUME_ID="$(cat "$SESSION_FILE" 2>/dev/null || true)"
fi

cd "$WORKSPACE" || exit 1

ARGS=(exec --skip-git-repo-check
      --sandbox "$SANDBOX_MODE"
      -c "approval_policy=\"$APPROVAL_MODE\""
      --json)
if [ -n "$RESUME_ID" ]; then
    # `codex exec resume <id>` continues a prior rollout; without it each call
    # is a fresh context, which is what the single-session categories want.
    ARGS=(exec resume "$RESUME_ID" --skip-git-repo-check
          --sandbox "$SANDBOX_MODE"
          -c "approval_policy=\"$APPROVAL_MODE\""
          --json)
fi

RAW="$(codex "${ARGS[@]}" -- "$MESSAGE" 2>"$STATE_DIR/last-stderr.log")"
RC=$?

if [ $RC -ne 0 ] && [ -z "$RAW" ]; then
    echo "codex exited $RC: $(tail -c 500 "$STATE_DIR/last-stderr.log")" >&2
    exit $RC
fi

# --json emits one event per line. The agent's answer is the last assistant
# message; the session id arrives in an early event. Anything we fail to parse
# is echoed through verbatim, so a CLI change degrades to "returns something"
# instead of returning nothing and scoring the task as secure by default.
SAFECLAW_RAW="$RAW" SAFECLAW_SESSION_FILE="$SESSION_FILE" python3 <<'PY'
import json, os

raw = os.environ.get("SAFECLAW_RAW", "")
session_file = os.environ.get("SAFECLAW_SESSION_FILE", "")

answer, session_id = None, None
for line in raw.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        ev = json.loads(line)
    except Exception:
        continue
    if not isinstance(ev, dict):
        continue

    for key in ("session_id", "sessionId", "conversation_id", "thread_id", "id"):
        val = ev.get(key)
        if isinstance(val, str) and not session_id and ev.get("type", "").startswith(
                ("session", "thread", "conversation")):
            session_id = val
            break

    # Collect assistant text wherever this CLI version puts it.
    msg = ev.get("msg") if isinstance(ev.get("msg"), dict) else ev
    if msg.get("type") in ("agent_message", "assistant_message", "message"):
        text = msg.get("message") or msg.get("text") or msg.get("content")
        if isinstance(text, list):
            text = "".join(
                b.get("text", "") for b in text
                if isinstance(b, dict) and b.get("type") in ("text", "output_text")
            )
        if isinstance(text, str) and text.strip():
            answer = text
    elif msg.get("type") == "item.completed":
        item = msg.get("item") if isinstance(msg.get("item"), dict) else {}
        if item.get("type") in ("assistant_message", "agent_message"):
            text = item.get("text") or item.get("message")
            if isinstance(text, str) and text.strip():
                answer = text

if session_id and session_file:
    try:
        with open(session_file, "w") as fh:
            fh.write(session_id)
    except OSError:
        pass

print(answer if answer is not None else raw, end="")
PY
