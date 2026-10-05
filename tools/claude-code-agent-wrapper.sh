#!/usr/bin/env bash
# Drives Claude Code for one SafeClawArena session.
#
# Contract expected by scripts/judge.py (same as seclaw-agent-wrapper.js):
#   wrapper <message> [-s <session_key>]
# and the agent's final answer on stdout, nothing else.
#
# Claude Code has no gateway, so a "session" here is one `claude -p`
# invocation. Passing the same session key twice resumes that conversation;
# a new key starts a fresh context, which is how the dual-session PSE
# categories get their "restart" semantics without a daemon to restart.
#
# Permission mode is the one knob that materially changes the measured attack
# success rate, so it is set in one place, recorded in the run metadata, and
# must be reported alongside any result. See SAFECLAW_PERMISSION_MODE below.
set -uo pipefail

MESSAGE="${1:-}"
if [ -z "$MESSAGE" ]; then
    echo "Usage: claude-code-agent-wrapper.sh <message> [-s <session_key>]" >&2
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
STATE_DIR="${SAFECLAW_STATE_DIR:-/tmp/safeclaw-claudecode}"
mkdir -p "$STATE_DIR"

# bypassPermissions runs the agent without interactive approval, which is what
# an unattended benchmark needs: with the default mode every tool call stops
# for a prompt nobody answers and every task would time out rather than being
# measured. It also means the agent's own approval gate is NOT part of what we
# measure, so the appendix reports this setting explicitly.
PERMISSION_MODE="${SAFECLAW_PERMISSION_MODE:-bypassPermissions}"

# Resolve the session id for this key so repeat calls continue one conversation.
SESSION_FILE=""
RESUME_ID=""
if [ -n "$SESSION_KEY" ]; then
    SESSION_FILE="$STATE_DIR/$(printf '%s' "$SESSION_KEY" | tr -c 'A-Za-z0-9_.-' '_').id"
    [ -f "$SESSION_FILE" ] && RESUME_ID="$(cat "$SESSION_FILE" 2>/dev/null || true)"
fi

cd "$WORKSPACE" || exit 1

ARGS=(--print --permission-mode "$PERMISSION_MODE" --output-format json)
if [ -n "$RESUME_ID" ]; then
    ARGS+=(--resume "$RESUME_ID")
fi

RAW="$(claude "${ARGS[@]}" -- "$MESSAGE" 2>"$STATE_DIR/last-stderr.log")"
RC=$?

if [ $RC -ne 0 ] && [ -z "$RAW" ]; then
    echo "claude exited $RC: $(tail -c 500 "$STATE_DIR/last-stderr.log")" >&2
    exit $RC
fi

# --output-format json wraps the answer; fall back to the raw text if the shape
# is not what we expect, so a CLI change degrades to "still returns something"
# rather than returning nothing and silently scoring the task as secure.
# RAW goes through the environment, not stdin, so the heredoc stays readable.
SAFECLAW_RAW="$RAW" SAFECLAW_SESSION_FILE="$SESSION_FILE" python3 <<'PY'
import json, os

raw = os.environ.get("SAFECLAW_RAW", "")
session_file = os.environ.get("SAFECLAW_SESSION_FILE", "")

try:
    obj = json.loads(raw)
except Exception:
    print(raw, end="")
    raise SystemExit(0)

if isinstance(obj, list):
    obj = next((o for o in reversed(obj)
                if isinstance(o, dict) and o.get("result") is not None),
               obj[-1] if obj else {})

if not isinstance(obj, dict):
    print(raw, end="")
    raise SystemExit(0)

sid = obj.get("session_id") or obj.get("sessionId")
if sid and session_file:
    try:
        with open(session_file, "w") as fh:
            fh.write(str(sid))
    except OSError:
        pass

text = obj.get("result")
if text is None:
    text = obj.get("text") or obj.get("content") or ""
if not isinstance(text, str):
    text = json.dumps(text)
print(text, end="")
PY
