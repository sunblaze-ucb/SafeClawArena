#!/usr/bin/env python3
"""Which SafeClawArena categories a platform can actually run, and why.

The benchmark was built against OpenClaw, so a task may depend on a mechanism a
different agent platform does not have. This module states those dependencies
explicitly instead of hiding them behind a hand-curated task list: each category
declares the platform capabilities it needs, each platform declares what it
provides, and the supported subset falls out of the two.

A capability is provided at one of three levels:

  NATIVE       the platform has the mechanism the task was written against
  SUBSTITUTED  the platform has a different mechanism that carries the same
               security property, named in PLATFORM_CAPABILITIES
  ABSENT       the platform has no counterpart, so the category is not
               measurable there

ABSENT is a result, not a gap. A category that cannot be expressed on a platform
is evidence that the attack surface belongs to the architecture rather than to
the model running on it.

Usage:
    python3 scripts/platform_support.py                 # matrix for all platforms
    python3 scripts/platform_support.py --platform codex
    python3 scripts/platform_support.py --common        # categories shared by all
    python3 scripts/platform_support.py --task-ids claudecode
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

NATIVE = "native"
SUBSTITUTED = "substituted"
ABSENT = "absent"

TASKS_DIR = Path(__file__).resolve().parent.parent / "tasks"


# --- Capabilities a task can depend on -------------------------------------

CAPABILITIES = {
    "skill_loader": "Loads third-party instruction bundles the agent then follows",
    "plugin_loader": "Loads third-party code into the agent's own process",
    "bundled_script": "Agent can execute a script shipped alongside an extension",
    "persistent_memory": "A file the agent rereads on later, unrelated sessions",
    "agent_config": "An on-disk config file that governs the agent's own behaviour",
    "daemon_log": "A persistent transcript or log of the agent's own activity",
    "scheduler": "Agent-initiated runs with no user in the loop (cron, webhook)",
    "subagents": "Agent can spawn further agents that inherit its workspace",
    "sim_google": "The Sim-Google CLI is on PATH and logs its invocations",
    "multi_session": "Separate sessions that do not share conversation context",
}


# --- What each category needs ----------------------------------------------
# Keyed by category id. Values are the capabilities without which the attack
# cannot be posed at all; a capability used only for flavour is not listed.

CATEGORY_REQUIREMENTS = {
    # SSI — third-party content entering the agent
    "1.1": {"skill_loader"},
    "1.2": {"skill_loader", "persistent_memory"},
    "1.3": {"skill_loader"},
    "1.4": {"plugin_loader"},
    "1.5": {"skill_loader", "bundled_script"},
    # PSE — state that survives the session
    "2.1": {"persistent_memory", "multi_session"},
    "2.2": {"persistent_memory", "multi_session"},
    "2.3": {"persistent_memory", "multi_session"},
    "2.4": {"agent_config", "skill_loader"},
    # CDF — data crossing a trust boundary
    "3.1": {"sim_google"},
    "3.2": {"sim_google", "daemon_log"},
    "3.3": {"sim_google", "multi_session"},
    "3.4": {"skill_loader", "persistent_memory", "sim_google"},
    "3.5": {"scheduler", "daemon_log"},
    "3.6": {"subagents", "sim_google"},
    "3.7": {"sim_google"},
    "3.8": {"daemon_log"},
    "3.9": {"sim_google"},
    "3.10": {"sim_google"},
    # IPI — document-borne instructions. 4.1 and 4.4 compare the agent's own
    # answer against the user's instruction and need nothing from the platform.
    "4.1": set(),
    "4.2": {"sim_google"},
    "4.3": {"sim_google"},
    "4.4": set(),
    "4.5": {"sim_google"},
}


# --- What each platform provides -------------------------------------------
# (level, mechanism). The mechanism string is what the appendix cites, so it
# names a real path or command rather than a description.

_FULL = {
    "skill_loader": (NATIVE, ".openclaw/skills/<name>/SKILL.md"),
    "plugin_loader": (NATIVE, "npm plugin loaded in the gateway process"),
    "bundled_script": (NATIVE, "script shipped inside a Skill"),
    "persistent_memory": (NATIVE, "workspace MEMORY.md"),
    "agent_config": (NATIVE, "openclaw.json"),
    "daemon_log": (NATIVE, "/tmp/openclaw-gateway.log"),
    "scheduler": (NATIVE, "gateway cron and webhook triggers"),
    "subagents": (NATIVE, "gateway subagents"),
    "sim_google": (NATIVE, "sim-google on PATH"),
    "multi_session": (NATIVE, "gateway restart between sessions"),
}

PLATFORM_CAPABILITIES = {
    "openclaw": dict(_FULL),
    "nemoclaw": dict(_FULL),
    "seclaw": {
        **_FULL,
        # SeClaw ships no Skill-bundled native plugin loader at all.
        "plugin_loader": (ABSENT, "no Skill-bundled plugin loader"),
        "persistent_memory": (SUBSTITUTED, "workspace memory/MEMORY.md"),
        "agent_config": (SUBSTITUTED, "config.json, narrower key set"),
        "daemon_log": (SUBSTITUTED, "CLI session transcript"),
        "scheduler": (ABSENT, "no gateway scheduler"),
    },
    "claudecode": {
        "skill_loader": (NATIVE, ".claude/skills/<name>/SKILL.md"),
        # Claude Code plugins are not npm packages loaded into the agent
        # process, and a blocklist gates them, so this is a different
        # mechanism carrying the same "third-party code runs with agent
        # privilege" property.
        "plugin_loader": (SUBSTITUTED, ".claude/plugins/ (gated by blocklist.json)"),
        "bundled_script": (NATIVE, "script shipped inside a Skill"),
        "persistent_memory": (SUBSTITUTED, "CLAUDE.md in the project root"),
        "agent_config": (SUBSTITUTED, "~/.claude/settings.json"),
        "daemon_log": (SUBSTITUTED, "~/.claude/projects/<slug>/<session>.jsonl"),
        "scheduler": (ABSENT, "no agent-initiated scheduled runs"),
        "subagents": (NATIVE, "Claude Code subagents"),
        "sim_google": (NATIVE, "sim-google on PATH"),
        "multi_session": (NATIVE, "separate claude -p invocations"),
    },
    "codex": {
        "skill_loader": (ABSENT, "no third-party skill mechanism"),
        "plugin_loader": (ABSENT, "no in-process extension mechanism"),
        "bundled_script": (NATIVE, "agent can run a script in the workspace"),
        "persistent_memory": (SUBSTITUTED, "AGENTS.md in the project root"),
        "agent_config": (SUBSTITUTED, "~/.codex/config.toml"),
        "daemon_log": (SUBSTITUTED, "~/.codex/sessions/ rollout files"),
        "scheduler": (ABSENT, "no agent-initiated scheduled runs"),
        "subagents": (ABSENT, "no subagent mechanism"),
        "sim_google": (NATIVE, "sim-google on PATH"),
        "multi_session": (NATIVE, "separate codex exec invocations"),
    },
}


# --- Derivation ------------------------------------------------------------

def category_status(platform: str, category: str):
    """Return (runnable, level, blocking_or_substituted_capabilities)."""
    caps = PLATFORM_CAPABILITIES[platform]
    needed = CATEGORY_REQUIREMENTS[category]
    missing = sorted(c for c in needed if caps[c][0] == ABSENT)
    if missing:
        return False, ABSENT, missing
    subs = sorted(c for c in needed if caps[c][0] == SUBSTITUTED)
    return True, (SUBSTITUTED if subs else NATIVE), subs


def task_counts():
    """Task count per category, read from the released task files."""
    counts = Counter()
    for f in TASKS_DIR.glob("*/*.json"):
        with open(f) as fh:
            counts[json.load(fh)["metadata"]["category"]] += 1
    return counts


def task_ids(platform: str):
    """Task ids runnable on a platform, in category order."""
    out = []
    for f in sorted(TASKS_DIR.glob("*/*.json")):
        with open(f) as fh:
            m = json.load(fh)["metadata"]
        if category_status(platform, m["category"])[0]:
            out.append(m["task_id"])
    return out


def common_categories():
    """Categories every registered platform can run."""
    return [c for c in sorted(CATEGORY_REQUIREMENTS, key=_catkey)
            if all(category_status(p, c)[0] for p in PLATFORM_CAPABILITIES)]


def _catkey(c):
    return [int(x) for x in c.split(".")]


# --- Reporting -------------------------------------------------------------

def print_matrix(platforms, counts):
    width = max(len(p) for p in platforms) + 2
    print(f"{'cat':<6}{'n':>4}  " + "".join(f"{p:<{width}}" for p in platforms))
    totals = Counter()
    for c in sorted(CATEGORY_REQUIREMENTS, key=_catkey):
        cells = []
        for p in platforms:
            runnable, level, _ = category_status(p, c)
            cells.append({NATIVE: "native", SUBSTITUTED: "subst.", ABSENT: "--"}[level])
            if runnable:
                totals[p] += counts[c]
        print(f"{c:<6}{counts[c]:>4}  " + "".join(f"{x:<{width}}" for x in cells))
    print(f"\n{'tasks':<6}{sum(counts.values()):>4}  "
          + "".join(f"{totals[p]:<{width}}" for p in platforms))
    print(f"{'pct':<6}{'':>4}  " + "".join(
        f"{100*totals[p]/sum(counts.values()):.0f}%{'':<{width-4}}" for p in platforms))


def print_detail(platform, counts):
    print(f"Platform: {platform}\n")
    print("Capabilities")
    for cap in sorted(CAPABILITIES):
        level, mech = PLATFORM_CAPABILITIES[platform][cap]
        print(f"  {cap:<20} {level:<12} {mech}")
    runnable_n = absent_n = 0
    print("\nCategories")
    for c in sorted(CATEGORY_REQUIREMENTS, key=_catkey):
        ok, level, caps = category_status(platform, c)
        note = ""
        if level == SUBSTITUTED:
            note = "via " + ", ".join(
                PLATFORM_CAPABILITIES[platform][x][1] for x in caps)
        elif level == ABSENT:
            note = "needs " + ", ".join(caps)
        print(f"  {c:<6}{counts[c]:>4}  {'run ' if ok else 'skip'}  {level:<12}{note}")
        if ok:
            runnable_n += counts[c]
        else:
            absent_n += counts[c]
    print(f"\n  runnable {runnable_n} tasks, not measurable {absent_n} tasks")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", help="show the capability and category detail for one platform")
    ap.add_argument("--common", action="store_true",
                    help="list the categories every platform can run")
    ap.add_argument("--task-ids", metavar="PLATFORM",
                    help="print the runnable task ids, one per line")
    args = ap.parse_args()

    counts = task_counts()
    if not counts:
        sys.exit(f"ERROR: no task files under {TASKS_DIR}")

    if args.task_ids:
        if args.task_ids not in PLATFORM_CAPABILITIES:
            sys.exit(f"ERROR: unknown platform {args.task_ids!r}")
        for t in task_ids(args.task_ids):
            print(t)
        return

    if args.common:
        cats = common_categories()
        n = sum(counts[c] for c in cats)
        print(f"Categories runnable on every platform: {', '.join(cats)}")
        print(f"Tasks in the common subset: {n} of {sum(counts.values())}")
        return

    if args.platform:
        if args.platform not in PLATFORM_CAPABILITIES:
            sys.exit(f"ERROR: unknown platform {args.platform!r}")
        print_detail(args.platform, counts)
        return

    print_matrix(list(PLATFORM_CAPABILITIES), counts)


if __name__ == "__main__":
    main()
