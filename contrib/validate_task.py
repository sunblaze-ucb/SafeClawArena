#!/usr/bin/env python3
"""
SafeClawArena — Task JSON Validator

Validates task JSON files against structural requirements before running
them through judge.py.

Usage:
    python3 contrib/validate_task.py tasks/contrib/ssi-1.1-001.json
    python3 contrib/validate_task.py tasks/contrib/*.json
    python3 contrib/validate_task.py tasks/contrib/ --recursive
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ── Supported check types (from judge.py) ───────────────────────────────────

VALID_CHECK_TYPES = {
    "output_contains", "output_regex", "output_not_contains",
    "taint_detected_in_output", "taint_detected_in_tool_call",
    "taint_detected_in_memory", "taint_detected_in_log",
    "taint_detected_in_sim_google_calls", "taint_detected_in_workspace_files",
    "taint_detected_in_auth_profiles", "taint_detected_in_file",
    "file_created", "file_deleted", "file_modified", "file_contains", "file_not_contains",
    "http_route_exists", "network_call_made",
    "memory_written", "memory_contains",
    "config_modified", "config_contains",
    "cron_job_created",
    "safety_constraint_bypassed", "behavioral_change_observed",
    "refusal_detected", "credential_exposed",
}

VALID_METRICS = {"SSI-Score", "PSE-Score", "CDF-Score"}

VALID_DIMENSIONS = {"SSI", "PSE", "CDF"}

SIM_GOOGLE_DATA_PATH_PREFIXES = {
    "gmail/inbox/", "drive/files/", "calendar/", "chat/spaces/",
    "tasks/", "contacts/", "keep/", "sheets/data/", "groups/",
}


class TaskValidator:
    def __init__(self, task: dict, filepath: str = ""):
        self.task = task
        self.filepath = filepath
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str):
        self.errors.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    def validate(self) -> bool:
        """Run all validations. Returns True if no errors."""
        self._check_metadata()
        self._check_environment()
        self._check_sessions()
        self._check_evaluation()
        self._check_taint_assets()
        self._check_skill_in_instruction()
        self._check_gog_data_paths()
        self._check_timeouts()
        return len(self.errors) == 0

    def _check_metadata(self):
        meta = self.task.get("metadata")
        if not meta:
            self.error("Missing 'metadata' block")
            return
        for field in ("task_id", "dimension", "category", "category_name"):
            if field not in meta:
                self.error(f"metadata.{field} is required")
        if meta.get("dimension") and meta["dimension"] not in VALID_DIMENSIONS:
            self.error(f"metadata.dimension must be one of {VALID_DIMENSIONS}, got '{meta['dimension']}'")

    def _check_environment(self):
        env = self.task.get("environment")
        if not env:
            self.error("Missing 'environment' block")
            return
        ws = env.get("workspace_files", [])
        if not ws:
            self.warn("No workspace_files defined — task may lack credential files")
        else:
            paths = [f["path"] for f in ws]
            if not any(".env" in p for p in paths):
                self.warn("No .env file in workspace_files")
            # Check workspace files have required fields
            for f in ws:
                if "path" not in f or "content" not in f:
                    self.error(f"workspace_file missing 'path' or 'content': {f.get('path', '?')}")

        # Check skills structure
        for skill in env.get("skills", []):
            for field in ("name", "content"):
                if field not in skill:
                    self.error(f"skill missing '{field}' field")

        # Check plugins structure
        for plugin in env.get("plugins", []):
            if "plugin_id" not in plugin:
                self.error("plugin missing 'plugin_id' field")
            if "files" not in plugin:
                self.error(f"plugin '{plugin.get('plugin_id', '?')}' missing 'files' dict")

    def _check_sessions(self):
        sessions = self.task.get("sessions")
        if not sessions:
            self.error("Missing 'sessions' list (need at least one session)")
            return
        session_ids = set()
        for s in sessions:
            if "session_id" not in s:
                self.error("Session missing 'session_id'")
            else:
                session_ids.add(s["session_id"])
            if "user_instruction" not in s:
                self.error(f"Session '{s.get('session_id', '?')}' missing 'user_instruction'")

    def _check_evaluation(self):
        ev = self.task.get("evaluation")
        if not ev:
            self.error("Missing 'evaluation' block")
            return
        metric = ev.get("metric")
        if metric and metric not in VALID_METRICS:
            self.error(f"evaluation.metric must be one of {VALID_METRICS}, got '{metric}'")

        # Check success_condition
        sc = ev.get("success_condition", {})
        checks = sc.get("checks", [])
        if not checks:
            self.warn("No success_condition.checks defined — judge won't know if attack succeeded")
        session_ids = {s["session_id"] for s in self.task.get("sessions", []) if "session_id" in s}
        for check in checks:
            ctype = check.get("type")
            if not ctype:
                self.error("Check missing 'type' field")
            elif ctype not in VALID_CHECK_TYPES:
                self.error(f"Unknown check type: '{ctype}'. Valid types: {sorted(VALID_CHECK_TYPES)}")
            # Validate session_id reference
            sid = check.get("session_id")
            if sid and sid not in session_ids:
                self.error(f"Check references session '{sid}' but sessions are {session_ids}")

    def _check_taint_assets(self):
        assets = self.task.get("taint_assets", [])
        if not assets:
            self.warn("No taint_assets defined — CDF scoring won't work")
            return
        total_weight = sum(a.get("severity_weight", 0) for a in assets)
        if abs(total_weight - 1.0) > 0.15:
            self.warn(f"taint_assets severity_weight sum = {total_weight:.2f} (expected ~1.0)")
        for a in assets:
            marker = a.get("marker", "")
            if not marker.startswith("CANARY_"):
                self.error(f"taint_asset '{a.get('asset_id', '?')}' marker should start with 'CANARY_', got '{marker[:20]}'")

    def _check_skill_in_instruction(self):
        """Verify skill names appear in user instruction (except Cat 1.4)."""
        meta = self.task.get("metadata", {})
        if meta.get("category") == "1.4":
            return  # Cat 1.4 deliberately omits skill name
        skills = self.task.get("environment", {}).get("skills", [])
        if not skills:
            return
        instructions = " ".join(
            s.get("user_instruction", "") for s in self.task.get("sessions", [])
        )
        for skill in skills:
            name = skill.get("name", "")
            if name and name not in instructions:
                self.warn(
                    f"Skill '{name}' not mentioned in any user instruction. "
                    f"OpenClaw may not load it. (Ignore if this is intentional, like Cat 1.4.)"
                )

    def _check_gog_data_paths(self):
        """Verify sim_google_data paths follow conventions."""
        sim_google_data = self.task.get("environment", {}).get("sim_google_data", [])
        for entry in sim_google_data:
            path = entry.get("path", "")
            if not any(path.startswith(prefix) for prefix in SIM_GOOGLE_DATA_PATH_PREFIXES):
                self.warn(
                    f"sim_google_data path '{path}' doesn't match known conventions: "
                    f"{sorted(SIM_GOOGLE_DATA_PATH_PREFIXES)}"
                )

    def _check_timeouts(self):
        for s in self.task.get("sessions", []):
            timeout = s.get("timeout_seconds", 0)
            if timeout and timeout < 300:
                self.warn(f"Session '{s.get('session_id', '?')}' timeout={timeout}s — recommend ≥600s")


def validate_file(filepath: Path) -> tuple[int, int]:
    """Validate one task JSON file. Returns (error_count, warning_count)."""
    try:
        with open(filepath) as f:
            task = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  FAIL  {filepath.name}: Invalid JSON — {e}")
        return 1, 0

    v = TaskValidator(task, str(filepath))
    valid = v.validate()

    status = "OK" if valid and not v.warnings else "WARN" if valid else "FAIL"
    print(f"  {status:4s}  {filepath.name}", end="")
    if v.errors:
        print(f"  ({len(v.errors)} errors, {len(v.warnings)} warnings)")
        for e in v.errors:
            print(f"        ERROR: {e}")
        for w in v.warnings:
            print(f"        WARN:  {w}")
    elif v.warnings:
        print(f"  ({len(v.warnings)} warnings)")
        for w in v.warnings:
            print(f"        WARN:  {w}")
    else:
        print()

    return len(v.errors), len(v.warnings)


def main():
    parser = argparse.ArgumentParser(description="Validate SafeClawArena task JSON files")
    parser.add_argument("targets", nargs="+", help="Task JSON files or directories")
    parser.add_argument("--recursive", "-r", action="store_true", help="Search directories recursively")
    args = parser.parse_args()

    files = []
    for target in args.targets:
        p = Path(target)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            pattern = "**/*.json" if args.recursive else "*.json"
            files.extend(sorted(p.glob(pattern)))
        else:
            print(f"  SKIP  {target} (not found)")

    if not files:
        print("No JSON files found.")
        return 1

    print(f"Validating {len(files)} task(s)...\n")
    total_errors = 0
    total_warnings = 0
    for f in files:
        e, w = validate_file(f)
        total_errors += e
        total_warnings += w

    print(f"\n{'='*60}")
    print(f"Results: {len(files)} files, {total_errors} errors, {total_warnings} warnings")
    if total_errors == 0:
        print("All tasks valid.")
    print(f"{'='*60}")
    return 1 if total_errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
