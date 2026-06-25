#!/usr/bin/env python3
"""
TTFHW JSON Quality Gate — Deterministic Validation Script.

Performs structural, type, timestamp, numerical, and security checks on
verification report JSON files. Designed for both CI (GitHub Actions) and
local development use.

Usage:
    python validate_json.py reports/*.json
    python validate_json.py reports/file1.json reports/file2.json

Output: JSON to stdout with structure:
    {"pass": bool, "files": {path: {"pass": bool, "issues": [...]}}}

Template reference:
    https://github.com/computing-TTFHW/ttfhw-report/blob/master/.claude/skills/ttfhw-verify-openeuler/assets/report_template.json
"""

import json
import re
import sys
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Template structure — expected top-level key names (recursive)
# ---------------------------------------------------------------------------

TEMPLATE_STRUCTURE = {
    "metadata": {
        "repo_path": str,
        "start_time": str,
        "end_time": str,
        "duration_seconds": int,
        "total_steps": int,
    },
    "machine_spec": {
        "host_machine": {
            "architecture": str,
            "cpu_model": str,
            "cpu_cores": int,
            "memory": str,
            "disk": str,
            "docker_version": str,
        },
        "container": {
            "os": str,
            "architecture": str,
            "cpu_cores": (int, type(None)),
            "memory": (str, type(None)),  # may be absent or "N/A" when container not started
        },
        "image_source": {
            "type": str,
            "image_name": str,
            "selection_reason": str,
            "dependency_mapping": {
                "from_dockerfile": str,
                "mappings": list,
            },
        },
    },
    "document_reading_summary": {
        "architecture": dict,
        "recommended_image": dict,
        "dockerfile_dependencies": dict,
        "dependencies": dict,
        "build_commands": dict,
        "ut_commands": dict,
        "sample_commands": dict,
        "special_dependencies": dict,
    },
    "execution_log": list,
    "process_timeline": list,
    "final_results": {
        "static_analysis": {
            "enabled": bool,
            "summary": str,
            "pre_commit": {
                "configured": bool,
                "config_file": (str, type(None)),
                "status": str,
                "duration_seconds": int,
                "total_hooks": int,
                "passed": int,
                "failed": int,
                "skipped": int,
                "failures": list,
            },
            "lint_runner": {
                "configured": bool,
                "config_file": (type(None), str),
            },
        },
        "devcontainer": {
            "enabled": bool,
            "config_dir": (str, type(None)),
            "config_files": list,
            "original_base_image": (str, type(None)),
            "used_image": (str, type(None)),
            "summary": str,
        },
        "build": {
            "status": str,
            "duration_seconds": int,
            "artifacts": list,
            "failure_reason": str,   # conditional: present when status != "成功"
        },
        "ut": {
            "status": str,
            "duration_seconds": int,
            "total": int,
            "passed": int,
            "failed": int,
            "failures": list,
            "failure_reason": str,   # conditional: present when status != success
        },
        "sample": {
            "status": str,
            "duration_seconds": int,
            "results": list,
            "failure_reason": str,   # conditional: present when status != "成功"
        },
    },
    "documentation_gaps": list,
    "problems_encountered": list,
}

# Top-level key severity classification (based on renderer consumption analysis)
# P0 ERROR: Renderer cannot function without these
TOP_KEYS_ERROR = ["metadata", "final_results"]
# P1 WARNING: Significant visual impact if missing
TOP_KEYS_WARNING = ["execution_log", "process_timeline", "problems_encountered"]
# P2 NOTICE: Renderer handles gracefully (dynamic iteration, empty defaults)
TOP_KEYS_NOTICE = ["machine_spec", "document_reading_summary", "documentation_gaps"]

# ---------------------------------------------------------------------------
# Security: Fields where shell/command syntax is EXPECTED (not flagged)
# ---------------------------------------------------------------------------

# Compiled regex patterns for paths where shell meta-characters are expected.
# These fields contain commands, command output, error messages, or
# documentation of shell commands/environment setup.
COMMAND_FIELD_PATTERNS = [
    # execution_log entries — actual commands that were run and their output
    re.compile(r'^execution_log\.\d+\.(command|output|error|note)$'),
    # document_reading_summary — commands extracted from repo docs
    re.compile(r'^document_reading_summary\.(build_commands|ut_commands|sample_commands)\.value$'),
    # dependency/special_dependency strings may contain shell env vars or dnf commands
    re.compile(r'^document_reading_summary\.(dependencies|special_dependencies)\.value(\.\d+)?$'),
    # dockerfile_dependencies: "apt-get install -y libssl-dev" style strings
    re.compile(r'^document_reading_summary\.dockerfile_dependencies\.value(\.\d+)?(\.(original|openEuler_equivalent))?$'),
    # problems_encountered — solutions may reference commands
    re.compile(r'^problems_encountered\.\d+\.solution$'),
    # process_timeline details.error — error messages may contain command references
    re.compile(r'^process_timeline\.\d+\.details\.error$'),
    # image_source.selection_reason — may reference Dockerfile commands
    re.compile(r'^machine_spec\.image_source\.selection_reason$'),
    # recommended_image.value — may reference Docker commands
    re.compile(r'^document_reading_summary\.recommended_image\.value$'),
]

# These are the field types that should NOT contain shell commands
# (We flag shell patterns only in text/descriptive fields, not in the above)

# ---------------------------------------------------------------------------
# Security patterns
# ---------------------------------------------------------------------------

# Shell injection patterns (dangerous in text/description fields)
SHELL_INJECTION_PATTERNS = [
    (r'\$\([^)]*\)', "shell command substitution $(...)"),
    (r'\$\{[^}]*\}', "shell variable substitution ${...}"),
    (r'`[^`]+`', "shell backtick execution"),
    (r';\s*(rm|sh|bash|wget|curl|nc|telnet)', "command chaining with dangerous command"),
    (r'\|\s*(sh|bash|/bin/sh|/bin/bash)', "pipe to shell execution"),
    (r'/dev/tcp/', "TCP device redirect (reverse shell indicator)"),
    (r'cmd\.exe|powershell\.exe|command\.com', "Windows shell invocation"),
]

# XSS / HTML injection patterns
XSS_PATTERNS = [
    (r'<script[^>]*>', "<script> tag"),
    (r'onerror\s*=', "onerror handler"),
    (r'onload\s*=', "onload handler"),
    (r'javascript\s*:', "javascript: URI"),
    (r'onclick\s*=', "onclick handler"),
    (r'onmouseover\s*=', "onmouseover handler"),
    (r'<iframe[^>]*>', "<iframe> tag"),
    (r'<object[^>]*>', "<object> tag"),
    (r'<embed[^>]*>', "<embed> tag"),
    (r'eval\s*\(', "eval() call"),
]

# AI prompt injection patterns (injected into JSON text fields to manipulate AI analysis)
PROMPT_INJECTION_PATTERNS = [
    (r'ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|directives?)', "AI prompt override", re.IGNORECASE),
    (r'you\s+are\s+(now|no\s+longer)\b.{0,50}\b(assistant|validator|checker)', "AI role hijack", re.IGNORECASE),
    (r'system\s*(prompt|message|instruction)\s*(:|is|was|now)\s*["\']?', "system prompt injection", re.IGNORECASE),
    (r'do\s+not\s+(check|validate|analyze|report|flag)\b', "suppression instruction", re.IGNORECASE),
    (r'output\s+(only|just|exactly)\s*["\']?\{\}', "output suppression", re.IGNORECASE),
    (r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>', "LLM instruction tags", re.IGNORECASE),
]

# Sensitive information patterns
SENSITIVE_INFO_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{32,}', "OpenAI/Anthropic API key"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "private key"),
    (r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}', "Bearer token"),
    (r'password\s*[:=]\s*["\']?\S+["\']?', "password assignment", re.IGNORECASE),
    (r'secret\s*[:=]\s*["\']?\S+["\']?', "secret assignment", re.IGNORECASE),
    (r'api[_-]?key\s*[:=]\s*["\']?\S{20,}["\']?', "API key assignment", re.IGNORECASE),
    (r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*', "JWT token"),
]

# Dangerous command patterns (informational — in command fields)
DANGEROUS_COMMANDS = [
    (r'rm\s+-rf\s+/', "rm -rf / (destructive delete)"),
    (r'rm\s+-rf\s+[~.]', "rm -rf with path"),
    (r'chmod\s+777\b', "chmod 777 (world-writable)"),
    (r'chmod\s+-R\s+777\b', "chmod -R 777 (recursive world-writable)"),
    (r'curl\s+.*\|\s*(ba)?sh', "curl pipe to shell"),
    (r'wget\s+.*-O\s*-\s*\|\s*(ba)?sh', "wget pipe to shell"),
    (r'>\s*/dev/sda', "write to block device"),
    (r'mkfs\.', "filesystem creation"),
    (r'dd\s+if=', "dd disk operation"),
    (r'git\s+clone\s+.*\|\s*(ba)?sh', "git clone pipe to shell"),
]

# Suspicious URL domains (in non-repo_path fields)
SUSPICIOUS_URL_PATTERNS = [
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "raw IP URL"),
    (r'https?://[^/]*\bpaste(bin)?\b', "pastebin URL"),
    (r'https?://[^/]*\b(ngrok|localhost|127\.0\.0\.1)\b', "tunnel/localhost URL"),
    (r'https?://[^/]*\b(bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl)\b', "URL shortener"),
]

# Sensitive file paths (in non-path fields)
SENSITIVE_PATHS = [
    (r'/etc/(passwd|shadow|group|sudoers)', "system auth file"),
    (r'/proc/(self|cmdline|cpuinfo|meminfo)', "proc filesystem"),
    (r'~(?=/\.ssh|/\.gnupg)', "user sensitive dotfile"),
    (r'C:\\Windows\\(System32|SysWOW64)', "Windows system directory"),
    (r'/root/\.(ssh|bashrc|bash_history)', "root sensitive file"),
]

# Base64 pattern (long base64 strings > 50 chars may hide malicious content)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')

# ISO 8601 timestamp pattern
ISO8601_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')


# ---------------------------------------------------------------------------
# Issue collector
# ---------------------------------------------------------------------------

class IssueCollector:
    """Collects validation issues for a single file."""

    def __init__(self):
        self.issues: List[Dict[str, Any]] = []

    def add(self, severity: str, check: str, path: str, message: str):
        self.issues.append({
            "severity": severity,  # "error", "warning", "notice"
            "check": check,
            "path": path,
            "message": message,
        })

    def has_errors(self) -> bool:
        return any(i["severity"] == "error" for i in self.issues)

    def to_dict(self) -> dict:
        return {
            "pass": not self.has_errors(),
            "issues": self.issues,
        }


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def fmt_path(*parts) -> str:
    """Format a JSON path: fmt_path('metadata', 'repo_path') -> '$.metadata.repo_path'."""
    return "$." + ".".join(str(p) for p in parts)


def get_nested(data: dict, path: str) -> Any:
    """Get a value by dot-separated path. Returns a sentinel if missing."""
    sentinel = object()
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, sentinel)
        elif isinstance(current, list):
            try:
                idx = int(key)
                current = current[idx] if idx < len(current) else sentinel
            except (ValueError, IndexError):
                return sentinel
        else:
            return sentinel
        if current is sentinel:
            return sentinel
    return current


def collect_all_values(obj: Any, prefix: str = "") -> List[Tuple[str, Any]]:
    """Recursively collect all leaf values with their JSON paths."""
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            results.extend(collect_all_values(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{prefix}.{i}" if prefix else str(i)
            results.extend(collect_all_values(v, p))
    else:
        results.append((prefix, obj))
    return results


def is_command_field(path: str) -> bool:
    """Check if a JSON path refers to a field where shell syntax is expected."""
    for pattern in COMMAND_FIELD_PATTERNS:
        if pattern.match(path):
            return True
    return False


# ---------------------------------------------------------------------------
# Helper: compare dict keys against template
# ---------------------------------------------------------------------------

def _compare_keys(data: dict, template: dict, base_path: str,
                  issues: IssueCollector, unknown_as: str = "notice"):
    """Recursively compare keys of `data` against `template`.
    Severity depends on which section:
    - final_results sub-keys missing → WARNING (affects badge rendering)
    - machine_spec / document_reading_summary sub-keys missing → NOTICE (renderer handles)
    """
    if not isinstance(data, dict):
        return

    t_keys = set(template.keys())
    d_keys = set(data.keys())

    # Determine severity based on context
    if base_path == "final_results" or base_path.startswith("final_results."):
        missing_sev = "warning"
    else:
        missing_sev = "notice"

    missing = t_keys - d_keys
    for k in sorted(missing):
        if k in ("failure_reason", "note"):
            continue
        issues.add(missing_sev, "template_structure",
                   fmt_path(base_path, k) if base_path else f"$.{k}",
                   f"缺少字段 '{k}'（标准模板中存在）")

    extra = d_keys - t_keys
    for k in sorted(extra):
        issues.add(unknown_as, "template_structure",
                   fmt_path(base_path, k) if base_path else f"$.{k}",
                   f"未知字段 '{k}'（不在标准模板中，渲染代码忽略）")

    # Recurse into common nested dicts
    for k in t_keys & d_keys:
        if isinstance(template[k], dict) and isinstance(data[k], dict):
            new_base = f"{base_path}.{k}" if base_path else k
            _compare_keys(data[k], template[k], new_base, issues, unknown_as)


# ---------------------------------------------------------------------------
# CHECK FUNCTIONS
# Each returns True if the check passes (no issue) or adds to issues.
# ---------------------------------------------------------------------------

def check_valid_json(filepath: str, issues: IssueCollector) -> Optional[dict]:
    """Try to parse the file as JSON. Returns the parsed dict or None."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        issues.add("error", "valid_json", "$",
                   f"JSON 解析失败: {e.msg}（第 {e.lineno} 行，第 {e.colno} 列）")
        return None
    except Exception as e:
        issues.add("error", "valid_json", "$",
                   f"无法读取文件: {e}")
        return None


def check_top_level_keys(data: dict, issues: IssueCollector):
    """Verify top-level keys with severity based on renderer impact."""
    all_known = set(TOP_KEYS_ERROR + TOP_KEYS_WARNING + TOP_KEYS_NOTICE)
    data_keys = list(data.keys())

    # P0 ERROR: metadata, final_results — renderer cannot function
    for k in TOP_KEYS_ERROR:
        if k not in data_keys:
            issues.add("error", "top_level_keys", "$",
                       f"缺少必需顶级字段 '{k}'（仪表盘核心数据源，缺失将导致无法展示）")
    # P1 WARNING: execution_log, process_timeline, problems_encountered
    for k in TOP_KEYS_WARNING:
        if k not in data_keys:
            issues.add("warning", "top_level_keys", "$",
                       f"缺少重要顶级字段 '{k}'（对应详情区域将为空）")
    # P2 NOTICE: machine_spec, document_reading_summary, documentation_gaps
    for k in TOP_KEYS_NOTICE:
        if k not in data_keys:
            issues.add("notice", "top_level_keys", "$",
                       f"缺少可选顶级字段 '{k}'（渲染代码可处理，对应信息区留空）")

    for k in data_keys:
        if k not in all_known:
            issues.add("notice", "top_level_keys", f"$.{k}",
                       f"未知顶级字段 '{k}'（渲染代码忽略，不影响展示）")


def check_metadata(data: dict, issues: IssueCollector):
    """Check metadata fields completeness and types."""
    meta = data.get("metadata", {})
    required = ["repo_path", "start_time", "end_time", "duration_seconds", "total_steps"]
    for field in required:
        if field not in meta:
            issues.add("error", "metadata", "$.metadata",
                       f"metadata 缺少必需字段 '{field}'")
        elif meta[field] is None:
            issues.add("error", "metadata", f"$.metadata.{field}",
                       f"metadata.{field} 为 null，应为非空值")

    # Type checks
    if isinstance(meta.get("duration_seconds"), bool):
        issues.add("error", "metadata_type", "$.metadata.duration_seconds",
                   "duration_seconds 为布尔值，应为整数")
    elif "duration_seconds" in meta and not isinstance(meta.get("duration_seconds"), int):
        issues.add("error", "metadata_type", "$.metadata.duration_seconds",
                   f"duration_seconds 应为整数，实际为 {type(meta['duration_seconds']).__name__}")

    if isinstance(meta.get("total_steps"), bool):
        issues.add("error", "metadata_type", "$.metadata.total_steps",
                   "total_steps 为布尔值，应为整数")
    elif "total_steps" in meta and not isinstance(meta.get("total_steps"), int):
        issues.add("error", "metadata_type", "$.metadata.total_steps",
                   f"total_steps 应为整数，实际为 {type(meta['total_steps']).__name__}")


def check_iso8601_timestamps(data: dict, issues: IssueCollector):
    """Check that all .timestamp and *_time fields are ISO 8601."""
    timestamps_to_check = [
        ("metadata.start_time", get_nested(data, "metadata.start_time")),
        ("metadata.end_time", get_nested(data, "metadata.end_time")),
    ]

    # execution_log timestamps
    exec_log = data.get("execution_log", [])
    if isinstance(exec_log, list):
        for i, entry in enumerate(exec_log):
            if isinstance(entry, dict) and "timestamp" in entry:
                timestamps_to_check.append(
                    (f"execution_log.{i}.timestamp", entry["timestamp"]))

    # process_timeline timestamps
    timeline = data.get("process_timeline", [])
    if isinstance(timeline, list):
        for i, entry in enumerate(timeline):
            if isinstance(entry, dict) and "timestamp" in entry:
                timestamps_to_check.append(
                    (f"process_timeline.{i}.timestamp", entry["timestamp"]))

    # problems_encountered timestamps
    problems = data.get("problems_encountered", [])
    if isinstance(problems, list):
        for i, entry in enumerate(problems):
            if isinstance(entry, dict) and "timestamp" in entry:
                timestamps_to_check.append(
                    (f"problems_encountered.{i}.timestamp", entry["timestamp"]))

    for path, ts in timestamps_to_check:
        if ts is None:
            continue
        # P0 ERROR for metadata timestamps (used for date display .split('T')[0])
        is_meta = path.startswith("metadata.")
        sev = "error" if is_meta else "warning"

        if not isinstance(ts, str) or not ISO8601_PATTERN.match(str(ts)):
            issues.add(sev, "timestamp_format", f"$.{path}",
                       f"时间戳格式无效 '{ts}' — 期望 ISO 8601 格式 (YYYY-MM-DDTHH:MM:SS)")
        else:
            try:
                datetime.fromisoformat(str(ts))
            except ValueError:
                issues.add(sev, "timestamp_format", f"$.{path}",
                           f"时间戳无法解析 '{ts}' — 不是合法的日期时间")


def check_type_correctness(data: dict, issues: IssueCollector):
    """Check type correctness for key fields throughout the JSON."""
    # execution_log: success must be bool, returncode must be int|null
    exec_log = data.get("execution_log", [])
    if isinstance(exec_log, list):
        for i, entry in enumerate(exec_log):
            if not isinstance(entry, dict):
                continue
            if "success" in entry and not isinstance(entry["success"], bool):
                issues.add("error", "type_check",
                           f"$.execution_log.{i}.success",
                           f"success must be boolean, got {type(entry['success']).__name__}")
            if "returncode" in entry and entry["returncode"] is not None:
                if isinstance(entry["returncode"], bool):
                    issues.add("error", "type_check",
                               f"$.execution_log.{i}.returncode",
                               "returncode is boolean, expected integer or null")
                elif not isinstance(entry["returncode"], int):
                    issues.add("error", "type_check",
                               f"$.execution_log.{i}.returncode",
                               f"returncode must be int or null, got {type(entry['returncode']).__name__}")
            if "duration_seconds" in entry:
                ds = entry["duration_seconds"]
                if isinstance(ds, bool):
                    issues.add("error", "type_check",
                               f"$.execution_log.{i}.duration_seconds",
                               "duration_seconds is boolean, expected integer")
                elif not isinstance(ds, (int, float)):
                    issues.add("error", "type_check",
                               f"$.execution_log.{i}.duration_seconds",
                               f"duration_seconds must be numeric, got {type(ds).__name__}")

    # final_results: enabled must be bool, configured must be bool
    fr = data.get("final_results", {})
    if isinstance(fr, dict):
        sa = fr.get("static_analysis", {})
        if isinstance(sa, dict):
            if "enabled" in sa and not isinstance(sa["enabled"], bool):
                issues.add("error", "type_check", "$.final_results.static_analysis.enabled",
                           f"enabled must be boolean, got {type(sa['enabled']).__name__}")
            pc = sa.get("pre_commit", {})
            if isinstance(pc, dict):
                for field in ["configured", "passed", "failed", "skipped", "total_hooks"]:
                    if field in pc:
                        val = pc[field]
                        if field == "configured":
                            if not isinstance(val, bool):
                                issues.add("error", "type_check",
                                           f"$.final_results.static_analysis.pre_commit.configured",
                                           f"configured must be boolean, got {type(val).__name__}")
                        elif isinstance(val, bool):
                            issues.add("error", "type_check",
                                       f"$.final_results.static_analysis.pre_commit.{field}",
                                       f"{field} is boolean, expected integer")
            lr = sa.get("lint_runner", {})
            if isinstance(lr, dict):
                if "configured" in lr and not isinstance(lr["configured"], bool):
                    issues.add("error", "type_check",
                               "$.final_results.static_analysis.lint_runner.configured",
                               f"configured must be boolean, got {type(lr['configured']).__name__}")

        dc = fr.get("devcontainer", {})
        if isinstance(dc, dict):
            if "enabled" in dc and not isinstance(dc["enabled"], bool):
                issues.add("error", "type_check", "$.final_results.devcontainer.enabled",
                           f"enabled must be boolean, got {type(dc['enabled']).__name__}")

        # build/ut/sample status must be string
        for section in ["build", "ut", "sample"]:
            sec = fr.get(section, {})
            if isinstance(sec, dict):
                for field in ["status", "duration_seconds"]:
                    if field in sec and field == "status" and not isinstance(sec.get("status"), str):
                        issues.add("error", "type_check",
                                   f"$.final_results.{section}.status",
                                   f"status must be string, got {type(sec['status']).__name__}")
                    elif field == "duration_seconds" and field in sec:
                        ds = sec["duration_seconds"]
                        if isinstance(ds, bool):
                            issues.add("error", "type_check",
                                       f"$.final_results.{section}.duration_seconds",
                                       "duration_seconds is boolean, expected integer")
                        elif not isinstance(ds, (int, float)):
                            issues.add("error", "type_check",
                                       f"$.final_results.{section}.duration_seconds",
                                       f"duration_seconds must be numeric, got {type(ds).__name__}")

                # ut-specific numeric checks
                if section == "ut":
                    for field in ["total", "passed", "failed"]:
                        val = sec.get(field)
                        if val is not None and isinstance(val, bool):
                            issues.add("error", "type_check",
                                       f"$.final_results.ut.{field}",
                                       f"{field} is boolean, expected integer")

    # machine_spec container cpu_cores — renderer displays as-is, string "N/A" is fine
    cpu_cores = get_nested(data, "machine_spec.container.cpu_cores")
    if cpu_cores is not None and isinstance(cpu_cores, str) and cpu_cores != "N/A":
        issues.add("notice", "type_check",
                   "$.machine_spec.container.cpu_cores",
                   f"cpu_cores 为字符串 '{cpu_cores}'，建议使用整数或 null（\"N/A\" 除外，渲染可直接展示）")
    elif cpu_cores is not None and isinstance(cpu_cores, bool):
        issues.add("error", "type_check",
                   "$.machine_spec.container.cpu_cores",
                   "cpu_cores 为布尔值，应为整数或 null")

    # container.memory — renderer handles absent key gracefully (dynamic grid)
    container = get_nested(data, "machine_spec.container")
    if isinstance(container, dict) and "memory" not in container:
        issues.add("notice", "type_check",
                   "$.machine_spec.container",
                   "缺少 container.memory 字段（渲染代码可处理，对应网格项留空）")
    elif isinstance(container, dict) and "memory" in container:
        mem = container["memory"]
        if mem is None:
            issues.add("notice", "type_check",
                       "$.machine_spec.container.memory",
                       "container.memory 为 null（渲染代码可处理）")


def check_precommit_consistency(data: dict, issues: IssueCollector):
    """Check that passed + failed + skipped == total_hooks."""
    pc = get_nested(data, "final_results.static_analysis.pre_commit")
    if not isinstance(pc, dict):
        return
    try:
        total = pc.get("total_hooks", 0)
        passed = pc.get("passed", 0)
        failed = pc.get("failed", 0)
        skipped = pc.get("skipped", 0)
        if isinstance(total, int) and isinstance(passed, int) and \
           isinstance(failed, int) and isinstance(skipped, int):
            if passed + failed + skipped != total:
                issues.add("error", "numeric_consistency",
                           "$.final_results.static_analysis.pre_commit",
                           f"passed({passed}) + failed({failed}) + skipped({skipped}) = "
                           f"{passed + failed + skipped}, but total_hooks = {total}")
    except (TypeError, ValueError):
        pass


def check_duration_consistency(data: dict, issues: IssueCollector):
    """Check that metadata.duration_seconds roughly matches end_time - start_time."""
    meta = data.get("metadata", {})
    start = meta.get("start_time")
    end = meta.get("end_time")
    declared = meta.get("duration_seconds")

    if isinstance(start, str) and isinstance(end, str) and isinstance(declared, (int, float)):
        try:
            # Parse and normalize to naive UTC for comparison
            def _parse_ts(ts: str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                # Convert to UTC then strip tzinfo for consistent comparison
                if dt.tzinfo is not None:
                    from datetime import timezone
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt

            s = _parse_ts(start)
            e = _parse_ts(end)
            actual = abs((e - s).total_seconds())
            if actual > 0 and declared > 0:
                ratio = abs(actual - declared) / max(actual, declared)
                if ratio > 0.15:
                    issues.add("notice", "duration_consistency",
                               "$.metadata",
                               f"声明的 duration_seconds={declared} 与实际时间差 "
                               f"({actual:.0f}s) 偏差 {ratio:.0%}（渲染代码使用声明值，不影响展示）")
        except (ValueError, OverflowError, TypeError):
            pass


def check_conditional_fields(data: dict, issues: IssueCollector):
    """Check that failure_reason exists when status indicates failure."""
    # Status values that the renderer treats as success (no failure_reason needed)
    SUCCESS_STATUSES = {"成功", "success", "passed", "ok"}
    # Status values that clearly indicate failure (failure_reason expected)
    FAILURE_STATUSES = {"不成功", "超时失败", "failed", "failure", "error", "blocked"}

    for section in ["build", "ut", "sample"]:
        sec = get_nested(data, f"final_results.{section}")
        if not isinstance(sec, dict):
            continue
        status = sec.get("status", "")
        has_reason = "failure_reason" in sec and sec.get("failure_reason")

        if isinstance(status, str) and status not in SUCCESS_STATUSES and status != "":
            if not has_reason:
                sev = "warning" if status in FAILURE_STATUSES or "失败" in status or "fail" in status.lower() else "notice"
                issues.add(sev, "conditional_field",
                           f"$.final_results.{section}",
                           f"状态为 '{status}' 但缺少 failure_reason 字段"
                           + ("（非成功状态缺少失败原因将影响详情页展示）" if sev == "warning" else ""))


def check_timestamp_monotonicity(data: dict, issues: IssueCollector):
    """Check timestamps in execution_log and process_timeline are monotonically non-decreasing."""
    def parse_ts(ts):
        try:
            return datetime.fromisoformat(str(ts))
        except (ValueError, OverflowError):
            return None

    exec_log = data.get("execution_log", [])
    if isinstance(exec_log, list):
        prev = None
        for i, entry in enumerate(exec_log):
            if isinstance(entry, dict) and "timestamp" in entry:
                cur = parse_ts(entry["timestamp"])
                if cur and prev and cur < prev:
                    issues.add("notice", "timestamp_order",
                               f"$.execution_log.{i}.timestamp",
                               f"时间戳回退: {entry['timestamp']} < 前一条（渲染排序可能异常）")
                if cur:
                    prev = cur

    timeline = data.get("process_timeline", [])
    if isinstance(timeline, list):
        prev = None
        for i, entry in enumerate(timeline):
            if isinstance(entry, dict) and "timestamp" in entry:
                cur = parse_ts(entry["timestamp"])
                if cur and prev and cur < prev:
                    issues.add("notice", "timestamp_order",
                               f"$.process_timeline.{i}.timestamp",
                               f"时间戳回退: {entry['timestamp']} < 前一条（渲染排序可能异常）")
                if cur:
                    prev = cur


def check_template_structure(data: dict, issues: IssueCollector):
    """Recursively compare data keys against the standard template."""
    _compare_keys(data, TEMPLATE_STRUCTURE, "", issues, unknown_as="notice")


def check_security_injection(data: dict, filepath: str, issues: IssueCollector):
    """Run security checks on the JSON content.

    Two categories:
    1. Pattern checks on ALL string values (XSS, sensitive info, base64)
    2. Shell injection checks on NON-command fields only
    """
    all_values = collect_all_values(data)

    for path, value in all_values:
        if not isinstance(value, str):
            continue
        is_cmd_field = is_command_field(path)
        full_path = f"$.{path}"

        # --- Check 1: XSS patterns (ALL fields) ---
        for pattern, desc in XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                issues.add("error", "security_xss", full_path,
                           f"XSS pattern detected: {desc} in value '{_truncate(value, 100)}'")
                break  # one XSS issue per field

        # --- Check 2: AI prompt injection (ALL fields, especially text) ---
        for pattern, desc, *flags in PROMPT_INJECTION_PATTERNS:
            kw = {}
            if flags and flags[0] is re.IGNORECASE:
                kw["flags"] = re.IGNORECASE
            if re.search(pattern, value, **kw):
                issues.add("error", "security_prompt_injection", full_path,
                           f"AI prompt injection detected: {desc} — "
                           f"'{_truncate(value, 100)}'")
                break

        # --- Check 3: Shell injection (NON-command fields only) ---
        if not is_cmd_field:
            for pattern, desc in SHELL_INJECTION_PATTERNS:
                if re.search(pattern, value):
                    issues.add("error" if "shell execution" in desc or "TCP" in desc else "warning",
                               "security_shell_injection", full_path,
                               f"Shell injection pattern in non-command field: {desc} — "
                               f"'{_truncate(value, 80)}'")
                    break

        # --- Check 3: Sensitive info (ALL fields) ---
        for pattern, desc, *flags in SENSITIVE_INFO_PATTERNS:
            kw = {}
            if flags and flags[0] is re.IGNORECASE:
                kw["flags"] = re.IGNORECASE
            if re.search(pattern, value, **kw):
                issues.add("error", "security_sensitive_info", full_path,
                           f"Possible sensitive info: {desc} in value '{_truncate(value, 80)}'")
                break

        # --- Check 4: Suspicious URLs (ALL fields) ---
        for pattern, desc in SUSPICIOUS_URL_PATTERNS + [
            (r'https?://[^/]*\b(discord|telegram|webhook)\b', "webhook/chat URL"),
            (r'https?://[^/]*\.(tk|ml|ga|cf)\b', "suspicious free domain"),
        ]:
            if re.search(pattern, value, re.IGNORECASE):
                issues.add("warning", "security_suspicious_url", full_path,
                           f"Suspicious URL: {desc} — '{_truncate(value, 100)}'")
                break

        # --- Check 5: Sensitive file paths (NON-command fields) ---
        if not is_cmd_field:
            for pattern, desc in SENSITIVE_PATHS:
                if re.search(pattern, value):
                    issues.add("warning", "security_sensitive_path", full_path,
                               f"Sensitive file path in non-path field: {desc} — "
                               f"'{_truncate(value, 80)}'")
                    break

        # --- Check 6: Base64 detection (text fields, not command output) ---
        if not is_cmd_field and len(value) > 50:
            if BASE64_PATTERN.search(value):
                issues.add("warning", "security_base64", full_path,
                           f"Possible base64-encoded content (>50 chars) in text field: "
                           f"'{_truncate(value, 60)}'")


def check_dangerous_commands(data: dict, issues: IssueCollector):
    """Audit execution_log commands for dangerous operations (informational only)."""
    exec_log = data.get("execution_log", [])
    if not isinstance(exec_log, list):
        return
    for i, entry in enumerate(exec_log):
        if not isinstance(entry, dict):
            continue
        for field in ["command", "output"]:
            value = entry.get(field, "")
            if not isinstance(value, str):
                continue
            for pattern, desc in DANGEROUS_COMMANDS:
                if re.search(pattern, value):
                    issues.add("notice", "security_dangerous_command",
                               f"$.execution_log.{i}.{field}",
                               f"Dangerous operation in execution log: {desc} — "
                               f"'{_truncate(value, 80)}'")
                    break


def check_docker_consistency(data: dict, issues: IssueCollector):
    """If docker_version says daemon unavailable, build/ut/sample should fail."""
    dv = get_nested(data, "machine_spec.host_machine.docker_version")
    if isinstance(dv, str) and "守护进程不可用" in dv:
        for section in ["build", "ut", "sample"]:
            status = get_nested(data, f"final_results.{section}.status")
            if isinstance(status, str) and status == "成功":
                issues.add("notice", "docker_consistency",
                           f"$.final_results.{section}",
                           f"Docker 守护进程不可用但 {section}.status 为 '成功' — "
                           f"数据存在矛盾，建议核实")


def check_empty_arrays(data: dict, issues: IssueCollector):
    """Flag empty arrays that may indicate incomplete data."""
    gaps = data.get("documentation_gaps", [])
    if isinstance(gaps, list) and len(gaps) == 0:
        issues.add("notice", "empty_array",
                   "$.documentation_gaps",
                   "documentation_gaps 为空（渲染代码支持，详情页文档缺口卡片留空）")

    # dockerfile mappings empty may be valid (no Dockerfile) but worth noting
    mappings = get_nested(data, "machine_spec.image_source.dependency_mapping.mappings")
    if isinstance(mappings, list) and len(mappings) == 0:
        from_dockerfile = get_nested(data, "machine_spec.image_source.dependency_mapping.from_dockerfile")
        if isinstance(from_dockerfile, str) and "Dockerfile" in from_dockerfile:
            pass  # legitimate
        else:
            issues.add("notice", "empty_array",
                       "$.machine_spec.image_source.dependency_mapping.mappings",
                       "Dependency mappings array is empty")


def check_failure_reason_quality(data: dict, issues: IssueCollector):
    """Basic heuristic check on failure_reason quality (AI does deeper analysis)."""
    for section in ["build", "ut", "sample"]:
        reason = get_nested(data, f"final_results.{section}.failure_reason")
        if isinstance(reason, str) and len(reason) < 10 and len(reason) > 0:
            issues.add("warning", "failure_reason_quality",
                       f"$.final_results.{section}.failure_reason",
                       f"failure_reason is very short ('{reason}') — lacks detail")


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string for error messages."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


# ---------------------------------------------------------------------------
# Main validation entry point
# ---------------------------------------------------------------------------

def validate_file(filepath: str) -> Dict[str, Any]:
    """Run all validation checks on a single JSON file."""
    issues = IssueCollector()

    if not os.path.isfile(filepath):
        issues.add("error", "file", "$", f"File not found: {filepath}")
        return {"file": filepath, "pass": False, "issues": issues.issues}

    # --- Phase 1: Parse ---
    data = check_valid_json(filepath, issues)
    if data is None:
        return {"file": filepath, "pass": False, "issues": issues.issues}

    # --- Phase 2: Structural checks ---
    check_top_level_keys(data, issues)
    check_metadata(data, issues)
    check_iso8601_timestamps(data, issues)
    check_type_correctness(data, issues)
    check_precommit_consistency(data, issues)
    check_duration_consistency(data, issues)
    check_conditional_fields(data, issues)
    check_timestamp_monotonicity(data, issues)
    check_template_structure(data, issues)
    check_docker_consistency(data, issues)
    check_empty_arrays(data, issues)
    check_failure_reason_quality(data, issues)

    # --- Phase 3: Security checks ---
    check_security_injection(data, filepath, issues)
    check_dangerous_commands(data, issues)

    return {"file": filepath, "pass": not issues.has_errors(), "issues": issues.issues}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: validate_json.py <file1.json> [file2.json ...]"},
                         indent=2, ensure_ascii=False))
        sys.exit(2)

    files = sys.argv[1:]
    results = {}
    overall_pass = True

    for filepath in files:
        result = validate_file(filepath)
        results[filepath] = result
        if not result["pass"]:
            overall_pass = False

    output = {
        "pass": overall_pass,
        "files": results,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
