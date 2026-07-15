#!/usr/bin/env python3
"""
TTFHW JSON Quality Gate — Sensitive Information Scanner.

Scans verification report JSON files for sensitive information leakage across
8 categories:

1. Cloud provider credentials (AWS, Huawei, Tencent, Alibaba, Azure)
2. Code hosting platform tokens (GitHub, GitLab, GitCode)
3. Communication platform tokens (Slack, Telegram, Discord, Lark/Feishu)
4. Database connection strings with embedded credentials
5. Private keys and JWT tokens
6. Generic secret assignments (password=, token=, api_key=, etc.)
7. PII — email, phone, Chinese ID card
8. Internal network info — private IPs, MAC addresses
9. High-entropy strings (potential unknown secrets)

Usage:
    python scan_sensitive_info.py reports/*.json
    python scan_sensitive_info.py reports/file1.json reports/file2.json

Output: JSON to stdout with structure:
    {"pass": bool, "files": {path: {"pass": bool, "issues": [...]}}}

Exit code: 0 if no ERROR-level issues, 1 otherwise.
"""

import json
import re
import sys
import os
import math
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Safe values / known false-positive exclusions
# ---------------------------------------------------------------------------

# Placeholder values that should NOT be flagged as real secrets
PLACEHOLDER_VALUES = re.compile(
    r'^(?:n/?a|na|null|none|nil|true|false|yes|no|undefined|unknown|'
    r'xxx+|\.?\*\.?+|-+|<{1,3}.*>{1,3}|'  # xxx, *, -, <placeholder>
    r'your[_-]?(?:password|secret|token|key|api[_-]?key|credential)|'
    r'password|secret|token|api[_-]?key|credential|'  # literal words
    r'example|sample|test|demo|dummy|fake|placeholder|'
    r'changeme?|todo|fixme|'
    r'\$[{(]?[A-Z_]+[})]?|'  # shell variable references: $VAR, ${VAR}, $(VAR)
    r'\*+|'  # masked: ******
    r'localhost|127\.0\.0\.1|0\.0\.0\.0|'
    r'\d+)$',
    re.IGNORECASE,
)

# Safe email domains that are commonly used as examples
SAFE_EMAIL_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'test.com', 'test.org',
    'localhost',
}

# Hash-like patterns (not secrets, just build artifacts)
HASH_PATTERNS = [
    re.compile(r'^sha\d*:\s*[0-9a-f]+$', re.IGNORECASE),  # sha256:abc123...
    re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE),  # git commit hash
    re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE),  # sha256 hash
    re.compile(r'^[0-9a-f]{32}$', re.IGNORECASE),  # md5 hash
]

# UUID pattern
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# Each entry: (regex, description) for fixed-severity categories,
# or (regex, description, severity) for mixed-severity categories.
# severity: "error" (blocking) or "warning" (advisory) or "notice"

# --- Category 1: Cloud Provider Credentials ---
CLOUD_CREDENTIAL_PATTERNS: List[Tuple[str, str]] = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'aws_secret_access_key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
     "AWS Secret Access Key assignment"),
    (r'aws_session_token\s*[=:]\s*["\']?[A-Za-z0-9/+=]{100,}["\']?',
     "AWS Session Token assignment"),
    (r'AKID[A-Za-z0-9]{13,40}', "Tencent Cloud Secret ID"),
    (r'tencent[_-]?cloud[_-]?(?:secret|sk)\s*[=:]\s*["\']?[A-Za-z0-9]{32,36}["\']?',
     "Tencent Cloud Secret Key assignment"),
    (r'LTAI[A-Za-z0-9]{12,24}', "Alibaba Cloud Access Key ID"),
    (r'aliyun[_-]?(?:secret|sk)\s*[=:]\s*["\']?[A-Za-z0-9]{30}["\']?',
     "Alibaba Cloud Access Key Secret assignment"),
    (r'AK[A-Z]{2}\d{2}[A-Za-z0-9]{16,48}', "Huawei Cloud Access Key ID"),
    (r'huawei[_-]?cloud[_-]?(?:secret|sk)\s*[=:]\s*["\']?[A-Za-z0-9]{32,64}["\']?',
     "Huawei Cloud Secret Access Key assignment"),
    (r'(?:AccountKey|account_key)\s*[=:]\s*["\']?[A-Za-z0-9+/=]{88}["\']?',
     "Azure Storage Account Key assignment"),
    (r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+',
     "Azure Storage Connection String"),
]

# --- Category 2: Code Hosting Platform Tokens ---
CODE_HOSTING_TOKEN_PATTERNS: List[Tuple[str, str]] = [
    (r'gh[pousr]_[A-Za-z0-9]{36,255}', "GitHub Token"),
    (r'github_pat_[A-Za-z0-9_]{22,}', "GitHub Fine-grained PAT"),
    (r'glpat-[A-Za-z0-9_-]{20}', "GitLab Personal Access Token"),
    (r'gitcode[_-]?(?:token|pat)\s*[=:]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
     "GitCode Token assignment"),
    (r'gitee[_-]?(?:token|pat)\s*[=:]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
     "Gitee Token assignment"),
]

# --- Category 3: Communication Platform Tokens ---
COMMUNICATION_TOKEN_PATTERNS: List[Tuple[str, str]] = [
    (r'xox[abprs]-[A-Za-z0-9-]{10,72}', "Slack Token"),
    (r'\d{8,12}:AA[A-Za-z0-9_-]{33,35}', "Telegram Bot Token"),
    (r'discord[_-]?(?:bot[_-]?)?token\s*[=:]\s*["\']?[A-Za-z0-9._-]{50,}["\']?',
     "Discord Bot Token assignment"),
    (r'lark[_-]?(?:app[_-]?secret|tenant[_-]?access[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
     "Lark/Feishu Secret assignment"),
    (r'feishu[_-]?(?:app[_-]?secret|tenant[_-]?access[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
     "Feishu Secret assignment"),
    (r'webhook[_-]?url\s*[=:]\s*["\']?https?://[^/]*\b(hooks|webhook)\b[^"\']*["\']?',
     "Webhook URL with credentials"),
]

# --- Category 4: Database Connection Strings ---
# Only flag when credentials are embedded (user:password@host)
DATABASE_CONNECTION_PATTERNS: List[Tuple[str, str]] = [
    (r'mongodb(?:\+srv)?://[^:\s"\'\s]+:[^@\s"\'\s]+@[^/\s"\'\s]+',
     "MongoDB connection string with credentials"),
    (r'mysql://[^:\s"\'\s]+:[^@\s"\'\s]+@[^/\s"\'\s]+',
     "MySQL connection string with credentials"),
    (r'(?:postgres|postgresql)://[^:\s"\'\s]+:[^@\s"\'\s]+@[^/\s"\'\s]+',
     "PostgreSQL connection string with credentials"),
    (r'redis://(?::[^@\s"\'\s]+|[^:\s"\'\s]+:[^@\s"\'\s]+)@[^/\s"\'\s]+',
     "Redis connection string with credentials"),
    (r'amqp://[^:\s"\'\s]+:[^@\s"\'\s]+@[^/\s"\'\s]+',
     "AMQP/RabbitMQ connection string with credentials"),
    (r'jdbc:(?:mysql|postgresql|oracle|sqlserver)://[^:\s"\'\s]+:[^@\s"\'\s]+@[^/\s"\'\s]+',
     "JDBC connection string with credentials"),
]

# --- Category 5: Private Keys & JWT ---
CRYPTO_PATTERNS: List[Tuple[str, str]] = [
    (r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----',
     "Private Key block"),
    (r'-----BEGIN\s+(?:CERTIFICATE|PUBLIC\s+KEY)-----[\s\S]{100,}?-----END\s+(?:CERTIFICATE|PUBLIC\s+KEY)-----',
     "Embedded certificate/public key"),
    (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
     "JWT Token"),
    (r'sk-[a-zA-Z0-9]{32,}', "OpenAI/Anthropic API Key"),
    (r'sk-ant-[A-Za-z0-9_-]{40,}', "Anthropic API Key"),
    (r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}', "Bearer Token"),
]

# --- Category 6: Generic Secret Assignments ---
# Uses negative lookahead to skip placeholder values.
# The value must be non-trivial (>= 4 chars, not a placeholder).
_PLACEHOLDERS = (
    r'N/?A|na|null|none|nil|true|false|undefined|unknown|'
    r'xxx+|\*+|-+|<{1,3}[^>]*>{1,3}|'
    r'your[_-]?(?:password|secret|token|key)|'
    r'password|secret|token|key|credential|'
    r'example|sample|test|demo|dummy|fake|placeholder|changeme?|todo|'
    r'\$[{(]?[A-Z_][A-Z0-9_]*[})]?'
)

GENERIC_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    (rf'(?:password|passwd|pwd)\s*[=:]\s*["\']?(?!{_PLACEHOLDERS}\s|{_PLACEHOLDERS}["\']|{_PLACEHOLDERS}$)\S{{4,}}["\']?',
     "Password assignment", "error"),
    (rf'secret\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{4,}}["\']?',
     "Secret assignment", "error"),
    (rf'api[_-]?key\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{8,}}["\']?',
     "API key assignment", "error"),
    (rf'access[_-]?token\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{16,}}["\']?',
     "Access token assignment", "error"),
    (rf'auth[_-]?token\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{16,}}["\']?',
     "Auth token assignment", "error"),
    (rf'refresh[_-]?token\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{16,}}["\']?',
     "Refresh token assignment", "error"),
    (rf'credential\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{8,}}["\']?',
     "Credential assignment", "error"),
    (rf'(?:client[_-]?secret|app[_-]?secret)\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{8,}}["\']?',
     "Client/App secret assignment", "error"),
    (rf'(?:private[_-]?key|priv[_-]?key)\s*[=:]\s*["\']?(?!{_PLACEHOLDERS})\S{{16,}}["\']?',
     "Private key assignment", "error"),
]

# --- Category 7: PII — Personal Information ---
PII_PATTERNS: List[Tuple[str, str, str]] = [
    (r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
     "Email address", "warning"),
    (r'(?<!\d)1[3-9]\d{9}(?!\d)',
     "Chinese mobile phone number", "warning"),
    (r'(?<!\d)\d{17}[\dXx](?!\d)',
     "Chinese ID card number", "error"),
]

# --- Category 8: Internal Network Information ---
NETWORK_INFO_PATTERNS: List[Tuple[str, str, str]] = [
    (r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
     r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
     r'|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
     "Private IP address", "warning"),
    (r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
     "MAC address", "notice"),
]

# --- Compiled patterns (done at module load for performance) ---
def _compile_patterns(
    patterns: List[Tuple[str, str, str]],
    default_severity: str = "error",
    ignore_case: bool = True,
) -> List[Tuple[re.Pattern, str, str]]:
    """Compile regex patterns with appropriate flags."""
    compiled = []
    flags = re.IGNORECASE if ignore_case else 0
    for entry in patterns:
        if len(entry) == 3:
            regex, desc, sev = entry
        else:
            regex, desc = entry
            sev = default_severity
        compiled.append((re.compile(regex, flags), desc, sev))
    return compiled


COMPILED_CLOUD = _compile_patterns(
    [(r, d, "error") for r, d in CLOUD_CREDENTIAL_PATTERNS]
)
COMPILED_CODE_HOSTING = _compile_patterns(
    [(r, d, "error") for r, d in CODE_HOSTING_TOKEN_PATTERNS]
)
COMPILED_COMMUNICATION = _compile_patterns(
    [(r, d, "error") for r, d in COMMUNICATION_TOKEN_PATTERNS]
)
COMPILED_DATABASE = _compile_patterns(
    [(r, d, "error") for r, d in DATABASE_CONNECTION_PATTERNS]
)
COMPILED_CRYPTO = _compile_patterns(
    [(r, d, "error") for r, d in CRYPTO_PATTERNS]
)
COMPILED_GENERIC_SECRET = _compile_patterns(GENERIC_SECRET_PATTERNS)
COMPILED_PII = _compile_patterns(PII_PATTERNS)
COMPILED_NETWORK = _compile_patterns(NETWORK_INFO_PATTERNS)

# All compiled patterns grouped for scanning
ALL_PATTERN_GROUPS = [
    ("sensitive_cloud_credential", COMPILED_CLOUD),
    ("sensitive_code_hosting_token", COMPILED_CODE_HOSTING),
    ("sensitive_communication_token", COMPILED_COMMUNICATION),
    ("sensitive_database_connection", COMPILED_DATABASE),
    ("sensitive_crypto_secret", COMPILED_CRYPTO),
    ("sensitive_generic_secret", COMPILED_GENERIC_SECRET),
    ("sensitive_pii", COMPILED_PII),
    ("sensitive_network_info", COMPILED_NETWORK),
]


# ---------------------------------------------------------------------------
# Entropy-based detection
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s or len(s) < 2:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_hash_like(s: str) -> bool:
    """Check if string looks like a known hash format (not a secret)."""
    for pattern in HASH_PATTERNS:
        if pattern.match(s):
            return True
    return False


def is_uuid(s: str) -> bool:
    """Check if string is a UUID."""
    return bool(UUID_PATTERN.match(s))


def is_safe_email(email: str) -> bool:
    """Check if email uses a known safe/example domain."""
    domain = email.rsplit('@', 1)[-1].lower()
    return domain in SAFE_EMAIL_DOMAINS


def is_git_url(matched_text: str, full_value: str) -> bool:
    """Check if an email-like match is actually a git SSH URL (git@host:...)."""
    # git@gitcode.com:user/repo.git — not an email
    if matched_text.lower().startswith('git@'):
        return True
    # Check if the full value contains git@ pattern
    idx = full_value.find(matched_text)
    if idx >= 0:
        after = full_value[idx + len(matched_text):idx + len(matched_text) + 1]
        if after == ':':
            return True
    return False


def is_url_credential(matched_text: str, full_value: str) -> bool:
    """Check if an email-like match is actually a URL credential (user:pass@host)."""
    idx = full_value.find(matched_text)
    if idx > 0:
        before = full_value[:idx]
        # If preceded by ://something: (URL with credentials like https://user:token@host)
        if '://' in before and before.rstrip().endswith(':'):
            return True
    return False


def is_package_version(matched_text: str) -> bool:
    """Check if an email-like match is actually a package version reference.

    Conan packages use format: name/version@user/channel
    e.g., libmcpp/1.2.164@openubmc.dev/dev
    The @ part looks like an email but isn't.
    """
    local_part = matched_text.rsplit('@', 1)[0]
    # Version-like: starts with digit, contains dots/dashes
    if local_part and local_part[0].isdigit():
        return True
    # All digits and dots (like 1.100.54)
    if re.match(r'^[\d.]+$', local_part):
        return True
    return False


def contains_cjk(s: str) -> bool:
    """Check if string contains CJK (Chinese/Japanese/Korean) characters.

    CJK text has naturally high entropy due to large Unicode code point range,
    causing false positives in entropy-based secret detection.
    """
    for ch in s:
        cp = ord(ch)
        # CJK Unified Ideographs, CJK Extension A, CJK Compatibility,
        # Hiragana, Katakana, Hangul Syllables, CJK Symbols & Punctuation
        if (0x4E00 <= cp <= 0x9FFF or   # CJK Unified Ideographs
            0x3400 <= cp <= 0x4DBF or   # CJK Extension A
            0x3040 <= cp <= 0x30FF or   # Hiragana + Katakana
            0xAC00 <= cp <= 0xD7AF or   # Hangul Syllables
            0x3000 <= cp <= 0x303F or   # CJK Symbols & Punctuation
            0xFF00 <= cp <= 0xFFEF):    # Fullwidth Forms
            return True
    return False


def looks_like_filename(s: str) -> bool:
    """Check if string looks like a filename (has a known extension)."""
    filename_extensions = (
        '.json', '.whl', '.tar', '.gz', '.tgz', '.zip', '.so', '.a',
        '.py', '.sh', '.txt', '.md', '.yml', '.yaml', '.xml', '.html',
        '.js', '.ts', '.go', '.rs', '.c', '.cpp', '.h', '.hpp',
        '.rpm', '.deb', '.img', '.iso', '.bin', '.exe', '.dll',
        '.jar', '.war', '.class', '.deb', '.patch', '.diff',
    )
    lower = s.lower()
    for ext in filename_extensions:
        if lower.endswith(ext):
            return True
    return False


def check_entropy(value: str, path: str) -> Optional[Dict[str, Any]]:
    """Check if a string has suspiciously high entropy (potential secret).

    Only flags strings that:
    - Are longer than 40 characters
    - Have entropy > 4.5 (typical for base64/hex encoded secrets)
    - Are pure ASCII (no CJK characters, which inflate entropy)
    - Don't look like hashes, UUIDs, filenames, file paths, or URLs
    - Are predominantly alphanumeric (no spaces, few special chars)
    - Consist mainly of base64/hex character set
    """
    if len(value) < 40:
        return None

    # Skip if it looks like a known benign pattern
    if is_hash_like(value) or is_uuid(value):
        return None
    if looks_like_filename(value):
        return None
    if '/' in value or value.startswith('http') or value.startswith('/'):
        return None
    if ' ' in value or '\n' in value:
        return None

    # Skip CJK text — high Unicode code points inflate entropy
    if contains_cjk(value):
        return None

    # Skip if too many non-alphanumeric chars (likely a sentence, not a secret)
    alnum_count = sum(1 for c in value if c.isalnum())
    if alnum_count / len(value) < 0.8:
        return None

    # Only flag if the string looks like base64 or hex encoding
    # (secrets are typically encoded as base64 or hex)
    # Allow: A-Z, a-z, 0-9, +, /, =, -, _ (base64 and base64url chars)
    if not re.match(r'^[A-Za-z0-9+/=_-]+$', value):
        return None

    entropy = shannon_entropy(value)
    if entropy > 4.5:
        return {
            "severity": "warning",
            "check": "sensitive_high_entropy",
            "path": path,
            "message": (f"High-entropy string detected (entropy={entropy:.2f}, "
                        f"len={len(value)}) — possible encoded secret: "
                        f"'{_truncate(value, 60)}'"),
        }
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate(s: str, max_len: int) -> str:
    """Truncate a string for error messages, masking the middle."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


def _mask_value(s: str) -> str:
    """Mask a sensitive value for display, showing only first/last few chars."""
    if len(s) <= 12:
        return s[:2] + "***"
    return s[:4] + "..." + s[-4:]


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


# ---------------------------------------------------------------------------
# Issue collector
# ---------------------------------------------------------------------------

class IssueCollector:
    """Collects scan issues for a single file."""

    def __init__(self):
        self.issues: List[Dict[str, Any]] = []

    def add(self, severity: str, check: str, path: str, message: str):
        self.issues.append({
            "severity": severity,
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
# Core scanning logic
# ---------------------------------------------------------------------------

def scan_string_value(value: str, path: str, issues: IssueCollector):
    """Scan a single string value against all pattern groups."""
    if not isinstance(value, str) or not value:
        return

    full_path = f"$.{path}" if path else "$"

    # Quick check: skip if value is a known placeholder
    stripped = value.strip()
    if stripped and PLACEHOLDER_VALUES.match(stripped):
        return

    # Run all pattern groups
    for check_name, compiled_patterns in ALL_PATTERN_GROUPS:
        for pattern, desc, severity in compiled_patterns:
            match = pattern.search(value)
            if match:
                matched_text = match.group(0)
                # Extra checks for email: skip false positives
                if desc == "Email address":
                    # Skip safe/example domains
                    if is_safe_email(matched_text):
                        continue
                    # Skip git SSH URLs (git@host:...)
                    if is_git_url(matched_text, value):
                        continue
                    # Skip URL credentials (https://user:token@host)
                    if is_url_credential(matched_text, value):
                        continue
                    # Skip package version references (1.2.3@user/channel)
                    if is_package_version(matched_text):
                        continue
                    # Skip noreply addresses
                    local_part = matched_text.split("@")[0].lower()
                    if local_part in ("noreply", "no-reply", "donotreply"):
                        continue

                issues.add(
                    severity,
                    check_name,
                    full_path,
                    f"{desc} detected: '{_mask_value(matched_text)}' "
                    f"in value '{_truncate(value, 80)}'",
                )
                # Only report one match per pattern group per value
                break

    # Entropy check (only for values that didn't match any specific pattern
    # and are not in known-safe categories)
    ent_issue = check_entropy(value, full_path)
    if ent_issue:
        issues.issues.append(ent_issue)


def scan_file(filepath: str) -> Dict[str, Any]:
    """Run sensitive info scan on a single JSON file."""
    issues = IssueCollector()

    if not os.path.isfile(filepath):
        issues.add("error", "file", "$", f"File not found: {filepath}")
        return {"file": filepath, "pass": False, "issues": issues.issues}

    # Read and parse JSON
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        issues.add("error", "json_parse", "$",
                   f"JSON parse error: {e.msg} (line {e.lineno}, col {e.colno})")
        return {"file": filepath, "pass": False, "issues": issues.issues}
    except Exception as e:
        issues.add("error", "file_read", "$", f"Cannot read file: {e}")
        return {"file": filepath, "pass": False, "issues": issues.issues}

    # Collect all string values and scan each
    all_values = collect_all_values(data)
    for path, value in all_values:
        if isinstance(value, str):
            scan_string_value(value, path, issues)

    return {
        "file": filepath,
        "pass": not issues.has_errors(),
        "issues": issues.issues,
    }


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def print_summary(results: Dict[str, Any]):
    """Print a human-readable summary to stderr."""
    total_errors = 0
    total_warnings = 0
    total_notices = 0
    files_with_issues = 0

    for filepath, info in results.items():
        issues = info.get("issues", [])
        if not issues:
            continue
        files_with_issues += 1
        errors = [i for i in issues if i["severity"] == "error"]
        warnings = [i for i in issues if i["severity"] == "warning"]
        notices = [i for i in issues if i["severity"] == "notice"]
        total_errors += len(errors)
        total_warnings += len(warnings)
        total_notices += len(notices)

    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    if total_errors > 0:
        print(f"🚫 敏感信息扫描: {total_errors} 个 ERROR, "
              f"{total_warnings} 个 WARNING, "
              f"{total_notices} 个 NOTICE "
              f"(涉及 {files_with_issues} 个文件)", file=sys.stderr)
    elif total_warnings > 0:
        print(f"⚠️ 敏感信息扫描: {total_warnings} 个 WARNING, "
              f"{total_notices} 个 NOTICE "
              f"(涉及 {files_with_issues} 个文件)", file=sys.stderr)
    elif total_notices > 0:
        print(f"ℹ️ 敏感信息扫描: {total_notices} 个 NOTICE "
              f"(涉及 {files_with_issues} 个文件)", file=sys.stderr)
    else:
        print("✅ 敏感信息扫描: 未发现敏感信息", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Print details for errors and warnings
    for filepath, info in results.items():
        issues = info.get("issues", [])
        if not issues:
            continue
        critical = [i for i in issues if i["severity"] in ("error", "warning")]
        if not critical:
            continue
        fname = filepath.split("/")[-1]
        print(f"\n📄 {fname}", file=sys.stderr)
        for issue in critical:
            icon = "🚫" if issue["severity"] == "error" else "⚠️"
            print(f"  {icon} [{issue['check']}] {issue['path']}",
                  file=sys.stderr)
            print(f"     {issue['message']}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(json.dumps(
            {"error": "Usage: scan_sensitive_info.py <file1.json> [file2.json ...]"},
            indent=2, ensure_ascii=False))
        sys.exit(2)

    files = sys.argv[1:]
    results = {}
    overall_pass = True

    for filepath in files:
        result = scan_file(filepath)
        results[filepath] = result
        if not result["pass"]:
            overall_pass = False

    output = {
        "pass": overall_pass,
        "files": results,
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))
    print_summary(results)

    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
