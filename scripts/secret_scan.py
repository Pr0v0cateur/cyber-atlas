#!/usr/bin/env python3
"""Scan repository files for likely committed secrets.

The script intentionally avoids external dependencies so it can run locally and
inside CI before the repository is pushed or reviewed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
]

SENSITIVE_ASSIGNMENT = re.compile(
    r"^\s*("
    r"THREATFOX_KEY|OTX_KEY|ABUSEIPDB_KEY|VIRUSTOTAL_KEY|"
    r"JWT_SECRET_KEY|SESSION_SECRET_KEY|"
    r"POSTGRES_PASSWORD|REDIS_PASSWORD|OPENSEARCH_PASSWORD|DEFAULT_ADMIN_PASSWORD|"
    r"DATABASE_URL|DATABASE_URL_ASYNC|REDIS_URL|OPENSEARCH_URL"
    r")\s*=\s*(.+?)\s*$",
    re.IGNORECASE,
)

SAFE_PLACEHOLDER_WORDS = (
    "change-me",
    "replace-with",
    "placeholder",
    "example",
    "your-",
    "<your",
    "[your",
)

ALLOWED_EXAMPLE_FILES = {
    ".env.example",
    ".env.production.example",
}

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".sqlite",
    ".db",
    ".pyc",
}


def git_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    files = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        files.append(REPO_ROOT / raw_path.decode("utf-8"))
    return files


def is_placeholder(value: str) -> bool:
    normalized = value.strip().strip('"').strip("'").lower()
    if not normalized:
        return True
    if normalized.startswith("${") and normalized.endswith("}"):
        return True
    return any(word in normalized for word in SAFE_PLACEHOLDER_WORDS)


def scan_file(path: Path) -> list[str]:
    relative = path.relative_to(REPO_ROOT).as_posix()
    if path.suffix.lower() in SKIP_SUFFIXES:
        return []

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[str] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(f"{relative}:{line_number}: possible {label}")

        assignment = SENSITIVE_ASSIGNMENT.match(line)
        if not assignment:
            continue

        value = assignment.group(2)
        if relative in ALLOWED_EXAMPLE_FILES and is_placeholder(value):
            continue
        if is_placeholder(value):
            continue

        findings.append(f"{relative}:{line_number}: sensitive value is not a placeholder")

    return findings


def main() -> int:
    findings: list[str] = []
    for path in git_files():
        findings.extend(scan_file(path))

    if findings:
        print("Secret scan failed. Review these lines before committing or pushing:\n")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    print("Secret scan passed. No likely committed secrets found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
