"""Conservative public-source checks; reports locations, never matched secrets.

This is a heuristic check, not a guarantee that arbitrary sensitive data is absent.
Use --secret-env with private configuration files outside the source tree to also
check for exact credential-value reuse. No configuration values are printed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


ROOT_FILES = {"README.md", "THIRD_PARTY_NOTICES.md", "SECURITY.md", "LICENSE", "CITATION.cff",
              ".gitignore", ".gitattributes", ".env.example", "pyproject.toml",
              "requirements.txt", "requirements.lock.txt"}
ROOT_DIRS = {"src", "configs", "prompts", "tests", "docs", "examples", "scripts"}
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache"}
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "service_token": re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b"),
    "private_ipv4": re.compile(r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"),
    "personal_windows_path": re.compile(r"\b[A-Za-z]:[\\/](?:Users|项目部署|6服务器)[\\/]", re.I),
}


def scan(root, secret_values=()):
    findings, count = [], 0
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS or part.endswith('.egg-info') for part in relative.parts):
            continue
        if path.is_symlink():
            findings.append({'file': relative.as_posix(), 'rule': 'symlink'})
            continue
        if not path.is_file():
            continue
        count += 1
        name = relative.as_posix()
        if (relative.parts[0] not in ROOT_DIRS and name not in ROOT_FILES or
                path.name in {'web.py', 'schema_library.py'} or
                path.suffix.lower() in {'.html', '.css', '.js', '.cjs', '.zip', '.gz', '.pem', '.key'} or
                path.name.startswith('.env') and path.name != '.env.example'):
            findings.append({'file': name, 'rule': 'publication_boundary'})
        try:
            content = path.read_text(encoding='utf-8-sig')
        except (UnicodeError, OSError):
            findings.append({'file': name, 'rule': 'unreviewed_binary'})
            continue
        for rule, pattern in PATTERNS.items():
            for match in pattern.finditer(content):
                findings.append({'file': name, 'line': content.count('\n', 0, match.start()) + 1, 'rule': rule})
        for secret in secret_values:
            if secret and secret in content:
                findings.append({'file': name, 'rule': 'private_configuration_value'})
    return {'files_checked': count, 'passed': not findings, 'findings': findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--secret-env', type=Path, action='append', default=[])
    args = parser.parse_args()
    values = []
    if args.secret_env:
        from dotenv import dotenv_values
        for path in args.secret_env:
            for key, value in dotenv_values(path).items():
                if value and re.search(r'KEY|TOKEN|PASSWORD|SECRET', key, re.I) and len(value) >= 8:
                    values.append(value)
    report = scan(args.root.resolve(), values)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
