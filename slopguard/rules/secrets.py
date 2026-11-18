"""Hard-coded credentials. Matched secrets are always redacted before they reach a report."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator

from ..context import FileContext
from ..models import Category, Finding, Severity
from .base import Rule, RuleMeta, register

# (name, pattern). Patterns are anchored on vendor-specific prefixes to keep false positives low.
PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        ("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
        ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
        ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"),
        ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        ("Stripe live key", r"\b[rs]k_live_[A-Za-z0-9]{20,}"),
        ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        ("Twilio API key", r"\bSK[0-9a-f]{32}\b"),
        ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        ("Database URL with password",
         r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"$<{]{3,}@"),
    )
)

# Cheap whole-file pre-checks so clean files skip the per-line work.
_PROVIDER_HINT = re.compile(r"AKIA|ASIA|gh[pousr]_|github_pat_|sk-|xox|_live_|AIza|SG\.|SK[0-9a-f]|eyJ|://|PRIVATE KEY")
_SECRET_HINT = re.compile(r"(?i)pass|pwd|secret|key|token|credential|auth")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")

_SECRET_NAME = (
    r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|"
    r"access[_-]?token|private[_-]?key|client[_-]?secret|token|credentials?)"
)
_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>[\w.\-]*" + _SECRET_NAME + r"[\w\-]*)[\"']?\s*(?::=|=>|[:=])\s*[\"'](?P<value>[^\"'\s]{8,})[\"']"
)
_ENV_ASSIGNMENT = re.compile(r"(?i)^\s*(?:export\s+)?(?P<name>[A-Z0-9_]*" + _SECRET_NAME + r"[A-Z0-9_]*)\s*=\s*(?P<value>[^\s#'\"]{8,})")

# Values that are obviously not real secrets.
_NOT_A_SECRET = re.compile(
    r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$|(?i:^(?:\$\{?|\{|<|%|process\.env|os\.environ|env\(|getenv|config\.|settings\.)|"
    r"(?:example|sample|dummy|placeholder|changeme|your[_\-]|xxxx|\*\*\*|redacted|test|fake|"
    r"none|null|undefined|true|false|password|secret|token))"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(line: str, secret: str) -> str:
    if len(secret) <= 8:
        masked = "*" * len(secret)
    else:
        masked = secret[:4] + "*" * min(len(secret) - 4, 12)
    return line.replace(secret, masked).strip()


@register
class ProviderSecretRule(Rule):
    meta = RuleMeta(
        id="SEC001",
        title="Hard-coded provider credential",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        description="A credential with a vendor-specific format (AWS, GitHub, Stripe, ...) is committed to source.",
        fix="Revoke and rotate the credential now, then load it from an environment variable or secret manager.",
        include_config_files=True,
    )

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        if not _PROVIDER_HINT.search(ctx.text):
            return
        for lineno, line in enumerate(ctx.lines, 1):
            for name, pattern in PROVIDER_PATTERNS:
                match = pattern.search(line)
                if match:
                    yield self.finding(
                        ctx, lineno, f"{name} committed to source.",
                        snippet=redact(line, match.group(0)),
                        severity=Severity.HIGH if ctx.is_test else Severity.CRITICAL,
                        confidence=0.95,
                    )
                    break
            else:
                if _PRIVATE_KEY.search(line):
                    yield self.finding(
                        ctx, lineno, "Private key material committed to source.",
                        snippet="-----BEGIN ... PRIVATE KEY----- (redacted)", confidence=0.99,
                    )


@register
class GenericSecretRule(Rule):
    meta = RuleMeta(
        id="SEC002",
        title="Hard-coded secret in assignment",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        description="A variable named like a password/token/key is assigned a literal, high-entropy value.",
        fix="Move the value to an environment variable or secret store and rotate it if it was ever real.",
        include_config_files=True,
    )

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        if not _SECRET_HINT.search(ctx.text):
            return
        pattern = _ENV_ASSIGNMENT if ctx.language.name == "dotenv" else _ASSIGNMENT
        for lineno, line in enumerate(ctx.lines, 1):
            if not _SECRET_HINT.search(line):
                continue
            match = pattern.search(line)
            if not match:
                continue
            value = match.group("value")
            if _NOT_A_SECRET.search(value) or any(p.search(value) for _, p in PROVIDER_PATTERNS):
                continue  # placeholders are reported by SLOP003; provider keys by SEC001
            entropy = shannon_entropy(value)
            if entropy < 3.0 or value.isalpha() and value.islower():
                continue
            yield self.finding(
                ctx, lineno,
                f"`{match.group('name')}` is assigned a literal secret (entropy {entropy:.1f} bits/char).",
                snippet=redact(line, value),
                severity=Severity.MEDIUM if ctx.is_test else Severity.HIGH,
                confidence=min(0.95, 0.5 + entropy / 10),
            )
