"""Dangerous sinks and insecure defaults, expressed once and applied across languages."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..context import FileContext, RepoContext
from ..models import Category, Finding, Severity
from .base import PatternRule, Rule, RuleMeta, compile_all, register

_SEC = Category.SECURITY


@register
class DynamicCodeExecutionRule(PatternRule):
    meta = RuleMeta(
        id="SEC010", title="Dynamic code execution", category=_SEC, severity=Severity.HIGH,
        description="eval/exec-style call executes a string as code; attacker-influenced input becomes remote code execution.",
        fix="Replace with a safe parser (json.loads, ast.literal_eval, a lookup table) or an explicit dispatch.",
    )
    patterns = compile_all(
        r"(?<![\w.])eval\s*\(",
        r"(?<![\w.])exec\s*\(",
        r"\bnew\s+Function\s*\(",
        r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]",
        r"(?<![\w.])compile\s*\([^)]*[\"']exec[\"']",
    )

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        stripped = line.strip()
        # `def exec(` / `async exec(` method definitions and `.exec(` regex calls are not sinks.
        if ctx.language.name in {"javascript", "typescript", "vue", "svelte"} and match.group(0).startswith("exec"):
            return False  # in JS `exec(` is child_process (shell injection, SEC011) or RegExp#exec
        return not stripped.startswith(("def ", "async def ", "function ")) and "literal_eval" not in line


@register
class ShellInjectionRule(PatternRule):
    meta = RuleMeta(
        id="SEC011", title="Shell command built at runtime", category=_SEC, severity=Severity.HIGH,
        description="A command is run through a shell; interpolated input enables command injection.",
        fix="Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder) and validate inputs.",
    )
    patterns = compile_all(
        r"\bos\.(?:system|popen)\s*\(",
        r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True",
        r"\bchild_process\b.*\bexec(?:Sync)?\s*\(|(?<![\w.])execSync\s*\(",
        r"(?<![\w.])exec\s*\(\s*(?:[\"'][^\"']*[\"']\s*\+|`[^`]*\$\{)",  # exec("cmd " + input)
        r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
        r"\bexec\.Command\s*\(\s*\"(?:sh|bash|cmd)\"\s*,\s*\"(?:-c|/c)\"",
        r"\bshell_exec\s*\(|\bpassthru\s*\(|(?<![\w.])system\s*\(\s*\$",
        r"`[^`]*\#\{[^}]+\}[^`]*`",  # ruby backticks with interpolation
    )


_SQL_KEYWORDS = r"(?:SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|WHERE\s+\w+\s*=)"


@register
class SqlInjectionRule(PatternRule):
    meta = RuleMeta(
        id="SEC012", title="SQL built with string interpolation", category=_SEC, severity=Severity.HIGH,
        description="A SQL statement is assembled by concatenation/formatting instead of bound parameters.",
        fix="Use parameterised queries (cursor.execute(sql, params), prepared statements, or the ORM's query builder).",
    )
    patterns = compile_all(
        r"(?i)f[\"'][^\"']*" + _SQL_KEYWORDS + r"[^\"']*\{",  # python f-string
        r"(?i)[\"'][^\"']*" + _SQL_KEYWORDS + r"[^\"']*[\"']\s*(?:\+|%\s*[\w(])",  # concat / % formatting
        r"(?i)[\"'][^\"']*" + _SQL_KEYWORDS + r"[^\"']*[\"']\s*\.\s*format\s*\(",
        r"(?i)`[^`]*" + _SQL_KEYWORDS + r"[^`]*\$\{",  # JS template literal
        r"(?i)(?:Sprintf|String\.format)\s*\(\s*\"[^\"]*" + _SQL_KEYWORDS,
    )


@register
class UnsafeDeserializationRule(PatternRule):
    meta = RuleMeta(
        id="SEC013", title="Unsafe deserialization", category=_SEC, severity=Severity.HIGH,
        description="Deserializing untrusted data with this API can execute arbitrary code.",
        fix="Use a data-only format (JSON) or a safe loader (yaml.safe_load); never unpickle untrusted bytes.",
    )
    patterns = compile_all(
        r"\b(?:pickle|cPickle|dill|marshal|shelve)\.loads?\s*\(",
        r"\byaml\.load\s*\((?![^)]*(?:SafeLoader|CSafeLoader|BaseLoader))",
        r"\byaml\.unsafe_load\s*\(",
        r"\bnew\s+ObjectInputStream\s*\(",
        r"(?<![\w>])unserialize\s*\(",
        r"\bMarshal\.load\b|\bYAML\.load\s*\(",
        r"\bBinaryFormatter\s*\(",
    )


@register
class WeakCryptoRule(PatternRule):
    meta = RuleMeta(
        id="SEC014", title="Weak cryptographic primitive", category=_SEC, severity=Severity.MEDIUM,
        description="MD5/SHA-1/DES/ECB are broken for security purposes (passwords, signatures, tokens).",
        fix="Use SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords, and AES-GCM for encryption.",
    )
    patterns = compile_all(
        r"\bhashlib\.(?:md5|sha1)\s*\(",
        r"(?i)\bcreateHash\s*\(\s*[\"'](?:md5|sha1)[\"']",
        r"(?i)MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"",
        r"(?i)\bCipher\.getInstance\s*\(\s*\"[^\"]*(?:DES|/ECB/)",
        r"\bmd5\s*\(\s*\$|\bcrypto/(?:md5|sha1|des)\b",
        r"\bDES\.new\s*\(|\bAES\.MODE_ECB\b",
    )

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        return "usedforsecurity=False" not in line.replace(" ", "")  # explicit non-security use (checksums, ids)


@register
class TlsVerificationDisabledRule(PatternRule):
    meta = RuleMeta(
        id="SEC015", title="TLS certificate verification disabled", category=_SEC, severity=Severity.HIGH,
        description="Disabling certificate checks allows trivial man-in-the-middle attacks.",
        fix="Remove the override; if a private CA is needed, configure its bundle explicitly.",
        include_config_files=True,
    )
    patterns = compile_all(
        r"\bverify\s*=\s*False\b",
        r"rejectUnauthorized\s*:\s*false",
        r"InsecureSkipVerify\s*:\s*true",
        r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[=:]\s*[\"']?0",
        r"\bssl\._create_unverified_context\b|\bCERT_NONE\b",
        r"(?i)curl_setopt\([^)]*CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)",
    )


@register
class InsecureRandomRule(PatternRule):
    meta = RuleMeta(
        id="SEC016", title="Predictable randomness for a security value", category=_SEC, severity=Severity.MEDIUM,
        description="A non-cryptographic RNG generates something that looks like a token, password, OTP or key.",
        fix="Use a CSPRNG: secrets.token_urlsafe(), crypto.randomBytes()/crypto.randomUUID(), SecureRandom.",
    )
    patterns = compile_all(
        r"(?i)(?:token|password|passwd|secret|otp|nonce|salt|api_?key|session|reset)\w*\s*[:=].*"
        r"(?:\brandom\.(?:random|randint|choice|choices|getrandbits)\b|Math\.random\(|\brand\(|mt_rand\(|new\s+Random\()",
    )


@register
class XssSinkRule(PatternRule):
    meta = RuleMeta(
        id="SEC017", title="Unescaped HTML sink", category=_SEC, severity=Severity.MEDIUM,
        description="Raw HTML is injected into the page; untrusted data here is cross-site scripting.",
        fix="Render text with textContent / framework escaping, or sanitise with a vetted library (DOMPurify).",
    )
    patterns = compile_all(
        r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)",
        r"\bdangerouslySetInnerHTML\s*=",
        r"\bdocument\.write(?:ln)?\s*\(",
        r"\bv-html\s*=",
        r"\|\s*safe\b|\bmark_safe\s*\(|\bMarkup\s*\(",
        r"\binsertAdjacentHTML\s*\(",
    )


@register
class DebugEnabledRule(PatternRule):
    meta = RuleMeta(
        id="SEC018", title="Debug mode enabled", category=_SEC, severity=Severity.MEDIUM,
        description="Debug mode exposes stack traces, interactive debuggers or secrets in production.",
        fix="Drive debug flags from the environment and default them to off.",
        include_config_files=True,
        include_tests=False,
    )
    patterns = compile_all(
        r"^\s*DEBUG\s*=\s*True\b",
        r"\.run\([^)]*debug\s*=\s*True",
        r"(?i)^\s*(?:app_)?debug\s*[:=]\s*[\"']?true[\"']?\s*$",
    )


@register
class PermissiveCorsRule(PatternRule):
    meta = RuleMeta(
        id="SEC019", title="Wildcard CORS policy", category=_SEC, severity=Severity.MEDIUM,
        description="Any origin may call this API; combined with credentials this leaks user data cross-site.",
        fix="Allow-list the exact origins that need access.",
        include_config_files=True,
    )
    patterns = compile_all(
        r"(?i)Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*",
        r"(?i)allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]",
        r"(?i)\bcors\(\s*\{[^}]*origin\s*:\s*[\"']\*[\"']",
        r"(?i)CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
        r"(?i)AllowAnyOrigin\(\)",
    )


@register
class InsecureTransportRule(PatternRule):
    meta = RuleMeta(
        id="SEC020", title="Plain-HTTP endpoint", category=_SEC, severity=Severity.LOW,
        description="Traffic to this endpoint is unencrypted and can be read or modified in transit.",
        fix="Use https:// (or make the scheme configurable for local development).",
        include_tests=False,
    )
    patterns = compile_all(
        r"[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.(?:com|org)|www\.w3\.org|schemas\.|json-schema\.org|xmlns)[\w.-]+",
    )


@register
class PromptInjectionRule(PatternRule):
    meta = RuleMeta(
        id="SEC022", title="Prompt-injection payload aimed at AI agents", category=_SEC, severity=Severity.HIGH,
        description="Text addressed to an AI assistant tries to override its instructions. Coding agents and "
                    "AI reviewers that read this repo may obey it.",
        fix="Remove the text and audit who added it; never let repository content steer automation.",
        include_config_files=True,
    )
    in_comments = "any"
    patterns = compile_all(
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)",
        r"(?i)\b(?:AI|LLM|assistant|agent|copilot|claude|gpt)s?\s*[:,]?\s+(?:you\s+must|please)\s+(?:ignore|approve|mark\s+.{0,20}\s+as\s+safe|delete|run)",
        r"(?i)\b(?:do\s+not|don't)\s+(?:report|flag|mention)\s+(?:this|these)\s+(?:issue|vulnerabilit|finding|secret)",
        r"(?i)<\s*/?\s*(?:system|im_start|im_end)\s*>",
    )


@register
class SensitiveFileCommittedRule(Rule):
    meta = RuleMeta(
        id="SEC021", title="Secrets file committed", category=_SEC, severity=Severity.HIGH,
        description="Environment or key files are part of the repository.",
        fix="Delete the file from version control (and history), rotate its secrets, and add it to .gitignore.",
    )
    _NAMES = re.compile(r"(^|/)(\.env(\.(?!example$|sample$|template$|dist$)[\w.]+)?|id_rsa|id_ed25519|\.npmrc|\.pypirc|credentials\.json|service-account[\w-]*\.json|[\w-]+\.pem|[\w-]+\.p12|[\w-]+\.pfx)$")

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        for rel in repo.inventory:
            if self._NAMES.search(rel):
                yield self.finding(None, 0, f"`{rel}` looks like a secrets file checked into the repository.",
                                   snippet=rel, path=rel, confidence=0.85)
