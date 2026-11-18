# AI usage log

This log records how AI tools were used to build SlopGuard during the Mycrobo AntiSlop hackathon (17–18 Nov 2026). The hackathon rules ask for it, and it also helps judges see which decisions were human and which were machine-assisted.

## Tools

| Tool | Used for |
|---|---|
| **Claude Code** (desktop app, Claude Opus 5.5) | Pair-programming: architecture discussion, drafting modules, writing tests, running the scanner on itself, docs |
| **Claude API** (`claude-opus-5-5`) | Runtime component: the `--ai` triage agent inside SlopGuard |

## Working method

1. **Brief.** I gave the assistant the assignment text: *"a simple agent for security and pulling slop as well as coding gaps and loose ends which is architecture agnostic"*. I also gave it the arena's grading split (60 points automated checks, 40 points judges) and the required files (`arena.json`, `README.md`, `AI_LOG.md`).
2. **Design first.** Before writing code we agreed on the key decisions:
   * Python with **zero runtime dependencies**, so the tool can't break on install.
   * A **declarative language table** instead of per-language parsers. This is what makes it architecture agnostic.
   * Static detection first, **LLM triage second**. The LLM judges candidates instead of reading the whole repo blindly, which keeps cost bounded and results reproducible.
   * The agent must be **safe to point at hostile repos**: read-only sandboxed tools, secret redaction, and a prompt-injection-resistant system prompt.
3. **Build in vertical slices.** Model → discovery → rules → engine → agent → reporters → CLI → tests → docs. Each slice was run before moving on.
4. **Eat our own dog food.** After the core worked, SlopGuard scanned its own source. Every finding was either a real defect, which we fixed, or a false positive, which we turned into a rule improvement (details below). CI now enforces `--fail-on medium` on the tool's own code.

## Prompts that shaped the project (abridged)

* *"Design an architecture-agnostic agent for security, AI slop, coding gaps and loose ends. Python. Must impress reviewers: precision over noise, CI-ready, honest about limits."*
* *"Use the official Anthropic SDK with a manual tool-use loop. Tools must be read-only and confined to the repo. Send all tool results back in one user message. Handle refusal / max_tokens / API errors without losing static results."*
* *"Write tests for the agent loop with a scripted fake client, so CI needs no API key."*
* *"Scan SlopGuard with SlopGuard and fix what it finds."*

## Where AI output was wrong, and what we changed

The useful part of the log is the corrections:

| Problem found | Fix |
|---|---|
| The first self-scan flagged our own rule descriptions. The text `'... rest of code ...'` in a description string matched the elision detector. | Reworded the descriptions, and wrote every regex with `\s+` between words so pattern source code never matches itself. |
| `raise NotImplementedError` inside a *fix message string* was reported as a stub. | LOOSE003 now requires the statement at line start; abstract methods and ABCs are exempt. |
| `hashlib.sha1(..., usedforsecurity=False)` was still flagged. The negative lookahead stopped at the first `)` inside `.encode("utf-8")`. | Replaced the lookahead with an explicit line check. Our fingerprinting uses that flag on purpose. |
| `"TODO"` / `"XXX"` *string constants* in our own code were reported as placeholder values. | Removed the bare markers from SLOP003. TODOs are handled by the comment-aware LOOSE001 instead. |
| In JavaScript, `exec("ping " + host)` was labelled *code* execution. | In JS `exec` is `child_process` (shell injection) or `RegExp#exec`, so it now routes to SEC011. |
| The draft CLI excluded the report directory with `.strip('./')`, which turned `.slopguard` into `slopguard/` and would have skipped the tool's own package. | Replaced it with a proper `relative_to` computation. |
| A draft dependency-collector loop contained a meaningless `if x if False else False` line, which is exactly the kind of slop the tool hunts. | Caught in review, removed. |
| Reports embedded the **absolute local path** (leaking the OS username). | Reports now show the path as typed, e.g. `examples/vulnerable-app`. |
| Committed sample reports were re-scanned and flagged the code they quote. | SlopGuard's own report files are excluded by default. |
| Python 3.10 has no `tomllib`, so config silently didn't load there. | Raised the floor to 3.11 instead of shipping a silent behaviour difference. |
| A test inspected a message list that the agent mutates after sending. | The fake client now snapshots requests. The real SDK serialises immediately, so production was never affected. |

## Human decisions

* The name, scope, rule catalogue and severity policy (a critical finding caps the grade, and AI-dismissed findings stay visible but unscored).
* Keeping fake credentials out of the repo: tests build provider-format tokens at runtime so GitHub push protection and SlopGuard itself never see a real-looking key.
* Prioritising precision over recall: a noisy tool gets ignored.

## Verification

* `pytest`: the full suite passes locally on Windows / Python 3.14. CI runs Linux and Windows on Python 3.11–3.13.
* `slopguard scan . --fail-on medium`: SlopGuard's own source has 0 open findings (3 justified inline suppressions in the HTML report template, where every value goes through `esc()`).
* `slopguard scan examples/vulnerable-app`: every planted issue across Python, JavaScript, Go, Java, YAML and `.env` is detected.
* The agent loop is verified with a scripted client (verdicts, new issues, parallel tool results, sandbox escape attempts, refusals, network failures). A live `--ai` run needs an `ANTHROPIC_API_KEY`.
