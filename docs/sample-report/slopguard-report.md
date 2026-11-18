# SlopGuard report

**Health score: 0/100 (grade F)** · 8 files · 243 lines · python, dotenv, yaml, java, json, javascript

## Overview

| Category | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Security | 1 | 20 | 9 | 1 | 0 |
| AI Slop | 0 | 4 | 2 | 5 | 0 |
| Coding Gap | 0 | 5 | 7 | 1 | 0 |
| Loose End | 0 | 0 | 6 | 18 | 0 |

## Security (31)

| | Rule | Location | Finding | Fix |
|---|---|---|---|---|
| 🟥 critical | `SEC001` | `api/app.py:14` | **Hard-coded provider credential**<br>Database URL with password committed to source. | Revoke and rotate the credential now, then load it from an environment variable or secret manager. |
| 🟧 high | `SEC021` | `.env` | **Secrets file committed**<br>`.env` looks like a secrets file checked into the repository. | Delete the file from version control (and history), rotate its secrets, and add it to .gitignore. |
| 🟧 high | `SEC002` | `.env:1` | **Hard-coded secret in assignment**<br>`STRIPE_SECRET` is assigned a literal secret (entropy 4.4 bits/char). | Move the value to an environment variable or secret store and rotate it if it was ever real. |
| 🟧 high | `SEC002` | `api/app.py:13` | **Hard-coded secret in assignment**<br>`DB_PASSWORD` is assigned a literal secret (entropy 4.2 bits/char). | Move the value to an environment variable or secret store and rotate it if it was ever real. |
| 🟧 high | `SEC012` | `api/app.py:22` | **SQL built with string interpolation**<br>A SQL statement is assembled by concatenation/formatting instead of bound parameters. | Use parameterised queries (cursor.execute(sql, params), prepared statements, or the ORM's query builder). |
| 🟧 high | `SEC011` | `api/app.py:30` | **Shell command built at runtime**<br>A command is run through a shell; interpolated input enables command injection. | Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder) and validate inputs. |
| 🟧 high | `SEC011` | `api/app.py:31` | **Shell command built at runtime**<br>A command is run through a shell; interpolated input enables command injection. | Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder) and validate inputs. |
| 🟧 high | `SEC013` | `api/app.py:37` | **Unsafe deserialization**<br>Deserializing untrusted data with this API can execute arbitrary code. | Use a data-only format (JSON) or a safe loader (yaml.safe_load); never unpickle untrusted bytes. |
| 🟧 high | `SEC013` | `api/app.py:38` | **Unsafe deserialization**<br>Deserializing untrusted data with this API can execute arbitrary code. | Use a data-only format (JSON) or a safe loader (yaml.safe_load); never unpickle untrusted bytes. |
| 🟧 high | `SEC015` | `api/app.py:49` | **TLS certificate verification disabled**<br>Disabling certificate checks allows trivial man-in-the-middle attacks. | Remove the override; if a private CA is needed, configure its bundle explicitly. |
| 🟧 high | `SEC010` | `api/app.py:56` | **Dynamic code execution**<br>eval/exec-style call executes a string as code; attacker-influenced input becomes remote code execution. | Replace with a safe parser (json.loads, ast.literal_eval, a lookup table) or an explicit dispatch. |
| 🟧 high | `SEC002` | `billing/Invoice.java:7` | **Hard-coded secret in assignment**<br>`password` is assigned a literal secret (entropy 3.8 bits/char). | Move the value to an environment variable or secret store and rotate it if it was ever real. |
| 🟧 high | `SEC013` | `billing/Invoice.java:10` | **Unsafe deserialization**<br>Deserializing untrusted data with this API can execute arbitrary code. | Use a data-only format (JSON) or a safe loader (yaml.safe_load); never unpickle untrusted bytes. |
| 🟧 high | `SEC011` | `billing/Invoice.java:21` | **Shell command built at runtime**<br>A command is run through a shell; interpolated input enables command injection. | Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder) and validate inputs. |
| 🟧 high | `SEC022` | `config.yaml:1` | **Prompt-injection payload aimed at AI agents**<br>Text addressed to an AI assistant tries to override its instructions. Coding agents and AI reviewers that read this repo may obey it. | Remove the text and audit who added it; never let repository content steer automation. |
| 🟧 high | `SEC012` | `web/server.js:11` | **SQL built with string interpolation**<br>A SQL statement is assembled by concatenation/formatting instead of bound parameters. | Use parameterised queries (cursor.execute(sql, params), prepared statements, or the ORM's query builder). |
| 🟧 high | `SEC011` | `web/server.js:16` | **Shell command built at runtime**<br>A command is run through a shell; interpolated input enables command injection. | Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder) and validate inputs. |
| 🟧 high | `SEC010` | `web/server.js:20` | **Dynamic code execution**<br>eval/exec-style call executes a string as code; attacker-influenced input becomes remote code execution. | Replace with a safe parser (json.loads, ast.literal_eval, a lookup table) or an explicit dispatch. |
| 🟧 high | `SEC012` | `worker/main.go:14` | **SQL built with string interpolation**<br>A SQL statement is assembled by concatenation/formatting instead of bound parameters. | Use parameterised queries (cursor.execute(sql, params), prepared statements, or the ORM's query builder). |
| 🟧 high | `SEC011` | `worker/main.go:17` | **Shell command built at runtime**<br>A command is run through a shell; interpolated input enables command injection. | Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder) and validate inputs. |
| 🟧 high | `SEC015` | `worker/main.go:22` | **TLS certificate verification disabled**<br>Disabling certificate checks allows trivial man-in-the-middle attacks. | Remove the override; if a private CA is needed, configure its bundle explicitly. |
| 🟨 medium | `SEC018` | `.env:2` | **Debug mode enabled**<br>Debug mode exposes stack traces, interactive debuggers or secrets in production. | Drive debug flags from the environment and default them to off. |
| 🟨 medium | `SEC014` | `api/app.py:43` | **Weak cryptographic primitive**<br>MD5/SHA-1/DES/ECB are broken for security purposes (passwords, signatures, tokens). | Use SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords, and AES-GCM for encryption. |
| 🟨 medium | `SEC018` | `api/app.py:80` | **Debug mode enabled**<br>Debug mode exposes stack traces, interactive debuggers or secrets in production. | Drive debug flags from the environment and default them to off. |
| 🟨 medium | `SEC016` | `api/utils.py:7` | **Predictable randomness for a security value**<br>A non-cryptographic RNG generates something that looks like a token, password, OTP or key. | Use a CSPRNG: secrets.token_urlsafe(), crypto.randomBytes()/crypto.randomUUID(), SecureRandom. |
| 🟨 medium | `SEC014` | `billing/Invoice.java:15` | **Weak cryptographic primitive**<br>MD5/SHA-1/DES/ECB are broken for security purposes (passwords, signatures, tokens). | Use SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords, and AES-GCM for encryption. |
| 🟨 medium | `SEC018` | `config.yaml:3` | **Debug mode enabled**<br>Debug mode exposes stack traces, interactive debuggers or secrets in production. | Drive debug flags from the environment and default them to off. |
| 🟨 medium | `SEC017` | `web/server.js:25` | **Unescaped HTML sink**<br>Raw HTML is injected into the page; untrusted data here is cross-site scripting. | Render text with textContent / framework escaping, or sanitise with a vetted library (DOMPurify). |
| 🟨 medium | `SEC016` | `web/server.js:29` | **Predictable randomness for a security value**<br>A non-cryptographic RNG generates something that looks like a token, password, OTP or key. | Use a CSPRNG: secrets.token_urlsafe(), crypto.randomBytes()/crypto.randomUUID(), SecureRandom. |
| 🟨 medium | `SEC014` | `worker/main.go:4` | **Weak cryptographic primitive**<br>MD5/SHA-1/DES/ECB are broken for security purposes (passwords, signatures, tokens). | Use SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords, and AES-GCM for encryption. |
| 🟦 low | `SEC020` | `web/server.js:35` | **Plain-HTTP endpoint**<br>Traffic to this endpoint is unencrypted and can be read or modified in transit. | Use https:// (or make the scheme configurable for local development). |

## AI Slop (11)

| | Rule | Location | Finding | Fix |
|---|---|---|---|---|
| 🟧 high | `SLOP004` | `api/app.py:9` | **Undeclared (possibly hallucinated) dependency**<br>`flask_jwt_magic` is imported but not declared in any Python manifest. | Verify the package really exists and is the one you intend, then declare and pin it - or remove the import. |
| 🟧 high | `SLOP004` | `web/server.js:3` | **Undeclared (possibly hallucinated) dependency**<br>`left-pad-pro-max` is imported but not declared in any package.json. | Verify the package really exists and is the one you intend, then declare and pin it - or remove the import. |
| 🟧 high | `SLOP001` | `web/server.js:8` | **LLM chat residue in code**<br>Conversational assistant text or a markdown fence was pasted into a source file. | Delete the conversational text and review the surrounding code - it was likely never read by a human. |
| 🟧 high | `SLOP002` | `web/server.js:40` | **Elided or placeholder implementation**<br>Generated code was truncated (an elided 'rest of the code' marker or a 'your logic here' stub), so behaviour is missing. | Write the missing implementation, or delete the stub and fail loudly until it exists. |
| 🟨 medium | `SLOP003` | `api/app.py:15` | **Placeholder value left in code**<br>A template value (an API-key placeholder, 'change me', lorem ipsum) was never replaced. | Read the value from configuration and fail fast with a clear error when it is missing. |
| 🟨 medium | `SLOP005` | `api/utils.py:30` | **Duplicated code block**<br>6+ line block duplicated from earlier in this file (line 20). | Extract the shared logic into one function/module and call it from both places. |
| 🟦 low | `SLOP006` | `api/app.py:1` | **Comment narrates obvious code**<br>Comment restates what the code obviously does. | Delete the comment, or replace it with the *why* behind the code. |
| 🟦 low | `SLOP006` | `api/app.py:18` | **Comment narrates obvious code**<br>Comment restates what the code obviously does. | Delete the comment, or replace it with the *why* behind the code. |
| 🟦 low | `SLOP006` | `api/app.py:23` | **Comment narrates obvious code**<br>Comment restates what the code obviously does. | Delete the comment, or replace it with the *why* behind the code. |
| 🟦 low | `SLOP007` | `web/server.js:44` | **Debugging leftover**<br>A debugger hook or ad-hoc debug print was left in committed code. | Remove it, or route the message through the project's logger at debug level. |
| 🟦 low | `SLOP007` | `web/server.js:45` | **Debugging leftover**<br>A debugger hook or ad-hoc debug print was left in committed code. | Remove it, or route the message through the project's logger at debug level. |

## Coding Gap (13)

| | Rule | Location | Finding | Fix |
|---|---|---|---|---|
| 🟧 high | `GAP011` | `api/app.py:57` | **Exception silently swallowed**<br>Catches everything and silently ignores it. | Log the exception with context, re-raise, or catch only the specific error you expect. |
| 🟧 high | `GAP011` | `api/utils.py:15` | **Exception silently swallowed**<br>Catches Exception and silently ignores it. | Log the exception with context, re-raise, or catch only the specific error you expect. |
| 🟧 high | `GAP001` | `billing/Invoice.java:22` | **Error silently swallowed**<br>Error is caught and ignored. | Handle the error, log it with context, or let it propagate. Catch the narrowest error type possible. |
| 🟧 high | `GAP001` | `web/server.js:36` | **Error silently swallowed**<br>Error is caught and ignored. | Handle the error, log it with context, or let it propagate. Catch the narrowest error type possible. |
| 🟧 high | `GAP001` | `worker/main.go:27` | **Error silently swallowed**<br>Error is caught and ignored. | Handle the error, log it with context, or let it propagate. Catch the narrowest error type possible. |
| 🟨 medium | `GAP004` | `<repository>` | **No automated tests**<br>5 source files (229 lines) and zero test files. | Add a test suite for the critical paths and run it in CI. |
| 🟨 medium | `GAP005` | `<repository>` | **Missing project hygiene file**<br>No .gitignore - build output and secrets are easy to commit by accident. | Add the missing file so others can build, run and safely contribute to the project. |
| 🟨 medium | `GAP003` | `api/app.py:46` | **Mutable default argument**<br>`fetch_avatar()` has a mutable default `{}`. | Default to None and create the object inside the function. |
| 🟨 medium | `GAP006` | `api/app.py:49` | **Network call without timeout**<br>HTTP requests without a timeout can hang a worker forever when the remote end stalls. | Pass an explicit timeout (e.g. requests.get(url, timeout=10)). |
| 🟨 medium | `GAP002` | `api/app.py:57` | **Bare except**<br>Bare `except:` catches every exception. | Catch a specific exception class (or at minimum `except Exception:`) and handle it. |
| 🟨 medium | `GAP007` | `worker/main.go:15` | **Discarded error return**<br>The error result of a call is assigned to `_` and never checked. | Check the error and handle or wrap it (`if err != nil { return fmt.Errorf(...: %w, err) }`). |
| 🟨 medium | `GAP007` | `worker/main.go:17` | **Discarded error return**<br>The error result of a call is assigned to `_` and never checked. | Check the error and handle or wrap it (`if err != nil { return fmt.Errorf(...: %w, err) }`). |
| 🟦 low | `GAP009` | `requirements.txt:1` | **Unpinned dependency**<br>`flask` has no version constraint. | Pin a version or compatible range (package>=1.2,<2) and commit a lock file. |

## Loose End (24)

| | Rule | Location | Finding | Fix |
|---|---|---|---|---|
| 🟨 medium | `LOOSE007` | `api/app.py:61` | **Empty function body**<br>`send_welcome_email()` has an empty body. | Implement it, raise NotImplementedError with a reason, or delete it. |
| 🟨 medium | `LOOSE006` | `api/app.py:68` | **Unreachable code**<br>Unreachable after `return` on line 67. | Delete the dead statements or fix the control flow that was meant to reach them. |
| 🟨 medium | `LOOSE003` | `api/app.py:72` | **Stubbed-out implementation**<br>The function body only throws 'not implemented' - callers will crash at runtime. | Implement the behaviour, or remove the code path and its callers. |
| 🟨 medium | `LOOSE001` | `billing/Invoice.java:27` | **Unresolved TODO/FIXME**<br>FIXME left in code: tax rules are wrong for international orders | Resolve it, or move it into the issue tracker and link the ticket in the comment. |
| 🟨 medium | `LOOSE003` | `billing/Invoice.java:28` | **Stubbed-out implementation**<br>The function body only throws 'not implemented' - callers will crash at runtime. | Implement the behaviour, or remove the code path and its callers. |
| 🟨 medium | `LOOSE003` | `worker/main.go:33` | **Stubbed-out implementation**<br>The function body only throws 'not implemented' - callers will crash at runtime. | Implement the behaviour, or remove the code path and its callers. |
| 🟦 low | `LOOSE004` | `api/app.py:9` | **Unused import**<br>`flask_jwt_magic` is imported but never used. | Remove the import. |
| 🟦 low | `LOOSE005` | `api/app.py:19` | **Function is never referenced**<br>`get_user` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/app.py:42` | **Function is never referenced**<br>`hash_password` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/app.py:46` | **Function is never referenced**<br>`fetch_avatar` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/app.py:54` | **Function is never referenced**<br>`calculate` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/app.py:61` | **Function is never referenced**<br>`send_welcome_email` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE001` | `api/app.py:62` | **Unresolved TODO/FIXME**<br>TODO left in code: actually send the email | Resolve it, or move it into the issue tracker and link the ticket in the comment. |
| 🟦 low | `LOOSE005` | `api/app.py:66` | **Function is never referenced**<br>`legacy_export` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/app.py:71` | **Function is never referenced**<br>`refund_payment` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE002` | `api/app.py:75` | **Commented-out code**<br>3 consecutive lines of commented-out code (lines 75-77). | Delete the block; if it must come back, recover it from git history. |
| 🟦 low | `LOOSE005` | `api/utils.py:6` | **Function is never referenced**<br>`make_reset_token` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/utils.py:11` | **Function is never referenced**<br>`load_config` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/utils.py:19` | **Function is never referenced**<br>`normalize_user_record` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `api/utils.py:29` | **Function is never referenced**<br>`normalize_admin_record` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `web/server.js:24` | **Function is never referenced**<br>`renderBanner` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `web/server.js:28` | **Function is never referenced**<br>`sessionToken` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `web/server.js:33` | **Function is never referenced**<br>`loadProfile` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |
| 🟦 low | `LOOSE005` | `web/server.js:39` | **Function is never referenced**<br>`chargeCard` is defined but never referenced anywhere in the repo. | Delete it if it is dead, or wire it up / export it if it was meant to be used. |

_Generated by SlopGuard 1.0.0_
