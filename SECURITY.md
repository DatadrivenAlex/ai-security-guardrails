# Security policy

`ai-security-guardrails` is a portfolio and teaching project by Alexandru Cojocari. It shows how a small service can inspect text *before* it is sent to a model and *before* a completion is shown to a user. It is not a product you should drop in front of a real LLM gateway and trust.

## What this project is

- A deterministic, offline rules engine behind a small HTTP API.
- A way to practice detection engineering: phrase lists, checksums, allow/deny policy, and tests that lock the expected decision in place.
- A map from a few of those rules onto the public [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/). The mapping lives in `docs/owasp-llm-top-10.md` and is intentionally incomplete.

## What this project is not

- **Not a SIEM.** There is no alert pipeline, no case management, no long-term event store, and no claim that the Prometheus counters are a security monitoring program.
- **Not VIES**, and not any other government or bank registry. IBAN handling is the public mod-97 checksum on a string that already looks like an IBAN. There is no VAT number check, no VIES lookup, and no payment-network call.
- **Not a web application firewall** and not a zero-day detector. Rules are regular expressions and a handful of reversible transforms (base64, hex, ROT13, a small homoglyph table, zero-width characters). A paraphrase, a language the lists do not cover, or a novel encoding will pass.
- **Not an assurance that a model will behave.** Denying a prompt here only helps if some other component actually honors the decision. This service never calls a model.
- **Not a secret scanner for git history**, a malware sandbox, or an identity system. Credential checks look for well-known *shapes* (for example `AKIA…`, a PEM header, `ghp_`). They do not prove a credential is live.
- **Not a place to send real customer data.** The reversible sanitize mode returns the original PII in `token_map` so a demo can round-trip. That map is sensitive.

## Data handling

- By default the service logs a short SHA-256 prefix, the text length, the decision, and detector names. It does not log the prompt, the completion, or the sanitize token map.
- `GUARDRAILS_LOG_PROMPTS=true` turns on a 200-character preview. Leave it false.
- Nothing is written to a database. Restarting the process drops counters.
- Policy files are trusted operator input. Do not let untrusted users edit `policies/*.yaml`. A hostile regular expression can be used for a ReDoS against this process; patterns are length-capped, but that is not a full sandbox.

## Threat model (educational)

In scope for the demo:

- A user prompt that tries to override instructions, using a known phrase or one of the supported encodings.
- A completion that repeats a system prompt the caller also sent to `/v1/inspect`, or that claims to reveal hidden instructions.
- Accidental PII or secret-shaped strings in either direction.

Out of scope:

- Indirect prompt injection hidden in a retrieved document that does not match the lists.
- Model or tool supply chain, training-data poisoning, embedding attacks, and cost or denial-of-service attacks against a provider.
- Whether a downstream tool should have been allowed to run. The `rm -rf` rule is a text flag for excessive-agency discussions, not a shell sandbox.
- Adversaries who can modify this service, its policy, or the host.

## Reporting

There is no bug bounty and no production deployment. If you find a bug in the demo, open a GitHub issue on [DatadrivenAlex/ai-security-guardrails](https://github.com/DatadrivenAlex/ai-security-guardrails). Please do not include live credentials, customer data, or a working exploit against anyone else's system.

## Hardening you would add before any real traffic

These are deliberately **not** implemented. They are the conversation a junior engineer should be ready to have:

1. Run the service on a private network, in front of an authenticated gateway, not on the public internet.
2. Put a size and rate limit at the gateway as well as the request-body cap already in the models.
3. Keep raw prompts in a purpose-built, access-controlled store if you must retain them. Do not put them in application logs.
4. Treat `token_map` as a secret and prefer non-reversible redaction unless a specific workflow needs the reverse map.
5. Add a reviewed corpus of bypasses and benign lookalikes, then decide where a statistical classifier is worth the false positives.
6. Fail closed when the policy file is missing (readiness already returns 503 in that case) and alert on a reload failure.
