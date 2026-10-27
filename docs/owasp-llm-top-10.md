# OWASP LLM Top 10 (2025) — what this demo actually covers

Source vocabulary: [OWASP Top 10 for Large Language Model Applications, 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

This table is honest about coverage. "Pattern" means a deterministic check in `src/guardrails/core`. It does not mean the risk is solved.

| ID | Risk | In this repo | What the code does |
| --- | --- | --- | --- |
| LLM01 | Prompt injection | Partial, pattern only | Instruction-override phrases, a short jailbreak list, role-play that asks to drop restrictions, and the same phrases after base64, hex, ROT13, a small homoglyph map, or zero-width characters. Paraphrases sail through. |
| LLM02 | Sensitive information disclosure | Partial, pattern only | Emails, phone numbers, IBAN strings that pass mod-97, card numbers that pass Luhn, and a few credential shapes. Findings mask the raw value. `/v1/sanitize` rewrites PII. No registry lookup (not VIES, not a BIN database, not a bank directory). |
| LLM03 | Supply chain | Not covered | No dependency firewall, model provenance, or plugin vetting. `pyproject.toml` pins lower bounds only. |
| LLM04 | Data and model poisoning | Not covered | This service never trains or fine-tunes a model. |
| LLM05 | Improper output handling | Partial, by contract | Callers get `allow`, `deny`, or `rewrite` plus a rewritten string for PII. Honoring that decision is the caller's job. The service does not render HTML or execute tools. |
| LLM06 | Excessive agency | Illustration only | The default policy flags `rm -rf` in text because a tool-using agent might later execute model output. There is no tool broker and no permission check. |
| LLM07 | System prompt leakage | Partial | Flags prompts that ask to reveal the system prompt. Flags a completion that contains a long fragment of the `system_prompt` field the caller sent, or that claims to quote hidden instructions. The service does not know a prompt you did not send. |
| LLM08 | Vector and embedding weaknesses | Not covered | No retrieval, no vector store, no document sandbox. |
| LLM09 | Misinformation | Not covered | No factuality check. A fluent wrong answer is `allow`. |
| LLM10 | Unbounded consumption | Not covered | No token budgeting, no model call, no rate limit across clients. Request bodies are capped at 20,000 characters so a single call stays small. |

## How a finding picks an action

The score is a capped sum of severity points (low 15, medium 35, high 60, critical 85) times the detector weight from the policy. It is there so a human can sort events. The decision is stricter than the score:

- Any finding whose suggested action is **deny** denies the call. Injection, jailbreak, obfuscation, secrets, system-prompt echo, and high-severity denylist hits do this.
- PII findings suggest **rewrite**. If nothing asked for a deny, `/v1/inspect` returns `rewrite` and a `rewritten_text` with placeholders such as `[EMAIL_1]`. The originals are not included. Use `/v1/sanitize` with `reversible: true` when a demo needs the map, and treat that map as sensitive.
- A deny does not come back as a "cleaned" prompt. Stripping a jailbreak sentence and then allowing the rest is a good way to miss the second sentence.

## Adding a rule

1. Prefer a new denylist entry in `policies/default.yaml` when the rule is local policy rather than a new idea about injection.
2. Add a detector only when the check needs a checksum, a decode step, or a span the denylist cannot express.
3. Add a pytest that locks the decision, and a second test for a nearby benign string that must stay `allow`.
4. Update this table if the rule changes which OWASP item you can talk about in an interview. Do not mark an item "covered" because a regex mentions it.
