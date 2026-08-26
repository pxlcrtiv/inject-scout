# daily tips

Daily LLM/prompt-security tips appended by scripts/daily_update.py (see README "Daily Green automation").

## 2026-08-24 — Tip of the day: Never splice fetched content into system prompts

System prompts must be authored by you, period. Fetched text belongs in a clearly delimited data field the model is told to treat as data.


## 2026-08-25 — Tip of the day: Use code, not prompting, for boundaries

Relying on 'ignore everything before this marker' wording is prompting; splitting fields at the API layer is engineering. Do the latter.


## 2026-08-26 — Tip of the day: Assume your system prompt will leak

Design prompts with no secrets in them. Anything you wouldn't post in a blog should not live in the system prompt.

