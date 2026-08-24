# Contributing

Thanks for helping make inject-scout better. This is a focused, deterministic
prompt-injection scanner for LLM applications: **rule-based, offline-testable,
zero-runtime-dependencies**. Please keep those properties.

## Ground rules

- **No runtime dependencies.** New rules must be pure-Python regex/string
  logic. No ML calls in the default path.
- **Deterministic output.** Same text → same findings, same order. No
  timestamps, no randomness, no set-ordering dependence.
- **Every rule needs a fixture case.** Add (or extend) an entry in
  `data/attacks.json` with its expected category, plus a golden assertion in
  `tests/` that the engine emits the rule id.
- **Low false-positive discipline.** Rules must be specific; when in doubt
  prefer `warn` over `error` and document the trade-off in the rule.
- **Tests stay offline.** No network, no model downloads, ever.

## Daily Green

The repo commits one dated entry per day via `scripts/daily_update.py`
(pool: `scripts/tips_pool.json`). Add tips to the pool; never edit
`docs/daily-tips.md` by hand.

## PR process

1. Fork, branch, change, test: `python -m pytest tests/ -q` (all green).
2. `ruff check` clean.
3. CLI smoke: `inject-scout demo | head`.
4. Open the PR; reference rule id(s) added and the corpus entries used.

## Style

- Type hints on all public functions; `py3.10+`.
- Every finding carries a concrete suggestion (what to do about it), not just
  a label.