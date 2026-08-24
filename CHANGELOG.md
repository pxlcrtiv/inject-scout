# Changelog

All notable changes to inject-scout are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] — 2026-08-24

### Added
- Initial release: `inject-scout` CLI with 22 deterministic detection rules
  across 8 attack categories (role escape, system-prompt leak, delimiter
  confusion, exfiltration, encoded tricks, indirect injection, tool abuse,
  jailbreak prompts).
- `check` (inline text), `scan` (files/dirs), `demo` (bundled attack corpus),
  `--list-rules` commands; text/markdown/JSON reports; `--strict` CI gate.
- 24-item attack fixture corpus (`data/attacks.json`) with golden tests;
  22-offline-test suite; Daily Green automation (24-tip pool).