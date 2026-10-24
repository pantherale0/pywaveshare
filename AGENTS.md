# Agent guide for pywaveshare

Instructions for AI coding agents working in this repository:
https://github.com/pantherale0/pywaveshare

## Project

`pywaveshare` is an async Python library for Waveshare / ZLAN network serial
adapters (RS232/RS485/RS422). Core surfaces:

- `WaveshareClient` — TCP control + serial proxy I/O
- UDP management helpers — discovery / status / RAM config on port `1092`
- Protocol modules — RFC2217, ZLAN RealCom / Gen-2, Waveshare 8-byte, UDP
- Optional `serialx` transport + URI registration (`waveshare://`)

Package layout:

- `pywaveshare/` — library code (`client`, `transport`, `protocol/`, models)
- `tests/` — pytest suite (asyncio mode auto)
- `scripts/` — local device helpers (not part of the published API)
- `.github/workflows/` — CI, release-please, PyPI trusted publishing

## Tooling

- Package manager / runner: **uv** (`uv.lock` is source of truth)
- Lint/format: **ruff**
- Types: **mypy** (`strict`)
- Tests: **pytest** + **pytest-asyncio** + **pytest-cov**
- Build backend: **hatchling**
- License: **Apache-2.0**

Install:

```bash
uv sync --extra dev
```

Validate before finishing work:

```bash
uv run ruff check pywaveshare tests scripts
uv run ruff format pywaveshare tests scripts
uv run mypy pywaveshare
uv run pytest --cov=pywaveshare --cov-report=term-missing
```

Prefer `uv run ...` over activating the venv manually.

## Coding conventions

- Target Python `>=3.11`; keep type hints precise under mypy strict.
- Match existing style: asyncio-first APIs, clear exception types in
  `exceptions.py`, shared enums/constants in `const.py`.
- Keep protocol framing/parsing in `pywaveshare/protocol/`; keep high-level
  client orchestration in `client.py`.
- Do not add dependencies unless necessary; runtime deps are intentionally empty
  (`serialx` is optional).
- Avoid drive-by refactors; change only what the task requires.
- Keep user-facing docs accurate when APIs change (`README.md`).

## Versioning and releases

- Version is dynamic via Hatch: single source of truth is
  `pywaveshare/__init__.py` (`__version__`); `pyproject.toml` uses
  `dynamic = ["version"]` + `[tool.hatch.version]`.
- release-please owns version bumps via Conventional Commits on `main`
  (updates `__version__`, changelog, and the release-please manifest).
- Do **not** manually bump versions or edit `CHANGELOG.md` /
  `.release-please-manifest.json` unless explicitly asked.
- Commit message prefixes matter: `feat`, `fix`, `docs`, `test`, `chore`, etc.

## CI / publishing notes

- CI: `.github/workflows/ci.yml` (lint + matrix tests + Codecov)
  - Codecov rejects tokenless uploads on protected branches. Prefer repo secret
    `CODECOV_TOKEN` from https://app.codecov.io/gh/pantherale0/pywaveshare
    (Settings → General → Repository upload token). If unset, CI falls back to
    OIDC (`id-token: write`) when the Codecov GitHub App is installed.
- Release/publish: `.github/workflows/release-please.yml`
  - PyPI uses OIDC trusted publishing with GitHub Environment `pypi`
  - Publish job is inlined because `GITHUB_TOKEN` releases do not trigger
    separate `on: release` workflows

## Safety

- Never commit secrets, tokens, `.env` files, or private device credentials.
- Do not force-push, rewrite history, or skip hooks unless the user asks.
- Hardware-facing scripts may talk to real devices; prefer mocked unit tests in
  `tests/` for library changes.
