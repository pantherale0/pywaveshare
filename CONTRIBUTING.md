# Contributing to pywaveshare

Thanks for your interest in contributing to
[pywaveshare](https://github.com/pantherale0/pywaveshare).

## Development setup

Requirements:

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

```bash
git clone https://github.com/pantherale0/pywaveshare.git
cd pywaveshare
uv sync --extra dev
```

## Checks

Run the same checks CI runs before opening a PR:

```bash
uv run ruff check pywaveshare tests scripts
uv run ruff format --check pywaveshare tests scripts
uv run mypy pywaveshare
uv run pytest --cov=pywaveshare --cov-report=term-missing
```

To auto-fix:

```bash
uv run ruff check --fix pywaveshare tests scripts
uv run ruff format pywaveshare tests scripts
```

## Pull requests

1. Open an issue first for larger changes so maintainers can align on approach.
2. Keep PRs focused; prefer small, reviewable commits.
3. Add or update tests for behavior changes.
4. Update docs/`README.md` when user-facing behavior changes.
5. Fill out the pull request template.

## Commit messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/)
so [release-please](https://github.com/googleapis/release-please) can automate
versioning and changelogs.

Examples:

- `feat: add UDP reboot helper timeout option`
- `fix: handle RFC2217 parity negotiation failure`
- `docs: clarify RealCom config mode usage`
- `test: cover ZLAN Gen-2 CRC verification`
- `chore: bump CI Python matrix`

Breaking changes should use `!` or a `BREAKING CHANGE:` footer, for example:

- `feat!: rename ConfigMode.WAVESHARE_8BYTE`

## Reporting bugs

Use the **Bug report** issue template and include:

- Library version / commit
- Python version and OS
- Adapter model and firmware (when relevant)
- Config mode (`RFC2217`, `REALCOM`, etc.)
- Minimal reproduction steps and logs

## Feature requests

Use the **Feature request** template. Describe the problem, proposed API, and
any hardware/firmware constraints.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE.md).
