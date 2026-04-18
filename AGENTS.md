# Repository Guidelines

## Project Structure & Module Organization
`src/azure_tenant_audit/` holds the core audit engine, collectors, adapters, and output logic. `src/auditex/` is the product wrapper with the CLI and MCP entrypoint. `tests/` contains automated tests named `test_*.py`. Keep reference material in `docs/specs/`, machine-readable contracts in `schemas/`, operator profiles in `profiles/`, and bootstrap/lab helpers in `tenant-bootstrap/`. Treat generated outputs as build artifacts, not hand-edited source.

## Build, Test, and Development Commands
Use `python3 -m venv .venv && source .venv/bin/activate && pip install -e .` for local setup. `make install` installs pinned requirements from `requirements.txt`. `make test` runs the full pytest suite. `make lint` runs `python -m compileall -q src tests` as a fast syntax check. Run the CLI with `auditex --offline --tenant-name demo --out outputs/offline`, or start the MCP server with `auditex-mcp`.

## Coding Style & Naming Conventions
Use Python 3.11+ and keep code readable, small, and explicit. Follow existing module names and keep collector files focused by service or concern, such as `collectors/conditional_access.py`. Prefer clear snake_case for functions, variables, and filenames. Match the repository’s current formatting style; there is no separate formatter enforced in this tree, so keep edits consistent with nearby code.

## Testing Guidelines
Add or update tests in `tests/` alongside the behavior you change. Use `test_<feature>.py` names and descriptive test functions. Prefer focused tests for collectors, normalization, CLI behavior, and output contracts. Run `make test` before shipping changes; use `make lint` for quick sanity checks when touching Python syntax or imports.

## Commit & Pull Request Guidelines
Commit history uses short Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`, and `chore:`. Keep messages imperative and scoped. For pull requests, state the user-visible change, list key commands run, link the related issue if there is one, and include sample output or screenshots only when the change affects reports, CLI output, or generated artifacts.

## Security & Data Handling
Keep raw tenant evidence local. Do not commit secrets, tokens, or tenant exports. Review `README.md` and `docs/specs/` before changing audit flow, output contracts, or response behavior.
