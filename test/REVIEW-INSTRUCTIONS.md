# Auditex Review Instructions

## Objective

Review this repository as if you are inheriting it to turn it into a production-grade Microsoft 365 audit and evidence platform for large enterprise tenants.

This is not a style review. It is a product, architecture, runtime, and trust review.

## Review Goals

- verify whether the current runtime is coherent
- verify whether the evidence model is trustworthy
- verify whether the delegated-first audit path is viable
- verify whether the export plane is operationally credible
- verify whether the guarded response plane is properly isolated
- verify whether the repo can scale toward `4,000-10,000` user tenants
- identify missing collectors, fragile assumptions, and poor abstractions
- improve anything that blocks a credible `1.0`

## Expected Review Method

1. Read the architecture and product docs first.
2. Read the feature inventory and reference map in this folder.
3. Inspect the canonical runtime under `src/azure_tenant_audit/` and `src/auditex/`.
4. Run the validation matrix in `VALIDATION-MATRIX.md`.
5. Challenge every plane boundary:
   - `inventory`
   - `export`
   - `response`
6. Challenge every trust boundary:
   - delegated token reuse
   - app-readonly escalation
   - adapter-backed command execution
   - local evidence storage
   - AI-safe normalization
7. Improve code, tests, docs, or architecture where needed.
8. Return the full result as a `.zip` deliverable defined in `DELIVERABLE-CONTRACT.md`.

## What To Be Skeptical About

- command-backed surfaces that are present but not yet deep enough
- places where docs may lag implementation
- scaling claims that are not yet proven by large fixtures or live validation
- export coverage that still depends on `m365` CLI instead of native APIs
- response actions that are scaffolded correctly but still limited in breadth
- whether blockers always degrade cleanly instead of aborting runs
- whether artifacts are sufficient for customer evidence handoff

## Minimum Acceptance Standard

The reviewer should not return a narrative only.

The reviewer should return:

- improved code
- improved tests
- improved docs
- explicit defect findings
- explicit risk findings
- explicit decisions on what is production-ready vs not production-ready
- a `.zip` containing the improved state and review evidence

## Review Outcome Requirement

The expected output is not a comment thread. The expected output is a `.zip` file containing the reviewer-improved project state, additional features or fixes, and written review artifacts.
