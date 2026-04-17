# Reviewer Deliverable Contract

## Required Return Artifact

The reviewer must return a single `.zip` file.

Suggested name:

- `auditex-review-YYYYMMDD.zip`

## The Zip Must Contain

- the improved repository state
- all code changes
- all test changes
- all documentation changes
- a review summary
- a risk register
- a change log
- execution notes
- test evidence
- any added backlog or roadmap documents

## Minimum Required Top-Level Review Files Inside The Zip

- `REVIEW-SUMMARY.md`
- `RISK-REGISTER.md`
- `CHANGELOG-REVIEWER.md`
- `TEST-EVIDENCE.md`
- `OPEN-QUESTIONS.md`
- `NEXT-STEPS.md`

## What `REVIEW-SUMMARY.md` Must Contain

- what was reviewed
- what was improved
- what was rejected
- what remains unsafe or incomplete
- whether the reviewer believes the project is ready for wider tenant use

## What `RISK-REGISTER.md` Must Contain

- issue
- impact
- likelihood
- recommended mitigation
- whether the reviewer fixed it or left it open

## What `TEST-EVIDENCE.md` Must Contain

- exact commands run
- pass/fail result
- any skipped areas
- reasons for skipped areas
- any live-tenant assumptions

## Expected Type Of Improvement

This is not a packaging-only handoff.

The reviewer is expected to:

- improve code
- improve tests
- improve features
- improve architecture where needed
- improve docs
- leave the project stronger than it was received

## Completion Standard

The review is complete only when the returned `.zip` contains both:

- a materially improved project state
- written evidence that explains why the reviewer changed what they changed
