# Identity review and least privilege: engineering decision record (V4)

**Status:** design and implementation documentation. These controls are implemented/tested locally where described; they are not evidence of a production security change or a completed external code review.

## Risk / failure mode

A missing Graph permission, principal not resolved, or unavailable sign-in timestamp must not be treated as safe or as proof of compromise.

## Safeguards

Read-only GET to approved hosts, explicit source completeness and missing-data handling, 2-person closure, exception expiry, reviewer evidence/ticket trail, no account modifications.

## Acceptance before a public release

1. Confirm the change description and security threat model with the command/run output.
2. Run `python -m unittest discover -s tests -v` on an isolated branch.
3. Run the relevant reproducible outcome study and verify its source label and SHA-256 fingerprint.
4. Confirm `.gitignore` excludes private tenant snapshots, scan exports and secrets; review diff for personal data and API tokens.
5. In GitHub after publication, require a real green Actions build and artifact download before tagging a release; do not label an unreviewed commit as reviewed.
6. Record a tested rollback path and limitations in the release notes.

## Safe rollback

Re-run review with prior snapshot; maintain open or unresolved state until authorization and manual owner verification. No live tenant access changes have been made.

## Remaining validation work

- Public Actions logs: **not yet available until the user publishes this repository**.
- Authorized Microsoft/Qualys/Trivy integration: **not claimed**.
- Real customer or employer outcome: **not claimed**.
