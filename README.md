# Entra & Azure RBAC Access Governance — Read-only Reviewer Pack

## Measured outcome (deterministic generated access-review workload)

**Problem / baseline:** owners receive fragmented role assignments, guest identities and service-principal credentials without a unified evidence-based escalation queue.

**Implementation:** read-only collector, nine privilege checks, independent approval, expiring exceptions, and drift reconciliation.

**Finding:** A modeled 2,000-user identity snapshot contains 376 role/credential records; the policy scan produces 151 control flags, deduplicated to 138 initial exception items (36.7% of records). This is a simulated first-pass reviewer queue, not an access certification or a measured reduction in real review time.

**Inspect:** `python -m src.operational_study` -> [`reports/operational-study.html`](reports/operational-study.html) and [`reports/operational-study.json`](reports/operational-study.json). No identity or tenant modifications are made.


An evidence-based entitlement review tool that collects identity and role assignment data through **real Microsoft Graph v1.0 and Azure Resource Manager GET endpoints** and produces a reviewer queue. No writes, account changes, secret collection or automatic remediation.

## The operational problem

Privileged roles, guest access, non-human identities, and cloud permission scope are often reviewed from separate portals. Reviewers need one transparent evidence trail and explicit decisions to confirm with application and resource owners.

## Architecture

`Azure CLI authenticated identity -> Microsoft Graph / ARM read-only requests -> tenant_snapshot.json (private) -> control checks -> prioritized JSON + HTML reviewer pack`

Graph collection: users, applications (service principals), groups, Entra directory role assignments and definitions. Optional Azure role assignments and definitions at the subscription scope. Pagination is supported and restricted to the expected Microsoft API hosts.

## Control logic

| Control | Decision requiring owner review |
|---|---|
| DIR-001 | Disabled user still assigned a directory role |
| DIR-002 | Guest identity holds a directory role |
| DIR-003 | Privileged account sign-in inactivity if supported signal is present |
| DIR-004 | Application identity has a high-privilege Entra role |
| APP-001 | Application credential expiring within 30 days / expired |
| AZ-001 | Subscription-level Owner or User Access Administrator |
| AZ-002 | Service principal with Azure Owner role |
| AZ-003 | Guest user holding privileged Azure RBAC role |
| AZ-004 | Principal not resolved in collected snapshot; treated as review, NOT assumed orphaned |

## Reproduce results without credentials

```bash
python -m unittest discover -s tests -v
python -m src.review --input fixtures/regression_snapshot.json --out reports --as-of 2026-11-16
```

**Validated:** 19 unit tests; sample review pack contains 7 findings on a **fictional regression dataset**. This demonstrates review logic, not a claim about a real tenant's exposure.

## Collect evidence from an authorized Azure tenant

1. Install Azure CLI and sign into a **tenant you own or have explicit authorization to assess**: `az login`.
2. Obtain permissions to read relevant Graph data (examples: User.Read.All, Application.Read.All, Group.Read.All, RoleManagement.Read.Directory; optional AuditLog.Read.All for `signInActivity`) and `Microsoft.Authorization/roleAssignments/read` / roleDefinitions read for subscription RBAC.
3. Capture a private snapshot: `python -m src.collect --subscription <subscription-id> --out private/tenant_snapshot.json`. If no Azure subscription access, omit `--subscription` and collect directory-only data.
4. Analyze: `python -m src.review --input private/tenant_snapshot.json --out private/review --as-of YYYY-MM-DD`.
5. Review HTML, validate each identity/assignment against change tickets, and document owner decisions. Do not publish private review outputs.

**Important**: Permission availability, licensing and sign-in retention vary by tenant. The collector fails rather than silently representing API-denied sources as successfully collected. The `.gitignore` excludes `private/`.

## Evidence

- `reports/review.html` is a screenshot-ready example of the reviewer UX.
- `reports/review.json` contains deterministic evidence with test-only identities.
- `tests/` checks control logic, HTML escaping, missing sign-in handling, and pagination host restrictions.

## Sources

- [Microsoft Graph unified role assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0)
- [Microsoft Graph sign-in logs](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)
- [Microsoft Entra role access review](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/view-assignments)

# Security and source transparency

- No organization or employer data is included. **Never commit an actual tenant snapshot, scan export, credentials, access tokens, or incident records** to a public repository.
- Tested Python logic is not a substitute for service-side testing. Azure integration actions require the operator's authorized account and their approval.
- The tools generate review recommendations; they do not automatically disable accounts, remediate systems, or modify an Azure deployment.

## Operational maturity additions (release 3)

- **Release readiness:** source-controlled regression tests run on every pull request in GitHub Actions; no privileged Azure or scanner credentials required for CI.
- **Governance and auditability:** output evidence is deterministic for committed fixtures; the commands and boundaries are recorded in `docs/OPERATING_MODEL.md`.
- **Separation of duties:** output is advisory, never auto-applies changes to user accounts, analytics rules or patches. Deployment or remediation requires an authorized operator.
- **Traceability:** inspect `reports/attestation.json` and rerun the documented steps before presenting results publicly.
- **Truthfulness:** an actual enterprise deployment is NOT claimed. Read-only cloud connectivity and cloud tenant validation require separate authorization.


## Independent attestation and identity drift

```bash
python -m src.decision_ledger --review reports/review.json --as-of 2026-11-16 --out reports
python -m src.drift --before fixtures/regression_snapshot.json --after fixtures/regression_snapshot.json --out reports/no-drift.json
```

The ledger computes stable finding IDs, enforces **separate owner and approver** for closed/accepted decisions, requires evidence tickets, and reopens expired risk exceptions. It records the review's SHA-256. Drift compares role/principal/scope assignments across snapshots. Drift is NOT proof of compromise. The included sample ledger intentionally keeps all seven fictional findings **open**, not falsely remediated.

For decisions, provide CSV columns `finding_id,decision,owner,approver,ticket,expires_on`. Supported decisions: `open`, `in_review`, `accepted_exception`, `remediated`, `false_positive`. Never publish real reviews.
