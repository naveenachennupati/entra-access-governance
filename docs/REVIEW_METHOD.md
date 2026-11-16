# Privileged access evidence model

Every observation includes the exact role definition, principal ID, scope and recommended reviewer action. Findings are **not** an assertion of malicious activity or noncompliance.

## Decision standard

- Confirm app/user owner and written business need.
- Prefer narrow RBAC scope where practical, and review role changes through change management.
- Only classify an object as orphaned after resolving directory API blind spots, security groups and cross-tenant principals; this tool deliberately reports such entries as *Review*.
- For sign-in inactivity, the absence of `signInActivity` is not treated as proof that an account is stale.
- Coordinate application credential rotations and approvals; never expose actual secret values in evidence.

## Trust boundaries

`fixtures/` contains fictional identities. `private/` is intentionally ignored. The tool never calls POST, PATCH, PUT or DELETE. Full enterprise evaluation requires authorized access and decisions by resource owners.
