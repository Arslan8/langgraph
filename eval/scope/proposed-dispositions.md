# Proposed acceptance dispositions (for the student to review and apply)

Prepared 2026-10-27 by Claude from `eval/status_claude.md`. Nothing here has
been applied to `campaigns/remediation-v2/acceptance.json` or the campaign
README; those records belong to the student.

## Item 2 (strict security gate): proposed `addressed-route-scoped`

- `make security-verify` exits 0 under the advisor-approved route-scoped
  acceptance (`raw/checks/claude-final-security-v3.{json,log}`, Lean audit run).
  Whole-system completeness remains NOT ESTABLISHED and SGV901–903 are still
  reported, each with route scope "discharged on every supported route".
- Supported routes: `tool-node-dispatch` (exact ToolNode under closed
  admission) and `output-publication` (OutputMediator → HostRouter →
  ObjectManagerHost). Their obligations rest on recomputed source proofs:
  router 21/21, host-output correspondence with the recursive validator
  contract, output-mediator correspondence, admission surface (4/4); plus
  registered refusal codes. Premises are listed per route in
  `docs/security/supported-surface.json`; the standard is in
  `docs/security/evidence-standard.md`.
- Unsupported and gated: plain Python nodes, Runnable subclasses, metadata
  promotion, graph-author callbacks (closed admission), the Docker route, SQL,
  notebook, and the pandas outer graph.
- **Not covered:** `linux-worker-compute` (pandas C) is recorded unsupported
  until a fresh Lean audit passes on the current tree (advisor decision); the
  in-progress grant-v3 edit makes the audit fail today. Promote it with a
  manifest flip and a rerun once the audit passes, and cite runtime evidence
  that records source identities.
- Suggested wording for `acceptance.json` item 2: "Route-scoped acceptance
  passes for tool-node-dispatch and output-publication with recomputed
  evidence (claude-final-security-v3); whole-system completeness not
  established; linux-worker-compute pending a passing Lean audit."

## Item 5 (notebook): unchanged `open`

Recorded unsupported and gated by closed admission; a server boundary is a
separate implementation project.

## Record corrections

See `eval/scope/record-corrections.md` (SQL RM1 cohort, v11 24/30 not 26/30,
`apps.csv` evidence column).

## Other items

No change proposed; historical gaps stay as recorded.
