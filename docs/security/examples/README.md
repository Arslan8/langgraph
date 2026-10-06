# Runnable security examples

These examples cover the decision layer that exists today:

1. [`guarded_tool_audit.py`](guarded_tool_audit.py) binds a principal, applies
   author DAC to a directly invoked tool, and verifies its audit hash chain.
2. [`corporate_recipient_policy.py`](corporate_recipient_policy.py) adds a
   restrictive policy module that rejects mail addressed outside the corporate
   domain.
3. [`constructive_profile.py`](constructive_profile.py) parses a `.slp` profile
   and shows `need` versus `want` behavior during constructive intersection.

Run them from the repository checkout:

```bash
cd libs/prebuilt
uv run python ../../docs/security/examples/guarded_tool_audit.py
uv run python ../../docs/security/examples/corporate_recipient_policy.py
uv run python ../../docs/security/examples/constructive_profile.py
```

These programs demonstrate in-process decisions, mediation, and audit. They do
not claim to confine arbitrary Python. The kernel backend described by
[ADR 0007](../adr/0007-kernel-enforced-confinement.md) is separate work; until
it lands, use operating-system isolation when tool code itself is untrusted.
