# Persistent Docker object execution

`langgraph.prebuilt.security.container.DockerObjectDispatcher` implements the
object dispatcher used by `cedar_security(..., dispatcher=dispatcher)`. The
resulting `ObjectPolicyHostExecutor` authorizes each invocation before the
dispatcher mounts the effective read grants. The coordinator tool callback is
used as a schema; its implementation does not execute.

Construct the dispatcher with a mapping of tool names to pinned `LinuxToolSpec`
artifacts, an exact local `sha256:` image ID, and canonical private host input
directories. The trusted image must contain `/usr/bin/python3`, libseccomp and
`/bin/sleep`. The supported resource surface is exact regular-file reads. Files
must have one link and reside under operator-owned directories inaccessible to
other host users. Namespace mutation by untrusted host processes is outside
this contract. The constructor pins a local Unix-socket Docker endpoint.
The host requires Linux pidfds exposed by libc and a Python interpreter with
its standard library. Missing guardian capabilities reject startup.

Containers have a read-only root, no network, no added capabilities, no new
privileges, a 32-process ceiling, a 1 GiB memory limit and a private 64 MiB `/tmp`.
The worker additionally installs resource limits and a seccomp filter before
acknowledging readiness. The dispatcher inspects the container and issues a
call-bound activation receipt before releasing the worker to import the tool.
Image contents and private `/tmp` are baseline runtime access; the image must
not contain secrets. These are content-access controls, not metadata secrecy.

Same-authority calls share container state but receive fresh Python workers.
Reuse binds principal identity, roles, scopes, session, delegation, security
slots, policy, effective grants, tool/runtime bytes and native mount identities.
An identity change destroys the whole old container and verifies absence before
creating its replacement. Failed or uncertain removal quarantines the old
container and prevents reuse. Timeouts and cancellation also destroy it;
repeated cancellation waits for cleanup to finish. Call `close()` in `finally`
to release the container after normal completion.

A separate guardian performs Docker lifecycle commands and records ownership
before submitting creation. A kernel pidfd binds it to the original controller;
controller death or explicit shutdown triggers whole-container reclamation.
Inherited pipe writers in forked descendants cannot delay detection of controller
death. An uncertain create response remains quarantined until the exact owned
container is observed and removed; an empty listing alone does not resolve it.
The guardian checks ownership labels before removal and retries failed cleanup.
Its source digest is acknowledged at startup and bound into runtime identity.

This adapter does not support general writes, RPC resources, deployment-bound
artifacts, enforcement waivers or remote Docker daemons. Runtime MAC admits the
exact production dispatcher type at supported graph/ToolNode boundaries;
operator forbids are still applied before each dispatch. Operator policy
is sealed at controller startup; deployment changes require a controller restart.
Live replacement is unsupported. Graph-local
policy changes and effective-grant reduction are distinct tested transitions.
Controller-crash cleanup requires the guardian to survive and the pinned Docker
daemon to remain or become reachable. Killing both processes, persistent daemon
failure, and host failure are not covered by a bounded cleanup guarantee.
Operators still need external recovery for those failures. Activation receipts and regression
tests do not discharge the still-open SGV901–903 complete-mediation proofs.

The prospective campaign driver is
`eval/remaining/container_dispatcher_campaign.py`. It performs useful sum
computation, observes same-authority state persistence, then checks state removal
and old-container absence after principal, graph-local policy or grant changes.
Its raw rows retain results, receipts, container identities and cleanup command
outcomes. Original evaluation-adapter cohorts remain separate.

`eval/remaining/container_mac_campaign.py` exercises changed operator policy
across graceful controller restarts. Both controllers run the same graph-local
permit and manifest. The stricter operator policy removes an optional private
file grant while preserving useful computation over the required input. Each
controller verifies that live policy replacement is refused and closes its
container before exit. This adds restart coverage, not controller-crash cleanup.

`eval/remaining/container_crash_campaign.py` separately tests real `SIGKILL` after
useful work: idle containers, active workers, delayed replies from real container
creation, and descendants retaining the controller pipe. Guardian removal and
guardian exit are observed before any harness cleanup; later cleanup cannot turn
a failed observation into a pass. These are lifecycle tests, not workflow
completion claims for interrupted calls or isolated-host performance measurements.
