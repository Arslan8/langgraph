# OSTree deployment measurements

Measurements were taken on 2026-10-18 with Linux `6.17.0-1032-oem` on an
Intel Xeon w5-3435X. The test used OSTree 2024.5, bubblewrap, the two-module
`ostree-deployments` example, and the same Python interpreter and secured
`ToolNode` for both invocation paths. These are development measurements, not
service-level objectives.

| Operation | Observed time |
| --- | ---: |
| Raw OSTree commit | 21.364 ms |
| Raw `--user-mode --force-copy` checkout | 8.048 ms |
| Manager publish A, including normalization, fsck, checkout, and validation | 88.774 ms |
| Manager publish B, including normalization, fsck, checkout, and validation | 86.944 ms |
| Existing selection bind and complete checkout revalidation | 41.215 ms |
| Legacy secured invocation, mean of five after warmup | 142.575 ms |
| Deployment-backed secured invocation, mean of five after warmup | 209.780 ms |

After publishing both releases, the repository contained 1,063 bytes of files.
Each force-copy checkout contained 268 bytes of files. Those figures report the
repository and materialized checkouts separately and exclude filesystem block
rounding and the SQLite selection database.

Releases A and B produced different commit checksums while retaining the same
primary-file SHA-256. The deployment invocation executed through the real
bubblewrap adapter and a real OSTree 2024.5 CLI. The measurement does not claim
application-output determinism, and the small fixture exaggerates fixed command
startup costs relative to realistic bundles.

## Follow-on verification

The independently versioned runtime path was exercised with the same OSTree
2024.5 binary and real bubblewrap adapter. A Python 3.13 runtime tree containing
the interpreter, standard library, ELF loader, native dependencies, and
libseccomp was published as a separate commit. The end-to-end invocation ran
without host `/usr`, `/lib`, or `/lib64` mounts and recorded distinct tool and
runtime commit identities in its activation receipt.
The A/B runtime regression then moved a runtime channel between calls and
confirmed the receipt sequence A, B, A for an old call retried after the move.
The durable-checkpoint regression repeated that condition across a closed and
reopened SQLite checkpoint backend and reconstructed executor.

Verified distribution was also exercised against a separate local OSTree
repository whose commit was signed with a newly generated Ed25519 OpenPGP key.
The consumer imported only the public key, configured that publisher as a
trusted remote, successfully pulled the signed commit, validated the bundle,
and created its local release ref after verification. A second repository with
an unsigned commit was configured with that same approved public key; OSTree
rejected the pull and the manager created no local release.
