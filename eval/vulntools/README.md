# Deliberately vulnerable tools

These functions are evaluation fixtures, not production utilities. Each headline
tool contains one ordinary implementation bug below an otherwise policy-conformant
call boundary. PoCs may invoke them only with temporary files, disposable SQLite
databases, loopback services, and inert canaries.

| Tool | Deliberate bug | Expected enforcing locus |
| --- | --- | --- |
| `read_file` | absolute component overrides the base in `os.path.join` | Landlock filesystem rule |
| `write_file` | follows a symlink selected below the argument boundary | Landlock filesystem rule |
| `run_shell` | metacharacters reach `sh -c` after argv0 validation | seccomp class + Landlock execute rule |
| `sql_query` | string concatenation changes SQL statement meaning | SQL broker |
| `web_fetch` | `urlopen` accepts `file://` as well as network URLs | Landlock filesystem rule |
| `send_email` | a newline in the recipient creates another header/recipient | mail broker |
| `post_to_slack` | payload can override the configured webhook | chat broker |
| `delegate_to_subagent` | child receives the parent's complete tool list | explicit child-subset check |

`camel_argument_hijack` is an auxiliary CaMeL-specific fixture. It models a value
which the flow graph regards as trusted being transformed inside a tool into a
filesystem target. It is reported separately from the eight-tool headline cohort.

The source intentionally stays small and direct so the analyzer's findings can be
reviewed against the code by eye. Do not “fix” these functions; safe counterparts
belong in the PoC harness or the actual slangGraph backend.
