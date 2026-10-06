# E1 static exposure census

Counts are projections of one static report through documented mediation models.
They are not runtime-blocking results. See `exposure.json` for every sink decision.

| tool | cohort | static_sinks | none | progent | camel | langchain-eydii | langchain-forge | langchain-nuggets | slanggraph-advisory | slanggraph-landlock | slanggraph-landlock-broker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| read_file | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 0 |
| write_file | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 0 |
| run_shell | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 0 |
| sql_query | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| web_fetch | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 0 |
| send_email | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| post_to_slack | headline | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| delegate_to_subagent | headline | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| camel_argument_hijack | auxiliary | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |

Static exposure is an upper bound; landed local-canary PoCs are the lower bound.
All hardware and model claims refer to `../../HARDWARE.md`.
