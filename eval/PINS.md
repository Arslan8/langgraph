# Evaluation dependency pins

Captured on 2026-10-05. Git pins are immutable commit objects resolved from each
repository's default branch. Python pins include the SHA-256 of both published
artifacts so installation can be hash-checked.

## Git repositories

| Component | Source | Default branch | Commit |
| --- | --- | --- | --- |
| Progent | `https://github.com/sunblaze-ucb/progent.git` | `main` | `5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565` |
| CaMeL | `https://github.com/google-research/camel-prompt-injection.git` | `main` | `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8` |
| AgentDojo | `https://github.com/ethz-spylab/agentdojo.git` | `main` | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` |
| InjecAgent | `https://github.com/uiuc-kang-lab/InjecAgent.git` | `main` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` |
| AdaptiveAttackAgent | `https://github.com/uiuc-kang-lab/AdaptiveAttackAgent.git` | `master` | `7ea08cf4424e689079c6bc6348e28fbb84a090eb` |
| ASB | `https://github.com/agiresearch/ASB.git` | `main` | `544540ff0788998072f7df463056fd17e62cc9f4` |
| AIOS | `https://github.com/agiresearch/AIOS.git` | `main` | `292d98f78c835499df18cdb6de6325bba1895862` |

The Progent source URL is retained exactly as specified for the study even though
the public project is also presented under the Agentic-AI-Risk-Mitigation
organization. The commit object is the authority.

## Python distributions

| Distribution | Version | Wheel SHA-256 | Source SHA-256 |
| --- | --- | --- | --- |
| `langchain-eydii` | `0.1.1` | `5abfd1347fefcce6eb87e0af78afc8e9e61d8dae77ead7dedc66c046c0e3ea90` | `c92c04e3a35e373ab036cf24b96a58c45ec616797fb92169b932b7bbb5c9abcc` |
| `langchain-forge` | `0.2.0` | `1f9c4884c18490af750ca1b400c05696291ec6768f5716035aa31227396820e5` | `7542c7ae81e774f89f0074657852655f8e19061ddc42fb2903885d838f80ccde` |
| `langchain-nuggets` | `1.4.0` | `7c39bee8435fabbbec8811095f9742d2c9d6c98891eefd3908b1bd004f03f12f` | `8a61da1dfc1437f0dbc3aa35e4aed6d0670dfd35b184a801f75156796d456113` |
| `agentdojo` | `0.1.35` | `364bea4219716b716bf639f504d195943f7f6a5535d312ca41d7098704a2affd` | `9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956` |
| `veritera` | `0.4.0` | `6de67bac1036b110276d3cfd2271c4e9567d41f8606afd3b7d9667948c8a47d3` | `4411462202802ce76a8137f73e38438969342a5549eb511d1a933da1d8397456` |

`langchain-forge==0.2.0` declares the open-ended dependency
`veritera>=0.2.0`. On the capture date, a fresh resolution selected 0.4.1 and
failed at import because that release no longer exports `Forge`. The artifact
pins the compatible 0.4.0 release above. This is dependency stabilization, not
a source patch to Forge.

## SEAgent status

SEAgent is treated as related work, not a runnable baseline. Its information-flow
graph idea may be represented by a slangGraph module named `flowgraph`, with an
explicit citation and without claiming to reimplement SEAgent. Before paper
submission, repeat the public-code search and add a reproduction appendix if the
authors release code and policy sets.
