# Evaluation hardware and model inventory

Captured on 2026-10-05. Every generated result table must cite this file and the
per-run audit record.

## Host

| Field | Value |
| --- | --- |
| Operating system | Ubuntu 24.04.5 LTS |
| Kernel | `6.17.0-1032-oem` |
| GPU | 2 × NVIDIA RTX A4000 |
| VRAM | 16,376 MiB per GPU |
| NVIDIA driver | `580.178.04` |
| Ollama client/server | `0.32.14` |
| Ollama endpoint | `http://localhost:11434/v1` |
| Ollama server context | 40,960 tokens (`OLLAMA_CONTEXT_LENGTH=40960`) |

The two GPUs provide approximately 32 GiB aggregate VRAM, but model selection keeps
headroom for an explicit benchmark context. Availability in aggregate VRAM does not
imply that every backend can shard a particular model efficiently.

## Selected models

### Primary: `qwen3.8:27b`

| Field | Value |
| --- | --- |
| Local model ID | `22130167c4c2` |
| Parameter count | 27.3B |
| Quantization | Q4_K_M |
| Advertised context | 262,144 tokens |
| Required capability | tools (present) |
| Config digest | `sha256:492b2922d38e553cabc2d319345644ed482874fbf5e5c9e4495cbf8e17b0cf5f` |
| Model layer digest | `sha256:f5f1dd8920d417aac2718b0bda3403da274301efdd6760b4f0f4b864ff2ad57d` |
| Projector layer digest | `sha256:ac3714bfdddeca31351f2752bf1a63f266f4df87c0b68c895e44945ca704448e` |
| Parameters layer digest | `sha256:906ee87bde6cff7bf3c3b1550f55cbbec261e027187fbb9f511f908ffc418334` |
| License layer digest | `sha256:4c6a8e842ef0d8504549facfb03f1273a8d0022991519bc1888522cc1a5517d1` |

### Secondary: `qwen3:8b`

| Field | Value |
| --- | --- |
| Local model ID | `500a1f067a9f` |
| Parameter count | 8.2B |
| Quantization | Q4_K_M |
| Advertised context | 40,960 tokens |
| Required capability | tools (present) |
| Model layer digest | `sha256:a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f` |
| Config digest | `sha256:05a61d37b08453e59290add468e3bb2f688e23a01e967fecb0e2fa41218cea76` |
| Template layer digest | `sha256:ae370d884f108d16e7cc8fd5259ebc5773a0afa6e078b11f4ed7e39a27e0dfc4` |
| Parameters layer digest | `sha256:cff3f395ef3756ab63e58b0ad1b32bb6f802905cae1472e6a12034e4246fbbdb` |
| License layer digest | `sha256:d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12` |

The model was pulled from the official Ollama `qwen3:8b` tag on 2026-10-05.

## Installed models rejected for the study

| Tag | Reason |
| --- | --- |
| `gpt-oss:120b` | 65 GB local image; insufficient VRAM headroom on this host |
| `llama3:latest` | advertises completion only, not tool calling |

## Run-level model settings

Every live run uses temperature `0`, seed `20261005`, and an explicit 40,960-token
server context. Ollama 0.32.14 ignored a per-request `options.num_ctx` field on its
OpenAI-compatible route during the setup probe, so the local server is started with
`OLLAMA_CONTEXT_LENGTH=40960`; the loader-reported context is the attestation. The
benchmark prompt census must still confirm that no pinned prompt exceeds this limit
before E3 begins.
