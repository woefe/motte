# Motte

Motte provides profiles for isolated development environments for agentic development with the [OpenCode](https://opencode.ai) coding agent.
Environments are isolated using [microsandbox](https://docs.microsandbox.dev) microVMs.

## Prerequisites

[Go](https://go.dev) 1.22 or newer to run the launcher.
The launcher reuses an already-installed microsandbox runtime and otherwise downloads its pinned `msb`/`libkrunfw` pair to `~/.microsandbox` on first start.
The microsandbox CLI (`msb`) itself is only needed for the one-offs below.

## Usage

```sh
go run . golang   # golang profile
go run . web      # web profile
```

This pulls the CI-built image, starts a microsandbox microVM, and launches the OpenCode TUI with the repository root mounted read-write at `/workspace`.
Add `--no-pull` to skip the registry pull so a locally loaded image can win.
The profiles live in `sandboxes/common.yaml` plus `sandboxes/<name>.yaml`; both follow the [microsandbox CLI config](https://docs.microsandbox.dev/cli/configuration) schema, and the launcher rejects fields it cannot translate.

Useful one-offs:

```sh
# Verify the sandbox can reach everything it should (agent + llama /health)
msb exec motte-golang -- check

# Continue a previous session
msb exec -t motte-golang -- opencode

# Clean up
msb rm -f motte-golang
```

## Images

CI rebuilds all images every Monday 04:00 UTC and on pushes touching `docker/**`.
Tags: `ghcr.io/woefe/motte/{base,golang,web}:{latest,YYYY-MM-DD}` — pin a specific weekly build via the date tag; `latest` is the rolling tag.

**adopting a new weekly image**: images rebuild on schedule; `go run .` re-pulls `:latest` and recreates the sandbox - sessions/config live on the sandbox's own root disk and are kept across stop/start.

## Default OpenCode inference providers
The default opencode config sets up a llama.cpp and OpenCode Go inference providers

### Local llama.cpp

A llama.cpp server on the host listening on port **9931
Make sure it is bound to an interface the sandbox gateway can reach, e.g. `--host 0.0.0.0`:

```sh
llama-server -m ./model.gguf --host 0.0.0.0 --port 9931
```

### OpenCode Go
The API key is injected with a **microsandbox secret** — it never enters the VM:

1. Create the key at https://opencode.ai/console
2. Export it in the host environment before launching:
   ```sh
   export OPENCODE_GO_KEY="sk_..."   # the launcher refuses to start without it
   ```
3. launch the sandbox with `go run . <profile>`

The alternative is the interactive `/connect` flow inside the TUI (credential stored in the sandbox's own root disk); the secret is preferred here because it keeps the key on the host.
