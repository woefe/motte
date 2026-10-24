# Motte

Motte provides profiles for isolated development environments for agentic development with the [OpenCode](https://opencode.ai) coding agent.
Environments are isolated using [microsandbox](https://docs.microsandbox.dev) microVMs.

## Prerequisites

[Go](https://go.dev) 1.22 or newer to run the launcher.
The launcher reuses an already-installed microsandbox runtime and otherwise downloads its pinned `msb`/`libkrunfw` pair to `~/.microsandbox` on first start.
The microsandbox CLI (`msb`) itself is only needed for the one-offs below and for `task build-images`.
Building images locally also needs `podman` and [Task](https://taskfile.dev).

## Usage

```sh
go run . golang   # golang profile
go run . web      # web profile
```

This pulls the CI-built image, starts a microsandbox microVM, and launches the OpenCode TUI with the directory you launched motte from mounted read-write at `/workspace`.
Each directory has its own VM, named after a hash of that directory; the launcher prints the name it uses.
A directory's VM is reused across runs, so sessions and config on its root disk are kept; pass `--replace` to recreate the VM from scratch.
Add `--no-pull` to skip the registry pull so a locally loaded image can win.
The profiles are compiled into the launcher (see `profile.go`); a profile image or egress policy change therefore goes through a rebuild rather than a config edit.

Useful one-offs (substitute the VM name the launcher printed):

```sh
# Verify the sandbox can reach everything it should (agent + llama /health)
msb exec <vm-name> -- check

# Continue a previous session
msb exec -t <vm-name> -- opencode

# Clean up
msb rm -f <vm-name>
```

## User network policies

Egress is deny-by-default with the built-in allow list; user config can widen it.
To allow additional hosts, create `~/.config/motte/<profile>.yaml`, or `~/.config/motte/common.yaml` to apply to every profile:

```yaml
network:
  allow:
    - "*.example.com"
```

Entries use the same [microsandbox CLI rule](https://docs.microsandbox.dev/cli/configuration) `TARGET[:PROTO[:PORTS]]` grammar as the built-in profiles and are appended (deduplicated) to them.
User config can only widen egress, never narrow it.
Only `network.allow` is accepted; unknown keys or invalid entries fail the launch, with the file path in the error.

## Images

CI rebuilds all images every Monday 04:00 UTC and on pushes touching `docker/**`.
Tags: `ghcr.io/woefe/motte/{base,golang,web}:{latest,YYYY-MM-DD}` — pin a specific weekly build via the date tag; `latest` is the rolling tag.

**adopting a new weekly image**: images rebuild on schedule; run `go run . <profile> --replace` to re-pull `:latest` and recreate the VM.

**building locally**: `task build-images` builds all images and loads them into the msb cache under the same `latest` refs the profiles reference; `task build-images name=golang` builds the base plus one variant.
Boot the local image with `go run . <profile> --no-pull --replace`.
The local image shadows `latest` in the msb cache only until the next plain `go run . <profile>` re-pulls GHCR, which restores the CI image.

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
