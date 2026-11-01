# Motte

Motte provides profiles for isolated development environments for agentic development using OpenCode.

## Tech stack and tools
- `microsandbox` for microVM isolation. Docs: https://docs.microsandbox.dev/llms.txt
- `mise` for installation and management of dev tooling. Docs: https://mise.jdx.dev/llms.txt
- `task` for make-like task running. Docs: https://taskfile.dev/llms.txt
- Golang for the motte binary
- Go SDK of the `microsandbox`
- Cobra for the CLI parsing: Docs: https://cobra.dev/docs/

## Project layout
- docker: docker images for the various development environments; build them locally with `task build-images`
- motte launcher
  - `motte opencode|oc <profile> [--no-pull] [--replace]` starts a profile in an isolated microsandbox VM via the Go SDK
  - `motte policies <ls|configure>` manages the user network policies
  - `motte secrets <add|set|configure|rm|ls>` manages keychain-backed secrets
- `cmd/motte` is the thin binary entrypoint; all Go code lives under `internal/`
- `internal/cli` builds the cobra command tree and carries the command implementations (prompts, ls formatting, exit semantics)
- `internal/launcher` is the boot flow: it merges the user policies into a profile, resolves the keychain secrets, and drives the microsandbox Go SDK
- `internal/profile` defines the built-in profiles as Go structs (compiled into the binary)
- `internal/policies` owns the network policy files and the network rule grammar
- `internal/secrets` owns the keychain-backed secrets and their scope files
- `internal/config` owns the config tree: the per-scope file paths, the config scopes (global, one per built-in profile, one per project directory hashed from its path), and the shared editor configure flow
- user policies and secrets live in scope files under `$XDG_CONFIG_HOME/motte/{policies,secrets}`

## Project constraints
- Write markdown `.md` files one sentence per line
- Run `go mod tidy` after adding new dependencies
- Run `task lint` to lint, test, and verify changes
- Use `log/slog` for logging: structured records to stderr via `slog.Info`/`Warn`/`Error`; prompts and command output stay on `fmt`
- Use code comments sparsely. Comments should never describe old behavior, but only the current behavior.
- If you have to explain too many details and cross references in comments think of a better design
- The README must stay well readable for human end-users: prefer the `motte` binary in examples, and avoid technical internals such as source file references or build details
