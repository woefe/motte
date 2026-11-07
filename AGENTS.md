# Motte

Motte provides isolated development environments for agentic development using OpenCode.

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
  - `motte init` interactively configures the project of the current directory
  - `motte opencode|oc [--no-pull] [--replace]` boots the current directory's project in an isolated microsandbox VM via the Go SDK
  - `motte policies <ls|configure>` manages the user policy groups
  - `motte secrets <add|set|configure|rm|ls>` manages keychain-backed secrets
- `cmd/motte` is the thin binary entrypoint; all Go code lives under `internal/`
- `internal/cli` builds the cobra command tree and carries the command implementations (prompts, ls formatting, exit semantics)
- `internal/launcher` is the boot flow: it merges the selected policy groups and the project entries into one allow list, resolves the keychain secrets, and drives the microsandbox Go SDK
- `internal/project` owns the per-directory project config files, the built-in image presets, and repository toolchain detection
- `internal/policies` owns the user policy group files and the network rule grammar
- `internal/secrets` owns the per-secret settings files and the keychain-backed values
- `internal/config` owns the config tree paths under `$XDG_CONFIG_HOME/motte` and the shared editor configure flow
- user config lives in one file per entity: `projects/<dir-hash>.yaml`, `policies/<group>.yaml`, `secrets/<NAME>.yaml`

## Project constraints
- Write markdown `.md` files one sentence per line
- Run `go mod tidy` after adding new dependencies
- Run `task lint` to lint, test, and verify changes
- Use `log/slog` for logging: structured records to stderr via `slog.Info`/`Warn`/`Error`; prompts and command output stay on `fmt`
- Use code comments sparsely. Comments should never describe old behavior, but only the current behavior.
- If you have to explain too many details and cross references in comments think of a better design
- The README must stay well readable for human end-users: prefer the `motte` binary in examples, and avoid technical internals such as source file references or build details
