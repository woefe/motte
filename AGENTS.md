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
- built-in profiles are defined as Go structs in `profile.go` (compiled into the binary)
- `scope.go` resolves the config scopes: global, one per built-in profile, and one per project directory (hashed from its path)
- `config.go` owns motte's config tree: the per-scope file paths, writing file skeletons, and the shared editor configure flow
- user policies and secrets live in scope files under `$XDG_CONFIG_HOME/motte/{policies,secrets}`

## Project constraints
- Write markdown `.md` files one sentence per line
- Run `go mod tidy` after adding new dependencies
- Run `task lint` to lint, test, and verify changes
- Use code comments sparsely. Comments should never describe old behavior, but only the current behavior.
- If you have to explain too many details and cross references in comments think of a better design
- The README must stay well readable for human end-users: prefer the `motte` binary in examples, and avoid technical internals such as source file references or build details
