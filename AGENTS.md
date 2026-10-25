# Motte

Motte provides profiles for isolated development environments for agentic development using OpenCode.

## Tech stack and tools
- `microsandbox` for microVM isolation. Docs: https://docs.microsandbox.dev/llms.txt
- `mise` for installation and management of dev tooling. Docs: https://mise.jdx.dev/llms.txt
- `task` for make-like task running. Docs: https://taskfile.dev/llms.txt
- Golang for the motte binary
- Go SDK of the `microsandbox`

## Project layout
- docker: docker images for the various development environments; build them locally with `task build-images`
- motte launcher. `go run . profile [--no-pull]` starts a profile in an isolated microsandbox VM via the Go SDK
- built-in profiles are defined as Go structs in `profile.go` (compiled into the binary)

## Project constraints
- Write markdown `.md` files one sentence per line
- Run `task lint` to lint, test, and verify changes
