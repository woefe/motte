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
- sandboxes: microsandbox configs including network policies and common settings
- motte launcher. `go run . <golang|web> [--no-pull]` starts a profile in an isolated microsandbox VM via the Go SDK

## Project constraints
- Write markdown `.md` files one sentence per line
- Run `task lint` to lint, test, and verify changes
