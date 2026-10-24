# Motte

Motte provides profiles for isolated development environments for agentic development using OpenCode.

## Tech stack
- `microsandbox` for microVM isolation
- Golang for the motte binary
- Go SDK of the `microsandbox`
- `mise` for installation and management of dev tooling

## Project layout
- docker: docker images for the various development environments
- sandboxes: microsandbox configs including network policies and common settings
- motte launcher. `go run . <golang|web> [--no-pull]` starts a profile in an isolated microsandbox VM via the Go SDK

## Microsandbox
Microsandbox docs are at https://docs.microsandbox.dev/cli/configuration

## Project constraints
- Write markdown `.md` files one sentence per line
- Run `task lint` to lint, test, and verify changes
