# Motte

Motte provides profiles for isolated development environments for agentic development using OpenCode.

## Tech stack
- Go launcher using the `microsandbox` Go SDK
- `microsandbox` for microVM isolation

## Project layout
- docker: docker images for the various development environments
- sandboxes: microsandbox configs including network policies and common settings
- launcher (main.go, profile.go, sdk.go): `go run . [golang|web] [--no-pull]` starts a profile in an isolated microsandbox VM via the Go SDK

## Microsandbox
Microsandbox docs are at https://docs.microsandbox.dev/cli/configuration

## Project constraints
- Write markdown `.md` files one sentence per line

