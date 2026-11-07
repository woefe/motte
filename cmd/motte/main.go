// Command motte launches an isolated OpenCode sandbox for this directory's
// project.
//
// Usage:
//
//	motte init
//	motte opencode [--no-pull] [--replace]
//	motte oc [--no-pull] [--replace]
//	motte policies ls
//	motte policies configure <group>
//	motte secrets <add|set|configure|rm|ls>
//
// --no-pull skips the registry pull so a locally loaded image can win.
// The VM is named after the directory you launch from (`motte-<dir-hash>`) and
// is reused across runs; --replace recreates it instead. Secrets are managed
// with the secrets subcommand and stored in the OS keychain. Behaviour and
// one-offs: see the README.
package main

import (
	"log/slog"
	"os"

	"github.com/woefe/motte/internal/cli"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	os.Exit(cli.Run(os.Args))
}
