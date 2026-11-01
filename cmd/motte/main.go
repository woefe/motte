// Command motte launches an OpenCode sandbox from a built-in profile.
//
// Usage:
//
//	motte opencode <base|golang|rails|web> [--no-pull] [--replace]
//	motte policies ls
//	motte policies configure <scope>
//	motte secrets <add|set|configure|rm|ls>
//
// --no-pull skips the registry pull so a locally loaded image can win.
// The VM is named after the directory you launch from and is reused across
// runs; --replace recreates it instead. Secrets are managed with the secrets
// subcommand and stored in the OS keychain. Behaviour and one-offs: see the
// README.
package main

import (
	"os"

	"github.com/woefe/motte/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args))
}
