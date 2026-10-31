// The motte command tree.
//
//	motte opencode <profile> [--no-pull] [--replace]
//	motte policies ls
//	motte policies configure <scope>
//	motte secrets <add|set|configure|rm|ls>
//
// The tree is built with cobra; every command carries its own help. Errors
// are printed by run in motte's own style, without cobra's usage dump.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// exitCoder is an error that carries the exit code motte exits with. An
// empty message means the command already reported what happened.
type exitCoder struct {
	code    int
	message string
}

func (e exitCoder) Error() string { return e.message }

// ExitCode returns the exit code the command exits with.
func (e exitCoder) ExitCode() int { return e.code }

// newRootCommand builds the motte command tree.
func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "motte",
		Short: "launch isolated OpenCode development environments",
		Long: "motte runs a profile in an isolated microVM and attaches the OpenCode TUI to it.\n" +
			"Secrets live in the OS keychain, network policies in ~/.config/motte/policies.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE:          runRoot,
	}
	// Cobra defaults this threshold only inside its own suggestion
	// formatting; the root command asks for the suggestions itself.
	root.SuggestionsMinimumDistance = 2
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(opencodeCommand(), policiesCommand(), secretsCommand())
	return root
}

// runRoot handles an invocation without a subcommand: it prints the help and
// points at the command the user meant.
func runRoot(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		printHelp(cmd)
		return exitCoder{code: 1}
	}
	arg := args[0]
	if slices.Contains(availableProfiles(), arg) {
		return exitCoder{code: 1, message: fmt.Sprintf(
			"unknown command %q; did you mean %q?", arg, "motte oc "+arg)}
	}
	if suggestions := cmd.Root().SuggestionsFor(arg); len(suggestions) > 0 {
		return exitCoder{code: 1, message: fmt.Sprintf(
			"unknown command %q; did you mean %q?", arg, "motte "+suggestions[0])}
	}
	return exitCoder{code: 1, message: fmt.Sprintf(
		"unknown command %q; expected opencode, oc, policies, or secrets", arg)}
}

// opencodeCommand boots a profile and attaches the OpenCode TUI to it.
func opencodeCommand() *cobra.Command {
	var noPull, replace bool
	cmd := &cobra.Command{
		Use:     "opencode <profile>",
		Aliases: []string{"oc"},
		Short:   "boot a profile and attach the OpenCode TUI",
		Args:    profileArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := boot(args[0], noPull, replace)
			if err != nil {
				return err
			}
			if code != 0 {
				return exitCoder{code: code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&noPull, "no-pull", false, "skip the registry pull so a locally loaded image can win")
	cmd.Flags().BoolVar(&replace, "replace", false, "recreate the VM instead of reusing this directory's VM")
	return cmd
}

// profileArgs accepts exactly one profile name.
func profileArgs(cmd *cobra.Command, args []string) error {
	switch len(args) {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("no profile given (expected one of %s)", strings.Join(availableProfiles(), ", "))
	default:
		return fmt.Errorf("expected one profile, got %d", len(args))
	}
}

// scopeArg is a resolved configure argument: exactly one field is set —
// profile, hash, or neither for the global scope.
type scopeArg struct {
	profile string
	hash    string
}

// resolveScopeArg resolves a configure argument: "global", "project", a
// built-in profile name, or a 12-hex project hash.
func resolveScopeArg(arg string) (scopeArg, error) {
	switch {
	case arg == "global":
		return scopeArg{}, nil
	case arg == "project":
		hash, err := dirHash()
		if err != nil {
			return scopeArg{}, err
		}
		return scopeArg{hash: hash}, nil
	case slices.Contains(availableProfiles(), arg):
		return scopeArg{profile: arg}, nil
	case secretHashPattern.MatchString(arg):
		return scopeArg{hash: arg}, nil
	default:
		return scopeArg{}, fmt.Errorf(
			"unknown scope %q; expected global, project, a profile (%s), or a project hash",
			arg, strings.Join(availableProfiles(), ", "))
	}
}

// labelScope renders a scope for listings and template headers: "global",
// "profile <name>", or "project <hash>"; thisDir marks the current
// directory's project.
func labelScope(profile, hash string, thisDir bool) string {
	switch {
	case profile != "":
		return "profile " + profile
	case hash != "":
		if thisDir {
			return "project " + hash + " (this directory)"
		}
		return "project " + hash
	default:
		return "global"
	}
}

// lsScopes returns the scopes that have a file in a config tree, ordered:
// the global scope, the built-in profiles, then the projects sorted by hash.
func lsScopes(root string) ([]scopeArg, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}
	existing := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		existing[strings.TrimSuffix(entry.Name(), ".yaml")] = true
	}
	var scopes []scopeArg
	if existing["global"] {
		scopes = append(scopes, scopeArg{})
	}
	for _, profile := range availableProfiles() {
		if existing[profile] {
			scopes = append(scopes, scopeArg{profile: profile})
		}
	}
	var hashes []string
	for name := range existing {
		if secretHashPattern.MatchString(name) {
			hashes = append(hashes, name)
		}
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		scopes = append(scopes, scopeArg{hash: hash})
	}
	return scopes, nil
}

// printHelp writes a command's help to its error output.
func printHelp(cmd *cobra.Command) {
	w := cmd.ErrOrStderr()
	cmd.SetOut(w)
	cmd.SetErr(w)
	_ = cmd.Help()
}
