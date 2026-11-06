// The motte command tree.
//
//	motte opencode <profile> [--no-pull] [--replace]
//	motte policies ls
//	motte policies configure <scope>
//	motte secrets <add|set|configure|rm|ls>
//
// The tree is built with cobra; every command carries its own help. Errors
// are printed by Run in motte's own style, without cobra's usage dump.
// Incomplete commands print their help and exit.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/launcher"
	"github.com/woefe/motte/internal/profile"
	"github.com/woefe/motte/internal/secrets"
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

// bootFunc runs a profile's sandbox and returns the workload's exit code.
type bootFunc func(profileName string, noPull, replace bool) (int, error)

// env holds the external dependencies of the CLI command tree.
type env struct {
	boot   bootFunc
	store  secrets.Store
	in     io.Reader
	out    io.Writer
	errOut io.Writer
}

func defaultEnv() env {
	return env{
		boot:   launcher.Boot,
		store:  secrets.DefaultStore(),
		in:     os.Stdin,
		out:    os.Stdout,
		errOut: os.Stderr,
	}
}

// Run dispatches the command tree and returns the exit code.
func Run(args []string) int {
	return runWithEnv(args, defaultEnv())
}

func runWithEnv(args []string, e env) int {
	root := newRootCommand(e)
	root.SetArgs(args[1:])
	err := root.Execute()
	if err == nil {
		return 0
	}
	// The configure flow already explained the invalid file; exit silently.
	if errors.Is(err, config.ErrInvalidAfterEdit) {
		return 1
	}
	if coded, ok := errors.AsType[exitCoder](err); ok {
		if coded.message != "" {
			_, _ = fmt.Fprintf(e.errOut, "motte: %s\n", coded.message)
		}
		return coded.ExitCode()
	}
	_, _ = fmt.Fprintf(e.errOut, "motte: %v\n", err)
	return 1
}

// newRootCommand builds the motte command tree.
func newRootCommand(e env) *cobra.Command {
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
	root.SetIn(e.in)
	root.SetOut(e.out)
	root.SetErr(e.errOut)
	// Cobra defaults this threshold only inside its own suggestion
	// formatting; the root command asks for the suggestions itself.
	root.SuggestionsMinimumDistance = 2
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(opencodeCommand(e.boot), policiesCommand(), secretsCommand(e.store))
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
	if slices.Contains(profile.Available(), arg) {
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
func opencodeCommand(boot bootFunc) *cobra.Command {
	var noPull, replace bool
	cmd := &cobra.Command{
		Use:     "opencode <profile>",
		Aliases: []string{"oc"},
		Short:   "boot a profile and attach the OpenCode TUI",
		Long:    "The profile is a built-in one: " + strings.Join(profile.Available(), ", ") + ".",
		Args:    singleArg,
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

// singleArg accepts exactly one argument; any other count prints the command
// help.
func singleArg(cmd *cobra.Command, args []string) error {
	if len(args) == 1 {
		return nil
	}
	return argHelpError(cmd)
}

// argHelpError prints a command's help and asks Run to exit with 1.
func argHelpError(cmd *cobra.Command) error {
	printHelp(cmd)
	return exitCoder{code: 1}
}

// printHelp writes a command's help to its error output.
func printHelp(cmd *cobra.Command) {
	w := cmd.ErrOrStderr()
	cmd.SetOut(w)
	cmd.SetErr(w)
	_ = cmd.Help()
}
