// The `motte policies` subcommand: inspect and edit the network policies.
//
// ls lists the existing policy files grouped by scope with their entries;
// configure opens a scope's file in $VISUAL/$EDITOR and re-validates it
// afterwards.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
)

// policiesCommand builds the `motte policies` command tree.
func policiesCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "policies",
		Short: "manage the user network policies",
		Long: "Policies live in ~/.config/motte/policies, one file per scope:\n" +
			"global.yaml, <profile>.yaml, and <hash>.yaml for the current directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printHelp(cmd)
			return exitCoder{code: 1}
		},
	}
	command.AddCommand(policiesLsCommand(), policiesConfigureCommand())
	return command
}

// policiesLsCommand lists the policy files.
func policiesLsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list the existing policy files grouped by scope, with their entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesLs()
		},
	}
}

// policiesConfigureCommand opens a scope's policy file in the editor.
func policiesConfigureCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "configure <scope>",
		Short: "open a scope's policy in $VISUAL/$EDITOR",
		Long:  "The scope is global, project, a built-in profile name, or a project hash.",
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesConfigure(args[0])
		},
	}
}

// runPoliciesLs lists the existing policy files grouped by scope, with the
// entries of each file.
func runPoliciesLs() error {
	root, err := config.PoliciesDir()
	if err != nil {
		return err
	}
	scopes, err := config.LsScopes(root)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		fmt.Fprintln(os.Stderr, "no policies configured; create one with `motte policies configure global`")
		return nil
	}
	hash, hashErr := config.DirHash()
	for i, scope := range scopes {
		if i > 0 {
			fmt.Println()
		}
		thisDir := hashErr == nil && scope.Hash != "" && scope.Hash == hash
		fmt.Printf("%s:\n", scope.Label(thisDir))
		path, err := policies.ScopePath(scope)
		if err != nil {
			return err
		}
		entries, err := policies.ReadPolicyFile(path)
		switch {
		case err != nil:
			fmt.Printf("  <unreadable: %v>\n", err)
		case len(entries) == 0:
			fmt.Printf("  (no entries)\n")
		default:
			for _, entry := range entries {
				fmt.Printf("  %s\n", entry)
			}
		}
	}
	return nil
}

// runPoliciesConfigure opens a scope's policy file in the editor and
// re-validates it afterwards.
func runPoliciesConfigure(scopeArg string) error {
	scope, err := config.ResolveScope(scopeArg)
	if err != nil {
		return err
	}
	path, err := policies.ScopePath(scope)
	if err != nil {
		return err
	}
	return config.ConfigureScope(config.ScopeFile{
		Path:   path,
		FixCmd: fmt.Sprintf("motte policies configure %s", scopeArg),
		Template: func() (string, error) {
			return policies.Template(scope)
		},
		Read: func() error {
			_, err := policies.ReadPolicyFile(path)
			return err
		},
	})
}
