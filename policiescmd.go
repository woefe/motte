// The `motte policies` subcommand: inspect and edit the network policies.
//
// ls lists the existing policy files grouped by scope with their entries;
// configure opens a scope's file in $VISUAL/$EDITOR and re-validates it
// afterwards.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// policiesCommand builds the `motte policies` command tree.
func policiesCommand() *cobra.Command {
	policies := &cobra.Command{
		Use:   "policies",
		Short: "manage the user network policies",
		Long: "Policies live in ~/.config/motte/policies, one file per scope:\n" +
			"global.yaml, <profile>.yaml, and <hash>.yaml for the current directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printHelp(cmd)
			return exitCoder{code: 1}
		},
	}
	policies.AddCommand(policiesLsCommand(), policiesConfigureCommand())
	return policies
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesConfigure(args[0])
		},
	}
}

// runPoliciesLs lists the existing policy files grouped by scope, with the
// entries of each file.
func runPoliciesLs() error {
	root, err := policiesDir()
	if err != nil {
		return err
	}
	scopes, err := lsScopes(root)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		fmt.Fprintln(os.Stderr, "no policies configured; create one with `motte policies configure global`")
		return nil
	}
	hash, hashErr := dirHash()
	for i, scope := range scopes {
		if i > 0 {
			fmt.Println()
		}
		thisDir := hashErr == nil && scope.hash != "" && scope.hash == hash
		fmt.Printf("%s:\n", labelScope(scope.profile, scope.hash, thisDir))
		path, err := policyTargetPath(policyTargetFromArg(scope))
		if err != nil {
			return err
		}
		entries, err := readPolicyFile(path)
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
func runPoliciesConfigure(scope string) error {
	arg, err := resolveScopeArg(scope)
	if err != nil {
		return err
	}
	target := policyTargetFromArg(arg)
	path, err := policyTargetPath(target)
	if err != nil {
		return err
	}
	return configureScope(scopeFile{
		path:     path,
		fixCmd:   fmt.Sprintf("motte policies configure %s", scope),
		template: func() (string, error) { return policyTemplate(target) },
		read:     func() error { _, err := readPolicyFile(path); return err },
	})
}
