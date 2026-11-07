// The `motte policies` subcommand: inspect and edit the user policy groups.
//
// ls lists the user policy groups with their entries and this project's
// effective network policy; configure opens a group's file in $VISUAL/$EDITOR
// and re-validates it afterwards.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/launcher"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/project"
)

// policiesCommand builds the `motte policies` command tree.
func policiesCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "policies",
		Short: "manage the user policy groups",
		Long:  "Policy groups live in ~/.config/motte/policies, one file (<group>.yaml) per group.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printHelp(cmd)
			return exitCoder{code: 1}
		},
	}
	command.AddCommand(policiesLsCommand(), policiesConfigureCommand())
	return command
}

// policiesLsCommand lists the policy groups and this project's effective
// network policy.
func policiesLsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list the policy groups and this project's effective network policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesLs(cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

// policiesConfigureCommand opens a policy group file in the editor.
func policiesConfigureCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "configure <group>",
		Short: "create or edit one user policy group in $VISUAL/$EDITOR",
		Long:  "The group name is a slug (lowercase letters, digits, and dashes).",
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesConfigure(cmd.ErrOrStderr(), args[0])
		},
	}
}

// runPoliciesLs lists the configured user policy groups and this directory's
// effective network policy.
func runPoliciesLs(out, errOut io.Writer) error {
	groups, err := policies.ListGroups()
	if err != nil {
		return err
	}
	proj, projectPath, projErr := project.ReadCurrent()
	hasProject := !errors.Is(projErr, project.ErrNotFound)

	if len(groups) == 0 && !hasProject {
		_, _ = fmt.Fprintln(
			errOut,
			"no policy groups or project configured; create a group with `motte policies configure <group>` or run `motte init`",
		)
		return nil
	}

	printed := false
	for _, group := range groups {
		if printed {
			_, _ = fmt.Fprintln(out)
		}
		printed = true
		_, _ = fmt.Fprintf(out, "group %s:\n", group)
		entries, err := policies.ReadGroup(group)
		printPolicyEntries(out, entries, err)
	}

	if hasProject {
		if printed {
			_, _ = fmt.Fprintln(out)
		}
		hash, _ := config.DirHash()
		_, _ = fmt.Fprintf(out, "effective policy (project %s):\n", hash)
		if projErr != nil {
			_, _ = fmt.Fprintf(out, "  <unreadable: %v>\n", projErr)
			return nil
		}
		effective, err := launcher.EffectiveAllow(proj, projectPath)
		printPolicyEntries(out, effective, err)
	}
	return nil
}

// printPolicyEntries renders a list of network allow entries or an error/empty
// placeholder.
func printPolicyEntries(out io.Writer, entries []string, err error) {
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(out, "  <unreadable: %v>\n", err)
	case len(entries) == 0:
		_, _ = fmt.Fprintf(out, "  (no entries)\n")
	default:
		for _, entry := range entries {
			_, _ = fmt.Fprintf(out, "  %s\n", entry)
		}
	}
}

// runPoliciesConfigure opens a policy group file in the editor and
// re-validates it afterwards.
func runPoliciesConfigure(errOut io.Writer, group string) error {
	path, err := policies.GroupPath(group)
	if err != nil {
		return err
	}
	return config.ConfigureFile(config.EditableFile{
		Path:   path,
		FixCmd: fmt.Sprintf("motte policies configure %s", group),
		ErrOut: errOut,
		Template: func() (string, error) {
			return policies.Template(group)
		},
		Read: func() error {
			_, err := policies.ReadGroupFile(path)
			return err
		},
	})
}
