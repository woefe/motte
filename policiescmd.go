// The `motte policies` subcommand: inspect and edit the network policies.
//
// ls lists every policy file with its scope and its entries; configure opens
// a scope's file in $VISUAL/$EDITOR and re-validates it afterwards.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
		Short: "list the policy files and their entries",
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
		Long:  "The scope is global, a built-in profile name, or project for the current directory.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesConfigure(args[0])
		},
	}
}

// policyRow is one listed policy file.
type policyRow struct {
	target  policyTarget
	path    string
	exists  bool
	entries []string
	err     error
}

// runPoliciesLs lists every policy file with its scope, path, and entries.
func runPoliciesLs() error {
	rows, err := collectPolicyRows()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no policies configured; create one with `motte policies configure global`")
		return nil
	}
	hash, hashErr := dirHash()
	for _, row := range rows {
		label := policyTargetLabel(row.target)
		if row.target.scope == scopePolicyProject && hashErr == nil && row.target.hash == hash {
			label += " (this directory)"
		}
		fmt.Printf("%s\t%s\n", label, row.path)
		switch {
		case row.err != nil:
			fmt.Printf("  <unreadable: %v>\n", row.err)
		case !row.exists:
			fmt.Printf("  (not created yet)\n")
		case len(row.entries) == 0:
			fmt.Printf("  (no entries)\n")
		default:
			for _, entry := range row.entries {
				fmt.Printf("  %s\n", entry)
			}
		}
	}
	if hashErr == nil {
		fmt.Printf("\nproject hash for the current directory: %s\n", hash)
	}
	return nil
}

// collectPolicyRows gathers the policy files that apply to a launch: the
// global file, the built-in profiles' files, and the project files in the
// policy directory.
func collectPolicyRows() ([]policyRow, error) {
	hash, hashErr := dirHash()
	targets := []policyTarget{{scope: scopePolicyGlobal}}
	for _, profile := range availableProfiles() {
		targets = append(targets, policyTarget{scope: scopePolicyProfile, profile: profile})
	}
	if hashErr == nil {
		targets = append(targets, policyTarget{scope: scopePolicyProject, hash: hash})
	}

	rows := make([]policyRow, 0, len(targets))
	seen := map[string]bool{}
	for _, target := range targets {
		path, err := policyTargetPath(target)
		if err != nil {
			return nil, err
		}
		seen[path] = true
		entries, err := readPolicyFile(path)
		rows = append(rows, policyRow{
			target:  target,
			path:    path,
			exists:  fileExists(path),
			entries: entries,
			err:     err,
		})
	}

	// The project files of other directories are listed too: they are part
	// of the same tree and a user may want to see them.
	extra, err := otherProjectPolicyRows(seen)
	if err != nil {
		return nil, err
	}
	rows = append(rows, extra...)
	return rows, nil
}

// otherProjectPolicyRows lists the project policy files of other directories.
func otherProjectPolicyRows(seen map[string]bool) ([]policyRow, error) {
	root, err := policiesDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".yaml")
		if !secretHashPattern.MatchString(name) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if seen[path] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]policyRow, 0, len(names))
	for _, name := range names {
		path := filepath.Join(root, name+".yaml")
		entries, err := readPolicyFile(path)
		rows = append(rows, policyRow{
			target:  policyTarget{scope: scopePolicyProject, hash: name},
			path:    path,
			entries: entries,
			err:     err,
		})
	}
	return rows, nil
}

// fileExists reports whether a path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runPoliciesConfigure opens a scope's policy file in the editor and
// re-validates it afterwards.
func runPoliciesConfigure(scopeArg string) error {
	target, err := resolvePolicyTarget(scopeArg)
	if err != nil {
		return err
	}
	path, err := policyTargetPath(target)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writePolicyTemplate(path, target); err != nil {
			return err
		}
	}
	if err := runEditor(path); err != nil {
		return err
	}
	if _, err := readPolicyFile(path); err != nil {
		fmt.Fprintf(os.Stderr, "motte: %s is invalid after editing: %v\n", path, err)
		fmt.Fprintf(os.Stderr, "motte: fix it with `motte policies configure %s`\n", scopeArg)
		return exitCoder{code: 1}
	}
	fmt.Fprintf(os.Stderr, "motte: %s is valid\n", path)
	return nil
}
