// The `motte init` subcommand: interactively configure this directory's
// project.
//
// Prompts for the image preset (or keeps an existing custom image), the user
// policy groups, and the secrets. Re-running `init` pre-fills its prompts from
// the existing project config and preserves hand-edited `network.allow`
// entries.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/secrets"
)

// initCommand builds the `motte init` command.
func initCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "configure this directory's project; interactive",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd)
		},
	}
}

// runInit interactively configures the current directory's project.
func runInit(cmd *cobra.Command) error {
	in := cmd.InOrStdin()
	if !isTerminalReader(in) {
		return fmt.Errorf(
			"motte init is interactive; run it in a terminal, or craft %s/projects/<hash>.yaml by hand",
			config.Hint(),
		)
	}
	return initProject(bufio.NewReader(in), cmd.ErrOrStderr())
}

// initProject runs the interactive project setup prompts and writes the
// current directory's project config.
func initProject(in *bufio.Reader, errOut io.Writer) error {
	projectDir, err := config.ProjectPath()
	if err != nil {
		return err
	}
	existing, path, err := project.ReadCurrent()
	hasExisting := err == nil
	if err != nil && !errors.Is(err, project.ErrNotFound) {
		return err
	}

	availableGroups, err := policies.ListGroups()
	if err != nil {
		return err
	}
	availableSecrets, err := secrets.ListNames()
	if err != nil {
		return err
	}

	image, err := promptInitImage(in, errOut, projectDir, existing, hasExisting)
	if err != nil {
		return err
	}
	groups, err := promptInitGroups(in, errOut, availableGroups, existing.AllowGroups)
	if err != nil {
		return err
	}
	defaultSecrets := availableSecrets
	if hasExisting {
		defaultSecrets = existing.Secrets
	}
	selectedSecrets, err := promptInitSecrets(in, errOut, availableSecrets, defaultSecrets)
	if err != nil {
		return err
	}

	cfg := project.Config{
		Image:       image,
		Allow:       existing.Allow,
		AllowGroups: groups,
		Secrets:     selectedSecrets,
	}
	if err := project.WriteFile(path, projectDir, cfg); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "motte: wrote project config %s\n", path)
	return nil
}

// promptInitImage prompts for a built-in image preset (or a full image
// reference), defaulting to the existing config or the detected repo
// toolchain.
func promptInitImage(
	in *bufio.Reader,
	errOut io.Writer,
	projectDir string,
	existing project.Config,
	hasExisting bool,
) (string, error) {
	defaultChoice := project.DetectPreset(projectDir)
	if hasExisting && existing.Image != "" {
		if preset, ok := project.PresetName(existing.Image); ok {
			defaultChoice = preset
		} else {
			defaultChoice = existing.Image
		}
	}
	presets := strings.Join(project.Presets(), ", ")
	answer, err := promptLine(
		in,
		errOut,
		fmt.Sprintf("image preset (%s) [%s]: ", presets, defaultChoice),
	)
	if err != nil {
		return "", err
	}
	choice := strings.TrimSpace(answer)
	if choice == "" {
		choice = defaultChoice
	}
	if ref, ok := project.PresetImage(choice); ok {
		return ref, nil
	}
	if strings.Contains(choice, "/") {
		return choice, nil
	}
	return "", fmt.Errorf(
		"unknown image preset %q (available: %s, or a full image reference)",
		choice,
		presets,
	)
}

// promptInitGroups prompts for comma-separated user policy groups.
func promptInitGroups(
	in *bufio.Reader,
	errOut io.Writer,
	available []string,
	current []string,
) ([]string, error) {
	availableLabel := "none configured"
	if len(available) > 0 {
		availableLabel = strings.Join(available, ", ")
	}
	defaultLabel := "none"
	if len(current) > 0 {
		defaultLabel = strings.Join(current, ", ")
	}
	answer, err := promptLine(
		in,
		errOut,
		fmt.Sprintf("policy groups, comma-separated (%s) [%s]: ", availableLabel, defaultLabel),
	)
	if err != nil {
		return nil, err
	}
	selected := parseSelection(answer, current)
	for _, group := range selected {
		if err := policies.ValidateGroupName(group); err != nil {
			return nil, err
		}
		if !slices.Contains(available, group) {
			return nil, fmt.Errorf(
				"policy group %q is not configured; create it with `motte policies configure %s`",
				group,
				group,
			)
		}
	}
	return selected, nil
}

// promptInitSecrets prompts for comma-separated secrets, defaulting to all
// configured secrets on a fresh project or the current selection when
// re-running init.
func promptInitSecrets(
	in *bufio.Reader,
	errOut io.Writer,
	available []string,
	defaults []string,
) ([]string, error) {
	availableLabel := "none configured"
	if len(available) > 0 {
		availableLabel = strings.Join(available, ", ")
	}
	defaultLabel := "none"
	if len(defaults) > 0 {
		defaultLabel = strings.Join(defaults, ", ")
	}
	answer, err := promptLine(
		in,
		errOut,
		fmt.Sprintf("secrets, comma-separated or 'none' (%s) [%s]: ", availableLabel, defaultLabel),
	)
	if err != nil {
		return nil, err
	}
	selected := parseSelection(answer, defaults)
	for _, name := range selected {
		if err := secrets.ValidateName(name); err != nil {
			return nil, err
		}
		if !slices.Contains(available, name) {
			return nil, fmt.Errorf(
				"secret %q is not configured; create it with `motte secrets add`",
				name,
			)
		}
	}
	return selected, nil
}

// parseSelection parses a comma-separated prompt answer: empty keeps defaults,
// "none" or "-" clears the list, and otherwise comma-separated items are
// trimmed and deduplicated.
func parseSelection(answer string, defaults []string) []string {
	trimmed := strings.TrimSpace(answer)
	if trimmed == "" {
		return slices.Clone(defaults)
	}
	lower := strings.ToLower(trimmed)
	if lower == "none" || lower == "-" {
		return nil
	}
	var out []string
	for item := range strings.SplitSeq(trimmed, ",") {
		item = strings.TrimSpace(item)
		if item == "" || slices.Contains(out, item) {
			continue
		}
		out = append(out, item)
	}
	return out
}
