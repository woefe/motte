// The `motte secrets` subcommand: manage keychain-backed secrets.
//
// add interactively creates a secret (name, scope, allowed hosts, value);
// set replaces an existing secret's value; configure opens the secret's scope
// file in $VISUAL/$EDITOR and re-validates it; rm deletes it after
// confirmation; ls lists the secrets grouped by scope with keychain presence.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// secretStdin buffers os.Stdin so sequential prompts do not lose input; the
// secrets commands refresh it per subcommand.
var secretStdin = bufio.NewReader(os.Stdin)

// secretsCommand builds the `motte secrets` command tree.
func secretsCommand() *cobra.Command {
	secrets := &cobra.Command{
		Use:   "secrets",
		Short: "manage keychain-backed secrets",
		Long: "Secret values live only in the OS keychain; motte's YAML files hold the\n" +
			"allowed hosts and the header fields of every secret.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printHelp(cmd)
			return exitCoder{code: 1}
		},
	}
	secrets.AddCommand(
		secretsAddCommand(),
		secretsSetCommand(),
		secretsConfigureCommand(),
		secretsRmCommand(),
		secretsLsCommand(),
	)
	return secrets
}

// secretsAddCommand creates a secret interactively.
func secretsAddCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "add",
		Short: "create a secret: prompts for name, scope, hosts, and value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsAdd()
		},
	}
}

// secretsSetCommand replaces an existing secret's value.
func secretsSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set <name>",
		Short: "(re)set an existing secret's value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsSet(args[0])
		},
	}
}

// secretsConfigureCommand opens a secret's config in the user's editor.
func secretsConfigureCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "configure <name>",
		Short: "open the secret's config in $VISUAL/$EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsConfigure(args[0])
		},
	}
}

// secretsRmCommand deletes a secret's config and keychain value.
func secretsRmCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "delete a secret's config and keychain value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsRm(args[0], force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "delete without asking")
	return cmd
}

// secretsLsCommand lists the configured secrets.
func secretsLsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list secrets grouped by scope",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsLs()
		},
	}
}

// runSecretsAdd interactively creates a secret.
func runSecretsAdd() error {
	if !isTerminal(os.Stdin) {
		return fmt.Errorf(
			"motte secrets add is interactive; run it in a terminal, or craft %s/secrets/*.yaml by hand and use `motte secrets set`",
			motteConfigHint(),
		)
	}
	secretStdin = bufio.NewReader(os.Stdin) // fresh buffer per subcommand

	leaf, err := promptLine("secret env var name (e.g. OPENCODE_GO_KEY): ")
	if err != nil {
		return err
	}
	scope, err := promptSecretScope()
	if err != nil {
		return err
	}
	parts := leaf
	if scope != "" {
		parts = scope + "/" + leaf
	}
	name, err := parseSecretName(parts)
	if err != nil {
		return err
	}
	if secretMetaExists(name) {
		return fmt.Errorf(
			"secret %s is already configured; change its value with `motte secrets set %s` or its hosts with `motte secrets configure %s`",
			name.full,
			name.full,
			name.full,
		)
	}

	spec := secretSpec{
		envVar:       name.leaf,
		allow:        defaultAllowCatalog(name.leaf),
		headerFields: defaultHeaderCatalog(name.leaf),
	}
	if spec.headerFields == nil {
		spec.headerFields = defaultSecretHeaderFields
	}
	defaults := "none"
	if len(spec.allow) > 0 {
		defaults = strings.Join(spec.allow, ", ")
	}
	entry, err := promptLine(
		fmt.Sprintf("allowed hosts, comma-separated (exact hosts or *.wildcards) [%s]: ", defaults),
	)
	if err != nil {
		return err
	}
	if entry != "" {
		spec.allow = splitHosts(entry)
	}
	if len(spec.allow) == 0 {
		return fmt.Errorf("at least one allowed host is required")
	}
	for _, host := range spec.allow {
		if err := validateSecretAllowEntry(host); err != nil {
			return err
		}
	}

	value, err := readSecretValue("value (input hidden): ", os.Stdout, os.Stdin)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(value)
	if err := writeSecretMeta(name, spec); err != nil {
		return err
	}
	// The config exists now, so remove it again if the keychain write fails;
	// a launch would otherwise fail with a keychain-less secret.
	if err := defaultSecretStore.set(name.full, value); err != nil {
		_ = removeSecretMeta(name)
		return err
	}
	fmt.Fprintf(os.Stderr, "motte: stored %s (%s); config at %s\n",
		name.full, scopeLabel(name), secretsConfigHint(name))
	return nil
}

// promptSecretScope asks for global, profile, or project scope and returns the
// name prefix: "" for global, a profile name, or the project hash.
func promptSecretScope() (string, error) {
	answer, err := promptLine("scope — [g]lobal, [p]rofile, or [project] for this directory [global]: ")
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "g", "global":
		return "", nil
	case "p", "profile":
		return promptSecretProfile()
	case "j", "proj", "project":
		hash, err := dirHash()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "project hash for the current directory: %s\n", hash)
		return hash, nil
	default:
		return "", fmt.Errorf("%q is not a scope; expected global, profile, or project", answer)
	}
}

// promptSecretProfile prompts for a built-in profile name.
func promptSecretProfile() (string, error) {
	names := availableProfiles()
	answer, err := promptLine(fmt.Sprintf("profile (%s): ", strings.Join(names, ", ")))
	if err != nil {
		return "", err
	}
	profile := strings.TrimSpace(answer)
	if !slices.Contains(names, profile) {
		return "", fmt.Errorf("%q is not a built-in profile (available: %s)", profile, strings.Join(names, ", "))
	}
	return profile, nil
}

// runSecretsSet replaces an existing secret's keychain value.
func runSecretsSet(nameArg string) error {
	name, err := parseSecretName(nameArg)
	if err != nil {
		return err
	}
	if !secretMetaExists(name) {
		return fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.full)
	}
	if _, err := readSecretMeta(name); err != nil {
		return err
	}
	value, err := readSecretValue("value (input hidden): ", os.Stdout, os.Stdin)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(value)
	if err := defaultSecretStore.set(name.full, value); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "motte: set the keychain value for %s\n", name.full)
	return nil
}

// runSecretsConfigure opens a secret config in the user's editor and
// re-validates it afterwards.
func runSecretsConfigure(nameArg string) error {
	name, err := parseSecretName(nameArg)
	if err != nil {
		return err
	}
	if !secretMetaExists(name) {
		return fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.full)
	}
	path, err := scopeKeyOf(name).path()
	if err != nil {
		return err
	}
	if err := runEditor(path); err != nil {
		return err
	}
	if _, err := readSecretMeta(name); err != nil {
		fmt.Fprintf(os.Stderr, "motte: %s is invalid after editing: %v\n", path, err)
		fmt.Fprintf(os.Stderr,
			"motte: fix it with `motte secrets configure %s`, or remove it with `motte secrets rm %s -f`\n",
			name.full, name.full)
		return exitCoder{code: 1}
	}
	if _, err := defaultSecretStore.get(name.full); err != nil {
		fmt.Fprintf(os.Stderr, "motte: warning: %s has no keychain value yet; set it with `motte secrets set %s`\n",
			name.full, name.full)
	}
	fmt.Fprintf(os.Stderr, "motte: %s is valid\n", path)
	return nil
}

// runSecretsRm deletes a secret's config and keychain value after asking.
func runSecretsRm(nameArg string, force bool) error {
	name, err := parseSecretName(nameArg)
	if err != nil {
		return err
	}
	if !secretMetaExists(name) {
		return fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.full)
	}
	confirmed, err := confirmPrompt(fmt.Sprintf("delete %s and its keychain value? [y/N]: ", name.full), force)
	if err != nil {
		return err
	}
	if !confirmed {
		fmt.Fprintln(os.Stderr, "motte: aborted")
		return nil
	}
	if err := defaultSecretStore.delete(name.full); err != nil {
		return err
	}
	if err := removeSecretMeta(name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "motte: removed %s\n", name.full)
	return nil
}

// lsRow is one listed secret with its keychain state or load error.
type lsRow struct {
	scopeKey secretScopeKey
	name     string // the full path-like name of the secret
	spec     secretSpec
	keychain string // "yes", "no", or "?" on a store error
	specErr  error
}

// runSecretsLs lists configured secrets grouped by scope.
func runSecretsLs() error {
	rows, err := collectLsRows()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no secrets configured; create one with `motte secrets add`")
		return nil
	}

	hash, hashErr := dirHash()

	// The rows come grouped by scope already: the global scope, then the
	// profiles, then the projects.
	prev := ""
	for _, row := range rows {
		group := lsGroup(row.scopeKey, hash, hashErr)
		if row.scopeKey.scope == scopeProject && hashErr == nil && row.scopeKey.hash == hash {
			group += " (this directory)"
		}
		if group != prev {
			fmt.Printf("\n%s\n", group)
			prev = group
		}
		state := row.keychain
		hosts := "<unparsable config>"
		if row.specErr == nil {
			hosts = strings.Join(row.spec.allow, ", ")
		}
		fmt.Printf("  %s\tkeychain: %s\tallow: %s\n", row.name, state, hosts)
	}
	fmt.Println()
	warnShadowedLeaves(rows)
	if hashErr == nil {
		fmt.Printf("project hash for the current directory: %s\n", hash)
	}
	return nil
}

// lsGroup renders the scope header of one listing group.
func lsGroup(key secretScopeKey, hash string, hashErr error) string {
	switch key.scope {
	case scopeGlobal:
		return "global:"
	case scopeProfile:
		return fmt.Sprintf("profile %s:", key.profile)
	default:
		if hashErr == nil && key.hash == hash {
			return "project:"
		}
		return fmt.Sprintf("project %s:", key.hash)
	}
}

// collectLsRows gathers the secrets of every scope, leniently listing the
// scopes whose file cannot be read.
func collectLsRows() ([]lsRow, error) {
	keys, err := secretScopeKeys()
	if err != nil {
		return nil, err
	}
	var rows []lsRow
	for _, key := range keys {
		secrets, err := readSecretScope(key)
		if err != nil {
			rows = append(rows, lsRow{scopeKey: key, keychain: "?", specErr: err})
			continue
		}
		for _, envVar := range sortedSecretNames(secrets) {
			spec := secrets[envVar]
			rows = append(rows, lsRow{
				scopeKey: key,
				name:     spec.name,
				spec:     spec,
				keychain: probeKeychain(spec.name),
			})
		}
	}
	return rows, nil
}

// warnShadowedLeaves prints one note per env var defined in several scopes.
func warnShadowedLeaves(rows []lsRow) {
	count := map[string]int{}
	for _, row := range rows {
		if row.specErr == nil {
			count[row.spec.envVar]++
		}
	}
	var leaves []string
	for leaf, n := range count {
		if n <= 1 {
			continue
		}
		leaves = append(leaves, leaf)
	}
	sort.Strings(leaves)
	for _, leaf := range leaves {
		fmt.Printf("note: %s is configured in %d scopes; the most specific wins\n", leaf, count[leaf])
	}
}

// --- prompt helpers ---------------------------------------------------------

// promptLine prints a prompt and reads one line from the terminal.
func promptLine(prompt string) (string, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	line, err := secretStdin.ReadString('\n')
	if line == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading input: %w", err)
		}
		return "", fmt.Errorf("reading input: unexpected end of input")
	}
	return strings.TrimSpace(line), nil
}

// readSecretValue prompts for a secret value without echoing it in a
// terminal; on a non-terminal stdin (a pipe) it reads the whole input as one
// line, never accepting argv values.
func readSecretValue(prompt string, echo io.Writer, in io.Reader) (string, error) {
	if file, ok := in.(*os.File); ok && isTerminal(file) {
		_, _ = fmt.Fprint(echo, prompt)
		value, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(echo)
		if err != nil {
			return "", fmt.Errorf("reading the value: %w", err)
		}
		return string(value), nil
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("reading the value: %w", err)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if strings.Contains(value, "\n") {
		return "", fmt.Errorf("the piped value must be a single line")
	}
	return value, nil
}

// confirmPrompt asks a question on a terminal; force short-circuits it, and a
// non-terminal stdin refuses instead of defaulting to yes.
func confirmPrompt(prompt string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("refusing to proceed without confirmation; rerun with -f in scripts")
	}
	answer, err := promptLine(prompt)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// defaultAllowCatalog returns the egress allow defaults for known secrets.
func defaultAllowCatalog(leaf string) []string {
	if leaf == opencodeSecretName {
		return []string{"*.opencode.ai"}
	}
	return nil
}

// defaultHeaderCatalog returns the header substitution defaults for known
// secrets.
func defaultHeaderCatalog(leaf string) []string {
	if leaf == opencodeSecretName {
		return []string{"authorization", "x-api-key"}
	}
	return nil
}

// splitHosts splits a comma-separated host list.
func splitHosts(entry string) []string {
	var hosts []string
	for _, host := range strings.Split(entry, ",") {
		if host = strings.TrimSpace(host); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// warnLargeValue warns when a value nears the size limits of keyring backends
// (macOS items hold about 4 KiB; Windows Credential Manager about 2560 bytes).
func warnLargeValue(value string) {
	if len(value) > 2560 {
		fmt.Fprintf(
			os.Stderr,
			"motte: warning: the value is %d bytes; system keyring backends have small item limits (~4 KiB on macOS, ~2560 bytes on Windows)\n",
			len(value),
		)
	}
}

// scopeLabel renders a secret's scope for one-line notices.
func scopeLabel(n secretName) string {
	return scopeKeyOf(n).label()
}

// runEditor opens path in $VISUAL/$EDITOR, or nano/vi, attached to the
// terminal. Editors configured with arguments go through the shell.
func runEditor(path string) error {
	editor := strings.TrimSpace(os.Getenv("VISUAL"))
	if editor == "" {
		editor = strings.TrimSpace(os.Getenv("EDITOR"))
	}
	if editor == "" {
		editor = "nano"
		if _, err := exec.LookPath("nano"); err != nil {
			if _, viErr := exec.LookPath("vi"); viErr != nil {
				return fmt.Errorf("no editor found; set $VISUAL or $EDITOR")
			}
			editor = "vi"
		}
	}
	var cmd *exec.Cmd
	if strings.ContainsAny(editor, " \t") {
		cmd = exec.Command("sh", "-c", editor+` "$1"`, "editor", path)
	} else {
		cmd = exec.Command(editor, path)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q on %s: %w", editor, path, err)
	}
	return nil
}

// motteConfigHint names the user config dir in error messages.
func motteConfigHint() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "motte")
	}
	return filepath.Join("<user config dir>", "motte")
}

// secretsConfigHint names a secret's scope file for interactive messages.
func secretsConfigHint(n secretName) string {
	if path, err := scopeKeyOf(n).path(); err == nil {
		return path
	}
	return n.full
}
