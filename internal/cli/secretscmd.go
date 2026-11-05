// The `motte secrets` subcommand: manage keychain-backed secrets.
//
// add interactively creates or changes a secret (name, scope, allowed hosts,
// value); set replaces an existing secret's value; configure opens a scope's
// file in $VISUAL/$EDITOR and re-validates it; rm deletes a secret after
// confirmation; ls lists the secrets grouped by scope with keychain presence.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/profile"
	"github.com/woefe/motte/internal/secrets"
	"golang.org/x/term"
)

// secretsCommand builds the `motte secrets` command tree.
func secretsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "secrets",
		Short: "manage keychain-backed secrets",
		Long: "Secret values live only in the OS keychain; motte's YAML files hold the\n" +
			"allowed hosts and the header fields of every secret.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printHelp(cmd)
			return exitCoder{code: 1}
		},
	}
	command.AddCommand(
		secretsAddCommand(),
		secretsSetCommand(),
		secretsConfigureCommand(),
		secretsRmCommand(),
		secretsLsCommand(),
	)
	return command
}

// secretsAddCommand creates or changes a secret interactively.
func secretsAddCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "add",
		Short: "create or change a secret: prompts for name, scope, hosts, and value",
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
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsSet(args[0])
		},
	}
}

// secretsConfigureCommand opens a scope's secrets file in the editor.
func secretsConfigureCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "configure <scope>",
		Short: "open a scope's secrets file in $VISUAL/$EDITOR",
		Long:  "The scope is global, project, a built-in profile name, or a project hash.",
		Args:  singleArg,
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
		Args:  singleArg,
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
		Short: "list the configured secrets grouped by scope, with keychain presence",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsLs()
		},
	}
}

// configureHintErr appends the configure command that repairs a scope file.
func configureHintErr(key secrets.ScopeKey, err error) error {
	return fmt.Errorf("%w; fix it with `motte secrets configure %s`", err, key.ConfigureArg())
}

// runSecretsAdd interactively creates or changes a secret.
func runSecretsAdd() error {
	if !isTerminal(os.Stdin) {
		return fmt.Errorf(
			"motte secrets add is interactive; run it in a terminal, or craft %s/secrets/*.yaml by hand and use `motte secrets set`",
			config.Hint(),
		)
	}
	return addSecret(bufio.NewReader(os.Stdin), os.Stdin)
}

// addSecret runs the interactive flow: prompts read from in, the value from
// valueIn. A configured name keeps its settings as prompt defaults and only
// replaces the keychain value on request.
func addSecret(in *bufio.Reader, valueIn io.Reader) error {
	leaf, err := promptLine(in, "secret env var name (e.g. EXAMPLE_API_KEY): ")
	if err != nil {
		return err
	}
	scope, err := promptSecretScope(in)
	if err != nil {
		return err
	}
	parts := leaf
	if scope != "" {
		parts = scope + "/" + leaf
	}
	name, err := secrets.ParseName(parts)
	if err != nil {
		return err
	}
	key := secrets.ScopeKeyOf(name)
	configured, err := secrets.ReadScope(key)
	if err != nil {
		return configureHintErr(key, err)
	}
	spec, exists := configured[name.Leaf]
	if !exists {
		spec = secrets.Spec{
			EnvVar:       name.Leaf,
			HeaderFields: secrets.DefaultHeaderFields,
		}
	}
	defaults := "none"
	if len(spec.Allow) > 0 {
		defaults = strings.Join(spec.Allow, ", ")
	}
	entry, err := promptLine(in,
		fmt.Sprintf("allowed hosts, comma-separated (exact hosts or *.wildcards) [%s]: ", defaults))
	if err != nil {
		return err
	}
	if entry != "" {
		spec.Allow = splitHosts(entry)
	}
	if len(spec.Allow) == 0 {
		return fmt.Errorf("at least one allowed host is required")
	}
	for _, host := range spec.Allow {
		if err := secrets.ValidateAllowEntry(host); err != nil {
			return err
		}
	}

	replaceValue := true
	if exists {
		if _, getErr := secrets.DefaultStore.Get(name.Full); getErr == nil {
			replaceValue, err = confirmPrompt(in, "replace the keychain value? [y/N]: ", false)
			if err != nil {
				return err
			}
		}
	}
	if replaceValue {
		value, err := readSecretValue("value (input hidden): ", os.Stdout, valueIn)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("an empty value is not a secret; aborting")
		}
		warnLargeValue(value)
		if err := secrets.DefaultStore.Set(name.Full, value); err != nil {
			return err
		}
	}
	if err := secrets.WriteMeta(name, spec); err != nil {
		return err
	}
	verb := "updated"
	if replaceValue {
		verb = "stored"
	}
	fmt.Fprintf(os.Stderr, "motte: %s %s (%s); config at %s\n",
		verb, name.Full, scopeLabel(name), secretsConfigHint(name))
	return nil
}

// promptSecretScope asks for global, profile, or project scope and returns the
// name prefix: "" for global, a profile name, or the project hash.
func promptSecretScope(in *bufio.Reader) (string, error) {
	answer, err := promptLine(in, "scope — [g]lobal, [p]rofile, or [project] for this directory [global]: ")
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "g", "global":
		return "", nil
	case "p", "profile":
		return promptSecretProfile(in)
	case "j", "proj", "project":
		hash, err := config.DirHash()
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
func promptSecretProfile(in *bufio.Reader) (string, error) {
	names := profile.Available()
	answer, err := promptLine(in, fmt.Sprintf("profile (%s): ", strings.Join(names, ", ")))
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(answer)
	if !slices.Contains(names, name) {
		return "", fmt.Errorf("%q is not a built-in profile (available: %s)", name, strings.Join(names, ", "))
	}
	return name, nil
}

// runSecretsSet replaces an existing secret's keychain value.
func runSecretsSet(nameArg string) error {
	name, err := secrets.ParseName(nameArg)
	if err != nil {
		return err
	}
	key := secrets.ScopeKeyOf(name)
	configured, err := secrets.ReadScope(key)
	if err != nil {
		return configureHintErr(key, err)
	}
	if _, ok := configured[name.Leaf]; !ok {
		return fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.Full)
	}
	value, err := readSecretValue("value (input hidden): ", os.Stdout, os.Stdin)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(value)
	if err := secrets.DefaultStore.Set(name.Full, value); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "motte: set the keychain value for %s\n", name.Full)
	return nil
}

// runSecretsConfigure opens a scope's secrets file in the editor, creating it
// from the template when missing, and re-validates it afterwards.
func runSecretsConfigure(scope string) error {
	arg, err := config.ResolveScopeArg(scope)
	if err != nil {
		return err
	}
	key := secrets.ScopeKeyFromArg(arg)
	path, err := key.Path()
	if err != nil {
		return err
	}
	return config.ConfigureScope(config.ScopeFile{
		Path:   path,
		FixCmd: fmt.Sprintf("motte secrets configure %s", scope),
		Template: func() (string, error) {
			return secrets.Template(key)
		},
		Read: func() error {
			_, err := secrets.ReadScope(key)
			return err
		},
	})
}

// runSecretsRm deletes a secret's config and keychain value after asking.
func runSecretsRm(nameArg string, force bool) error {
	name, err := secrets.ParseName(nameArg)
	if err != nil {
		return err
	}
	key := secrets.ScopeKeyOf(name)
	configured, err := secrets.ReadScope(key)
	if err != nil {
		return configureHintErr(key, err)
	}
	if _, ok := configured[name.Leaf]; !ok {
		return fmt.Errorf("secret %s is not configured", name.Full)
	}
	if !force && !isTerminal(os.Stdin) {
		return fmt.Errorf("refusing to proceed without confirmation; rerun with -f in scripts")
	}
	confirmed, err := confirmPrompt(bufio.NewReader(os.Stdin),
		fmt.Sprintf("delete %s and its keychain value? [y/N]: ", name.Full), force)
	if err != nil {
		return err
	}
	if !confirmed {
		fmt.Fprintln(os.Stderr, "motte: aborted")
		return nil
	}
	if err := secrets.DefaultStore.Delete(name.Full); err != nil {
		return err
	}
	if err := secrets.RemoveMeta(name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "motte: removed %s\n", name.Full)
	return nil
}

// lsRow is one listed secret with its keychain state.
type lsRow struct {
	name     string // the full path-like name of the secret
	spec     secrets.Spec
	keychain string // "yes", "no", or "?" on a store error
}

// runSecretsLs lists the secrets of the existing scope files, grouped by
// scope, with keychain presence and the allowed hosts.
func runSecretsLs() error {
	root, err := config.SecretsDir()
	if err != nil {
		return err
	}
	scopes, err := config.LsScopes(root)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		fmt.Fprintln(os.Stderr, "no secrets configured; create one with `motte secrets add`")
		return nil
	}
	hash, hashErr := config.DirHash()
	var rows []lsRow
	for i, scope := range scopes {
		if i > 0 {
			fmt.Println()
		}
		key := secrets.ScopeKeyFromArg(scope)
		thisDir := hashErr == nil && scope.Hash != "" && scope.Hash == hash
		fmt.Printf("%s:\n", config.LabelScope(scope.Profile, scope.Hash, thisDir))
		configured, err := secrets.ReadScope(key)
		if err != nil {
			fmt.Printf("  <unreadable: %v>\n", err)
			continue
		}
		var group []lsRow
		for _, envVar := range secrets.SortedNames(configured) {
			spec := configured[envVar]
			group = append(group, lsRow{
				name:     spec.Name,
				spec:     spec,
				keychain: secrets.ProbeKeychain(spec.Name),
			})
		}
		if len(group) == 0 {
			fmt.Printf("  (no secrets)\n")
			continue
		}
		rows = append(rows, group...)
		printLsGroup(group)
	}
	if notes := shadowNotes(rows); len(notes) > 0 {
		fmt.Println()
		for _, note := range notes {
			fmt.Println(note)
		}
	}
	return nil
}

// printLsGroup prints one scope's secrets as a table aligned by name.
func printLsGroup(group []lsRow) {
	width := 0
	for _, row := range group {
		if len(row.name) > width {
			width = len(row.name)
		}
	}
	for _, row := range group {
		fmt.Printf("  %-*s  keychain: %s  allow: %s\n",
			width, row.name, row.keychain, strings.Join(row.spec.Allow, ", "))
	}
}

// shadowNotes returns one note per env var configured in several scopes; the
// most specific scope wins.
func shadowNotes(rows []lsRow) []string {
	count := map[string]int{}
	for _, row := range rows {
		count[row.spec.EnvVar]++
	}
	var leaves []string
	for leaf, n := range count {
		if n > 1 {
			leaves = append(leaves, leaf)
		}
	}
	sort.Strings(leaves)
	notes := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		notes = append(notes, fmt.Sprintf(
			"note: %s is configured in %d scopes; the most specific wins", leaf, count[leaf]))
	}
	return notes
}

// --- prompt helpers ---------------------------------------------------------

// promptLine prints a prompt and reads one line from in.
func promptLine(in *bufio.Reader, prompt string) (string, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	line, err := in.ReadString('\n')
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

// confirmPrompt asks a yes-no question; force short-circuits it.
func confirmPrompt(in *bufio.Reader, prompt string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	answer, err := promptLine(in, prompt)
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

// splitHosts splits a comma-separated host list.
func splitHosts(entry string) []string {
	var hosts []string
	for host := range strings.SplitSeq(entry, ",") {
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
func scopeLabel(n secrets.Name) string {
	key := secrets.ScopeKeyOf(n)
	return config.LabelScope(key.Profile, key.Hash, false)
}

// secretsConfigHint names a secret's scope file for interactive messages.
func secretsConfigHint(n secrets.Name) string {
	if path, err := secrets.ScopeKeyOf(n).Path(); err == nil {
		return path
	}
	return n.Full
}
