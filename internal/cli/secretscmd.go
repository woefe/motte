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
func secretsCommand(store secrets.Store) *cobra.Command {
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
		secretsAddCommand(store),
		secretsSetCommand(store),
		secretsConfigureCommand(),
		secretsRmCommand(store),
		secretsLsCommand(store),
	)
	return command
}

// secretsAddCommand creates or changes a secret interactively.
func secretsAddCommand(store secrets.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "add",
		Short: "create or change a secret: prompts for name, scope, hosts, and value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsAdd(cmd, store)
		},
	}
}

// secretsSetCommand replaces an existing secret's value.
func secretsSetCommand(store secrets.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "set <name>",
		Short: "(re)set an existing secret's value",
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsSet(cmd.InOrStdin(), cmd.ErrOrStderr(), store, args[0])
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
			return runSecretsConfigure(cmd.ErrOrStderr(), args[0])
		},
	}
}

// secretsRmCommand deletes a secret's config and keychain value.
func secretsRmCommand(store secrets.Store) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "delete a secret's config and keychain value",
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsRm(cmd.InOrStdin(), cmd.ErrOrStderr(), store, args[0], force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "delete without asking")
	return cmd
}

// secretsLsCommand lists the configured secrets.
func secretsLsCommand(store secrets.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list the configured secrets grouped by scope, with keychain presence",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsLs(cmd.OutOrStdout(), cmd.ErrOrStderr(), store)
		},
	}
}

// configureHintErr appends the configure command that repairs a scope file.
func configureHintErr(scope config.Scope, err error) error {
	return fmt.Errorf("%w; fix it with `motte secrets configure %s`", err, scope.ConfigureArg())
}

// runSecretsAdd interactively creates or changes a secret.
func runSecretsAdd(cmd *cobra.Command, store secrets.Store) error {
	in := cmd.InOrStdin()
	if !isTerminalReader(in) {
		return fmt.Errorf(
			"motte secrets add is interactive; run it in a terminal, or craft %s/secrets/*.yaml by hand and use `motte secrets set`",
			config.Hint(),
		)
	}
	return addSecret(bufio.NewReader(in), in, cmd.ErrOrStderr(), store)
}

// addSecret runs the interactive flow: prompts read from in, the value from
// valueIn, and notices go to errOut. A configured name keeps its settings as
// prompt defaults and only replaces the keychain value on request.
func addSecret(in *bufio.Reader, valueIn io.Reader, errOut io.Writer, store secrets.Store) error {
	leaf, err := promptLine(in, errOut, "secret env var name (e.g. EXAMPLE_API_KEY): ")
	if err != nil {
		return err
	}
	scope, err := promptSecretScope(in, errOut)
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
	configured, err := secrets.ReadScope(name.Scope)
	if err != nil {
		return configureHintErr(name.Scope, err)
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
	entry, err := promptLine(in, errOut,
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
		if _, getErr := store.Get(name.Full); getErr == nil {
			replaceValue, err = confirmPrompt(in, errOut, "replace the keychain value? [y/N]: ", false)
			if err != nil {
				return err
			}
		}
	}
	if replaceValue {
		value, err := readSecretValue("value (input hidden): ", errOut, valueIn)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("an empty value is not a secret; aborting")
		}
		warnLargeValue(errOut, value)
		if err := store.Set(name.Full, value); err != nil {
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
	_, _ = fmt.Fprintf(errOut, "motte: %s %s (%s); config at %s\n",
		verb, name.Full, name.Scope.Label(false), secretsConfigHint(name))
	return nil
}

// promptSecretScope asks for global, profile, or project scope and returns the
// name prefix: "" for global, a profile name, or the project hash.
func promptSecretScope(in *bufio.Reader, errOut io.Writer) (string, error) {
	answer, err := promptLine(in, errOut, "scope — [g]lobal, [p]rofile, or [project] for this directory [global]: ")
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "g", "global":
		return "", nil
	case "p", "profile":
		return promptSecretProfile(in, errOut)
	case "j", "proj", "project":
		hash, err := config.DirHash()
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(errOut, "project hash for the current directory: %s\n", hash)
		return hash, nil
	default:
		return "", fmt.Errorf("%q is not a scope; expected global, profile, or project", answer)
	}
}

// promptSecretProfile prompts for a built-in profile name.
func promptSecretProfile(in *bufio.Reader, errOut io.Writer) (string, error) {
	names := profile.Available()
	answer, err := promptLine(in, errOut, fmt.Sprintf("profile (%s): ", strings.Join(names, ", ")))
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
func runSecretsSet(in io.Reader, errOut io.Writer, store secrets.Store, nameArg string) error {
	name, err := secrets.ParseName(nameArg)
	if err != nil {
		return err
	}
	configured, err := secrets.ReadScope(name.Scope)
	if err != nil {
		return configureHintErr(name.Scope, err)
	}
	if _, ok := configured[name.Leaf]; !ok {
		return fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.Full)
	}
	value, err := readSecretValue("value (input hidden): ", errOut, in)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(errOut, value)
	if err := store.Set(name.Full, value); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "motte: set the keychain value for %s\n", name.Full)
	return nil
}

// runSecretsConfigure opens a scope's secrets file in the editor, creating it
// from the template when missing, and re-validates it afterwards.
func runSecretsConfigure(errOut io.Writer, scopeArg string) error {
	scope, err := config.ResolveScope(scopeArg)
	if err != nil {
		return err
	}
	path, err := secrets.ScopePath(scope)
	if err != nil {
		return err
	}
	return config.ConfigureScope(config.ScopeFile{
		Path:   path,
		FixCmd: fmt.Sprintf("motte secrets configure %s", scopeArg),
		ErrOut: errOut,
		Template: func() (string, error) {
			return secrets.Template(scope)
		},
		Read: func() error {
			_, err := secrets.ReadScope(scope)
			return err
		},
	})
}

// runSecretsRm deletes a secret's config and keychain value after asking.
func runSecretsRm(in io.Reader, errOut io.Writer, store secrets.Store, nameArg string, force bool) error {
	name, err := secrets.ParseName(nameArg)
	if err != nil {
		return err
	}
	configured, err := secrets.ReadScope(name.Scope)
	if err != nil {
		return configureHintErr(name.Scope, err)
	}
	if _, ok := configured[name.Leaf]; !ok {
		return fmt.Errorf("secret %s is not configured", name.Full)
	}
	if !force && !isTerminalReader(in) {
		return fmt.Errorf("refusing to proceed without confirmation; rerun with -f in scripts")
	}
	confirmed, err := confirmPrompt(bufio.NewReader(in), errOut,
		fmt.Sprintf("delete %s and its keychain value? [y/N]: ", name.Full), force)
	if err != nil {
		return err
	}
	if !confirmed {
		_, _ = fmt.Fprintln(errOut, "motte: aborted")
		return nil
	}
	if err := store.Delete(name.Full); err != nil {
		return err
	}
	if err := secrets.RemoveMeta(name); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "motte: removed %s\n", name.Full)
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
func runSecretsLs(out, errOut io.Writer, store secrets.Store) error {
	root, err := config.SecretsDir()
	if err != nil {
		return err
	}
	scopes, err := config.LsScopes(root)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		_, _ = fmt.Fprintln(errOut, "no secrets configured; create one with `motte secrets add`")
		return nil
	}
	hash, hashErr := config.DirHash()
	var rows []lsRow
	for i, scope := range scopes {
		if i > 0 {
			_, _ = fmt.Fprintln(out)
		}
		thisDir := hashErr == nil && scope.Hash != "" && scope.Hash == hash
		_, _ = fmt.Fprintf(out, "%s:\n", scope.Label(thisDir))
		configured, err := secrets.ReadScope(scope)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  <unreadable: %v>\n", err)
			continue
		}
		var group []lsRow
		for _, envVar := range secrets.SortedNames(configured) {
			spec := configured[envVar]
			group = append(group, lsRow{
				name:     spec.Name,
				spec:     spec,
				keychain: secrets.ProbeKeychain(store, spec.Name),
			})
		}
		if len(group) == 0 {
			_, _ = fmt.Fprintf(out, "  (no secrets)\n")
			continue
		}
		rows = append(rows, group...)
		printLsGroup(out, group)
	}
	if notes := shadowNotes(rows); len(notes) > 0 {
		_, _ = fmt.Fprintln(out)
		for _, note := range notes {
			_, _ = fmt.Fprintln(out, note)
		}
	}
	return nil
}

// printLsGroup prints one scope's secrets as a table aligned by name.
func printLsGroup(out io.Writer, group []lsRow) {
	width := 0
	for _, row := range group {
		if len(row.name) > width {
			width = len(row.name)
		}
	}
	for _, row := range group {
		_, _ = fmt.Fprintf(out, "  %-*s  keychain: %s  allow: %s\n",
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
func promptLine(in *bufio.Reader, errOut io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(errOut, prompt)
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
func confirmPrompt(in *bufio.Reader, errOut io.Writer, prompt string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	answer, err := promptLine(in, errOut, prompt)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// isTerminalReader reports whether r is an interactive terminal file.
func isTerminalReader(r io.Reader) bool {
	file, ok := r.(*os.File)
	return ok && isTerminal(file)
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
func warnLargeValue(errOut io.Writer, value string) {
	if len(value) > 2560 {
		_, _ = fmt.Fprintf(
			errOut,
			"motte: warning: the value is %d bytes; system keyring backends have small item limits (~4 KiB on macOS, ~2560 bytes on Windows)\n",
			len(value),
		)
	}
}

// secretsConfigHint names a secret's scope file for interactive messages.
func secretsConfigHint(n secrets.Name) string {
	if path, err := secrets.ScopePath(n.Scope); err == nil {
		return path
	}
	return n.Full
}
