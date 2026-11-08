// The `motte secrets` subcommand: manage keychain-backed secrets.
//
// add interactively creates or changes a secret (name, allowed hosts, value);
// set replaces an existing secret's value; configure opens a secret's settings
// file in $VISUAL/$EDITOR and re-validates it; rm deletes a secret after
// confirmation; ls lists the secrets with keychain presence.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/woefe/motte/internal/config"
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
		Short: "create or change a secret; prompts for name, hosts, and value",
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
		Short: "(re)set a secret's keychain value",
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsSet(cmd.InOrStdin(), cmd.ErrOrStderr(), store, args[0])
		},
	}
}

// secretsConfigureCommand opens a secret's settings file in the editor.
func secretsConfigureCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "configure <name>",
		Short: "create or edit one secret's settings in $VISUAL/$EDITOR",
		Long:  "The name must be a valid environment variable name.",
		Args:  singleArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsConfigure(cmd.ErrOrStderr(), args[0])
		},
	}
}

// secretsRmCommand deletes a secret's settings file and keychain value.
func secretsRmCommand(store secrets.Store) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "delete a secret's settings file and keychain value",
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
		Short: "list the secrets with keychain presence",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretsLs(cmd.OutOrStdout(), cmd.ErrOrStderr(), store)
		},
	}
}

// configureHintErr appends the configure command that repairs a secret file.
func configureHintErr(name string, err error) error {
	return fmt.Errorf("%w; fix it with `motte secrets configure %s`", err, name)
}

// runSecretsAdd interactively creates or changes a secret.
func runSecretsAdd(cmd *cobra.Command, store secrets.Store) error {
	in := cmd.InOrStdin()
	if !isTerminalReader(in) {
		return fmt.Errorf(
			"motte secrets add is interactive; run it in a terminal, or craft %s/secrets/<NAME>.yaml by hand and use `motte secrets set`",
			config.Hint(),
		)
	}
	return addSecret(bufio.NewReader(in), in, cmd.ErrOrStderr(), store)
}

// addSecret runs the interactive flow: prompts read from in, the value from
// valueIn, and notices go to errOut. A configured name keeps its settings as
// prompt defaults and only replaces the keychain value on request.
func addSecret(in *bufio.Reader, valueIn io.Reader, errOut io.Writer, store secrets.Store) error {
	name, err := promptLine(in, errOut, "secret env var name (e.g. EXAMPLE_API_KEY): ")
	if err != nil {
		return err
	}
	if err := secrets.ValidateName(name); err != nil {
		return err
	}
	spec, err := secrets.Read(name)
	exists := err == nil
	if err != nil {
		if !errors.Is(err, secrets.ErrNotFound) {
			return configureHintErr(name, err)
		}
		spec = secrets.Spec{
			Name:         name,
			EnvVar:       name,
			HeaderFields: secrets.DefaultHeaderFields,
		}
	}
	defaults := "none"
	if len(spec.Allow) > 0 {
		defaults = strings.Join(spec.Allow, ", ")
	}
	entry, err := promptLine(
		in,
		errOut,
		fmt.Sprintf("allowed hosts, comma-separated (exact hosts, *.wildcards, or *) [%s]: ", defaults),
	)
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
		if _, getErr := store.Get(name); getErr == nil {
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
		if err := store.Set(name, value); err != nil {
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
	_, _ = fmt.Fprintf(errOut, "motte: %s %s; config at %s\n", verb, name, secretsConfigHint(name))
	return nil
}

// runSecretsSet replaces an existing secret's keychain value.
func runSecretsSet(in io.Reader, errOut io.Writer, store secrets.Store, name string) error {
	if err := secrets.ValidateName(name); err != nil {
		return err
	}
	if _, err := secrets.Read(name); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name)
		}
		return configureHintErr(name, err)
	}
	value, err := readSecretValue("value (input hidden): ", errOut, in)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(errOut, value)
	if err := store.Set(name, value); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "motte: set the keychain value for %s\n", name)
	return nil
}

// runSecretsConfigure opens a secret's settings file in the editor, creating
// it from the template when missing, and re-validates it afterwards.
func runSecretsConfigure(errOut io.Writer, name string) error {
	path, err := secrets.Path(name)
	if err != nil {
		return err
	}
	return config.ConfigureFile(config.EditableFile{
		Path:   path,
		FixCmd: fmt.Sprintf("motte secrets configure %s", name),
		ErrOut: errOut,
		Template: func() (string, error) {
			return secrets.Template(name)
		},
		Read: func() error {
			_, err := secrets.ReadFile(path, name)
			return err
		},
	})
}

// runSecretsRm deletes a secret's settings file and keychain value after
// asking.
func runSecretsRm(in io.Reader, errOut io.Writer, store secrets.Store, name string, force bool) error {
	if err := secrets.ValidateName(name); err != nil {
		return err
	}
	if _, err := secrets.Read(name); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return fmt.Errorf("secret %s is not configured", name)
		}
		return configureHintErr(name, err)
	}
	if !force && !isTerminalReader(in) {
		return fmt.Errorf("refusing to proceed without confirmation; rerun with -f in scripts")
	}
	confirmed, err := confirmPrompt(
		bufio.NewReader(in),
		errOut,
		fmt.Sprintf("delete %s and its keychain value? [y/N]: ", name),
		force,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		_, _ = fmt.Fprintln(errOut, "motte: aborted")
		return nil
	}
	if err := store.Delete(name); err != nil {
		return err
	}
	if err := secrets.RemoveMeta(name); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "motte: removed %s\n", name)
	return nil
}

// lsRow is one listed secret with its keychain state or read error.
type lsRow struct {
	name     string
	spec     secrets.Spec
	keychain string
	err      error
}

// runSecretsLs lists the configured secrets with keychain presence and the
// allowed hosts.
func runSecretsLs(out, errOut io.Writer, store secrets.Store) error {
	names, err := secrets.ListNames()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		_, _ = fmt.Fprintln(errOut, "no secrets configured; create one with `motte secrets add`")
		return nil
	}
	width := 0
	rows := make([]lsRow, 0, len(names))
	for _, name := range names {
		if len(name) > width {
			width = len(name)
		}
		path, pathErr := secrets.Path(name)
		var spec secrets.Spec
		var readErr error
		if pathErr != nil {
			readErr = pathErr
		} else {
			spec, readErr = secrets.ReadFile(path, name)
		}
		if readErr != nil {
			rows = append(rows, lsRow{name: name, err: readErr})
			continue
		}
		rows = append(rows, lsRow{
			name:     name,
			spec:     spec,
			keychain: secrets.ProbeKeychain(store, name),
		})
	}
	for _, row := range rows {
		if row.err != nil {
			_, _ = fmt.Fprintf(out, "%-*s  <unreadable: %v>\n", width, row.name, row.err)
			continue
		}
		_, _ = fmt.Fprintf(out, "%-*s  keychain: %s  allow: %s\n",
			width, row.name, row.keychain, strings.Join(row.spec.Allow, ", "))
	}
	return nil
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

// secretsConfigHint names a secret's settings file for interactive messages.
func secretsConfigHint(name string) string {
	if path, err := secrets.Path(name); err == nil {
		return path
	}
	return name
}
