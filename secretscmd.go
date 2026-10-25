// The `motte secrets` subcommand: manage keychain-backed secrets.
//
// add interactively creates a secret (name, scope, allowed hosts, value);
// set replaces an existing secret's value; configure opens the secret's YAML
// config in $VISUAL/$EDITOR and re-validates it; rm deletes it after
// confirmation; ls lists configs grouped by scope with keychain presence; mv
// moves a secret's config and re-keys its keychain entry.
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

	"golang.org/x/term"
)

// secretsUsage is the help text of `motte secrets`.
const secretsUsage = `manage keychain-backed secrets

  motte secrets add               create a secret: prompts for name, scope, hosts, and value
  motte secrets set <name>        (re)set an existing secret's value (reads stdin when piped)
  motte secrets configure <name>  open the secret's config in $VISUAL/$EDITOR
  motte secrets rm <name> [-f]    delete a secret's config and keychain value
  motte secrets ls                list secrets grouped by scope
  motte secrets mv <old> <new>    rename a secret, moving config and keychain value

Names are path-like: NAME, <profile>/NAME, or <profile>/<dir-hash>/NAME for
project scope. Values are stored only in the OS keychain, never on disk.`

// secretStdin buffers os.Stdin so sequential prompts do not lose input; run
// secrets refreshes it per subcommand.
var secretStdin = bufio.NewReader(os.Stdin)

// runSecrets dispatches the secrets subcommand tree.
func runSecrets(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, secretsUsage)
		return 1
	}
	secretStdin = bufio.NewReader(os.Stdin) // fresh buffer per subcommand
	cmd, rest := args[0], args[1:]
	var exit int
	var subErr error
	switch cmd {
	case "add":
		exit, subErr = cmdSecretsAdd(rest)
	case "set":
		exit, subErr = cmdSecretsSet(rest)
	case "configure":
		exit, subErr = cmdSecretsConfigure(rest)
	case "rm":
		exit, subErr = cmdSecretsRm(rest)
	case "ls":
		exit, subErr = cmdSecretsLs(rest)
	case "mv":
		exit, subErr = cmdSecretsMv(rest)
	default:
		exit, subErr = 1, fmt.Errorf("unknown secrets command %q; expected add|set|configure|rm|ls|mv", cmd)
	}
	if subErr != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", subErr)
		return 1
	}
	return exit
}

// cmdSecretsAdd interactively creates a secret.
func cmdSecretsAdd(args []string) (int, error) {
	if len(args) != 0 {
		return 1, fmt.Errorf("motte secrets add takes no arguments; it is interactive")
	}
	if !isTerminal(os.Stdin) {
		return 1, fmt.Errorf(
			"motte secrets add is interactive; run it in a terminal, or craft %s/secrets/*.yaml by hand and use `motte secrets set`",
			motteConfigHint(),
		)
	}
	secretStdin = bufio.NewReader(os.Stdin) // fresh buffer per subcommand

	leaf, err := promptLine("secret env var name (e.g. OPENCODE_GO_KEY): ")
	if err != nil {
		return 1, err
	}
	scope, err := promptSecretScope()
	if err != nil {
		return 1, err
	}
	parts := leaf
	if scope != "" {
		parts = scope + "/" + leaf
	}
	name, err := parseSecretName(parts)
	if err != nil {
		return 1, err
	}
	if secretMetaExists(name) {
		return 1, fmt.Errorf(
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
		return 1, err
	}
	if entry != "" {
		spec.allow = splitHosts(entry)
	}
	if len(spec.allow) == 0 {
		return 1, fmt.Errorf("at least one allowed host is required")
	}
	for _, host := range spec.allow {
		if err := validateSecretAllowEntry(host); err != nil {
			return 1, err
		}
	}

	value, err := readSecretValue("value (input hidden): ", os.Stdout, os.Stdin)
	if err != nil {
		return 1, err
	}
	if value == "" {
		return 1, fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(value)
	if err := writeSecretMeta(name, spec); err != nil {
		return 1, err
	}
	// The config exists now, so remove it again if the keychain write fails;
	// a launch would otherwise fail with a keychain-less secret.
	if err := defaultSecretStore.set(name.full, value); err != nil {
		_ = removeSecretMeta(name)
		return 1, err
	}
	fmt.Fprintf(os.Stderr, "motte: stored %s (%s); config at %s\n",
		name.full, scopeLabel(name), secretsConfigHint(name))
	return 0, nil
}

// promptSecretScope asks for global, profile, or project scope and returns the
// name prefix: "" for global, a profile name, or profile/hash for project.
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
		profile, err := promptSecretProfile()
		if err != nil {
			return "", err
		}
		hash, err := dirHash()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "project hash for the current directory: %s\n", hash)
		return profile + "/" + hash, nil
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

// cmdSecretsSet replaces an existing secret's keychain value.
func cmdSecretsSet(args []string) (int, error) {
	if len(args) != 1 {
		return 1, fmt.Errorf("motte secrets set <name>")
	}
	name, err := parseSecretName(args[0])
	if err != nil {
		return 1, err
	}
	if !secretMetaExists(name) {
		return 1, fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.full)
	}
	if _, err := readSecretMeta(name); err != nil {
		return 1, err
	}
	value, err := readSecretValue("value (input hidden): ", os.Stdout, os.Stdin)
	if err != nil {
		return 1, err
	}
	if value == "" {
		return 1, fmt.Errorf("an empty value is not a secret; aborting")
	}
	warnLargeValue(value)
	if err := defaultSecretStore.set(name.full, value); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stderr, "motte: set the keychain value for %s\n", name.full)
	return 0, nil
}

// cmdSecretsConfigure opens a secret config in the user's editor and
// re-validates it afterwards.
func cmdSecretsConfigure(args []string) (int, error) {
	if len(args) != 1 {
		return 1, fmt.Errorf("motte secrets configure <name>")
	}
	name, err := parseSecretName(args[0])
	if err != nil {
		return 1, err
	}
	if !secretMetaExists(name) {
		return 1, fmt.Errorf("secret %s is not configured; create it with `motte secrets add`", name.full)
	}
	path, err := secretConfigPath(name)
	if err != nil {
		return 1, err
	}
	if err := runEditor(path); err != nil {
		return 1, err
	}
	if _, err := readSecretMeta(name); err != nil {
		fmt.Fprintf(os.Stderr, "motte: %s is invalid after editing: %v\n", path, err)
		fmt.Fprintf(os.Stderr,
			"motte: fix it with `motte secrets configure %s`, or remove it with `motte secrets rm %s -f`\n",
			name.full, name.full)
		return 1, nil
	}
	if _, err := defaultSecretStore.get(name.full); err != nil {
		fmt.Fprintf(os.Stderr, "motte: warning: %s has no keychain value yet; set it with `motte secrets set %s`\n",
			name.full, name.full)
	}
	fmt.Fprintf(os.Stderr, "motte: %s is valid\n", path)
	return 0, nil
}

// cmdSecretsRm deletes a secret's config and keychain value after asking.
func cmdSecretsRm(args []string) (int, error) {
	var force bool
	var positional []string
	for _, arg := range args {
		switch arg {
		case "-f", "--force":
			force = true
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return 1, fmt.Errorf("motte secrets rm <name> [-f]")
	}
	name, err := parseSecretName(positional[0])
	if err != nil {
		return 1, err
	}
	if !secretMetaExists(name) {
		return 1, fmt.Errorf("secret %s is not configured", name.full)
	}
	confirmed, err := confirmPrompt(fmt.Sprintf("delete %s and its keychain value? [y/N]: ", name.full), force)
	if err != nil {
		return 1, err
	}
	if !confirmed {
		fmt.Fprintln(os.Stderr, "motte: aborted")
		return 0, nil
	}
	if err := defaultSecretStore.delete(name.full); err != nil {
		return 1, err
	}
	if err := removeSecretMeta(name); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stderr, "motte: removed %s\n", name.full)
	return 0, nil
}

// lsRow is one listed secret with its keychain state or load error.
type lsRow struct {
	name     secretName
	raw      string // the raw file-relative name, shown when parse failed
	spec     secretSpec
	keychain string // "yes", "no", or "?" on a store error
	specErr  error
}

// cmdSecretsLs lists configured secrets grouped by scope.
func cmdSecretsLs(args []string) (int, error) {
	if len(args) != 0 {
		return 1, fmt.Errorf("motte secrets ls takes no arguments")
	}
	rows, err := collectLsRows()
	if err != nil {
		return 1, err
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no secrets configured; create one with `motte secrets add`")
		return 0, nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].name.scope != rows[j].name.scope {
			return rows[i].name.scope < rows[j].name.scope
		}
		if rows[i].name.profile != rows[j].name.profile {
			return rows[i].name.profile < rows[j].name.profile
		}
		if rows[i].name.hash != rows[j].name.hash {
			return rows[i].name.hash < rows[j].name.hash
		}
		return rows[i].name.full < rows[j].name.full
	})

	hash, hashErr := dirHash()

	// Grouping order: global, each profile, then each profile's projects,
	// relying on the row sort already being (scope, profile, hash).
	prev := ""
	for _, row := range rows {
		group := lsGroup(row.name, hash, hashErr)
		if row.name.scope != scopeGlobal && hashErr == nil && row.name.hash == hash {
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
		display := row.name.full
		if display == "" {
			display = row.raw
		}
		fmt.Printf("  %s\tkeychain: %s\tallow: %s\n", display, state, hosts)
	}
	fmt.Println()
	warnShadowedLeaves(rows)
	if hashErr == nil {
		fmt.Printf("project hash for the current directory: %s\n", hash)
	}
	return 0, nil
}

// lsGroup renders the scope header of one listing group.
func lsGroup(n secretName, hash string, hashErr error) string {
	switch n.scope {
	case scopeGlobal:
		return "global:"
	case scopeProfile:
		return fmt.Sprintf("profile %s:", n.profile)
	default:
		if n.hash == hash && hashErr == nil {
			return fmt.Sprintf("project %s:", n.profile)
		}
		return fmt.Sprintf("project %s/%s:", n.profile, n.hash)
	}
}

// collectLsRows walks the whole secrets tree, leniently listing even
// unparseable names and unreadable configs.
func collectLsRows() ([]lsRow, error) {
	root, err := secretsDir()
	if err != nil {
		return nil, err
	}
	var rows []lsRow
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			// An inaccessible entry is skipped so ls still shows the rest.
			fmt.Fprintf(os.Stderr, "motte: skipping %s: %v\n", path, err)
			return nil
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		label := trimYAMLExt(filepath.ToSlash(rel))
		name, err := parseSecretName(label)
		if err != nil {
			rows = append(rows, lsRow{raw: label, specErr: err, keychain: "?"})
			return nil
		}
		row := lsRow{name: name, raw: label}
		row.spec, row.specErr = readSecretMeta(name)
		row.keychain = probeKeychain(name.full)
		rows = append(rows, row)
		return nil
	})
	return rows, err
}

// trimYAMLExt strips the .yaml suffix of a secret config file name.
func trimYAMLExt(name string) string {
	return strings.TrimSuffix(name, ".yaml")
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

// cmdSecretsMv moves a secret's config and re-keys its keychain value.
func cmdSecretsMv(args []string) (int, error) {
	if len(args) != 2 {
		return 1, fmt.Errorf("motte secrets mv <old> <new>")
	}
	oldName, err := parseSecretName(args[0])
	if err != nil {
		return 1, err
	}
	newName, err := parseSecretName(args[1])
	if err != nil {
		return 1, err
	}
	if oldName.full == newName.full {
		return 1, fmt.Errorf("source and target are the same secret")
	}
	if !secretMetaExists(oldName) {
		return 1, fmt.Errorf("secret %s is not configured", oldName.full)
	}
	if secretMetaExists(newName) {
		return 1, fmt.Errorf("secret %s is already configured", newName.full)
	}
	spec, err := readSecretMeta(oldName)
	if err != nil {
		return 1, err
	}
	value, configErr := defaultSecretStore.get(oldName.full)
	if configErr != nil {
		fmt.Fprintf(os.Stderr, "motte: note: %s has no keychain value; only the configuration moves\n", oldName.full)
	}
	if value != "" {
		if err := defaultSecretStore.set(newName.full, value); err != nil {
			return 1, err
		}
	}
	if err := writeSecretMeta(newName, spec); err != nil {
		return 1, err
	}
	if err := removeSecretMeta(oldName); err != nil {
		return 1, err
	}
	if value != "" {
		if err := defaultSecretStore.delete(oldName.full); err != nil {
			return 1, err
		}
	}
	fmt.Fprintf(os.Stderr, "motte: renamed %s to %s\n", oldName.full, newName.full)
	return 0, nil
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
	switch n.scope {
	case scopeProfile:
		return fmt.Sprintf("profile %s", n.profile)
	case scopeProject:
		return fmt.Sprintf("project %s/%s", n.profile, n.hash)
	default:
		return "global"
	}
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

// secretsConfigHint names a secret's YAML file for interactive messages.
func secretsConfigHint(n secretName) string {
	if path, err := secretConfigPath(n); err == nil {
		return path
	}
	return n.full
}
