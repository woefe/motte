// Secrets: user-configured credentials stored in the OS keychain.
//
// Secret values live in the system keyring (service "motte", account = the
// secret's full path-like name) and never in motte's YAML configs or in a
// durable sandbox config on the host: the launch flow only feeds the value
// through a host env var, and the sandbox config stores a reference to that
// var, which the runtime resolves at every sandbox start.
//
// Names are path-like with scopes: NAME (global), <profile>/NAME (profile),
// <profile>/<dirHash>/NAME (project + profile). Configurations live under
// $XDG_CONFIG_HOME/motte/secrets mirroring the name layout, one YAML file per
// secret, holding the allowed hosts and header fields.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	kr "github.com/zalando/go-keyring"
	"go.yaml.in/yaml/v3"
)

const (
	// keyringService is the OS-keyring service name all motte secrets share.
	keyringService = "motte"
	// secretHostVarPrefix names the host env var a secret's value is passed
	// through; the sandbox config stores a source reference to it.
	secretHostVarPrefix = "MOTTE_SECRET_"
)

// defaultSecretHeaderFields is used when a secret config omits them.
var defaultSecretHeaderFields = []string{"authorization"}

// opencodeSecretName is the secret motte hints at and migrates from older
// sandboxes.
const opencodeSecretName = "OPENCODE_GO_KEY"

// errSecretNotFound reports a missing keychain entry.
var errSecretNotFound = errors.New("secret not found")

// secretSpec is one effective secret: its full path-like name, the guest env
// var the placeholder appears under, and the substitution policy. The value
// arrives separately, via the keychain.
type secretSpec struct {
	name         string
	envVar       string
	allow        []string
	headerFields []string
}

// secretScope distinguishes the three scopes a secret name can carry.
type secretScope int

const (
	scopeGlobal secretScope = iota
	scopeProfile
	scopeProject
)

// secretName is a validated secret name plus its resolved scope parts.
type secretName struct {
	full    string
	scope   secretScope
	profile string
	hash    string
	leaf    string
}

var (
	secretLeafPattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	secretHashPattern   = regexp.MustCompile(`^[0-9a-f]{12}$`)
	secretProfileFormat = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

// parseSecretName validates a path-like secret name and resolves its scope.
// A single segment is a global secret; two segments need a built-in profile
// name; three segments need a profile and a 12-hex directory hash.
func parseSecretName(name string) (secretName, error) {
	if name == "" {
		return secretName{}, fmt.Errorf("empty secret name")
	}
	parts := strings.Split(name, "/")
	n := secretName{full: name}
	switch len(parts) {
	case 1:
		n.scope = scopeGlobal
	case 2:
		if err := validSecretScopeProfile(parts[0], name); err != nil {
			return secretName{}, err
		}
		n.scope, n.profile = scopeProfile, parts[0]
	case 3:
		if err := validSecretScopeProfile(parts[0], name); err != nil {
			return secretName{}, err
		}
		if !secretHashPattern.MatchString(parts[1]) {
			return secretName{}, fmt.Errorf(
				"invalid secret name %q: %q is not a project hash (12 hex chars)", name, parts[1])
		}
		n.scope, n.profile, n.hash = scopeProject, parts[0], parts[1]
	default:
		return secretName{}, fmt.Errorf("invalid secret name %q: at most three segments", name)
	}
	for _, part := range parts[:len(parts)-1] {
		if strings.ContainsAny(part, " \t\r\n") || filepath.Clean(part) != part {
			return secretName{}, fmt.Errorf("invalid secret name %q", name)
		}
	}
	n.leaf = parts[len(parts)-1]
	if !secretLeafPattern.MatchString(n.leaf) {
		return secretName{}, fmt.Errorf(
			"invalid secret name %q: the last segment must be a valid env var name", name)
	}
	return n, nil
}

// validSecretScopeProfile checks a name's profile segment: built-in profile
// names, so a typo like rail/FOO fails at parse time.
func validSecretScopeProfile(profile, name string) error {
	if !secretProfileFormat.MatchString(profile) || !slices.Contains(availableProfiles(), profile) {
		return fmt.Errorf("invalid secret name %q: %q is not a built-in profile (available: %s)",
			name, profile, strings.Join(availableProfiles(), ", "))
	}
	return nil
}

// secretHostEnvVar returns the host env var a resolved secret value travels in.
func secretHostEnvVar(envVar string) string {
	return secretHostVarPrefix + envVar
}

// secretStore is the keychain boundary; tests swap in an in-memory fake.
type secretStore interface {
	get(account string) (string, error)
	set(account, value string) error
	delete(account string) error
}

// keyringStore is the real store backed by the OS keyring.
type keyringStore struct{}

func (keyringStore) get(account string) (string, error) {
	value, err := kr.Get(keyringService, account)
	if errors.Is(err, kr.ErrNotFound) {
		return "", fmt.Errorf("secret %s: %w", account, errSecretNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from the keyring: %w", account, err)
	}
	return value, nil
}

func (keyringStore) set(account, value string) error {
	if err := kr.Set(keyringService, account, value); err != nil {
		return fmt.Errorf("storing %s in the keyring: %w", account, err)
	}
	return nil
}

func (keyringStore) delete(account string) error {
	if err := kr.Delete(keyringService, account); err != nil && !errors.Is(err, kr.ErrNotFound) {
		return fmt.Errorf("deleting %s from the keyring: %w", account, err)
	}
	return nil
}

// defaultSecretStore is the process-wide keychain; tests override it.
var defaultSecretStore secretStore = keyringStore{}

// probeKeychain reports whether an account carries a secret: "yes", "no", or
// "?" when the keychain itself could not be serviced.
func probeKeychain(account string) string {
	switch _, err := defaultSecretStore.get(account); {
	case err == nil:
		return "yes"
	case errors.Is(err, errSecretNotFound):
		return "no"
	default:
		return "?"
	}
}

// secretsDir returns the root of the per-user secrets config tree.
func secretsDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config dir: %w", err)
	}
	return filepath.Join(dir, "motte", "secrets"), nil
}

// secretConfigPath maps a validated secret name to its YAML file path.
func secretConfigPath(n secretName) (string, error) {
	root, err := secretsDir()
	if err != nil {
		return "", err
	}
	rel := n.leaf
	switch n.scope {
	case scopeProfile:
		rel = filepath.Join(n.profile, rel)
	case scopeProject:
		rel = filepath.Join(n.profile, n.hash, rel)
	}
	return filepath.Join(root, rel+".yaml"), nil
}

// secretFileDoc is the strict secret config schema.
type secretFileDoc struct {
	Allow        []string `yaml:"allow"`
	HeaderFields []string `yaml:"header_fields"`
}

// readSecretMeta strictly decodes one secret config file. The allow list is
// required and validated as host patterns; header_fields default to
// `authorization`.
func readSecretMeta(n secretName) (secretSpec, error) {
	path, err := secretConfigPath(n)
	if err != nil {
		return secretSpec{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return secretSpec{}, err
	}
	if err != nil {
		return secretSpec{}, fmt.Errorf("reading secret config %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc secretFileDoc
	if err := decoder.Decode(&doc); err != nil {
		return secretSpec{}, fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return secretSpec{}, fmt.Errorf("invalid secret config %s: multiple YAML documents", path)
	}
	if len(doc.Allow) == 0 {
		return secretSpec{}, fmt.Errorf("invalid secret config %s: allow is empty; at least one host is required", path)
	}
	for _, entry := range doc.Allow {
		if err := validateSecretAllowEntry(entry); err != nil {
			return secretSpec{}, fmt.Errorf("invalid secret config %s: %w", path, err)
		}
	}
	for _, field := range doc.HeaderFields {
		if strings.TrimSpace(field) == "" {
			return secretSpec{}, fmt.Errorf("invalid secret config %s: empty header field", path)
		}
	}
	if doc.HeaderFields == nil {
		doc.HeaderFields = defaultSecretHeaderFields
	}
	return secretSpec{name: n.full, envVar: n.leaf, allow: doc.Allow, headerFields: doc.HeaderFields}, nil
}

// secretMetaExists reports whether a secret config file exists.
func secretMetaExists(n secretName) bool {
	path, err := secretConfigPath(n)
	if err != nil {
		return false
	}
	_, statErr := os.Stat(path)
	return statErr == nil
}

// writeSecretMeta atomically writes one secret config file.
func writeSecretMeta(n secretName, spec secretSpec) error {
	path, err := secretConfigPath(n)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(secretFileDoc{Allow: spec.allow, HeaderFields: spec.headerFields})
	if err != nil {
		return fmt.Errorf("serializing secret config %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing secret config %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("writing secret config %s: %w", path, err)
	}
	return nil
}

// removeSecretMeta deletes one secret config file and any now-empty scope
// directories above it (project hash, then profile).
func removeSecretMeta(n secretName) error {
	path, err := secretConfigPath(n)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing secret config %s: %w", path, err)
	}
	root, err := secretsDir()
	if err != nil {
		return err
	}
	for dir := filepath.Dir(path); dir != root; dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil {
			break // not empty or already gone
		}
	}
	return nil
}

// validateSecretAllowEntry checks one secret allow host: an exact host, a
// `*.suffix` wildcard, or `*` for any host — the SDK SecretEntry grammar.
func validateSecretAllowEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "*" {
		return nil
	}
	if rest, ok := strings.CutPrefix(entry, "*."); ok {
		if rest == "" || strings.ContainsAny(rest, " :/\\*") {
			return fmt.Errorf("invalid secret allow host %q", entry)
		}
		return nil
	}
	if strings.ContainsAny(entry, " :/\\*") || !strings.Contains(entry, ".") {
		return fmt.Errorf("invalid secret allow host %q; expected an exact host, a *.suffix wildcard, or *", entry)
	}
	return nil
}

// scanEffectiveSecrets returns the effective secret set for a profile launch:
// global secrets plus the profile's own and this directory's project secrets,
// with project > profile > global precedence, deduplicated by env var name.
func scanEffectiveSecrets(profileName string) ([]secretSpec, error) {
	hash, err := dirHash()
	if err != nil {
		return nil, err
	}
	var effective []secretSpec
	winner := map[string]int{} // leaf -> index of the winning secret so far
	dirs := []struct {
		scope secretScope
		rel   string
	}{
		{scopeGlobal, ""},
		{scopeProfile, profileName},
		{scopeProject, profileName + "/" + hash},
	}
	for _, scope := range dirs {
		names, err := listSecretConfigs(scope.rel, profileName)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			spec, err := readSecretMeta(n)
			if err != nil {
				return nil, err
			}
			if idx, ok := winner[spec.envVar]; ok {
				fmt.Fprintf(os.Stderr, "motte: secret %s is shadowed by the more specific %s\n",
					effective[idx].name, spec.name)
				effective[idx] = spec
				continue
			}
			winner[spec.envVar] = len(effective)
			effective = append(effective, spec)
		}
	}
	return effective, nil
}

// listSecretConfigs enumerates the YAML configs under a scope-relative dir,
// returning their validated full names.
func listSecretConfigs(rel string, profileName string) ([]secretName, error) {
	root, err := secretsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, rel))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", filepath.Join(root, rel), err)
	}
	names := make([]secretName, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()
		if rel != "" {
			name = rel + "/" + name
		}
		n, err := parseSecretName(strings.TrimSuffix(name, ".yaml"))
		if err != nil {
			return nil, err
		}
		if profileName != "" && n.scope != scopeGlobal && n.profile != profileName {
			return nil, fmt.Errorf(
				"secret %s is scoped to profile %s, not %s", n.full, n.profile, profileName)
		}
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].full < names[j].full })
	return names, nil
}

// secretCountAll returns how many secret configs exist under any scope; used
// for the first-run hint.
func secretCountAll() (int, error) {
	root, err := secretsDir()
	if err != nil {
		return 0, err
	}
	count := 0
	err = filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".yaml" {
			count++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("scanning %s: %w", root, err)
	}
	return count, nil
}

// storedSecret is one secret as recorded in a durable sandbox config.
type storedSecret struct {
	envVar       string
	value        string
	allow        []string
	headerFields []string
}

// parseStoredSecrets extracts the secrets of a stored sandbox config JSON,
// tolerating the durable shapes runtimes have written: secrets as an array or
// a map, hosts as HostPattern objects or strings, and `injection` as the
// older spelling of `substitution`.
func parseStoredSecrets(configJSON string) ([]storedSecret, error) {
	if configJSON == "" {
		return nil, nil
	}
	var config struct {
		Network *struct {
			Secrets *struct {
				Secrets json.RawMessage `json:"secrets"`
			} `json:"secrets"`
		} `json:"network"`
	}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("parsing sandbox config: %w", err)
	}
	if config.Network == nil || config.Network.Secrets == nil || len(config.Network.Secrets.Secrets) == 0 {
		return nil, nil
	}
	var docs []storedSecretJSON
	if err := json.Unmarshal(config.Network.Secrets.Secrets, &docs); err != nil {
		// A map keyed by name; fold the keys into the env var slot.
		keyed := map[string]storedSecretJSON{}
		if err := json.Unmarshal(config.Network.Secrets.Secrets, &keyed); err != nil {
			return nil, fmt.Errorf("parsing sandbox config secrets: %w", err)
		}
		for key, doc := range keyed {
			doc.EnvVar = firstNonEmpty(doc.EnvVar, key)
			docs = append(docs, doc)
		}
	}
	var entries []storedSecret
	for _, doc := range docs {
		entries = append(entries, doc.storedSecret())
	}
	return entries, nil
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// storedSecretJSON mirrors the durable SecretEntry serde shape.
type storedSecretJSON struct {
	Name    string             `json:"name"`
	EnvVar  string             `json:"env_var"`
	Value   string             `json:"value"`
	Allowed []hostPatternValue `json:"allowed_hosts"`
	Allow   []hostPatternValue `json:"allow"`
	Sub     *storedSubJSON     `json:"substitution"`
	Inject  *storedSubJSON     `json:"injection"`
}

// storedSecret converts to the compact runtime form, preferring the kebab-case
// field and the alias.
func (s storedSecretJSON) storedSecret() storedSecret {
	sub := s.Sub
	if sub == nil {
		sub = s.Inject
	}
	var headers []string
	if sub != nil {
		headers = sub.HeaderFields
	}
	return storedSecret{
		envVar:       firstNonEmpty(s.EnvVar, s.Name),
		value:        s.Value,
		allow:        hostPatternStrings(s.Allowed, s.Allow),
		headerFields: headers,
	}
}

// hostPatternStrings joins two field aliases, taking the first non-empty.
func hostPatternStrings(groups ...[]hostPatternValue) []string {
	for _, group := range groups {
		if len(group) > 0 {
			var out []string
			for _, p := range group {
				out = append(out, p.pattern)
			}
			return out
		}
	}
	return nil
}

// storedSubJSON is the substitution (or injection) sub-document.
type storedSubJSON struct {
	HeaderFields []string `json:"header_fields"`
}

// hostPatternValue accepts the shapes `HostPattern` serializes to: a string
// ("any", an exact host, or a "*.suffix") or an externally tagged object
// ({"exact":h}, {"wildcard":h}, {"any":null}).
type hostPatternValue struct {
	pattern string
}

func (h *hostPatternValue) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		h.pattern = str
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("host pattern: %w", err)
	}
	if value, ok := fields["wildcard"]; ok {
		if str, ok := value.(string); ok {
			h.pattern = str
		}
		return nil
	}
	if value, ok := fields["exact"]; ok {
		if str, ok := value.(string); ok {
			h.pattern = str
		}
		return nil
	}
	_, any := fields["any"]
	if len(fields) == 0 || (any && len(fields) == 1) {
		h.pattern = "*"
		return nil
	}
	return fmt.Errorf("host pattern: unknown shape %s", string(data))
}

// secretDrift compares the secrets stored in a sandbox config against the
// desired set (both keyed by env var name). It returns the desired secrets to
// upsert, stored secrets to remove, and the upserts that replace a stored raw
// (plaintext) value with a keychain-backed env reference.
func secretDrift(stored []storedSecret, desired []secretSpec) (upsert []secretSpec, remove, migrated []string) {
	want := make(map[string]secretSpec, len(desired))
	for _, spec := range desired {
		want[spec.envVar] = spec
	}
	have := make(map[string]bool, len(stored))
	for _, s := range stored {
		if s.envVar == "" {
			continue
		}
		have[s.envVar] = true
		desired, ok := want[s.envVar]
		if !ok {
			remove = append(remove, s.envVar)
			continue
		}
		if s.value != "" {
			// A plaintext value from an older motte build: replace it with
			// the keychain-backed env reference.
			upsert = append(upsert, desired)
			migrated = append(migrated, s.envVar)
			continue
		}
		if !slices.Equal(s.allow, desired.allow) || !slices.Equal(s.headerFields, desired.headerFields) {
			upsert = append(upsert, desired)
		}
	}
	for _, spec := range desired {
		if !have[spec.envVar] {
			upsert = append(upsert, spec)
		}
	}
	return upsert, remove, migrated
}
