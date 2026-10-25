// Secrets: user-configured credentials stored in the OS keychain.
//
// Secret values live in the system keyring (service "motte", account = the
// secret's full path-like name) and never in motte's YAML configs or in a
// durable sandbox config on the host: the launch flow only feeds the value
// through a host env var, and the sandbox config stores a reference to that
// var, which the runtime resolves at every sandbox start.
//
// Names are path-like with scopes: NAME (global), <profile>/NAME (profile),
// and <hash>/NAME (project, the current directory). The settings of a scope
// live in one file under $XDG_CONFIG_HOME/motte/secrets: global.yaml,
// <profile>.yaml, and <hash>.yaml.
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

// defaultSecretHeaderFields is used when a secret entry omits them.
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
	secretLeafPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	secretHashPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

// parseSecretName validates a path-like secret name and resolves its scope.
// A single segment is a global secret; two segments are profile-scoped when
// the first is a built-in profile name and project-scoped when it is a
// project hash.
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
		switch {
		case slices.Contains(availableProfiles(), parts[0]):
			n.scope, n.profile = scopeProfile, parts[0]
		case secretHashPattern.MatchString(parts[0]):
			n.scope, n.hash = scopeProject, parts[0]
		default:
			return secretName{}, fmt.Errorf(
				"invalid secret name %q: %q is not a built-in profile (available: %s) nor a 12-hex project hash",
				name, parts[0], strings.Join(availableProfiles(), ", "),
			)
		}
	default:
		return secretName{}, fmt.Errorf("invalid secret name %q: at most two segments", name)
	}
	n.leaf = parts[len(parts)-1]
	if !secretLeafPattern.MatchString(n.leaf) {
		return secretName{}, fmt.Errorf(
			"invalid secret name %q: the last segment must be a valid env var name", name)
	}
	return n, nil
}

// secretScopeKey identifies a scope: the file its settings live in and the
// prefix its secret names carry.
type secretScopeKey struct {
	scope   secretScope
	profile string
	hash    string
}

// scopeKeyOf returns the scope key a secret name belongs to.
func scopeKeyOf(n secretName) secretScopeKey {
	switch n.scope {
	case scopeProfile:
		return secretScopeKey{scope: scopeProfile, profile: n.profile}
	case scopeProject:
		return secretScopeKey{scope: scopeProject, hash: n.hash}
	default:
		return secretScopeKey{scope: scopeGlobal}
	}
}

// prefix returns the scope prefix of a secret name.
func (k secretScopeKey) prefix() string {
	switch k.scope {
	case scopeProfile:
		return k.profile
	case scopeProject:
		return k.hash
	default:
		return ""
	}
}

// name returns the full name of a secret in the scope.
func (k secretScopeKey) name(envVar string) string {
	if prefix := k.prefix(); prefix != "" {
		return prefix + "/" + envVar
	}
	return envVar
}

// label renders the scope for messages and listings.
func (k secretScopeKey) label() string {
	switch k.scope {
	case scopeProfile:
		return "profile " + k.profile
	case scopeProject:
		return "project " + k.hash
	default:
		return "global"
	}
}

// path returns the file the scope's settings live in.
func (k secretScopeKey) path() (string, error) {
	root, err := secretsDir()
	if err != nil {
		return "", err
	}
	name := "global.yaml"
	switch k.scope {
	case scopeProfile:
		name = k.profile + ".yaml"
	case scopeProject:
		name = k.hash + ".yaml"
	}
	return filepath.Join(root, name), nil
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

// secretScopeDoc is the schema of a scope file: the secrets it holds.
type secretScopeDoc struct {
	Secrets map[string]secretEntryDoc `yaml:"secrets"`
}

// secretEntryDoc is one secret's settings in a scope file.
type secretEntryDoc struct {
	Allow        []string `yaml:"allow"`
	HeaderFields []string `yaml:"header_fields"`
}

// readSecretScope strictly decodes one scope file and returns the secrets it
// holds, keyed by env var name. A missing file holds no secrets.
func readSecretScope(key secretScopeKey) (map[string]secretSpec, error) {
	path, err := key.path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading secret config %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc secretScopeDoc
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid secret config %s: multiple YAML documents", path)
	}
	secrets := make(map[string]secretSpec, len(doc.Secrets))
	for envVar, entry := range doc.Secrets {
		if len(entry.Allow) == 0 {
			return nil, fmt.Errorf(
				"invalid secret config %s: %s has an empty allow list; at least one host is required",
				path, envVar)
		}
		for _, host := range entry.Allow {
			if err := validateSecretAllowEntry(host); err != nil {
				return nil, fmt.Errorf("invalid secret config %s: %w", path, err)
			}
		}
		for _, field := range entry.HeaderFields {
			if strings.TrimSpace(field) == "" {
				return nil, fmt.Errorf("invalid secret config %s: %s has an empty header field", path, envVar)
			}
		}
		headerFields := entry.HeaderFields
		if headerFields == nil {
			headerFields = defaultSecretHeaderFields
		}
		secrets[envVar] = secretSpec{
			name:         key.name(envVar),
			envVar:       envVar,
			allow:        entry.Allow,
			headerFields: headerFields,
		}
	}
	return secrets, nil
}

// secretScopeNode returns the document of a scope file, with an empty
// "secrets" mapping when the file does not exist yet.
func secretScopeNode(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return emptySecretScope(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading secret config %s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return emptySecretScope(), nil
	}
	return &doc, nil
}

// emptySecretScope returns an empty scope document.
func emptySecretScope() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		},
	}
}

// secretsMapping returns the "secrets" mapping of a scope document, creating
// it when it is missing.
func secretsMapping(doc *yaml.Node) (*yaml.Node, error) {
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("the secret config has no document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("the secret config is not a mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "secrets" {
			mapping := root.Content[i+1]
			if mapping.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("the secret config's `secrets` is not a mapping")
			}
			return mapping, nil
		}
	}
	mapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "secrets"},
		mapping)
	return mapping, nil
}

// setSecretEntry adds or replaces one secret in a scope mapping.
func setSecretEntry(mapping *yaml.Node, envVar string, spec secretSpec) {
	value := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	allow := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, host := range spec.allow {
		allow.Content = append(allow.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: host})
	}
	headers := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, field := range spec.headerFields {
		headers.Content = append(headers.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: field})
	}
	value.Content = append(value.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "allow"}, allow,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "header_fields"}, headers)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == envVar {
			mapping.Content[i+1] = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: envVar}, value)
}

// removeSecretEntry drops one secret from a scope mapping and reports
// whether it was there.
func removeSecretEntry(mapping *yaml.Node, envVar string) bool {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == envVar {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return true
		}
	}
	return false
}

// writeSecretScope writes a scope document atomically.
func writeSecretScope(path string, doc *yaml.Node) error {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("serializing secret config %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("serializing secret config %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing secret config %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("writing secret config %s: %w", path, err)
	}
	return nil
}

// secretMetaExists reports whether a secret is configured in its scope.
func secretMetaExists(n secretName) bool {
	secrets, err := readSecretScope(scopeKeyOf(n))
	if err != nil {
		return false
	}
	_, ok := secrets[n.leaf]
	return ok
}

// readSecretMeta returns the settings of one configured secret.
func readSecretMeta(n secretName) (secretSpec, error) {
	secrets, err := readSecretScope(scopeKeyOf(n))
	if err != nil {
		return secretSpec{}, err
	}
	spec, ok := secrets[n.leaf]
	if !ok {
		return secretSpec{}, fmt.Errorf("secret %s is not configured", n.full)
	}
	return spec, nil
}

// writeSecretMeta adds or replaces one secret in its scope file. The file
// keeps the comments and the other secrets it holds.
func writeSecretMeta(n secretName, spec secretSpec) error {
	key := scopeKeyOf(n)
	path, err := key.path()
	if err != nil {
		return err
	}
	doc, err := secretScopeNode(path)
	if err != nil {
		return err
	}
	mapping, err := secretsMapping(doc)
	if err != nil {
		return fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	setSecretEntry(mapping, n.leaf, spec)
	return writeSecretScope(path, doc)
}

// removeSecretMeta deletes one secret from its scope file and removes the
// file when it holds no secret anymore.
func removeSecretMeta(n secretName) error {
	key := scopeKeyOf(n)
	path, err := key.path()
	if err != nil {
		return err
	}
	doc, err := secretScopeNode(path)
	if err != nil {
		return err
	}
	mapping, err := secretsMapping(doc)
	if err != nil {
		return fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	if !removeSecretEntry(mapping, n.leaf) {
		return nil
	}
	if len(mapping.Content) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing secret config %s: %w", path, err)
		}
		return nil
	}
	return writeSecretScope(path, doc)
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
	keys := []secretScopeKey{
		{scope: scopeGlobal},
		{scope: scopeProfile, profile: profileName},
		{scope: scopeProject, hash: hash},
	}
	var effective []secretSpec
	winner := map[string]int{} // env var -> index of the winning secret so far
	for _, key := range keys {
		secrets, err := readSecretScope(key)
		if err != nil {
			return nil, err
		}
		for _, envVar := range sortedSecretNames(secrets) {
			spec := secrets[envVar]
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

// sortedSecretNames returns the env var names of a scope in a stable order.
func sortedSecretNames(secrets map[string]secretSpec) []string {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// secretScopeKeys returns every scope that has a file in the secrets tree:
// the global scope, the built-in profiles, and the project files.
func secretScopeKeys() ([]secretScopeKey, error) {
	root, err := secretsDir()
	if err != nil {
		return nil, err
	}
	keys := []secretScopeKey{{scope: scopeGlobal}}
	for _, profile := range availableProfiles() {
		keys = append(keys, secretScopeKey{scope: scopeProfile, profile: profile})
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return keys, nil
		}
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}
	var hashes []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".yaml")
		if !secretHashPattern.MatchString(name) {
			continue
		}
		hashes = append(hashes, name)
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		keys = append(keys, secretScopeKey{scope: scopeProject, hash: hash})
	}
	return keys, nil
}

// secretCountAll returns how many secrets are configured under any scope;
// used for the first-run hint.
func secretCountAll() (int, error) {
	keys, err := secretScopeKeys()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, key := range keys {
		secrets, err := readSecretScope(key)
		if err != nil {
			return 0, err
		}
		count += len(secrets)
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
