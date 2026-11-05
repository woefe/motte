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
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/profile"
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

// DefaultHeaderFields is used when a secret entry omits them.
var DefaultHeaderFields = []string{"authorization"}

// ErrNotFound reports a missing keychain entry.
var ErrNotFound = errors.New("secret not found")

// Spec is one effective secret: its full path-like name, the guest env var
// the placeholder appears under, and the substitution policy. The value
// arrives separately, via the keychain.
type Spec struct {
	Name         string
	EnvVar       string
	Allow        []string
	HeaderFields []string
}

// Scope distinguishes the three scopes a secret name can carry.
type Scope int

const (
	ScopeGlobal Scope = iota
	ScopeProfile
	ScopeProject
)

// Name is a validated secret name plus its resolved scope parts.
type Name struct {
	Full    string
	Scope   Scope
	Profile string
	Hash    string
	Leaf    string
}

// secretLeafPattern matches the leaf (env var) segment of a secret name.
var secretLeafPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseName validates a path-like secret name and resolves its scope.
// A single segment is a global secret; two segments are profile-scoped when
// the first is a built-in profile name and project-scoped when it is a
// project hash.
func ParseName(name string) (Name, error) {
	if name == "" {
		return Name{}, fmt.Errorf("empty secret name")
	}
	parts := strings.Split(name, "/")
	n := Name{Full: name}
	switch len(parts) {
	case 1:
		n.Scope = ScopeGlobal
	case 2:
		switch {
		case slices.Contains(profile.Available(), parts[0]):
			n.Scope, n.Profile = ScopeProfile, parts[0]
		case config.ProjectHashPattern.MatchString(parts[0]):
			n.Scope, n.Hash = ScopeProject, parts[0]
		default:
			return Name{}, fmt.Errorf(
				"invalid secret name %q: %q is not a built-in profile (available: %s) nor a 12-hex project hash",
				name, parts[0], strings.Join(profile.Available(), ", "),
			)
		}
	default:
		return Name{}, fmt.Errorf("invalid secret name %q: at most two segments", name)
	}
	n.Leaf = parts[len(parts)-1]
	if !secretLeafPattern.MatchString(n.Leaf) {
		return Name{}, fmt.Errorf(
			"invalid secret name %q: the last segment must be a valid env var name", name)
	}
	return n, nil
}

// ScopeKey identifies a scope: the file its settings live in and the prefix
// its secret names carry.
type ScopeKey struct {
	Scope   Scope
	Profile string
	Hash    string
}

// ScopeKeyOf returns the scope key a secret name belongs to.
func ScopeKeyOf(n Name) ScopeKey {
	switch n.Scope {
	case ScopeProfile:
		return ScopeKey{Scope: ScopeProfile, Profile: n.Profile}
	case ScopeProject:
		return ScopeKey{Scope: ScopeProject, Hash: n.Hash}
	default:
		return ScopeKey{Scope: ScopeGlobal}
	}
}

// ScopeKeyFromArg maps a resolved configure argument to its scope key.
func ScopeKeyFromArg(arg config.ScopeArg) ScopeKey {
	switch {
	case arg.Profile != "":
		return ScopeKey{Scope: ScopeProfile, Profile: arg.Profile}
	case arg.Hash != "":
		return ScopeKey{Scope: ScopeProject, Hash: arg.Hash}
	default:
		return ScopeKey{Scope: ScopeGlobal}
	}
}

// prefix returns the scope prefix of a secret name.
func (k ScopeKey) prefix() string {
	switch k.Scope {
	case ScopeProfile:
		return k.Profile
	case ScopeProject:
		return k.Hash
	default:
		return ""
	}
}

// name returns the full name of a secret in the scope.
func (k ScopeKey) name(envVar string) string {
	if prefix := k.prefix(); prefix != "" {
		return prefix + "/" + envVar
	}
	return envVar
}

// ConfigureArg renders the scope as a `motte secrets configure` argument.
func (k ScopeKey) ConfigureArg() string {
	switch k.Scope {
	case ScopeProfile:
		return k.Profile
	case ScopeProject:
		if hash, err := config.DirHash(); err == nil && hash == k.Hash {
			return "project"
		}
		return k.Hash
	default:
		return "global"
	}
}

// Path returns the file the scope's settings live in.
func (k ScopeKey) Path() (string, error) {
	root, err := config.SecretsDir()
	if err != nil {
		return "", err
	}
	name := "global.yaml"
	switch k.Scope {
	case ScopeProfile:
		name = k.Profile + ".yaml"
	case ScopeProject:
		name = k.Hash + ".yaml"
	}
	return filepath.Join(root, name), nil
}

// HostEnvVar returns the host env var a resolved secret value travels in.
func HostEnvVar(envVar string) string {
	return secretHostVarPrefix + envVar
}

// Store is the keychain boundary; tests swap in an in-memory fake.
type Store interface {
	Get(account string) (string, error)
	Set(account, value string) error
	Delete(account string) error
}

// keyringStore is the real store backed by the OS keyring.
type keyringStore struct{}

func (keyringStore) Get(account string) (string, error) {
	value, err := kr.Get(keyringService, account)
	if errors.Is(err, kr.ErrNotFound) {
		return "", fmt.Errorf("secret %s: %w", account, ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from the keyring: %w", account, err)
	}
	return value, nil
}

func (keyringStore) Set(account, value string) error {
	if err := kr.Set(keyringService, account, value); err != nil {
		return fmt.Errorf("storing %s in the keyring: %w", account, err)
	}
	return nil
}

func (keyringStore) Delete(account string) error {
	if err := kr.Delete(keyringService, account); err != nil && !errors.Is(err, kr.ErrNotFound) {
		return fmt.Errorf("deleting %s from the keyring: %w", account, err)
	}
	return nil
}

// DefaultStore is the process-wide keychain; tests override it.
var DefaultStore Store = keyringStore{}

// ProbeKeychain reports whether an account carries a secret: "yes", "no", or
// "?" when the keychain itself could not be serviced.
func ProbeKeychain(account string) string {
	switch _, err := DefaultStore.Get(account); {
	case err == nil:
		return "yes"
	case errors.Is(err, ErrNotFound):
		return "no"
	default:
		return "?"
	}
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

// ReadScope strictly decodes one scope file and returns the secrets it
// holds, keyed by env var name. A missing file holds no secrets.
func ReadScope(key ScopeKey) (map[string]Spec, error) {
	path, err := key.Path()
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
	secrets := make(map[string]Spec, len(doc.Secrets))
	for envVar, entry := range doc.Secrets {
		if len(entry.Allow) == 0 {
			return nil, fmt.Errorf(
				"invalid secret config %s: %s has an empty allow list; at least one host is required",
				path, envVar)
		}
		for _, host := range entry.Allow {
			if err := ValidateAllowEntry(host); err != nil {
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
			headerFields = DefaultHeaderFields
		}
		secrets[envVar] = Spec{
			Name:         key.name(envVar),
			EnvVar:       envVar,
			Allow:        entry.Allow,
			HeaderFields: headerFields,
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

// secretsMapping returns the "secrets" mapping of a scope document. A missing
// key is appended; a null value (an empty `secrets:`) becomes an empty
// mapping in place, keeping its comments.
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
			switch {
			case mapping.Kind == yaml.MappingNode:
				return mapping, nil
			case mapping.Tag == "!!null":
				mapping.Kind = yaml.MappingNode
				mapping.Tag = "!!map"
				mapping.Value = ""
				return mapping, nil
			default:
				return nil, fmt.Errorf("the secret config's `secrets` is not a mapping")
			}
		}
	}
	mapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "secrets"},
		mapping)
	return mapping, nil
}

// setSecretEntry adds or replaces one secret in a scope mapping.
func setSecretEntry(mapping *yaml.Node, envVar string, spec Spec) {
	value := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	allow := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, host := range spec.Allow {
		allow.Content = append(allow.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: host})
	}
	headers := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, field := range spec.HeaderFields {
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

// Template returns the commented skeleton of a new secrets scope file. The
// project scope of the current directory names the directory it belongs to,
// so the file identifies its location.
func Template(key ScopeKey) (string, error) {
	header := fmt.Sprintf("# motte secrets — %s\n#\n", config.LabelScope(key.Profile, key.Hash, false))
	if hash, err := config.DirHash(); err == nil && key.Scope == ScopeProject && hash == key.Hash {
		path, err := config.ProjectPath()
		if err != nil {
			return "", err
		}
		header += fmt.Sprintf("# Project path: %s\n#\n", path)
	}
	return header + "# Values live in the OS keychain; set one with `motte secrets set <name>`.\n" +
		"# This file holds the settings only:\n" +
		"#   allow: the hosts a value may reach (an exact host or a *.wildcard)\n" +
		"#   header_fields: the headers the value is substituted into\n" +
		"secrets:\n" +
		"  # EXAMPLE_API_KEY:\n" +
		"  #   allow:\n" +
		"  #     - \"api.example.com\"\n", nil
}

// WriteMeta adds or replaces one secret in its scope file. The file keeps
// the comments and the other secrets it holds.
func WriteMeta(n Name, spec Spec) error {
	key := ScopeKeyOf(n)
	path, err := key.Path()
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
	setSecretEntry(mapping, n.Leaf, spec)
	return writeSecretScope(path, doc)
}

// RemoveMeta deletes one secret from its scope file and removes the file
// when it holds no secret anymore.
func RemoveMeta(n Name) error {
	key := ScopeKeyOf(n)
	path, err := key.Path()
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
	if !removeSecretEntry(mapping, n.Leaf) {
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

// ValidateAllowEntry checks one secret allow host: an exact host, a
// `*.suffix` wildcard, or `*` for any host — the SDK SecretEntry grammar.
func ValidateAllowEntry(entry string) error {
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

// ScanEffective returns the effective secret set for a profile launch:
// global secrets plus the profile's own and this directory's project secrets,
// with project > profile > global precedence, deduplicated by env var name.
func ScanEffective(profileName string) ([]Spec, error) {
	hash, err := config.DirHash()
	if err != nil {
		return nil, err
	}
	keys := []ScopeKey{
		{Scope: ScopeGlobal},
		{Scope: ScopeProfile, Profile: profileName},
		{Scope: ScopeProject, Hash: hash},
	}
	var effective []Spec
	winner := map[string]int{} // env var -> index of the winning secret so far
	for _, key := range keys {
		secrets, err := ReadScope(key)
		if err != nil {
			return nil, err
		}
		for _, envVar := range SortedNames(secrets) {
			spec := secrets[envVar]
			if idx, ok := winner[spec.EnvVar]; ok {
				slog.Warn("secret is shadowed by a more specific scope",
					"secret", effective[idx].Name, "winner", spec.Name)
				effective[idx] = spec
				continue
			}
			winner[spec.EnvVar] = len(effective)
			effective = append(effective, spec)
		}
	}
	return effective, nil
}

// SortedNames returns the env var names of a scope in a stable order.
func SortedNames(secrets map[string]Spec) []string {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CountAll returns how many secrets are configured under any scope; used
// for the first-run hint.
func CountAll() (int, error) {
	root, err := config.SecretsDir()
	if err != nil {
		return 0, err
	}
	scopes, err := config.LsScopes(root)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, scope := range scopes {
		secrets, err := ReadScope(ScopeKeyFromArg(scope))
		if err != nil {
			return 0, err
		}
		count += len(secrets)
	}
	return count, nil
}

// Stored is one secret as recorded in a durable sandbox config.
type Stored struct {
	EnvVar       string
	Value        string
	Allow        []string
	HeaderFields []string
}

// ParseStored extracts the secrets of a stored sandbox config JSON,
// tolerating the durable shapes runtimes have written: secrets as an array or
// a map, hosts as HostPattern objects or strings, and `injection` as the
// older spelling of `substitution`.
func ParseStored(configJSON string) ([]Stored, error) {
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
	var entries []Stored
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
func (s storedSecretJSON) storedSecret() Stored {
	sub := s.Sub
	if sub == nil {
		sub = s.Inject
	}
	var headers []string
	if sub != nil {
		headers = sub.HeaderFields
	}
	return Stored{
		EnvVar:       firstNonEmpty(s.EnvVar, s.Name),
		Value:        s.Value,
		Allow:        hostPatternStrings(s.Allowed, s.Allow),
		HeaderFields: headers,
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

// Drift compares the secrets stored in a sandbox config against the desired
// set (both keyed by env var name). It returns the desired secrets to
// upsert, stored secrets to remove, and the upserts that replace a stored raw
// (plaintext) value with a keychain-backed env reference.
func Drift(stored []Stored, desired []Spec) (upsert []Spec, remove, migrated []string) {
	want := make(map[string]Spec, len(desired))
	for _, spec := range desired {
		want[spec.EnvVar] = spec
	}
	have := make(map[string]bool, len(stored))
	for _, s := range stored {
		if s.EnvVar == "" {
			continue
		}
		have[s.EnvVar] = true
		desired, ok := want[s.EnvVar]
		if !ok {
			remove = append(remove, s.EnvVar)
			continue
		}
		if s.Value != "" {
			// A plaintext value from an older motte build: replace it with
			// the keychain-backed env reference.
			upsert = append(upsert, desired)
			migrated = append(migrated, s.EnvVar)
			continue
		}
		if !slices.Equal(s.Allow, desired.Allow) || !slices.Equal(s.HeaderFields, desired.HeaderFields) {
			upsert = append(upsert, desired)
		}
	}
	for _, spec := range desired {
		if !have[spec.EnvVar] {
			upsert = append(upsert, spec)
		}
	}
	return upsert, remove, migrated
}
