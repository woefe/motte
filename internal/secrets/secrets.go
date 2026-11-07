// Secrets: user-configured credentials stored in the OS keychain.
//
// Secret values live in the system keyring (service "motte", account = the
// secret's env var name) and never in motte's YAML configs or in a durable
// sandbox config on the host: the launch flow only feeds the value through a
// host env var, and the sandbox config stores a reference to that var, which
// the runtime resolves at every sandbox start.
//
// Each secret's settings live in one file under $XDG_CONFIG_HOME/motte/secrets:
// `<NAME>.yaml`.
package secrets

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
	"strings"

	"github.com/woefe/motte/internal/config"
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
var DefaultHeaderFields = []string{"authorization", "x-api-key"}

// ErrNotFound reports a missing keychain entry or secret settings file.
var ErrNotFound = errors.New("secret not found")

// Spec is one secret's configuration: its env var name and substitution
// policy. The value arrives separately, via the keychain.
type Spec struct {
	Name         string
	EnvVar       string
	Allow        []string
	HeaderFields []string
}

// secretNamePattern matches a valid secret env var name.
var secretNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateName checks that name is a valid environment variable name.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("empty secret name")
	}
	if !secretNamePattern.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: must be a valid env var name", name)
	}
	return nil
}

// Path returns the file a secret's settings live in after validating the name.
func Path(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	root, err := config.SecretsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name+".yaml"), nil
}

// ListNames returns the sorted names of the configured secrets under
// ~/.config/motte/secrets.
func ListNames() ([]string, error) {
	root, err := config.SecretsDir()
	if err != nil {
		return nil, err
	}
	return config.ListYAMLNames(root)
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

// DefaultStore returns the OS keyring store.
func DefaultStore() Store {
	return keyringStore{}
}

// ProbeKeychain reports whether an account carries a secret in store: "yes",
// "no", or "?" when the keychain itself could not be serviced.
func ProbeKeychain(store Store, account string) string {
	switch _, err := store.Get(account); {
	case err == nil:
		return "yes"
	case errors.Is(err, ErrNotFound):
		return "no"
	default:
		return "?"
	}
}

// secretFileDoc is one secret's settings file schema.
type secretFileDoc struct {
	Allow        []string `yaml:"allow"`
	HeaderFields []string `yaml:"header_fields,omitempty"`
}

// Read strictly decodes one secret's settings file by name. A missing file
// returns ErrNotFound wrapped.
func Read(name string) (Spec, error) {
	path, err := Path(name)
	if err != nil {
		return Spec{}, err
	}
	return ReadFile(path, name)
}

// ReadFile strictly decodes one secret's settings file at path. A missing file
// returns ErrNotFound wrapped.
func ReadFile(path, name string) (Spec, error) {
	if err := ValidateName(name); err != nil {
		return Spec{}, fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Spec{}, fmt.Errorf("secret %s: %w", name, ErrNotFound)
	}
	if err != nil {
		return Spec{}, fmt.Errorf("reading secret config %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc secretFileDoc
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return Spec{}, fmt.Errorf(
				"invalid secret config %s: %s has an empty allow list; at least one host is required",
				path, name)
		}
		return Spec{}, fmt.Errorf("invalid secret config %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Spec{}, fmt.Errorf("invalid secret config %s: multiple YAML documents", path)
	}
	if len(doc.Allow) == 0 {
		return Spec{}, fmt.Errorf(
			"invalid secret config %s: %s has an empty allow list; at least one host is required",
			path, name)
	}
	for _, host := range doc.Allow {
		if err := ValidateAllowEntry(host); err != nil {
			return Spec{}, fmt.Errorf("invalid secret config %s: %w", path, err)
		}
	}
	for _, field := range doc.HeaderFields {
		if strings.TrimSpace(field) == "" {
			return Spec{}, fmt.Errorf("invalid secret config %s: %s has an empty header field", path, name)
		}
	}
	headerFields := doc.HeaderFields
	if headerFields == nil {
		headerFields = slices.Clone(DefaultHeaderFields)
	}
	return Spec{
		Name:         name,
		EnvVar:       name,
		Allow:        doc.Allow,
		HeaderFields: headerFields,
	}, nil
}

// Template returns the commented skeleton of a new secret settings file.
func Template(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return fmt.Sprintf(`# motte secret — %s
# Value lives in the OS keychain; set it with `+"`motte secrets set %s`"+`.
allow:
  - "api.example.com"
header_fields:
  - "authorization"
`, name, name), nil
}

// WriteMeta writes one secret's settings file atomically with 0600
// permissions.
func WriteMeta(name string, spec Spec) error {
	path, err := Path(name)
	if err != nil {
		return err
	}
	headers := spec.HeaderFields
	if len(headers) == 0 {
		headers = DefaultHeaderFields
	}
	doc := secretFileDoc{
		Allow:        spec.Allow,
		HeaderFields: headers,
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# motte secret — %s\n", name)
	fmt.Fprintf(&buf, "# Value lives in the OS keychain; set it with `motte secrets set %s`.\n", name)
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("serializing secret config %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("serializing secret config %s: %w", path, err)
	}
	return config.WriteAtomic(path, buf.Bytes())
}

// RemoveMeta deletes a secret's settings file.
func RemoveMeta(name string) error {
	path, err := Path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing secret config %s: %w", path, err)
	}
	return nil
}

// ValidateAllowEntry checks one secret allow host: an exact host, a
// `*.suffix` wildcard, or `*` for any host — the SDK SecretEntry grammar.
func ValidateAllowEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "*" {
		return nil
	}
	if rest, ok := strings.CutPrefix(entry, "*."); ok {
		if rest == "" || strings.ContainsAny(rest, " :/\\*") || !strings.Contains(rest, ".") {
			return fmt.Errorf("invalid secret allow host %q", entry)
		}
		return nil
	}
	if strings.ContainsAny(entry, " :/\\*") || !strings.Contains(entry, ".") {
		return fmt.Errorf("invalid secret allow host %q; expected an exact host, a *.suffix wildcard, or *", entry)
	}
	return nil
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
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("host pattern: wildcard must be a string")
		}
		h.pattern = str
		return nil
	}
	if value, ok := fields["exact"]; ok {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("host pattern: exact must be a string")
		}
		h.pattern = str
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
