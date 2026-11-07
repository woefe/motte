// The launcher: motte's boot flow. It resolves this directory's project,
// creates or reuses this directory's sandbox via the microsandbox Go SDK,
// converges the sandbox's secrets onto the desired set, and attaches the
// terminal to the workload.
package launcher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/project"
)

// labelKey is the sandbox label that carries the sandbox config fingerprint
// (image and effective network policy), so a reused VM can be told that its
// config changed.
const labelKey = "motte.policy"

// Boot launches this directory's project sandbox and returns the workload's
// exit code.
func Boot(noPull, replace bool) (int, error) {
	resolved, err := project.ResolveCurrent()
	if err != nil {
		return 1, err
	}
	defer resolved.ClearSecretEnv()

	opts := sandboxOptions(resolved, noPull)

	ctx := context.Background()

	// Reuse the installed msb/libkrunfw pair or install the SDK's pinned
	// runtime to ~/.microsandbox.
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		return 1, fmt.Errorf("ensuring the microsandbox runtime: %w", err)
	}

	name := resolved.SandboxName
	state := launchState{secrets: resolved.Secrets, policyFingerprint: resolved.Fingerprint}
	sandbox, err := openSandbox(ctx, name, opts, replace, state)
	resolved.ClearSecretEnv()
	if err != nil {
		return 1, err
	}
	slog.Info("using sandbox", "name", name)

	// Bridge this terminal to the workload; blocks until the workload exits.
	code, attachErr := sandbox.AttachDefault(ctx)

	// Stop always runs, even on attach errors; the named sandbox and its
	// root disk persist across runs.
	if err := sandbox.Stop(ctx); err != nil {
		slog.Error("failed to stop sandbox", "error", err)
	}
	if err := sandbox.Close(); err != nil {
		slog.Warn("failed to close the sandbox handle", "error", err)
	}
	if attachErr != nil {
		return 1, fmt.Errorf("attaching to %s: %w", name, attachErr)
	}
	return code, nil
}

// launchState is the desired state of a launch: the resolved secrets and the
// fingerprint of the image and effective network policy.
type launchState struct {
	secrets           []project.ResolvedSecret
	policyFingerprint string
}

// openSandbox returns a live sandbox for name. With replace set it recreates
// the VM; otherwise it reuses this directory's persisted VM when one exists and
// creates it (logging pull/boot progress) only when none does yet. The
// effective secrets are converged onto the sandbox config after create and on
// every reuse, so drifted or migrated secrets are fixed per launch.
func openSandbox(
	ctx context.Context,
	name string,
	opts []m.SandboxOption,
	replace bool,
	state launchState,
) (*m.Sandbox, error) {
	if replace {
		sandbox, err := createSandbox(ctx, name, append(append([]m.SandboxOption{}, opts...), m.WithReplace()))
		if err != nil {
			return nil, err
		}
		if err := convergeAfterCreate(ctx, sandbox, state.secrets); err != nil {
			_ = sandbox.Stop(ctx)
			_ = sandbox.Close()
			return nil, err
		}
		return sandbox, nil
	}
	handle, err := m.GetSandbox(ctx, name)
	if err == nil {
		if err := convergeOnReuse(ctx, name, handle, state); err != nil {
			return nil, err
		}
		return handle.ConnectOrStart(ctx)
	}
	if !m.IsKind(err, m.ErrSandboxNotFound) {
		return nil, fmt.Errorf("looking up sandbox %s: %w", name, err)
	}
	sandbox, createErr := createSandbox(ctx, name, opts)
	if createErr == nil {
		if err := convergeAfterCreate(ctx, sandbox, state.secrets); err != nil {
			_ = sandbox.Stop(ctx)
			_ = sandbox.Close()
			return nil, err
		}
		return sandbox, nil
	}
	if m.IsKind(createErr, m.ErrSandboxAlreadyExists) {
		// A concurrent launch created it first; converge on that VM.
		handle, handleErr := m.GetSandbox(ctx, name)
		if handleErr != nil {
			return nil, createErr
		}
		if err := convergeOnReuse(ctx, name, handle, state); err != nil {
			return nil, err
		}
		return handle.ConnectOrStart(ctx)
	}
	return nil, createErr
}

// secretModder is the modify subset shared by Sandbox and SandboxHandle.
type secretModder interface {
	Modify(ctx context.Context, opts m.ModifyOptions) (*m.SandboxModificationPlan, error)
}

// convergeAfterCreate applies secrets to a freshly created sandbox. The VM
// booted without them, so the restart policy reboots it with the secrets in
// place. The stored config of a fresh sandbox carries no secrets yet.
func convergeAfterCreate(ctx context.Context, sandbox *m.Sandbox, desired []project.ResolvedSecret) error {
	if len(desired) == 0 {
		return nil
	}
	plan, err := modifySecrets(ctx, sandbox, sandbox.Name(), nil, desired, m.ModificationPolicyRestart)
	if err != nil {
		return err
	}
	reportModifications(plan, sandbox.Name())
	return nil
}

// convergeOnReuse diffs the stored sandbox config against the desired secrets
// and fixes drift: a stopped VM gets the persisted patch applied for its next
// start; a running VM gets a note instead (its restart is left to the user).
func convergeOnReuse(ctx context.Context, name string, handle *m.SandboxHandle, state launchState) error {
	stored, err := parseStoredSecrets(handle.ConfigJSON())
	if err != nil {
		return fmt.Errorf("sandbox %s: %w", name, err)
	}
	reportPolicyDrift(handle, state.policyFingerprint)
	if handle.Status() == m.SandboxStatusRunning {
		plan, err := modifySecrets(ctx, handle, name, stored, state.secrets, m.ModificationPolicyNextStart)
		if err != nil {
			return err
		}
		if plan != nil {
			slog.Info("sandbox is running; secret changes apply on its next start", "name", name)
		}
		return nil
	}
	if _, err := modifySecrets(ctx, handle, name, stored, state.secrets, m.ModificationPolicyNextStart); err != nil {
		return err
	}
	return nil
}

// reportPolicyDrift tells the user that a reused VM runs an image or network
// policy that is no longer the current one.
func reportPolicyDrift(handle *m.SandboxHandle, fingerprint string) {
	config, err := handle.Config()
	if err != nil || config.Labels == nil {
		return
	}
	stored, ok := config.Labels[labelKey]
	if !ok || stored == fingerprint {
		return
	}
	slog.Warn(
		"the project image or network policy changed since this VM was created; recreate it with --replace to apply it",
	)
}

// modifySecrets builds and applies the convergence patch from the drift
// between stored and desired secrets; it is a no-op without drift.
func modifySecrets(ctx context.Context, modder secretModder, name string, stored []storedSecret,
	desired []project.ResolvedSecret, policy m.ModificationPolicy,
) (*m.SandboxModificationPlan, error) {
	upsert, remove, migrated := secretDrift(stored, desired)
	if len(upsert) == 0 && len(remove) == 0 {
		return nil, nil
	}
	for _, envVar := range migrated {
		slog.Info("migrating the stored plaintext secret to a keychain-backed env reference", "secret", envVar)
	}
	plan, err := modder.Modify(ctx, m.ModifyOptions{
		Secrets:       secretModifySpecs(upsert),
		SecretsRemove: remove,
		Policy:        policy,
	})
	if err != nil {
		return nil, fmt.Errorf("applying secrets to sandbox %s: %w", name, err)
	}
	return plan, nil
}

// reportModifications logs a one-line summary of an applied plan.
func reportModifications(plan *m.SandboxModificationPlan, name string) {
	if plan == nil || len(plan.Changes) == 0 {
		return
	}
	slog.Info("sandbox reboots to apply secret changes", "name", name, "changes", len(plan.Changes))
}

// createSandbox boots a new sandbox, logging creation progress.
func createSandbox(ctx context.Context, name string, opts []m.SandboxOption) (*m.Sandbox, error) {
	slog.Info("creating sandbox", "name", name)
	progress, results := m.CreateSandboxWithProgress(ctx, name, opts...)
	logDone := logCreationProgress(progress)
	result := <-results
	<-logDone
	if result.Err != nil {
		return nil, fmt.Errorf("creating sandbox %s: %w", name, result.Err)
	}
	return result.Sandbox, nil
}

// logCreationProgress logs the image pulling and VM creation.
// Returns a channel closed when the event stream is drained.
func logCreationProgress(events <-chan m.CreationProgress) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		pulled := false
		booted := false
		for event := range events {
			if event.Kind == "pull" && !pulled {
				pulled = true
				slog.Info("pulling image")
			} else if event.Kind == "startup" && !booted {
				booted = true
				slog.Info("booting sandbox")
			}
		}
	}()
	return done
}

// --- durable sandbox secret parsing and drift -------------------------------

// storedSecret is one secret as recorded in a durable sandbox config.
type storedSecret struct {
	EnvVar       string
	Value        string
	Allow        []string
	HeaderFields []string
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
		entries = append(entries, doc.toStoredSecret())
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

func (s storedSecretJSON) toStoredSecret() storedSecret {
	sub := s.Sub
	if sub == nil {
		sub = s.Inject
	}
	var headers []string
	if sub != nil {
		headers = sub.HeaderFields
	}
	return storedSecret{
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

// secretDrift compares the secrets stored in a sandbox config against the
// desired set (both keyed by env var name). It returns the desired secrets to
// upsert, stored secrets to remove, and the upserts that replace a stored raw
// (plaintext) value with a keychain-backed env reference.
func secretDrift(
	stored []storedSecret,
	desired []project.ResolvedSecret,
) (upsert []project.ResolvedSecret, remove, migrated []string) {
	want := make(map[string]project.ResolvedSecret, len(desired))
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
