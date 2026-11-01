// The launcher: motte's boot flow. It assembles the effective profile (the
// built-in definition with the user's network policy entries merged in),
// resolves the keychain secrets, creates or reuses this directory's sandbox
// via the microsandbox Go SDK, converges the sandbox's secrets onto the
// desired set, and attaches the terminal to the profile's workload.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/profile"
	"github.com/woefe/motte/internal/secrets"
)

// Boot launches the profile's sandbox and returns the workload's exit code.
func Boot(profileName string, noPull, replace bool) (int, error) {
	p, err := loadProfile(profileName)
	if err != nil {
		return 1, err
	}
	if len(p.Cmd) == 0 {
		return 1, fmt.Errorf("profile %s has no cmd to attach to", profileName)
	}

	// Resolve the effective secrets from the OS keychain and feed them to the
	// runtime via host env vars; the env vars are only needed until the
	// sandbox booted.
	resolved, err := resolveSecrets(p)
	if err != nil {
		return 1, err
	}
	defer unsetSecretEnv(resolved)

	opts, err := sandboxOptions(p, noPull)
	if err != nil {
		return 1, err
	}

	ctx := context.Background()

	// Reuse the installed msb/libkrunfw pair or install the SDK's pinned
	// runtime to ~/.microsandbox.
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		return 1, fmt.Errorf("ensuring the microsandbox runtime: %w", err)
	}

	name, err := sandboxName(profileName)
	if err != nil {
		return 1, err
	}
	fingerprint := policies.Fingerprint(p)
	state := launchState{secrets: resolved, policyFingerprint: fingerprint}
	sandbox, err := openSandbox(ctx, name, opts, replace, state)
	if err != nil {
		return 1, err
	}
	slog.Info("using sandbox", "name", name)

	// Bridge this terminal to the profile's cmd workload; blocks until the
	// workload exits.
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

// loadProfile returns the effective profile: the built-in definition with
// the user's policy entries merged on top of the built-in egress policy.
func loadProfile(name string) (*profile.Profile, error) {
	p, err := profile.Load(name)
	if err != nil {
		return nil, err
	}
	extra, err := policies.Allow(name)
	if err != nil {
		return nil, err
	}
	p.ExtendAllow(extra)
	return p, nil
}

// sandboxName returns the msb VM name for a profile in this directory: the
// directory hash is prefixed to the profile name, so the VM persists per
// directory instead of being recreated on every run.
func sandboxName(profileName string) (string, error) {
	hash, err := config.DirHash()
	if err != nil {
		return "", err
	}
	return hash + "-motte-" + profileName, nil
}

// launchState is the desired state of a launch: the resolved secrets and the
// fingerprint of the effective network policy.
type launchState struct {
	secrets           []secrets.Spec
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
func convergeAfterCreate(ctx context.Context, sandbox *m.Sandbox, desired []secrets.Spec) error {
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
	stored, err := secrets.ParseStored(handle.ConfigJSON())
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

// reportPolicyDrift tells the user that a reused VM runs a network policy
// that is no longer the current one. The policy is part of the sandbox
// config, so it only reaches a recreated VM.
func reportPolicyDrift(handle *m.SandboxHandle, fingerprint string) {
	config, err := handle.Config()
	if err != nil || config.Labels == nil {
		return
	}
	stored, ok := config.Labels[policies.LabelKey]
	if !ok || stored == fingerprint {
		return
	}
	slog.Warn("the network policy changed since this VM was created; recreate it with --replace to apply it")
}

// modifySecrets builds and applies the convergence patch from the drift
// between stored and desired secrets; it is a no-op without drift.
func modifySecrets(ctx context.Context, modder secretModder, name string, stored []secrets.Stored,
	desired []secrets.Spec, policy m.ModificationPolicy,
) (*m.SandboxModificationPlan, error) {
	upsert, remove, migrated := secrets.Drift(stored, desired)
	if len(upsert) == 0 && len(remove) == 0 {
		return nil, nil
	}
	for _, envVar := range migrated {
		slog.Info("migrating the stored plaintext secret to a keychain-backed env reference", "secret", envVar)
	}
	if slices.Contains(remove, secrets.OpencodeSecretName) {
		slog.Info("removing the formerly built-in secret from the sandbox; re-enable it with: motte secrets add",
			"sandbox", name, "secret", secrets.OpencodeSecretName)
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

// resolveSecrets returns the effective secret set for a launch: scanned from
// the user's secret configs with precedence applied, validated, egress
// extended with their allow entries, and values pulled from the keychain into
// host env vars for the sandbox boot.
func resolveSecrets(p *profile.Profile) ([]secrets.Spec, error) {
	configured, err := secrets.ScanEffective(p.Name)
	if err != nil {
		return nil, err
	}
	if count, err := secrets.CountAll(); err == nil && count == 0 {
		slog.Info("no secrets configured; store the OpenCode key in the OS keychain with: motte secrets add",
			"secret", secrets.OpencodeSecretName)
	}
	var egress []string
	for _, secret := range configured {
		egress = append(egress, secret.Allow...)
	}
	p.ExtendAllow(egress)
	for _, secret := range configured {
		value, err := secrets.DefaultStore.Get(secret.Name)
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, fmt.Errorf(
				"secret %s is not in the keychain — set it with: motte secrets set %s",
				secret.Name, secret.Name)
		}
		if err != nil {
			return nil, err
		}
		if err := os.Setenv(secrets.HostEnvVar(secret.EnvVar), value); err != nil {
			return nil, fmt.Errorf("exporting %s: %w", secrets.HostEnvVar(secret.EnvVar), err)
		}
	}
	return configured, nil
}

// unsetSecretEnv clears the host env vars secrets resolve through.
func unsetSecretEnv(specs []secrets.Spec) {
	for _, secret := range specs {
		_ = os.Unsetenv(secrets.HostEnvVar(secret.EnvVar))
	}
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
