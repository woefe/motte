// The launcher: motte's boot flow. It reads this directory's project config,
// merges the always-on base policy, the selected policy groups, and the
// project's extra allow entries into one allow list, mounts the user's
// OpenCode config, resolves the keychain secrets, creates or reuses this
// directory's sandbox via the microsandbox Go SDK, converges the sandbox's
// secrets onto the desired set, and attaches the terminal to the workload.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/secrets"
)

// Boot launches this directory's project sandbox and returns the workload's
// exit code.
func Boot(noPull, replace bool) (int, error) {
	proj, projectPath, err := loadProject()
	if err != nil {
		return 1, err
	}
	allow, err := EffectiveAllow(proj, projectPath)
	if err != nil {
		return 1, err
	}

	// Resolve the project's selected secrets from the OS keychain and feed
	// them to the runtime via host env vars; the env vars are cleared once the
	// sandbox has booted.
	resolved, err := resolveSecrets(proj.Secrets, secrets.DefaultStore())
	if err != nil {
		return 1, err
	}
	defer unsetSecretEnv(resolved)

	opts, err := sandboxOptions(proj.Image, allow, noPull)
	if err != nil {
		return 1, err
	}

	ctx := context.Background()

	// Reuse the installed msb/libkrunfw pair or install the SDK's pinned
	// runtime to ~/.microsandbox.
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		return 1, fmt.Errorf("ensuring the microsandbox runtime: %w", err)
	}

	name, err := sandboxName()
	if err != nil {
		return 1, err
	}
	fingerprint := policies.Fingerprint(proj.Image, allow)
	state := launchState{secrets: resolved, policyFingerprint: fingerprint}
	sandbox, err := openSandbox(ctx, name, opts, replace, state)
	unsetSecretEnv(resolved)
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

// loadProject reads the current directory's project config, or fails with a
// hint to run `motte init` when none exists yet.
func loadProject() (project.Config, string, error) {
	proj, path, err := project.ReadCurrent()
	if errors.Is(err, project.ErrNotFound) {
		return project.Config{}, path, fmt.Errorf(
			"no project configured for this directory (%s); run `motte init` first",
			path,
		)
	}
	if err != nil {
		return project.Config{}, path, err
	}
	return proj, path, nil
}

// EffectiveAllow computes the deduplicated egress allow list for a project
// config: the always-on base policy plus every selected policy group plus the
// project's network.allow entries. A selected group without a file fails with
// projectPath in the error.
func EffectiveAllow(proj project.Config, projectPath string) ([]string, error) {
	allow := policies.BaseAllow()
	for _, group := range proj.AllowGroups {
		entries, err := policies.ReadGroup(group)
		if errors.Is(err, policies.ErrGroupNotFound) {
			return nil, fmt.Errorf(
				"project config %s: policy group %q does not exist; create it with `motte policies configure %s`",
				projectPath, group, group,
			)
		}
		if err != nil {
			return nil, err
		}
		allow = policies.ExtendAllow(allow, entries)
	}
	allow = policies.ExtendAllow(allow, proj.Allow)
	return allow, nil
}

// sandboxName returns the msb VM name for this directory: `motte-<dir-hash>`.
func sandboxName() (string, error) {
	hash, err := config.DirHash()
	if err != nil {
		return "", err
	}
	return "motte-" + hash, nil
}

// launchState is the desired state of a launch: the resolved secrets and the
// fingerprint of the image and effective network policy.
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

// reportPolicyDrift tells the user that a reused VM runs an image or network
// policy that is no longer the current one.
func reportPolicyDrift(handle *m.SandboxHandle, fingerprint string) {
	config, err := handle.Config()
	if err != nil || config.Labels == nil {
		return
	}
	stored, ok := config.Labels[policies.LabelKey]
	if !ok || stored == fingerprint {
		return
	}
	slog.Warn(
		"the project image or network policy changed since this VM was created; recreate it with --replace to apply it",
	)
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

// resolveSecrets loads the settings and keychain values of the selected secret
// names into host env vars for the sandbox boot. Secret allow hosts do not
// widen the network egress allow list.
func resolveSecrets(selected []string, store secrets.Store) ([]secrets.Spec, error) {
	var resolved []secrets.Spec
	seen := make(map[string]bool, len(selected))
	for _, name := range selected {
		if seen[name] {
			continue
		}
		seen[name] = true
		spec, err := secrets.Read(name)
		if errors.Is(err, secrets.ErrNotFound) {
			unsetSecretEnv(resolved)
			return nil, fmt.Errorf(
				"secret %s is not configured — create it with: motte secrets add",
				name,
			)
		}
		if err != nil {
			unsetSecretEnv(resolved)
			return nil, err
		}
		value, err := store.Get(spec.Name)
		if errors.Is(err, secrets.ErrNotFound) {
			unsetSecretEnv(resolved)
			return nil, fmt.Errorf(
				"secret %s is not in the keychain — set it with: motte secrets set %s",
				spec.Name, spec.Name,
			)
		}
		if err != nil {
			unsetSecretEnv(resolved)
			return nil, err
		}
		if err := os.Setenv(secrets.HostEnvVar(spec.EnvVar), value); err != nil {
			unsetSecretEnv(resolved)
			return nil, fmt.Errorf("exporting %s: %w", secrets.HostEnvVar(spec.EnvVar), err)
		}
		resolved = append(resolved, spec)
	}
	return resolved, nil
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
