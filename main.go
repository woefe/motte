// Command motte launches an OpenCode sandbox from a built-in profile.
//
// Usage:
//
//	motte <base|golang|rails|web> [--no-pull] [--replace]
//	motte secrets <add|set|configure|rm|ls|mv>
//
// --no-pull skips the registry pull so a locally loaded image can win.
// The VM is named after the directory you launch from and is reused across
// runs; --replace recreates it instead. Secrets are managed with the secrets
// subcommand and stored in the OS keychain. Behaviour and one-offs: see the
// README.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run launches the profile sandbox or dispatches the secrets subcommand and
// returns the workload's exit code.
func run(args []string) int {
	if len(args) > 0 && args[0] == "secrets" {
		return runSecrets(args[1:])
	}
	profileName, noPull, replace, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	profile, err := loadProfile(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}
	if len(profile.cmd) == 0 {
		fmt.Fprintf(os.Stderr, "motte: profile %s has no cmd to attach to\n", profileName)
		return 1
	}

	// Resolve the effective secrets from the OS keychain and feed them to the
	// runtime via host env vars; the env vars are only needed until the
	// sandbox booted.
	secrets, err := resolveSecrets(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}
	defer unsetSecretEnv(secrets)

	opts, err := sandboxOptions(profile, noPull)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}

	ctx := context.Background()

	// Reuse the installed msb/libkrunfw pair or install the SDK's pinned
	// runtime to ~/.microsandbox.
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "motte: ensuring the microsandbox runtime: %v\n", err)
		return 1
	}

	name, err := sandboxName(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}
	sandbox, err := openSandbox(ctx, name, opts, replace, secrets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "motte: sandbox %s\n", name)

	// Bridge this terminal to the profile's cmd workload; blocks until the
	// workload exits.
	code, attachErr := sandbox.AttachDefault(ctx)

	// Stop always runs, even on attach errors; the named sandbox and its
	// root disk persist across runs.
	if err := sandbox.Stop(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "motte: failed to stop sandbox: %v\n", err)
	}
	if err := sandbox.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "motte: closing sandbox handle: %v\n", err)
	}
	if attachErr != nil {
		fmt.Fprintf(os.Stderr, "motte: attaching to %s: %v\n", name, attachErr)
		return 1
	}
	return code
}

// parseArgs takes a built-in profile name and/or --no-pull and --replace in
// any order. It fails when no profile is given and on anything else.
func parseArgs(args []string) (profile string, noPull, replace bool, err error) {
	set := false
	for _, arg := range args {
		// Every built-in profile name is a valid value; anything else must be
		// a flag.
		if _, ok := builtins[arg]; ok {
			profile = arg
			set = true
			continue
		}
		switch arg {
		case "--no-pull":
			noPull = true
		case "--replace":
			replace = true
		default:
			return "", false, false, fmt.Errorf(
				"unknown argument: %s (expected %s, --no-pull, or --replace)", arg, choices(),
			)
		}
	}
	if !set {
		return "", false, false, fmt.Errorf("no profile given (expected one of %s)", choices())
	}
	return profile, noPull, replace, nil
}

// choices names the built-in profiles for the usage errors: a pipe-joined,
// sorted list.
func choices() string {
	return strings.Join(availableProfiles(), "|")
}

// dirHash returns a short hash of the resolved current working directory, so
// every directory maps to one stable, unique sandbox-name fragment.
// Symlinks are resolved first so linked or renamed paths share a sandbox.
func dirHash() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolving the working directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks in %s: %w", cwd, err)
	}
	sum := sha256.Sum256([]byte(resolved))
	return hex.EncodeToString(sum[:6]), nil
}

// sandboxName returns the msb VM name for a profile in this directory: the
// directory hash is prefixed to the profile name, so the VM persists per
// directory instead of being recreated on every run.
func sandboxName(profileName string) (string, error) {
	hash, err := dirHash()
	if err != nil {
		return "", err
	}
	return hash + "-motte-" + profileName, nil
}

// openSandbox returns a live sandbox for name. With replace set it recreates
// the VM; otherwise it reuses this directory's persisted VM when one exists and
// creates it (streaming pull/boot progress) only when none does yet. The
// effective secrets are converged onto the sandbox config after create and on
// every reuse, so drifted or migrated secrets are fixed per launch.
func openSandbox(
	ctx context.Context,
	name string,
	opts []m.SandboxOption,
	replace bool,
	secrets []secretSpec,
) (*m.Sandbox, error) {
	if replace {
		sandbox, err := createSandbox(ctx, name, append(append([]m.SandboxOption{}, opts...), m.WithReplace()))
		if err != nil {
			return nil, err
		}
		if err := convergeAfterCreate(ctx, sandbox, secrets); err != nil {
			return nil, err
		}
		return sandbox, nil
	}
	handle, err := m.GetSandbox(ctx, name)
	if err == nil {
		if err := convergeOnReuse(ctx, name, handle, secrets); err != nil {
			return nil, err
		}
		return handle.ConnectOrStart(ctx)
	}
	if !m.IsKind(err, m.ErrSandboxNotFound) {
		return nil, fmt.Errorf("looking up sandbox %s: %w", name, err)
	}
	sandbox, createErr := createSandbox(ctx, name, opts)
	if createErr == nil {
		if err := convergeAfterCreate(ctx, sandbox, secrets); err != nil {
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
		if err := convergeOnReuse(ctx, name, handle, secrets); err != nil {
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
func convergeAfterCreate(ctx context.Context, sandbox *m.Sandbox, secrets []secretSpec) error {
	if len(secrets) == 0 {
		return nil
	}
	plan, err := modifySecrets(ctx, sandbox, sandbox.Name(), nil, secrets, m.ModificationPolicyRestart)
	if err != nil {
		return err
	}
	reportModifications(plan, sandbox.Name())
	return nil
}

// convergeOnReuse diffs the stored sandbox config against the desired secrets
// and fixes drift: a stopped VM gets the persisted patch applied for its next
// start; a running VM gets a note instead (its restart is left to the user).
func convergeOnReuse(ctx context.Context, name string, handle *m.SandboxHandle, secrets []secretSpec) error {
	stored, err := parseStoredSecrets(handle.ConfigJSON())
	if err != nil {
		return fmt.Errorf("sandbox %s: %w", name, err)
	}
	if handle.Status() == m.SandboxStatusRunning {
		plan, err := modifySecrets(ctx, handle, name, stored, secrets, m.ModificationPolicyNextStart)
		if err != nil {
			return err
		}
		if plan != nil {
			fmt.Fprintf(os.Stderr,
				"motte: sandbox %s is running; secret changes apply on its next start\n", name)
		}
		return nil
	}
	if _, err := modifySecrets(ctx, handle, name, stored, secrets, m.ModificationPolicyNextStart); err != nil {
		return err
	}
	return nil
}

// modifySecrets builds and applies the convergence patch from the drift
// between stored and desired secrets; it is a no-op without drift.
func modifySecrets(ctx context.Context, modder secretModder, name string, stored []storedSecret,
	secrets []secretSpec, policy m.ModificationPolicy,
) (*m.SandboxModificationPlan, error) {
	upsert, remove, migrated := secretDrift(stored, secrets)
	if len(upsert) == 0 && len(remove) == 0 {
		return nil, nil
	}
	for _, envVar := range migrated {
		fmt.Fprintf(os.Stderr,
			"motte: migrating secret %s: the stored plaintext copy is replaced by a keychain-backed env reference\n",
			envVar)
	}
	if slices.Contains(remove, opencodeSecretName) {
		fmt.Fprintf(
			os.Stderr,
			"motte: removing the formerly built-in secret %s from sandbox %s; re-enable it with: motte secrets add %s\n",
			opencodeSecretName,
			name,
			opencodeSecretName,
		)
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

// reportModifications prints a one-line summary of an applied plan.
func reportModifications(plan *m.SandboxModificationPlan, name string) {
	if plan == nil || len(plan.Changes) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "motte: sandbox %s reboots to apply %d secret change(s)\n", name, len(plan.Changes))
}

// resolveSecrets returns the effective secret set for a launch: scanned from
// the user's secret configs with precedence applied, validated, egress
// extended with their allow entries, and values pulled from the keychain into
// host env vars for the sandbox boot.
func resolveSecrets(p *profile) ([]secretSpec, error) {
	configured, err := scanEffectiveSecrets(p.name)
	if err != nil {
		return nil, err
	}
	if count, err := secretCountAll(); err == nil && count == 0 {
		fmt.Fprintf(os.Stderr,
			"motte: no secrets configured; to store a key for OpenCode in the OS keychain run: motte secrets add %s\n",
			opencodeSecretName)
	}
	var egress []string
	for _, secret := range configured {
		egress = append(egress, secret.allow...)
	}
	p.extendAllow(egress)
	for _, secret := range configured {
		value, err := defaultSecretStore.get(secret.name)
		if errors.Is(err, errSecretNotFound) {
			return nil, fmt.Errorf(
				"secret %s is not in the keychain — set it with: motte secrets set %s",
				secret.name, secret.name)
		}
		if err != nil {
			return nil, err
		}
		if err := os.Setenv(secretHostEnvVar(secret.envVar), value); err != nil {
			return nil, fmt.Errorf("exporting %s: %w", secretHostEnvVar(secret.envVar), err)
		}
	}
	return configured, nil
}

// unsetSecretEnv clears the host env vars secrets resolve through.
func unsetSecretEnv(secrets []secretSpec) {
	for _, secret := range secrets {
		_ = os.Unsetenv(secretHostEnvVar(secret.envVar))
	}
}

// createSandbox boots a new sandbox, streaming creation progress to stderr.
func createSandbox(ctx context.Context, name string, opts []m.SandboxOption) (*m.Sandbox, error) {
	progress, results := m.CreateSandboxWithProgress(ctx, name, opts...)
	displayDone := displayCreationProgress(progress)
	result := <-results
	<-displayDone
	if result.Err != nil {
		return nil, fmt.Errorf("creating sandbox %s: %w", name, result.Err)
	}
	return result.Sandbox, nil
}

// displayCreationProgress renders sandbox-creation progress (image pull, VM
// boot) to stderr as a single updating line while creation runs.
// It returns a channel closed when the event stream ends.
func displayCreationProgress(events <-chan m.CreationProgress) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if !isCharDevice(os.Stderr) {
			for range events { // drain so telemetry never stalls creation
			}
			return
		}
		var last string
		for event := range events {
			line := creationProgressLine(event)
			if line == "" || line == last {
				continue
			}
			if pad := len(last) - len(line); pad > 0 {
				line += strings.Repeat(" ", pad) // erase leftovers
			}
			fmt.Fprintf(os.Stderr, "\r%s", line)
			last = line
		}
		if last != "" {
			fmt.Fprintln(os.Stderr)
		}
	}()
	return done
}

// creationProgressLine renders one creation event as a short status line.
func creationProgressLine(event m.CreationProgress) string {
	detail := event.Progress
	switch event.Kind {
	case "pull":
		return pullProgressLine(detail)
	case "startup":
		line := startupPhase(detail.Phase)
		if detail.TotalBytes != nil && *detail.TotalBytes > 0 {
			line += fmt.Sprintf(" — %d / %d MiB", detail.CompletedBytes>>20, *detail.TotalBytes>>20)
		}
		return line
	default:
		return detail.Phase
	}
}

// pullProgressLine renders one image-pull event.
func pullProgressLine(d m.CreationProgressDetail) string {
	layer := ""
	// Early pull events carry a layer count but no layer index yet.
	if d.LayerCount != nil && d.LayerIndex != nil && *d.LayerCount > 0 {
		layer = fmt.Sprintf("layer %d/%d: ", *d.LayerIndex+1, *d.LayerCount)
	}
	switch d.Kind {
	case "resolving":
		return fmt.Sprintf("pulling %s: resolving", d.Reference)
	case "resolved":
		return fmt.Sprintf("pulling %s: %d layers", d.Reference, deref(d.LayerCount))
	case "layer_download_progress":
		return layer + "downloading " + byteProgress(d.DownloadedBytes, d.TotalBytes)
	case "layer_download_verifying":
		return layer + "verifying"
	case "layer_download_complete":
		return layer + "downloaded"
	case "layer_materialize_started":
		return layer + "materializing"
	case "layer_materialize_progress":
		return layer + "materializing " + byteProgress(d.BytesRead, d.TotalBytes)
	case "layer_materialize_writing":
		return layer + "writing erofs"
	case "layer_materialize_complete":
		return layer + "materialized"
	case "stitch_merging_trees":
		return "stitching: merging layers"
	case "stitch_writing_fsmeta":
		return "stitching: fsmeta"
	case "stitch_writing_vmdk":
		return "stitching: vmdk"
	case "stitch_done":
		return "pull complete"
	default:
		return ""
	}
}

// startupPhase renders one VM startup phase.
func startupPhase(phase string) string {
	switch phase {
	case "preparing_snapshot":
		return "preparing sandbox"
	case "waiting_for_memory_backing":
		return "waiting for RAM backing"
	case "preparing_memory_backing":
		return "preparing RAM backing"
	case "reusing_memory_backing":
		return "reusing RAM backing"
	case "syncing_memory_backing":
		return "syncing RAM backing"
	case "activating":
		return "activating sandbox"
	default:
		return phase
	}
}

// byteProgress renders completed of total bytes with a percentage.
func byteProgress(done uint64, total *uint64) string {
	if total == nil || *total == 0 {
		return humanBytes(done)
	}
	return fmt.Sprintf("%s / %s (%d%%)", humanBytes(done), humanBytes(*total), done*100 / *total)
}

// humanBytes renders a byte count in binary units.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	size := float64(n)
	var suffix string
	for size >= unit && suffix != "GiB" {
		size /= unit
		switch suffix {
		case "":
			suffix = "KiB"
		case "KiB":
			suffix = "MiB"
		case "MiB":
			suffix = "GiB"
		}
	}
	return fmt.Sprintf("%.1f %s", size, suffix)
}

func deref[T any](v *T) T {
	if v == nil {
		var zero T
		return zero
	}
	return *v
}

// isCharDevice reports whether f is a character device such as a terminal.
func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
