// Command motte launches an OpenCode sandbox from a profile in sandboxes/.
//
// Usage:
//
//	go run . <golang|web> [--no-pull]
//
// --no-pull skips the registry pull so a locally loaded image can win.
// Behaviour, prerequisites, and one-offs: see the README.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run launches the profile sandbox and returns the workload's exit code.
func run(args []string) int {
	profileName, noPull, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	profile, err := loadProfile(filepath.Join(sourceDir(), "sandboxes"), profileName, os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}
	if len(profile.cmd) == 0 {
		fmt.Fprintf(os.Stderr, "motte: profile %s has no cmd to attach to; set cmd in sandboxes/*.yaml\n", profileName)
		return 1
	}

	opts, err := sandboxOptions(profile, noPull)
	if err != nil {
		fmt.Fprintf(os.Stderr, "motte: %v\n", err)
		return 1
	}

	ctx := context.Background()

	// Reuse the installed msb/libkrunfw pair or install the SDK's pinned
	// runtime (to ~/.microsandbox), like the SDK docs' setup helper.
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "motte: ensuring the microsandbox runtime: %v\n", err)
		return 1
	}

	name := "motte-" + profileName
	progress, results := m.CreateSandboxWithProgress(ctx, name, opts...)
	displayDone := displayCreationProgress(progress)
	result := <-results
	<-displayDone
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "motte: creating sandbox %s: %v\n", name, result.Err)
		return 1
	}
	sandbox := result.Sandbox

	// Bridge this terminal to the profile's cmd workload (the old
	// `msb run -t`); blocks until the workload exits.
	code, attachErr := sandbox.AttachDefault(ctx)

	// Stop always runs, even on attach errors; the named sandbox and its
	// root disk persist for the README's one-offs, as with the old run.sh.
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

// parseArgs takes a profile name and/or --no-pull in any order.
// It fails when no profile is given and on anything else.
func parseArgs(args []string) (profile string, noPull bool, err error) {
	set := false
	for _, arg := range args {
		switch arg {
		case "golang", "web":
			profile = arg
			set = true
		case "--no-pull":
			noPull = true
		default:
			return "", false, fmt.Errorf("unknown argument: %s (expected golang|web or --no-pull)", arg)
		}
	}
	if !set {
		return "", false, fmt.Errorf("no profile given (expected golang|web)")
	}
	return profile, noPull, nil
}

// sourceDir returns the directory of this source file: the repo root, like the
// old run.sh's `cd "$(dirname "$0")"`.
// It keeps the sandboxes/ configs next to the launcher regardless of the
// working directory it is started from.
func sourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
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
