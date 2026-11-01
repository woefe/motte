// Rendering of sandbox-creation progress: the single updating stderr line
// for the image pull and the VM boot.
package launcher

import (
	"fmt"
	"os"
	"strings"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

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
