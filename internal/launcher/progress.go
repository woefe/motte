// Logging of sandbox-creation progress: one slog line per image-pull or
// VM-boot stage.
package launcher

import (
	"fmt"
	"log/slog"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

// logCreationProgress logs one line per new creation stage — the image pull
// and the VM boot — and returns a channel closed when the event stream is
// drained.
func logCreationProgress(events <-chan m.CreationProgress) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		logged := make(map[string]bool)
		for event := range events {
			switch event.Kind {
			case "pull":
				stage := pullStage(event.Progress)
				if stage == "" || logged[stage] {
					continue
				}
				logged[stage] = true
				slog.Info("pulling image", "stage", stage)
			case "startup":
				stage := startupStage(event.Progress.Phase)
				if stage == "" || logged[stage] {
					continue
				}
				logged[stage] = true
				slog.Info("booting sandbox", "stage", stage)
			}
		}
	}()
	return done
}

// pullStage labels one image-pull event. Byte counters are not logged; the
// progress and writing events of a stage collapse into its single line.
func pullStage(d m.CreationProgressDetail) string {
	target := "image"
	if d.LayerIndex != nil {
		target = fmt.Sprintf("layer %d", *d.LayerIndex+1)
		if d.LayerCount != nil && *d.LayerCount > 0 {
			target = fmt.Sprintf("layer %d/%d", *d.LayerIndex+1, *d.LayerCount)
		}
	}
	switch d.Kind {
	case "resolving":
		return "resolving"
	case "resolved":
		return "resolved"
	case "layer_download_progress":
		return "downloading " + target
	case "layer_download_verifying":
		return "verifying " + target
	case "layer_download_complete":
		return "downloaded " + target
	case "layer_materialize_started", "layer_materialize_progress", "layer_materialize_writing":
		return "materializing " + target
	case "layer_materialize_complete":
		return "materialized " + target
	case "stitch_merging_trees", "stitch_writing_fsmeta", "stitch_writing_vmdk":
		return "stitching layers"
	case "stitch_done":
		return "complete"
	default:
		return ""
	}
}

// startupStage labels one VM startup phase; unknown phases pass through so
// new runtime phases stay visible in the log.
func startupStage(phase string) string {
	switch phase {
	case "preparing_snapshot":
		return "preparing snapshot"
	case "waiting_for_memory_backing":
		return "waiting for RAM backing"
	case "preparing_memory_backing":
		return "preparing RAM backing"
	case "reusing_memory_backing":
		return "reusing RAM backing"
	case "syncing_memory_backing":
		return "syncing RAM backing"
	case "activating":
		return "activating"
	default:
		return phase
	}
}
