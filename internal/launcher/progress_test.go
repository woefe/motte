package launcher

import (
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/testutil"
)

// TestPullStage covers the stage labels of the image-pull events, including
// the early events that carry a layer count but no layer index yet.
func TestPullStage(t *testing.T) {
	count, index := uint64(12), uint64(2)
	tests := []struct {
		name string
		d    m.CreationProgressDetail
		want string
	}{
		{"resolving", m.CreationProgressDetail{Kind: "resolving"}, "resolving"},
		{"resolved", m.CreationProgressDetail{Kind: "resolved"}, "resolved"},
		{
			"downloading with the layer numbers",
			m.CreationProgressDetail{Kind: "layer_download_progress", LayerCount: &count, LayerIndex: &index},
			"downloading layer 3/12",
		},
		{
			"downloading before the layer index arrives",
			m.CreationProgressDetail{Kind: "layer_download_progress", LayerCount: &count},
			"downloading image",
		},
		{
			"verifying",
			m.CreationProgressDetail{Kind: "layer_download_verifying", LayerIndex: &index},
			"verifying layer 3",
		},
		{
			"downloaded",
			m.CreationProgressDetail{Kind: "layer_download_complete", LayerIndex: &index},
			"downloaded layer 3",
		},
		{
			"materializing collapses its sub-stages",
			m.CreationProgressDetail{Kind: "layer_materialize_writing", LayerCount: &count, LayerIndex: &index},
			"materializing layer 3/12",
		},
		{"materialized", m.CreationProgressDetail{Kind: "layer_materialize_complete"}, "materialized image"},
		{"stitching", m.CreationProgressDetail{Kind: "stitch_writing_vmdk"}, "stitching layers"},
		{"complete", m.CreationProgressDetail{Kind: "stitch_done"}, "complete"},
		{"unknown kind", m.CreationProgressDetail{Kind: "something_new"}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pullStage(test.d); got != test.want {
				t.Errorf("pullStage = %q, want %q", got, test.want)
			}
		})
	}
}

// TestStartupStage covers the startup phase labels; unknown phases pass
// through so new runtime phases stay visible in the log.
func TestStartupStage(t *testing.T) {
	tests := []struct{ phase, want string }{
		{"preparing_snapshot", "preparing snapshot"},
		{"waiting_for_memory_backing", "waiting for RAM backing"},
		{"preparing_memory_backing", "preparing RAM backing"},
		{"reusing_memory_backing", "reusing RAM backing"},
		{"syncing_memory_backing", "syncing RAM backing"},
		{"activating", "activating"},
		{"brand_new_phase", "brand_new_phase"},
		{"", ""},
	}
	for _, test := range tests {
		if got := startupStage(test.phase); got != test.want {
			t.Errorf("startupStage(%q) = %q, want %q", test.phase, got, test.want)
		}
	}
}

// TestLogCreationProgress logs one line per stage: byte-counter repeats and
// duplicate phases collapse, and events without a stage stay out of the log.
func TestLogCreationProgress(t *testing.T) {
	buf := testutil.SwapLogger(t)
	count, index := uint64(12), uint64(2)
	events := make(chan m.CreationProgress, 8)
	for _, event := range []m.CreationProgress{
		{Kind: "pull", Progress: m.CreationProgressDetail{Kind: "resolving"}},
		{Kind: "pull", Progress: m.CreationProgressDetail{
			Kind: "layer_download_progress", LayerCount: &count, LayerIndex: &index,
		}},
		{Kind: "pull", Progress: m.CreationProgressDetail{
			Kind: "layer_download_progress", LayerCount: &count, LayerIndex: &index, DownloadedBytes: 1 << 20,
		}},
		{Kind: "startup", Progress: m.CreationProgressDetail{Phase: "activating"}},
		{Kind: "startup", Progress: m.CreationProgressDetail{Phase: "activating"}},
		{Kind: "pull", Progress: m.CreationProgressDetail{Kind: "something_new"}},
	} {
		events <- event
	}
	close(events)
	<-logCreationProgress(events)

	logged := buf.String()
	if got := strings.Count(logged, `msg="pulling image"`); got != 2 {
		t.Errorf("pulling image logged %d times, want 2:\n%s", got, logged)
	}
	if got := strings.Count(logged, `msg="booting sandbox"`); got != 1 {
		t.Errorf("booting sandbox logged %d times, want 1:\n%s", got, logged)
	}
	if got := strings.Count(logged, "downloading layer 3/12"); got != 1 {
		t.Errorf("downloading stage logged %d times, want 1:\n%s", got, logged)
	}
	if strings.Contains(logged, "something_new") {
		t.Errorf("an event without a stage leaked into the log:\n%s", logged)
	}
}
