package launcher

import (
	"strings"
	"testing"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/testutil"
)

// TestLogCreationProgress logs each stage once despite repeated events, and
// closes the returned channel after the event stream drains.
func TestLogCreationProgress(t *testing.T) {
	events := make(chan m.CreationProgress, 8)
	for _, kind := range []string{"pull", "pull", "startup", "startup"} {
		events <- m.CreationProgress{Kind: kind}
	}
	close(events)

	buf := testutil.SwapLogger(t)
	done := logCreationProgress(events)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("done did not close after the event stream drained")
	}
	for _, msg := range []string{"pulling image", "booting sandbox"} {
		if got := strings.Count(buf.String(), msg); got != 1 {
			t.Errorf("%q logged %d times, want once; log: %s", msg, got, buf.String())
		}
	}
}

// TestLogCreationProgressSkipsUnknownKinds: unknown kinds log nothing but
// still drain and close the channel.
func TestLogCreationProgressSkipsUnknownKinds(t *testing.T) {
	events := make(chan m.CreationProgress, 2)
	events <- m.CreationProgress{Kind: "layer"}
	close(events)

	buf := testutil.SwapLogger(t)
	done := logCreationProgress(events)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("done did not close after the event stream drained")
	}
	if got := buf.String(); got != "" {
		t.Errorf("log for unknown events = %q, want empty", got)
	}
}

// TestParseStoredSecrets covers the durable config shapes: array or map,
// HostPattern objects or strings, and the injection alias.
func TestParseStoredSecrets(t *testing.T) {
	arrayShape := `{"network":{"secrets":{"secrets":[
		{"env_var":"EXAMPLE_API_KEY","value":"","source":{"kind":"env","var":"MOTTE_SECRET_EXAMPLE_API_KEY"},
		 "allowed_hosts":[{"wildcard":"*.opencode.ai"},{"exact":"api.example.com"}],
		 "substitution":{"headers":true,"header_fields":["authorization"]}},
		{"env_var":"legacy","value":"plaintext","allowed_hosts":["legacy.example.com"],
		 "injection":{"header_fields":["origin"]}}]}}}`
	stored, err := parseStoredSecrets(arrayShape)
	if err != nil {
		t.Fatalf("parseStoredSecrets: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored = %+v, want 2", stored)
	}
	first := stored[0]
	if first.EnvVar != "EXAMPLE_API_KEY" || first.Value != "" ||
		len(first.Allow) != 2 || first.Allow[0] != "*.opencode.ai" || first.Allow[1] != "api.example.com" ||
		len(first.HeaderFields) != 1 || first.HeaderFields[0] != "authorization" {
		t.Errorf("first = %+v", first)
	}
	if second := stored[1]; second.EnvVar != "legacy" || second.Value != "plaintext" ||
		len(second.Allow) != 1 || second.Allow[0] != "legacy.example.com" ||
		len(second.HeaderFields) != 1 || second.HeaderFields[0] != "origin" {
		t.Errorf("second = %+v", second)
	}

	mapShape := `{"network":{"secrets":{"secrets":{"open_key":
		{"env_var":"OPEN_KEY","value":"","allowed_hosts":[{"exact":"ok.example.com"}]}}}}}`
	stored, err = parseStoredSecrets(mapShape)
	if err != nil {
		t.Fatalf("parseStoredSecrets(map): %v", err)
	}
	if len(stored) != 1 || stored[0].EnvVar != "OPEN_KEY" || stored[0].Allow[0] != "ok.example.com" {
		t.Fatalf("map stored = %+v", stored)
	}

	// No secrets section, no entries.
	if stored, err := parseStoredSecrets(`{"network":{}}`); err != nil || stored != nil {
		t.Fatalf("empty config = %v %v", stored, err)
	}
}

// TestSecretDrift compares stored against desired: adds, raw migrations, host
// policy changes, and removals.
func TestSecretDrift(t *testing.T) {
	desired := []project.ResolvedSecret{
		{
			EnvVar:       "a_key",
			HostEnv:      "MOTTE_SECRET_a_key",
			Allow:        []string{"a.example.com"},
			HeaderFields: []string{"authorization"},
		},
		{
			EnvVar:       "b_key",
			HostEnv:      "MOTTE_SECRET_b_key",
			Allow:        []string{"b.example.com"},
			HeaderFields: []string{"authorization"},
		},
	}

	// Nothing stored: everything is an add.
	upsert, remove, migrated := secretDrift(nil, desired)
	if len(upsert) != 2 || len(remove) != 0 || len(migrated) != 0 {
		t.Fatalf("nil stored: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Matching env-source stored secrets: no drift.
	upsert, remove, migrated = secretDrift([]storedSecret{
		{EnvVar: "a_key", Allow: []string{"a.example.com"}, HeaderFields: []string{"authorization"}},
		{EnvVar: "b_key", Allow: []string{"b.example.com"}, HeaderFields: []string{"authorization"}},
	}, desired)
	if len(upsert) != 0 || len(remove) != 0 || len(migrated) != 0 {
		t.Fatalf("matching: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Raw plaintext stored value: migrates to an env reference; the desired
	// b_key is not stored, so it is added in the same patch.
	upsert, remove, migrated = secretDrift([]storedSecret{
		{
			EnvVar:       "a_key",
			Value:        "plaintext",
			Allow:        []string{"a.example.com"},
			HeaderFields: []string{"authorization"},
		},
	}, desired)
	if len(upsert) != 2 || upsert[0].EnvVar != "a_key" || upsert[1].EnvVar != "b_key" ||
		len(migrated) != 1 || migrated[0] != "a_key" || len(remove) != 0 {
		t.Fatalf("raw: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// A host mismatch changes the stored rule; b_key is additionally added.
	upsert, remove, migrated = secretDrift([]storedSecret{
		{EnvVar: "a_key", Allow: []string{"other.example.com"}, HeaderFields: []string{"authorization"}},
	}, desired)
	if len(upsert) != 2 || upsert[0].EnvVar != "a_key" || len(migrated) != 0 {
		t.Fatalf("host mismatch: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Stored secrets not desired are removed.
	upsert, remove, migrated = secretDrift([]storedSecret{{EnvVar: "stale_key"}}, nil)
	if len(upsert) != 0 || len(remove) != 1 || remove[0] != "stale_key" || len(migrated) != 0 {
		t.Fatalf("stale: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}
}
