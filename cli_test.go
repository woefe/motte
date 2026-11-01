package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// execute runs the command tree with args and returns the error it produced.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	root := newRootCommand()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root.Execute()
}

// TestLabelScope renders the shared scope labels: "global", "profile <name>",
// and "project <hash>" with the current-directory mark.
func TestLabelScope(t *testing.T) {
	tests := []struct {
		profile, hash string
		thisDir       bool
		want          string
	}{
		{want: "global"},
		{profile: "golang", want: "profile golang"},
		{hash: "1234567890ab", want: "project 1234567890ab"},
		{hash: "1234567890ab", thisDir: true, want: "project 1234567890ab (this directory)"},
	}
	for _, test := range tests {
		if got := labelScope(test.profile, test.hash, test.thisDir); got != test.want {
			t.Errorf("labelScope(%q, %q, %v) = %q, want %q",
				test.profile, test.hash, test.thisDir, got, test.want)
		}
	}
}

// TestOpenCodeBootsTheProfile checks that both command names resolve and hand
// the profile and their flags to the boot.
func TestOpenCodeBootsTheProfile(t *testing.T) {
	original := boot
	t.Cleanup(func() { boot = original })
	tests := []struct {
		name    string
		args    []string
		profile string
		noPull  bool
		replace bool
	}{
		{name: "oc", args: []string{"oc", "golang", "--replace"}, profile: "golang", replace: true},
		{
			name: "opencode", args: []string{"opencode", "web", "--no-pull", "--replace"},
			profile: "web", noPull: true, replace: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotProfile string
			var gotNoPull, gotReplace bool
			boot = func(profile string, noPull, replace bool) (int, error) {
				gotProfile, gotNoPull, gotReplace = profile, noPull, replace
				return 0, nil
			}
			if err := execute(t, test.args...); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if gotProfile != test.profile || gotNoPull != test.noPull || gotReplace != test.replace {
				t.Errorf("boot(%q, no-pull=%v, replace=%v), want (%q, no-pull=%v, replace=%v)",
					gotProfile, gotNoPull, gotReplace, test.profile, test.noPull, test.replace)
			}
		})
	}

	// The command takes exactly one profile.
	for _, args := range [][]string{{"oc"}, {"oc", "golang", "web"}} {
		if err := execute(t, args...); err == nil {
			t.Errorf("execute(%v) = nil, want a usage error", args)
		}
	}
}

// TestRootCommandErrors covers the invocation without a subcommand: the help
// is printed and the known profile names get a hint.
func TestRootCommandErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		wantRe string
	}{
		{name: "no command", wantRe: ""},
		{name: "profile name", args: []string{"golang"}, wantRe: `did you mean "motte oc golang"`},
		{name: "typo", args: []string{"secretes"}, wantRe: `did you mean "motte secrets"`},
		{name: "unknown", args: []string{"frobnicate"}, wantRe: "expected opencode, oc, policies, or secrets"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := execute(t, test.args...)
			if err == nil {
				t.Fatal("error = nil, want a failure")
			}
			if test.wantRe != "" && !strings.Contains(err.Error(), test.wantRe) {
				t.Errorf("error = %v, want containing %q", err, test.wantRe)
			}
			var coded exitCoder
			if !errors.As(err, &coded) || coded.code != 1 {
				t.Errorf("exit code = %v, want 1", err)
			}
		})
	}
}

// TestSecretsCommandErrors covers the usage errors of the secrets
// subcommands.
func TestSecretsCommandErrors(t *testing.T) {
	for _, args := range [][]string{
		{"secrets"},
		{"secrets", "bogus"},
		{"secrets", "set"},
		{"secrets", "set", "a", "b"},
		{"secrets", "configure"},
		{"secrets", "rm"},
		{"secrets", "rm", "a", "b"},
		{"secrets", "add", "a"},
		{"secrets", "ls", "a"},
		{"secrets", "configure", "bogus"},
	} {
		if err := execute(t, args...); err == nil {
			t.Errorf("execute(%v) = nil, want a usage error", args)
		}
	}
}

// TestPoliciesCommandErrors covers the usage errors of the policies
// subcommands.
func TestPoliciesCommandErrors(t *testing.T) {
	for _, args := range [][]string{
		{"policies"},
		{"policies", "bogus"},
		{"policies", "configure"},
		{"policies", "configure", "bogus"},
		{"policies", "ls", "a"},
	} {
		if err := execute(t, args...); err == nil {
			t.Errorf("execute(%v) = nil, want a usage error", args)
		}
	}
}

// TestRunExitCodes checks the exit code run returns and what it prints for a
// failing and a succeeding command.
func TestRunExitCodes(t *testing.T) {
	isolatedConfigDir(t)
	tests := []struct {
		name   string
		args   []string
		want   int
		wantRe string // expected stderr substring
	}{
		{
			name: "coded message", args: []string{"motte", "golang"},
			want: 1, wantRe: `unknown command "golang"; did you mean "motte oc golang"`,
		},
		{
			name: "usage error", args: []string{"motte", "policies", "ls", "a"},
			want: 1, wantRe: "unknown command",
		},
		{name: "success", args: []string{"motte", "policies", "ls"}, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var code int
			_, stderr := captureOutput(t, func() { code = run(test.args) })
			if code != test.want {
				t.Errorf("run(%v) = %d, want %d", test.args, code, test.want)
			}
			if test.wantRe == "" {
				return
			}
			if !strings.Contains(stderr, test.wantRe) {
				t.Errorf("stderr = %q, want containing %q", stderr, test.wantRe)
			}
		})
	}
}
