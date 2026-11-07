package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/secrets"
	"github.com/woefe/motte/internal/testutil"
)

// execute runs the command tree with args and returns the error it produced.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	return executeWithBoot(t, nil, args...)
}

func executeWithBoot(t *testing.T, boot bootFunc, args ...string) error {
	t.Helper()
	root := newRootCommand(env{
		boot:   boot,
		store:  testutil.NewFakeStore(secrets.ErrNotFound, nil),
		in:     strings.NewReader(""),
		out:    io.Discard,
		errOut: io.Discard,
	})
	root.SetArgs(args)
	return root.Execute()
}

// runCLI runs the full CLI dispatch with captured stdout and stderr.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code = runWithEnv(args, env{
		boot:   func(bool, bool) (int, error) { return 0, nil },
		store:  testutil.NewFakeStore(secrets.ErrNotFound, nil),
		in:     strings.NewReader(""),
		out:    &outBuf,
		errOut: &errBuf,
	})
	return code, outBuf.String(), errBuf.String()
}

// TestOpenCodeBootsTheProject checks that both command names resolve and hand
// their flags to the boot without positional arguments.
func TestOpenCodeBootsTheProject(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		noPull  bool
		replace bool
	}{
		{name: "oc default", args: []string{"oc"}},
		{name: "oc replace", args: []string{"oc", "--replace"}, replace: true},
		{name: "opencode flags", args: []string{"opencode", "--no-pull", "--replace"}, noPull: true, replace: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotNoPull, gotReplace bool
			boot := func(noPull, replace bool) (int, error) {
				gotNoPull, gotReplace = noPull, replace
				return 0, nil
			}
			if err := executeWithBoot(t, boot, test.args...); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if gotNoPull != test.noPull || gotReplace != test.replace {
				t.Errorf("boot(no-pull=%v, replace=%v), want (no-pull=%v, replace=%v)",
					gotNoPull, gotReplace, test.noPull, test.replace)
			}
		})
	}

	// Positional arguments are rejected with help output.
	if err := execute(t, "oc", "golang"); err == nil {
		t.Error("execute([oc golang]) = nil, want a usage error")
	}
}

// TestRootCommandErrors covers the invocation without a subcommand: the help
// is printed and typos get a suggestion.
func TestRootCommandErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		wantRe string
	}{
		{name: "no command", wantRe: ""},
		{name: "typo", args: []string{"secretes"}, wantRe: `did you mean "motte secrets"`},
		{name: "unknown", args: []string{"frobnicate"}, wantRe: "expected init, opencode, oc, policies, or secrets"},
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
		{"secrets", "configure", "bad-name"},
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
		{"policies", "configure", "Bad_Group"},
		{"policies", "ls", "a"},
	} {
		if err := execute(t, args...); err == nil {
			t.Errorf("execute(%v) = nil, want a usage error", args)
		}
	}
}

// TestIncompleteCommandsPrintHelp checks that commands invoked with a missing
// mandatory argument (or unexpected positional argument) print their help
// alone, without an error message after it, and exit with 1.
func TestIncompleteCommandsPrintHelp(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		wantRe string
	}{
		{
			name:   "oc with unexpected arg",
			args:   []string{"motte", "oc", "golang"},
			wantRe: "Usage:\n  motte opencode [flags]",
		},
		{
			name: "policies configure without group",
			args: []string{"motte", "policies", "configure"},
			wantRe: "The group name is a slug (lowercase letters, digits, and dashes)." +
				"\n\nUsage:\n  motte policies configure <group> [flags]",
		},
		{
			name:   "secrets rm without name",
			args:   []string{"motte", "secrets", "rm"},
			wantRe: "Usage:\n  motte secrets rm <name> [flags]",
		},
		{
			name:   "secrets set without name",
			args:   []string{"motte", "secrets", "set"},
			wantRe: "Usage:\n  motte secrets set <name> [flags]",
		},
		{
			name:   "secrets configure without name",
			args:   []string{"motte", "secrets", "configure"},
			wantRe: "Usage:\n  motte secrets configure <name> [flags]",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, test.args...)
			if code != 1 {
				t.Errorf("Run(%v) = %d, want 1", test.args, code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want an empty stdout", stdout)
			}
			if !strings.Contains(stderr, test.wantRe) {
				t.Errorf("stderr = %q, want containing %q", stderr, test.wantRe)
			}
			if strings.Contains(stderr, "\nmotte: ") {
				t.Errorf("stderr = %q has an error message after the help", stderr)
			}
		})
	}
}

// TestRunExitCodes checks the exit code Run returns and what it prints for a
// failing and a succeeding command.
func TestRunExitCodes(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	tests := []struct {
		name   string
		args   []string
		want   int
		wantRe string // expected stderr substring
	}{
		{
			name:   "unknown command",
			args:   []string{"motte", "frobnicate"},
			want:   1,
			wantRe: `unknown command "frobnicate"; expected init, opencode, oc, policies, or secrets`,
		},
		{
			name:   "usage error",
			args:   []string{"motte", "policies", "ls", "a"},
			want:   1,
			wantRe: "unknown command",
		},
		{name: "success", args: []string{"motte", "policies", "ls"}, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, test.args...)
			if code != test.want {
				t.Errorf("Run(%v) = %d, want %d", test.args, code, test.want)
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
