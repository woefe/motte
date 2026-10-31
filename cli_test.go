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

// TestOpenCodeFlagParsing resolves the opencode command through both of its
// names and parses its flags.
func TestOpenCodeFlagParsing(t *testing.T) {
	for _, name := range []string{"oc", "opencode"} {
		t.Run(name, func(t *testing.T) {
			root := newRootCommand()
			cmd, rest, err := root.Find([]string{name, "golang", "--replace", "--no-pull"})
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			if cmd.Name() != "opencode" {
				t.Fatalf("command = %q, want opencode", cmd.Name())
			}
			if err := cmd.ParseFlags(rest); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			replace, _ := cmd.Flags().GetBool("replace")
			noPull, _ := cmd.Flags().GetBool("no-pull")
			if !replace || !noPull {
				t.Errorf("replace=%v no-pull=%v, want both true", replace, noPull)
			}
			if got := cmd.Flags().Args(); len(got) != 1 || got[0] != "golang" {
				t.Errorf("args = %v, want [golang]", got)
			}
		})
	}
}

// TestOpenCodeBootsTheProfile checks that the command hands the profile and
// its flags to the boot.
func TestOpenCodeBootsTheProfile(t *testing.T) {
	original := boot
	t.Cleanup(func() { boot = original })
	var gotProfile string
	var gotNoPull, gotReplace bool
	boot = func(profile string, noPull, replace bool) (int, error) {
		gotProfile, gotNoPull, gotReplace = profile, noPull, replace
		return 0, nil
	}
	if err := execute(t, "oc", "golang", "--replace"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotProfile != "golang" || !gotReplace || gotNoPull {
		t.Errorf("boot(%q, no-pull=%v, replace=%v)", gotProfile, gotNoPull, gotReplace)
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

// TestRunExitCodes checks the exit code run reports for a failing and a
// succeeding command.
func TestRunExitCodes(t *testing.T) {
	isolatedConfigDir(t)
	if code := run([]string{"motte", "golang"}); code != 1 {
		t.Errorf("run(golang) = %d, want 1", code)
	}
	if code := run([]string{"motte", "policies", "ls"}); code != 0 {
		t.Errorf("run(policies ls) = %d, want 0", code)
	}
}
