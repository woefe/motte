package main

import (
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		profile string
		noPull  bool
		replace bool
		wantRe  string // expected error substring, or "" for success
	}{
		{name: "golang profile", args: []string{"golang"}, profile: "golang"},
		{name: "web profile", args: []string{"web"}, profile: "web"},
		{name: "golang with no-pull", args: []string{"golang", "--no-pull"}, profile: "golang", noPull: true},
		{name: "no-pull before profile", args: []string{"--no-pull", "web"}, profile: "web", noPull: true},
		{name: "golang with replace", args: []string{"golang", "--replace"}, profile: "golang", replace: true},
		{name: "no arguments", args: []string{}, wantRe: "no profile given"},
		{name: "only no-pull", args: []string{"--no-pull"}, wantRe: "no profile given"},
		{name: "only replace", args: []string{"--replace"}, wantRe: "no profile given"},
		{name: "unknown argument", args: []string{"rails"}, wantRe: "unknown argument"},
		{name: "unknown arg, no profile", args: []string{"rails", "--no-pull"}, wantRe: "unknown argument"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, noPull, replace, err := parseArgs(test.args)
			if test.wantRe != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantRe) {
					t.Errorf("parseArgs(%v) error = %v, want containing %q", test.args, err, test.wantRe)
				}
				return
			}
			if err != nil {
				t.Errorf("parseArgs(%v) = %v", test.args, err)
				return
			}
			if profile != test.profile {
				t.Errorf("parseArgs(%v) profile = %q, want %q", test.args, profile, test.profile)
			}
			if noPull != test.noPull {
				t.Errorf("parseArgs(%v) noPull = %v, want %v", test.args, noPull, test.noPull)
			}
			if replace != test.replace {
				t.Errorf("parseArgs(%v) replace = %v, want %v", test.args, replace, test.replace)
			}
		})
	}
}
