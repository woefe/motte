package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// isolatedConfigDir points XDG_CONFIG_HOME at a fresh temp dir so tests never
// read a real ~/.config/motte.
func isolatedConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// workingDir returns the test process's working directory: the base the
// launcher resolves relative mount sources against.
func workingDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return wd
}

// mustDirHash returns the hash of the current directory.
func mustDirHash(t *testing.T) string {
	t.Helper()
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// fixture returns the contents of a testdata file (relpath uses /).
func fixture(t *testing.T, relpath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", relpath))
	if err != nil {
		t.Fatalf("read fixture %s: %v", relpath, err)
	}
	return string(data)
}

// writeConfigFile writes a file under $XDG_CONFIG_HOME/motte (relpath uses /).
func writeConfigFile(t *testing.T, relpath, content string) {
	t.Helper()
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", relpath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// captureOutput runs f with stdout and stderr piped, and returns what was
// printed on each. Only for outputs far below the pipe buffer.
func captureOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	originalStdout, originalStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	f()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = originalStdout, originalStderr
	stdoutData, _ := io.ReadAll(stdoutReader)
	stderrData, _ := io.ReadAll(stderrReader)
	return string(stdoutData), string(stderrData)
}
