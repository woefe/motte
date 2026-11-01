// User configuration files: where a scope's file lives under motte's config
// tree, and how motte creates, writes, and edits it.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// motteConfigDir returns the root of motte's per-user config tree.
func motteConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config dir: %w", err)
	}
	return filepath.Join(dir, "motte"), nil
}

// policiesDir returns the root of the per-user policy tree.
func policiesDir() (string, error) { return motteSubdir("policies") }

// secretsDir returns the root of the per-user secrets config tree.
func secretsDir() (string, error) { return motteSubdir("secrets") }

// motteSubdir returns one of motte's config subdirectories.
func motteSubdir(name string) (string, error) {
	root, err := motteConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

// motteConfigHint names the user config dir in error messages.
func motteConfigHint() string {
	dir, err := motteConfigDir()
	if err != nil {
		return filepath.Join("<user config dir>", "motte")
	}
	return dir
}

// writeNewFile creates a config file with a rendered skeleton, making the
// parent directory first.
func writeNewFile(path, contents string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// scopeFile is one scope's config file as the configure flow needs it: where
// it lives, the command to re-run when an edit breaks it, how to render its
// skeleton, and how to read it back.
type scopeFile struct {
	path     string
	fixCmd   string
	template func() (string, error)
	read     func() error
}

// configureScope opens a scope's config file in the editor, creating it from
// its template when missing, and re-reads it afterwards. A file that fails to
// parse after editing keeps its content and exits non-zero.
func configureScope(f scopeFile) error {
	if _, err := os.Stat(f.path); errors.Is(err, os.ErrNotExist) {
		template, err := f.template()
		if err != nil {
			return err
		}
		if err := writeNewFile(f.path, template); err != nil {
			return err
		}
	}
	if err := runEditor(f.path); err != nil {
		return err
	}
	if err := f.read(); err != nil {
		fmt.Fprintf(os.Stderr, "motte: %s is invalid after editing: %v\n", f.path, err)
		fmt.Fprintf(os.Stderr, "motte: fix it with `%s`\n", f.fixCmd)
		return exitCoder{code: 1}
	}
	fmt.Fprintf(os.Stderr, "motte: %s is valid\n", f.path)
	return nil
}

// runEditor opens path in $VISUAL/$EDITOR, or nano/vi, attached to the
// terminal. Editors configured with arguments go through the shell.
func runEditor(path string) error {
	editor := strings.TrimSpace(os.Getenv("VISUAL"))
	if editor == "" {
		editor = strings.TrimSpace(os.Getenv("EDITOR"))
	}
	if editor == "" {
		editor = "nano"
		if _, err := exec.LookPath("nano"); err != nil {
			if _, viErr := exec.LookPath("vi"); viErr != nil {
				return fmt.Errorf("no editor found; set $VISUAL or $EDITOR")
			}
			editor = "vi"
		}
	}
	var cmd *exec.Cmd
	if strings.ContainsAny(editor, " \t") {
		cmd = exec.Command("sh", "-c", editor+` "$1"`, "editor", path)
	} else {
		cmd = exec.Command(editor, path)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q on %s: %w", editor, path, err)
	}
	return nil
}
