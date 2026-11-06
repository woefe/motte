// User configuration files: where a scope's file lives under motte's config
// tree, and how motte creates, writes, and edits it.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrInvalidAfterEdit reports a scope file that fails to parse after the
// editor exited. The caller exits non-zero without printing another line:
// the configure flow already explained the failure.
var ErrInvalidAfterEdit = errors.New("the scope file is invalid after editing")

// ConfigDir returns the root of motte's per-user config tree.
func ConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config dir: %w", err)
	}
	return filepath.Join(dir, "motte"), nil
}

// PoliciesDir returns the root of the per-user policy tree.
func PoliciesDir() (string, error) { return motteSubdir("policies") }

// SecretsDir returns the root of the per-user secrets config tree.
func SecretsDir() (string, error) { return motteSubdir("secrets") }

// OpencodeDir returns the directory mounted read-only as the guest's
// /etc/opencode.
func OpencodeDir() (string, error) { return motteSubdir("opencode") }

// defaultOpencodeConfig is the opencode.json written when none exists yet.
const defaultOpencodeConfig = `{
  "$schema": "https://opencode.ai/config.json"
}
`

// EnsureOpencodeConfig returns the OpenCode config directory, creating it
// with a default opencode.json when the file is missing. An existing file is
// kept as is.
func EnsureOpencodeConfig() (string, error) {
	dir, err := OpencodeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "opencode.json")
	if _, err := os.Stat(path); err == nil {
		return dir, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("checking %s: %w", path, err)
	}
	if err := WriteNewFile(path, defaultOpencodeConfig); err != nil {
		return "", err
	}
	return dir, nil
}

// motteSubdir returns one of motte's config subdirectories.
func motteSubdir(name string) (string, error) {
	root, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

// Hint names the user config dir in error messages.
func Hint() string {
	dir, err := ConfigDir()
	if err != nil {
		return filepath.Join("<user config dir>", "motte")
	}
	return dir
}

// WriteNewFile creates a config file with a rendered skeleton, making the
// parent directory first. The file mode is 0600 regardless of the umask:
// the chmod call, unlike the create mode, bypasses it.
func WriteNewFile(path, contents string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("setting the mode of %s: %w", path, err)
	}
	return nil
}

// ScopeFile is one scope's config file as the configure flow needs it: where
// it lives, the command to re-run when an edit breaks it, how to render its
// skeleton, and how to read it back.
type ScopeFile struct {
	Path     string
	FixCmd   string
	ErrOut   io.Writer
	Template func() (string, error)
	Read     func() error
}

// ConfigureScope opens a scope's config file in the editor, creating it from
// its template when missing, and re-reads it afterwards. A file that fails
// to parse after editing keeps its content and exits non-zero.
func ConfigureScope(f ScopeFile) error {
	errOut := f.ErrOut
	if errOut == nil {
		errOut = os.Stderr
	}
	if _, err := os.Stat(f.Path); errors.Is(err, os.ErrNotExist) {
		template, err := f.Template()
		if err != nil {
			return err
		}
		if err := WriteNewFile(f.Path, template); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("checking %s: %w", f.Path, err)
	}
	if err := runEditor(f.Path); err != nil {
		return err
	}
	if err := f.Read(); err != nil {
		_, _ = fmt.Fprintf(errOut, "motte: %s is invalid after editing: %v\n", f.Path, err)
		_, _ = fmt.Fprintf(errOut, "motte: fix it with `%s`\n", f.FixCmd)
		return ErrInvalidAfterEdit
	}
	_, _ = fmt.Fprintf(errOut, "motte: %s is valid\n", f.Path)
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
