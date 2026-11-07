// User configuration files: where motte's config tree lives under
// $XDG_CONFIG_HOME/motte, the directory hash that keys a project, and how
// motte creates, writes, and edits config files.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ErrInvalidAfterEdit reports a config file that fails to parse after the
// editor exited. The caller exits non-zero without printing another line:
// the configure flow already explained the failure.
var ErrInvalidAfterEdit = errors.New("the config file is invalid after editing")

// ConfigDir returns the root of motte's per-user config tree.
func ConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config dir: %w", err)
	}
	return filepath.Join(dir, "motte"), nil
}

// ProjectsDir returns the root of the per-directory project config tree.
func ProjectsDir() (string, error) { return motteSubdir("projects") }

// PoliciesDir returns the root of the per-user policy group tree.
func PoliciesDir() (string, error) { return motteSubdir("policies") }

// SecretsDir returns the root of the per-user secret settings tree.
func SecretsDir() (string, error) { return motteSubdir("secrets") }

// OpencodeDir returns the directory mounted read-only as the guest's
// /etc/opencode.
func OpencodeDir() (string, error) { return motteSubdir("opencode") }

// ProjectPath returns the resolved current working directory, the directory
// the project config and sandbox belong to. Symlinks are resolved so linked or
// renamed paths share a project.
func ProjectPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolving the working directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks in %s: %w", cwd, err)
	}
	return resolved, nil
}

// DirHash returns a 12-hex hash of the resolved current working directory, so
// every directory maps to one stable project config and sandbox name.
func DirHash() (string, error) {
	resolved, err := ProjectPath()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(resolved))
	return hex.EncodeToString(sum[:6]), nil
}

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

// WriteNewFile creates or replaces a config file, making the parent directory
// first. The file mode is 0600 regardless of the umask: the chmod call, unlike
// the create mode, bypasses it.
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

// WriteAtomic writes data to path atomically with 0600 permissions, creating
// parent directories as needed.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("setting the mode of %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ListYAMLNames returns the sorted stems of all `.yaml` files in dir. A
// missing directory returns nil without error.
func ListYAMLNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		names = append(names, strings.TrimSuffix(entry.Name(), ".yaml"))
	}
	sort.Strings(names)
	return names, nil
}

// EditableFile is one config file as the configure flow needs it: where it
// lives, the command to re-run when an edit breaks it, how to render its
// skeleton, and how to read it back.
type EditableFile struct {
	Path     string
	FixCmd   string
	ErrOut   io.Writer
	Template func() (string, error)
	Read     func() error
}

// ConfigureFile opens a config file in the editor, creating it from its
// template when missing, and re-reads it afterwards. A file that fails to
// parse after editing keeps its content and exits non-zero.
func ConfigureFile(f EditableFile) error {
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
