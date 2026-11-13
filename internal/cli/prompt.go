// Shared interactive prompt and terminal helpers for the CLI commands.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// promptLine prints a prompt and reads one line from in.
func promptLine(in *bufio.Reader, errOut io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(errOut, prompt)
	line, err := in.ReadString('\n')
	if line == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading input: %w", err)
		}
		return "", fmt.Errorf("reading input: unexpected end of input")
	}
	return strings.TrimSpace(line), nil
}

// confirmPrompt asks a yes-no question; force short-circuits it.
func confirmPrompt(in *bufio.Reader, errOut io.Writer, prompt string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	answer, err := promptLine(in, errOut, prompt)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// isTerminalReader reports whether r is an interactive terminal file.
func isTerminalReader(r io.Reader) bool {
	file, ok := r.(*os.File)
	return ok && isTerminal(file)
}

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
