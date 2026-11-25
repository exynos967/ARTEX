//go:build windows

package server

import (
	"os/exec"
	"time"
)

// configurePythonCmd configures cancellation and a bounded pipe WaitDelay so
// timed-out Python scripts cannot hang execPython if a grandchild inherits stdio.
func configurePythonCmd(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 3 * time.Second
}
