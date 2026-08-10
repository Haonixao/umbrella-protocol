//go:build windows
// +build windows

package tunnel

import (
	"os/exec"
	"syscall"
)

func execCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd
}
