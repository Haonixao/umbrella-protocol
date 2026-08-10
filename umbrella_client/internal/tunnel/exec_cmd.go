//go:build !windows && !android
// +build !windows,!android

package tunnel

import (
	"os/exec"
)

func execCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}
