// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package tailssh

import (
	"os"
	"os/exec"
	"tailscale.com/types/logger"

	"tailscale.com/tempfork/gliderlabs/ssh"
)

// startWithPTY starts cmd with a psuedo-terminal attached to Stdin, Stdout and Stderr.
func (ss *sshSession) startWithPTY() (*os.File, error) {
	return nil, nil
}

func resizeWindow(fd int, winCh <-chan ssh.Window) {
	for win := range winCh {
	}
}

func setCtty(cmd *exec.Cmd) {}

func dropPrivileges(logf logger.Logf, wantUid, wantGid int, supplementaryGroups []int) error {
	return nil
}

func setGroups(groupIDs []int) error {
	return nil
}

func groupsMatchCurrent(groupIDs []int) bool {
	return false
}
