// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"errors"

	"github.com/creack/pty"
	"github.com/u-root/u-root/pkg/termios"
	"tailscale.com/tempfork/gliderlabs/ssh"
)

// startWithPTY starts cmd with a psuedo-terminal attached to Stdin, Stdout and Stderr.
func (ss *sshSession) startWithPTY() (*os.File, error) {
	ptyReq := ss.ptyReq
	cmd := ss.cmd
	if cmd == nil {
		return nil, errors.New("nil ss.cmd")
	}
	if ptyReq == nil {
		return nil, errors.New("nil ss.ptyReq")
	}

	var tty *os.File
	ptyFile, tty, err = pty.Open()
	if err != nil {
		return nil, fmt.Errorf("pty.Open: %w", err)
	}
	defer func() {
		if err != nil {
			ptyFile.Close()
			tty.Close()
		}
	}()
	ptyRawConn, err := tty.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("SyscallConn: %w", err)
	}
	var ctlErr error
	if err := ptyRawConn.Control(func(fd uintptr) {
		// Load existing PTY settings to modify them & save them back.
		tios, err := termios.GTTY(int(fd))
		if err != nil {
			ctlErr = fmt.Errorf("GTTY: %w", err)
			return
		}

		// Set the rows & cols to those advertised from the ptyReq frame
		// received over SSH.
		tios.Row = int(ptyReq.Window.Height)
		tios.Col = int(ptyReq.Window.Width)

		for c, v := range ptyReq.Modes {
			if c == gossh.TTY_OP_ISPEED {
				tios.Ispeed = int(v)
				continue
			}
			if c == gossh.TTY_OP_OSPEED {
				tios.Ospeed = int(v)
				continue
			}
			k, ok := opcodeShortName[c]
			if !ok {
				ss.vlogf("unknown opcode: %d", c)
				continue
			}
			if _, ok := tios.CC[k]; ok {
				tios.CC[k] = uint8(v)
				continue
			}
			if _, ok := tios.Opts[k]; ok {
				tios.Opts[k] = v > 0
				continue
			}
			ss.vlogf("unsupported opcode: %v(%d)=%v", k, c, v)
		}

		// Save PTY settings.
		if _, err := tios.STTY(int(fd)); err != nil {
			ctlErr = fmt.Errorf("STTY: %w", err)
			return
		}
	}); err != nil {
		return nil, fmt.Errorf("ptyRawConn.Control: %w", err)
	}
	if ctlErr != nil {
		return nil, fmt.Errorf("ptyRawConn.Control func: %w", ctlErr)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	updateStringInSlice(cmd.Args, "--has-tty=false", "--has-tty=true")
	if ptyName, err := ptyName(ptyFile); err == nil {
		updateStringInSlice(cmd.Args, "--tty-name=", "--tty-name="+ptyName)
		fullPath := filepath.Join("/dev", ptyName)
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_TTY=%s", fullPath))
	}

	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	ss.logf("starting pty command: %+v", cmd.Args)
	if err = cmd.Start(); err != nil {
		return nil, err
	}

	// We need to be able to close stdin and stdout separately later so make a
	// dup.
	ptyDup, err := syscall.Dup(int(ptyFile.Fd()))
	if err != nil {
		return nil, err
	}

	ss.stdin = ptyFile
	ss.stdout = os.NewFile(uintptr(ptyDup), ptyFile.Name())
	ss.stderr = nil // not available for pty

	return ptyFile, nil

}

func resizeWindow(fd int, winCh <-chan ssh.Window) {
	for win := range winCh {
		unix.IoctlSetWinsize(fd, syscall.TIOCSWINSZ, &unix.Winsize{
			Row: uint16(win.Height),
			Col: uint16(win.Width),
		})
	}
}

func setCtty(cmd *exec.Cmd) {
	// If we were launched with a tty then we should
	// mark that as the ctty of the child. However,
	// as the ctty is being passed from the parent
	// we set the child to foreground instead which
	// also passes the ctty.
	// However, we can not do this if never had a tty to
	// begin with.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Foreground: true,
	}
}

// dropPrivileges contains all the logic for dropping privileges to a different
// UID, GID, and set of supplementary groups. This function is
// security-sensitive and ordering-dependent; please be very cautious if/when
// refactoring.
//
// WARNING: if you change this function, you *MUST* run the TestDropPrivileges
// test in this package as root on at least Linux, FreeBSD and Darwin. This can
// be done by running:
//
//	go test -c ./ssh/tailssh/ && sudo ./tailssh.test -test.v -test.run TestDropPrivileges
func dropPrivileges(logf logger.Logf, wantUid, wantGid int, supplementaryGroups []int) error {
	fatalf := func(format string, args ...any) {
		logf("[unexpected] error dropping privileges: "+format, args...)
		os.Exit(1)
	}

	euid := os.Geteuid()
	egid := os.Getegid()

	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		// On FreeBSD and Darwin, the first entry returned from the
		// getgroups(2) syscall is the egid, and changing it with
		// setgroups(2) changes the egid of the process. This is
		// technically a violation of the POSIX standard; see the
		// following article for more detail:
		//    https://www.usenix.org/system/files/login/articles/325-tsafrir.pdf
		//
		// In this case, we add an entry at the beginning of the
		// groupIDs list containing the expected gid if it's not
		// already there, which modifies the egid and additional groups
		// as one unit.
		if len(supplementaryGroups) == 0 || supplementaryGroups[0] != wantGid {
			supplementaryGroups = append([]int{wantGid}, supplementaryGroups...)
		}
	}

	if err := setGroups(supplementaryGroups); err != nil {
		return err
	}
	if egid != wantGid {
		// On FreeBSD and Darwin, we may have already called the
		// equivalent of setegid(wantGid) via the call to setGroups,
		// above. However, per the manpage, setgid(getegid()) is an
		// allowed operation regardless of privilege level.
		//
		// FreeBSD:
		//	The setgid() system call is permitted if the specified ID
		//	is equal to the real group ID or the effective group ID
		//	of the process, or if the effective user ID is that of
		//	the super user.
		//
		// Darwin:
		//	The setgid() function is permitted if the effective
		//	user ID is that of the super user, or if the specified
		//	group ID is the same as the effective group ID.  If
		//	not, but the specified group ID is the same as the real
		//	group ID, setgid() will set the effective group ID to
		//	the real group ID.
		if err := syscall.Setgid(wantGid); err != nil {
			fatalf("Setgid(%d): %v", wantGid, err)
		}
	}
	if euid != wantUid {
		// Switch users if required before starting the desired process.
		if err := syscall.Setuid(wantUid); err != nil {
			fatalf("Setuid(%d): %v", wantUid, err)
		}
	}

	// If we changed either the UID or GID, defensively assert that we
	// cannot reset the it back to our original values, and that the
	// current egid/euid are the expected values after we change
	// everything; if not, we exit the process.
	if assertPrivilegesWereDroppedByAttemptingToUnDrop {
		if egid != wantGid {
			if err := syscall.Setegid(egid); err == nil {
				fatalf("able to set egid back to %d", egid)
			}
		}
		if euid != wantUid {
			if err := syscall.Seteuid(euid); err == nil {
				fatalf("able to set euid back to %d", euid)
			}
		}
	}
	if assertPrivilegesWereDropped {
		if got := os.Getegid(); got != wantGid {
			fatalf("got egid=%d, want %d", got, wantGid)
		}
		if got := os.Geteuid(); got != wantUid {
			fatalf("got euid=%d, want %d", got, wantUid)
		}
		// TODO(andrew-d): assert that our supplementary groups are correct
	}

	return nil
}

func setGroups(groupIDs []int) error {
	if runtime.GOOS == "darwin" && len(groupIDs) > 16 {
		// darwin returns "invalid argument" if more than 16 groups are passed to syscall.Setgroups
		// some info can be found here:
		// https://opensource.apple.com/source/samba/samba-187.8/patches/support-darwin-initgroups-syscall.auto.html
		// this fix isn't great, as anyone reading this has probably just wasted hours figuring out why
		// some permissions thing isn't working, due to some arbitrary group ordering, but it at least allows
		// this to work for more things than it previously did.
		groupIDs = groupIDs[:16]
	}

	err := syscall.Setgroups(groupIDs)
	if err != nil && os.Geteuid() != 0 && groupsMatchCurrent(groupIDs) {
		// If we're not root, ignore a Setgroups failure if all groups are the same.
		return nil
	}
	return err
}