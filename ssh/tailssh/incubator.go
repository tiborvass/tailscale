// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code for the incubator process.  Tailscaled
// launches the incubator as the same user as it was launched as.  The
// incubator then registers a new session with the OS, sets its UID
// and groups to the specified `--uid`, `--gid` and `--groups`, and
// then launches the requested `--cmd`.

//go:build linux || (darwin && !ios) || freebsd || openbsd || windows

package tailssh

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/sftp"
	"go4.org/mem"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/types/logger"
	"tailscale.com/util/lineread"
	"tailscale.com/version/distro"
)

func init() {
	childproc.Add("ssh", beIncubator)
}

var ptyName = func(f *os.File) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

// maybeStartLoginSession starts a new login session for the specified UID.
// On success, it may return a non-nil close func which must be closed to
// release the session.
// See maybeStartLoginSessionLinux.
var maybeStartLoginSession = func(logf logger.Logf, ia incubatorArgs) (close func() error, err error) {
	return nil, nil
}

// newIncubatorCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
//
// If ss.srv.tailscaledPath is empty, this method is equivalent to
// exec.CommandContext.
//
// The returned Cmd.Env is guaranteed to be nil; the caller populates it.
func (ss *sshSession) newIncubatorCommand() (cmd *exec.Cmd) {
	defer func() {
		if cmd.Env != nil {
			panic("internal error")
		}
	}()
	var (
		name    string
		args    []string
		isSFTP  bool
		isShell bool
	)
	switch ss.Subsystem() {
	case "sftp":
		isSFTP = true
	case "":
		name = loginShell(ss.conn.localUser)
		if rawCmd := ss.RawCommand(); rawCmd != "" {
			args = append(args, "-c", rawCmd)
		} else {
			isShell = true
			args = append(args, "-l") // login shell
		}
	default:
		panic(fmt.Sprintf("unexpected subsystem: %v", ss.Subsystem()))
	}

	if ss.conn.srv.tailscaledPath == "" {
		// TODO(maisem): this doesn't work with sftp
		return exec.CommandContext(ss.ctx, name, args...)
	}
	lu := ss.conn.localUser
	ci := ss.conn.info
	gids := strings.Join(ss.conn.userGroupIDs, ",")
	remoteUser := ci.uprof.LoginName
	if ci.node.IsTagged() {
		remoteUser = strings.Join(ci.node.Tags, ",")
	}

	incubatorArgs := []string{
		"be-child",
		"ssh",
		"--uid=" + lu.Uid,
		"--gid=" + lu.Gid,
		"--groups=" + gids,
		"--local-user=" + lu.Username,
		"--remote-user=" + remoteUser,
		"--remote-ip=" + ci.src.Addr().String(),
		"--has-tty=false", // updated in-place by startWithPTY
		"--tty-name=",     // updated in-place by startWithPTY
	}

	if isSFTP {
		incubatorArgs = append(incubatorArgs, "--sftp")
	} else {
		if isShell {
			incubatorArgs = append(incubatorArgs, "--shell")
		}
		if isShell || runtime.GOOS == "darwin" {
			// Only the macOS version of the login command supports executing a
			// command, all other versions only support launching a shell
			// without taking any arguments.
			if lp, err := exec.LookPath("login"); err == nil {
				incubatorArgs = append(incubatorArgs, "--login-cmd="+lp)
			}
		}
		incubatorArgs = append(incubatorArgs, "--cmd="+name)
		if len(args) > 0 {
			incubatorArgs = append(incubatorArgs, "--")
			incubatorArgs = append(incubatorArgs, args...)
		}
	}
	return exec.CommandContext(ss.ctx, ss.conn.srv.tailscaledPath, incubatorArgs...)
}

const debugIncubator = false

type stdRWC struct{}

func (stdRWC) Read(p []byte) (n int, err error) {
	return os.Stdin.Read(p)
}

func (stdRWC) Write(b []byte) (n int, err error) {
	return os.Stdout.Write(b)
}

func (stdRWC) Close() error {
	os.Exit(0)
	return nil
}

type incubatorArgs struct {
	uid          int
	gid          int
	groups       string
	localUser    string
	remoteUser   string
	remoteIP     string
	ttyName      string
	hasTTY       bool
	cmdName      string
	isSFTP       bool
	isShell      bool
	loginCmdPath string
	cmdArgs      []string
}

func parseIncubatorArgs(args []string) (a incubatorArgs) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.IntVar(&a.uid, "uid", 0, "the uid of local-user")
	flags.IntVar(&a.gid, "gid", 0, "the gid of local-user")
	flags.StringVar(&a.groups, "groups", "", "comma-separated list of gids of local-user")
	flags.StringVar(&a.localUser, "local-user", "", "the user to run as")
	flags.StringVar(&a.remoteUser, "remote-user", "", "the remote user/tags")
	flags.StringVar(&a.remoteIP, "remote-ip", "", "the remote Tailscale IP")
	flags.StringVar(&a.ttyName, "tty-name", "", "the tty name (pts/3)")
	flags.BoolVar(&a.hasTTY, "has-tty", false, "is the output attached to a tty")
	flags.StringVar(&a.cmdName, "cmd", "", "the cmd to launch (ignored in sftp mode)")
	flags.BoolVar(&a.isShell, "shell", false, "is launching a shell (with no cmds)")
	flags.BoolVar(&a.isSFTP, "sftp", false, "run sftp server (cmd is ignored)")
	flags.StringVar(&a.loginCmdPath, "login-cmd", "", "the path to `login` cmd")
	flags.Parse(args)
	a.cmdArgs = flags.Args()
	return a
}

// beIncubator is the entrypoint to the `tailscaled be-child ssh` subcommand.
// It is responsible for informing the system of a new login session for the user.
// This is sometimes necessary for mounting home directories and decrypting file
// systems.
//
// Tailscaled launches the incubator as the same user as it was
// launched as.  The incubator then registers a new session with the
// OS, sets its UID and groups to the specified `--uid`, `--gid` and
// `--groups` and then launches the requested `--cmd`.
func beIncubator(args []string) error {
	// To defend against issues like https://golang.org/issue/1435,
	// defensively lock our current goroutine's thread to the current
	// system thread before we start making any UID/GID/group changes.
	//
	// This shouldn't matter on Linux because syscall.AllThreadsSyscall is
	// used to invoke syscalls on all OS threads, but (as of 2023-03-23)
	// that function is not implemented on all platforms.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ia := parseIncubatorArgs(args)
	if ia.isSFTP && ia.isShell {
		return fmt.Errorf("--sftp and --shell are mutually exclusive")
	}

	logf := logger.Discard
	if debugIncubator {
		// We don't own stdout or stderr, so the only place we can log is syslog.
		logf = logger.SystemDaemon(logger.LevelInfo|logger.LevelDaemon, "tailscaled-ssh")
	}

	euid := os.Geteuid()
	runningAsRoot := euid == 0
	if runningAsRoot && ia.loginCmdPath != "" {
		// Check if we can exec into the login command instead of trying to
		// incubate ourselves.
		if la := ia.loginArgs(); la != nil {
			return syscall.Exec(ia.loginCmdPath, la, os.Environ())
		}
	}

	// Inform the system that we are about to log someone in.
	// We can only do this if we are running as root.
	// This is best effort to still allow running on machines where
	// we don't support starting sessions, e.g. darwin.
	sessionCloser, err := maybeStartLoginSession(logf, ia)
	if err == nil && sessionCloser != nil {
		defer sessionCloser()
	}

	var groupIDs []int
	for _, g := range strings.Split(ia.groups, ",") {
		gid, err := strconv.ParseInt(g, 10, 32)
		if err != nil {
			return err
		}
		groupIDs = append(groupIDs, int(gid))
	}

	if err := dropPrivileges(logf, ia.uid, ia.gid, groupIDs); err != nil {
		return err
	}

	if ia.isSFTP {
		logf("handling sftp")

		server, err := sftp.NewServer(stdRWC{})
		if err != nil {
			return err
		}
		return server.Serve()
	}

	cmd := exec.Command(ia.cmdName, ia.cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if ia.hasTTY {
		setCtty(cmd)
	}
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		ps := ee.ProcessState
		code := ps.ExitCode()
		if code < 0 {
			// TODO(bradfitz): do we need to also check the syscall.WaitStatus
			// and make our process look like it also died by signal/same signal
			// as our child process? For now we just do the exit code.
			fmt.Fprintf(os.Stderr, "[tailscale-ssh: process died: %v]\n", ps.String())
			code = 1 // for now. so we don't exit with negative
		}
		os.Exit(code)
	}
	return err
}

const (
	// This controls whether we assert that our privileges were dropped
	// using geteuid/getegid; it's a const and not an envknob because the
	// incubator doesn't see the parent's environment.
	//
	// TODO(andrew): remove this const and always do this after sufficient
	// testing, e.g. the 1.40 release
	assertPrivilegesWereDropped = true

	// TODO(andrew-d): verify that this works in more configurations before
	// enabling by default.
	assertPrivilegesWereDroppedByAttemptingToUnDrop = false
)

// launchProcess launches an incubator process for the provided session.
// It is responsible for configuring the process execution environment.
// The caller can wait for the process to exit by calling cmd.Wait().
//
// It sets ss.cmd, stdin, stdout, and stderr.
func (ss *sshSession) launchProcess() error {
	ss.cmd = ss.newIncubatorCommand()

	cmd := ss.cmd
	homeDir := ss.conn.localUser.HomeDir
	if _, err := os.Stat(homeDir); err == nil {
		cmd.Dir = homeDir
	} else if os.IsNotExist(err) {
		// If the home directory doesn't exist, we can't chdir to it.
		// Instead, we'll chdir to the root directory.
		cmd.Dir = "/"
	} else {
		return err
	}
	// TODO(windows): SYSTEMROOT and PATH
	cmd.Env = envForUser(ss.conn.localUser)
	for _, kv := range ss.Environ() {
		if acceptEnvPair(kv) {
			cmd.Env = append(cmd.Env, kv)
		}
	}

	ci := ss.conn.info
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("SSH_CLIENT=%s %d %d", ci.src.Addr(), ci.src.Port(), ci.dst.Port()),
		fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", ci.src.Addr(), ci.src.Port(), ci.dst.Addr(), ci.dst.Port()),
	)

	if ss.agentListener != nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", ss.agentListener.Addr()))
	}

	ptyReq, winCh, isPty := ss.Pty()
	if !isPty {
		ss.logf("starting non-pty command: %+v", cmd.Args)
		return ss.startWithStdPipes()
	}
	ss.ptyReq = &ptyReq
	ptyFile, err := ss.startWithPTY()
	if err != nil {
		return err
	}
	go resizeWindow(int(ptyFile.Fd()) /* arbitrary fd */, winCh)
	return nil
}

// opcodeShortName is a mapping of SSH opcode
// to mnemonic names expected by the termios package.
// These are meant to be platform independent.
var opcodeShortName = map[uint8]string{
	gossh.VINTR:         "intr",
	gossh.VQUIT:         "quit",
	gossh.VERASE:        "erase",
	gossh.VKILL:         "kill",
	gossh.VEOF:          "eof",
	gossh.VEOL:          "eol",
	gossh.VEOL2:         "eol2",
	gossh.VSTART:        "start",
	gossh.VSTOP:         "stop",
	gossh.VSUSP:         "susp",
	gossh.VDSUSP:        "dsusp",
	gossh.VREPRINT:      "rprnt",
	gossh.VWERASE:       "werase",
	gossh.VLNEXT:        "lnext",
	gossh.VFLUSH:        "flush",
	gossh.VSWTCH:        "swtch",
	gossh.VSTATUS:       "status",
	gossh.VDISCARD:      "discard",
	gossh.IGNPAR:        "ignpar",
	gossh.PARMRK:        "parmrk",
	gossh.INPCK:         "inpck",
	gossh.ISTRIP:        "istrip",
	gossh.INLCR:         "inlcr",
	gossh.IGNCR:         "igncr",
	gossh.ICRNL:         "icrnl",
	gossh.IUCLC:         "iuclc",
	gossh.IXON:          "ixon",
	gossh.IXANY:         "ixany",
	gossh.IXOFF:         "ixoff",
	gossh.IMAXBEL:       "imaxbel",
	gossh.IUTF8:         "iutf8",
	gossh.ISIG:          "isig",
	gossh.ICANON:        "icanon",
	gossh.XCASE:         "xcase",
	gossh.ECHO:          "echo",
	gossh.ECHOE:         "echoe",
	gossh.ECHOK:         "echok",
	gossh.ECHONL:        "echonl",
	gossh.NOFLSH:        "noflsh",
	gossh.TOSTOP:        "tostop",
	gossh.IEXTEN:        "iexten",
	gossh.ECHOCTL:       "echoctl",
	gossh.ECHOKE:        "echoke",
	gossh.PENDIN:        "pendin",
	gossh.OPOST:         "opost",
	gossh.OLCUC:         "olcuc",
	gossh.ONLCR:         "onlcr",
	gossh.OCRNL:         "ocrnl",
	gossh.ONOCR:         "onocr",
	gossh.ONLRET:        "onlret",
	gossh.CS7:           "cs7",
	gossh.CS8:           "cs8",
	gossh.PARENB:        "parenb",
	gossh.PARODD:        "parodd",
	gossh.TTY_OP_ISPEED: "tty_op_ispeed",
	gossh.TTY_OP_OSPEED: "tty_op_ospeed",
}

// startWithStdPipes starts cmd with os.Pipe for Stdin, Stdout and Stderr.
func (ss *sshSession) startWithStdPipes() (err error) {
	var stdin io.WriteCloser
	var stdout, stderr io.ReadCloser
	defer func() {
		if err != nil {
			for _, c := range []io.Closer{stdin, stdout, stderr} {
				if c != nil {
					c.Close()
				}
			}
		}
	}()
	cmd := ss.cmd
	if cmd == nil {
		return errors.New("nil cmd")
	}
	stdin, err = cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	ss.stdin = stdin
	ss.stdout = stdout
	ss.stderr = stderr
	return nil
}

func loginShell(u *user.User) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("getent", "passwd", u.Uid).Output()
		// out is "root:x:0:0:root:/root:/bin/bash"
		f := strings.SplitN(string(out), ":", 10)
		if len(f) > 6 {
			return strings.TrimSpace(f[6]) // shell
		}
	case "darwin":
		// Note: /Users/username is key, and not the same as u.HomeDir.
		out, _ := exec.Command("dscl", ".", "-read", filepath.Join("/Users", u.Username), "UserShell").Output()
		// out is "UserShell: /bin/bash"
		s, ok := strings.CutPrefix(string(out), "UserShell: ")
		if ok {
			return strings.TrimSpace(s)
		}
	case "windows":
		return `C:\Windows\System32\cmd.exe`
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/sh"
}

func envForUser(u *user.User) []string {
	return []string{
		fmt.Sprintf("SHELL=" + loginShell(u)),
		fmt.Sprintf("USER=" + u.Username),
		fmt.Sprintf("HOME=" + u.HomeDir),
		fmt.Sprintf("PATH=" + defaultPathForUser(u)),
	}
}

// defaultPathTmpl specifies the default PATH template to use for new sessions.
//
// If empty, a default value is used based on the OS & distro to match OpenSSH's
// usually-hardcoded behavior. (see
// https://github.com/tailscale/tailscale/issues/5285 for background).
//
// The template may contain @{HOME} or @{PAM_USER} which expand to the user's
// home directory and username, respectively. (PAM is not used, despite the
// name)
var defaultPathTmpl = envknob.RegisterString("TAILSCALE_SSH_DEFAULT_PATH")

func defaultPathForUser(u *user.User) string {
	if s := defaultPathTmpl(); s != "" {
		return expandDefaultPathTmpl(s, u)
	}
	isRoot := u.Uid == "0"
	switch distro.Get() {
	case distro.Debian:
		hi := hostinfo.New()
		if hi.Distro == "ubuntu" {
			// distro.Get's Debian includes Ubuntu. But see if it's actually Ubuntu.
			// Ubuntu doesn't empirically seem to distinguish between root and non-root for the default.
			// And it includes /snap/bin.
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
		}
		if isRoot {
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		}
		return "/usr/local/bin:/usr/bin:/bin:/usr/bn/games"
	case distro.NixOS:
		return defaultPathForUserOnNixOS(u)
	}
	if isRoot {
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

func defaultPathForUserOnNixOS(u *user.User) string {
	var path string
	lineread.File("/etc/pam/environment", func(lineb []byte) error {
		if v := pathFromPAMEnvLine(lineb, u); v != "" {
			path = v
			return io.EOF // stop iteration
		}
		return nil
	})
	return path
}

func pathFromPAMEnvLine(line []byte, u *user.User) (path string) {
	if !mem.HasPrefix(mem.B(line), mem.S("PATH")) {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(string(line), "PATH"))
	if quoted, ok := strings.CutPrefix(rest, "DEFAULT="); ok {
		if path, err := strconv.Unquote(quoted); err == nil {
			return expandDefaultPathTmpl(path, u)
		}
	}
	return ""
}

func expandDefaultPathTmpl(t string, u *user.User) string {
	p := strings.NewReplacer(
		"@{HOME}", u.HomeDir,
		"@{PAM_USER}", u.Username,
	).Replace(t)
	if strings.Contains(p, "@{") {
		// If there are unknown expansions, conservatively fail closed.
		return ""
	}
	return p
}

// updateStringInSlice mutates ss to change the first occurrence of a
// to b.
func updateStringInSlice(ss []string, a, b string) {
	for i, s := range ss {
		if s == a {
			ss[i] = b
			return
		}
	}
}

// acceptEnvPair reports whether the environment variable key=value pair
// should be accepted from the client. It uses the same default as OpenSSH
// AcceptEnv.
func acceptEnvPair(kv string) bool {
	k, _, ok := strings.Cut(kv, "=")
	if !ok {
		return false
	}
	return k == "TERM" || k == "LANG" || strings.HasPrefix(k, "LC_")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loginArgs returns the arguments to use to exec the login binary.
// It returns nil if the login binary should not be used.
// The login binary is only used:
//   - on darwin, if the client is requesting a shell or a command.
//   - on linux and BSD, if the client is requesting a shell with a TTY.
func (ia *incubatorArgs) loginArgs() []string {
	if ia.isSFTP {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		args := []string{
			ia.loginCmdPath,
			"-f", // already authenticated

			// login typically discards the previous environment, but we want to
			// preserve any environment variables that we currently have.
			"-p",

			"-h", ia.remoteIP, // -h is "remote host"
			ia.localUser,
		}
		if !ia.hasTTY {
			args[2] = "-pq" // -q is "quiet" which suppresses the login banner
		}
		if ia.cmdName != "" {
			args = append(args, ia.cmdName)
			args = append(args, ia.cmdArgs...)
		}
		return args
	case "linux":
		if !ia.isShell || !ia.hasTTY {
			// We can only use login command if a shell was requested with a TTY. If
			// there is no TTY, login exits immediately, which breaks things likes
			// mosh and VSCode.
			return nil
		}
		if distro.Get() == distro.Arch && !fileExists("/etc/pam.d/remote") {
			// See https://github.com/tailscale/tailscale/issues/4924
			//
			// Arch uses a different login binary that makes the -h flag set the PAM
			// service to "remote". So if they don't have that configured, don't
			// pass -h.
			return []string{ia.loginCmdPath, "-f", ia.localUser, "-p"}
		}
		return []string{ia.loginCmdPath, "-f", ia.localUser, "-h", ia.remoteIP, "-p"}
	case "freebsd", "openbsd":
		if !ia.isShell || !ia.hasTTY {
			// We can only use login command if a shell was requested with a TTY. If
			// there is no TTY, login exits immediately, which breaks things likes
			// mosh and VSCode.
			return nil
		}
		return []string{ia.loginCmdPath, "-fp", "-h", ia.remoteIP, ia.localUser}
	}
	panic("unimplemented")
}

func groupsMatchCurrent(groupIDs []int) bool {
	existing, err := syscall.Getgroups()
	if err != nil {
		return false
	}
	if len(existing) != len(groupIDs) {
		return false
	}
	groupIDs = slices.Clone(groupIDs)
	sort.Ints(groupIDs)
	sort.Ints(existing)
	return slices.Equal(groupIDs, existing)
}