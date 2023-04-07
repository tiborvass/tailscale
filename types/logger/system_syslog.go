// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package logger

import (
	"log"
	"log/syslog"
)

const (
	LevelInfo = syslog.LOG_INFO
	LevelWarning = syslog.LOG_WARNING
	LevelError = syslog.LOG_ERROR
	LevelDaemon = syslog.LOG_DAEMON
)

func SystemDaemon(level int, name string) Logf {
	if sl, err := syslog.New(level, name); err == nil {
		return log.New(sl, "", 0).Printf
	}
	return Discard
}