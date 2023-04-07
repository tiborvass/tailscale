// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package logger

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	LevelInfo = eventlog.Info
	LevelWarning = eventlog.Warning
	LevelError = eventlog.Error
	LevelDaemon = 0 // ignored on Windows
)

func SystemDaemon(level uint32, name string) Logf {
	var el *eventlog.Log

	// The following was adapted from github.com/google/logger/logger_windows.go
	// which is under Apache License v2.0
	{
		// Continue if we receive "registry key already exists" or if we get
		// ERROR_ACCESS_DENIED so that we can log without administrative permissions
		// for pre-existing eventlog sources.
		err := eventlog.InstallAsEventCreate(name, level)
		if err != nil {
			if !strings.Contains(err.Error(), "registry key already exists") && err != windows.ERROR_ACCESS_DENIED {
				return Discard
			}
		}
		el, err = eventlog.Open(name)
		if err != nil {
			return Discard
		}
	}

	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if (level&LevelError != 0) {
			el.Error(2, msg)
			return
		}
		if (level&LevelWarning != 0) {
			el.Warning(3, msg)
			return
		}
		el.Info(1, msg)
	}
}