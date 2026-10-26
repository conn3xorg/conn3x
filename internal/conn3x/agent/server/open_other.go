// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package server

import (
	"os"
	"syscall"
)

// openRegular opens path for reading if it's still the regular file st
// describes. The agent ships only for Linux; this lets its tests run
// elsewhere, without O_PATH. Non-blocking, in case a FIFO is there now.
func openRegular(path string, st *syscall.Stat_t) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var fst syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &fst); err != nil {
		f.Close()
		return nil, err
	}
	if fst.Mode&syscall.S_IFMT != syscall.S_IFREG || fst.Dev != st.Dev || fst.Ino != st.Ino {
		f.Close()
		return nil, errChanged(path)
	}
	return f, nil
}
