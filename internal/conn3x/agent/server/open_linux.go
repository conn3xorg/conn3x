// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"os"
	"strconv"
	"syscall"
)

// oPath is O_PATH, which syscall leaves out on amd64. It's the same on
// every architecture.
const oPath = 0x200000

// openRegular opens path for reading only if it's still the regular file
// st describes. Opening something else, such as a device or a FIFO, can
// itself have effects, so path is first opened with O_PATH, which doesn't
// open the file itself, and checked. Only then is it opened for reading,
// through /proc. Without O_PATH or /proc, the shell is asked instead.
func openRegular(path string, st *syscall.Stat_t) (*os.File, error) {
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer syscall.Close(fd)
	// A kernel without O_PATH ignores the flag.
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if errno != 0 || flags&oPath == 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EINVAL}
	}
	var fst syscall.Stat_t
	if err := syscall.Fstat(fd, &fst); err != nil {
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if fst.Mode&syscall.S_IFMT != syscall.S_IFREG || fst.Dev != st.Dev || fst.Ino != st.Ino {
		return nil, errChanged(path)
	}
	return os.OpenFile("/proc/self/fd/"+strconv.Itoa(fd), os.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
}
