// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"regexp"
	"strings"
)

// symbolicPattern is the part of chmod's symbolic modes a recursive
// directory takes: every clause names who it's for, so the umask never
// comes into it, and only r, w, x and X, so setuid, setgid and sticky bits
// are never given out to a whole tree.
var symbolicPattern = regexp.MustCompile(`^[ugoa]+[-=+][rwxX]*(,[ugoa]+[-=+][rwxX]*)*$`)

// IsSymbolic reports whether mode is a symbolic mode, such as "u=rwX,g=rX,o=".
func IsSymbolic(mode string) bool { return symbolicPattern.MatchString(mode) }

// applySymbolic returns what chmod makes of perm with mode, as GNU chmod
// does: X gives execute where the path is a directory or already has it for
// someone, and = on a directory keeps its setuid and setgid bits.
func applySymbolic(mode string, perm uint32, dir bool) uint32 {
	for _, clause := range strings.Split(mode, ",") {
		i := strings.IndexAny(clause, "=+-")
		who, op, perms := clause[:i], clause[i], clause[i+1:]
		var affected uint32
		for _, w := range who {
			switch w {
			case 'u':
				affected |= 04700
			case 'g':
				affected |= 02070
			case 'o':
				affected |= 01007
			case 'a':
				affected |= 07777
			}
		}
		var value uint32
		for _, p := range perms {
			switch p {
			case 'r':
				value |= 0444
			case 'w':
				value |= 0222
			case 'x':
				value |= 0111
			case 'X':
				if dir || perm&0111 != 0 {
					value |= 0111
				}
			}
		}
		value &= affected
		switch op {
		case '=':
			keep := ^affected
			if dir {
				keep |= 06000
			}
			perm = perm&keep | value
		case '+':
			perm |= value
		case '-':
			perm &^= value
		}
	}
	return perm & 07777
}
