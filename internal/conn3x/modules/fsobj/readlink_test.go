// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"context"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// failing answers every command with one failed result.
type failing ssh.Result

func (f failing) Run(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result(f), nil
}

// A read that fails, such as the path guard refusing, is an error, not a
// missing link: refresh would drop the link from state, and a delete would
// do nothing.
func TestReadLinkFailureIsAnError(t *testing.T) {
	r := failing{ExitCode: 1, Stderr: []byte("refusing /srv/app: owned by deploy\n")}
	if a, err := ReadLink(ctx, r, "/srv/app/current"); err == nil || err.Error() != "reading /srv/app/current: refusing /srv/app: owned by deploy" {
		t.Errorf("ReadLink = %+v, %v", a, err)
	}
	if err := DeleteLink(ctx, r, "/srv/app/current"); err == nil {
		t.Error("DeleteLink succeeded on a host that refused the read")
	}
}
