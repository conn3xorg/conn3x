// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package repo

import (
	"context"
	"errors"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
)

// Alpine's repositories are lines in a file, so every entry point refuses
// it before anything runs, rather than writing Debian's files there.
func TestAlpineRefused(t *testing.T) {
	ctx := context.Background()
	r := Repo{Name: "extra", URL: "https://example.com/alpine", Key: "key"}
	if r.Files(pkg.APK) != nil {
		t.Error("Files on Alpine")
	}
	if _, err := InSync(ctx, nil, pkg.APK, r); !errors.Is(err, errAlpine) {
		t.Errorf("InSync: %v", err)
	}
	if err := Apply(ctx, nil, pkg.APK, r); !errors.Is(err, errAlpine) {
		t.Errorf("Apply: %v", err)
	}
	if err := Delete(ctx, nil, pkg.APK, r); !errors.Is(err, errAlpine) {
		t.Errorf("Delete: %v", err)
	}
	if _, _, err := ReadSources(ctx, nil, pkg.APK); !errors.Is(err, errAlpine) {
		t.Errorf("ReadSources: %v", err)
	}
	if err := Disable(ctx, nil, pkg.APK, []string{"x"}); !errors.Is(err, errAlpine) {
		t.Errorf("Disable: %v", err)
	}
}

func TestSUSERefused(t *testing.T) {
	ctx := context.Background()
	r := Repo{Name: "extra", URL: "https://example.com/suse", Key: "key"}
	if r.Files(pkg.SUSE) != nil {
		t.Error("Files on SUSE")
	}
	if err := Apply(ctx, nil, pkg.SUSE, r); !errors.Is(err, errSUSE) {
		t.Errorf("Apply: %v", err)
	}
	if _, _, err := ReadSources(ctx, nil, pkg.SUSE); !errors.Is(err, errSUSE) {
		t.Errorf("ReadSources: %v", err)
	}
}
