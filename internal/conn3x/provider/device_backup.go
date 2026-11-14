// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// backupNow is when a backup is taken; a test sets it.
var backupNow = time.Now

// writeDeviceBackup writes a device's configuration to dir as
// HOST-YYYYMMDDTHHMMSSZ.cfg, readable by its owner only, since a running
// configuration can hold hashed secrets. The directory is made, owner only,
// when it's missing. A file that's there already is never overwritten.
func writeDeviceBackup(dir, host, config string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("device_backup_dir: %w", err)
	}
	name := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(host)
	stem := filepath.Join(dir, name+"-"+backupNow().UTC().Format("20060102T150405Z"))
	// Two circuits on one device can commit in the same second: the second
	// backup gets -2, and so on.
	var f *os.File
	var err error
	for i := 1; ; i++ {
		path := stem + ".cfg"
		if i > 1 {
			path = fmt.Sprintf("%s-%d.cfg", stem, i)
		}
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil || !os.IsExist(err) || i == 100 {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("device_backup_dir: %w", err)
	}
	if _, err := f.WriteString(config); err != nil {
		f.Close()
		return fmt.Errorf("device_backup_dir: %w", err)
	}
	return f.Close()
}
