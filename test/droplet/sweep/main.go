// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Command sweep deletes test droplets tagged conn3x-ci that are older than
// -max-age, and conn3x-ci SSH keys no remaining test droplet uses. It never
// touches anything without the tag or the name prefix.
//
//	DIGITALOCEAN_TOKEN=... go run ./test/droplet/sweep -max-age 2h
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/opentofu/opentofu/test/droplet/doapi"
)

func main() {
	maxAge := flag.Duration("max-age", 2*time.Hour, "delete tagged droplets older than this")
	dryRun := flag.Bool("dry-run", false, "only list what would be deleted")
	flag.Parse()
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "sweep: DIGITALOCEAN_TOKEN is not set")
		os.Exit(2)
	}
	if err := sweep(context.Background(), &doapi.Client{Token: token}, *maxAge, *dryRun, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "sweep:", err)
		os.Exit(1)
	}
}

func sweep(ctx context.Context, c *doapi.Client, maxAge time.Duration, dryRun bool, now time.Time) error {
	droplets, err := c.TaggedDroplets(ctx)
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, d := range droplets {
		if now.Sub(d.Created) <= maxAge {
			live[d.Name] = true
			fmt.Printf("keeping droplet %s (%d), %s old\n", d.Name, d.ID, now.Sub(d.Created).Round(time.Minute))
			continue
		}
		fmt.Printf("deleting droplet %s (%d), created %s\n", d.Name, d.ID, d.Created.Format(time.RFC3339))
		if !dryRun {
			if err := c.DeleteDroplet(ctx, d.ID); err != nil {
				return err
			}
		}
	}
	keys, err := c.SSHKeys(ctx, doapi.Tag+"-")
	if err != nil {
		return err
	}
	for _, k := range keys {
		if live[k.Name] {
			continue
		}
		fmt.Printf("deleting SSH key %s (%d)\n", k.Name, k.ID)
		if !dryRun {
			if err := c.DeleteSSHKey(ctx, k.ID); err != nil {
				return err
			}
		}
	}
	fmt.Println("sweep done")
	return nil
}
