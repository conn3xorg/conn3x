// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package doapi is the small slice of the DigitalOcean API the real-host
// tests need to clean up after themselves.
package doapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Tag marks everything the tests create.
const Tag = "conn3x-ci"

// Client talks to the DigitalOcean API with a token.
type Client struct {
	Token   string
	HTTP    *http.Client
	BaseURL string // defaults to the public API
}

// Droplet is the part of a droplet the cleanup needs.
type Droplet struct {
	ID      int       `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created_at"`
}

// SSHKey is the part of an SSH key the cleanup needs.
type SSHKey struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	base := c.BaseURL
	if base == "" {
		base = "https://api.digitalocean.com/v2"
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound && method == http.MethodDelete {
		return nil
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// TaggedDroplets lists the droplets carrying Tag.
func (c *Client) TaggedDroplets(ctx context.Context) ([]Droplet, error) {
	var out struct {
		Droplets []Droplet `json:"droplets"`
	}
	err := c.do(ctx, http.MethodGet, "/droplets?per_page=200&tag_name="+Tag, &out)
	return out.Droplets, err
}

// DeleteDroplet deletes one droplet. A droplet that is already gone is fine.
func (c *Client) DeleteDroplet(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, "/droplets/"+strconv.Itoa(id), nil)
}

// SSHKeys lists the account's SSH keys whose names start with prefix.
func (c *Client) SSHKeys(ctx context.Context, prefix string) ([]SSHKey, error) {
	var out struct {
		SSHKeys []SSHKey `json:"ssh_keys"`
	}
	if err := c.do(ctx, http.MethodGet, "/account/keys?per_page=200", &out); err != nil {
		return nil, err
	}
	var keys []SSHKey
	for _, k := range out.SSHKeys {
		if strings.HasPrefix(k.Name, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// DeleteSSHKey deletes one SSH key.
func (c *Client) DeleteSSHKey(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, "/account/keys/"+strconv.Itoa(id), nil)
}

// DeleteRun removes the droplet and SSH key named conn3x-ci-<runID>.
func (c *Client) DeleteRun(ctx context.Context, runID string) error {
	name := Tag + "-" + runID
	droplets, err := c.TaggedDroplets(ctx)
	if err != nil {
		return err
	}
	for _, d := range droplets {
		if d.Name == name {
			if err := c.DeleteDroplet(ctx, d.ID); err != nil {
				return err
			}
		}
	}
	keys, err := c.SSHKeys(ctx, name)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.Name == name {
			if err := c.DeleteSSHKey(ctx, k.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
