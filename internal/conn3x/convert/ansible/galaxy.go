// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// A Galaxy role, as -role takes it: namespace.name, or namespace.name,version.
var galaxyRoleRe = regexp.MustCompile(`^([A-Za-z0-9_-]{1,64})\.([A-Za-z0-9_-]{1,64})(?:,([A-Za-z0-9._+-]{1,64}))?$`)

// GalaxyAPI and GitHubArchive are where roles come from; tests point them
// at a local server.
var (
	GalaxyAPI     = "https://galaxy.ansible.com/api/v1"
	GitHubArchive = "https://github.com"
)

// maxRoleArchive bounds a role download, and maxRoleFiles what it unpacks
// to: roles are small, and a bigger archive is more likely a mistake.
const (
	maxRoleArchive = 64 << 20
	maxRoleFiles   = 256 << 20
)

// IsGalaxyRole reports whether spec reads as a Galaxy role rather than a
// directory. A directory of that name on disk wins; the caller checks.
func IsGalaxyRole(spec string) bool { return galaxyRoleRe.MatchString(spec) }

// GalaxyRole is a role fetched from Galaxy.
type GalaxyRole struct {
	Name    string // namespace.name
	Version string // the tag fetched, or the commit when the role has no versions
	Repo    string // the GitHub repository it came from
	Dir     string // where it was unpacked
}

// FetchGalaxyRole downloads a Galaxy role into a new directory under dir,
// named namespace.name as ansible-galaxy names it, and returns it. Without
// a version it takes the highest one Galaxy lists, by semantic version.
func FetchGalaxyRole(ctx context.Context, spec, dir string) (GalaxyRole, error) {
	m := galaxyRoleRe.FindStringSubmatch(spec)
	if m == nil {
		return GalaxyRole{}, fmt.Errorf("%q isn't a Galaxy role: write it namespace.name, or namespace.name,version", spec)
	}
	owner, name, want := m[1], m[2], m[3]
	client := &http.Client{Timeout: 2 * time.Minute}
	q := url.Values{"owner__username": {owner}, "name": {name}}
	var found struct {
		Results []struct {
			GitHubUser    string `json:"github_user"`
			GitHubRepo    string `json:"github_repo"`
			Commit        string `json:"commit"`
			SummaryFields struct {
				Versions []struct {
					Name string `json:"name"`
				} `json:"versions"`
			} `json:"summary_fields"`
		} `json:"results"`
	}
	if err := getJSON(ctx, client, GalaxyAPI+"/roles/?"+q.Encode(), &found); err != nil {
		return GalaxyRole{}, fmt.Errorf("looking up %s.%s on Galaxy: %w", owner, name, err)
	}
	if len(found.Results) != 1 {
		return GalaxyRole{}, fmt.Errorf("Galaxy has no role %s.%s; a collection's roles come with the collection, which -role doesn't download", owner, name)
	}
	r := found.Results[0]
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`).MatchString(r.GitHubUser + r.GitHubRepo) {
		return GalaxyRole{}, fmt.Errorf("Galaxy gives %s.%s an odd repository, %s/%s; download it yourself", owner, name, r.GitHubUser, r.GitHubRepo)
	}
	var versions []string
	for _, v := range r.SummaryFields.Versions {
		versions = append(versions, v.Name)
	}
	ref := want
	switch {
	case want != "":
		found := false
		for _, v := range versions {
			found = found || v == want
		}
		if !found {
			return GalaxyRole{}, fmt.Errorf("%s.%s has no version %s on Galaxy; it has %s", owner, name, want, strings.Join(versions, ", "))
		}
	case len(versions) > 0:
		ref = highest(versions)
	case regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(r.Commit):
		ref = r.Commit
	default:
		return GalaxyRole{}, fmt.Errorf("%s.%s has no versions on Galaxy; give one, as %s.%s,<version>", owner, name, owner, name)
	}
	repo := r.GitHubUser + "/" + r.GitHubRepo
	dest := filepath.Join(dir, owner+"."+name)
	if err := os.Mkdir(dest, 0o755); err != nil {
		return GalaxyRole{}, err
	}
	if err := fetchTarball(ctx, client, GitHubArchive+"/"+repo+"/archive/"+url.PathEscape(ref)+".tar.gz", dest); err != nil {
		return GalaxyRole{}, fmt.Errorf("downloading %s.%s %s from github.com/%s: %w", owner, name, ref, repo, err)
	}
	return GalaxyRole{Name: owner + "." + name, Version: ref, Repo: "https://github.com/" + repo, Dir: dest}, nil
}

// highest is the newest version, by semantic version where they parse,
// and otherwise the last in Galaxy's list.
func highest(versions []string) string {
	sv := func(v string) string {
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		return v
	}
	sorted := append([]string{}, versions...)
	sort.SliceStable(sorted, func(i, j int) bool { return semver.Compare(sv(sorted[i]), sv(sorted[j])) < 0 })
	if !semver.IsValid(sv(sorted[len(sorted)-1])) {
		return versions[0]
	}
	return sorted[len(sorted)-1]
}

func getJSON(ctx context.Context, client *http.Client, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}

// fetchTarball unpacks a GitHub archive into dest, without its top
// directory. Only plain files and directories come out: an entry that
// would land outside dest, a link, or a device is refused, since the
// archive is someone else's.
func fetchTarball(ctx context.Context, client *http.Client, u, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	if resp.ContentLength > maxRoleArchive {
		return fmt.Errorf("the archive is %d bytes, more than a role should be", resp.ContentLength)
	}
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxRoleArchive+1))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var written int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue // GitHub's archives start with one, holding the commit
		}
		clean := path.Clean(h.Name)
		// Cleaned, a name that climbs out starts with .. or /.
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("the archive has %q, which would land outside the role", h.Name)
		}
		_, rel, ok := strings.Cut(clean, "/")
		if !ok || rel == "" {
			continue // the top directory itself
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			written += h.Size
			if written > maxRoleFiles {
				return errors.New("the archive unpacks to more than a role should be")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			_, err = io.CopyN(f, tr, h.Size)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("the archive has %q, a link or special file; a role is plain files, so download it yourself if this one needs that", h.Name)
		}
	}
}
