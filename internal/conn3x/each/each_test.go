// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package each

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// tree writes files, by slash path, under a new root and loads it.
func tree(t *testing.T, files map[string]string) *Tree {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tr, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// A repository of the usual shape: network in s3, app reading it, db in
// gcs read by app, a shared module, and a reporting configuration that
// reads network's state through a variable, so it names it by hand.
var repo = map[string]string{
	"network/main.tf": `terraform {
  backend "s3" {
    bucket = "acme-tf"
    key    = "prod/network.tfstate"
    region = "eu-west-1"
  }
}`,
	"db/main.tf": `terraform {
  backend "gcs" {
    bucket = "acme-tf"
    prefix = "prod/db"
  }
}`,
	"app/main.tf": `terraform {
  backend "s3" {
    bucket = "acme-tf"
    key    = "prod/app.tfstate"
  }
}
data "terraform_remote_state" "network" {
  backend = "s3"
  config  = { bucket = "acme-tf", key = "prod/network.tfstate", region = "eu-west-1" }
}
data "terraform_remote_state" "db" {
  backend = "gcs"
  config = {
    bucket = "acme-tf"
    prefix = "prod/db"
  }
}
module "web" {
  source = "../modules/web"
}`,
	"modules/web/main.tf":    `module "nginx" { source = "./nginx" }`,
	"modules/web/nginx/x.tf": `variable "port" {}`,
	"report/main.tf": `variable "state_key" {}
data "terraform_remote_state" "network" {
  backend = "s3"
  config  = { bucket = "acme-tf", key = var.state_key }
}`,
	"report/conn3x.each.hcl": `depends_on = ["../network"]
watch      = ["../policies"]`,
	"policies/readme.md": "not a configuration",
	"local/a/main.tf":    `output "x" { value = 1 }`,
	"local/b/main.tf": `data "terraform_remote_state" "a" {
  backend = "local"
  config  = { path = "../a/terraform.tfstate" }
}`,
	".terraform/modules/x/main.tf": `module "nope" {}`,
}

func TestRootsAndEdges(t *testing.T) {
	tr := tree(t, repo)
	if got, want := tr.Roots(), []string{"app", "db", "local/a", "local/b", "network", "report"}; !reflect.DeepEqual(got, want) {
		t.Errorf("roots %v, want %v", got, want)
	}
	for dir, want := range map[string][]string{
		"app":     {"db", "network"},
		"report":  {"network"},
		"local/b": {"local/a"},
		"network": nil,
	} {
		if got := tr.Edges[dir]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s depends on %v, want %v", dir, got, want)
		}
	}
	if len(tr.Problems) != 1 || !strings.Contains(tr.Problems[0], "report: couldn't work out which configuration data.terraform_remote_state.network reads") {
		t.Errorf("problems %q", tr.Problems)
	}
}

func TestChanged(t *testing.T) {
	tr := tree(t, repo)
	for name, tc := range map[string]struct {
		files []string
		want  []string
	}{
		"its own file":           {[]string{"db/main.tf"}, []string{"app", "db"}},
		"a module two deep":      {[]string{"modules/web/nginx/x.tf"}, []string{"app"}},
		"upstream of two":        {[]string{"network/main.tf"}, []string{"app", "network", "report"}},
		"a watched path":         {[]string{"policies/readme.md"}, []string{"report"}},
		"a local state reader":   {[]string{"local/a/main.tf"}, []string{"local/a", "local/b"}},
		"nothing that's read":    {[]string{"README.md"}, nil},
		"a lock file":            {[]string{"report/.terraform.lock.hcl"}, []string{"report"}},
		"a prefix that isn't it": {[]string{"network-old/main.tf"}, nil},
	} {
		if got := tr.Changed(tc.files); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestLevels(t *testing.T) {
	tr := tree(t, repo)
	got, err := tr.Levels(tr.Roots())
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"db", "local/a", "network"}, {"app", "local/b", "report"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("levels %v, want %v", got, want)
	}
	// A dependency left out of the set doesn't hold anything back.
	if got, _ := tr.Levels([]string{"app"}); !reflect.DeepEqual(got, [][]string{{"app"}}) {
		t.Errorf("app alone: %v", got)
	}

	cyc := tree(t, map[string]string{
		"a/main.tf": `terraform {
  backend "local" {
    path = "a.tfstate"
  }
}
data "terraform_remote_state" "b" {
  backend = "local"
  config  = { path = "../b/b.tfstate" }
}`,
		"b/main.tf": `terraform {
  backend "local" {
    path = "b.tfstate"
  }
}
data "terraform_remote_state" "a" {
  backend = "local"
  config  = { path = "../a/a.tfstate" }
}`,
	})
	if _, err := cyc.Levels(cyc.Roots()); err == nil || !strings.Contains(err.Error(), "cycle: a, b") {
		t.Errorf("a cycle: %v", err)
	}
}

// A directory that something calls as a module is still a root when it
// has a backend of its own.
func TestModuleWithBackendIsRoot(t *testing.T) {
	tr := tree(t, map[string]string{
		"shared/main.tf": `terraform {
  backend "s3" {
    bucket = "b"
    key    = "shared"
  }
}`,
		"app/main.tf": `module "s" { source = "../shared" }`,
	})
	if got := tr.Roots(); !reflect.DeepEqual(got, []string{"app", "shared"}) {
		t.Errorf("roots %v", got)
	}
}

func TestBadEachFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte(`output "x" { value = 1 }`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(`depends_on = "network"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "depends_on must be a list of paths") {
		t.Errorf("a string depends_on: %v", err)
	}
}
