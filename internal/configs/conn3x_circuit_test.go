// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"

	"github.com/opentofu/opentofu/internal/configs/symlib"
)

func loadCircuitModule(t *testing.T, files map[string]string) (*Module, hcl.Diagnostics) {
	t.Helper()
	full := map[string]string{}
	for name, src := range files {
		full["mod/"+name] = src
	}
	mod, diags := testParser(full).LoadConfigDir("mod")
	if mod != nil {
		diags = diags.Extend(mod.Finalize(symlib.EmptyTable, RootModuleCallForTesting()))
	}
	return mod, diags
}

const webCircuit = `
resource "terraform_data" "box" {
  input = "203.0.113.10"
}

circuit "web" {
  hosts = { web1 = terraform_data.box.output }
  ssh {
    user             = "root"
    private_key_file = "~/.ssh/id_ed25519"
  }

  step "motd" {
    file {
      path    = "/etc/motd"
      content = "hello ${each.key}\n"
    }
  }

  step "issue" {
    depends_on = [terraform_data.box]
    file {
      path    = "/etc/issue"
      content = conn3x_file.web__motd[each.key].sha256
    }
  }
}
`

func TestCircuitLowersToResources(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": webCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	motd, ok := mod.ManagedResources["conn3x_file.web__motd"]
	if !ok {
		t.Fatalf("no conn3x_file.web__motd; have %v", keys(mod.ManagedResources))
	}
	issue := mod.ManagedResources["conn3x_file.web__issue"]
	if issue == nil {
		t.Fatal("no conn3x_file.web__issue")
	}

	if motd.ForEach == nil || issue.ForEach == nil {
		t.Fatal("steps are not repeated over hosts")
	}
	if got := motd.Provider.String(); got != "terraform.io/builtin/conn3x" {
		t.Fatalf("provider = %s", got)
	}

	// The first step has no step dependencies; the second follows it and
	// keeps its own depends_on.
	if len(motd.DependsOn) != 0 {
		t.Fatalf("first step depends on %v", motd.DependsOn)
	}
	var deps []string
	for _, d := range issue.DependsOn {
		deps = append(deps, traversalString(d))
	}
	if strings.Join(deps, ",") != "terraform_data.box,conn3x_file.web__motd" {
		t.Fatalf("second step depends_on = %v", deps)
	}

	// The step body has the module arguments plus an ssh block whose host
	// comes from each.value.
	content, diags := motd.Config.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "path"}, {Name: "content"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "ssh"}},
	})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if len(content.Blocks) != 1 {
		t.Fatalf("got %d ssh blocks", len(content.Blocks))
	}
	ssh, diags := content.Blocks[0].Body.JustAttributes()
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	host, ok := ssh["host"]
	if !ok {
		t.Fatal("ssh block has no host")
	}
	refs := host.Expr.Variables()
	if len(refs) != 1 || traversalString(refs[0]) != "each.value" {
		t.Fatalf("host = %v, want each.value", refs)
	}
	if _, ok := ssh["user"]; !ok {
		t.Fatal("circuit ssh settings not copied to the step")
	}
}

func TestCircuitInTfFile(t *testing.T) {
	_, diags := loadCircuitModule(t, map[string]string{"main.tf": webCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
}

func TestCircuitErrors(t *testing.T) {
	for name, tc := range map[string]struct{ src, want string }{
		"missing hosts": {`circuit "a" {
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "hosts"},
		"host in circuit ssh": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
    host = "1.2.3.4"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "comes from hosts"},
		"unknown module": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    packge {
      name = "nginx"
    }
  }
}`, `Unknown module "packge"`},
		"two modules": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path = "/x"
      content = "x"
    }
    file {
      path = "/y"
      content = "y"
    }
  }
}`, "exactly one module"},
		"duplicate step": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
  step "s" {
    file {
      path    = "/y"
      content = "y"
    }
  }
}`, "Duplicate step"},
		"duplicate circuit": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}
circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "t" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "Duplicate circuit"},
		"double underscore": {`circuit "a__b" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "Invalid circuit name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": tc.src})
			if !diags.HasErrors() {
				t.Fatal("no error")
			}
			if !strings.Contains(diags.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", diags.Error(), tc.want)
			}
		})
	}
}

func keys(m map[string]*Resource) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func traversalString(tr hcl.Traversal) string {
	var parts []string
	for _, step := range tr {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			parts = append(parts, s.Name)
		case hcl.TraverseAttr:
			parts = append(parts, s.Name)
		}
	}
	return strings.Join(parts, ".")
}
