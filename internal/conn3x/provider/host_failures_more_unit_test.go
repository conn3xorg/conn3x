// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// brHostSteps are more host steps, each with the arguments it needs to
// plan.
var brHostSteps = map[string]map[string]cty.Value{
	"conn3x_acl":                 {"etype": cty.StringVal("user"), "entity": cty.StringVal("deploy"), "path": cty.StringVal("/srv"), "permissions": cty.StringVal("rx")},
	"conn3x_alternatives":        {"name": cty.StringVal("editor"), "path": cty.StringVal("/usr/bin/vim")},
	"conn3x_archive":             {"creates": cty.StringVal("/opt/app/bin"), "dest": cty.StringVal("/opt/app"), "src": cty.StringVal("/tmp/app.tar.gz")},
	"conn3x_authorized_key":      {"key": cty.StringVal(brKeyA), "user": cty.StringVal("deploy")},
	"conn3x_block":               {"path": cty.StringVal("/etc/hosts"), "block": cty.StringVal("10.0.0.1 db")},
	"conn3x_crontab":             {"user": cty.StringVal("root")},
	"conn3x_debconf":             {"name": cty.StringVal("postfix"), "question": cty.StringVal("postfix/main_mailer_type"), "vtype": cty.StringVal("select"), "value": cty.StringVal("Internet Site")},
	"conn3x_directory":           {"path": cty.StringVal("/srv/app")},
	"conn3x_download":            {"dest": cty.StringVal("/opt/a.tgz"), "sha256": cty.StringVal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "url": cty.StringVal("https://example.com/a.tgz")},
	"conn3x_file":                {"path": cty.StringVal("/etc/motd"), "content": cty.StringVal("hi\n")},
	"conn3x_filesystem":          {"device": cty.StringVal("/dev/vdb"), "type": cty.StringVal("ext4")},
	"conn3x_firewalld":           {"service": cty.StringVal("http")},
	"conn3x_git":                 {"dest": cty.StringVal("/srv/app"), "repo": cty.StringVal("https://example.com/app.git")},
	"conn3x_hostname":            {"name": cty.StringVal("web1")},
	"conn3x_ini":                 {"option": cty.StringVal("x"), "path": cty.StringVal("/etc/a.ini"), "section": cty.StringVal("s"), "value": cty.StringVal("1")},
	"conn3x_iptables_rule":       {"chain": cty.StringVal("INPUT"), "jump": cty.StringVal("ACCEPT")},
	"conn3x_json_value":          {"key": cty.StringVal("a"), "path": cty.StringVal("/etc/a.json"), "value": cty.StringVal("1")},
	"conn3x_known_hosts":         {"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA)},
	"conn3x_limit":               {"domain": cty.StringVal("*"), "item": cty.StringVal("nofile"), "path": cty.StringVal("/etc/security/limits.d/90.conf"), "type": cty.StringVal("soft"), "value": cty.StringVal("1024")},
	"conn3x_line":                {"path": cty.StringVal("/etc/a"), "line": cty.StringVal("x=1")},
	"conn3x_link":                {"path": cty.StringVal("/usr/local/bin/app"), "target": cty.StringVal("/opt/app/bin/app")},
	"conn3x_locale":              {"name": cty.StringVal("en_US.UTF-8")},
	"conn3x_mount":               {"fstype": cty.StringVal("ext4"), "path": cty.StringVal("/data"), "src": cty.StringVal("/dev/vdb1")},
	"conn3x_nftables":            {"content": cty.StringVal("chain input {\n}\n"), "table": cty.StringVal("filter")},
	"conn3x_postgresql_database": {"name": cty.StringVal("app")},
	"conn3x_replace":             {"path": cty.StringVal("/etc/a"), "regexp": cty.StringVal("a"), "replace": cty.StringVal("b")},
	"conn3x_selinux_boolean":     {"name": cty.StringVal("httpd_can_network_connect"), "value": cty.True},
	"conn3x_selinux_fcontext":    {"setype": cty.StringVal("httpd_sys_content_t"), "target": cty.StringVal("/srv/www(/.*)?")},
	"conn3x_selinux_mode":        {"mode": cty.StringVal("enforcing")},
	"conn3x_ssh_keypair":         {"path": cty.StringVal("/root/.ssh/id_ed25519")},
	"conn3x_sudoers":             {"commands": cty.ListVal([]cty.Value{cty.StringVal("/usr/bin/systemctl restart app")}), "name": cty.StringVal("deploy"), "user": cty.StringVal("deploy")},
	"conn3x_timezone":            {"name": cty.StringVal("UTC")},
	"conn3x_tls_private_key":     {"path": cty.StringVal("/etc/ssl/private/a.key")},
	"conn3x_ufw_rule":            {"action": cty.StringVal("allow"), "port": cty.StringVal("80")},
	"conn3x_xml_value":           {"path": cty.StringVal("/etc/a.xml"), "xpath": cty.StringVal("/a/b"), "value": cty.StringVal("1")},
	"conn3x_package_sources":     {},
}

// brReadsDrift are steps whose refresh on a host that fails every command
// isn't an error: it reports them out of sync, or gone. alternatives reads
// a failed command with no message as nothing registered, since Red Hat's
// tool says nothing for any error, so its removal is a no-op too.
var brReadsDrift = map[string]bool{
	"conn3x_alternatives": true, "conn3x_archive": true, "conn3x_authorized_key": true, "conn3x_hostname": true,
	"conn3x_locale": true, "conn3x_timezone": true,
}

// On a host whose every command fails, creating any host step fails, so
// does refreshing one, and so does removing one with on_remove = "delete".
func TestMoreHostStepsSurfaceHostFailures(t *testing.T) {
	broken := unitHost(t, (&unitScripts{}).on("", "!sh: the host broke").answer)
	steps := map[string]map[string]cty.Value{}
	for k, v := range unitHostSteps {
		steps[k] = v
	}
	for k, v := range brHostSteps {
		steps[k] = v
	}
	for typeName, attrs := range steps {
		t.Run(typeName, func(t *testing.T) {
			rt := resourceTypes[typeName]
			cfg := eosStep(typeName, attrs, broken)
			if d := rt.validate(cfg); d.HasErrors() {
				t.Fatalf("validate: %v", d.Err())
			}
			null := cty.NullVal(cfg.Type())
			plan := rt.plan(providers.PlanResourceChangeRequest{PriorState: null, ProposedNewState: cfg, Config: cfg})
			if plan.Diagnostics.HasErrors() {
				t.Fatalf("plan: %v", plan.Diagnostics.Err())
			}
			if resp := rt.apply(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: null, PlannedState: plan.PlannedState, Config: cfg}); !resp.Diagnostics.HasErrors() {
				t.Error("created on a broken host")
			}
			// State as an apply would have left it, in sync.
			vals := cfg.AsValueMap()
			for k, v := range plan.PlannedState.AsValueMap() {
				if v.IsKnown() {
					vals[k] = v
				}
			}
			vals["id"] = cty.StringVal(typeName + " on web1")
			if _, ok := vals["in_sync"]; ok {
				vals["in_sync"] = cty.True
			}
			_, removable := vals["on_remove"]
			if removable {
				vals["on_remove"] = cty.StringVal(onRemoveDelete)
			}
			prior := cty.ObjectVal(vals)
			if brReadsDrift[typeName] {
				return
			}
			if resp := rt.read(ctx, providers.ReadResourceRequest{TypeName: typeName, PriorState: prior}); !resp.Diagnostics.HasErrors() {
				t.Errorf("refreshed on a broken host: %#v", resp.NewState)
			}
			if resp := rt.apply(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: prior, PlannedState: null}); removable && !resp.Diagnostics.HasErrors() {
				t.Error("deleted on a broken host")
			}
		})
	}
}
