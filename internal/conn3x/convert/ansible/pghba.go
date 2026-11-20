// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// pgHbaTypes and pgHbaMethods are what community.postgresql's
// postgresql_pg_hba accepts (PG_HBA_TYPES, PG_HBA_METHODS).
var (
	pgHbaTypes   = []string{"local", "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"}
	pgHbaMethods = []string{"trust", "reject", "md5", "password", "gss", "sspi", "krb5", "ident", "peer", "ldap", "radius", "cert", "pam", "scram-sha-256"}
)

// pgHbaCatchAll is where a new rule goes: above the first rule of its kind
// (local, or one of the host types) for all databases and all users.
// PostgreSQL uses the first rule that matches, so appended after such a
// rule, the new one would never be reached; above the first rule of all,
// a local all all rule would shut out Debian's local all postgres peer,
// which Conn3x's PostgreSQL steps log in by. Ansible sorts the whole file
// instead, more specific rules first; this is the part of that order a
// stock file needs.
func pgHbaCatchAll(contype string) string {
	kind := `host(ssl|nossl|gssenc|nogssenc)?`
	if contype == "local" {
		kind = `local`
	}
	return `^\s*` + kind + `\s+all\s+all\s`
}

// pgHbaModule converts community.postgresql.postgresql_pg_hba with one
// rule into a line step. Ansible keys a rule by type, database, user and
// source, so the step's regexp matches those and a rule with the same key
// and another method or options is replaced in place.
func pgHbaModule(in *input) ([]step, string) {
	for _, k := range []string{"rules", "rules_behavior", "comment", "backup_file"} {
		if in.has(k) {
			return nil, "sets " + k + ", which a line step can't do"
		}
	}
	if in.bool("overwrite", false) {
		return nil, "sets overwrite, which replaces every rule in the file; write the whole file with a file step"
	}
	in.ignore("overwrite", "sort_rules", "keep_comments_at_rules")
	dest := in.str("dest")
	contype := in.str("contype")
	databases, users := in.str("databases"), in.str("users")
	address := in.str("address", "source", "src")
	netmask, method, options := in.str("netmask"), in.str("method"), in.str("options")
	if in.problem != "" {
		return nil, in.problem
	}
	if databases == "" {
		databases = "all"
	}
	if users == "" {
		users = "all"
	}
	if address == "" {
		address = "samehost"
	}
	if method == "" {
		method = "md5"
	}
	switch {
	case dest == "":
		return nil, "has no dest"
	case contype == "":
		return nil, "has no contype, so Ansible changes nothing"
	case !slices.Contains(pgHbaTypes, contype):
		return nil, "has contype " + contype + ", which Ansible refuses"
	case !slices.Contains(pgHbaMethods, method):
		return nil, "has method " + method + ", which Ansible refuses"
	}
	for _, v := range []string{databases, users, address, netmask, method, options} {
		if strings.Contains(v, "${") || strings.Contains(v, "{{") || strings.ContainsAny(v, "\n\r#") {
			return nil, "has a value that's still a template, or has a line break or #, so its rule can't be matched"
		}
	}
	for _, v := range []string{databases, users} {
		if strings.Contains(v, ",") || strings.HasPrefix(v, `"`) || strings.ContainsAny(v, " \t") {
			return nil, "lists several databases or users, or quotes one, which Ansible turns into a rule each"
		}
	}

	fields := []string{contype, databases, users}
	if contype != "local" {
		src, why := pgHbaSource(address, netmask)
		if why != "" {
			return nil, why
		}
		fields = append(fields, src)
	}
	key := `^\s*` + strings.Join(quoteAll(fields), `\s+`) + `(\s|$)`
	opts, why := pgHbaOptions(options)
	if why != "" {
		return nil, why
	}
	line := strings.Join(append(fields, method), " ")
	if opts != "" {
		line += " " + opts
	}
	attrs := []attr{s("path", dest), s("line", line), s("regexp", key)}
	if in.state("present", "present", "absent") == "absent" {
		attrs = append(attrs, s("state", "absent"))
	} else {
		attrs = append(attrs, s("insertbefore", pgHbaCatchAll(contype)))
	}
	if in.bool("create", false) {
		attrs = append(attrs, attr{key: "create", val: cty.True})
	}
	attrs, why = in.editFileArgs(attrs)
	if why != "" {
		return nil, why
	}
	note := "Ansible sorts the whole of pg_hba.conf, more specific rules first; this step puts the rule above the first rule of its kind for all databases and all users, or at the end. PostgreSQL reads the file again only on a reload, which Ansible doesn't do either, so notify a handler that reloads it."
	return one("line", attrs, note)
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = regexp.QuoteMeta(s)
	}
	return out
}

// pgHbaSource is a rule's source as Ansible writes it: a network in CIDR
// form, with an address and netmask joined into one, or a host name or a
// keyword such as samehost as it is.
func pgHbaSource(address, netmask string) (string, string) {
	if strings.HasPrefix(address, `"`) {
		return "", "quotes its address"
	}
	if p, err := netip.ParsePrefix(address); err == nil {
		if netmask != "" {
			return "", "sets netmask with an address in CIDR form, which Ansible refuses"
		}
		if p.Masked() != p {
			return "", "has the address " + address + ", which has host bits set, and Ansible refuses it"
		}
		return p.String(), ""
	}
	if a, err := netip.ParseAddr(address); err == nil {
		m, err := netip.ParseAddr(netmask)
		if netmask == "" || err != nil || m.Is4() != a.Is4() {
			return "", "has an address without a CIDR suffix and no netmask of its kind, which Ansible refuses"
		}
		bits, ok := maskBits(m)
		if !ok {
			return "", "has the netmask " + netmask + ", which isn't contiguous"
		}
		p := netip.PrefixFrom(a, bits)
		if p.Masked() != p {
			return "", "has the address " + address + ", which has host bits set for its netmask, and Ansible refuses it"
		}
		return p.String(), ""
	}
	if netmask != "" {
		return "", "sets netmask with a host name, which Ansible refuses"
	}
	if strings.ContainsAny(address, `:\/@+ `) {
		return "", "has the address " + address + ", which Ansible reads as neither an address nor a host name"
	}
	return address, ""
}

// maskBits is the prefix length of a netmask such as 255.255.255.0.
func maskBits(m netip.Addr) (int, bool) {
	b, bits, ended := m.AsSlice(), 0, false
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			if x&(1<<i) != 0 {
				if ended {
					return 0, false
				}
				bits++
			} else {
				ended = true
			}
		}
	}
	return bits, true
}

// pgHbaOptions is a rule's options as Ansible writes them: key=value
// pairs, sorted by key.
func pgHbaOptions(options string) (string, string) {
	if options == "" {
		return "", ""
	}
	if strings.Contains(options, `"`) {
		return "", "quotes an option"
	}
	opts := strings.Fields(options)
	keys := map[string]bool{}
	for _, o := range opts {
		k, v, ok := strings.Cut(o, "=")
		if !ok || k == "" || v == "" || keys[k] {
			return "", "has options " + options + ", which Ansible refuses: each must be key=value, once"
		}
		keys[k] = true
	}
	sort.Strings(opts)
	return strings.Join(opts, " "), ""
}
