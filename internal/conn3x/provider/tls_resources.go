// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/tls"
	"github.com/opentofu/opentofu/internal/providers"
)

// tlsNow is the time certificate expiry is judged against; tests move it.
var tlsNow = time.Now

func intOr(v cty.Value, fallback int) int {
	if !known(v) {
		return fallback
	}
	n, _ := v.AsBigFloat().Int64()
	return int(n)
}

func tlsKeySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A private key in a PEM file, generated on the host with its openssl, so the key never leaves it. Only the public key is in state.",
		Attributes: map[string]*configschema.Attribute{
			"id":             {Type: cty.String, Computed: true},
			"revision":       revisionAttr(),
			"path":           {Type: cty.String, Required: true, Description: "Absolute path of the key file."},
			"type":           {Type: cty.String, Optional: true, Description: "\"rsa\" (default), \"ecdsa\" or \"ed25519\". Changing it, or bits or curve, generates a new key."},
			"bits":           {Type: cty.Number, Optional: true, Description: "For rsa: 2048, 3072 (default) or 4096."},
			"curve":          {Type: cty.String, Optional: true, Description: "For ecdsa: \"P-256\" (default) or \"P-384\"."},
			"mode":           {Type: cty.String, Optional: true, Description: "Octal permissions, ending in 0 so others can't read it. Defaults to \"0600\"."},
			"owner":          {Type: cty.String, Optional: true, Description: "Owner. Unset keeps the file's."},
			"group":          {Type: cty.String, Optional: true, Description: "Group. Unset keeps the file's."},
			"on_remove":      {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the key, \"delete\" removes it."},
			"public_key_pem": {Type: cty.String, Computed: true, Description: "The key's public half, PEM-encoded."},
			"in_sync":        {Type: cty.Bool, Computed: true, Description: "Whether the file holds a key of this kind with this mode, owner and group."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func tlsKeyFrom(v cty.Value) tls.Key {
	bits := 0
	if b := v.GetAttr("bits"); known(b) {
		bits = intOr(b, 0)
	}
	return tls.Key{Path: stringOr(v.GetAttr("path"), ""), Type: stringOr(v.GetAttr("type"), ""), Bits: bits, Curve: stringOr(v.GetAttr("curve"), ""),
		Mode: stringOr(v.GetAttr("mode"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), "")}
}

// unknownWhenStale marks computed attributes unknown in a plan that will
// change the host, since apply decides them.
func unknownWhenStale(resp providers.PlanResourceChangeResponse, attrs ...string) providers.PlanResourceChangeResponse {
	if resp.PlannedState.IsNull() || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	for _, a := range attrs {
		vals[a] = cty.UnknownVal(vals[a].Type())
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func planTLSKey(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return unknownWhenStale(planSynced(req, "tls_private_key", []string{"path"}, []string{"type", "bits", "curve", "mode", "owner", "group"}), "public_key_pem")
}

func readTLSKey(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		k := tlsKeyFrom(prior)
		s, err := tls.ReadKey(ctx, h, k.Path)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(withAttr(prior, "public_key_pem", s.PublicKeyPEM), k.Matches(s)), nil
	})
}

func applyTLSKey(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			k := tlsKeyFrom(planned)
			if err := tls.ApplyKey(ctx, h, k); err != nil {
				return cty.NilVal, fmt.Errorf("tls_private_key %s: %w", k.Path, err)
			}
			s, err := tls.ReadKey(ctx, h, k.Path)
			if err != nil {
				return cty.NilVal, err
			}
			return withSync(withAttr(planned, "public_key_pem", s.PublicKeyPEM), true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return tls.DeleteKey(ctx, h, tlsKeyFrom(prior).Path)
		})
}

func tlsCertSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A self-signed certificate for a key already on the host, such as one from tls_private_key, made with the host's openssl and renewed before it expires.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"path":              {Type: cty.String, Required: true, Description: "Absolute path of the certificate file."},
			"key_path":          {Type: cty.String, Required: true, Description: "Absolute path of the private key it's for."},
			"common_name":       {Type: cty.String, Required: true, Description: "Subject common name, such as the host's name."},
			"dns_names":         {Type: cty.List(cty.String), Optional: true, Description: "Host names in the subject alternative names. Clients check these, not the common name."},
			"ip_addresses":      {Type: cty.List(cty.String), Optional: true, Description: "IP addresses in the subject alternative names."},
			"days":              {Type: cty.Number, Optional: true, Description: "How long it's valid, from 1 to 3650 days. Defaults to 365."},
			"renew_before_days": {Type: cty.Number, Optional: true, Description: "Refresh plans a new certificate when fewer days than this are left. Defaults to 30."},
			"mode":              {Type: cty.String, Optional: true, Description: "Octal permissions. Defaults to \"0644\"."},
			"owner":             {Type: cty.String, Optional: true, Description: "Owner. Unset keeps the file's."},
			"group":             {Type: cty.String, Optional: true, Description: "Group. Unset keeps the file's."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file, \"delete\" removes it."},
			"cert_pem":          {Type: cty.String, Computed: true, Description: "The certificate, PEM-encoded, for clients to trust."},
			"not_after":         {Type: cty.String, Computed: true, Description: "When it expires, in RFC 3339."},
			"in_sync":           {Type: cty.Bool, Computed: true, Description: "Whether the file holds a certificate for the key with these names and enough days left."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func tlsCertFrom(v cty.Value) tls.Cert {
	return tls.Cert{Path: stringOr(v.GetAttr("path"), ""), KeyPath: stringOr(v.GetAttr("key_path"), ""), CommonName: stringOr(v.GetAttr("common_name"), ""),
		DNSNames: stringList(v.GetAttr("dns_names")), IPs: stringList(v.GetAttr("ip_addresses")),
		Days: intOr(v.GetAttr("days"), 0), RenewDays: intOr(v.GetAttr("renew_before_days"), 0),
		Mode: stringOr(v.GetAttr("mode"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), "")}
}

func planTLSCert(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return unknownWhenStale(planSynced(req, "tls_self_signed_cert", []string{"path"},
		[]string{"key_path", "common_name", "dns_names", "ip_addresses", "days", "renew_before_days", "mode", "owner", "group"}), "cert_pem", "not_after")
}

func certAttrs(v cty.Value, s tls.CertState) cty.Value {
	notAfter := ""
	if !s.NotAfter.IsZero() {
		notAfter = s.NotAfter.UTC().Format(time.RFC3339)
	}
	return withAttr(withAttr(v, "cert_pem", s.PEM), "not_after", notAfter)
}

func readTLSCert(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := tlsCertFrom(prior)
		s, err := tls.ReadCert(ctx, h, c)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(certAttrs(prior, s), c.Matches(s, tlsNow())), nil
	})
}

func applyTLSCert(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			c := tlsCertFrom(planned)
			if err := tls.ApplyCert(ctx, h, c, tlsNow()); err != nil {
				return cty.NilVal, fmt.Errorf("tls_self_signed_cert %s: %w", c.Path, err)
			}
			s, err := tls.ReadCert(ctx, h, c)
			if err != nil {
				return cty.NilVal, err
			}
			return withSync(certAttrs(planned, s), true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return tls.DeleteCert(ctx, h, tlsCertFrom(prior).Path)
		})
}

// withAttr is v with a string attribute set; "" makes it null.
func withAttr(v cty.Value, name, s string) cty.Value {
	vals := v.AsValueMap()
	vals[name] = cty.NullVal(cty.String)
	if s != "" {
		vals[name] = cty.StringVal(s)
	}
	return cty.ObjectVal(vals)
}

func tlsCSRSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A certificate signing request for a key already on the host, such as one from tls_private_key, for your own CA to sign. Made with the host's openssl.",
		Attributes: map[string]*configschema.Attribute{
			"id":           {Type: cty.String, Computed: true},
			"revision":     revisionAttr(),
			"path":         {Type: cty.String, Required: true, Description: "Absolute path of the request file."},
			"key_path":     {Type: cty.String, Required: true, Description: "Absolute path of the private key it's for."},
			"common_name":  {Type: cty.String, Required: true, Description: "Subject common name, such as the host's name."},
			"dns_names":    {Type: cty.List(cty.String), Optional: true, Description: "Host names to ask for as subject alternative names."},
			"ip_addresses": {Type: cty.List(cty.String), Optional: true, Description: "IP addresses to ask for as subject alternative names."},
			"mode":         {Type: cty.String, Optional: true, Description: "Octal permissions. Defaults to \"0644\"."},
			"owner":        {Type: cty.String, Optional: true, Description: "Owner. Unset keeps the file's."},
			"group":        {Type: cty.String, Optional: true, Description: "Group. Unset keeps the file's."},
			"on_remove":    {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file, \"delete\" removes it."},
			"csr_pem":      {Type: cty.String, Computed: true, Description: "The request, PEM-encoded, for your CA."},
			"in_sync":      {Type: cty.Bool, Computed: true, Description: "Whether the file holds a request for the key with these names."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func tlsCSRFrom(v cty.Value) tls.CSR {
	return tls.CSR{Path: stringOr(v.GetAttr("path"), ""), KeyPath: stringOr(v.GetAttr("key_path"), ""), CommonName: stringOr(v.GetAttr("common_name"), ""),
		DNSNames: stringList(v.GetAttr("dns_names")), IPs: stringList(v.GetAttr("ip_addresses")),
		Mode: stringOr(v.GetAttr("mode"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), "")}
}

func planTLSCSR(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return unknownWhenStale(planSynced(req, "tls_csr", []string{"path"},
		[]string{"key_path", "common_name", "dns_names", "ip_addresses", "mode", "owner", "group"}), "csr_pem")
}

func readTLSCSR(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := tlsCSRFrom(prior)
		s, err := tls.ReadCSR(ctx, h, c)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(withAttr(prior, "csr_pem", s.PEM), c.Matches(s)), nil
	})
}

func applyTLSCSR(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			c := tlsCSRFrom(planned)
			if err := tls.ApplyCSR(ctx, h, c); err != nil {
				return cty.NilVal, fmt.Errorf("tls_csr %s: %w", c.Path, err)
			}
			s, err := tls.ReadCSR(ctx, h, c)
			if err != nil {
				return cty.NilVal, err
			}
			return withSync(withAttr(planned, "csr_pem", s.PEM), true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return tls.DeleteCert(ctx, h, tlsCSRFrom(prior).Path)
		})
}
