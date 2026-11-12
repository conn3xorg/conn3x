Use `tls_self_signed_cert` for a certificate an internal service can start with, before or instead of a CA. Conn3x signs it on the host with the host's `openssl`, for a key that's already there, and makes a new one when it gets close to expiring.

## Example usage

A key and a certificate for a web server, valid for a year and renewed a month before it runs out:

```hcl
step "web_key" {
  tls_private_key {
    path = "/etc/pki/tls/private/web.key"
  }
}

step "web_cert" {
  tls_self_signed_cert {
    path        = "/etc/pki/tls/certs/web.crt"
    key_path    = "/etc/pki/tls/private/web.key"
    common_name = "web1.internal.example"
    dns_names   = ["web1.internal.example", "web.internal.example"]
  }
}
```

A short-lived certificate for an address, renewed when a week is left:

```hcl
step "metrics_cert" {
  tls_self_signed_cert {
    path              = "/etc/metrics/tls.crt"
    key_path          = "/etc/metrics/tls.key"
    common_name       = "metrics"
    ip_addresses      = ["10.0.0.20"]
    days              = 30
    renew_before_days = 7
  }
}
```

`cert_pem` holds the certificate, so another resource can hand it to the clients that should trust it.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the certificate and the public half of the key at `key_path`. `in_sync` is true when the certificate:
- is signed by that key, for that key;
- has the `common_name`, `dns_names` and `ip_addresses` asked for;
- has more than `renew_before_days` left;
- has the file mode, owner and group asked for.

When it gets within `renew_before_days` of expiring, the next plan shows an update, and the apply makes a new certificate, which also notifies any handlers.

**Applying.** Conn3x writes an `openssl req` config of its own, so the distribution's defaults can't make the certificate a CA. The certificate gets:
- `CA:FALSE`;
- the `digitalSignature` and `keyEncipherment` key uses;
- the `serverAuth` and `clientAuth` extended uses;
- your names as subject alternative names.

It's written to a temporary file and moved into place. When the key changes, such as a `tls_private_key` step with a new `type`, the certificate was planned before it, so the next plan finds it's for the old key and makes a new one. If only the mode, owner or group is wrong, the certificate is kept and only those change. The key must already exist, so put the `tls_private_key` step first.

**The host needs `openssl`** 1.1.1 or newer.

## Removal

When you delete a `tls_self_signed_cert` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the certificate. `"delete"` removes the file.

## From Ansible

This is `community.crypto.x509_certificate` with `provider: selfsigned`. `conn3x convert ansible` doesn't translate it yet.
