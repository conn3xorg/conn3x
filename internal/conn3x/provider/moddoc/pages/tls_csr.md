Use `tls_csr` when your own CA signs the host's certificate. Conn3x writes the certificate signing request on the host with its `openssl`, from a key that's already there, so only the request travels to the CA, never the key.

## Example usage

A key and a request for the CA, which then reads `csr_pem`:

```hcl
step "web_key" {
  tls_private_key {
    path = "/etc/pki/tls/private/web.key"
  }
}

step "web_csr" {
  tls_csr {
    path        = "/etc/pki/tls/web.csr"
    key_path    = "/etc/pki/tls/private/web.key"
    common_name = "web1.internal.example"
    dns_names   = ["web1.internal.example"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the request and the public half of the key at `key_path`. `in_sync` is true when the request is signed by that key, for that key, with the `common_name`, `dns_names` and `ip_addresses` asked for, and the file has the mode, owner and group asked for.

**Applying.** The request asks for the same extensions as [`tls_self_signed_cert`](/modules/tls_self_signed_cert)'s certificate: `CA:FALSE`, server and client use, and your names as subject alternative names. Your CA decides what it actually signs. When the key changes, the next plan makes a new request for it.

**The host needs `openssl`** 1.1.1 or newer.

## Removal

When you delete a `tls_csr` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the request. `"delete"` removes the file.

## From Ansible

`conn3x convert ansible` turns `community.crypto.openssl_csr` tasks with a common name and `DNS:` or `IP:` alternative names into `tls_csr` steps. With no alternative names, the common name becomes the one DNS name, as Ansible's `use_common_name_for_san` does. Other subject fields, key usages, other extensions and a key passphrase stay a TODO.
