Use `tls_private_key` to give a host its own TLS private key. Conn3x runs the host's `openssl` to make it, so the key is created on the host and never crosses the network or lands in state. Only the public half does, as `public_key_pem`.

## Example usage

An RSA key for a web server, readable by root only:

```hcl
step "web_key" {
  tls_private_key {
    path = "/etc/pki/tls/private/web.key"
  }
}
```

An ECDSA key that the `nginx` group can read:

```hcl
step "web_key" {
  tls_private_key {
    path  = "/etc/nginx/tls/web.key"
    type  = "ecdsa"
    curve = "P-384"
    group = "nginx"
    mode  = "0640"
  }
}
```

Pair it with [`tls_self_signed_cert`](/modules/tls_self_signed_cert) for a certificate, or send `public_key_pem` to your own CA.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks `openssl pkey` for the key's public half and reads the file's mode, owner and group. `in_sync` is true when the file holds an unencrypted key of the `type`, `bits` and `curve` asked for, with that mode, and the owner and group you set.

**Applying.** A missing key is generated with `openssl genpkey` into a temporary file that only its owner can read from the moment it exists, then moved into place. A key of the right kind that only has the wrong mode, owner or group keeps its content: Conn3x copies it and sets those. A key of another kind is replaced by a new one, so anything signed for the old key, such as a certificate, has to be made again. A file at `path` that isn't a private key `openssl` can read, such as an encrypted key, is left alone and the step fails.

**Mode.** `mode` must end in `0`, so other users can never read the key.

**The host needs `openssl`.** Add a `package` step for it first if the image doesn't have it. Ed25519 keys need OpenSSL 1.1.1 or newer.

## Removal

When you delete a `tls_private_key` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the key. `"delete"` removes the file.

## From Ansible

`conn3x convert ansible` turns `community.crypto.openssl_privatekey` tasks into `tls_private_key` steps. Ansible's default, RSA 4096, becomes `bits = 4096`, and ECC keys on `secp256r1` or `secp384r1` become `ecdsa` on `P-256` or `P-384`. A task with a `passphrase`, a `format`, a `regenerate` other than the default, a mode others can read, or another key type stays a TODO.
