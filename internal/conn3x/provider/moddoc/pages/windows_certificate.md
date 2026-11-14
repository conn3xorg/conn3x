**Experimental.** New, and tested on GitHub's Windows Server 2022 and 2025 runners, not yet on an Azure server. See [Windows readiness](https://github.com/conn3xorg/conn3x/blob/main/docs/windows-readiness.md).

Use `windows_certificate` to import a certificate file into one of a Windows host's certificate stores: your internal CA's certificate into `Root`, or a web server's `.pfx`, private key and all, into `My` for IIS. It's the `Import-Certificate` or `Import-PfxCertificate` you'd otherwise run by hand, and a plan shows whether the certificate is still there.

## Example usage

Trust an internal CA on every server:

```hcl
step "corp_ca" {
  windows_certificate {
    path       = "C:\\certs\\corp-root-ca.cer"
    store_name = "Root"
  }
}
```

A server certificate with its private key, for IIS. Give the password from an ephemeral variable, so it stays out of state and plan files:

```hcl
step "web_cert" {
  windows_certificate {
    path        = "C:\\certs\\www.pfx"
    store_name  = "My"
    password_wo = "use-an-ephemeral-variable-here"
  }
}
```

Put the file on the host first, with a [`windows_file`](/modules/windows_file) step.
<!-- reference -->
## How it works

**Applying.** Conn3x imports the file into `store_location` and `store_name`: a `.pfx` or `.p12` with `Import-PfxCertificate`, its private key marked not exportable, and anything else with `Import-Certificate`. It records the certificate's `thumbprint` and the file's `file_sha256`. For a `.pfx` that brings its chain with it, the thumbprint is the certificate with the private key.

**The password.** `password_wo` goes to the host on standard input, never on a command line, and never into state or a plan file. A wrong password fails the step without repeating it.

**Reading.** On every plan, Conn3x looks for the recorded thumbprint in the store, and hashes the file if it's still there. `in_sync` is true when the certificate is in the store, with its private key for a `.pfx`, and the file is the one imported. Removing the file after the import, as many do with a `.pfx`, is fine.

**Renewal.** Put the renewed file at the same `path`, and the next plan sees a different file and imports it. The old certificate stays in the store, since a site may still be bound to it; take it out once nothing uses it.

**Changes.** Changing `state` updates the store in place. Changing `path`, `store_location` or `store_name` replaces the step.

## Removal

`on_remove = "forget"`, the default, leaves the certificate in the store. `on_remove = "delete"` takes it out by its thumbprint. The file stays either way.
