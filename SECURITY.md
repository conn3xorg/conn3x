# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem.

Report it privately through
[GitHub's private vulnerability reporting](https://github.com/conn3xorg/conn3x/security/advisories/new),
or email **security@conn3x.org**.

Include what you found, how to reproduce it, and the version you tested
(`conn3x version`). You'll get an acknowledgement within 3 business days,
and we'll keep you posted while we work on a fix. Once a fix ships, we
publish an advisory and credit you, unless you'd rather stay anonymous.

Please reproduce the problem yourself before you report it. A scanner's or an AI tool's findings, pasted without checking, aren't a report; see [AI_POLICY.md](AI_POLICY.md).

## What you trust when you run Conn3x

A circuit you add with a `module` block is code you run, as much as a script
you download. Its `ssh` block and its `data "conn3x_host"` sources connect
when you plan, with the keys on your machine, and its functions can read
your files. So read a shared circuit before you use it, pin its `ref` to a
commit, since a tag can be moved, and run `conn3x lint`: rule C3X102 reports
a module that names its own hosts, keys or password file.

`become_password_file` is set once for a circuit, so every host in it gets
the same sudo password. A host that is taken over as root can read it as
sudo runs, and it then works on the circuit's other hosts. Give hosts that
shouldn't share that risk their own password and their own circuit, or use
sudo rules that need no password.

`conn3x mcp` gives an AI assistant tools that only read inside the directory
you start it in. Two of them, `validate` and `summarise_plan`, run Conn3x
there: that evaluates the configuration, functions such as `file()`
included, and what an error quotes goes to the assistant. Start it in a
directory whose circuits you trust. They refuse a directory with provider
plugins installed unless you start it with `-allow-plugins`, because
validating starts those plugins.

`conn3x lsp`, the language server for editors, runs `conn3x validate` in a
file's directory when you save it. It skips a directory with provider
plugins installed, and tells the editor why, unless you start it with
`-allow-plugins`, so saving a file from a repository you only cloned starts
nothing that repository committed.

## Supported versions

Security fixes go to the latest minor version, so upgrade to the newest
release to get them.
