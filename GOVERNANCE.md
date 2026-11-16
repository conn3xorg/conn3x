# Governance

## Today

James Conway ([@jamesconwaydev](https://github.com/jamesconwaydev)) started
Conn3x and makes the final call on decisions while the project is small.
Decisions happen in public, in issues, Discussions and pull requests.

## Commitments that don't change

- **Conn3x stays open source.** It's licensed under the Mozilla Public
  License 2.0, and that license will not change.
- **No CLA, no copyright assignment.** Contributors keep the copyright to
  their work and sign off under the Developer Certificate of Origin. Because
  copyright stays with everyone who contributed, no single person or company
  can relicense the project.
- **Sponsors get visibility, not control.** Every feature is in the open
  source project. Nobody can pay for a feature that's held back from
  everyone else.

## Who does what

| Role | Who | How |
| --- | --- | --- |
| Final decisions | James Conway ([@jamesconwaydev](https://github.com/jamesconwaydev)) | In public, in issues, Discussions and pull requests |
| Security response | James Conway | Reports through [private vulnerability reporting](https://github.com/conn3xorg/conn3x/security/advisories/new) or security@conn3x.org, as [SECURITY.md](SECURITY.md) describes |
| Releases | James Conway | The release workflow builds, signs (Sigstore, keyless) and attests every release from `main` |
| Second review | Foothills Digital ([@foothillsdigital](https://github.com/foothillsdigital)) | Asked on every pull request by the second-review workflow; required by [CODEOWNERS](.github/CODEOWNERS) for the code that logs in to hosts, runs as root or builds releases |

## If one of us can't continue

Two people own the [conn3xorg](https://github.com/conn3xorg) organization:
James Conway and Foothills Digital. Either one alone can triage and close
issues, merge pull requests and run the release workflow. Signing is
keyless, through Sigstore, so there's no key to hand over.

Some things still hang off James's account: the tokens that publish to
Homebrew, Scoop, winget and the package repositories, the winget fork, and
the conn3x.org domain. If James stopped, Foothills Digital would replace
those tokens with their own, a few minutes' work in the `release`
environment's settings, and could release within a week. The website would
need the domain moved.

## Maintainers

Anyone who contributes steadily and reviews other people's work can be
invited to become a maintainer. With two or more maintainers:

- every pull request asks a maintainer other than the author for a review.
  It's required for the code that logs in to hosts, runs as root or builds
  releases ([CODEOWNERS](.github/CODEOWNERS)); elsewhere a change can merge
  once CI passes, and we aim to have most of them reviewed
- decisions are made by consensus, falling back to a majority vote of maintainers

The current list is in [MAINTAINERS.md](MAINTAINERS.md).

## Where this is headed

Once Conn3x has maintainers from more than one organization, the plan is to
move the project, its trademark and its domains to a neutral foundation,
such as a CNCF Sandbox application. That way the project doesn't depend on
any one person or company.
