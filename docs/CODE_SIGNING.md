# Code signing policy

Status: preparing an application to SignPath Foundation; not yet approved. Current builds are unsigned. No certificate or Foundation sponsorship is claimed.

Maintainer, author/reviewer and proposed release approver: [Alan-WPN](https://github.com/Alan-WPN). Contact: support@alanpn.ru. MFA is required for repository and signing access. Each release-signing request must be manually approved.

Only project-owned binaries built by a verifiable CI workflow from this public source may be submitted. Upstream binaries retain their upstream provenance and signatures; they are not signed as if authored by this project. Product name/version metadata will be enforced as part of the eventual signing configuration.

Before the first signing request, replace per-download executable modification with an immutable installer and secure separate enrollment, complete release testing and configure SignPath's required source/artifact checks.

After actual approval, add the required attribution: Free code signing provided by SignPath.io, certificate by SignPath Foundation.

[Privacy policy](PRIVACY.md) · [Foundation conditions](https://signpath.org/terms)
