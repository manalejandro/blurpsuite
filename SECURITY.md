# Security Policy

## Supported versions

Security fixes are applied to the latest code on the default branch. There are
no separately maintained release branches at this time; please update to the
most recent source before reporting an issue.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability.

Use GitHub's private vulnerability reporting for this repository: open the
**Security** tab and choose **Report a vulnerability**. Include:

- affected component and version or commit,
- steps to reproduce or a proof of concept,
- impact and any suggested mitigation,
- whether the issue has been disclosed elsewhere.

You should receive an acknowledgment within seven days. We will confirm the
finding, agree on a disclosure timeline with you, and credit you in the fix
notes unless you prefer to remain anonymous.

If private reporting is unavailable for this repository, contact the
maintainers through GitHub directly and request a private channel before
sharing exploit details.

## Scope notes

Blurp Suite is intended for local, authorized testing. It currently tunnels
`CONNECT` requests without TLS interception and has no authentication on its
proxy listener. By default it binds to `127.0.0.1`; do not expose it to
untrusted networks with `--bind 0.0.0.0` without appropriate protections.
