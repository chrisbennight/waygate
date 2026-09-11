# Report a security vulnerability

Do not put exploit details, credentials, private policies, or sensitive logs
in a public issue or pull request. Use the repository's **Security → Report a
vulnerability** private reporting flow when it is available. If the host does
not offer that flow, open a minimal issue asking the maintainers for a private
security contact, without describing the vulnerability or affected private
deployment. Wait for that private route before sending details.

For a public GitHub launch, maintainers must enable private vulnerability
reporting and test that the reporting route is available. This source file does
not enable a hosting feature or establish a monitored email address.

In the private report, provide the affected version or source commit, relevant
configuration with secrets removed, expected and actual behavior, a minimal
synthetic reproduction, and the security boundary involved. Distinguish a
demonstrated failure from a suspected issue. Coordinate disclosure while the
maintainers investigate and prepare a fix.

Security fixes target the current maintained main/release line. Older snapshots
and locally modified deployments are not promised backports. There is no
guaranteed response time, commercial support contract, or bug bounty. Operators
remain responsible for selecting updates and validating their own deployment.
