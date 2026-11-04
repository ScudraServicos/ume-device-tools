# Security

This script runs as root and changes the firewall. If you find a problem (a rule that
blocks the wrong traffic, a step that weakens existing firewall rules, or a way for
someone else to run code), report it **privately**:

- Use **"Report a vulnerability"** on this repository's **Security** tab (GitHub private
  vulnerability reporting). Do not open a public issue.

Include the version (`bash cve-2026-98432-mitigate.sh --version`), the Ubuntu release,
the output of `--status`, and the steps to reproduce.

## Checking what you run

- Use the pinned command from the README. It points at a release tag, not a branch.
- Each release lists the SHA-256 of the script. Compare it before running:

  ```bash
  sha256sum cve-2026-98432-mitigate.sh
  ```
