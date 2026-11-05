# Security

This script runs as root and reads every local account's files. If you find a problem (a check
that misses or misreports a trace, a firewall rule that blocks the wrong traffic, a step that
weakens existing settings, or a way for someone else to run code), report it **privately**:

- Use **"Report a vulnerability"** on this repository's **Security** tab (GitHub private
  vulnerability reporting). Do not open a public issue.

Include the version (`bash device-tools.sh --version`), the system (macOS or Ubuntu release),
the output of `--status`, and the steps to reproduce.

## Checking what you run

- Use the pinned command from the README. It points at a release tag, not a branch.
- Each release lists the SHA-256 of the script. Compare it before running:

  ```bash
  shasum -a 256 device-tools.sh   # sha256sum on Linux
  ```
