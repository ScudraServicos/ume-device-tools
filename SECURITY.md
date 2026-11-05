# Security

This script runs as root and reads every local account's files. If you find a problem (a check
that misses or misreports a trace, a firewall rule that blocks the wrong traffic, a step that
weakens existing settings, or a way for someone else to run code), report it **privately**:

- Use **"Report a vulnerability"** on this repository's **Security** tab (GitHub private
  vulnerability reporting). Do not open a public issue.

Include the version (`bash device-tools.sh --version`), the system (macOS or Ubuntu release),
the output of `--status`, and the steps to reproduce.

## Checking what you run

- Use the command from the README. It downloads the script attached to the latest release,
  which is published only from a tag signed by the infrasec team and cannot be changed later.
- Each release has the script's SHA-256 as `device-tools.sh.sha256`. Check it before running:

  ```bash
  shasum -a 256 -c device-tools.sh.sha256   # sha256sum -c on Linux
  ```
