# Security

These scripts run as root (`device-tools.sh`) or as administrator (`device-tools.ps1`) and read
every local account's files. If you find a problem (a check that misses or misreports a trace, a
firewall rule that blocks the wrong traffic, a step that weakens existing settings, or a way for
someone else to run code), report it **privately**:

- Use **"Report a vulnerability"** on this repository's **Security** tab (GitHub private
  vulnerability reporting). Do not open a public issue.

Include the version (`bash device-tools.sh --version`, or `--version` after the Windows command),
the system (macOS, Ubuntu or Windows release), the output of `--status`, and the steps to
reproduce.

## Checking what you run

- Use the commands from the README. They download the scripts attached to the latest release,
  which is published only by the release workflow from `main`, after a pull request approved by
  the infrasec team and passing every test, and cannot be changed later.
- Each release has the SHA-256 of each script (`device-tools.sh.sha256`,
  `device-tools.ps1.sha256`). Check it before running:

  ```bash
  shasum -a 256 -c device-tools.sh.sha256   # sha256sum -c on Linux
  ```

  ```powershell
  (Get-FileHash device-tools.ps1 -Algorithm SHA256).Hash -eq (Get-Content device-tools.ps1.sha256).Split(' ')[0]
  ```
