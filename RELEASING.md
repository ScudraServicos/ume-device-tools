# Releasing

A release is published by the `release` workflow when an infrasec member pushes a **signed tag**
`v<VERSION>` on `main`. The workflow checks the tag, runs every test on that commit, and only then
publishes. It never creates tags.

```
pull request (new VERSION) -> tests -> infrasec approval -> merge
  -> infrasec member pushes signed tag v<VERSION> on main
  -> release workflow: checks the tag -> runs every test -> publishes the release (latest)
```

The commands in the README always download the latest release, so they never change.

## Before your first release (once)

- You are a member of the `infrasec` team: only infrasec members can push tags.
- Git signs your tags, and GitHub knows the key:
  - SSH key: `git config --global gpg.format ssh` and
    `git config --global user.signingkey <path to your public key, or the key itself>`.
  - Add the same public key to GitHub: **Settings > SSH and GPG keys > New SSH key**, key type
    **Signing Key**.
  - GPG keys work too: add the key under **New GPG key**.

GitHub shows a tag signed with a key it knows as **Verified**. The workflow refuses tags that are
not verified.

## Steps

### 1. Make the change on a branch

- Branch name: `<type>/<scope>/<detail>`, e.g. `fix/device-tools/windows-startup-check`.
- **If you change `device-tools.sh` or `device-tools.ps1`, raise the version in both files** to the
  same value:

  | File | Line |
  |---|---|
  | `device-tools.sh` | `VERSION="2026.11.06"` |
  | `device-tools.ps1` | `$Version = '2026.11.06'` |

  Use today's date, `YYYY.MM.DD`. For a second release on the same day, add `.1`, `.2`, ...
  (`2026.11.06.1`).
- Changes only to docs or workflows keep the version and need no release.
- Commits must be signed (the `main` rule rejects unsigned ones).

### 2. Open the pull request

GitHub runs the `test` workflow. Its last job, `tests`, is green only when all of these pass:

| Job | What it checks |
|---|---|
| version and syntax | Both scripts carry the same version. If a script changed, the version is new and not released yet. Syntax checks: bash, PowerShell, ASCII-only `device-tools.ps1`. |
| windows check (windows-latest) | `tests/windows-check.ps1` as administrator, with Windows PowerShell 5.1 and PowerShell 7. |
| windows check (ubuntu-latest) | The same test with PowerShell 7 on Linux, against fake profile folders. |
| macos check | `tests/macos-check.sh` with the bash 3.2 that ships with macOS. |
| ubuntu e2e (18.04 ... 26.04) | `tests/ubuntu-e2e.sh` in Docker, one job per Ubuntu release. |

The `version and syntax` log says which tag to push after merging, or that there is nothing to tag.

### 3. Approve the pull request (infrasec reviewer)

Any member of the `infrasec` team other than the author approves. GitHub does not let authors
approve their own pull requests.

1. Open the pull request and check that **All checks have passed**.
2. Open **Files changed** and read the diff, the scripts above all: they run as root and as
   administrator on every computer.
3. Click **Review changes**, choose **Approve**, then **Submit review**.

Pushing a new commit after the approval cancels it: approve again after reading the new commit.

### 4. Merge

Click **Merge pull request**. Nothing is published yet: that needs the tag (step 5).

### 5. Push the signed tag (infrasec member)

On your computer, from the repository folder, with the version of the merged scripts
(`2026.11.06` in this example):

```bash
git switch main
git pull --ff-only
grep '^VERSION=' device-tools.sh                         # must show VERSION="2026.11.06"
git tag -s v2026.11.06 -m "v2026.11.06"                  # -s: annotated and signed
git push origin v2026.11.06
```

- `-s` is required. A plain `git tag v2026.11.06` makes an unsigned, lightweight tag, which the
  workflow refuses.
- Tag `main` after the merge, not your branch. The workflow refuses a tag whose commit is not in
  `main`.

### 6. The release publishes itself

Pushing the tag starts the **release** workflow (Actions tab), which takes about 10 to 15 minutes:

1. **check the tag**: the name is `v<VERSION>`, the tag is annotated, GitHub verifies its
   signature, and its commit is in `main`.
2. **test**: every test from step 2 runs again, on the tagged commit.
3. **release**: the tag must match `VERSION` in both scripts. Then it publishes the release:
   - files: `device-tools.sh`, `device-tools.ps1` and their `.sha256`;
   - release notes: both commands, the SHA-256 values and a link to the pull request;
   - marked as latest.

If any step fails, nothing is published.

### 7. Check it

```bash
gh release view --repo ScudraServicos/ume-device-tools          # latest release, files and notes
curl -fsSL https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.sh | grep '^VERSION='
curl -fsSL https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.ps1 | grep '^\$Version'
```

Both must show the new version. Releases are immutable: once published, their files and tag
cannot change. To fix a release, merge a new pull request with a newer version and tag it.

## When something fails

| Where | Message | What to do |
|---|---|---|
| Pull request, `version and syntax` | `The scripts changed, so raise VERSION in both` | Raise the version in both scripts (step 1) and push. |
| Pull request, `version and syntax` | `vX is already released: pick a newer VERSION` | Use a newer version, e.g. add `.1`. |
| Pull request, `version and syntax` | `VERSION ... and $Version ... must be equal` | Use the same value in both files. |
| Pull request, any job | `a test failed or did not run` | Open that job's log, fix it, push. The approval must be given again. |
| release, check the tag | `tag vX does not exist` (`gh: Not Found (HTTP 404)` in older runs) | The workflow was run by hand for a tag nobody pushed. Do step 5. |
| release, check the tag | `is not an annotated tag` | The tag was made without `-s`. Fix the tag (below). |
| release, check the tag | `signature is not verified by GitHub` | Your signing key is not on your GitHub account as a **Signing Key** (see "Before your first release"). Add it, then fix the tag (below). |
| release, check the tag | `is not in main` | The tag points to a branch commit. Merge the pull request, then fix the tag (below) on `main`. |
| release, release | `does not match the scripts` | The tag name and `VERSION` differ. Fix the tag (below) with the right name, on the right commit. |
| release, test | A test failed | Nothing was published. If it was a temporary outage (a download, a runner), retry (below). Otherwise fix it in a new pull request with a new version. |

**To fix a tag before its release exists** (only infrasec members can delete tags):

```bash
git push origin :refs/tags/v2026.11.06      # delete the tag on GitHub
git tag -d v2026.11.06                      # delete it locally
# then repeat step 5
```

Once a release is published, its tag is locked (immutable releases). Use a newer version instead.

**To retry a release for a tag that exists:** Actions > **release** > **Run workflow** > branch `main`,
tag `v2026.11.06` > **Run workflow**. To rerun only the failed jobs of a run, use
**Re-run failed jobs** on that run.

## Controls

| Control | Where |
|---|---|
| Every change to `main` goes through a pull request with an approval from infrasec (code owners), given after the last push. All review threads must be resolved. | Ruleset `main: pull request reviewed by infrasec` |
| Commits on `main` must be signed. | Same ruleset |
| Only infrasec members can push branches and create, move or delete tags. | Rulesets `branches: only infrasec can push`, `tags: only infrasec can create, move or delete` |
| The release needs a signed tag verified by GitHub, on a commit in `main`, and every test passing on that commit. | `release.yml` |
| Releases cannot be changed once published. | Settings > Immutable releases |
| Only the release job can write, and only to create the release. It never creates tags. Workflows cannot approve pull requests. The default token is read-only, and no third-party actions are used. | `release.yml`, Settings > Actions |
