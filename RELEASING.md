# Releasing

A release happens on its own when an approved pull request is merged into `main`. Nobody creates
tags or runs workflows by hand.

```
pull request -> tests pass -> infrasec approves -> merge -> tests again -> release v<VERSION> (latest)
```

The commands in the README always download the latest release, so they never change.

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
- Changes only to docs or workflows keep the version and publish no release.
- Commits must be signed (the `main` rule rejects unsigned ones).

### 2. Open the pull request

GitHub runs the `test` workflow. All of these must pass before the pull request can be merged
(the required check is called `tests`):

| Job | What it checks |
|---|---|
| version and syntax | Both scripts carry the same version. If a script changed, the version is new and not released yet. Syntax checks: bash, PowerShell, ASCII-only `device-tools.ps1`. |
| windows check (windows-latest) | `tests/windows-check.ps1` as administrator, with Windows PowerShell 5.1 and PowerShell 7. |
| windows check (ubuntu-latest) | The same test with PowerShell 7 on Linux, against fake profile folders. |
| macos check | `tests/macos-check.sh` with the bash 3.2 that ships with macOS. |
| ubuntu e2e (18.04 ... 26.04) | `tests/ubuntu-e2e.sh` in Docker, one job per Ubuntu release. |

The `version and syntax` log says what merging will do: "this pull request will release vX" or
"publishes no new release".

### 3. Approve the pull request (infrasec reviewer)

Any member of the `infrasec` team other than the author approves. GitHub does not let authors
approve their own pull requests.

1. Open the pull request and check that **All checks have passed**.
2. Open **Files changed** and read the diff, the scripts above all: they run as root and as
   administrator on every computer.
3. Click **Review changes**, choose **Approve**, then **Submit review**.

Pushing a new commit after the approval cancels it: approve again after reading the new commit.

### 4. Merge

When the pull request has the approval and a green `tests` check, click **Merge pull request**.
Use the button: GitHub signs the merge commit, and the release requires a signed commit.

### 5. The release publishes itself

The merge starts the **release** workflow (Actions tab). It takes about 10 to 15 minutes:

1. It runs every test again on the merged commit.
2. If `v<VERSION>` is not released yet, it creates that tag on the merged commit and publishes
   the release:
   - files: `device-tools.sh`, `device-tools.ps1` and their `.sha256`;
   - release notes: both commands, the SHA-256 values and a link to the pull request;
   - marked as latest.
3. If the version is already released, it stops with the note "already released, so there is
   nothing to publish". That is expected for docs-only changes.

### 6. Check it

```bash
gh release view --repo ScudraServicos/ume-device-tools          # latest release, files and notes
curl -fsSL https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.sh | grep '^VERSION='
curl -fsSL https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.ps1 | grep '^\$Version'
```

Both must show the new version. Releases are immutable: once published, their files and tag
cannot change. To fix a release, merge a new pull request with a newer version.

## When something fails

| Where | Message | What to do |
|---|---|---|
| Pull request, `version and syntax` | `The scripts changed, so raise VERSION in both` | Raise the version in both scripts (step 1) and push. |
| Pull request, `version and syntax` | `vX is already released: pick a newer VERSION` | Use a newer version, e.g. add `.1`. |
| Pull request, `version and syntax` | `VERSION ... and $Version ... must be equal` | Use the same value in both files. |
| Pull request, any other job | `a test failed or did not run` | Open that job's log, fix it, push. The approval must be given again. |
| Pull request | Merge button disabled | It needs an approval from infrasec and a green `tests` check. |
| release workflow | A test failed on the merged commit | Nothing was published. If the failure was a temporary outage (e.g. a download), retry (below). Otherwise fix it in a new pull request. |
| release workflow | `commit ... is not signed and verified by GitHub` | Merge with the **Merge pull request** button, which signs the commit. |
| release workflow | Tag creation refused by a rule | The tags rule must allow the GitHub Actions app (see Controls). Ask the infrasec team. |

**To retry a release:** Actions > **release** > **Run workflow** > branch `main` > **Run workflow**.
It runs the tests again and publishes the version on `main` if it is not released yet. Do not create
tags by hand: older releases needed a signed tag first, and running the workflow for a tag that did
not exist failed with `gh: Not Found (HTTP 404)`. That step no longer exists.

## Controls

| Control | Where |
|---|---|
| Every change to `main` goes through a pull request with an approval from infrasec (code owners), given after the last push. All review threads must be resolved. | Ruleset `main: pull request reviewed by infrasec` |
| The `tests` check must pass before merging. | Same ruleset, required status check |
| Commits on `main` must be signed. The release also refuses an unverified commit. | Same ruleset; `release.yml` |
| Only infrasec members can push branches. | Ruleset `branches: only infrasec can push` |
| Tags can be created only by infrasec members and by the release workflow (GitHub Actions app). | Ruleset `tags: only infrasec can create, move or delete` |
| Releases cannot be changed once published. | Settings > Immutable releases |
| Only the release job can write, and only to the repository's contents. Workflows cannot approve pull requests. The default token is read-only, and no third-party actions are used. | `release.yml`, Settings > Actions |

The `main` rule has a bypass for the repository admin (merge without approval or checks). A merge
through the bypass is still released, so use it only in an emergency and ask for a review
afterwards.
