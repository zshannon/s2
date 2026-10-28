# Weekly upstream proposals

The sync runs Tuesday at 09:00 America/Los_Angeles and can be dispatched on main.
It never merges, publishes, deploys, or changes main.

## Setup required before merging this workflow

Configure the Actions secret `UPSTREAM_SYNC_TOKEN` with a fine-grained token
restricted to this repository, with Contents, Pull requests, and Workflows
read/write permission. Keep the token value out of commits and logs.

The built-in `GITHUB_TOKEN` cannot import changes to workflow files. Upstream
snapshots can include those changes, so it is not a reliable credential for this
job. GitHub documents the additional Workflows permission for
[creating and updating references](https://docs.github.com/en/rest/git/refs).
The sync fails explicitly if its credential is missing. Configure and verify it
before merging; otherwise the scheduled job will repeatedly fail.

The normal workflow token remains read-only. Only the sync step receives the
scoped credential, and only schedule/manual runs on this fork's main can reach
that step. Pull requests run the regression tests without this credential.
The sync reads commit metadata and updates refs through GitHub's API; it never
checks out or executes upstream code in its privileged job.

The scoped token may cause normal PR/push workflows to run. Review the repository's
workflow triggers and required checks when setting it up. A draft is a review
state, not a guarantee that GitHub will suppress all CI.

## Proposal lifecycle

1. When main already contains upstream, do nothing.
2. Otherwise open one draft PR from a fork-owned
   `automation/upstream-<initial-upstream-sha>` branch.
3. Reuse that PR while it is open. If its upstream snapshot is unchanged, do not
   push, edit the PR, change readiness, or dispatch CI.
4. Fast-forward an untouched proposal only when upstream advances. Move a ready
   PR back to draft before the update. Never force-push.
5. If the branch contains manual work that the new upstream snapshot does not
   contain, leave it alone. Finish the integration manually.
6. Respect closed proposals that already contain the current candidate. A newer
   candidate can get a fresh branch and PR after the previous proposal closes.
   Completed branches are never reset, even if new human commits arrive there.
7. Once an editable replacement exists, close the old direct-upstream tracking
   PR and link its history from the replacement. A failed API operation remains
   a failed run; retries do not create duplicate proposals.

New and refreshed snapshots stay draft until a maintainer reviews the changes,
resolves conflicts, and checks CI. There is no automatic promotion to ready.

## Resolve and merge manually

Check out the proposal's branch in a separate worktree. Merge this fork's main
into that branch, resolve conflicts, and push to the same branch. Preserve the
fork's PKI behavior and its deployment/package-release configuration. For the
TypeScript SDK, also retain the published Biscuit dependency and `@zshannon`
package names.

Review workflow changes before approving any approval-required runs. Wait for
required checks, mark the PR ready, and merge using a **merge commit**. Squashing
or rebasing upstream imports loses the ancestry used to identify new changes.
After manual commits are added, the sync will preserve them; incorporate any
further desired upstream commits manually until that PR is merged or closed.

## Local regression tests

```sh
TEST_REPO=s2 node --test .github/scripts/test-sync-upstream.cjs
```

These tests simulate GitHub responses and writes; they do not prove that the
configured credential has the required permissions. Verify the first manual sync
after setup, including its replacement draft PR, then rerun the unchanged
candidate and confirm there are no branch or PR writes.
