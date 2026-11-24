<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Git Commit

`git.commit` commits the text evidence an earlier step recorded to a branch
of a Git repository, one file per device and command, and pushes only when
a file changed. Put it after a `netcli.collect_evidence` step that reads
`show running-config`, and the repository's history becomes the history of
the network's configuration: each commit is a change, and a run that finds
nothing new adds no commit.

## Using It

Repository URL is the repository's `https://` clone URL, without a login.
Branch (default `main`) is where the step commits. A branch that does not
exist fails the step unless Create the branch is on; it then starts empty,
holding only this step's files, which is what the first backup into an
empty repository needs.

Username and Password or Token are the Git login. The password or token
must be a secret reference (`vault://orgs/acme/secrets/git/token`) or a
`{{ secret('...') }}` template; a value written in clear is refused. The
user name may be text, a reference or a template. Git gets them through
`GIT_ASKPASS` from files in the container, never in the URL, an argument or
an environment variable, and the resolved values are redacted from the
step's output. With a token, use any user name the server accepts (GitHub
takes `x-access-token`). Leave both empty for a server that needs no login.

Evidence Step chooses the earlier step whose evidence is committed. The
step takes that step's newest artifact per device and command, so a loop
or a retry commits what was read last. A capture that failed (an
unreachable device, a command the device refused) is skipped and listed in
the output, and its file in the repository is left as it was. So is a
capture the device failed after (it answered in one loop iteration and was
unreachable in a later one): the step does not commit an older read. Artifacts
without text (uploaded files) are skipped too.

Path (default `{device}/{command}.txt`) says where each artifact goes in the
repository. `{device}` is the device name, `{command}` the command,
`{name}` the artifact's name and `{step}` the evidence step's id; each is
made safe for a file name (letters, digits, `.`, `_` and `-`; anything else
becomes `_`). For one running configuration per router,
`configs/{device}.cfg` reads well. Two artifacts that would land on the same
path fail the step, so with several commands keep `{command}` in Path. The
step writes only these files: other files in the branch are kept, and a
device that is no longer collected keeps its last file.

Commit Message defaults to `Hegemony: <flow> run <run id>`; templates such
as `{{ run_id }}` are filled in. Author Name and Author Email (advanced)
name the commit's author and committer.

Turn on Trust the organization's CAs (advanced) for a Git server whose
certificate a private CA signed: git then trusts the organization's trusted
CAs as well as the public ones.

The step runs git in a container on the platform's sandbox, like
`container.run`, so the flow's network policy must allow it to reach the
Git server on port 443. Execution image (advanced) defaults to
`ghcr.io/hegemony-sh/git-runner:0.55`; change it only to pull that image
from a mirror. Timeout, memory and CPU limits, environment variables and
egress rules work as in `container.run`.

When another run pushes to the branch between this step's clone and its
push, the step starts again from the new branch head, up to three times.
Git runs with hooks, system and global configuration and credential
helpers off, and talks only HTTPS; `GIT_*` variables set in Environment
Variables are dropped, except the commit identity, so none can undo that.
Paths are given to git literally, never as patterns. A symbolic link in the repository on a
path the step writes fails the step instead of being followed.

## Output

The summary says how many files the commit changed and the commit, or that
nothing changed. The container's output is kept as evidence, with a
`git_commit` record of the repository, branch, commit, files written,
files changed and captures skipped.

- `steps.NODE_ID.output.changed`: whether a commit was pushed; false when
  every file already matched the branch.
- `steps.NODE_ID.output.commit`: the branch head after the step, the new
  commit or, when nothing changed, the existing one (empty for a new
  branch with nothing to commit).
- `steps.NODE_ID.output.branch`: the branch committed to.
- `steps.NODE_ID.output.files`: the repository paths the step wrote.
- `steps.NODE_ID.output.changed_files`: the paths the commit changed.
- `steps.NODE_ID.output.skipped`: the captures left out, each as
  `device:command: reason`.

The path lists hold at most 500 entries; the evidence keeps them all.

## When It Fails

The step fails without starting git when the settings are invalid (a URL
that is not `https://` or carries a login, a bad branch name, a Path that
leaves the repository or reaches into `.git`, a password written in
clear), when Evidence Step has no text evidence in this run, when two
artifacts land on one path, and when the files exceed 16 MiB each or 32 MiB
together.

It fails after starting git when the branch does not exist and Create the
branch is off, when git cannot log in, does not trust the server's
certificate or cannot reach it (each named in the error), when the
repository has a symbolic link or a folder where a file is written, and
when the server refuses the push, or the branch kept moving through three
tries. Nothing is committed in any of these cases. When the step's result
cannot be read from the container, or a push is reported without its
commit or changed files, the step fails rather than guess.
