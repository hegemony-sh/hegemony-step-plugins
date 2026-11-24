<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-git

Git for Hegemony flows — the `git.` namespace.

Handlers:

- `git.commit` — commit the text evidence an earlier step recorded (such as
  the running configurations a `netcli.collect_evidence` step read) to a
  branch of a Git repository over HTTPS, one file per device and command,
  and push only when a file changed. The repository's history is then the
  history of what the step read: a configuration backup in Git with no
  playbook to write.

The login (a user name and a password or token) is given as secret
references, resolved by the platform, handed to git through `GIT_ASKPASS`
from files, and redacted from output; it never appears in the URL, an
argument or an environment variable.

The step runs on the platform's Docker-in-Docker sandbox through
`container.run`'s runner (this wheel depends on `hegemony-steps-container`),
under the flow's egress policy. Its default image is
`ghcr.io/hegemony-sh/git-runner:0.55`, built and published from
`images/git-runner/` in this repository.

Namespace prefix (= entry-point name): `git.` — see the repo-level
`CONVENTIONS.md` for the naming rules. The handler's page is under
`src/hegemony_steps_git/docs/`.
