# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# What git.commit relies on, run inside the image by the Images workflow
# (docker run -i IMAGE -s < smoke-test.sh): /bin/sh as the entrypoint, an
# unprivileged user, `timeout` with -k, git with GIT_CONFIG_GLOBAL, the CA
# bundle, the notices, and a commit pushed to a repository the way the step
# commits (offline: a local bare repository).
set -eu
test "$(id -u)" != 0
for b in git timeout mktemp; do command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }; done
timeout -s TERM -k 1 5 true
test -s /etc/ssl/certs/ca-certificates.crt
for f in THIRD-PARTY-NOTICES.md alpine-packages.txt git-version.txt; do
  test -s "/usr/share/doc/hegemony/$f" || { echo "missing notices file $f"; exit 1; }
done
grep -q "^git-" /usr/share/doc/hegemony/alpine-packages.txt
grep -q "Written offer" /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md

work="$(mktemp -d)"
export HOME="$work" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=smoke GIT_AUTHOR_EMAIL=smoke@localhost
export GIT_COMMITTER_NAME=smoke GIT_COMMITTER_EMAIL=smoke@localhost
git init --quiet --bare "$work/remote.git"
git init --quiet "$work/repo"
cd "$work/repo"
git checkout --quiet --orphan main
echo "hostname r1" > r1.cfg
git -c core.hooksPath=/dev/null add --force -- r1.cfg
git diff --cached --name-only -z | grep -q r1.cfg
git -c core.hooksPath=/dev/null commit --quiet --no-verify --no-gpg-sign -m smoke
git -c protocol.file.allow=always push --porcelain "$work/remote.git" HEAD:refs/heads/main
test "$(git -C "$work/remote.git" rev-parse main)" = "$(git rev-parse HEAD)"
echo "git-runner smoke test passed"
