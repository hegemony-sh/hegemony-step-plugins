# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# What ansible.playbook relies on, run inside the image by the Images workflow
# (docker run -i IMAGE -s < smoke-test.sh): /bin/sh as the entrypoint, an
# unprivileged user, ansible-core with libssh, the collections the platform
# maps device platforms onto, and the notices.
set -eu
test "$(id -u)" != 0
ansible-playbook --version
python3 -c "import pylibsshext, ncclient"
for c in ansible.netcommon ansible.utils ansible.posix community.general \
         cisco.ios cisco.nxos cisco.iosxr arista.eos junipernetworks.junos; do
  ansible-galaxy collection list "$c" | grep -q "^$c " || { echo "missing $c"; exit 1; }
done
for b in ssh sshpass git; do command -v "$b" >/dev/null; done
for f in THIRD-PARTY-NOTICES.md python-packages.txt ansible-collections.txt; do
  test -s "/usr/share/doc/hegemony/$f" || { echo "missing notices file $f"; exit 1; }
done
grep -q "^ansible-core | " /usr/share/doc/hegemony/python-packages.txt
grep -q "Written offer" /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md
echo "ansible-runner: ok"
