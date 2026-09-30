# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# What tf.plan and tf.apply rely on, run inside the image by the Images
# workflow (docker run -i IMAGE -s < smoke-test.sh): /bin/sh as the entrypoint,
# root (the steps write the run's shared workspace), `timeout` with -k, git
# and ssh for module sources, the CA bundle, the notices, and a saved plan
# applied the way the steps apply it (offline: no provider).
set -eu
test "$(id -u)" = 0
tofu version
for b in git ssh timeout; do command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }; done
timeout -s TERM -k 1 5 true
test -s /etc/ssl/certs/ca-certificates.crt
for f in THIRD-PARTY-NOTICES.md alpine-packages.txt opentofu-version.txt; do
  test -s "/usr/share/doc/hegemony/$f" || { echo "missing notices file $f"; exit 1; }
done
grep -q "^OpenTofu v" /usr/share/doc/hegemony/opentofu-version.txt
grep -q "^git-" /usr/share/doc/hegemony/alpine-packages.txt
grep -q "Written offer" /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md

work="$(mktemp -d)"
cd "$work"
# terraform_data is in the built-in provider, which init does not download.
cat > main.tf <<'TF'
resource "terraform_data" "smoke" {
  input = "yes"
}

output "ok" {
  value = terraform_data.smoke.output
}
TF
tofu init -input=false -no-color > /dev/null
set +e
tofu plan -input=false -no-color -detailed-exitcode -out=plan.tfplan > /dev/null
status=$?
set -e
test "$status" = 2 || { echo "plan exited $status, expected 2 (changes)"; exit 1; }
tofu apply -input=false -no-color plan.tfplan > /dev/null
test "$(tofu output -raw ok)" = yes
echo "opentofu-runner: ok"
