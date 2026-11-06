#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds every fuzz/*_fuzzer.py into $OUT as a standalone PyInstaller
# executable plus the wrapper ClusterFuzzLite runs. The plugins under test
# are installed with the SDK they pin, from this checkout, so the fuzzers
# exercise the code of the pull request.

pip3 install --no-cache-dir \
  ./packages/step_sdk \
  ./plugins/steps_http \
  ./plugins/steps_container

python3 fuzz/seed_corpus.py build/fuzz-corpus

for fuzzer in fuzz/*_fuzzer.py; do
  name=$(basename -s .py "$fuzzer")
  package="$name.pkg"
  # Include both checked-in seed recipes and any restored nightly corpus.
  (cd "build/fuzz-corpus/$name" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
  printf '[libfuzzer]\nmax_len = 16384\n' > "$OUT/$name.options"
  mkdir -p /tmp/fuzz-build
  pyinstaller --specpath /tmp/fuzz-build --workpath "/tmp/fuzz-build/$name" --distpath "$OUT" --onefile --name "$package" "$fuzzer"
  # Pure-Python targets: no sanitizer library to preload.
  cat > "$OUT/$name" <<WRAPPER
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
"\$this_dir/$package" "\$@"
WRAPPER
  chmod +x "$OUT/$name"
done
