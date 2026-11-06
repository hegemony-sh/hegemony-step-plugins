# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The ClusterFuzzLite build image: OSS-Fuzz's Python builder, which carries
# Atheris and PyInstaller. Pinned by digest; Renovate proposes the new digest
# when the tag moves (.github/renovate.json).

FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9

COPY . $SRC/hegemony-step-plugins
WORKDIR $SRC/hegemony-step-plugins
COPY .clusterfuzzlite/build.sh $SRC/
