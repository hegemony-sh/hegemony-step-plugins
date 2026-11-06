# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Corpus replay must report failures without hiding later regressions."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("failing", [False, True])
def test_corpus_replay_reports_failures_and_runs_remaining_inputs(tmp_path, failing):
    target = tmp_path / "target.py"
    target.write_text(
        "def test_one_input(data):\n"
        "    print('replayed:', data.decode(), flush=True)\n"
        "    if data == b'bad':\n"
        "        raise ValueError('deliberate regression')\n"
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01-first").write_bytes(b"first")
    (corpus / "02-middle").write_bytes(b"bad" if failing else b"middle")
    (corpus / "03-last").write_bytes(b"last")
    script = Path(__file__).resolve().parents[1] / "fuzz/replay_corpus.py"
    result = subprocess.run(
        [sys.executable, str(script), str(target), str(corpus)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == int(failing)
    assert "replayed: first" in result.stdout
    assert "replayed: last" in result.stdout
    if failing:
        assert str(corpus / "02-middle") in result.stderr
        assert "ValueError: deliberate regression" in result.stderr
    else:
        assert not result.stderr
