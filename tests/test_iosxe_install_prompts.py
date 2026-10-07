# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Each question the install asks gets exactly one answer.

The transports answer a key when it shows up in new output, each key once.
The install's keys overlapped ("This operation requires a reload", "Do you
want to proceed", "Please confirm you have changed boot config ...",
"[y/n]"), so one question arriving in pieces got a "y" per piece, and the
extra ones went to whatever the device asked next. The keys are now the
choice lists the questions end with, which no question holds twice.
"""

from __future__ import annotations

from typing import Any

import pytest

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import (
    _INSTALL_ANSWERS,
    IOSXEInstallDriver,
)
from tests.iosxe_fakes import Result, ScriptedTransport

BOOT_OK = Result("BOOT variable = flash:packages.conf;\nCONFIG_FILE variable = \n")
START = "install_add_activate_commit: START Mon Oct  5 10:00:00 UTC 2026\n"
DONE = (
    "y\nActivate: Passed on [1]\nFinished Activate\n"
    "Install will reload the system now!\n"
    "SUCCESS: install_add_activate_commit  Mon Oct  5 10:12:00 UTC 2026\n"
)
# What IOS-XE asks before it activates: 16.x and 17.x.
QUESTION_16 = (
    "This operation requires a reload of the system. Do you want to proceed? "
    "Please confirm you have changed boot config to flash:packages.conf [y/n]"
)
QUESTION_17 = "This operation may require a reload of the system. Do you want to proceed? [y/n]"
QUESTIONS = [
    QUESTION_16,
    QUESTION_17,
    "Proceed with install? [y/n]",
    "System configuration has been modified. Save? [yes/no]: ",
]


def _keys_in(text: str) -> list[str]:
    """The answer keys a transport finds in ``text`` (it matches ignoring case)."""
    return [key for key in _INSTALL_ANSWERS if key.lower() in text.lower()]


@pytest.mark.parametrize("question", QUESTIONS)
def test_every_question_holds_exactly_one_key(question):
    assert len(_keys_in(question)) == 1


class _PromptingTransport(ScriptedTransport):
    """Prints the install output in pieces and answers as the transports do.

    netmiko's wait loop, scrapli and asyncssh look for the answer keys in each
    new piece of output, send the answer of the first key found that was not
    answered yet, and answer each key once.
    """

    def __init__(self, pieces: list[str]) -> None:
        super().__init__({"show boot": BOOT_OK})
        self.pieces = pieces
        self.sent: list[str] = []

    async def execute_command_timing(
        self,
        command: str,
        *,
        answers: dict[str, str] | None = None,
        wait_for_patterns: list[str] | None = None,
        **kwargs: Any,
    ) -> Result:
        self.calls.append([command])
        output = ""
        answered: set[str] = set()
        for piece in self.pieces:
            output += piece
            for key, answer in (answers or {}).items():
                if key.lower() not in answered and key.lower() in piece.lower():
                    answered.add(key.lower())
                    self.sent.append(answer)
                    break
            if any(p.lower() in output.lower() for p in wait_for_patterns or []):
                break
        return Result(output, command=command)


def _pieces(question: str, cuts: list[str]) -> list[str]:
    """``question`` split before each of ``cuts``, after the install's start."""
    pieces, rest = [START], question
    for cut in cuts:
        head, _, tail = rest.partition(cut)
        pieces.append(head)
        rest = cut + tail
    return [*pieces, rest, DONE]


@pytest.mark.parametrize(
    ("question", "cuts"),
    [
        (QUESTION_16, []),
        (QUESTION_16, ["Do you want", "Please confirm"]),
        (QUESTION_16, ["Please confirm"]),
        (QUESTION_17, []),
        (QUESTION_17, ["Do you want"]),
    ],
    ids=["16.x", "16.x-in-three-pieces", "16.x-in-two-pieces", "17.x", "17.x-in-two-pieces"],
)
async def test_the_activation_question_gets_one_answer(question, cuts):
    ssh = _PromptingTransport(_pieces(question, cuts))
    result = await IOSXEInstallDriver().install(ssh, image_name="img.bin", dest_fs="flash:")
    assert result.success is True, result.error
    assert result.reboot_triggered is True
    assert ssh.sent == ["y"]


async def test_the_install_sends_the_choice_keys():
    ssh = ScriptedTransport({"show boot": BOOT_OK, "install add": Result(START + DONE)})
    await IOSXEInstallDriver().install(ssh, image_name="img.bin", dest_fs="flash:")
    answers = ssh.timing_kwargs["install add file flash:img.bin activate commit"]["answers"]
    assert answers == {"[y/n]": "y", "[yes/no]": "yes"}
