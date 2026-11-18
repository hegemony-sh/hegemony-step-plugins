# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Answers to the questions a CLI command asks (netcli.execute ``prompts``).

The first tests check the SDK's dialogue on its own. The rest run the
netmiko and scrapli transports against a real in-process SSH server
(``tests/ssh_fakes.py``) whose ``delete`` asks IOS's two questions.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import asyncssh
import pytest
from pydantic import ValidationError

from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_step_sdk.cli_prompts import (
    MAX_PROMPT_ANSWERS,
    CliPrompt,
    CliPromptError,
    PromptDialogue,
    prompts_for,
)
from hegemony_transport_netmiko.transport import SSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import PASSWORD, USERNAME, Servers, checks_off, ssh_servers

DELETE_PROMPTS = [
    CliPrompt(command=r"^delete ", expect=r"Delete filename \[.*\]\?"),
    CliPrompt(command=r"^delete ", expect=r"\[confirm\]"),
]

# --- the dialogue -------------------------------------------------------------------------


def test_an_entry_applies_to_the_commands_its_pattern_finds():
    any_command = CliPrompt(expect=r"\[confirm\]")
    prompts = [*DELETE_PROMPTS, any_command]

    assert prompts_for("delete flash:a.bin", prompts) == prompts
    assert prompts_for("show flash", prompts) == [any_command]


@pytest.mark.parametrize(
    "fields",
    [{"expect": ""}, {"expect": "("}, {"expect": "x", "command": "["}, {"expect": "x" * 501}],
    ids=["empty", "bad-expect", "bad-command", "too-long"],
)
def test_an_invalid_entry_is_refused(fields: dict[str, Any]):
    with pytest.raises(ValidationError):
        CliPrompt(**fields)


def test_each_entry_answers_once_and_matches_the_last_line_only():
    dialogue = PromptDialogue(DELETE_PROMPTS)

    assert dialogue.answer_for("Delete filename [a.bin]? ") == ""
    # An earlier line that holds a question's words is not a question.
    assert dialogue.answer_for("[confirm] was printed\nr1#") is None
    assert dialogue.answer_for("Delete flash:a.bin? [confirm]") == ""
    with pytest.raises(CliPromptError, match="again"):
        dialogue.answer_for("Delete flash:b.bin? [confirm]")


def test_a_repeating_entry_answers_every_time_up_to_the_limit():
    dialogue = PromptDialogue([CliPrompt(expect=r"\[confirm\]", answer="y", repeat=True)])

    for _ in range(MAX_PROMPT_ANSWERS):
        assert dialogue.answer_for("Delete flash:d/x? [confirm]") == "y"
    with pytest.raises(CliPromptError, match="kept asking"):
        dialogue.answer_for("Delete flash:d/x? [confirm]")


# --- the transports, against a real SSH server ---------------------------------------------

HOST = "127.0.0.1"
TRANSPORTS = {"netmiko": SSHTransport, "scrapli": ScrapliTransport}


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


@pytest.fixture(params=sorted(TRANSPORTS))
def transport_id(request) -> str:
    return request.param


async def _run(servers: Servers, transport_id: str, prompts, commands, timeout=5.0):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    transport = TRANSPORTS[transport_id](
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=timeout,
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_cli_prompts(prompts)
    return await transport.execute_commands(commands)


@pytest.mark.asyncio
async def test_a_delete_answers_the_questions_the_step_lists(servers, transport_id):
    results = await _run(
        servers, transport_id, DELETE_PROMPTS, ["delete flash:mega.jpg", "show flash"]
    )

    assert [r.exit_code for r in results] == [0, 0], [r.error for r in results]
    assert "Delete flash:mega.jpg? [confirm]" in results[0].output
    assert not results[0].output.rstrip().endswith("#")
    # The next command runs on a session back at its prompt.
    assert results[1].output.strip() == "output of show flash"


@pytest.mark.asyncio
async def test_a_question_nobody_listed_names_the_line_the_device_waits_at(servers, transport_id):
    results = await _run(
        servers, transport_id, DELETE_PROMPTS[:1], ["delete flash:mega.jpg"], timeout=1.0
    )

    [result] = results
    assert result.exit_code == -1
    assert "the device is waiting at: 'Delete flash:mega.jpg? [confirm]'" in result.error
    assert "under prompts" in result.error


@pytest.mark.asyncio
async def test_without_prompts_a_timeout_suggests_listing_the_question(servers, transport_id):
    results = await _run(servers, transport_id, [], ["delete flash:mega.jpg"], timeout=1.0)

    [result] = results
    assert result.exit_code == -1
    assert "list it under prompts" in result.error
