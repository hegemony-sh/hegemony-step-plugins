# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Answers to the questions a CLI command asks, declared by the flow.

A command such as ``delete flash:x`` stops at "Delete filename [x]?" and at
"[confirm]" before the device prompt returns, so a transport that waits for
the prompt alone runs into the command timeout. A step lists the questions
it expects and what to answer; a transport that supports them
(``configure_cli_prompts``) answers exactly those and nothing else. A
question nobody listed fails the command, naming the line the device is
waiting at.

No SSH library is imported here: the transports read the session and ask
:class:`PromptDialogue` what to send.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Longest pattern accepted, so a pattern stays a pattern and not a program.
MAX_PATTERN_LENGTH = 500

#: Answers one command may send in all, ``repeat`` entries included: a device
#: that keeps asking is stopped rather than answered for ever.
MAX_PROMPT_ANSWERS = 50


class CliPromptError(RuntimeError):
    """A command's dialogue could not go on; the message says where it stopped."""


def _compile(value: str, field: str) -> str:
    if len(value) > MAX_PATTERN_LENGTH:
        raise ValueError(f"{field} is longer than {MAX_PATTERN_LENGTH} characters")
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f"{field} is not a valid regular expression: {exc}") from exc
    return value


class CliPrompt(BaseModel):
    """One question a command may ask, and the answer to send."""

    model_config = ConfigDict(extra="forbid")

    command: str = Field(
        default="",
        title="Command",
        description=(
            "Regular expression searched in each command's text; the entry applies to "
            "the commands it matches. Empty applies it to every command."
        ),
    )
    expect: str = Field(
        min_length=1,
        title="Question",
        description=(
            "Regular expression for the question, matched against the last line the "
            "device printed, for example 'Delete filename \\[.*\\]\\?' or '\\[confirm\\]'."
        ),
    )
    answer: str = Field(
        default="",
        title="Answer",
        description="What to type, followed by Enter. Empty sends Enter alone.",
    )
    repeat: bool = Field(
        default=False,
        title="Answer every time",
        description=(
            "Answer this question each time it is asked, not only once per command "
            "(for example a delete /recursive that confirms each file)."
        ),
    )

    @field_validator("command")
    @classmethod
    def _valid_command(cls, value: str) -> str:
        return _compile(value, "command")

    @field_validator("expect")
    @classmethod
    def _valid_expect(cls, value: str) -> str:
        return _compile(value, "expect")


def prompts_for(command: str, prompts: Sequence[CliPrompt]) -> list[CliPrompt]:
    """The entries that apply to ``command``, in the order they were listed."""
    return [p for p in prompts if not p.command or re.search(p.command, command)]


def last_line(output: str) -> str:
    """The last line the device printed, without trailing blanks."""
    lines = output.rstrip().splitlines()
    return lines[-1].strip() if lines else ""


def waiting_at(output: str) -> str:
    """Where a command stopped, for an error message."""
    line = last_line(output)
    return f"the device is waiting at: {line!r}" if line else "the device printed nothing"


class PromptDialogue:
    """What to send for one command, given what the device has printed.

    Each entry answers once per command unless it repeats. An entry that
    matches again after its one answer, or more than ``MAX_PROMPT_ANSWERS``
    answers in all, ends the dialogue with :class:`CliPromptError`.
    """

    def __init__(self, prompts: Sequence[CliPrompt]) -> None:
        self._prompts = list(prompts)
        self._used: set[int] = set()
        self._answers = 0

    def answer_for(self, output: str) -> str | None:
        """The answer to the question ``output`` ends at; None when it ends at none."""
        line = last_line(output)
        if not line:
            return None
        for index, prompt in enumerate(self._prompts):
            if not re.search(prompt.expect, line):
                continue
            if index in self._used and not prompt.repeat:
                raise CliPromptError(
                    f"The device asked {line!r} again; that answer is given once per "
                    "command (set repeat to answer it every time)"
                )
            self._answers += 1
            if self._answers > MAX_PROMPT_ANSWERS:
                raise CliPromptError(
                    f"The device kept asking questions: more than {MAX_PROMPT_ANSWERS} answers"
                )
            self._used.add(index)
            return prompt.answer
        return None
