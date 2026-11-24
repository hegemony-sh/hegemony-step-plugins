# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The text a CLI command puts in the run's live log (the Logs tab)."""


def command_transcript(command: str, output: str | None) -> str:
    """The command as a ``$ command`` line, then its output.

    The transports strip the device's echo of the command and its prompt, so
    the line is what shows which command ran. A command that prints nothing,
    such as ``delete /force``, still leaves that line in the log.
    """
    text = f"$ {command}\n"
    if output:
        text += output if output.endswith("\n") else output + "\n"
    return text


def was_skipped(result: object) -> bool:
    """Whether the transport skipped the command instead of running it.

    Every transport gives a command it did not send (after an earlier
    failure, a closed session or a cancelled run) an error that starts with
    ``Skipped:``. The live log leaves such a command out, so it does not
    read as one that ran.
    """
    error = getattr(result, "error", None)
    return isinstance(error, str) and error.startswith("Skipped:")
