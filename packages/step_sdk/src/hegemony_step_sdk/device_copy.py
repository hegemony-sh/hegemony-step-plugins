# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""How the built-in device transports read a ``copy <url> <fs><name>`` dialogue.

The device echoes the inputs of the copy (the command, "Destination filename
[<name>]?", "Accessing <url>..."), so its markers are matched in
:func:`copy_answer`, not in the raw output.
"""

from __future__ import annotations

#: Output that ends a ``copy <url> <fs>`` dialogue, whether it worked or not.
#: "nknown command" is a platform without this copy command ("% Unknown
#: command" on FRR, "unknown command." on Junos): the answer is final.
COPY_DONE_MARKERS = (
    "bytes copied",
    "%Error",
    "Error opening",
    "Invalid",
    "not found",
    "timed out",
    "refused",
    "Could not",
    "Incomplete command",
    "nknown command",
    "Broken pipe",
)

#: Output that means the copy failed.
COPY_ERROR_MARKERS = (
    "%Error",
    "Error opening",
    "Error reading",
    "Invalid",
    "not found",
    "refused",
    "Could not",
    "Broken pipe",
    "timed out",
)


def copy_answer(output: str, url: str, dest_filename: str) -> str:
    """The device's own words in a copy dialogue: ``output`` without the inputs it echoes.

    The device repeats the URL and the file name (the command echo,
    "Destination filename [<name>]?", "Accessing <url>..."), so a name like
    ``Invalid-image.bin`` must not read as the device's "Invalid".
    """
    for echoed in (url, dest_filename):
        if echoed:
            output = output.replace(echoed, "")
    return output
