# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Check that a command template can only insert values as literal shell words.

The host renders a step's ``{{ }}`` templates before ``shell.execute`` runs, so
a value can carry a run input or another step's output into the remote command
line. ``| quote`` (the host's ``shlex.quote`` filter) turns a value into one
literal word, but only where the shell reads it as a word: inside ``"..."`` a
value holding ``"`` closes the quotes, inside a comment or an unquoted
here-document a newline or ``$(...)`` in it runs, and so on. So a command is
accepted only when

- Jinja's own parser shows every inserted value is ``... | quote`` at the top
  of its expression (``x ~ y | quote`` quotes only ``y``), and no statement
  wraps or imports output the check cannot see (``{% filter %}``,
  ``{% include %}``, macros); and
- a small shell scanner, fed the literal text between the template tags, finds
  every value and every ``{% %}`` statement outside quotes, comments,
  backticks and here-documents. Requiring that at statements too keeps the
  branches of ``{% if %}``/``{% for %}`` from changing the quoting state, so
  scanning the text in document order covers every way the template renders.

Anything the scanner cannot follow is refused rather than guessed at.
"""

from __future__ import annotations

from jinja2 import Environment, nodes
from jinja2.exceptions import TemplateSyntaxError

#: Default delimiters, the same the host's SandboxedEnvironment uses. Only
#: parses and lexes; nothing is rendered here.
_ENV = Environment()

#: Statements whose output the check cannot follow: they post-process or pull
#: in rendered text (``{% filter replace("'", "") %}`` would strip the quoting).
_OPAQUE_STATEMENTS: tuple[type[nodes.Node], ...] = (
    nodes.FilterBlock,
    nodes.CallBlock,
    nodes.Macro,
    nodes.Include,
    nodes.Import,
    nodes.FromImport,
    nodes.Extends,
    nodes.Block,
)

#: Lexer tokens that open a tag whose output or branching the scanner must see
#: from an unquoted position (comments render nothing and are skipped).
_TAG_STARTS = frozenset({"variable_begin", "block_begin", "raw_begin"})

#: Characters after which a ``#`` starts a comment.
_WORD_BREAKS = frozenset(" \t\n;&|()<>")

NOT_QUOTED = (
    "a {{ }} value must end with | quote, e.g. {{ inputs.name | quote }}, or be "
    'passed in Environment Variables and read as "$NAME"'
)
NOT_A_WORD = (
    "a {{ }} value and every {% %} statement must stand outside quotes, comments, "
    "backticks and here-documents, where | quote keeps the value one word; write "
    "it unquoted, as in echo {{ inputs.name | quote }}"
)
OPAQUE = "{% filter %}, {% include %}, {% import %}, {% extends %} and macros are not supported"
INVALID = "is not a valid template"


def command_template_problem(command: str) -> str | None:
    """Why ``command`` could let a rendered value become shell syntax, or None."""
    if "{" not in command:
        return None
    try:
        tree = _ENV.parse(command)
        tokens = list(_ENV.lex(command))
    except TemplateSyntaxError:
        return INVALID
    if any(True for _ in tree.find_all(_OPAQUE_STATEMENTS)):
        return OPAQUE
    for output in tree.find_all(nodes.Output):
        for child in output.nodes:
            if not isinstance(child, nodes.TemplateData) and not _is_quoted(child):
                return NOT_QUOTED
    scanner = _ShellScanner()
    for _lineno, token, value in tokens:
        if token == "data":
            scanner.feed(value)
        elif token in _TAG_STARTS and not scanner.at_safe_point():
            return NOT_A_WORD
    return None


def _is_quoted(expression: nodes.Node) -> bool:
    """Whether the whole expression is ``<value> | quote`` with no arguments."""
    return (
        isinstance(expression, nodes.Filter)
        and expression.name == "quote"
        and not expression.args
        and not expression.kwargs
        and expression.dyn_args is None
        and expression.dyn_kwargs is None
    )


class _ShellScanner:
    """POSIX shell quoting state over the literal text of a command template.

    Tracks just enough to say whether the next character would be read in an
    unquoted word position: quotes, ``$'...'``, backslash escapes, backticks,
    comments and here-documents. Where it would have to guess (command
    substitution inside double quotes) it marks itself unsure, and every later
    value is refused.
    """

    def __init__(self) -> None:
        self.state = "normal"
        self.escaped = False
        self.unsure = False
        self.prev = "\n"
        # Here-documents announced on the current line: (delimiter, strip tabs).
        self.pending: list[tuple[str, bool]] = []
        self.heredoc_line = ""
        self.delimiter = ""
        self.delimiter_quote = ""

    def at_safe_point(self) -> bool:
        """Whether text inserted now would be read as (part of) an unquoted word."""
        return self.state == "normal" and not self.escaped and not self.unsure and self.prev != "$"

    def feed(self, text: str) -> None:
        index = 0
        while index < len(text):
            char = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""
            index += self._step(char, following, text, index)

    def _step(self, char: str, following: str, text: str, index: int) -> int:
        """Consume ``char`` (with one character of lookahead); returns how many were used."""
        state = self.state
        if state == "heredoc_body":
            self._heredoc_char(char)
            return 1
        if state == "heredoc_delimiter":
            return self._delimiter_char(char)
        if self.escaped:
            self.escaped = False
            self.prev = "x"
            return 1
        if state == "single":
            if char == "'":
                self.state = "normal"
        elif state == "ansi":
            if char == "\\":
                self.escaped = True
            elif char == "'":
                self.state = "normal"
        elif state == "double":
            if char == "\\":
                self.escaped = True
            elif char == '"':
                self.state = "normal"
            elif char == "`" or (char == "$" and following == "("):
                # A nested command could hold quotes this scanner would misread.
                self.unsure = True
        elif state == "backtick":
            if char == "\\":
                self.escaped = True
            elif char == "`":
                self.state = "normal"
        elif state == "comment":
            if char == "\n":
                self._newline()
        else:
            return self._normal_char(char, following, text, index)
        self.prev = char
        return 1

    def _normal_char(self, char: str, following: str, text: str, index: int) -> int:
        if char == "\\":
            self.escaped = True
        elif char == "'":
            self.state = "ansi" if self.prev == "$" else "single"
        elif char == '"':
            self.state = "double"
        elif char == "`":
            self.state = "backtick"
        elif char == "#" and self.prev in _WORD_BREAKS:
            self.state = "comment"
        elif char == "<" and following == "<" and text[index + 2 : index + 3] != "<":
            strip = text[index + 2 : index + 3] == "-"
            self.state = "heredoc_delimiter"
            self.delimiter = ""
            self.delimiter_quote = ""
            self.pending.append(("", strip))
            self.prev = "<"
            return 3 if strip else 2
        elif char == "\n":
            self._newline()
        self.prev = char
        return 1

    def _delimiter_char(self, char: str) -> int:
        """Read the here-document's delimiter word (quotes removed)."""
        if self.delimiter_quote:
            if char == self.delimiter_quote:
                self.delimiter_quote = ""
            else:
                self.delimiter += char
            return 1
        if char in "'\"":
            self.delimiter_quote = char
            return 1
        if char in " \t" and not self.delimiter:
            return 1
        if char in _WORD_BREAKS:
            self.pending[-1] = (self.delimiter, self.pending[-1][1])
            self.state = "normal"
            self.prev = " "
            # The character that ended the word is read again as normal text.
            return 0
        self.delimiter += char
        return 1

    def _newline(self) -> None:
        self.state = "normal"
        self.prev = "\n"
        if self.pending:
            self.state = "heredoc_body"
            self.heredoc_line = ""

    def _heredoc_char(self, char: str) -> None:
        if char != "\n":
            self.heredoc_line += char
            return
        delimiter, strip = self.pending[0]
        line = self.heredoc_line.lstrip("\t") if strip else self.heredoc_line
        self.heredoc_line = ""
        if line == delimiter:
            self.pending.pop(0)
            if not self.pending:
                self.state = "normal"
                self.prev = "\n"
