// SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Conventional Commits — commitlint configuration
// Docs: https://commitlint.js.org/reference/configuration.html
//
// JavaScript rather than YAML because `ignores` only accepts predicate
// functions, which YAML cannot express. .mjs specifically:
// wagoid/commitlint-github-action rejects a .js configFile.

// The official SemVer 2.0.0 grammar from semver.org, with its capture groups
// made non-capturing, so a malformed version (01.2.3, 3.0.0.4) is linted
// rather than exempted.
const SEMVER =
  /(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?/
    .source;

// The @semantic-release/git message template from .releaserc.json, exactly.
const RELEASE_COMMIT = new RegExp(`^chore\\(release\\): ${SEMVER} \\[skip ci\\]$`);

// Scopes are free-form, so nobody has to look up a list: one or more
// comma-separated names (sdk, core-transports, sdk,docs), each lower-case
// letters, digits and single dashes, at most SCOPE_MAX_LENGTH characters. A
// fixed list kept rejecting new areas and sending authors to reword and
// force-push. Same rule as the hegemony host repository.
const SCOPE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SCOPE_MAX_LENGTH = 20;

function scopeFormat({ scope }) {
  if (!scope) {
    return [true];
  }
  const bad = scope
    .split(",")
    .filter((name) => !SCOPE.test(name) || name.length > SCOPE_MAX_LENGTH);
  return [
    bad.length === 0,
    `scope names must be lower-case letters, digits and single dashes, at most ` +
      `${SCOPE_MAX_LENGTH} characters, comma-separated without spaces ` +
      `(e.g. sdk, core-transports, sdk,docs); not: ${bad.map((name) => JSON.stringify(name)).join(", ")}`,
  ];
}

export default {
  extends: ["@commitlint/config-conventional"],

  plugins: [{ rules: { "scope-format": scopeFormat } }],

  // semantic-release commits the generated CHANGELOG entry as the body of its
  // release commit, whose lines run far past body-max-line-length (every
  // entry carries a full commit URL). commitlint's built-in defaultIgnores
  // skip a bare `chore(release): 1.2.3`, but the ` [skip ci]` suffix from the
  // template defeats that pattern, so the release commit would be linted and
  // fail wherever it enters a PR range. Match the template exactly, marker
  // included: `chore(release): prepare for launch` stays fully linted.
  ignores: [(message) => RELEASE_COMMIT.test(message.split("\n")[0])],

  rules: {
    // Any scope, in one shape: see SCOPE above.
    "scope-format": [2, "always"],
  },
};
