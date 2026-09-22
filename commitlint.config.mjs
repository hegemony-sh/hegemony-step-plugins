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

export default {
  extends: ["@commitlint/config-conventional"],

  // semantic-release commits the generated CHANGELOG entry as the body of its
  // release commit, whose lines run far past body-max-line-length (every
  // entry carries a full commit URL). commitlint's built-in defaultIgnores
  // skip a bare `chore(release): 1.2.3`, but the ` [skip ci]` suffix from the
  // template defeats that pattern, so the release commit would be linted and
  // fail wherever it enters a PR range. Match the template exactly, marker
  // included: `chore(release): prepare for launch` stays fully linted.
  ignores: [(message) => RELEASE_COMMIT.test(message.split("\n")[0])],

  rules: {
    // Allowed scopes for this repository
    "scope-enum": [
      2, // error
      "always",
      [
        "sdk",
        "vault",
        "1password",
        "ci",
        "deps",
        "docs",
        "release",
        "tests",
      ],
    ],
  },
};
