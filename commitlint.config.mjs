/** @type {import('@commitlint/types').UserConfig} */
export default {
  extends: ["@commitlint/config-conventional"],
  // Align with release-please / Conventional Commits used by this repo.
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "build",
        "chore",
        "ci",
        "docs",
        "feat",
        "fix",
        "perf",
        "refactor",
        "revert",
        "style",
        "test",
      ],
    ],
    // Soft limit for readable subjects; release-please does not enforce length.
    "header-max-length": [2, "always", 120],
    "subject-case": [0],
  },
};
