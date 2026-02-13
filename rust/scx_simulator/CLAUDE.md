
scx_simulator: Development Guidelines
=======================================================

This document contains the development guidelines and instructions for the project. This guide OVERRIDES any default behaviors and MUST be followed exactly.

If you become stuck with an issue you cannot debug, you can file an issue for it and leave it to work on other topics. Of course, the tests should be always passing before each commit and achieve reasonably good code coverage as described below.

Coding conventions
========================================

You HATE duplicated code. You follow DRY religiously and seek clean abstractions where functions are short, and complexity is factored into helpers, traits, and centralized infrastructure that is shared as much as possible. You hate duplication so much that you would rather centralize repetitive code EVEN if it means the interface to the shared functionality becomes fairly complex (e.g. the shared logic uses callbacks with complex types for the pieces that vary between use cases).

You also dislike long files. Whenever a file grows longer than 1500 lines you propose ideas for breaking it into separate modules.

PREFER STRONG TYPES. Do not use "u32" or "String" where you can have a more specific type or at least a type alias. "String" makes it very unclear which values are legal. We want explicit Enums to lock down the possibilities for our state, and we want separate types for numerical IDs and distinct, non-overlapping uses of basic integers.

Delete trailing spaces. Don't leave empty lines that consist only of whitespace. (Double newline is fine.)

Adhere to high-performance Rust patterns (unboxing, minimizing allocation, etc). In particular, adhere to the below programming patterns / avoid anti-patterns, which generally fall under the principle of "zero copy":

- Avoid clone: instead take a temporary reference to the object and manage lifetimes appropriately.
- Avoid collect: instead take an iterator with references to the original collection without copying.

Read OPTIMIZATION.md for more details.

Documentation and Analysis
========================================

When creating analysis documents, specifications, or other AI-generated documentation, place them in the `ai_docs/` directory. This keeps the top-level clean and makes it clear which documents are AI-generated analysis (and may become outdated) versus core project documentation.

Workflow: Commits and Version Control
================================================================================

Clean Start: Before beginning work on a task
--------------------------------------------

Make sure we start in a clean state. Check that we have no uncommitted changes in our working copy. Perform `git pull origin <BRANCH>` to make sure we are starting with the latest version on our branch. Check that `./validate.sh` passes in our starting state.

Pre-Commit: checks before committing to git
--------------------------------------------

Run `./validate.sh` and ensure that it passes or fix any problems before committing.

Also include a `Test Results Summary` section in every commit message that summarizes how many tests passed of what kind.

If you validate some changes with a new manual or temporary test, that test should be added to either the unit tests or integration tests and it should be called consistently from `./validate.sh`.

NEVER add binary files or large serialized artifacts to version control without explicit permission. Always carefully review what you are adding with `git add`, and update `.gitignore` as needed.

Amending commits
----------------------------------------

It is fine to amend the most recent commit (git commit --amend) as long as it has NOT been pushed to the remote yet. If the commit has already been pushed, create a new commit instead.

Branches and pushing
----------------------------------------

The `main` branch is protected. Never push directly to main. Only push to feature branches after validation. Don't force push unless you're asked to or ask permission.

Issue Tracking
========================================

We use minibeads (`mb`) for local issue tracking. Run `mb quickstart` to learn
the commands. Use `mb ready` to find the next issue to work on, and update issue
status as you work (`mb update sim-N --status in_progress`, `mb close sim-N`).

File issues for bugs, TODOs, and feature work rather than leaving stale TODO
comments in code. Reference issue IDs (e.g. sim-1) in commit messages when
closing issues.
