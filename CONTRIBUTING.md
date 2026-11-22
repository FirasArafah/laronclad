# Contributing to Laronclad

Laronclad is early, so feedback on detection is as valuable as code.

## The most useful contributions

- **False positives**: something legitimate that was flagged.
- **Missed attacks**: something malicious that was not.
- **Rule ideas** and notes on what is noisy in real applications.

Use the issue templates, and describe the *shape* of an input rather than real
queries, hosts, tokens or personal data.

## Before you start

- Open an issue first for anything non-trivial.
- For small fixes, a pull request is fine.
- Do not open public issues for security problems. See [SECURITY.md](SECURITY.md).

## Setting up

    git clone https://github.com/FirasArafah/laronclad.git
    cd laronclad
    composer install

Run the same checks CI runs:

    composer test
    composer analyse
    vendor/bin/pint --test

## What a good pull request looks like

- One focused change per pull request.
- Tests for new behavior. Rules need both "matches" and "does not match" cases.
- A pattern that scans input should have a test with hostile input, so it
  cannot hang.
- Anything the package does must stay fail-open: a monitoring tool must never
  break the application it watches.

## Commit messages

Conventional Commits: `<type>(<scope>): <subject>`, first line at most 72
characters, lowercase, no trailing period.

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `style`, `chore`,
`ci`, `build`, `revert`.

## License

By contributing you agree that your contribution is licensed under the
Apache License 2.0, like the rest of the project.
