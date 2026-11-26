# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- An approval name is now refused when it holds a slash, a NUL (null) byte, or is `.` or `..`.
  `delegated_identity` answers `None` for such a name. It already did so for an empty name, a name
  with a space and a name longer than thirty-two bytes.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
