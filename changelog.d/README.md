# Changelog fragments

Each merge request adds one file here; they are compiled into `CHANGELOG.md`
by `utils/create_release.py` (using [towncrier](https://towncrier.readthedocs.io)).

Name the file `<MR number>.<type>.md`, e.g. `105.fixed.md`. For an entry
without MR, use `+<short-name>.<type>.md`. The MR reference is appended
automatically, so do not write it in the text.

Types:

* `added`: new feature or provider
* `modified`: change of behavior of an existing feature
* `fixed`: bug fix
* `deprecated`: feature that will be removed
* `removed`: feature removed

The content is a single changelog entry: keep it short, wrap lines at 80
characters, and do not start it with a bullet.
