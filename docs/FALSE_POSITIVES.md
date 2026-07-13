# False Positives

Packsight intentionally separates facts, static analysis, heuristics, and missing information. A finding can be useful without proving exploitability.

Common false-positive sources:

- a deprecated function exists but is unreachable through production state;
- a version gate is implemented through a pattern the parser does not recognize;
- an old package ID is retained only for migration, indexing, or documentation;
- a missing lockfile is acceptable for a library but not an application/package deployment;
- source code differs from deployed bytecode because verified source is unavailable or incomplete.

Use accepted findings to document known context. Do not downgrade uncertainty to safe without evidence.
