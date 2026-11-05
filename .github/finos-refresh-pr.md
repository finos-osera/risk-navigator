Refreshes the FINOS public repository snapshot and selected resolved npm dependency graphs. The coverage report records scan times, repository commits, scan gaps, and signal timestamps.

Only the application dataset (maximum 5 MiB), coverage report (maximum 256 KiB), and dataset selector metadata are committed. Raw inventories, upstream vulnerability dumps, databases, and caches stay out of Git.

Validation: dataset schema, distribution size limits, and Python tests. Review changes in repository coverage and findings before merging; partial scans must not be interpreted as clean repositories.
