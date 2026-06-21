# SecEBL Public Final Benchmark Examples

This directory contains a publicly releasable subset of the internal Linux final
benchmark for verifying the release code path.

**The full internal benchmark, training corpora, private pressure-stream rows,
and removed sensitive benchmark sessions are not distributed in this GitHub
repository.**

The `*_gold.rev20.jsonl` filenames are kept for compatibility. In this release,
they are the expected Rev20 behavior-tag labels for this public benchmark
subset.

- `linux/example_sessions.jsonl`: 10,520 Linux command-session rows from 531
  public subset sessions.
- `linux/example_gold.rev20.jsonl`: matching Rev20 behavior tags for the same
  10,520 rows.

Session-level labels use English enums: `normal_operation` and `intrusion`.
