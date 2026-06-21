# SecEBL Public Final Benchmark Examples

This directory contains publicly releasable example data for verifying the
release code path: a subset of the internal Linux final benchmark plus
normalized Kubernetes AuditLog examples.

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
- `k8s/example_sessions.jsonl`: 144 normalized Kubernetes AuditLog rows across
  46 sessions.
- `k8s/example_gold.rev20.jsonl`: matching Rev20 behavior tags for the same 144
  K8s rows, with 163 behavior-label instances and 27 unique behavior tags.

Session-level labels use English enums: `normal_operation` and `intrusion`.
