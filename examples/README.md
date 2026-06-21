# SecEBL Public Example Data

This directory contains public examples for verifying the release code path.

**Important: these files are not the SecEBL internal benchmark and should not be
used as the headline evaluation set. They are a small, reviewed subset for smoke
tests and API demonstration.**

**The full training corpora and full internal benchmarks include real or sensitive
telemetry context, so they are not distributed in this GitHub repository.**

The `*_gold.rev20.jsonl` filenames are kept for compatibility. In this release,
they are simply the expected Rev20 behavior-tag labels for the public examples.

- `linux/example_sessions.jsonl`: 1,365 Linux command-session rows from 30 complete normal sessions and 30 complete intrusion sessions selected from a withheld internal benchmark. Command text is preserved verbatim; session labels are normalized to English enums.
- `linux/example_gold.rev20.jsonl`: matching Rev20 behavior tags for the Linux examples.
- `k8s/example_sessions.jsonl`: 144 normalized Kubernetes AuditLog example rows.
- `k8s/example_gold.rev20.jsonl`: matching Rev20 behavior tags for the K8s examples.

These files are examples/smoke-test data only. The reported model metrics come
from internal benchmarks and pressure-stream evaluations described in the
top-level README.
