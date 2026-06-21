# L1 Data, Benchmark, Accuracy, and Performance Summary

This document consolidates the L1 tag taxonomy, training sample information,
benchmark information, historical base-model change evidence, accuracy metrics,
and runtime performance for the current public SecEBL release.

Raw training corpora, the full internal benchmark, private pressure-stream rows,
review queues, and private run logs are not redistributed because parts of them
contain real telemetry or real operational context. Public examples are included
as a reviewed subset of the internal Linux final benchmark for smoke tests and
API/output inspection; headline L1 metrics come from the larger internal
evaluation.

## L1 Tag Taxonomy

| Area | Item | Count | Distribution | Notes |
| --- | --- | ---: | --- | --- |
| Vocabulary | Behavior vocabulary | 361 labels | 12 behavior groups | Flat behavior-intent vocabulary. Labels describe visible behavior, not maliciousness or final risk. |
| Vocabulary | Behavior groups | 12 groups | `observation_and_discovery`: 51<br>`configuration_and_log_modification`: 12<br>`filesystem_and_data`: 33<br>`execution_and_process`: 28<br>`network`: 51<br>`identity_auth_and_secrets`: 31<br>`persistence_services_and_storage`: 27<br>`kernel_memory_and_tracing`: 14<br>`package_build_and_source`: 19<br>`database_and_infrastructure_services`: 33<br>`containers_and_cloud_native`: 34<br>`cloud_control_plane`: 28 | Internal Linux benchmark covers 361 / 361 labels. |

## Training Samples And Benchmark Data

| Area | Dataset / Artifact | Size | Distribution | Notes |
| --- | --- | ---: | --- | --- |
| Training corpus | Combined training corpus | 86,285 rows | Linux command corpus: 85,277 rows<br>Kubernetes AuditLog corpus: 1,008 rows | Raw corpora are not redistributed. |
| Training corpus | Usable training observations | 82,895 rows | 3,390 abstain rows skipped | Rows with usable behavior labels. |
| Training corpus | Positive command/tag pairs | 117,092 base pairs<br>118,858 effective pairs | 1,766 boundary-sensitive pairs duplicated once | Effective pair count after targeted boundary upsampling. |
| Training corpus | Linux command corpus | 85,277 rows | 361 unique behavior labels<br>roughly 2,700 distinct first-token/tool forms | Covers shell utilities, network tools, package/build tools, cloud CLIs, IaC tools, container tooling, databases, secret stores, and Kubernetes tooling. |
| Training corpus | Kubernetes AuditLog corpus | 1,008 rows | 40 unique behavior labels | Manually authored normalized Kubernetes AuditLog events. |
| Training setup | Model and objective | `Alibaba-NLP/gte-modernbert-base` | `MultipleNegativesRankingLoss` with hard-negative-aware batches | L1 is an embedding retrieval labeler. |
| Training setup | Hardware and runtime | RTX 5090 32GB<br>128 epochs<br>batch size 112<br>`fp32`<br>58,291 seconds, about 16.2 hours | 1,062 steps per epoch<br>135,936 optimizer steps<br>sequence length 160 | Training run used learning rate `2e-5`, warmup ratio `0.06`, 8,156 warmup steps, weight decay `0.01`. |
| Training setup | Hard negatives | n/a | Schema-level hard negatives<br>hard-negative-aware MNRL batches<br>targeted boundary upsampling | Hard negatives target read-vs-search, inspect-vs-modify, local-vs-remote execution, wrapper commands, and tool-specific boundary cases. |
| Public examples | Linux benchmark subset | 10,520 rows<br>531 sessions | 2,934 normal-operation rows<br>7,586 intrusion rows<br>10,019 rows with labels<br>14,807 behavior-label instances<br>349 unique labels | Publicly releasable subset of the internal Linux final benchmark for smoke tests and API demonstration. |
| Public examples | Linux label cardinality | 10,520 rows | 0 labels: 501 rows<br>1 label: 7,389 rows<br>2 labels: 1,284 rows<br>3 labels: 783 rows<br>4 labels: 377 rows<br>5 labels: 135 rows<br>6 labels: 42 rows<br>7 labels: 6 rows<br>8 labels: 3 rows | Public Linux subset distribution. |
| Public examples | Top Linux public-subset labels | n/a | `stage_temporary_path`: 920<br>`inspect_network_state`: 758<br>`stage_hidden_path`: 653<br>`inspect_current_identity`: 525<br>`read_credential_material`: 482<br>`inspect_system_state`: 406<br>`query_dns_records`: 354<br>`enumerate_filesystem`: 334<br>`inspect_infrastructure_service`: 317<br>`search_credentials`: 299 | Distribution of included public Linux subset examples. |
| Internal benchmark | Linux command benchmark | 12,594 rows | 11,889 rows with labels<br>17,287 behavior-label instances<br>361 / 361 unique labels | Full internal L1 behavior-label evaluation set; rows are not redistributed. |
| Internal benchmark | Kubernetes evaluation set | 144 rows | 144 rows with labels<br>163 behavior-label instances<br>27 / 361 unique labels | Small-domain Kubernetes sanity/evaluation set. |
| Internal benchmark | Combined L1 evaluation | 12,738 rows | 12,033 rows with labels<br>17,450 behavior-label instances<br>361 / 361 unique labels | Combined Linux internal benchmark plus Kubernetes evaluation set. |
| Internal benchmark | Linux benchmark label cardinality | 12,594 rows | 0 labels: 705 rows<br>1 label: 8,829 rows<br>2 labels: 1,567 rows<br>3 labels: 901 rows<br>4 labels: 402 rows<br>5 labels: 139 rows<br>6+ labels: 51 rows | Shows the benchmark includes dense multi-label rows, not only single-label commands. |
| Internal benchmark | Top Linux benchmark labels | n/a | `stage_temporary_path`: 987<br>`inspect_network_state`: 801<br>`stage_hidden_path`: 655<br>`inspect_current_identity`: 578<br>`read_credential_material`: 551<br>`inspect_system_state`: 481<br>`inspect_infrastructure_service`: 390<br>`query_dns_records`: 372<br>`enumerate_filesystem`: 365<br>`search_credentials`: 315 | Aggregate benchmark-label distribution. |

## Historical Base-Model Change Evidence

This table records the available historical evidence around the move from the
early BGE baseline to the GTE ModernBERT line. It is not a pure base-model A/B:
the corpus, hard-negative setup, and evaluation data changed over time. The
numbers are included only as historical release evidence for why the current
line uses `Alibaba-NLP/gte-modernbert-base`.

| Baseline | Base model | Training / run setup | Available retrieval evidence | Available session evidence | Takeaway |
| --- | --- | --- | --- | --- | --- |
| 2026-06-11 BGE Ep48 | `BAAI/bge-base-en-v1.5` | 48 epochs<br>batch size 192<br>`fp32`<br>`MultipleNegativesRankingLoss`<br>`unique_label` batch sampler<br>61,994 effective pairs<br>runtime 8,167.579s | Holdout retrieval diagnostic on 1,053 samples:<br>exact match 67.52%<br>micro F1 77.30%<br>top1 accuracy 82.65%<br>oracle top-k coverage 95.92% | Final Linux HQ e2e:<br>849 sessions / 18,961 rows<br>TP/TN/FP/FN 521/259/67/2<br>accuracy 91.87%<br>attack recall 99.62%<br>normal recall 79.45% | Early baseline had high attack recall but weak normal recall and many false positives. |
| 2026-06-17 GTE ModernBERT 60ep | `Alibaba-NLP/gte-modernbert-base` | 60 epochs<br>batch size 112<br>`fp32`<br>MNRL hard negatives<br>106,715 effective pairs<br>runtime 20,134.312s | Linux final-goldall command evaluation:<br>18,961 rows / 17,830 rows with gold<br>top5 any-hit 96.85%<br>top5 all-covered 89.80%<br>micro recall@5 91.62% | Final Linux HQ e2e:<br>849 sessions / 18,961 rows<br>TP/TN/FP/FN 514/305/21/9<br>accuracy 96.47%<br>attack recall 98.28%<br>normal recall 93.56% | Compared with the BGE baseline's session result, accuracy increased by 4.59 pp, normal recall increased by 14.11 pp, and false positives dropped from 67 to 21. |
| Current public L1 release | `Alibaba-NLP/gte-modernbert-base` | 128 epochs<br>batch size 112<br>`fp32`<br>hard-negative-aware batches<br>118,858 effective pairs<br>runtime about 16.2 hours | Linux internal benchmark:<br>12,594 rows / 11,889 rows with labels<br>dynamic exact 87.32%<br>top5 any-hit 98.49%<br>top5 all-covered 95.44%<br>micro recall@5 96.44% | L2 session scorer is documented separately; current L1 table focuses on behavior-label retrieval. | Current released line keeps GTE ModernBERT as the base model because it supports stronger behavior-label retrieval with the maintained training setup. |

## L1 Accuracy

| Dataset | Rows | Label coverage | Dynamic exact | Top5 any-hit | Top5 all-covered | Micro recall@5 | Interpretation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Linux internal benchmark | 12,594 | 361 / 361 | 87.32% | 98.49% | 95.44% | 96.44% | Main L1 quality signal because it covers the full vocabulary and includes dense multi-label rows. |
| Kubernetes evaluation set | 144 | 27 / 361 | 99.31% | 100.00% | 100.00% | 100.00% | Small-domain Kubernetes result, not a broad Kubernetes coverage claim. |
| Combined evaluation | 12,738 | 361 / 361 | 87.47% | 98.50% | 95.50% | 96.47% | Combined L1 retrieval result. |

Metric definitions:

- **Dynamic exact**: strict exact-match metric for the dynamic label set.
- **Top5 any-hit**: at least one expected behavior label appears in the top 5.
- **Top5 all-covered**: all expected behavior labels appear within the top 5.
- **Micro recall@5**: behavior-label instance recall at top 5.

L1 public example metrics are computed from ranked top-k labels, not from a
user-facing selection threshold. Runtime L1 predictions expose ranked
`top_labels`; they do not emit `behavior_tags` or a final verdict.

## L1 Runtime Performance

| Area | Metric / Setting | Value | Measurement Context | Notes |
| --- | --- | ---: | --- | --- |
| Recommended serving | Precision | FP16 | Single-card CUDA | Main recommended inference precision. |
| Recommended serving | Attention | SDPA | Single-card CUDA | Used in the RTX 5090 spot-check. |
| Recommended serving | `max_seq_length` | 160 | L1 embedding path | Matches the release serving profile. |
| Recommended serving | Batch size | 224 default | RTX 5090 spot-check | Batch size 384 was slightly faster in one quick sweep but not enough to replace the stable default. |
| Recommended serving | Sorting | `sort_by=char` | Batch construction | Reduces padding waste. |
| Recommended serving | Padding | Dynamic | Batch construction | No forced pad alignment. |
| Recommended serving | Output path | GPU tensor output plus GPU top-k | L1 retrieval path | Avoids copying full embedding matrices to NumPy. |
| Throughput | Recommended no-cache unique inference | Mean 5,308.72 unique cmdlines/s | RTX 5090 32GB, FP16, SDPA, batch size 224 | Single-card CUDA spot-check. |
| Latency | Recommended no-cache latency | About 0.1884 ms per unique cmdline | Same RTX 5090 spot-check | Derived from recommended no-cache unique inference. |
| Throughput range | `bs224` repeat range | 5,025.47 - 5,433.78 unique cmdlines/s | RTX 5090, batch size 224 | Measured repeat range for the recommended setting. |
| Quick sweep | Best quick-sweep point | 5,378.45 unique cmdlines/s | RTX 5090, batch size 384 | Slightly faster in one sweep, but not the documented stable default. |
| Cache path | Exact raw-event cache lookup | Mean 1,817,462.76 rows/s | Exact raw event string cache key | Cache hits reuse saved L1 top-k predictions and do not run model inference. |
| Optimization | Main serving optimizations | n/a | FP16 with SDPA<br>GPU-resident command and label embeddings<br>GPU top-k<br>length-based batch sorting<br>exact raw-event caching | These optimizations preserve L1 semantics while improving throughput. |
