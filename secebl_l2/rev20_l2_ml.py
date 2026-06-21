#!/usr/bin/env python3
"""Train and run a lightweight rev20 ML L2 session scorer.

The ML L2 intentionally consumes only cached L1 top-k label ids and retrieval
scores. Raw command text is used only as a lookup key for prediction rows and
never becomes a model feature.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

os.environ.setdefault("USE_TF", "0")
os.environ.setdefault("USE_FLAX", "0")
os.environ.setdefault("TRANSFORMERS_NO_TF", "1")
os.environ.setdefault("TRANSFORMERS_NO_FLAX", "1")

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rev20_l2_features import (  # noqa: E402
    build_tag_hits,
    load_prediction_tags,
    load_risk_policy,
    l1_event_feature_profile,
    selected_tag_scores_from_top_labels,
)
from session_scorer import write_json  # noqa: E402
from stream_risk_common import (  # noqa: E402
    ATTACK_LABEL,
    KNOWN_LABELS,
    NORMAL_LABEL,
    StreamEvent,
    infer_input_format,
    iter_benchmark_events,
    iter_csv_events,
    parse_session_fields,
)
from v4_tags_embedding_retrieval import (  # noqa: E402
    DEFAULT_MAX_TAGS_PER_COMMAND,
    DEFAULT_MIN_TAG_SCORE,
    DEFAULT_MULTI_LABEL_GAP,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = Path(__file__).resolve().parent / "tag_risk_policy.rev20.json"
DEFAULT_MODEL_OUT = ROOT / "models/rev20-l2-ml/logreg.joblib"
DEFAULT_RESULTS_OUT = ROOT / "runs/rev20_l2_ml/session_results.json"
SCHEMA = "agentsmith_rev20_l2_ml_v1"
FEATURE_SCHEMA = "agentsmith_rev20_l2_features_v1"
SCORE_TRANSFORM_RAW = "raw"
SCORE_TRANSFORM_THRESHOLD_MARGIN = "threshold_margin"
SCORE_TRANSFORMS = {SCORE_TRANSFORM_RAW, SCORE_TRANSFORM_THRESHOLD_MARGIN}
PROBABILITY_EPSILON = 1e-9
CHAIN_MARKERS = {
    "credential_access",
    "egress",
    "persistence",
    "ingress_execution",
    "identity_policy",
    "recon",
    "remote_access",
    "boundary_cross",
}
CHAIN_FAMILIES = {
    "remote_access",
    "privilege",
    "network_recon",
    "data_movement",
    "data_egress",
}
CHAIN_TAGS = {
    "create_archive",
    "upload_external_content",
    "archive_sensitive_content",
    "upload_sensitive_content",
    "read_credential_material",
    "upload_credential_material",
    "download_script",
    "execute_downloaded_content",
    "download_executable",
    "write_executable_content",
}


@dataclass(frozen=True)
class L1Event:
    selected_tags: tuple[str, ...]
    top_labels: tuple[dict[str, Any], ...]
    tag_scores: tuple[tuple[str, float], ...]
    families: tuple[str, ...]
    markers: tuple[str, ...]
    family_points: dict[str, float]
    event_intensity: float
    top1_score: float
    top2_score: float
    top_margin: float
    explicit_attack: bool
    operational_only: bool
    routine_maintenance_only: bool
    professional_operation: bool
    professional_anchor: bool
    professional_sensitive: bool


@dataclass
class SessionFeatureState:
    session_id: str
    expected: str | None = None
    command_count: int = 0
    tagged_events: int = 0
    selected_tag_total: int = 0
    tag_counts: Counter[str] = field(default_factory=Counter)
    tag_score_sum: Counter[str] = field(default_factory=Counter)
    tag_score_max: dict[str, float] = field(default_factory=dict)
    family_counts: Counter[str] = field(default_factory=Counter)
    family_points: Counter[str] = field(default_factory=Counter)
    marker_counts: Counter[str] = field(default_factory=Counter)
    family_transitions: Counter[str] = field(default_factory=Counter)
    marker_transitions: Counter[str] = field(default_factory=Counter)
    event_intensity_sum: float = 0.0
    event_intensity_sq_sum: float = 0.0
    event_intensity_max: float = 0.0
    event_intensity_min: float = 10.0
    event_intensity_over_5: int = 0
    event_intensity_over_6: int = 0
    event_intensity_over_7: int = 0
    top1_sum: float = 0.0
    top1_max: float = 0.0
    top_margin_sum: float = 0.0
    explicit_attack_count: int = 0
    operational_only_count: int = 0
    routine_maintenance_count: int = 0
    professional_count: int = 0
    professional_anchor_count: int = 0
    professional_sensitive_count: int = 0
    first_family_pos: dict[str, int] = field(default_factory=dict)
    last_family_pos: dict[str, int] = field(default_factory=dict)
    first_marker_pos: dict[str, int] = field(default_factory=dict)
    last_marker_pos: dict[str, int] = field(default_factory=dict)
    first_tag_pos: dict[str, int] = field(default_factory=dict)
    last_tag_pos: dict[str, int] = field(default_factory=dict)
    prev_families: tuple[str, ...] = ()
    prev_markers: tuple[str, ...] = ()
    tail_scores: deque[float] = field(default_factory=lambda: deque(maxlen=16))
    tail_tagged: deque[int] = field(default_factory=lambda: deque(maxlen=16))
    tail_marker_counts: deque[int] = field(default_factory=lambda: deque(maxlen=16))
    tail_score_sum: float = 0.0
    tail_tagged_sum: int = 0
    tail_marker_count_sum: int = 0

    def add(self, event: L1Event) -> None:
        self.command_count += 1
        pos = self.command_count
        if event.selected_tags:
            self.tagged_events += 1
        self.selected_tag_total += len(event.selected_tags)

        tag_counts = self.tag_counts
        tag_score_sum = self.tag_score_sum
        tag_score_max = self.tag_score_max
        first_tag_pos = self.first_tag_pos
        last_tag_pos = self.last_tag_pos
        for tag, score in event.tag_scores:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            tag_score_sum[tag] = tag_score_sum.get(tag, 0.0) + score
            previous_max = tag_score_max.get(tag, 0.0)
            if score > previous_max:
                tag_score_max[tag] = score
            if tag in CHAIN_TAGS and tag not in first_tag_pos:
                first_tag_pos[tag] = pos
            if tag in CHAIN_TAGS:
                last_tag_pos[tag] = pos

        current_families = event.families
        current_markers = event.markers
        family_counts = self.family_counts
        first_family_pos = self.first_family_pos
        last_family_pos = self.last_family_pos
        for family in current_families:
            family_counts[family] = family_counts.get(family, 0) + 1
            if family in CHAIN_FAMILIES and family not in first_family_pos:
                first_family_pos[family] = pos
            if family in CHAIN_FAMILIES:
                last_family_pos[family] = pos
        family_points = self.family_points
        for family, points in event.family_points.items():
            family_points[family] = family_points.get(family, 0.0) + float(points)
        marker_counts = self.marker_counts
        first_marker_pos = self.first_marker_pos
        last_marker_pos = self.last_marker_pos
        for marker in current_markers:
            marker_counts[marker] = marker_counts.get(marker, 0) + 1
            if marker in CHAIN_MARKERS and marker not in first_marker_pos:
                first_marker_pos[marker] = pos
            if marker in CHAIN_MARKERS:
                last_marker_pos[marker] = pos

        family_transitions = self.family_transitions
        for previous in self.prev_families:
            for current in current_families:
                transition = f"{previous}->{current}"
                family_transitions[transition] = family_transitions.get(transition, 0) + 1
        marker_transitions = self.marker_transitions
        for previous in self.prev_markers:
            for current in current_markers:
                transition = f"{previous}->{current}"
                marker_transitions[transition] = marker_transitions.get(transition, 0) + 1
        self.prev_families = current_families
        self.prev_markers = current_markers

        intensity = float(event.event_intensity)
        self.event_intensity_sum += intensity
        self.event_intensity_sq_sum += intensity * intensity
        self.event_intensity_max = max(self.event_intensity_max, intensity)
        self.event_intensity_min = min(self.event_intensity_min, intensity)
        self.event_intensity_over_5 += int(intensity >= 5.0)
        self.event_intensity_over_6 += int(intensity >= 6.0)
        self.event_intensity_over_7 += int(intensity >= 7.0)
        self.top1_sum += event.top1_score
        self.top1_max = max(self.top1_max, event.top1_score)
        self.top_margin_sum += event.top_margin
        self.explicit_attack_count += int(event.explicit_attack)
        self.operational_only_count += int(event.operational_only)
        self.routine_maintenance_count += int(event.routine_maintenance_only)
        self.professional_count += int(event.professional_operation)
        self.professional_anchor_count += int(event.professional_anchor)
        self.professional_sensitive_count += int(event.professional_sensitive)
        if len(self.tail_scores) == self.tail_scores.maxlen:
            self.tail_score_sum -= self.tail_scores[0]
        if len(self.tail_tagged) == self.tail_tagged.maxlen:
            self.tail_tagged_sum -= self.tail_tagged[0]
        if len(self.tail_marker_counts) == self.tail_marker_counts.maxlen:
            self.tail_marker_count_sum -= self.tail_marker_counts[0]
        self.tail_scores.append(intensity)
        self.tail_score_sum += intensity
        tagged_value = 1 if event.selected_tags else 0
        self.tail_tagged.append(tagged_value)
        self.tail_tagged_sum += tagged_value
        marker_count = len(current_markers)
        self.tail_marker_counts.append(marker_count)
        self.tail_marker_count_sum += marker_count

    def feature_dict(self) -> dict[str, float]:
        n = max(self.command_count, 1)
        transition_denominator = max(n - 1, 1)
        features: dict[str, float] = {
            "schema_bias": 1.0,
            "events": float(n),
            "log_events": math.log1p(n),
            "events_ge_32": float(n >= 32),
            "events_ge_128": float(n >= 128),
            "events_ge_512": float(n >= 512),
            "events_ge_2048": float(n >= 2048),
            "tagged_event_ratio": self.tagged_events / n,
            "selected_tags_per_event": self.selected_tag_total / n,
            "unique_tag_count": float(len(self.tag_counts)),
            "unique_family_count": float(len(self.family_counts)),
            "unique_marker_count": float(len(self.marker_counts)),
            "event_intensity_mean": self.event_intensity_sum / n,
            "event_intensity_max": self.event_intensity_max,
            "event_intensity_min": self.event_intensity_min if self.command_count else 0.0,
            "event_intensity_std": self._event_intensity_std(n),
            "event_intensity_over_5_ratio": self.event_intensity_over_5 / n,
            "event_intensity_over_6_ratio": self.event_intensity_over_6 / n,
            "event_intensity_over_7_ratio": self.event_intensity_over_7 / n,
            "top1_score_mean": self.top1_sum / n,
            "top1_score_max": self.top1_max,
            "top_margin_mean": self.top_margin_sum / n,
            "explicit_attack_ratio": self.explicit_attack_count / n,
            "operational_only_ratio": self.operational_only_count / n,
            "routine_maintenance_ratio": self.routine_maintenance_count / n,
            "professional_ratio": self.professional_count / n,
            "professional_anchor_ratio": self.professional_anchor_count / n,
            "professional_sensitive_ratio": self.professional_sensitive_count / n,
            "tail16_event_intensity_mean": self.tail_score_sum / len(self.tail_scores) if self.tail_scores else 0.0,
            "tail16_event_intensity_max": max(self.tail_scores) if self.tail_scores else 0.0,
            "tail16_tagged_ratio": self.tail_tagged_sum / len(self.tail_tagged) if self.tail_tagged else 0.0,
            "tail16_marker_mean": self.tail_marker_count_sum / len(self.tail_marker_counts)
            if self.tail_marker_counts
            else 0.0,
        }
        long_context = math.log1p(n) if n >= 32 else 0.0
        features.update(
            {
                "long_context": long_context,
                "long_context_tagged_ratio": long_context * features["tagged_event_ratio"],
                "long_context_professional_ratio": long_context * features["professional_ratio"],
                "long_context_professional_anchor_ratio": long_context * features["professional_anchor_ratio"],
                "long_context_routine_maintenance_ratio": long_context * features["routine_maintenance_ratio"],
                "long_context_operational_only_ratio": long_context * features["operational_only_ratio"],
                "long_context_explicit_attack_ratio": long_context * features["explicit_attack_ratio"],
            }
        )

        for tag, count in self.tag_counts.items():
            features[f"tag_count_log::{tag}"] = math.log1p(count)
            features[f"tag_ratio::{tag}"] = count / n
            features[f"tag_score_mean::{tag}"] = self.tag_score_sum[tag] / max(count, 1)
            features[f"tag_score_max::{tag}"] = self.tag_score_max.get(tag, 0.0)
        for family, count in self.family_counts.items():
            features[f"family_count_log::{family}"] = math.log1p(count)
            features[f"family_ratio::{family}"] = count / n
            features[f"family_points::{family}"] = self.family_points[family] / n
        for marker, count in self.marker_counts.items():
            features[f"marker_count_log::{marker}"] = math.log1p(count)
            features[f"marker_ratio::{marker}"] = count / n
        for transition, count in self.family_transitions.items():
            features[f"family_transition::{transition}"] = count / transition_denominator
        for transition, count in self.marker_transitions.items():
            features[f"marker_transition::{transition}"] = count / transition_denominator

        features.update(self._chain_features())
        return features

    def _event_intensity_std(self, n: int) -> float:
        mean = self.event_intensity_sum / max(n, 1)
        variance = max(0.0, self.event_intensity_sq_sum / max(n, 1) - mean * mean)
        return math.sqrt(variance)

    @staticmethod
    def _mean(values: Iterable[float | int]) -> float:
        values = list(values)
        return float(sum(values) / len(values)) if values else 0.0

    def _before(self, first_map: dict[str, int], last_map: dict[str, int], left: str, right: str) -> float:
        if left not in first_map or right not in last_map:
            return 0.0
        return 1.0 if first_map[left] < last_map[right] else 0.0

    def _cooccur(self, counter: Counter[str], *names: str) -> float:
        return 1.0 if all(counter.get(name, 0) > 0 for name in names) else 0.0

    def _chain_features(self) -> dict[str, float]:
        return {
            "chain_marker_credential_before_egress": self._before(
                self.first_marker_pos, self.last_marker_pos, "credential_access", "egress"
            ),
            "chain_marker_credential_before_persistence": self._before(
                self.first_marker_pos, self.last_marker_pos, "credential_access", "persistence"
            ),
            "chain_marker_ingress_before_persistence": self._before(
                self.first_marker_pos, self.last_marker_pos, "ingress_execution", "persistence"
            ),
            "chain_marker_identity_and_credential": self._cooccur(
                self.marker_counts, "identity_policy", "credential_access"
            ),
            "chain_marker_recon_before_credential": self._before(
                self.first_marker_pos, self.last_marker_pos, "recon", "credential_access"
            ),
            "chain_marker_remote_before_boundary": self._before(
                self.first_marker_pos, self.last_marker_pos, "remote_access", "boundary_cross"
            ),
            "chain_family_remote_before_privilege": self._before(
                self.first_family_pos, self.last_family_pos, "remote_access", "privilege"
            ),
            "chain_family_network_recon_before_remote": self._before(
                self.first_family_pos, self.last_family_pos, "network_recon", "remote_access"
            ),
            "chain_family_data_movement_before_data_egress": self._before(
                self.first_family_pos, self.last_family_pos, "data_movement", "data_egress"
            ),
            "chain_tag_archive_before_upload": max(
                self._before(self.first_tag_pos, self.last_tag_pos, "create_archive", "upload_external_content"),
                self._before(self.first_tag_pos, self.last_tag_pos, "archive_sensitive_content", "upload_sensitive_content"),
                self._before(self.first_tag_pos, self.last_tag_pos, "read_credential_material", "upload_credential_material"),
            ),
            "chain_tag_download_before_execute": max(
                self._before(self.first_tag_pos, self.last_tag_pos, "download_script", "execute_downloaded_content"),
                self._before(self.first_tag_pos, self.last_tag_pos, "download_executable", "execute_downloaded_content"),
                self._before(self.first_tag_pos, self.last_tag_pos, "download_executable", "write_executable_content"),
            ),
        }


def label_to_int(label: str | None) -> int | None:
    if label == ATTACK_LABEL:
        return 1
    if label == NORMAL_LABEL:
        return 0
    return None


def int_to_label(value: int) -> str:
    return ATTACK_LABEL if int(value) == 1 else NORMAL_LABEL


def top_scores(top_labels: list[dict[str, Any]]) -> tuple[float, float, float]:
    scores = [float(row.get("score") or 0.0) for row in top_labels[:2]]
    top1 = scores[0] if scores else 0.0
    top2 = scores[1] if len(scores) > 1 else 0.0
    return top1, top2, max(0.0, top1 - top2)


def l1_event_from_prediction(
    *,
    top_labels: list[dict[str, Any]],
    policy: dict[str, Any],
) -> L1Event:
    tag_scores = selected_tag_scores_from_top_labels(
        top_labels,
        min_score=float(policy.get("min_tag_score", DEFAULT_MIN_TAG_SCORE)),
        max_tags=int(policy.get("max_tags_per_command", DEFAULT_MAX_TAGS_PER_COMMAND)),
        multi_label_gap=float(policy.get("multi_label_gap", DEFAULT_MULTI_LABEL_GAP)),
    )
    hits = build_tag_hits(tag_scores, policy)
    event_profile = l1_event_feature_profile(hits)
    top1, top2, margin = top_scores(top_labels)
    family_points: Counter[str] = Counter()
    marker_set: set[str] = set()
    for hit in hits:
        family_points[hit.family] += float(hit.points)
        marker_set.update(hit.markers)
    family_set = {hit.family for hit in hits}
    return L1Event(
        selected_tags=tuple(tag for tag, _score in tag_scores),
        top_labels=tuple(dict(row) for row in top_labels),
        tag_scores=tuple(tag_scores),
        families=tuple(sorted(family_set)),
        markers=tuple(sorted(marker_set)),
        family_points=dict(family_points),
        event_intensity=float(event_profile["event_intensity"]),
        top1_score=top1,
        top2_score=top2,
        top_margin=margin,
        explicit_attack=bool(event_profile.get("explicit_attack")),
        operational_only=bool(event_profile.get("operational_only")),
        routine_maintenance_only=bool(event_profile.get("routine_maintenance_only")),
        professional_operation=bool(event_profile.get("professional_operation")),
        professional_anchor=bool(event_profile.get("professional_anchor")),
        professional_sensitive=bool(event_profile.get("professional_sensitive")),
    )


def events_for_input(args: argparse.Namespace) -> Iterator[StreamEvent]:
    input_format = infer_input_format(args.input, args.input_format)
    if input_format == "csv":
        yield from iter_csv_events(
            args.input,
            cmdline_field=args.cmdline_field,
            session_id_fields=args.session_id_fields,
            session_id_separator=args.session_id_separator,
            expected_field=args.expected_field,
            timestamp_field=args.timestamp_field,
            encoding=args.encoding,
            include_raw_row=False,
            limit_rows=args.limit_rows,
            session_shard_count=args.session_shard_count,
            session_shard_index=args.session_shard_index,
        )
        return
    yield from iter_benchmark_events(
        args.input,
        session_id_fields=args.session_id_fields,
        session_id_separator=args.session_id_separator,
        expected_field=args.expected_field or "expected",
        timestamp_field=args.timestamp_field,
        include_raw_row=False,
        limit_rows=args.limit_rows,
        session_shard_count=args.session_shard_count,
        session_shard_index=args.session_shard_index,
    )


def build_prediction_map(args: argparse.Namespace, policy: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if not args.predictions:
        raise SystemExit("--predictions is required; ML L2 consumes cached L1 output")
    return load_prediction_tags(args.predictions)


def add_event_to_state(
    event: StreamEvent,
    *,
    states: dict[str, SessionFeatureState],
    predictions: dict[str, list[dict[str, Any]]],
    policy: dict[str, Any],
    missing_tag_policy: str,
    l1_event_cache: dict[str, L1Event] | None = None,
) -> SessionFeatureState | None:
    prediction = predictions.get(event.command)
    if prediction is None:
        if missing_tag_policy == "skip":
            return None
        if missing_tag_policy == "empty":
            prediction = ([], [])
        else:
            raise KeyError(f"missing L1 prediction for row {event.row_number}")
    l1_event = l1_event_cache.get(event.command) if l1_event_cache is not None else None
    if l1_event is None:
        l1_event = l1_event_from_prediction(top_labels=prediction, policy=policy)
        if l1_event_cache is not None:
            l1_event_cache[event.command] = l1_event
    return add_l1_event_to_state(event, l1_event=l1_event, states=states)


def add_l1_event_to_state(
    event: StreamEvent,
    *,
    l1_event: L1Event,
    states: dict[str, SessionFeatureState],
) -> SessionFeatureState:
    state = states.get(event.session_id)
    if state is None:
        state = SessionFeatureState(session_id=event.session_id, expected=event.expected)
        states[event.session_id] = state
    elif state.expected is None and event.expected is not None:
        state.expected = event.expected
    state.add(l1_event)
    return state


def session_states_from_events(
    events: Iterable[StreamEvent],
    *,
    predictions: dict[str, list[dict[str, Any]]],
    policy: dict[str, Any],
    missing_tag_policy: str,
    l1_event_cache: dict[str, L1Event] | None = None,
) -> dict[str, SessionFeatureState]:
    states: dict[str, SessionFeatureState] = {}
    for event in events:
        add_event_to_state(
            event,
            states=states,
            predictions=predictions,
            policy=policy,
            missing_tag_policy=missing_tag_policy,
            l1_event_cache=l1_event_cache,
        )
    return states


def session_matrix(states: dict[str, SessionFeatureState], *, require_labels: bool) -> tuple[list[str], list[dict[str, float]], list[int]]:
    session_ids: list[str] = []
    features: list[dict[str, float]] = []
    labels: list[int] = []
    for session_id, state in sorted(states.items()):
        label = label_to_int(state.expected)
        if require_labels and label is None:
            continue
        session_ids.append(session_id)
        features.append(state.feature_dict())
        if label is not None:
            labels.append(label)
    return session_ids, features, labels


def train_model(features: list[dict[str, float]], labels: list[int], *, c_value: float, max_iter: int) -> Any:
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    return Pipeline(
        [
            ("vectorizer", DictVectorizer(sparse=True)),
            ("scaler", StandardScaler(with_mean=False)),
            (
                "classifier",
                LogisticRegression(
                    C=c_value,
                    class_weight="balanced",
                    max_iter=max_iter,
                    solver="liblinear",
                    random_state=17,
                ),
            ),
        ]
    ).fit(features, labels)


def effective_cv_folds(labels: list[int], requested_folds: int) -> int:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives < 2 or negatives < 2:
        return 0
    return max(2, min(requested_folds, positives, negatives))


def cross_validated_probabilities(
    features: list[dict[str, float]],
    labels: list[int],
    *,
    folds: int,
    c_value: float,
    max_iter: int,
) -> list[float]:
    from sklearn.model_selection import StratifiedKFold

    split_count = effective_cv_folds(labels, folds)
    if split_count < 2:
        model = train_model(features, labels, c_value=c_value, max_iter=max_iter)
        return [float(value) for value in model.predict_proba(features)[:, 1]]
    probs = [0.0] * len(labels)
    splitter = StratifiedKFold(n_splits=split_count, shuffle=True, random_state=17)
    for train_idx, test_idx in splitter.split(features, labels):
        train_x = [features[idx] for idx in train_idx]
        train_y = [labels[idx] for idx in train_idx]
        test_x = [features[idx] for idx in test_idx]
        model = train_model(train_x, train_y, c_value=c_value, max_iter=max_iter)
        fold_probs = model.predict_proba(test_x)[:, 1]
        for idx, prob in zip(test_idx, fold_probs):
            probs[idx] = float(prob)
    return probs


def metrics_at_threshold(labels: list[int], probs: list[float], threshold: float) -> dict[str, Any]:
    preds = [1 if prob >= threshold else 0 for prob in probs]
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": (tp + tn) / max(len(labels), 1),
        "attack_recall": tp / (tp + fn) if tp + fn else 0.0,
        "normal_recall": tn / (tn + fp) if tn + fp else 0.0,
        "attack_precision": tp / (tp + fp) if tp + fp else 0.0,
        "threshold": threshold,
    }


def clip_probability(value: float) -> float:
    return max(PROBABILITY_EPSILON, min(1.0 - PROBABILITY_EPSILON, float(value)))


def logit(value: float) -> float:
    prob = clip_probability(value)
    return math.log(prob / (1.0 - prob))


def sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def score_threshold_for_transform(model_threshold: float, score_transform: str) -> float:
    if score_transform == SCORE_TRANSFORM_THRESHOLD_MARGIN:
        return 0.5
    return float(model_threshold)


def transform_model_probability(
    model_probability: float,
    *,
    model_threshold: float,
    score_transform: str,
    score_transform_scale: float,
) -> float:
    if score_transform == SCORE_TRANSFORM_RAW:
        return float(model_probability)
    if score_transform != SCORE_TRANSFORM_THRESHOLD_MARGIN:
        raise ValueError(f"unsupported score transform: {score_transform}")
    margin = logit(model_probability) - logit(model_threshold)
    return sigmoid(float(score_transform_scale) * margin)


def transform_model_probabilities(
    model_probabilities: Iterable[float],
    *,
    model_threshold: float,
    score_transform: str,
    score_transform_scale: float,
) -> list[float]:
    return [
        transform_model_probability(
            prob,
            model_threshold=model_threshold,
            score_transform=score_transform,
            score_transform_scale=score_transform_scale,
        )
        for prob in model_probabilities
    ]


@dataclass(frozen=True)
class LinearProbabilityScorer:
    weights: dict[str, float]
    intercept: float
    scalar_weights: dict[str, float] = field(default_factory=dict)
    tag_count_log_weights: dict[str, float] = field(default_factory=dict)
    tag_ratio_weights: dict[str, float] = field(default_factory=dict)
    tag_score_mean_weights: dict[str, float] = field(default_factory=dict)
    tag_score_max_weights: dict[str, float] = field(default_factory=dict)
    family_count_log_weights: dict[str, float] = field(default_factory=dict)
    family_ratio_weights: dict[str, float] = field(default_factory=dict)
    family_points_weights: dict[str, float] = field(default_factory=dict)
    marker_count_log_weights: dict[str, float] = field(default_factory=dict)
    marker_ratio_weights: dict[str, float] = field(default_factory=dict)
    family_transition_weights: dict[str, float] = field(default_factory=dict)
    marker_transition_weights: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_model(cls, model: Any) -> "LinearProbabilityScorer | None":
        try:
            vectorizer = model.named_steps["vectorizer"]
            scaler = model.named_steps["scaler"]
            classifier = model.named_steps["classifier"]
            coefficients = classifier.coef_[0]
            scales = getattr(scaler, "scale_", None)
            vocabulary = dict(vectorizer.vocabulary_)
            intercept = float(classifier.intercept_[0])
        except Exception:
            return None
        weights: dict[str, float] = {}
        for name, index in vocabulary.items():
            scale = 1.0 if scales is None else float(scales[index] or 1.0)
            weights[str(name)] = float(coefficients[index]) / scale
        return cls.from_weights(weights=weights, intercept=intercept)

    @classmethod
    def from_weights(cls, *, weights: dict[str, float], intercept: float) -> "LinearProbabilityScorer":
        scalar_weights: dict[str, float] = {}
        tag_count_log_weights: dict[str, float] = {}
        tag_ratio_weights: dict[str, float] = {}
        tag_score_mean_weights: dict[str, float] = {}
        tag_score_max_weights: dict[str, float] = {}
        family_count_log_weights: dict[str, float] = {}
        family_ratio_weights: dict[str, float] = {}
        family_points_weights: dict[str, float] = {}
        marker_count_log_weights: dict[str, float] = {}
        marker_ratio_weights: dict[str, float] = {}
        family_transition_weights: dict[str, float] = {}
        marker_transition_weights: dict[str, float] = {}
        prefixes = (
            ("tag_count_log::", tag_count_log_weights),
            ("tag_ratio::", tag_ratio_weights),
            ("tag_score_mean::", tag_score_mean_weights),
            ("tag_score_max::", tag_score_max_weights),
            ("family_count_log::", family_count_log_weights),
            ("family_ratio::", family_ratio_weights),
            ("family_points::", family_points_weights),
            ("marker_count_log::", marker_count_log_weights),
            ("marker_ratio::", marker_ratio_weights),
            ("family_transition::", family_transition_weights),
            ("marker_transition::", marker_transition_weights),
        )
        for name, weight in weights.items():
            for prefix, target in prefixes:
                if name.startswith(prefix):
                    target[name[len(prefix) :]] = weight
                    break
            else:
                scalar_weights[name] = weight
        return cls(
            weights=weights,
            intercept=intercept,
            scalar_weights=scalar_weights,
            tag_count_log_weights=tag_count_log_weights,
            tag_ratio_weights=tag_ratio_weights,
            tag_score_mean_weights=tag_score_mean_weights,
            tag_score_max_weights=tag_score_max_weights,
            family_count_log_weights=family_count_log_weights,
            family_ratio_weights=family_ratio_weights,
            family_points_weights=family_points_weights,
            marker_count_log_weights=marker_count_log_weights,
            marker_ratio_weights=marker_ratio_weights,
            family_transition_weights=family_transition_weights,
            marker_transition_weights=marker_transition_weights,
        )

    def probability(self, features: dict[str, float]) -> float:
        logit_value = self.decision_from_features(features)
        return sigmoid(logit_value)

    def state_probability(self, state: SessionFeatureState) -> float:
        logit_value = self.decision_from_state(state)
        return sigmoid(logit_value)

    def decision_from_features(self, features: dict[str, float]) -> float:
        total = self.intercept
        weights = self.weights
        for name, value in features.items():
            weight = weights.get(name)
            if weight:
                total += weight * float(value)
        return total

    def decision_from_state(self, state: SessionFeatureState) -> float:
        scalar = self.scalar_weights
        total = self.intercept
        n = max(state.command_count, 1)
        transition_denominator = max(n - 1, 1)

        total += scalar.get("schema_bias", 0.0)
        total += scalar.get("events", 0.0) * float(n)
        if scalar.get("log_events"):
            total += scalar["log_events"] * math.log1p(n)
        total += scalar.get("tagged_event_ratio", 0.0) * (state.tagged_events / n)
        total += scalar.get("selected_tags_per_event", 0.0) * (state.selected_tag_total / n)
        total += scalar.get("unique_tag_count", 0.0) * float(len(state.tag_counts))
        total += scalar.get("unique_family_count", 0.0) * float(len(state.family_counts))
        total += scalar.get("unique_marker_count", 0.0) * float(len(state.marker_counts))
        total += scalar.get("event_intensity_mean", 0.0) * (state.event_intensity_sum / n)
        total += scalar.get("event_intensity_max", 0.0) * state.event_intensity_max
        total += scalar.get("event_intensity_min", 0.0) * (state.event_intensity_min if state.command_count else 0.0)
        if scalar.get("event_intensity_std"):
            total += scalar["event_intensity_std"] * state._event_intensity_std(n)
        total += scalar.get("event_intensity_over_5_ratio", 0.0) * (state.event_intensity_over_5 / n)
        total += scalar.get("event_intensity_over_6_ratio", 0.0) * (state.event_intensity_over_6 / n)
        total += scalar.get("event_intensity_over_7_ratio", 0.0) * (state.event_intensity_over_7 / n)
        total += scalar.get("top1_score_mean", 0.0) * (state.top1_sum / n)
        total += scalar.get("top1_score_max", 0.0) * state.top1_max
        total += scalar.get("top_margin_mean", 0.0) * (state.top_margin_sum / n)
        total += scalar.get("explicit_attack_ratio", 0.0) * (state.explicit_attack_count / n)
        total += scalar.get("operational_only_ratio", 0.0) * (state.operational_only_count / n)
        total += scalar.get("routine_maintenance_ratio", 0.0) * (state.routine_maintenance_count / n)
        total += scalar.get("professional_ratio", 0.0) * (state.professional_count / n)
        total += scalar.get("professional_anchor_ratio", 0.0) * (state.professional_anchor_count / n)
        total += scalar.get("professional_sensitive_ratio", 0.0) * (state.professional_sensitive_count / n)
        if state.tail_scores:
            total += scalar.get("tail16_event_intensity_mean", 0.0) * float(
                state.tail_score_sum / len(state.tail_scores)
            )
            total += scalar.get("tail16_event_intensity_max", 0.0) * float(max(state.tail_scores))
        total += scalar.get("tail16_tagged_ratio", 0.0) * (
            float(state.tail_tagged_sum / len(state.tail_tagged)) if state.tail_tagged else 0.0
        )
        total += scalar.get("tail16_marker_mean", 0.0) * (
            float(state.tail_marker_count_sum / len(state.tail_marker_counts)) if state.tail_marker_counts else 0.0
        )

        for tag, count in state.tag_counts.items():
            weight = self.tag_count_log_weights.get(tag)
            if weight:
                total += weight * math.log1p(count)
            weight = self.tag_ratio_weights.get(tag)
            if weight:
                total += weight * (count / n)
            weight = self.tag_score_mean_weights.get(tag)
            if weight:
                total += weight * (state.tag_score_sum[tag] / max(count, 1))
            weight = self.tag_score_max_weights.get(tag)
            if weight:
                total += weight * state.tag_score_max.get(tag, 0.0)
        for family, count in state.family_counts.items():
            weight = self.family_count_log_weights.get(family)
            if weight:
                total += weight * math.log1p(count)
            weight = self.family_ratio_weights.get(family)
            if weight:
                total += weight * (count / n)
            weight = self.family_points_weights.get(family)
            if weight:
                total += weight * (state.family_points[family] / n)
        for marker, count in state.marker_counts.items():
            weight = self.marker_count_log_weights.get(marker)
            if weight:
                total += weight * math.log1p(count)
            weight = self.marker_ratio_weights.get(marker)
            if weight:
                total += weight * (count / n)
        for transition, count in state.family_transitions.items():
            weight = self.family_transition_weights.get(transition)
            if weight:
                total += weight * (count / transition_denominator)
        for transition, count in state.marker_transitions.items():
            weight = self.marker_transition_weights.get(transition)
            if weight:
                total += weight * (count / transition_denominator)

        weight = scalar.get("chain_marker_credential_before_egress")
        if weight:
            total += weight * state._before(state.first_marker_pos, state.last_marker_pos, "credential_access", "egress")
        weight = scalar.get("chain_marker_credential_before_persistence")
        if weight:
            total += weight * state._before(
                state.first_marker_pos, state.last_marker_pos, "credential_access", "persistence"
            )
        weight = scalar.get("chain_marker_ingress_before_persistence")
        if weight:
            total += weight * state._before(
                state.first_marker_pos, state.last_marker_pos, "ingress_execution", "persistence"
            )
        weight = scalar.get("chain_marker_identity_and_credential")
        if weight:
            total += weight * state._cooccur(state.marker_counts, "identity_policy", "credential_access")
        weight = scalar.get("chain_marker_recon_before_credential")
        if weight:
            total += weight * state._before(state.first_marker_pos, state.last_marker_pos, "recon", "credential_access")
        weight = scalar.get("chain_marker_remote_before_boundary")
        if weight:
            total += weight * state._before(
                state.first_marker_pos, state.last_marker_pos, "remote_access", "boundary_cross"
            )
        weight = scalar.get("chain_family_remote_before_privilege")
        if weight:
            total += weight * state._before(
                state.first_family_pos, state.last_family_pos, "remote_access", "privilege"
            )
        weight = scalar.get("chain_family_network_recon_before_remote")
        if weight:
            total += weight * state._before(
                state.first_family_pos, state.last_family_pos, "network_recon", "remote_access"
            )
        weight = scalar.get("chain_family_data_movement_before_data_egress")
        if weight:
            total += weight * state._before(
                state.first_family_pos, state.last_family_pos, "data_movement", "data_egress"
            )
        weight = scalar.get("chain_tag_archive_before_upload")
        if weight:
            total += weight * max(
                state._before(state.first_tag_pos, state.last_tag_pos, "create_archive", "upload_external_content"),
                state._before(
                    state.first_tag_pos,
                    state.last_tag_pos,
                    "archive_sensitive_content",
                    "upload_sensitive_content",
                ),
                state._before(
                    state.first_tag_pos,
                    state.last_tag_pos,
                    "read_credential_material",
                    "upload_credential_material",
                ),
            )
        weight = scalar.get("chain_tag_download_before_execute")
        if weight:
            total += weight * max(
                state._before(state.first_tag_pos, state.last_tag_pos, "download_script", "execute_downloaded_content"),
                state._before(
                    state.first_tag_pos,
                    state.last_tag_pos,
                    "download_executable",
                    "execute_downloaded_content",
                ),
                state._before(
                    state.first_tag_pos,
                    state.last_tag_pos,
                    "download_executable",
                    "write_executable_content",
                ),
            )
        return total


def choose_threshold(
    labels: list[int],
    probs: list[float],
    *,
    min_attack_recall: float,
    threshold_floor: float = 0.0,
) -> tuple[float, dict[str, Any]]:
    floor = max(0.0, min(1.0, float(threshold_floor)))
    candidates = sorted(
        threshold
        for threshold in {floor, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, *probs}
        if threshold >= floor
    )
    if not candidates:
        candidates = [floor]
    scored = [(threshold, metrics_at_threshold(labels, probs, threshold)) for threshold in candidates]
    feasible = [item for item in scored if item[1]["attack_recall"] >= min_attack_recall]
    if feasible:
        best = max(
            feasible,
            key=lambda item: (
                item[1]["normal_recall"],
                item[1]["accuracy"],
                item[0],
            ),
        )
    else:
        best = max(
            scored,
            key=lambda item: (
                (item[1]["attack_recall"] + item[1]["normal_recall"]) / 2.0,
                item[1]["accuracy"],
            ),
        )
    return float(best[0]), dict(best[1])


def session_result_rows(
    session_ids: list[str],
    states: dict[str, SessionFeatureState],
    labels: list[int],
    probs: list[float],
    threshold: float,
    *,
    scoring_mode: str,
    model_probs: list[float] | None = None,
    model_threshold: float | None = None,
    score_transform: str = SCORE_TRANSFORM_RAW,
    score_transform_scale: float = 1.0,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    raw_probs = model_probs if model_probs is not None else probs
    effective_model_threshold = threshold if model_threshold is None else model_threshold
    for session_id, expected_int, prob, raw_prob in zip(session_ids, labels, probs, raw_probs):
        pred_int = 1 if prob >= threshold else 0
        state = states[session_id]
        results.append(
            {
                "session_id": session_id,
                "expected": int_to_label(expected_int),
                "session_label": int_to_label(pred_int),
                "match": pred_int == expected_int,
                "command_count": state.command_count,
                "risk_probability": round(prob, 6),
                "risk_score": round(prob * 10.0, 4),
                "threshold": round(threshold, 6),
                "threshold_score": round(threshold * 10.0, 4),
                "model_probability": round(raw_prob, 6),
                "model_score": round(raw_prob * 10.0, 4),
                "model_threshold": round(effective_model_threshold, 6),
                "model_threshold_score": round(effective_model_threshold * 10.0, 4),
                "score_transform": score_transform,
                "score_transform_scale": round(float(score_transform_scale), 6),
                "scoring_mode": scoring_mode,
            }
        )
    return results


def prediction_probability(model: Any, features: dict[str, float]) -> float:
    if isinstance(model, LinearProbabilityScorer):
        return model.probability(features)
    return float(model.predict_proba([features])[:, 1][0])


def state_prediction_probability(model: Any, state: SessionFeatureState) -> float:
    if isinstance(model, LinearProbabilityScorer):
        return model.state_probability(state)
    return prediction_probability(model, state.feature_dict())


def adjust_model_probability_for_semantic_context(state: SessionFeatureState, model_probability: float) -> float:
    if state.command_count < 128:
        return float(model_probability)
    n = max(state.command_count, 1)
    explicit_attack_ratio = state.explicit_attack_count / n
    professional_ratio = state.professional_count / n
    routine_ratio = state.routine_maintenance_count / n
    operational_ratio = state.operational_only_count / n
    has_operational_context = professional_ratio >= 0.15 or routine_ratio >= 0.15 or operational_ratio >= 0.05
    if explicit_attack_ratio <= 0.01 and has_operational_context:
        return min(float(model_probability), 0.85)
    return float(model_probability)


def score_probability_row(
    *,
    session_id: str,
    state: SessionFeatureState,
    prob: float,
    threshold: float,
    scoring_mode: str,
    model_prob: float | None = None,
    model_threshold: float | None = None,
    score_transform: str = SCORE_TRANSFORM_RAW,
    score_transform_scale: float = 1.0,
) -> dict[str, Any]:
    pred_int = 1 if prob >= threshold else 0
    expected_int = label_to_int(state.expected)
    raw_prob = float(prob if model_prob is None else model_prob)
    effective_model_threshold = threshold if model_threshold is None else model_threshold
    return {
        "session_id": session_id,
        "expected": state.expected or "",
        "session_label": int_to_label(pred_int),
        "match": pred_int == expected_int if expected_int is not None else None,
        "command_count": state.command_count,
        "risk_probability": round(prob, 6),
        "risk_score": round(prob * 10.0, 4),
        "threshold": round(threshold, 6),
        "threshold_score": round(threshold * 10.0, 4),
        "model_probability": round(raw_prob, 6),
        "model_score": round(raw_prob * 10.0, 4),
        "model_threshold": round(effective_model_threshold, 6),
        "model_threshold_score": round(effective_model_threshold * 10.0, 4),
        "score_transform": score_transform,
        "score_transform_scale": round(float(score_transform_scale), 6),
        "scoring_mode": scoring_mode,
    }


def should_score_online_window(state: SessionFeatureState, *, min_window_size: int, score_every: int) -> bool:
    min_window = max(1, min_window_size)
    if state.command_count < min_window:
        return False
    return (state.command_count - min_window) % max(1, score_every) == 0


def top_linear_contributions(model: Any, features: dict[str, float], *, limit: int = 12) -> list[dict[str, Any]]:
    try:
        vectorizer = model.named_steps["vectorizer"]
        scaler = model.named_steps["scaler"]
        classifier = model.named_steps["classifier"]
        matrix = scaler.transform(vectorizer.transform([features]))
        row = matrix.tocsr()
        coefs = classifier.coef_[0]
        names = vectorizer.get_feature_names_out()
    except Exception:
        return []
    contributions: list[dict[str, Any]] = []
    for idx, value in zip(row.indices, row.data):
        contribution = float(value) * float(coefs[idx])
        if abs(contribution) < 0.01:
            continue
        contributions.append(
            {
                "feature": str(names[idx]),
                "value": round(float(value), 4),
                "contribution": round(contribution, 4),
            }
        )
    contributions.sort(key=lambda item: abs(float(item["contribution"])), reverse=True)
    return contributions[:limit]


def command_train(args: argparse.Namespace) -> int:
    import joblib
    import sklearn

    started = time.time()
    policy = load_risk_policy(args.risk_policy)
    predictions = build_prediction_map(args, policy)
    l1_event_cache: dict[str, L1Event] = {}
    states = session_states_from_events(
        events_for_input(args),
        predictions=predictions,
        policy=policy,
        missing_tag_policy=args.missing_tag_policy,
        l1_event_cache=l1_event_cache,
    )
    session_ids, features, labels = session_matrix(states, require_labels=True)
    if len(set(labels)) < 2:
        raise SystemExit("training requires both normal and attack sessions")
    oof_probs = cross_validated_probabilities(
        features,
        labels,
        folds=args.folds,
        c_value=args.c_value,
        max_iter=args.max_iter,
    )
    if args.threshold_override is not None:
        model_threshold = float(args.threshold_override)
        threshold_selection = "override"
    else:
        model_threshold, _raw_validation_metrics = choose_threshold(
            labels,
            oof_probs,
            min_attack_recall=args.min_attack_recall,
            threshold_floor=args.threshold_floor,
        )
        threshold_selection = "oof_min_attack_recall"
    score_threshold = score_threshold_for_transform(model_threshold, args.score_transform)
    oof_score_probs = transform_model_probabilities(
        oof_probs,
        model_threshold=model_threshold,
        score_transform=args.score_transform,
        score_transform_scale=args.score_transform_scale,
    )
    validation_metrics = metrics_at_threshold(labels, oof_score_probs, score_threshold)
    raw_validation_metrics = metrics_at_threshold(labels, oof_probs, model_threshold)
    split_count = effective_cv_folds(labels, args.folds)
    validation_mode = "stratified_oof" if split_count >= 2 else "resubstitution_small_class_fallback"
    model = train_model(features, labels, c_value=args.c_value, max_iter=args.max_iter)
    train_probs = [float(value) for value in model.predict_proba(features)[:, 1]]
    train_score_probs = transform_model_probabilities(
        train_probs,
        model_threshold=model_threshold,
        score_transform=args.score_transform,
        score_transform_scale=args.score_transform_scale,
    )
    train_metrics = metrics_at_threshold(labels, train_score_probs, score_threshold)
    raw_train_metrics = metrics_at_threshold(labels, train_probs, model_threshold)
    oof_results = session_result_rows(
        session_ids,
        states,
        labels,
        oof_score_probs,
        score_threshold,
        scoring_mode="rev20_l2_ml_oof",
        model_probs=oof_probs,
        model_threshold=model_threshold,
        score_transform=args.score_transform,
        score_transform_scale=args.score_transform_scale,
    )
    artifact = {
        "schema": SCHEMA,
        "feature_schema": FEATURE_SCHEMA,
        "model_kind": "logistic_regression_l2",
        "model": model,
        "threshold": score_threshold,
        "model_threshold": model_threshold,
        "score_threshold": score_threshold,
        "score_transform": args.score_transform,
        "score_transform_scale": args.score_transform_scale,
        "risk_policy": str(args.risk_policy),
        "risk_policy_id": policy.get("config_id"),
        "training": {
            "input": str(args.input),
            "predictions": str(args.predictions),
            "sessions": len(session_ids),
            "positive_sessions": int(sum(labels)),
            "negative_sessions": int(len(labels) - sum(labels)),
            "folds": split_count,
            "validation_mode": validation_mode,
            "min_attack_recall": args.min_attack_recall,
            "threshold_floor": args.threshold_floor,
            "threshold_override": args.threshold_override,
            "threshold_selection": threshold_selection,
            "model_threshold": model_threshold,
            "score_threshold": score_threshold,
            "score_transform": args.score_transform,
            "score_transform_scale": args.score_transform_scale,
            "validation_metrics_oof": validation_metrics,
            "validation_metrics_oof_model_probability": raw_validation_metrics,
            "train_metrics_resubstitution": train_metrics,
            "train_metrics_resubstitution_model_probability": raw_train_metrics,
            "oof_results": str(args.oof_results_out) if args.oof_results_out else None,
            "runtime_seconds": round(time.time() - started, 3),
            "sklearn_version": sklearn.__version__,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, args.output)
    summary = {
        "schema": SCHEMA,
        "model": str(args.output),
        "threshold": score_threshold,
        "model_threshold": model_threshold,
        "score_threshold": score_threshold,
        "score_transform": args.score_transform,
        "score_transform_scale": args.score_transform_scale,
        **artifact["training"],
    }
    if args.summary_out:
        write_json(args.summary_out, summary)
    if args.oof_results_out:
        write_json(
            args.oof_results_out,
            {
                "schema": "agentsmith_rev20_l2_ml_oof_results_v1",
                "summary": {
                    "sessions": len(oof_results),
                    "scoring_engine": "rev20_l2_ml",
                    "validation_mode": validation_mode,
                    **validation_metrics,
                    "model_threshold": model_threshold,
                    "score_transform": args.score_transform,
                    "score_transform_scale": args.score_transform_scale,
                },
                "config": {
                    "input": str(args.input),
                    "predictions": str(args.predictions),
                    "risk_policy": str(args.risk_policy),
                    "feature_schema": FEATURE_SCHEMA,
                    "raw_command_features": False,
                },
                "results": oof_results,
            },
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def load_artifact(path: Path) -> dict[str, Any]:
    import joblib

    payload = joblib.load(path)
    if payload.get("schema") != SCHEMA:
        raise SystemExit(f"unsupported ML L2 artifact schema: {payload.get('schema')}")
    return payload


def command_score(args: argparse.Namespace) -> int:
    started = time.time()
    artifact = load_artifact(args.model)
    model = artifact["model"]
    scoring_model = LinearProbabilityScorer.from_model(model) or model
    score_transform = str(artifact.get("score_transform") or SCORE_TRANSFORM_RAW)
    score_transform_scale = float(artifact.get("score_transform_scale") or 1.0)
    if score_transform not in SCORE_TRANSFORMS:
        raise SystemExit(f"unsupported score transform in artifact: {score_transform}")
    if score_transform_scale <= 0:
        raise SystemExit(f"invalid score transform scale in artifact: {score_transform_scale}")
    model_threshold = float(artifact.get("model_threshold", artifact.get("threshold", 0.5)))
    threshold = float(args.threshold if args.threshold is not None else artifact.get("score_threshold", artifact["threshold"]))
    policy = load_risk_policy(args.risk_policy)
    predictions = build_prediction_map(args, policy)
    l1_event_cache: dict[str, L1Event] = {}
    states: dict[str, SessionFeatureState] = {}
    online_window_records = 0
    online_attack_windows = 0
    if args.online_windows_out:
        args.online_windows_out.parent.mkdir(parents=True, exist_ok=True)
    online_handle = args.online_windows_out.open("w", encoding="utf-8") if args.online_windows_out else None
    try:
        for event in events_for_input(args):
            state = add_event_to_state(
                event,
                states=states,
                predictions=predictions,
                policy=policy,
                missing_tag_policy=args.missing_tag_policy,
                l1_event_cache=l1_event_cache,
            )
            if state is None:
                continue
            if online_handle and should_score_online_window(
                state,
                min_window_size=args.min_window_size,
                score_every=args.score_every,
            ):
                model_prob = state_prediction_probability(scoring_model, state)
                model_prob = adjust_model_probability_for_semantic_context(state, model_prob)
                prob = transform_model_probability(
                    model_prob,
                    model_threshold=model_threshold,
                    score_transform=score_transform,
                    score_transform_scale=score_transform_scale,
                )
                window = score_probability_row(
                    session_id=state.session_id,
                    state=state,
                    prob=prob,
                    threshold=threshold,
                    scoring_mode="rev20_l2_ml_online",
                    model_prob=model_prob,
                    model_threshold=model_threshold,
                    score_transform=score_transform,
                    score_transform_scale=score_transform_scale,
                )
                window["row_number"] = event.row_number
                if args.explain:
                    feature_dict = state.feature_dict()
                    window["top_feature_contributions"] = top_linear_contributions(model, feature_dict, limit=8)
                online_handle.write(json.dumps(window, ensure_ascii=False, sort_keys=True) + "\n")
                online_window_records += 1
                online_attack_windows += int(window["session_label"] == ATTACK_LABEL)
    finally:
        if online_handle:
            online_handle.close()

    session_items = sorted(states.items())
    results: list[dict[str, Any]] = []
    attack_sessions = 0
    session_alert_records = 0
    known_y_true: list[int] = []
    known_y_prob: list[float] = []
    if args.alerts_out:
        args.alerts_out.parent.mkdir(parents=True, exist_ok=True)
    alert_handle = args.alerts_out.open("w", encoding="utf-8") if args.alerts_out else None
    try:
        for session_id, state in session_items:
            feature_dict = state.feature_dict() if args.explain else None
            model_prob = (
                prediction_probability(scoring_model, feature_dict)
                if feature_dict is not None
                else state_prediction_probability(scoring_model, state)
            )
            model_prob = adjust_model_probability_for_semantic_context(state, model_prob)
            prob = transform_model_probability(
                model_prob,
                model_threshold=model_threshold,
                score_transform=score_transform,
                score_transform_scale=score_transform_scale,
            )
            result = score_probability_row(
                session_id=session_id,
                state=state,
                prob=prob,
                threshold=threshold,
                scoring_mode="rev20_l2_ml_final",
                model_prob=model_prob,
                model_threshold=model_threshold,
                score_transform=score_transform,
                score_transform_scale=score_transform_scale,
            )
            if feature_dict is not None and not args.no_session_results:
                result["top_feature_contributions"] = top_linear_contributions(model, feature_dict)
            expected_int = label_to_int(result["expected"])
            if expected_int is not None:
                known_y_true.append(expected_int)
                known_y_prob.append(float(result["risk_probability"]))
            if result["session_label"] == ATTACK_LABEL:
                attack_sessions += 1
                session_alert_records += 1
                if alert_handle:
                    alert = {
                        "schema": "agentsmith_rev20_l2_ml_alert_v1",
                        "alert_type": "rev20_l2_ml_session_risk",
                        "session_id": session_id,
                        "risk_probability": round(prob, 6),
                        "risk_score": round(prob * 10.0, 4),
                        "threshold": round(threshold, 6),
                        "threshold_score": round(threshold * 10.0, 4),
                        "model_probability": round(model_prob, 6),
                        "model_score": round(model_prob * 10.0, 4),
                        "model_threshold": round(model_threshold, 6),
                        "model_threshold_score": round(model_threshold * 10.0, 4),
                        "score_transform": score_transform,
                        "score_transform_scale": round(score_transform_scale, 6),
                        "command_count": state.command_count,
                        "expected": state.expected,
                        "top_feature_contributions": top_linear_contributions(model, feature_dict, limit=8)
                        if feature_dict is not None
                        else [],
                    }
                    alert_handle.write(json.dumps(alert, ensure_ascii=False, sort_keys=True) + "\n")
            if not args.no_session_results:
                results.append(result)
    finally:
        if alert_handle:
            alert_handle.close()
    if known_y_true:
        y_true = known_y_true
        y_prob = known_y_prob
        summary_metrics = metrics_at_threshold(y_true, y_prob, threshold)
    else:
        summary_metrics = {
            "tp": 0,
            "tn": 0,
            "fp": 0,
            "fn": 0,
            "accuracy": None,
            "attack_recall": None,
            "normal_recall": None,
            "attack_precision": None,
            "threshold": threshold,
        }
    summary = {
        "schema": "agentsmith_rev20_l2_ml_results_v1",
        "sessions": len(session_items),
        "attack_sessions": attack_sessions,
        "session_alert_records": session_alert_records,
        "online_window_records": online_window_records,
        "online_attack_windows": online_attack_windows,
        "rows_seen": sum(state.command_count for state in states.values()),
        "runtime_seconds": round(time.time() - started, 3),
        "rows_per_second": sum(state.command_count for state in states.values()) / max(time.time() - started, 1e-9),
        "scoring_engine": "rev20_l2_ml",
        "model": str(args.model),
        "predictions": str(args.predictions),
        "threshold": threshold,
        "threshold_score": threshold * 10.0,
        "model_threshold": model_threshold,
        "model_threshold_score": model_threshold * 10.0,
        "score_transform": score_transform,
        "score_transform_scale": score_transform_scale,
        **summary_metrics,
    }
    payload: dict[str, Any] = {
        "schema": "agentsmith_rev20_l2_ml_results_v1",
        "summary": summary,
        "config": {
            "input": str(args.input),
            "input_format": infer_input_format(args.input, args.input_format),
            "model": str(args.model),
            "predictions": str(args.predictions),
            "risk_policy": str(args.risk_policy),
            "missing_tag_policy": args.missing_tag_policy,
            "feature_schema": FEATURE_SCHEMA,
            "raw_command_features": False,
            "model_threshold": model_threshold,
            "score_threshold": threshold,
            "score_transform": score_transform,
            "score_transform_scale": score_transform_scale,
            "online_windows_out": str(args.online_windows_out) if args.online_windows_out else None,
            "min_window_size": args.min_window_size,
            "score_every": args.score_every,
        },
    }
    if not args.no_session_results:
        payload["results"] = results
    write_json(args.output, payload)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_benchmark_memory(args: argparse.Namespace) -> int:
    artifact = load_artifact(args.model)
    model = artifact["model"]
    scoring_model = LinearProbabilityScorer.from_model(model) or model
    score_transform = str(artifact.get("score_transform") or SCORE_TRANSFORM_RAW)
    score_transform_scale = float(artifact.get("score_transform_scale") or 1.0)
    if score_transform not in SCORE_TRANSFORMS:
        raise SystemExit(f"unsupported score transform in artifact: {score_transform}")
    model_threshold = float(artifact.get("model_threshold", artifact.get("threshold", 0.5)))
    threshold = float(args.threshold if args.threshold is not None else artifact.get("score_threshold", artifact["threshold"]))
    policy = load_risk_policy(args.risk_policy)
    predictions = build_prediction_map(args, policy)
    events = list(events_for_input(args))
    if args.max_events is not None:
        events = events[: args.max_events]

    warm_cache: dict[str, L1Event] = {}
    if args.warm_l1_event_cache:
        for command in {event.command for event in events}:
            prediction = predictions.get(command)
            if prediction is None:
                if args.missing_tag_policy == "error":
                    raise KeyError(f"missing L1 prediction for command in benchmark cache warmup")
                continue
            warm_cache[command] = l1_event_from_prediction(
                top_labels=prediction,
                policy=policy,
            )
    resolved_events: list[tuple[str, str | None, L1Event]] | None = None
    if args.pre_resolve_events:
        resolved_events = []
        for event in events:
            l1_event = warm_cache.get(event.command)
            if l1_event is None:
                prediction = predictions.get(event.command)
                if prediction is None:
                    if args.missing_tag_policy == "error":
                        raise KeyError("missing L1 prediction for command in benchmark pre-resolve")
                    continue
                l1_event = l1_event_from_prediction(
                    top_labels=prediction,
                    policy=policy,
                )
                warm_cache[event.command] = l1_event
            resolved_events.append((event.session_id, event.expected, l1_event))

    runs: list[dict[str, Any]] = []
    repeat_count = max(1, int(args.repeat))
    for repeat_index in range(repeat_count):
        states: dict[str, SessionFeatureState] = {}
        l1_event_cache = dict(warm_cache) if args.warm_l1_event_cache else {}
        online_window_records = 0
        online_attack_windows = 0
        final_attack_sessions = 0
        skipped_events = 0
        started = time.perf_counter()
        if resolved_events is not None:
            for session_id, expected, l1_event in resolved_events:
                state = states.get(session_id)
                if state is None:
                    state = SessionFeatureState(session_id=session_id, expected=expected)
                    states[session_id] = state
                elif state.expected is None and expected is not None:
                    state.expected = expected
                state.add(l1_event)
                if args.online_windows and should_score_online_window(
                    state,
                    min_window_size=args.min_window_size,
                    score_every=args.score_every,
                ):
                    model_prob = state_prediction_probability(scoring_model, state)
                    prob = transform_model_probability(
                        model_prob,
                        model_threshold=model_threshold,
                        score_transform=score_transform,
                        score_transform_scale=score_transform_scale,
                    )
                    online_window_records += 1
                    online_attack_windows += int(prob >= threshold)
        else:
            for event in events:
                try:
                    state = add_event_to_state(
                        event,
                        states=states,
                        predictions=predictions,
                        policy=policy,
                        missing_tag_policy=args.missing_tag_policy,
                        l1_event_cache=l1_event_cache,
                    )
                except KeyError:
                    if args.missing_tag_policy == "error":
                        raise
                    state = None
                if state is None:
                    skipped_events += 1
                    continue
                if args.online_windows and should_score_online_window(
                    state,
                    min_window_size=args.min_window_size,
                    score_every=args.score_every,
                ):
                    model_prob = state_prediction_probability(scoring_model, state)
                    prob = transform_model_probability(
                        model_prob,
                        model_threshold=model_threshold,
                        score_transform=score_transform,
                        score_transform_scale=score_transform_scale,
                    )
                    online_window_records += 1
                    online_attack_windows += int(prob >= threshold)
        if args.score_final:
            for _session_id, state in states.items():
                model_prob = state_prediction_probability(scoring_model, state)
                prob = transform_model_probability(
                    model_prob,
                    model_threshold=model_threshold,
                    score_transform=score_transform,
                    score_transform_scale=score_transform_scale,
                )
                final_attack_sessions += int(prob >= threshold)
        elapsed = time.perf_counter() - started
        processed_events = len(resolved_events) if resolved_events is not None else len(events) - skipped_events
        runs.append(
            {
                "repeat": repeat_index + 1,
                "events": len(events),
                "processed_events": processed_events,
                "skipped_events": skipped_events,
                "sessions": len(states),
                "online_window_records": online_window_records,
                "online_attack_windows": online_attack_windows,
                "final_attack_sessions": final_attack_sessions if args.score_final else None,
                "l1_event_cache_entries": len(l1_event_cache),
                "seconds": elapsed,
                "tps": processed_events / max(elapsed, 1e-9),
            }
        )

    tps_values = [float(run["tps"]) for run in runs]
    summary = {
        "schema": "agentsmith_rev20_l2_ml_memory_benchmark_v1",
        "events": len(events),
        "repeat": repeat_count,
        "best_tps": max(tps_values) if tps_values else 0.0,
        "mean_tps": sum(tps_values) / len(tps_values) if tps_values else 0.0,
        "online_windows": bool(args.online_windows),
        "score_final": bool(args.score_final),
        "warm_l1_event_cache": bool(args.warm_l1_event_cache),
        "pre_resolve_events": bool(args.pre_resolve_events),
        "min_window_size": args.min_window_size,
        "score_every": args.score_every,
        "model": str(args.model),
        "predictions": str(args.predictions),
        "input": str(args.input),
        "scoring_engine": "rev20_l2_ml",
        "scoring_model": "compiled_linear" if isinstance(scoring_model, LinearProbabilityScorer) else "sklearn_pipeline",
        "score_transform": score_transform,
        "score_transform_scale": score_transform_scale,
        "threshold": threshold,
        "model_threshold": model_threshold,
        "runs": runs,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def add_common_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-format", choices=["auto", "benchmark_jsonl", "csv"], default="auto")
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--risk-policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--missing-tag-policy", choices=["error", "skip", "empty"], default="error")
    parser.add_argument("--cmdline-field", default="cmdline")
    parser.add_argument("--session-id-field", dest="session_id_fields", action="append", default=None)
    parser.add_argument("--session-id-fields", dest="session_id_fields_csv", default=None)
    parser.add_argument("--session-id-separator", default="|")
    parser.add_argument("--expected-field", default="expected")
    parser.add_argument("--timestamp-field", default=None)
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--limit-rows", type=int, default=None)
    parser.add_argument("--session-shard-count", type=int, default=1)
    parser.add_argument("--session-shard-index", type=int, default=0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    train = subparsers.add_parser("train", help="Train ML L2 from labeled sessions and cached L1 predictions")
    add_common_input_args(train)
    train.add_argument("--output", type=Path, default=DEFAULT_MODEL_OUT)
    train.add_argument("--summary-out", type=Path, default=None)
    train.add_argument("--oof-results-out", type=Path, default=None)
    train.add_argument("--folds", type=int, default=5)
    train.add_argument("--c-value", type=float, default=0.5)
    train.add_argument("--max-iter", type=int, default=2000)
    train.add_argument("--min-attack-recall", type=float, default=0.98)
    train.add_argument(
        "--threshold-floor",
        type=float,
        default=0.0,
        help="Lowest deployable threshold considered when auto-selecting from OOF probabilities.",
    )
    train.add_argument(
        "--threshold-override",
        type=float,
        default=None,
        help="Persist this deploy threshold while still reporting OOF metrics at that threshold.",
    )
    train.add_argument(
        "--score-transform",
        choices=sorted(SCORE_TRANSFORMS),
        default=SCORE_TRANSFORM_RAW,
        help=(
            "Transform model probabilities before emitting risk_probability. "
            "threshold_margin centers the output score at the selected model threshold."
        ),
    )
    train.add_argument(
        "--score-transform-scale",
        type=float,
        default=1.0,
        help="Positive scale for threshold_margin probability separation.",
    )
    train.set_defaults(func=command_train)

    score = subparsers.add_parser("score", help="Score sessions with a saved ML L2 model")
    add_common_input_args(score)
    score.add_argument("--model", type=Path, required=True)
    score.add_argument("--output", type=Path, default=DEFAULT_RESULTS_OUT)
    score.add_argument("--alerts-out", type=Path, default=None)
    score.add_argument("--online-windows-out", type=Path, default=None)
    score.add_argument("--min-window-size", type=int, default=8)
    score.add_argument("--score-every", type=int, default=4)
    score.add_argument("--threshold", type=float, default=None)
    score.add_argument("--explain", action=argparse.BooleanOptionalAction, default=True)
    score.add_argument("--no-session-results", action="store_true")
    score.set_defaults(func=command_score)

    benchmark = subparsers.add_parser(
        "benchmark-memory",
        help="Benchmark pure in-memory ML L2 aggregation and scoring without L1 or input I/O timing.",
    )
    add_common_input_args(benchmark)
    benchmark.add_argument("--model", type=Path, required=True)
    benchmark.add_argument("--max-events", type=int, default=None)
    benchmark.add_argument("--repeat", type=int, default=3)
    benchmark.add_argument("--online-windows", action=argparse.BooleanOptionalAction, default=True)
    benchmark.add_argument("--score-final", action=argparse.BooleanOptionalAction, default=False)
    benchmark.add_argument("--warm-l1-event-cache", action=argparse.BooleanOptionalAction, default=True)
    benchmark.add_argument("--pre-resolve-events", action=argparse.BooleanOptionalAction, default=True)
    benchmark.add_argument("--min-window-size", type=int, default=8)
    benchmark.add_argument("--score-every", type=int, default=4)
    benchmark.add_argument("--threshold", type=float, default=None)
    benchmark.set_defaults(func=command_benchmark_memory)

    args = parser.parse_args()
    args.session_id_fields = parse_session_fields(args)
    if args.session_shard_count < 1:
        raise SystemExit("--session-shard-count must be >= 1")
    if args.session_shard_index < 0 or args.session_shard_index >= args.session_shard_count:
        raise SystemExit("--session-shard-index must be in [0, session_shard_count)")
    if hasattr(args, "threshold_floor") and not (0.0 <= args.threshold_floor <= 1.0):
        raise SystemExit("--threshold-floor must be in [0, 1]")
    if getattr(args, "threshold_override", None) is not None and not (0.0 <= args.threshold_override <= 1.0):
        raise SystemExit("--threshold-override must be in [0, 1]")
    if getattr(args, "score_transform_scale", 1.0) <= 0:
        raise SystemExit("--score-transform-scale must be > 0")
    if getattr(args, "min_window_size", 1) < 1:
        raise SystemExit("--min-window-size must be >= 1")
    if getattr(args, "score_every", 1) < 1:
        raise SystemExit("--score-every must be >= 1")
    if getattr(args, "repeat", 1) < 1:
        raise SystemExit("--repeat must be >= 1")
    if getattr(args, "max_events", None) is not None and args.max_events < 1:
        raise SystemExit("--max-events must be >= 1")
    return args


def main() -> int:
    args = parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
