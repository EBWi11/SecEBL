#!/usr/bin/env python3
"""Shared L1-semantic feature helpers for the rev20 ML L2 scorer.

This module does not make session verdicts. It converts cached L1 top-label
outputs into tag/family/marker feature signals consumed by ``rev20_l2_ml.py``.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stream_risk_common import prediction_command
from v4_tags_embedding_retrieval import (
    DEFAULT_MAX_TAGS_PER_COMMAND,
    DEFAULT_MIN_TAG_SCORE,
    DEFAULT_MULTI_LABEL_GAP,
    select_top_labels,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE_POLICY = Path(__file__).resolve().parent / "tag_risk_policy.rev20.json"


@dataclass(frozen=True)
class TagHit:
    tag_id: str
    score: float
    family: str
    points: float
    markers: tuple[str, ...] = ()
    benign: bool = False
    operational: bool = False
    explicit_attack: bool = False
    routine_maintenance: bool = False
    professional_operation: bool = False
    professional_anchor: bool = False
    professional_sensitive: bool = False


def iter_jsonl(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc


def load_risk_policy(path: Path) -> dict[str, Any]:
    """Load the tag profile policy used for ML L2 feature extraction."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    label_to_group: dict[str, str] = {}
    schema_path = ROOT / "tags_schema_rev20.json"
    if not schema_path.exists():
        schema_path = Path(__file__).resolve().parent / "tags_schema_rev20.json"
    if schema_path.exists():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        for group, labels in dict(schema.get("groups") or {}).items():
            for label in labels:
                label_to_group[str(label)] = str(group)
    routine_cfg = dict(payload.get("scoring_routine_maintenance") or {})
    professional_cfg = dict(payload.get("scoring_professional_operations") or {})
    return {
        **payload,
        "label_to_group": label_to_group,
        "scoring_routine_maintenance_tags": set(routine_cfg.get("tags") or []),
        "scoring_routine_maintenance_cfg": routine_cfg,
        "scoring_professional_operation_tags": set(professional_cfg.get("tags") or []),
        "scoring_professional_anchor_tags": set(professional_cfg.get("anchor_tags") or []),
        "scoring_professional_sensitive_tags": set(professional_cfg.get("sensitive_tags") or []),
    }


def is_scoring_routine_maintenance_tag(tag_id: str, profile: dict[str, Any], policy: dict[str, Any]) -> bool:
    if tag_id not in policy.get("scoring_routine_maintenance_tags", set()):
        return False
    if profile.get("explicit_attack"):
        return False
    if profile.get("markers"):
        return False
    return True


def professional_flags(tag_id: str, profile: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, bool, bool]:
    anchor = bool(profile.get("professional_anchor")) or tag_id in policy.get("scoring_professional_anchor_tags", set())
    sensitive = bool(profile.get("professional_sensitive")) or tag_id in policy.get(
        "scoring_professional_sensitive_tags", set()
    )
    operation = (
        bool(profile.get("professional_operation"))
        or tag_id in policy.get("scoring_professional_operation_tags", set())
        or anchor
        or sensitive
    )
    return operation, anchor, sensitive


def tag_profile(tag_id: str, policy: dict[str, Any]) -> dict[str, Any]:
    overrides = dict(policy.get("tag_overrides") or {})
    if tag_id in overrides:
        profile = dict(overrides[tag_id])
    else:
        group = policy["label_to_group"].get(tag_id, "unknown")
        defaults = dict((policy.get("group_defaults") or {}).get(group) or {"base_points": 0.5, "family": "generic"})
        profile = {
            "points": float(defaults.get("base_points", 0.5)),
            "family": str(defaults.get("family", "generic")),
        }
    profile.setdefault("points", 0.0)
    profile.setdefault("family", "generic")
    profile["markers"] = list(profile.get("markers") or [])
    return profile


def retrieval_weight(score: float) -> float:
    return max(0.35, min(1.0, (float(score) - 0.20) / 0.60))


def selected_tag_scores_from_top_labels(
    top_labels: list[dict[str, Any]],
    *,
    min_score: float,
    max_tags: int,
    multi_label_gap: float = DEFAULT_MULTI_LABEL_GAP,
) -> list[tuple[str, float]]:
    hits: list[tuple[str, float]] = []
    for item in select_top_labels(
        top_labels,
        min_score=min_score,
        max_tags=max_tags,
        multi_label_gap=multi_label_gap,
    ):
        tag_id = str(item.get("label_id") or "").strip()
        if not tag_id:
            continue
        score = float(item.get("score") or 0.0)
        hits.append((tag_id, score))
    return hits


def build_tag_hits(tag_scores: list[tuple[str, float]], policy: dict[str, Any]) -> list[TagHit]:
    hits: list[TagHit] = []
    for tag_id, score in tag_scores:
        profile = tag_profile(tag_id, policy)
        points = float(profile["points"]) * retrieval_weight(score)
        professional_operation, professional_anchor, professional_sensitive = professional_flags(tag_id, profile, policy)
        hits.append(
            TagHit(
                tag_id=tag_id,
                score=score,
                family=str(profile["family"]),
                points=points,
                markers=tuple(str(marker) for marker in profile.get("markers") or []),
                benign=bool(profile.get("benign")),
                operational=bool(profile.get("operational")),
                explicit_attack=bool(profile.get("explicit_attack")),
                routine_maintenance=is_scoring_routine_maintenance_tag(tag_id, profile, policy),
                professional_operation=professional_operation,
                professional_anchor=professional_anchor,
                professional_sensitive=professional_sensitive,
            )
        )
    return hits


def l1_event_feature_profile(tag_hits: list[TagHit]) -> dict[str, Any]:
    """Return per-command semantic feature signals for ML L2.

    ``event_intensity`` is a continuous feature summarizing selected L1 evidence;
    it is not used to emit an L2 verdict.
    """

    raw_intensity = 4.0
    family_scores: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()
    for hit in tag_hits:
        raw_intensity += hit.points
        family_scores[hit.family] += max(hit.points, 0.0)
        for marker in hit.markers:
            marker_counts[marker] += 1.0

    benign_count = sum(1 for hit in tag_hits if hit.benign or hit.operational)
    routine_maintenance_only = bool(tag_hits) and all(hit.routine_maintenance for hit in tag_hits)
    operational_only = bool(tag_hits) and all(hit.operational or hit.benign for hit in tag_hits)
    professional_operation = any(hit.professional_operation for hit in tag_hits)
    professional_anchor = any(hit.professional_anchor for hit in tag_hits)
    professional_sensitive = any(hit.professional_sensitive for hit in tag_hits)

    return {
        "event_intensity": max(0.0, min(raw_intensity, 10.0)),
        "families": dict(family_scores),
        "markers": dict(marker_counts),
        "explicit_attack": any(hit.explicit_attack for hit in tag_hits),
        "operational_only": operational_only,
        "routine_maintenance_only": routine_maintenance_only,
        "professional_operation": professional_operation,
        "professional_anchor": professional_anchor,
        "professional_sensitive": professional_sensitive,
        "benign_ratio": benign_count / max(len(tag_hits), 1),
    }


def load_prediction_tags(path: Path) -> dict[str, list[dict[str, Any]]]:
    tags_by_command: dict[str, list[dict[str, Any]]] = {}
    for row in iter_jsonl(path):
        command = prediction_command(row)
        if not command:
            continue
        top_labels = row.get("top_labels")
        if not isinstance(top_labels, list):
            continue
        tags_by_command[command] = list(top_labels)
    return tags_by_command
