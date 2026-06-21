"""Shared flat label retrieval helpers for rev20 tag embedding models."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
from typing import Any

import numpy as np

DEFAULT_MIN_TAG_SCORE = 0.55
DEFAULT_GLOBAL_SCORE_FLOOR = 0.45
DEFAULT_MAX_TAGS_PER_COMMAND = 4
DEFAULT_MULTI_LABEL_GAP = 0.12
DEFAULT_SCORE_CALIBRATION = Path(__file__).resolve().parents[1] / "model_artifacts/score_calibration.rev20.json"


def label_axis(label_id: str) -> str:
    return label_id.split(":", 1)[0]


def rank_labels(
    scores: np.ndarray,
    label_ids: list[str],
    *,
    top_k: int = 5,
) -> list[tuple[str, float]]:
    ranked_indices = np.argsort(-scores)[:top_k]
    return [(label_ids[item], float(scores[item])) for item in ranked_indices]


def load_score_calibration(path: str | Path | None) -> dict | None:
    if path is None:
        candidate = DEFAULT_SCORE_CALIBRATION
        path = candidate if candidate.exists() else None
    if not path:
        return None
    path = Path(path)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def calibration_path_for_model(model_path: str | Path | None) -> Path | None:
    if not model_path:
        return None
    model_path = Path(model_path)
    model_root = model_path.parent if model_path.name == "model" else model_path
    candidate = model_root / "score_calibration.rev20.json"
    return candidate if candidate.exists() else None


def score_threshold_for_label(
    label_id: str,
    *,
    axis: str | None = None,
    calibration: dict[str, Any] | None = None,
    global_floor: float = DEFAULT_MIN_TAG_SCORE,
) -> float:
    if not calibration:
        return global_floor
    axis = axis or label_axis(label_id)
    label_thresholds = calibration.get("label_thresholds") or {}
    axis_thresholds = calibration.get("axis_thresholds") or {}
    default_threshold = float(calibration.get("default_threshold", global_floor))
    floor = float(calibration.get("global_floor", global_floor))
    label_entry = label_thresholds.get(label_id) or {}
    threshold = label_entry.get("threshold")
    if threshold is None:
        axis_entry = axis_thresholds.get(axis) or {}
        threshold = axis_entry.get("threshold", default_threshold)
    return max(floor, float(threshold))


def _passes_label_threshold(
    item: dict[str, Any],
    *,
    calibration: dict[str, Any] | None,
    global_floor: float,
) -> bool:
    label_id = str(item.get("label_id") or "")
    if not label_id:
        return False
    axis = str(item.get("axis") or label_axis(label_id))
    score = float(item.get("score") or 0.0)
    threshold = score_threshold_for_label(
        label_id,
        axis=axis,
        calibration=calibration,
        global_floor=global_floor,
    )
    return score >= threshold


def calibrated_top_labels(
    top_labels: list[dict],
    calibration: dict | None,
) -> list[dict]:
    if not calibration:
        return top_labels
    global_floor = float(calibration.get("global_floor", DEFAULT_MIN_TAG_SCORE))
    min_keep_per_axis = {
        str(axis): int(value)
        for axis, value in (calibration.get("min_keep_per_axis") or {}).items()
    }
    kept = [
        item
        for item in sorted(top_labels, key=lambda row: -float(row.get("score") or 0.0))
        if _passes_label_threshold(item, calibration=calibration, global_floor=global_floor)
    ]
    if not min_keep_per_axis:
        return kept

    kept_by_axis: dict[str, int] = defaultdict(int)
    for item in kept:
        axis = str(item.get("axis") or label_axis(str(item.get("label_id", ""))))
        kept_by_axis[axis] += 1
    existing = {str(item.get("label_id")) for item in kept}
    all_by_axis: dict[str, list[dict]] = defaultdict(list)
    for item in top_labels:
        axis = str(item.get("axis") or label_axis(str(item.get("label_id", ""))))
        all_by_axis[axis].append(item)
    for axis, minimum in min_keep_per_axis.items():
        if kept_by_axis.get(axis, 0) >= minimum:
            continue
        for item in sorted(all_by_axis.get(axis, []), key=lambda row: -float(row.get("score") or 0.0)):
            if kept_by_axis.get(axis, 0) >= minimum:
                break
            label_id = str(item.get("label_id"))
            if label_id in existing:
                continue
            kept.append(item)
            existing.add(label_id)
            kept_by_axis[axis] += 1
    kept.sort(key=lambda item: -float(item.get("score", 0.0)))
    return kept


def _select_balanced_gap(
    ranked: list[dict],
    *,
    global_floor: float,
    max_tags: int,
    multi_label_gap: float,
    calibration: dict[str, Any] | None = None,
) -> list[dict]:
    if not ranked or max_tags <= 0:
        return []
    if not _passes_label_threshold(ranked[0], calibration=calibration, global_floor=global_floor):
        return []
    selected = [ranked[0]]
    top_score = float(ranked[0].get("score") or 0.0)
    for item in ranked[1:]:
        score = float(item.get("score") or 0.0)
        if top_score - score > multi_label_gap:
            break
        if not _passes_label_threshold(
            item,
            calibration=calibration,
            global_floor=global_floor,
        ):
            continue
        selected.append(item)
        if len(selected) >= max_tags:
            break
    return selected


def select_top_labels(
    top_labels: list[dict],
    *,
    min_score: float = DEFAULT_MIN_TAG_SCORE,
    max_tags: int = DEFAULT_MAX_TAGS_PER_COMMAND,
    multi_label_gap: float = DEFAULT_MULTI_LABEL_GAP,
    calibration: dict[str, Any] | None = None,
) -> list[dict]:
    ranked = sorted(top_labels, key=lambda item: -float(item.get("score") or 0.0))
    if not ranked:
        return []
    global_floor = float((calibration or {}).get("global_floor", min_score)) if calibration else min_score
    return _select_balanced_gap(
        ranked,
        global_floor=global_floor,
        max_tags=max_tags,
        multi_label_gap=multi_label_gap,
        calibration=calibration,
    )


def selected_label_ids(
    top_labels: list[dict],
    *,
    min_score: float = DEFAULT_MIN_TAG_SCORE,
    max_tags: int = DEFAULT_MAX_TAGS_PER_COMMAND,
    multi_label_gap: float = DEFAULT_MULTI_LABEL_GAP,
    calibration: dict[str, Any] | None = None,
) -> list[str]:
    return [
        str(item.get("label_id"))
        for item in select_top_labels(
            top_labels,
            min_score=min_score,
            max_tags=max_tags,
            multi_label_gap=multi_label_gap,
            calibration=calibration,
        )
        if item.get("label_id")
    ]
