"""Shared flat label retrieval helpers for rev20 tag embedding models."""

from __future__ import annotations

import numpy as np

DEFAULT_MIN_TAG_SCORE = 0.55
DEFAULT_MAX_TAGS_PER_COMMAND = 4
DEFAULT_MULTI_LABEL_GAP = 0.12


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


def rank_label_matrix(
    scores: object,
    label_ids: list[str],
    *,
    top_k: int = 5,
) -> list[list[tuple[str, float]]]:
    """Rank a score matrix with torch top-k when available, otherwise NumPy."""
    effective_top_k = min(max(int(top_k), 0), len(label_ids))
    if effective_top_k == 0:
        return [[] for _ in range(len(scores))]  # type: ignore[arg-type]

    if hasattr(scores, "topk"):
        top_scores, top_indices = scores.topk(effective_top_k, dim=1)  # type: ignore[attr-defined]
        top_scores_rows = top_scores.detach().cpu().tolist()
        top_indices_rows = top_indices.detach().cpu().tolist()
        return [
            [(label_ids[int(index)], float(score)) for index, score in zip(indices, row_scores)]
            for indices, row_scores in zip(top_indices_rows, top_scores_rows)
        ]

    score_matrix = np.asarray(scores)
    return [rank_labels(row, label_ids, top_k=effective_top_k) for row in score_matrix]


def select_top_labels(
    top_labels: list[dict],
    *,
    min_score: float = DEFAULT_MIN_TAG_SCORE,
    max_tags: int = DEFAULT_MAX_TAGS_PER_COMMAND,
    multi_label_gap: float = DEFAULT_MULTI_LABEL_GAP,
) -> list[dict]:
    ranked = sorted(top_labels, key=lambda item: -float(item.get("score") or 0.0))
    if not ranked or max_tags <= 0:
        return []
    if float(ranked[0].get("score") or 0.0) < min_score:
        return []
    selected = [ranked[0]]
    top_score = float(ranked[0].get("score") or 0.0)
    for item in ranked[1:]:
        score = float(item.get("score") or 0.0)
        if top_score - score > multi_label_gap:
            break
        if score < min_score:
            continue
        selected.append(item)
        if len(selected) >= max_tags:
            break
    return selected
