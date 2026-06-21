"""Compatibility exports for shared SecEBL Rev20 tag retrieval helpers."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secebl_l1.v4_tags_embedding_retrieval import (  # noqa: E402,F401
    DEFAULT_GLOBAL_SCORE_FLOOR,
    DEFAULT_MAX_TAGS_PER_COMMAND,
    DEFAULT_MIN_TAG_SCORE,
    DEFAULT_MULTI_LABEL_GAP,
    DEFAULT_SCORE_CALIBRATION,
    calibrated_top_labels,
    calibration_path_for_model,
    label_axis,
    load_score_calibration,
    rank_labels,
    score_threshold_for_label,
    select_top_labels,
    selected_label_ids,
)
