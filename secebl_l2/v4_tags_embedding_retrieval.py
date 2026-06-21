"""Compatibility exports for shared SecEBL Rev20 tag retrieval helpers."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secebl_l1.v4_tags_embedding_retrieval import (  # noqa: E402,F401
    DEFAULT_MAX_TAGS_PER_COMMAND,
    DEFAULT_MIN_TAG_SCORE,
    DEFAULT_MULTI_LABEL_GAP,
    label_axis,
    rank_labels,
    select_top_labels,
)
