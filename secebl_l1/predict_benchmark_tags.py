#!/usr/bin/env python3
"""Generate ranked Rev20 top-label predictions for a session benchmark."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

os.environ.setdefault("USE_TF", "0")
os.environ.setdefault("USE_FLAX", "0")
os.environ.setdefault("TRANSFORMERS_NO_TF", "1")
os.environ.setdefault("TRANSFORMERS_NO_FLAX", "1")

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from session_scorer import command_text, read_jsonl, session_rows  # noqa: E402
from rev20_model_loading import load_sentence_transformer  # noqa: E402
from rev20_prompt_profiles import (  # noqa: E402
    add_prompt_profile_argument,
    prompt_profile_metadata,
    resolve_prompt_prefixes,
)
from v4_tags_embedding_retrieval import label_axis, rank_labels  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "model_artifacts"
DEFAULT_DATA_DIR = ROOT / "model_artifacts"
DEFAULT_BENCHMARK = ROOT / "examples/linux/example_gold.rev20.jsonl"
DEFAULT_OUT_DIR = ROOT / "runs/example_linux_l1/latest"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def maybe_prefix(texts: list[str], prefix: str | None) -> list[str]:
    if not prefix:
        return texts
    return [f"{prefix}: {text}" for text in texts]


def unique_commands(rows: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for row in rows:
        command = command_text(row)
        if not command:
            raise ValueError(f"benchmark row missing command text: {row}")
        seen.setdefault(command, None)
    return list(seen)


def main() -> None:
    args = parse_args()
    import numpy as np

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    semantic_rows = load_jsonl(data_dir / "semantic_texts.jsonl")
    benchmark_rows = read_jsonl(Path(args.benchmark))
    commands = unique_commands(benchmark_rows)
    label_ids = [str(row["label_id"]) for row in semantic_rows]
    label_groups = {str(row["label_id"]): str(row.get("axis") or label_axis(str(row["label_id"]))) for row in semantic_rows}
    semantic_texts = [str(row["text"]) for row in semantic_rows]
    saved_top_k = args.save_top_k

    model = load_sentence_transformer(args.model, device=args.device)
    model.max_seq_length = args.max_seq_length

    started_at = time.time()
    command_embeddings = model.encode(
        maybe_prefix(commands, args.query_prefix),
        batch_size=args.batch_size,
        normalize_embeddings=True,
        show_progress_bar=args.show_progress_bar,
    )
    semantic_embeddings = model.encode(
        maybe_prefix(semantic_texts, args.tag_prefix),
        batch_size=args.batch_size,
        normalize_embeddings=True,
        show_progress_bar=args.show_progress_bar,
    )
    sims = np.matmul(command_embeddings, semantic_embeddings.T)

    predictions: list[dict[str, Any]] = []
    for idx, command in enumerate(commands):
        ranked = rank_labels(sims[idx], label_ids, top_k=args.save_top_k)
        top_labels = [
            {"label_id": label_id, "score": score, "axis": label_groups.get(label_id, label_axis(label_id))}
            for label_id, score in ranked[:saved_top_k]
        ]
        predictions.append(
            {
                "observation_id": f"{args.observation_prefix}:{idx}",
                "command": command,
                "top_labels": top_labels,
            }
        )

    predictions_path = out_dir / "predictions.jsonl"
    write_jsonl(predictions_path, predictions)

    try:
        sessions = session_rows(benchmark_rows)
        session_count = len(sessions)
    except ValueError:
        session_count = 0
    summary = {
        "benchmark": str(args.benchmark),
        "model": str(args.model),
        "data_dir": str(data_dir),
        "session_count": session_count,
        "command_rows": len(benchmark_rows),
        "unique_commands": len(commands),
        "label_count": len(label_ids),
        "max_seq_length": args.max_seq_length,
        "batch_size": args.batch_size,
        "device": args.device,
        **prompt_profile_metadata(
            prompt_profile=args.prompt_profile,
            query_prefix=args.query_prefix,
            tag_prefix=args.tag_prefix,
        ),
        "saved_top_k": saved_top_k,
        "runtime_seconds": round(time.time() - started_at, 3),
        "predictions": str(predictions_path),
    }
    (out_dir / "prediction_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--max-seq-length", type=int, default=160)
    parser.add_argument("--device", default="auto", help="SentenceTransformers device: auto, cpu, cuda, mps, etc.")
    add_prompt_profile_argument(parser, default=None, include_none=True)
    parser.add_argument("--query-prefix", default=None)
    parser.add_argument("--tag-prefix", default=None)
    parser.add_argument("--save-top-k", type=int, default=5)
    parser.add_argument("--observation-prefix", default="benchmark")
    parser.add_argument("--show-progress-bar", action="store_true")
    args = parser.parse_args()
    args.prompt_profile, args.query_prefix, args.tag_prefix = resolve_prompt_prefixes(
        prompt_profile=args.prompt_profile,
        query_prefix=args.query_prefix,
        tag_prefix=args.tag_prefix,
        default_profile=None,
    )
    return args


if __name__ == "__main__":
    main()
