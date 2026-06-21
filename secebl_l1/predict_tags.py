#!/usr/bin/env python3
"""Predict ranked Rev20 top labels for command lines or normalized audit-log events."""

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

from rev20_model_loading import load_sentence_transformer  # noqa: E402
from rev20_prompt_profiles import add_prompt_profile_argument, prompt_profile_metadata, resolve_prompt_prefixes  # noqa: E402
from v4_tags_embedding_retrieval import label_axis, rank_labels  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "model_artifacts"
DEFAULT_DATA_DIR = ROOT / "model_artifacts"
DEFAULT_OUT = ROOT / "runs/predict_tags/predictions.jsonl"
DEFAULT_TEXT_FIELDS = ("cmdline", "command", "k8slog", "raw", "event", "message")


def maybe_prefix(texts: list[str], prefix: str | None) -> list[str]:
    if not prefix:
        return texts
    return [f"{prefix}: {text}" for text in texts]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
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


def row_text(row: dict[str, Any], fields: list[str]) -> str:
    for field in fields:
        value = row.get(field)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def load_input_events(args: argparse.Namespace) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for idx, text in enumerate(args.text or []):
        text = str(text).strip()
        if text:
            events.append({"text": text, "source": "cli", "source_index": idx})
    if args.input is None:
        return events

    input_format = args.input_format
    if input_format == "auto":
        input_format = "jsonl" if args.input.suffix.lower() in {".jsonl", ".json"} else "text"

    if input_format == "text":
        with args.input.open("r", encoding=args.encoding) as handle:
            for line_no, line in enumerate(handle, 1):
                text = line.rstrip("\n").strip()
                if text:
                    events.append({"text": text, "source": str(args.input), "source_line": line_no})
        return events

    rows = read_jsonl(args.input)
    for idx, row in enumerate(rows):
        text = row_text(row, args.text_field)
        if not text:
            raise ValueError(f"{args.input}:{idx + 1}: missing text field in {args.text_field}")
        event = {
            "text": text,
            "source": str(args.input),
            "source_index": idx,
        }
        if row.get("session_id") is not None:
            event["session_id"] = row.get("session_id")
        if row.get("expected") is not None:
            event["expected"] = row.get("expected")
        events.append(event)
    return events


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> None:
    args = parse_args()
    import numpy as np

    semantic_rows = read_jsonl(args.data_dir / "semantic_texts.jsonl")
    events = load_input_events(args)
    if not events:
        raise SystemExit("no input events; pass --text or --input")

    label_ids = [str(row["label_id"]) for row in semantic_rows]
    label_groups = {str(row["label_id"]): str(row.get("axis") or label_axis(str(row["label_id"]))) for row in semantic_rows}
    semantic_texts = [str(row["text"]) for row in semantic_rows]

    unique_texts = list(dict.fromkeys(str(event["text"]) for event in events))
    model = load_sentence_transformer(args.model, device=args.device)
    model.max_seq_length = args.max_seq_length

    started_at = time.time()
    event_embeddings = model.encode(
        maybe_prefix(unique_texts, args.query_prefix),
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
    sims = np.matmul(event_embeddings, semantic_embeddings.T)

    by_text: dict[str, dict[str, Any]] = {}
    for idx, text in enumerate(unique_texts):
        ranked = rank_labels(sims[idx], label_ids, top_k=args.save_top_k)
        top_labels = [
            {"label_id": label_id, "score": score, "axis": label_groups.get(label_id, label_axis(label_id))}
            for label_id, score in ranked
        ]
        by_text[text] = {
            "top_labels": top_labels,
        }

    predictions: list[dict[str, Any]] = []
    for idx, event in enumerate(events):
        prediction = by_text[str(event["text"])]
        row = {
            "observation_id": f"{args.observation_prefix}:{idx}",
            "command": event["text"],
            "top_labels": prediction["top_labels"],
        }
        for key in ("session_id", "expected", "source", "source_index", "source_line"):
            if key in event:
                row[key] = event[key]
        predictions.append(row)

    write_jsonl(args.output, predictions)
    summary = {
        "events": len(events),
        "unique_events": len(unique_texts),
        "labels": len(label_ids),
        "model": str(args.model),
        "data_dir": str(args.data_dir),
        "output": str(args.output),
        "batch_size": args.batch_size,
        "device": args.device,
        "max_seq_length": args.max_seq_length,
        **prompt_profile_metadata(
            prompt_profile=args.prompt_profile,
            query_prefix=args.query_prefix,
            tag_prefix=args.tag_prefix,
        ),
        "runtime_seconds": round(time.time() - started_at, 3),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", action="append", default=[])
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument("--input-format", choices=["auto", "jsonl", "text"], default="auto")
    parser.add_argument("--text-field", action="append", default=None)
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--max-seq-length", type=int, default=160)
    parser.add_argument("--device", default="auto", help="SentenceTransformers device: auto, cpu, cuda, mps, etc.")
    add_prompt_profile_argument(parser, default="mid", include_none=True)
    parser.add_argument("--query-prefix", default=None)
    parser.add_argument("--tag-prefix", default=None)
    parser.add_argument("--save-top-k", type=int, default=5)
    parser.add_argument("--observation-prefix", default="event")
    parser.add_argument("--show-progress-bar", action="store_true")
    args = parser.parse_args()
    if args.text_field is None:
        args.text_field = list(DEFAULT_TEXT_FIELDS)
    args.prompt_profile, args.query_prefix, args.tag_prefix = resolve_prompt_prefixes(
        prompt_profile=args.prompt_profile,
        query_prefix=args.query_prefix,
        tag_prefix=args.tag_prefix,
        default_profile="mid",
    )
    return args


if __name__ == "__main__":
    main()
