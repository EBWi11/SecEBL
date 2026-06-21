#!/usr/bin/env python3
"""Evaluate final-gold cmdline top-k tag retrieval from cached L1 predictions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from session_scorer import command_text, read_jsonl  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GOLD = ROOT / "examples/linux/example_gold.rev20.jsonl"


def gold_tags(row: dict[str, Any]) -> set[str]:
    return {str(tag) for tag in row.get("behavior_tags", []) if str(tag)}


def load_predictions(path: Path) -> dict[str, list[dict[str, Any]]]:
    predictions: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl(path):
        command = command_text(row)
        if not command:
            continue
        top_labels = list(row.get("top_labels") or [])
        previous = predictions.get(command)
        if previous is not None and previous != top_labels:
            raise ValueError(f"conflicting predictions for command: {command}")
        predictions[command] = top_labels
    return predictions


def top_label_ids(top_labels: list[dict[str, Any]], k: int) -> set[str]:
    return {
        str(item.get("label_id"))
        for item in top_labels[:k]
        if item.get("label_id") is not None and str(item.get("label_id"))
    }


def rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def miss_record(
    *,
    row_index: int,
    row: dict[str, Any],
    gold: set[str],
    top_labels: list[dict[str, Any]],
    max_k: int,
) -> dict[str, Any]:
    predicted = top_label_ids(top_labels, max_k)
    hit_tags = gold & predicted
    missed_tags = gold - predicted
    return {
        "miss_type": "partial_gold_coverage" if hit_tags else "no_gold_hit",
        "row_index": row_index,
        "gold_id": row.get("gold_id"),
        "session_id": row.get("session_id"),
        "session_expected": row.get("session_expected"),
        "platform": row.get("platform"),
        "source_row_index": row.get("source_row_index"),
        "gold": sorted(gold),
        "hit_tags": sorted(hit_tags),
        "missed_tags": sorted(missed_tags),
        "extra_topk_tags": sorted(predicted - gold),
        "top_labels": [
            {
                "rank": rank,
                "label_id": item.get("label_id"),
                "score": item.get("score"),
                "axis": item.get("axis"),
            }
            for rank, item in enumerate(top_labels[:max_k], 1)
        ],
        "command": command_text(row),
    }


def evaluate_gold_rows(
    rows: list[dict[str, Any]],
    predictions: dict[str, list[dict[str, Any]]],
    *,
    max_k: int,
    sample_limit: int,
) -> dict[str, Any]:
    rows_with_gold = 0
    rows_without_gold = 0
    missing_prediction_rows = 0
    single_label_rows = 0
    gold_tag_instances = 0
    by_k = [
        {
            "k": k,
            "any_gold_hit": 0,
            "all_gold_covered": 0,
            "gold_tag_hits": 0,
            "single_label_hit": 0,
        }
        for k in range(1, max_k + 1)
    ]
    miss_samples: list[dict[str, Any]] = []
    miss_records: list[dict[str, Any]] = []

    for row_index, row in enumerate(rows, 1):
        gold = gold_tags(row)
        if not gold:
            rows_without_gold += 1
            continue

        rows_with_gold += 1
        gold_tag_instances += len(gold)
        if len(gold) == 1:
            single_label_rows += 1

        command = command_text(row)
        top_labels = predictions.get(command)
        if top_labels is None:
            missing_prediction_rows += 1
            top_labels = []

        top_max = top_label_ids(top_labels, max_k)
        if gold and not (gold <= top_max):
            record = miss_record(row_index=row_index, row=row, gold=gold, top_labels=top_labels, max_k=max_k)
            miss_records.append(record)
            if len(miss_samples) < sample_limit:
                miss_samples.append(record)

        for metrics in by_k:
            predicted = top_label_ids(top_labels, int(metrics["k"]))
            overlap = gold & predicted
            metrics["any_gold_hit"] += int(bool(overlap))
            metrics["all_gold_covered"] += int(gold <= predicted)
            metrics["gold_tag_hits"] += len(overlap)
            if len(gold) == 1:
                metrics["single_label_hit"] += int(bool(overlap))

    by_k_summary = []
    for metrics in by_k:
        any_hits = int(metrics["any_gold_hit"])
        all_covered = int(metrics["all_gold_covered"])
        tag_hits = int(metrics["gold_tag_hits"])
        single_hits = int(metrics["single_label_hit"])
        by_k_summary.append(
            {
                "k": int(metrics["k"]),
                "rows_with_gold": rows_with_gold,
                "any_gold_hit": any_hits,
                "any_gold_hit_accuracy": rate(any_hits, rows_with_gold),
                "all_gold_covered": all_covered,
                "all_gold_covered_rate": rate(all_covered, rows_with_gold),
                "gold_tag_hits": tag_hits,
                "gold_tag_instances": gold_tag_instances,
                "micro_recall": rate(tag_hits, gold_tag_instances),
                "single_label_rows": single_label_rows,
                "single_label_hit": single_hits,
                "single_label_hit_rate": rate(single_hits, single_label_rows),
            }
        )

    top = by_k_summary[-1] if by_k_summary else {}
    top5 = next((item for item in by_k_summary if item["k"] == 5), None)
    summary = {
        "rows": len(rows),
        "rows_with_gold": rows_with_gold,
        "rows_without_gold": rows_without_gold,
        "missing_prediction_rows": missing_prediction_rows,
        "max_k": max_k,
        "by_k": by_k_summary,
        "topk_any_gold_hit_accuracy": top.get("any_gold_hit_accuracy", 0.0),
        "topk_any_gold_hit_count": top.get("any_gold_hit", 0),
        "topk_all_gold_covered_rate": top.get("all_gold_covered_rate", 0.0),
        "topk_all_gold_covered_count": top.get("all_gold_covered", 0),
        "micro_recall_at_k": top.get("micro_recall", 0.0),
        "micro_recall_at_k_count": top.get("gold_tag_hits", 0),
        "gold_tag_instances": gold_tag_instances,
        "single_label_topk_hit_rate": top.get("single_label_hit_rate", 0.0),
        "single_label_topk_hit_count": top.get("single_label_hit", 0),
        "single_label_rows": single_label_rows,
        "miss_record_count": len(miss_records),
        "miss_samples": miss_samples,
        "miss_records": miss_records,
    }
    if top5 is not None:
        summary.update(
            {
                "top5_any_gold_hit_accuracy": top5.get("any_gold_hit_accuracy", 0.0),
                "top5_any_gold_hit_count": top5.get("any_gold_hit", 0),
                "top5_all_gold_covered_rate": top5.get("all_gold_covered_rate", 0.0),
                "top5_all_gold_covered_count": top5.get("all_gold_covered", 0),
                "micro_recall_at_5": top5.get("micro_recall", 0.0),
                "micro_recall_at_5_count": top5.get("gold_tag_hits", 0),
                "single_label_top5_hit_rate": top5.get("single_label_hit_rate", 0.0),
                "single_label_top5_hit_count": top5.get("single_label_hit", 0),
            }
        )
    return summary


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--misses-out", type=Path, default=None)
    parser.add_argument("--max-k", type=int, default=5)
    parser.add_argument("--sample-limit", type=int, default=50)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.max_k < 1:
        raise SystemExit("--max-k must be >= 1")
    rows = read_jsonl(args.gold)
    predictions = load_predictions(args.predictions)
    summary = evaluate_gold_rows(
        rows,
        predictions,
        max_k=args.max_k,
        sample_limit=max(0, args.sample_limit),
    )
    summary["gold"] = str(args.gold)
    summary["predictions"] = str(args.predictions)
    miss_records = list(summary.pop("miss_records"))
    misses_out = args.misses_out
    if misses_out is None and args.out is not None:
        misses_out = args.out.with_suffix(".misses.jsonl")
    if misses_out is not None:
        write_jsonl(misses_out, miss_records)
        summary["misses_out"] = str(misses_out)
    text = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
