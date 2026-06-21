#!/usr/bin/env python3
"""Shared stream I/O, session lifecycle, and batching helpers for rev20 L2 scoring."""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import math
import subprocess
import sys
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from session_scorer import command_text, read_jsonl  # noqa: E402

ATTACK_LABEL = "intrusion"
NORMAL_LABEL = "normal_operation"
UNKNOWN_LABEL = "unknown"
KNOWN_LABELS = {ATTACK_LABEL, NORMAL_LABEL}
SCORE_DETAIL_FULL = "full"
SCORE_DETAIL_LEAN = "lean"


@dataclass(frozen=True)
class StreamEvent:
    row_number: int
    session_id: str
    command: str
    expected: str | None = None
    timestamp: str | None = None
    event_time: float | None = None
    raw_row: dict[str, Any] | None = None


@dataclass(frozen=True)
class ScoringConfig:
    min_window_size: int
    score_every: int
    max_history_events: int
    threshold_score: float
    score_final_windows: bool
    session_idle_seconds: float
    session_max_age_seconds: float
    score_detail_level: str


@contextmanager
def open_text(path: Path, *, encoding: str) -> Iterator[io.TextIOBase]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding=encoding, newline="") as handle:
            yield handle
        return
    if path.suffix == ".zst":
        proc = subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.stdout is None:
            raise RuntimeError("zstd stdout is unavailable")
        handle = io.TextIOWrapper(proc.stdout, encoding=encoding, newline="")
        try:
            yield handle
        finally:
            active_exception = sys.exc_info()[0] is not None
            handle.close()
            _stdout, stderr = proc.communicate()
            rc = proc.returncode
            if rc != 0 and not active_exception and rc not in {-13, 70}:
                detail = stderr.decode(encoding, errors="replace").strip() if stderr else ""
                raise RuntimeError(f"zstd failed for {path}: exit {rc} {detail}")
        return
    with path.open("r", encoding=encoding, newline="") as handle:
        yield handle


def infer_input_format(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if ".csv" in suffixes:
        return "csv"
    if ".jsonl" in suffixes:
        return "benchmark_jsonl"
    raise SystemExit(f"cannot infer input format from {path}; pass --input-format")


def value_from_fields(row: dict[str, Any], fields: list[str], separator: str) -> str:
    values = [str(row.get(field) or "").strip() for field in fields]
    if any(not value for value in values):
        return ""
    return separator.join(values)


def parse_timestamp_seconds(value: str | None) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        number = None
    if number is not None and math.isfinite(number):
        abs_number = abs(number)
        if abs_number >= 1e17:
            return number / 1_000_000_000.0
        if abs_number >= 1e14:
            return number / 1_000_000.0
        if abs_number >= 1e11:
            return number / 1_000.0
        return number
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def iter_benchmark_events(
    path: Path,
    *,
    session_id_fields: list[str],
    session_id_separator: str,
    expected_field: str,
    timestamp_field: str | None,
    include_raw_row: bool,
    limit_rows: int | None,
    session_shard_count: int,
    session_shard_index: int,
) -> Iterator[StreamEvent]:
    emitted = 0
    for row_number, row in enumerate(read_jsonl(path), 1):
        command = command_text(row).strip()
        session_id = value_from_fields(row, session_id_fields, session_id_separator)
        if not command or not session_id:
            continue
        if not session_in_shard(session_id, session_shard_count, session_shard_index):
            continue
        expected = str(row.get(expected_field) or row.get("expected") or "").strip() or None
        raw_timestamp = row.get(timestamp_field) if timestamp_field else None
        timestamp = str(raw_timestamp).strip() if raw_timestamp is not None else None
        emitted += 1
        yield StreamEvent(
            row_number=row_number,
            session_id=session_id,
            command=command,
            expected=expected,
            timestamp=timestamp,
            event_time=parse_timestamp_seconds(timestamp),
            raw_row=dict(row) if include_raw_row else None,
        )
        if limit_rows is not None and emitted >= limit_rows:
            break


def iter_csv_events(
    path: Path,
    *,
    cmdline_field: str,
    session_id_fields: list[str],
    session_id_separator: str,
    expected_field: str | None,
    timestamp_field: str | None,
    encoding: str,
    include_raw_row: bool,
    limit_rows: int | None,
    session_shard_count: int,
    session_shard_index: int,
) -> Iterator[StreamEvent]:
    with open_text(path, encoding=encoding) as handle:
        reader = csv.DictReader(handle)
        required = [cmdline_field, *session_id_fields]
        if timestamp_field:
            required.append(timestamp_field)
        missing = [name for name in required if name not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f"CSV missing required field(s): {', '.join(missing)}; available={reader.fieldnames or []}")
        has_expected = bool(expected_field and expected_field in (reader.fieldnames or []))
        emitted = 0
        for row_number, row in enumerate(reader, 2):
            command = str(row.get(cmdline_field) or "").strip()
            session_id = value_from_fields(row, session_id_fields, session_id_separator)
            if not command or not session_id:
                continue
            if not session_in_shard(session_id, session_shard_count, session_shard_index):
                continue
            expected = str(row.get(expected_field) or "").strip() if has_expected else None
            raw_timestamp = row.get(timestamp_field) if timestamp_field else None
            timestamp = str(raw_timestamp).strip() if raw_timestamp is not None else None
            emitted += 1
            yield StreamEvent(
                row_number=row_number,
                session_id=session_id,
                command=command,
                expected=expected or None,
                timestamp=timestamp or None,
                event_time=parse_timestamp_seconds(timestamp),
                raw_row=dict(row) if include_raw_row else None,
            )
            if limit_rows is not None and emitted >= limit_rows:
                break


def session_in_shard(session_id: str, shard_count: int, shard_index: int) -> bool:
    if shard_count <= 1:
        return True
    return zlib.crc32(session_id.encode("utf-8", errors="replace")) % shard_count == shard_index


def batched(events: Iterator[StreamEvent], batch_size: int) -> Iterator[list[StreamEvent]]:
    batch: list[StreamEvent] = []
    for event in events:
        batch.append(event)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def prediction_command(row: dict[str, Any]) -> str:
    command = str(row.get("command") or row.get("cmdline") or "").strip()
    if command:
        return command
    try:
        return command_text(row).strip()
    except Exception:
        return ""


def should_score_online(state: Any, config: ScoringConfig) -> bool:
    if state.command_count < max(1, config.min_window_size):
        return False
    return (state.command_count - max(1, config.min_window_size)) % max(1, config.score_every) == 0


def lifecycle_enabled(config: ScoringConfig) -> bool:
    return config.session_idle_seconds > 0 or config.session_max_age_seconds > 0


def session_instance_id(base_session_id: str, segment: int) -> str:
    if segment <= 1:
        return base_session_id
    return f"{base_session_id}#part{segment}"


def rollover_reason(state: Any, event: StreamEvent, config: ScoringConfig) -> str | None:
    if event.event_time is None:
        return None
    if (
        config.session_idle_seconds > 0
        and state.last_event_time is not None
        and event.event_time - state.last_event_time > config.session_idle_seconds
    ):
        return "session_idle"
    if (
        config.session_max_age_seconds > 0
        and state.first_event_time is not None
        and event.event_time - state.first_event_time > config.session_max_age_seconds
    ):
        return "session_max_age"
    return None


def update_top_windows(state: Any, window: dict[str, Any]) -> None:
    state.top_windows.append(window)
    state.top_windows.sort(key=lambda item: float(item.get("risk_probability") or 0.0), reverse=True)
    del state.top_windows[3:]


def flush_alerts_if_needed(handle: Any, stats: dict[str, Any], alert_flush_every: int) -> None:
    if alert_flush_every > 0 and int(stats.get("alerts", 0)) % alert_flush_every == 0:
        handle.flush()


def session_ids_to_prune(
    sessions: dict[str, Any],
    *,
    current_row: int,
    max_idle_rows: int,
    max_sessions: int,
) -> list[str]:
    prune_ids: list[str] = []
    if max_idle_rows > 0:
        prune_ids.extend(
            session_id
            for session_id, state in sessions.items()
            if state.last_row_number is not None and current_row - state.last_row_number > max_idle_rows
        )
    if max_sessions > 0 and len(sessions) > max_sessions:
        already = set(prune_ids)
        remaining = [(session_id, state) for session_id, state in sessions.items() if session_id not in already]
        ordered = sorted(remaining, key=lambda item: item[1].last_row_number or 0)
        prune_ids.extend(session_id for session_id, _state in ordered[: max(0, len(sessions) - max_sessions)])
    return prune_ids


def parse_session_fields(args: argparse.Namespace) -> list[str]:
    if args.session_id_fields:
        fields = [field.strip() for field in args.session_id_fields if field.strip()]
    elif args.session_id_fields_csv:
        fields = [field.strip() for field in args.session_id_fields_csv.split(",") if field.strip()]
    else:
        fields = ["session_id"]
    if not fields:
        raise SystemExit("at least one session id field is required")
    return fields
