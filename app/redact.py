"""Overlap resolution and single-pass redaction against original Unicode offsets.

Positions are Python string indices, i.e. Unicode code-point offsets into the
*original* text. Overlapping fragments are resolved in one greedy pass ordered
by (priority desc, start asc, span desc); the redacted output is then built in
a single left-to-right sweep so every offset always refers to the original
document and never to intermediate, already-shifted text.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Fragment:
    start: int
    end: int
    category: str
    priority: int = 0


@dataclass(frozen=True)
class PlacedFragment:
    fragment: Fragment
    placeholder: str
    redacted_start: int
    redacted_end: int


@dataclass(frozen=True)
class DroppedFragment:
    fragment: Fragment
    reason: str


def normalize_category(raw: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in raw.strip().upper())
    return (cleaned.strip("_") or "SENSITIVE")[:24]


def validate_fragments(
    text_length: int, fragments: list[Fragment]
) -> list[dict]:
    """Return a list of out-of-bounds fragment descriptions (empty = all ok)."""
    errors = []
    for i, f in enumerate(fragments):
        if f.start < 0 or f.end > text_length or f.start >= f.end:
            errors.append(
                {
                    "index": i,
                    "start": f.start,
                    "end": f.end,
                    "text_length": text_length,
                    "message": "must satisfy 0 <= start < end <= len(text)",
                }
            )
    return errors


def resolve_overlaps(
    fragments: list[Fragment],
) -> tuple[list[Fragment], list[DroppedFragment]]:
    """Pick a non-overlapping subset, honouring priority.

    Sort by (priority desc, start asc, longer span first) and greedily accept
    fragments that do not intersect an already accepted one. Returns the
    accepted fragments sorted by start, plus the dropped ones with a reason.
    """
    seen: set[tuple[int, int, str]] = set()
    unique: list[Fragment] = []
    for f in fragments:
        key = (f.start, f.end, f.category)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    ordered = sorted(
        unique, key=lambda f: (-f.priority, f.start, -(f.end - f.start), f.category)
    )

    accepted: list[Fragment] = []  # kept sorted by start
    starts: list[int] = []
    dropped: list[DroppedFragment] = []

    for f in ordered:
        i = bisect.bisect_left(starts, f.start)
        conflict = False
        if i > 0 and accepted[i - 1].end > f.start:
            conflict = True  # previous accepted interval reaches into f
        if not conflict and i < len(accepted) and f.end > accepted[i].start:
            conflict = True  # f reaches into the next accepted interval
        if conflict:
            dropped.append(DroppedFragment(f, "overlap_higher_priority"))
        else:
            starts.insert(i, f.start)
            accepted.insert(i, f)

    return accepted, dropped


def build_redacted(
    text: str,
    accepted: list[Fragment],
    placeholder_fn: Callable[[Fragment], str],
) -> tuple[str, list[PlacedFragment]]:
    """Single left-to-right sweep over the original text.

    `accepted` must be sorted by start and non-overlapping. Returns the
    redacted text and the placed fragments with their positions in it.
    """
    parts: list[str] = []
    placed: list[PlacedFragment] = []
    cursor = 0
    out_len = 0
    for f in accepted:
        head = text[cursor : f.start]
        parts.append(head)
        out_len += len(head)
        placeholder = placeholder_fn(f)
        parts.append(placeholder)
        redacted_start = out_len
        out_len += len(placeholder)
        placed.append(
            PlacedFragment(
                fragment=f,
                placeholder=placeholder,
                redacted_start=redacted_start,
                redacted_end=out_len,
            )
        )
        cursor = f.end
    parts.append(text[cursor:])
    return "".join(parts), placed
