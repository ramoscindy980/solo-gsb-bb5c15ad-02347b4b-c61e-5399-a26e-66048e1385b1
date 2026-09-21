"""Unit tests for the overlap-resolution / redaction engine."""
from app.redact import (
    Fragment,
    build_redacted,
    normalize_category,
    resolve_overlaps,
    validate_fragments,
)


def ph(f: Fragment) -> str:
    return f"[[{f.category}@{f.start}:{f.end}]]"


def test_no_overlap_keeps_everything_in_order():
    frags = [Fragment(10, 12, "B"), Fragment(0, 3, "A"), Fragment(5, 6, "C")]
    accepted, dropped = resolve_overlaps(frags)
    assert [(f.start, f.end) for f in accepted] == [(0, 3), (5, 6), (10, 12)]
    assert dropped == []


def test_higher_priority_wins_over_earlier_start():
    frags = [
        Fragment(0, 10, "LOW", priority=0),
        Fragment(3, 6, "HIGH", priority=10),
    ]
    accepted, dropped = resolve_overlaps(frags)
    assert [(f.start, f.end, f.category) for f in accepted] == [(3, 6, "HIGH")]
    assert len(dropped) == 1
    assert dropped[0].reason == "overlap_higher_priority"


def test_same_priority_earlier_start_wins():
    frags = [Fragment(4, 9, "B"), Fragment(0, 6, "A")]
    accepted, dropped = resolve_overlaps(frags)
    assert [f.category for f in accepted] == ["A"]
    assert len(dropped) == 1


def test_same_priority_longer_span_wins():
    frags = [Fragment(2, 4, "SHORT"), Fragment(2, 8, "LONG")]
    accepted, dropped = resolve_overlaps(frags)
    assert [f.category for f in accepted] == ["LONG"]
    assert len(dropped) == 1


def test_contained_fragment_is_dropped():
    frags = [Fragment(0, 20, "OUTER"), Fragment(5, 8, "INNER")]
    accepted, dropped = resolve_overlaps(frags)
    assert [f.category for f in accepted] == ["OUTER"]
    assert [d.fragment.category for d in dropped] == ["INNER"]


def test_adjacent_fragments_do_not_overlap():
    frags = [Fragment(0, 5, "A"), Fragment(5, 10, "B")]
    accepted, dropped = resolve_overlaps(frags)
    assert len(accepted) == 2
    assert dropped == []


def test_exact_duplicates_are_deduplicated():
    frags = [Fragment(0, 5, "A"), Fragment(0, 5, "A"), Fragment(0, 5, "B")]
    accepted, dropped = resolve_overlaps(frags)
    assert len(accepted) == 1
    assert len(dropped) == 1  # same span, different category -> conflict


def test_build_redacted_uses_original_offsets():
    text = "甲方张三与乙方李四签订合同"
    frags = [Fragment(2, 4, "NAME"), Fragment(7, 9, "NAME")]
    accepted, _ = resolve_overlaps(frags)
    redacted, placed = build_redacted(text, accepted, ph)
    assert redacted == "甲方[[NAME@2:4]]与乙方[[NAME@7:9]]签订合同"
    # placeholder positions refer to the redacted output
    first, second = placed
    assert redacted[first.redacted_start : first.redacted_end] == first.placeholder
    assert redacted[second.redacted_start : second.redacted_end] == second.placeholder


def test_build_redacted_with_unicode_code_points():
    text = "a😀b密c"
    frags = [Fragment(2, 3, "X")]  # the 'b' after the emoji
    accepted, _ = resolve_overlaps(frags)
    redacted, placed = build_redacted(text, accepted, ph)
    assert redacted == "a😀[[X@2:3]]密c"
    assert placed[0].redacted_start == 2


def test_validate_fragments_bounds():
    errors = validate_fragments(10, [Fragment(-1, 3, "A"), Fragment(8, 8, "B"), Fragment(9, 11, "C")])
    assert len(errors) == 3
    assert validate_fragments(10, [Fragment(0, 10, "OK")]) == []


def test_normalize_category():
    assert normalize_category("  pii-name ") == "PII_NAME"
    assert normalize_category("***") == "SENSITIVE"
    assert normalize_category("身份证号") == "身份证号"
