"""
Width-based screening for integer overflow sinks.

This module isolates the pruning policy so it can be iterated independently
from the higher-level detection pipeline.
"""

from __future__ import annotations

import logging
from typing import List, Sequence, Tuple

LOG = logging.getLogger(__name__)

from argument_resolver.utils.integer_overflow import ArithmeticOperation, OperandWidthState

WIDTH_STATUS_NO = "NO_NARROW_OVERFLOW"
WIDTH_STATUS_POSSIBLE = "POSSIBLE"
WIDTH_STATUS_DEPRIORITIZE = "DEPRIORITIZE"

CRITICAL_NOTE_KEYS = (
    "used_as_addr",
    "looks_like_addr",
    "used_as_length",
    "used_as_index",
    "used_as_store_value",
    "updates_sp",
    "updates_pc",
)

ALLOWED_ORIGINS = {
    "register",
    "const",
    "memory",
    "widen",
    "trunc",
}


def _has_critical_usage(sink: ArithmeticOperation) -> bool:
    for key in CRITICAL_NOTE_KEYS:
        if sink.notes.get(key):
            return True
    return False


def _state_is_reliable(state: OperandWidthState, op_width: int) -> bool:
    if state.width is None or state.width != op_width:
        return False
    if state.origin not in ALLOWED_ORIGINS:
        return False
    if state.origin == "widen":
        return state.source_width is not None and state.source_width < state.width
    if state.origin == "trunc":
        return state.source_width is not None and state.source_width > state.width
    return True


def _all_operands_widen_before_op(
    states: Sequence[OperandWidthState], op_width: int
) -> bool:
    if not states:
        return False
    for state in states:
        if state.origin != "widen":
            return False
        if state.source_width is None or state.width is None:
            return False
        if state.width != op_width:
            return False
        if state.source_width >= op_width:
            return False
    return True


def _has_range_cap_evidence(_sink: ArithmeticOperation) -> Tuple[bool, str]:
    # Placeholder: add structural range-cap evidence here when available.
    return False, ""


def assess_width_status(sink: ArithmeticOperation) -> Tuple[str, str]:
    states = sink.operand_states or ()
    op_width = sink.bit_width or 0

    if not states or op_width == 0:
        return WIDTH_STATUS_POSSIBLE, "missing width evidence"

    if _has_critical_usage(sink):
        return WIDTH_STATUS_POSSIBLE, "critical usage: keep"

    for state in states:
        if not _state_is_reliable(state, op_width):
            return WIDTH_STATUS_POSSIBLE, "operand width/origin unclear"
        if state.origin == "trunc":
            return WIDTH_STATUS_POSSIBLE, "trunc operand: keep"

    if _all_operands_widen_before_op(states, op_width):
        return (
            WIDTH_STATUS_NO,
            "widen-before-op: only excludes narrow-width overflow site",
        )

    has_range_cap, reason = _has_range_cap_evidence(sink)
    if has_range_cap:
        return WIDTH_STATUS_NO, reason

    widen_targets = [
        w.dst_width for w in sink.widen_uses if w.dst_width and w.dst_width > op_width
    ]
    if widen_targets:
        return WIDTH_STATUS_DEPRIORITIZE, "result widened later"

    return WIDTH_STATUS_DEPRIORITIZE, "width-consistent operands without exclusion evidence"


def screen_by_width(
    sinks: Sequence[ArithmeticOperation],
) -> List[Tuple[ArithmeticOperation, str, str]]:
    screened: List[Tuple[ArithmeticOperation, str, str]] = []
    before = len(sinks)
    skipped = 0
    for sink in sinks:
        status, reason = assess_width_status(sink)
        sink.notes["width_status"] = status
        sink.notes["width_reason"] = reason
        if status == WIDTH_STATUS_NO:
            skipped += 1
            if sink.ins_addr is not None:
                LOG.debug("Width screening drop: %s @ %#x", sink.function, sink.ins_addr)
            continue
        screened.append((sink, status, reason))
    LOG.info("Width screening: %d -> %d", before, len(screened))
    return screened
