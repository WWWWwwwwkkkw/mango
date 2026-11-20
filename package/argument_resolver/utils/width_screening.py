"""
Width-based screening for integer overflow sinks.

This module isolates the pruning policy so it can be iterated independently
from the higher-level detection pipeline.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import List, Sequence, Tuple

from argument_resolver.utils.integer_overflow import ArithmeticOperation, OperandWidthState

LOG = logging.getLogger(__name__)

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


def _signed_bounds(state: OperandWidthState, width: int, unsigned: Tuple[int, int]) -> Tuple[int, int]:
    sign_bit = 1 << (width - 1)
    lo, hi = unsigned
    if hi < sign_bit:
        return lo, hi
    if lo >= sign_bit:
        return lo - 2 * sign_bit, hi - 2 * sign_bit
    if state.origin == "widen" and state.signed and state.source_width:
        sign_bit = 1 << (state.source_width - 1)
    return -sign_bit, sign_bit - 1


def _result_bounds(op: str, left: Tuple[int, int], right: Tuple[int, int]) -> Tuple[int, int]:
    a, b = left
    c, d = right
    if op == "Add":
        return a + c, b + d
    if op == "Sub":
        return a - d, b - c
    products = (a * c, a * d, b * c, b * d)
    return min(products), max(products)


def assess_width_status(sink: ArithmeticOperation) -> Tuple[str, str]:
    width = sink.bit_width
    states = sink.operand_states
    if not width or len(states) != 2 or states[0].width != width:
        return WIDTH_STATUS_POSSIBLE, "missing or incompatible operand widths"
    if sink.vex_op == f"Iop_Shl{width}":
        # VEX scalar shifts use an I8 count even when the value is I32 or I64.
        count = states[1].unsigned_bounds
        if states[1].width != 8 or count is None or count[0] != count[1] or not 0 <= count[0] < width:
            return WIDTH_STATUS_POSSIBLE, "shift count is not a single in-range value"
        bounds = states[0].unsigned_bounds
        if bounds is None or not 0 <= bounds[0] <= bounds[1]:
            return WIDTH_STATUS_POSSIBLE, "shift input range unproven"
        output_width = min(width, sink.narrow_use_width or width)
        if bounds[1] << count[0] < 1 << (output_width - 1):
            return WIDTH_STATUS_NO, "nonnegative left shift fits signed and unsigned result ranges"
        return WIDTH_STATUS_POSSIBLE, "shift may exceed operation or narrowing width"
    if states[1].width != width:
        return WIDTH_STATUS_POSSIBLE, "missing or incompatible operand widths"
    op = next((name for name in ("Add", "Sub", "Mul") if sink.vex_op == f"Iop_{name}{width}"), None)
    if op is None:
        return WIDTH_STATUS_POSSIBLE, "operation has no range rule"

    # VEX Add/Sub/Mul operate on bit patterns. Prove both interpretations.
    maximum = (1 << width) - 1
    unsigned = [state.unsigned_bounds or (0, maximum) for state in states]
    signed = [_signed_bounds(state, width, bounds) for state, bounds in zip(states, unsigned)]
    ulo, uhi = _result_bounds(op, *unsigned)
    slo, shi = _result_bounds(op, *signed)
    sign_bit = 1 << (width - 1)
    if 0 <= ulo and uhi <= maximum and -sign_bit <= slo and shi < sign_bit:
        narrow = sink.narrow_use_width
        if narrow and narrow < width:
            narrow_sign = 1 << (narrow - 1)
            if uhi >= 1 << narrow or slo < -narrow_sign or shi >= narrow_sign:
                return WIDTH_STATUS_POSSIBLE, "result may lose range in a local narrowing conversion"
        return WIDTH_STATUS_NO, "signed and unsigned result ranges fit"

    if any(sink.notes.get(key) for key in CRITICAL_NOTE_KEYS):
        return WIDTH_STATUS_POSSIBLE, "critical usage and unproven result range"
    if sink.widen_uses:
        return WIDTH_STATUS_DEPRIORITIZE, "result widened later; operation range unproven"
    return WIDTH_STATUS_POSSIBLE, "result range may exceed the operation width"


def screen_by_width(
    sinks: Sequence[ArithmeticOperation],
) -> List[Tuple[ArithmeticOperation, str, str]]:
    screened: List[Tuple[ArithmeticOperation, str, str]] = []
    decisions = Counter()
    for sink in sinks:
        status, reason = assess_width_status(sink)
        decisions[(sink.vex_op, status, reason)] += 1
        sink.notes["width_status"] = status
        sink.notes["width_reason"] = reason
        if status == WIDTH_STATUS_NO:
            if sink.ins_addr is not None:
                LOG.debug("Width screening drop: %s @ %#x", sink.function, sink.ins_addr)
            continue
        screened.append((sink, status, reason))
    LOG.info("Width screening: %d -> %d", len(sinks), len(screened))
    for (op, status, reason), count in sorted(decisions.items()):
        LOG.info("Width decisions: %s %s (%s): %d", op, status, reason, count)
    return screened
