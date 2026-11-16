"""
Shared helpers for reasoning about VEX statements that Angr does not support well.

Dirty / LLSC / MBE statements frequently cause translation, propagator, or
decompiler crashes.  Mango does not attempt to emulate them, so other modules
use these helpers to identify such statements and either skip the corresponding
blocks or mark them as unknown boundaries.
"""

from __future__ import annotations

from typing import Optional

import angr
from angr import errors as angr_errors
import pyvex

# Collect all statement types that should be considered "dirty" for our purposes.
DIRTY_STMT_TYPES = tuple(
    stmt
    for stmt in (
        getattr(pyvex.IRStmt, "Dirty", None),
        getattr(pyvex.IRStmt, "LLSC", None),
        getattr(pyvex.IRStmt, "MBE", None),
    )
    if stmt is not None
)


def block_has_dirty_statements(block: angr.block.Block) -> bool:
    """
    Return True if the given basic block contains unsupported statements.
    """

    statements = getattr(block.vex, "statements", tuple())
    return any(isinstance(stmt, DIRTY_STMT_TYPES) for stmt in statements)


def function_has_dirty_blocks(func: angr.knowledge_plugins.functions.function.Function) -> bool:
    """
    Tell whether Angr identified dirty statements anywhere inside ``func``.
    """

    try:
        blocks = list(func.blocks)
    except angr_errors.SimTranslationError:
        return False
    return any(block_has_dirty_statements(block) for block in blocks)


def codeloc_hits_dirty(project: angr.Project, codeloc) -> bool:
    """
    Determine if ``codeloc`` lives inside a block that contains dirty statements.
    """

    if codeloc is None:
        return False
    block_addr: Optional[int] = getattr(codeloc, "block_addr", None)
    addr = block_addr or getattr(codeloc, "ins_addr", None)
    if addr is None:
        return False

    try:
        block = project.factory.block(addr)
    except angr_errors.AngrError:
        return False
    except Exception:
        return False

    return block_has_dirty_statements(block)


__all__ = [
    "DIRTY_STMT_TYPES",
    "block_has_dirty_statements",
    "codeloc_hits_dirty",
    "function_has_dirty_blocks",
]
