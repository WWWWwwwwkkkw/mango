"""Analysis state owned by one binary's integer-overflow detection call."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

LOG = logging.getLogger(__name__)


class BinaryAnalysisContext:
    """Reuse an existing CFG and lazily prepare its global CC/VRA metadata.

    Create a new context for every detection call. Per-sink RDA states and
    results are deliberately not cached here.
    """

    def __init__(self, project: angr.Project):
        self.project = project
        self.guard_ranges = {}
        self._binary_path = Path(project.filename).resolve()
        self._calling_conventions_ready = False
        self._reload_before_retry = False

    def project_for(self, binary_path: str) -> angr.Project:
        if Path(binary_path).resolve() != self._binary_path:
            raise ValueError("Analysis context belongs to a different binary")
        if self._reload_before_retry:
            # VRA may have changed function prototypes or variable metadata
            # before raising. A retry needs a clean KB, just as the former
            # standalone loader provided for each candidate.
            from argument_resolver.utils.integer_overflow import build_project
            self.project = build_project(str(self._binary_path))
            self.guard_ranges.clear()
            self._reload_before_retry = False
        if not self._calling_conventions_ready:
            LOG.info("Recovering shared calling conventions and variables for %s", binary_path)
            try:
                self.project.analyses.CompleteCallingConventions(
                    recover_variables=True, analyze_callsites=True
                )
            except Exception:
                self._reload_before_retry = True
                raise
            self._calling_conventions_ready = True
            LOG.info("Shared calling-convention and variable recovery complete")
        return self.project
