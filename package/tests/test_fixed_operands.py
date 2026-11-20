"""Exercise constant pruning across direct branches, including MIPS delay slots."""
import unittest
from unittest.mock import patch

import angr
import archinfo

from argument_resolver.utils import integer_overflow_detection as detection


class FixedOperandTests(unittest.TestCase):
    def remaining_sites(self, words, address):
        arch = archinfo.ArchMIPS32(endness="Iend_LE")
        code = b"".join(word.to_bytes(4, "little") for word in words)
        project = angr.load_shellcode(code, arch, load_address=0x4000)
        project.analyses.CFGFast(normalize=True, function_starts=[0x4000])
        # Inspect the input of the first expensive stage of the production pipeline.
        with patch.object(detection, "build_project", return_value=project), \
             patch.object(detection, "BinaryAnalysisContext"), \
             patch.object(detection, "_filter_constant_sinks", return_value=[]) as inspect:
            detection.run_detection("fixed-control", function_addrs=[0x4000],
                                    min_addr=address, max_addr=address)
        survivors = inspect.call_args.args[1] if inspect.called else []
        return [s.ins_addr for s, _, _ in survivors]

    def test_all_incoming_edges_must_prove_safe_operands(self):
        # beq a0,zero,end; lui v0,high; b end; <alternate definition>;
        # end: jr ra; addiu v0,v0,imm
        for alternate, high, imm, keep in (
            (0, 0x8000, 1, False),           # both edges agree, no wrap
            (0x3c028000, 0x8000, 1, False),  # same literal assigned twice
            (0x00a01021, 0x8000, 1, True),   # move v0,a1 on one edge
            (0x8ca20000, 0x8000, 1, True),   # lw v0,0(a1) on one edge
            (0x3c020001, 0x8000, 1, True),   # distinct reaching literals
            (0, 0x8000, 0xffff, True),       # INT_MIN - 1
            (0, 1, 0xffff, True),            # unsigned wrap only
        ):
            with self.subTest(alternate=alternate, high=high, imm=imm):
                words = [0x10800003, 0x3c020000 | high, 0x10000001, alternate,
                         0x03e00008, 0x24420000 | imm]
                self.assertEqual(self.remaining_sites(words, 0x4014), [0x4014] if keep else [])

    def test_loop_backedge_invalidates_initial_constant(self):
        # The first visit to the loop header sees 37. A later visit can see a1.
        words = [0x10000003, 0x24020025, 0x10000001, 0x00a01021,
                 0x1480fffd, 0, 0x03e00008, 0x2442000b]
        self.assertEqual(self.remaining_sites(words, 0x401c), [0x401c])
