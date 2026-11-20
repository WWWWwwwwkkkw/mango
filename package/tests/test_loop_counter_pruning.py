import unittest

import angr
import archinfo

from argument_resolver.utils.integer_overflow import IntegerOverflowScanner


class LoopCounterPruningTests(unittest.TestCase):
    def check_update(self, arch, code, *, skipped, offset=0, width=32):
        start = 0x4000
        project = angr.load_shellcode(bytes.fromhex(code), arch=arch, load_address=start)
        project.analyses.CFGFast(normalize=True, function_starts=[start])
        scanner = IntegerOverflowScanner(project)

        def updates(detection):
            return [op for op in scanner.scan(function_addrs=[start], value_sinks_only=detection)
                    if op.ins_addr == start + offset and op.bit_width == width
                    and op.classification == "value_arith"]

        self.assertTrue(updates(False), "fixture must reach value-sink classification")
        self.assertEqual(bool(updates(True)), not skipped)

    def test_register_counters(self):
        fixtures = [
            ("AMD64", "83c00283f86472f8c3"),  # add eax,2 / cmp eax,100 / jb
            ("AMD64", "ffc875fcc3"),  # dec eax / jne
            ("ARMEL", "020050e2fdffff1a1eff2fe1"),  # subs r0,r0,2 / bne
            ("AARCH64", "00080071e1ffff54c0035fd6"),  # subs w0,w0,2 / b.ne
            (archinfo.ArchMIPS32(endness="Iend_LE"), "02004224feff4414000000000800e00300000000"),
            (archinfo.ArchMIPS32(endness="Iend_BE"), "2442fffe1444fffe0000000003e0000800000000"),
        ]
        for arch, code in fixtures:
            with self.subTest(arch=str(arch), code=code):
                self.check_update(arch, code, skipped=True)

    def test_stack_counter(self):
        # add DWORD PTR [rbp-4],2 / cmp DWORD PTR [rbp-4],100 / jb
        self.check_update("AMD64", "8345fc02837dfc6472f6c3", skipped=True)

    def test_independent_stack_store_in_loop(self):
        # Store another local between the update and the test.
        self.check_update("AMD64", "8345fc028945f8837dfc6472f3c3", skipped=True)
        # Moving that store two bytes overlaps the counter.
        self.check_update("AMD64", "8345fc028945fa837dfc6472f3c3", skipped=False)

    def test_update_and_comparison_in_separate_blocks(self):
        # add eax,2 / jmp test / nop / cmp eax,100 / jb update / ret
        self.check_update("AMD64", "83c002eb019083f86472f5c3", skipped=True)
        # Overwriting eax before testing it breaks the chain.
        self.check_update("AMD64", "83c002eb019089f883f86472f3c3", skipped=False)

    def test_mips_boolean_lowering(self):
        # addiu v0,v0,2 / sltiu t0,v0,100 / bnez t0,update / nop
        self.check_update(archinfo.ArchMIPS32(endness="Iend_LE"),
                          "020042246400482cfdff0015000000000800e00300000000", skipped=True)

    def test_keeps_ambiguous_updates(self):
        for code in (
            "83c00283ff6472f8c3",  # eax updated, edi controls the loop
            "83c00283f864720190c3",  # both successors go forward, no cycle
            "83c00283c00183f86472f5c3",  # second update supersedes first
            "8345fc02837df86472f6c3",  # different stack slot controls the loop
            "83c04083f86472f8c3",  # large stride
            "83c00383f86472f8c3",  # first stride above the cutoff
            "83c002890783f86472f6c3",  # updated counter also stored through edi
            "83c00283f86472f885ff74f490ebf1",  # both paths stay in the same loop
        ):
            with self.subTest(code=code):
                self.check_update("AMD64", code, skipped=False)
