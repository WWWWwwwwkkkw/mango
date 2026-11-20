"""Regression cases for real VEX jump-target uses outside IRSB.statements."""
from types import SimpleNamespace
import unittest

import archinfo
import pyvex

from argument_resolver.utils.integer_overflow import FollowupWiden, IRSBUseDef


def arithmetic_block(widen_op=None, next_expr=None):
    arch = archinfo.ArchMIPS32()
    types = ["Ity_I32", "Ity_I32"]
    statements = [
        pyvex.IRStmt.IMark(0x400000, 4, 0),
        pyvex.IRStmt.WrTmp(0, pyvex.IRExpr.Get(arch.registers["a0"][0], "Ity_I32")),
        pyvex.IRStmt.WrTmp(1, pyvex.IRExpr.Binop("Iop_Add32", [
            pyvex.IRExpr.RdTmp(0), pyvex.IRExpr.Const(pyvex.const.U32(4)),
        ])),
    ]
    if widen_op is not None:
        types.append("Ity_I64")
        statements.append(pyvex.IRStmt.WrTmp(
            2, pyvex.IRExpr.Unop(widen_op, [pyvex.IRExpr.RdTmp(1)]),
        ))
    irsb = pyvex.IRSB.empty_block(
        arch, 0x400000, statements=statements,
        nxt=pyvex.IRExpr.RdTmp(1) if next_expr is None else next_expr,
        tyenv=pyvex.IRTypeEnv(arch, types=types), jumpkind="Ijk_Boring", size=4,
    )
    return SimpleNamespace(addr=0x400000, vex=irsb), arch


class FollowupWidensTests(unittest.TestCase):
    def test_arithmetic_jump_target_has_no_followup_widen(self):
        block, arch = arithmetic_block()
        analyzer = IRSBUseDef(block, arch)
        self.assertEqual(analyzer.followup_widens(1), ())
        classification, flags = analyzer.classify_tmp(1)
        self.assertEqual(classification, "control_flow")
        self.assertTrue(flags["updates_pc"])

    def test_jump_target_does_not_hide_real_widening(self):
        block, arch = arithmetic_block(widen_op="Iop_32Uto64")
        analyzer = IRSBUseDef(block, arch)
        self.assertEqual(analyzer.followup_widens(1), (FollowupWiden(64, False),))

    def test_normal_widening_preserves_signedness(self):
        for op, signed in [("Iop_32Uto64", False), ("Iop_32Sto64", True)]:
            with self.subTest(op=op):
                block, arch = arithmetic_block(
                    widen_op=op, next_expr=pyvex.IRExpr.Const(pyvex.const.U32(0x400004)),
                )
                self.assertEqual(IRSBUseDef(block, arch).followup_widens(1),
                                 (FollowupWiden(64, signed),))

    def test_condition_in_jump_expression_is_not_a_statement_widen(self):
        jump = pyvex.IRExpr.ITE(
            pyvex.IRExpr.Binop("Iop_CmpNE32", [
                pyvex.IRExpr.RdTmp(1), pyvex.IRExpr.Const(pyvex.const.U32(0)),
            ]),
            pyvex.IRExpr.Const(pyvex.const.U32(0x400004)),
            pyvex.IRExpr.Const(pyvex.const.U32(0x400008)),
        )
        block, arch = arithmetic_block(next_expr=jump)
        self.assertEqual(IRSBUseDef(block, arch).followup_widens(1), ())


if __name__ == "__main__":
    unittest.main()
