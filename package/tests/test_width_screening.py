"""Check width decisions against concrete signed and unsigned arithmetic."""

import operator
import unittest
from dataclasses import replace
from types import SimpleNamespace

import archinfo
import pyvex

from argument_resolver.utils.integer_overflow import ArithmeticOperation, IRSBUseDef, OperandWidthState
from argument_resolver.utils.width_screening import WIDTH_STATUS_NO, assess_width_status


class WidthScreeningTests(unittest.TestCase):
    def test_all_eight_bit_operand_pairs(self):
        base = ArithmeticOperation("fixture", 0, 0, 0, 0, "", 8, "", "", 0)
        operands = [OperandWidthState(8, None, None, "const", (i, i)) for i in range(256)]
        signed = [int.from_bytes(bytes([i]), "big", signed=True) for i in range(256)]
        for name, calculate in (("Add", operator.add), ("Sub", operator.sub), ("Mul", operator.mul)):
            operation = replace(base, vex_op=f"Iop_{name}8")
            for a, left in enumerate(operands):
                for b, right in enumerate(operands):
                    sink = replace(operation, operand_states=(left, right))
                    status, _ = assess_width_status(sink)
                    fits = (0 <= calculate(a, b) <= 255
                            and -128 <= calculate(signed[a], signed[b]) <= 127)
                    if (status == WIDTH_STATUS_NO) != fits:
                        self.fail(f"{name}8({a}, {b}): {status}, expected safe={fits}")

    def test_left_shift_boundaries(self):
        for bounds, count, narrow, safe in (
            ((0, 255), (2, 2), None, True),
            ((0, 1), (30, 30), None, True),
            ((0, 1), (31, 31), None, False),
            ((1, 1), (32, 32), None, False),
            ((1, 1), (1, 2), None, False),
            ((0, 63), (1, 1), 8, True),
            ((0, 64), (1, 1), 8, False),
            (None, (1, 1), None, False),
            ((0x80000000, 0xffffffff), (1, 1), None, False),
        ):
            with self.subTest(bounds=bounds, count=count, narrow=narrow):
                left = OperandWidthState(32, None, None, "computed", bounds)
                right = OperandWidthState(8, None, None, "computed", count)
                sink = ArithmeticOperation("fixture", 0, 0, 0, 0, "Iop_Shl32", 32, "", "", 0,
                                           operand_states=(left, right), narrow_use_width=narrow)
                self.assertEqual(assess_width_status(sink)[0] == WIDTH_STATUS_NO, safe)

    def test_shift_and_select_operand_ranges(self):
        arch = archinfo.ArchMIPS32()
        x = pyvex.IRExpr.Get(arch.registers["a0"][0], "Ity_I32")
        amount = pyvex.IRExpr.Const(pyvex.const.U8(24))
        shr = pyvex.IRExpr.Binop("Iop_Shr32", [x, amount])
        sar = pyvex.IRExpr.Binop("Iop_Sar32", [x, amount])
        literal = pyvex.IRExpr.Const(pyvex.const.U32(500))
        cond = pyvex.IRExpr.Binop("Iop_CmpNE32", [x, literal])
        for expr, expected in (
            (shr, (0, 255)), (sar, None),
            (pyvex.IRExpr.ITE(cond, shr, literal), (0, 500)),
            (pyvex.IRExpr.ITE(cond, literal, x), None),
            (pyvex.IRExpr.ITE(cond, x, literal), None),
        ):
            with self.subTest(expr=str(expr)):
                statements = [
                    pyvex.IRStmt.WrTmp(0, expr),
                    pyvex.IRStmt.WrTmp(1, pyvex.IRExpr.Binop("Iop_Add32", [pyvex.IRExpr.RdTmp(0), literal])),
                ]
                ir = pyvex.IRSB.empty_block(arch, 0, statements=statements, nxt=literal,
                                            tyenv=pyvex.IRTypeEnv(arch, types=["Ity_I32"] * 2),
                                            jumpkind="Ijk_Boring", size=4)
                analyzer = IRSBUseDef(SimpleNamespace(vex=ir, addr=0), arch)
                self.assertEqual(analyzer.operand_width_states(1)[0].unsigned_bounds, expected)
