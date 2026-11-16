"""Exercise IR conversion without ever calling vex_lift."""
import faulthandler
import sys
import time
import pyvex
from pyvex import ffi, pvc
from pyvex.expr import IRExpr, Binop, Const, RdTmp
from pyvex.const import U32
from pyvex.stmt import IRStmt, WrTmp

faulthandler.enable()
if '--no-null-check' in sys.argv:
    from pyvex.expr import enum_to_expr_class
    IRExpr._from_c = staticmethod(lambda item: enum_to_expr_class(item.tag)._from_c(item))
if '--stmt-dispatch' in sys.argv:
    from pyvex.stmt import enum_to_stmt_class
    IRStmt._from_c = staticmethod(lambda item: enum_to_stmt_class(item.tag)._from_c(item))
constant = ffi.new('IRConst *')
constant.tag = pvc.Ico_U32
constant.Ico.U32 = 0x400000
left = ffi.new('IRExpr *')
left.tag = pvc.Iex_Const
left.Iex.Const.con = constant
right = ffi.new('IRExpr *')
right.tag = pvc.Iex_RdTmp
right.Iex.RdTmp.tmp = 20
expression = ffi.new('IRExpr *')
expression.tag = pvc.Iex_Binop
expression.Iex.Binop.op = pvc.Iop_Add32
expression.Iex.Binop.arg1 = left
expression.Iex.Binop.arg2 = right
statement = ffi.new('IRStmt *')
statement.tag = pvc.Ist_WrTmp
statement.Ist.WrTmp.tmp = 32
statement.Ist.WrTmp.data = expression
if '--unowned' in sys.argv:
    statement_owner = statement
    statement = ffi.cast('IRStmt *', int(ffi.cast('uintptr_t', statement)))

started = time.monotonic()
for repeat in range(10):
    for index in range(100000):
        if '--python-only' in sys.argv:
            result = WrTmp(32, Binop('Iop_Add32', [Const(U32(0x400000)), RdTmp.get_instance(20)]))
        elif '--cffi-only' in sys.argv:
            result = [statement.Ist.WrTmp.tmp, statement.Ist.WrTmp.data.Iex.Binop.arg1.Iex.Const.con.Ico.U32]
        else:
            result = IRStmt._from_c(statement)
    print('PASS', repeat + 1, 'seconds', round(time.monotonic() - started, 3), flush=True)
