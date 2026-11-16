"""Standalone pure-Python reduction: no firmware, Mango, PyVEX or CFFI imports."""
import faulthandler
import sys

faulthandler.enable()
print(sys.version, flush=True)
NULL = object()

class Struct:
    def __getattr__(self, name):
        value = Struct()
        setattr(self, name, value)
        return value
    def __getitem__(self, index):
        return self

class Value:
    __slots__ = ['_value']
    def __init__(self, value): self._value = value
    @property
    def value(self): return self._value
    @staticmethod
    def _from_c(item): return Value(item.Ico.U32)

class Constant:
    __slots__ = ['_con']
    def __init__(self, con): self._con = con
    @staticmethod
    def _from_c(item):
        con = value_from_c(item.Iex.Const.con)
        return Constant.get_instance(con)
    @staticmethod
    def get_instance(con):
        if con.value < 1024 and con.__class__ in const_pool:
            return const_pool[con.__class__][con.value]
        return Constant(con)

class Temp:
    __slots__ = ['tmp']
    def __init__(self, tmp): self.tmp = tmp
    @staticmethod
    def _from_c(item): return Temp.get_instance(item.Iex.RdTmp.tmp)
    @staticmethod
    def get_instance(tmp): return temp_pool[tmp] if tmp < 1024 else Temp(tmp)

class Binary:
    __slots__ = ['op', 'args']
    def __init__(self, op, args): self.op, self.args = op, args
    @staticmethod
    def _from_c(item):
        return Binary(enums[item.Iex.Binop.op],
                      [expression_from_c(arg) for arg in [item.Iex.Binop.arg1, item.Iex.Binop.arg2]])

class Assignment:
    __slots__ = ['tmp', 'data']
    def __init__(self, tmp, data): self.tmp, self.data = tmp, data
    @staticmethod
    def _from_c(item): return Assignment(item.Ist.WrTmp.tmp, expression_from_c(item.Ist.WrTmp.data))

enums = {1: 'U32', 2: 'Add32'}
value_classes = {'U32': Value}
expr_classes = {1: Constant, 2: Temp, 3: Binary}
statement_classes = {1: Assignment}
temp_pool = [Temp(i) for i in range(1024)]
const_pool = {Value: [Constant(Value(i)) for i in range(1024)]}

def value_from_c(item):
    if item[0] == NULL: return None
    return value_classes[enums[item.tag]]._from_c(item)

def expression_from_c(item):
    if item == NULL or item[0] == NULL: return None
    return expr_classes[item.tag]._from_c(item)

def statement_from_c(item):
    if item[0] == NULL: return None
    result = statement_classes[item.tag]._from_c(item)
    return result._from_c(item)

value, left, right, expr, stmt = [Struct() for _ in range(5)]
value.tag, value.Ico.U32 = 1, 0x400000
left.tag, left.Iex.Const.con = 1, value
right.tag, right.Iex.RdTmp.tmp = 2, 20
expr.tag, expr.Iex.Binop.op = 3, 2
expr.Iex.Binop.arg1, expr.Iex.Binop.arg2 = left, right
stmt.tag, stmt.Ist.WrTmp.tmp, stmt.Ist.WrTmp.data = 1, 32, expr
for repeat in range(10):
    for index in range(100000):
        result = statement_from_c(stmt)
    print('PASS', repeat + 1, flush=True)
