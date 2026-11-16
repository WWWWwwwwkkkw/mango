"""No pyvex/archinfo/native library imports: recursive CFFI-backed objects."""
import faulthandler
import sys
import cffi

faulthandler.enable()
ffi = cffi.FFI()
ffi.cdef('''
typedef struct Node { int tag; unsigned int value; struct Node *left, *right; } Node;
''')
owners = [ffi.new('Node *') for _ in range(3)]
owners[0].tag = 1
owners[0].value = 0x400000
owners[1].tag = 1
owners[1].value = 0xFFFFFFFF
owners[2].tag = 2
owners[2].left, owners[2].right = owners[0], owners[1]
root = ffi.cast('Node *', int(ffi.cast('uintptr_t', owners[2])))

class Leaf:
    __slots__ = ['value']
    def __init__(self, value): self.value = value
    @staticmethod
    def from_c(node): return Leaf(node.value)

class Op:
    __slots__ = ['args']
    def __init__(self, args): self.args = args
    @staticmethod
    def from_c(node): return Op([convert(arg) for arg in [node.left, node.right]])

classes = {1: Leaf, 2: Op}
def convert(node):
    if node == ffi.NULL or node[0] == ffi.NULL:
        return None
    return classes[node.tag].from_c(node)

for repeat in range(10):
    for index in range(100000):
        result = convert(root)
    print('PASS', repeat + 1, flush=True)
