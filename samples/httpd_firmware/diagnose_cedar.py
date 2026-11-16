"""Print static scanner evidence for the cedar target without calling an LLM."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "package"))
import angr
from argument_resolver.utils.integer_overflow import build_project, IntegerOverflowScanner, IRSBUseDef
from argument_resolver.utils.width_screening import assess_width_status

binary = str(Path(__file__).parent / "bin" / "cedar_router_httpd")
project = build_project(binary)
function = project.kb.functions.function(name="plan_upload")
print("ANGR", angr.__version__, "FUNCTION", hex(function.addr))
scanner = IntegerOverflowScanner(project)
for block in function.blocks:
    ir = IRSBUseDef(block, project.arch)
    for tmp, op, stmt, address in ir.arith_nodes:
        if address == 0x4015e0:
            print("TARGET", hex(address), op, "matches", op in scanner.target_ops)
            print("CLASSIFICATION", ir.classify_tmp(tmp))
            print("USES", ir.uses_tmp.get(tmp))
            print(block.vex)
for sink in scanner.scan(function_names=["plan_upload"]):
    print("SCAN", hex(sink.ins_addr), sink.vex_op, sink.classification, assess_width_status(sink))
