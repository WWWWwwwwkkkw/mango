import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import angr
import archinfo
import claripy
from angr.analyses.reaching_definitions.function_handler import FunctionCallData
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from argument_resolver.utils.guarded_index_rda import _add_alternatives, _incoming_range
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from argument_resolver.utils.integer_overflow import IntegerOverflowScanner
from argument_resolver.utils.integer_overflow_detection import run_detection, save_sink_reports
from argument_resolver.utils.overflow_input_evidence import input_evidence
from argument_resolver.handlers.option_parser import OptionParserEffects


class OptionParserCallTests(unittest.TestCase):
    def test_unresolved_target_is_skipped(self):
        project = angr.load_shellcode(b"\xc3", "amd64", load_address=0x4000)
        handler = OptionParserEffects(project)
        call = FunctionCallData(CodeLocation(0x4000, 0), CodeLocation(None, None), None)
        handler.handle_function(project.factory.blank_state(), call)
        self.assertEqual(handler.call_trace, [])
        self.assertFalse(call.effects)


@unittest.skipUnless(shutil.which("gcc") and platform.machine() == "x86_64", "uses x86-64 GCC fixtures")
class InputEvidenceTests(unittest.TestCase):
    def exported(self, main, leaf=None):
        leaf = leaf or '''
            unsigned leaf(unsigned a, unsigned b) {
                __asm__ volatile ("addl %1,%0" : "+a"(a) : "d"(b) : "cc");
                return a;
            }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "demo"
            source = "#include <stdlib.h>\n#include <unistd.h>\n#include <sys/socket.h>\n" + leaf + main
            subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", "-x", "c", "-", "-o", str(binary)],
                           input=source.encode(), check=True)
            reports = run_detection(str(binary), function_names=["leaf"], include_operand_origins=False)
            self.assertEqual(len(reports), 1)
            path, = save_sink_reports(reports, tmp)
            return json.loads(Path(path).read_text())["input_evidence"]

    def test_recv_input_on_first_operand(self):
        info = self.exported("int main(void){unsigned char c=0; recv(0,&c,1,0); return leaf(c,11);}")
        self.assertEqual(info["status"], "external_input")
        left, right = info["operands"]
        self.assertTrue(any(s.startswith("recv(") for s in left["sources"]))
        self.assertEqual(right["observed_values"], [11])
        self.assertEqual(right["sources"], [])

    def test_unused_input_is_not_attributed_to_operands(self):
        info = self.exported("int main(void){unsigned char c; read(0,&c,1); return leaf(37,11);}")
        self.assertEqual(info["status"], "unknown")
        self.assertEqual([o["observed_values"] for o in info["operands"]], [[37], [11]])
        self.assertTrue(all(not o["sources"] for o in info["operands"]))

    def test_guarded_dynamic_argument(self):
        info = self.exported(
            "int main(int n,char **v){if(n<2||n>3)return 0;"
            "return leaf((unsigned char)v[n-1][0],48);}")
        self.assertEqual(info["operands"][0]["sources"], ["ARGV_1", "ARGV_2"])
        self.assertEqual(info["operands"][1]["observed_values"], [48])

    def test_one_sided_guard_leaves_index_unknown(self):
        info = self.exported(
            "int main(int n,char **v){if(n<2)return 0;"
            "return leaf((unsigned char)v[n-1][0],48);}")
        self.assertEqual(info["status"], "unknown")

    def test_other_range_and_slots(self):
        info = self.exported(
            "int main(int n,char **v){if(n>5||n<4)return 0;"
            "return leaf((unsigned char)v[n-2][0],48);}")
        self.assertEqual(info["operands"][0]["sources"], ["ARGV_2", "ARGV_3"])

    def test_guard_on_different_variable_and_wide_range(self):
        for lower, upper in [("m<2", "n>3"), ("n<2", "n>8")]:
            with self.subTest(lower=lower, upper=upper):
                info = self.exported(
                    "int main(int n,char **v){volatile int m=n;"
                    f"if({lower}||{upper})return 0;"
                    "return leaf((unsigned char)v[n-1][0],48);}")
                self.assertEqual(info["status"], "unknown")

    def test_guarded_lookup_in_constant_table(self):
        info = self.exported(
            'int main(int n,char **v){const char *table[]={"A","B"};'
            'if(n<2||n>3)return 0;return leaf(table[n-2][0],48);}')
        self.assertEqual(info["status"], "unknown")
        self.assertEqual(info["operands"][0]["observed_values"], [65, 66])

    def test_global_index_uses_its_actual_storage(self):
        info = self.exported(
            "volatile int cursor;"
            "int main(int n,char **v){cursor=n;if(cursor<2||cursor>3)return 0;"
            "return leaf((unsigned char)v[cursor-1][0],48);}")
        self.assertEqual(info["operands"][0]["sources"], ["ARGV_1", "ARGV_2"])

    def test_option_parser_can_update_global_index(self):
        for call in ('getopt(n,v,"a")', 'getopt_long(n,v,"a",opts,0)',
                     'getopt_long_only(n,v,"a",opts,0)'):
            with self.subTest(call=call):
                info = self.exported(
                    '\n#include <getopt.h>\nstatic struct option opts[]={{0}};\n'
                    f'int main(int n,char **v){{optind=1;{call};return leaf(optind,48);}}')
                self.assertEqual(info["operands"][0]["observed_values"], [])
                self.assertEqual(info["operands"][0]["sources"], [])

    def test_local_function_named_like_parser_retains_its_own_semantics(self):
        info = self.exported(
            'int getopt(int n,char *const v[],const char *fmt){return -1;}'
            'int main(int n,char **v){optind=1;getopt(n,v,"a");return leaf(optind,48);}')
        self.assertEqual(info["operands"][0]["observed_values"], [1])

    def test_input_is_read_from_memory_operand(self):
        info = self.exported(
            "int main(int n,char **v){return leaf(11,(unsigned char *)v[1]);}",
            '''unsigned leaf(unsigned a,unsigned char *p){
                __asm__ volatile ("addb %1,%b0" : "+a"(a) : "m"(*p) : "cc");
                return a;
            }''')
        self.assertEqual(info["status"], "external_input")
        self.assertEqual(info["operands"][0]["sources"], [])
        self.assertIn("ARGV_1", info["operands"][1]["sources"])

    def test_memory_and_immediate_with_no_explicit_register_operands(self):
        info = self.exported(
            "int main(int n,char **v){return leaf((unsigned char *)v[1]);}",
            '''unsigned leaf(unsigned char *p){
                __asm__ volatile ("addb $3,%0" : "+m"(*p) : : "cc");
                return *p;
            }''')
        self.assertIn("ARGV_1", info["operands"][0]["sources"])
        self.assertEqual(info["operands"][1]["observed_values"], [3])

    def test_environment_and_read_markers(self):
        for expr, prefix in [('getenv("COUNT")[0]', 'getenv('), ('c', 'read(')]:
            with self.subTest(source=prefix):
                info = self.exported('int main(void){unsigned char c=0; read(0,&c,1); return leaf('
                                     + expr + ',11);}')
                self.assertEqual(info["status"], "external_input")
                self.assertTrue(all(s.startswith(prefix) for s in info["operands"][0]["sources"]))
                self.assertTrue(info["operands"][0]["sources"])


class GuardedRangeStateTests(unittest.TestCase):
    def test_relative_bounds_require_an_anchor_and_a_live_index(self):
        # end == 6 and end-index == 2 imply index == 4. In the controls
        # another argument is checked, or a delay slot overwrites index.
        for endian in ("little", "big"):
            for first_branch, delay, expected in (
                (0x14880007, 0, True), (0x14C80007, 0, False),
                (0x14880007, 0x00c02821, False),
            ):
                with self.subTest(endian=endian, branch=first_branch, delay=delay):
                    words = [0x24080006, first_branch, 0, 0x00854823, 0x24080002,
                             0x15280003, delay, 0x03e00008, 0, 0x03e00008, 0]
                    arch = archinfo.ArchMIPS32(endness="Iend_LE" if endian == "little" else "Iend_BE")
                    code = b"".join(word.to_bytes(4, endian) for word in words)
                    project = angr.load_shellcode(code, arch, load_address=0x5000)
                    project.analyses.CFGFast(normalize=True, function_starts=[0x5000])
                    function = project.kb.functions[0x5000]
                    node = next(b for b in function.graph if b.addr == 0x501c)
                    regions = _incoming_range(project, function, node)
                    arg = Register(*arch.registers["a1"])
                    self.assertEqual([vals for slot, vals in regions if slot == arg],
                                     [(4,)] if expected else [])

    def test_same_register_bounds_on_mips_and_aarch64(self):
        # Each checks 2 <= arg < 4. MIPS uses slti/branches and delay slots,
        # AArch64 uses condition flags and compares its full-width argument.
        mips = "0200882806000015000000000400882803000011000000000800e003000000000800e00300000000"
        arm = "1f0800f18b0000541f1000f14a000054c0035fd6c0035fd6"
        for arch, code, accepted, arg in [
            (archinfo.ArchMIPS32(endness="Iend_LE"), mips, 24, "a0"),
            (archinfo.ArchAArch64(), arm, 16, "x0"),
        ]:
            with self.subTest(arch=arch.name):
                project = angr.load_shellcode(bytes.fromhex(code), arch, load_address=0x4000)
                project.analyses.CFGFast(normalize=True, function_starts=[0x4000])
                function = project.kb.functions[0x4000]
                node = next(b for b in function.graph if b.addr == 0x4000 + accepted)
                regions = _incoming_range(project, function, node)
                self.assertIn((Register(*arch.registers[arg]), (2, 3)), regions or ())

    def test_excluded_indices_are_not_reintroduced(self):
        arch = archinfo.ArchAMD64()
        state = LiveDefinitions(arch)
        frame = state.stack_address(-16)
        state.registers.store(arch.registers["rbp"][0], frame, endness=arch.memory_endness)
        addr = state.get_stack_address(frame - 4)
        even = claripy.BVS("index", 32) << 1
        state.stack.store(addr, even, endness=arch.memory_endness)
        slot = MemoryLocation(SpOffset(arch.bits, -20), 4, endness=arch.memory_endness)
        refined = _add_alternatives(state, slot, range(2, 6))
        actual = refined.stack.load(addr, 4, endness=arch.memory_endness)[0]
        self.assertEqual({value.concrete_value for value in actual if value.concrete}, {2, 4})
        self.assertIn(even, actual)
        self.assertIs(state.stack.load(addr, 4, endness=arch.memory_endness).one_value(), even)
        with patch.object(claripy.Solver, "satisfiable", side_effect=claripy.ClaripyError):
            self.assertIs(_add_alternatives(state, slot, range(2, 6)), state)


class MipsOperandTests(unittest.TestCase):
    def test_three_register_add_ignores_previous_destination_and_plain_top(self):
        arch = archinfo.ArchMIPS32(endness="Iend_LE")
        # addu v0,a0,a1 / jr ra / nop
        proj = angr.load_shellcode(bytes.fromhex("211085000800e00300000000"), arch, load_address=0x4000)
        proj.analyses.CFGFast(normalize=True, function_starts=[0x4000])
        sink, = [op for op in IntegerOverflowScanner(proj).scan() if op.ins_addr == 0x4000]
        state = LiveDefinitions(arch)
        for reg, val in (("v0", claripy.BVS("ARGV_3", 32, explicit_name=True)),
                         ("a0", state.top(32)), ("a1", claripy.BVV(11, 32))):
            state.registers.store(arch.registers[reg][0], MultiValues(val))
        unknown = input_evidence(proj, sink, state, None)
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual(unknown["operands"][0]["observed_values"], [])
        state.registers.store(arch.registers["a0"][0],
                              MultiValues(claripy.BVS("ARGV_1", 32, explicit_name=True)))
        observed = input_evidence(proj, sink, state, None)
        self.assertEqual([o["sources"] for o in observed["operands"]], [["ARGV_1"], []])
