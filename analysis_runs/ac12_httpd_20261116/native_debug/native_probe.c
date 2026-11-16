#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pyvex.h"

typedef struct { uint64_t addr; uint32_t size; unsigned char *data; } Block;
static unsigned long expressions;
static void visit_expr(IRExpr *e, int depth) {
    if (!e) return;
    if (depth > 500) { fprintf(stderr, "cyclic/deep IR expression\n"); abort(); }
    ++expressions;
    switch (e->tag) {
    case Iex_Binder: case Iex_Get: case Iex_RdTmp: case Iex_VECRET: case Iex_GSPTR: break;
    case Iex_Const: if (!e->Iex.Const.con) abort(); break;
    case Iex_GetI: visit_expr(e->Iex.GetI.ix, depth+1); break;
    case Iex_Unop: visit_expr(e->Iex.Unop.arg, depth+1); break;
    case Iex_Binop: visit_expr(e->Iex.Binop.arg1, depth+1); visit_expr(e->Iex.Binop.arg2, depth+1); break;
    case Iex_Triop: visit_expr(e->Iex.Triop.details->arg1, depth+1); visit_expr(e->Iex.Triop.details->arg2, depth+1); visit_expr(e->Iex.Triop.details->arg3, depth+1); break;
    case Iex_Qop: visit_expr(e->Iex.Qop.details->arg1, depth+1); visit_expr(e->Iex.Qop.details->arg2, depth+1); visit_expr(e->Iex.Qop.details->arg3, depth+1); visit_expr(e->Iex.Qop.details->arg4, depth+1); break;
    case Iex_Load: visit_expr(e->Iex.Load.addr, depth+1); break;
    case Iex_ITE: visit_expr(e->Iex.ITE.cond, depth+1); visit_expr(e->Iex.ITE.iftrue, depth+1); visit_expr(e->Iex.ITE.iffalse, depth+1); break;
    case Iex_CCall:
        for (int i=0; e->Iex.CCall.args[i]; ++i) { if (i > 40) abort(); visit_expr(e->Iex.CCall.args[i], depth+1); }
        break;
    default: fprintf(stderr, "invalid expression tag %#x\n", e->tag); abort();
    }
}
static void visit_stmt(IRStmt *s) {
    switch (s->tag) {
    case Ist_NoOp: case Ist_IMark: case Ist_MBE: break;
    case Ist_AbiHint: visit_expr(s->Ist.AbiHint.base, 0); visit_expr(s->Ist.AbiHint.nia, 0); break;
    case Ist_Put: visit_expr(s->Ist.Put.data, 0); break;
    case Ist_PutI: visit_expr(s->Ist.PutI.details->ix, 0); visit_expr(s->Ist.PutI.details->data, 0); break;
    case Ist_WrTmp: visit_expr(s->Ist.WrTmp.data, 0); break;
    case Ist_Store: visit_expr(s->Ist.Store.addr, 0); visit_expr(s->Ist.Store.data, 0); break;
    case Ist_StoreG: visit_expr(s->Ist.StoreG.details->addr, 0); visit_expr(s->Ist.StoreG.details->data, 0); visit_expr(s->Ist.StoreG.details->guard, 0); break;
    case Ist_LoadG: visit_expr(s->Ist.LoadG.details->addr, 0); visit_expr(s->Ist.LoadG.details->alt, 0); visit_expr(s->Ist.LoadG.details->guard, 0); break;
    case Ist_Exit: visit_expr(s->Ist.Exit.guard, 0); break;
    case Ist_LLSC: visit_expr(s->Ist.LLSC.addr, 0); visit_expr(s->Ist.LLSC.storedata, 0); break;
    case Ist_CAS: visit_expr(s->Ist.CAS.details->addr, 0); visit_expr(s->Ist.CAS.details->expdLo, 0); visit_expr(s->Ist.CAS.details->expdHi, 0); visit_expr(s->Ist.CAS.details->dataLo, 0); visit_expr(s->Ist.CAS.details->dataHi, 0); break;
    case Ist_Dirty:
        visit_expr(s->Ist.Dirty.details->guard, 0); visit_expr(s->Ist.Dirty.details->mAddr, 0);
        for (int i=0; s->Ist.Dirty.details->args[i]; ++i) { if (i>40) abort(); visit_expr(s->Ist.Dirty.details->args[i], 0); }
        break;
    default: fprintf(stderr, "invalid statement tag %#x\n", s->tag); abort();
    }
}
static Block read_block(FILE *in) {
    Block b;
    if (fread(&b.addr, 8, 1, in) != 1 || fread(&b.size, 4, 1, in) != 1) abort();
    b.data = malloc(b.size + 64);
    if (!b.data || fread(b.data, 1, b.size, in) != b.size) abort();
    memset(b.data + b.size, 0x5a, 64);
    return b;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *in = fopen(argv[1], "rb");
    if (!in) return 3;
    uint32_t nr, nb;
    if (fread(&nr, 4, 1, in) != 1 || fread(&nb, 4, 1, in) != 1) return 4;
    if (!vex_init()) return 5;
    Block *regions_in = calloc(nr, sizeof(Block));
    for (uint32_t i = 0; i < nr; ++i) {
        regions_in[i] = read_block(in);
        register_readonly_region(regions_in[i].addr, regions_in[i].size, regions_in[i].data);
    }
    Block *blocks = calloc(nb, sizeof(Block));
    for (uint32_t i = 0; i < nb; ++i) blocks[i] = read_block(in);
    fclose(in);
    VexArchInfo info;
    LibVEX_default_VexArchInfo(&info);
    info.endness = VexEndnessLE;
    info.hwcaps = 0;
    unsigned long count = 0;
    for (int repeat = 0; repeat < 10; ++repeat) {
        for (uint32_t i = 0; i < nb; ++i) {
            for (int cross = 0; cross < 2; ++cross) {
                VEXLiftResult *result = vex_lift(VexArchMIPS32, info, blocks[i].data, blocks[i].addr, 99, blocks[i].size, 1, 0, 1, 1, 1,
                    cross ? VexRegUpdUnwindregsAtMemAccess : VexRegUpdLdAllregsAtEachInsn, 0);
                if (!result || !result->irsb) { fprintf(stderr, "lift failure %#lx\n", (unsigned long)blocks[i].addr); return 6; }
                for (int s=0; s<result->irsb->stmts_used; ++s) visit_stmt(result->irsb->stmts[s]);
                visit_expr(result->irsb->next, 0);
                for (int j = 0; j < 64; ++j) if (blocks[i].data[blocks[i].size + j] != 0x5a) return 7;
                ++count;
            }
        }
        printf("PASS %d translations %lu expressions %lu\n", repeat + 1, count, expressions);
        fflush(stdout);
    }
    return 0;
}
