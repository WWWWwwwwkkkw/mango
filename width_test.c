// width_screening_test.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 让编译器别把函数内联掉，方便产生清晰的 VEX
#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

// 模拟“用户输入/外部输入”
NOINLINE int32_t ext_i32(void) {
    volatile int32_t x = 0x7ffff000; // 接近上界，方便触发潜在溢出
    return x;
}

NOINLINE uint64_t ext_u64(void) {
    volatile uint64_t x = 0x1fffffffULL << 33; // 高位非零，方便截断风险
    return x;
}

// ------------------------------
// A) 应该触发 NO(Drop) 的场景：两侧都 widen-before-op，然后做 64 位加法
// 预期：width_status = NO_NARROW_OVERFLOW（原因：widen-before-op 排除窄位溢出点）
// ------------------------------
NOINLINE int64_t case_widen_before_op_drop(int32_t a, int32_t b) {
    int64_t x = (int64_t)a;     // 32Sto64
    int64_t y = (int64_t)b;     // 32Sto64
    return x + y;               // Add64
}

// ------------------------------
// B) 绝不能 Drop：先 Add32 再 widen（最常见误剪反例）
// 预期：POSSIBLE 或 DEPRIORITIZE，但绝不能 NO
// ------------------------------
NOINLINE int64_t case_add32_then_widen_keep(int32_t a, int32_t b) {
    int32_t s = a + b;          // Add32（潜在 signed overflow UB / VEX wrap）
    return (int64_t)s;          // 32Sto64
}

// ------------------------------
// C) critical usage：长度参数（必须保留）
// 预期：POSSIBLE（critical_usage 命中 used_as_length）
// ------------------------------
NOINLINE int case_length_critical_keep(int32_t n) {
    // n + 16: Add32
    int32_t len = n + 16;
    // 关键用途：malloc 长度
    char *p = (char *)malloc((size_t)len);
    if (!p) return -1;
    memset(p, 0x41, (size_t)len);
    free(p);
    return len;
}

// ------------------------------
// D) critical usage：索引（必须保留）
// 预期：POSSIBLE（critical_usage 命中 used_as_index/addr）
// ------------------------------
NOINLINE int case_index_critical_keep(int32_t idx) {
    int32_t i = idx + 1;        // Add32
    volatile int arr[16] = {0};
    // 关键用途：数组索引（地址计算）
    return arr[i & 15];         // 这里 AND 只是避免运行时崩，但分析应仍看到 idx+1 的索引用途链
}

// ------------------------------
// E) trunc：64->32 截断后参与 Add32（必须保留）
// 预期：POSSIBLE（operand 出现 trunc，不降权不 Drop）
// ------------------------------
NOINLINE uint32_t case_trunc_keep(uint64_t x64) {
    uint32_t x32 = (uint32_t)x64; // 64to32 trunc
    return x32 + 1;               // Add32
}

// ------------------------------
// F) range-cap 硬证据：AND 常量掩码封顶（Step4 若实现可 Drop，否则保留）
// 预期：
//   - 若你实现了 AND 掩码硬证据 NO：可能 NO（非关键用途时）
//   - 若没实现 Step4：POSSIBLE/DEPRIORITIZE（但不应误剪关键路径）
// ------------------------------
NOINLINE uint32_t case_and_mask_range_cap(uint32_t a, uint32_t b) {
    uint32_t x = a & 0xFFu;     // And32 with const 0xFF => [0,255]
    uint32_t y = b & 0xFFu;     // And32 with const 0xFF => [0,255]
    return x + y;               // Add32 最大 510，不可能溢出 32 位
}

// 主函数：让各个 case 都被引用，避免死代码消除
int main(void) {
    int32_t a = ext_i32();
    int32_t b = ext_i32();
    uint64_t u = ext_u64();

    volatile int64_t r1 = case_widen_before_op_drop(a, b);
    volatile int64_t r2 = case_add32_then_widen_keep(a, b);

    volatile int r3 = case_length_critical_keep(a);
    volatile int r4 = case_index_critical_keep(b);

    volatile uint32_t r5 = case_trunc_keep(u);
    volatile uint32_t r6 = case_and_mask_range_cap((uint32_t)a, (uint32_t)b);

    // 防止编译器优化掉
    return (int)(r1 ^ r2) ^ r3 ^ r4 ^ (int)r5 ^ (int)r6;
}
