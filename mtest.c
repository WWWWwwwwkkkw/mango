/*
 * router_mgmt_demo.c
 *
 * A router/firmware-flavored C example that includes:
 *  - External input parsing (management UDP-like packet, TLV format)
 *  - An INTENTIONAL integer-overflow vulnerability (allocation size overflow)
 *  - Safe arithmetic examples (checked add/mul, bounds-checked parsing)
 *  - Mixed operand cases:
 *      - external input + constant
 *      - external input * external input
 *      - pointer/address arithmetic (field-address computations, base+offset)
 *
 * NOTE: This file is for security research / teaching. Do NOT deploy in real firmware.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -std=c11 router_mgmt_demo.c -o router_demo
 *
 * Run (reads a hex string from stdin, e.g. "010203..."):
 *   echo "010100000010..." | ./router_demo
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------------- Router-ish structs ----------------------------- */

#define MAX_PKT          2048
#define MAX_IFNAME       16
#define MAX_ACL_ENTRIES  4096
#define MAX_ACL_BYTES    (256 * 1024)

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  action; /* 0=drop, 1=allow */
} acl_entry_t;

typedef struct {
    char     ifname[MAX_IFNAME];
    uint32_t lan_ip;
    uint32_t lan_mask;
    uint32_t wan_ip;

    /* pretend "ppp state" buffer used by PPP / PPTP / L2TP pipeline */
    uint8_t  ppp_state[512];

    /* ACL table used by firewall */
    acl_entry_t *acl;
    size_t       acl_count;
    size_t       acl_capacity;
} router_ctx_t;

/* ----------------------------- Packet format ----------------------------- */
/*
 * mgmt packet layout (big picture):
 *
 *   struct mgmt_hdr {
 *     uint8_t  ver;        // must be 1
 *     uint8_t  msg_type;   // 1=SET_ACL
 *     uint16_t flags;
 *     uint32_t seq;
 *     uint16_t payload_len; // length of TLV payload that follows
 *     uint16_t reserved;
 *   }  (total 12 bytes)
 *
 *   TLV payload:
 *     [type:1][len:2][value:len bytes]...
 *
 * TLV types (examples):
 *   0x10: IFNAME (len<=15, ASCII)
 *   0x20: ACL_BLOB (value contains entry_count + entries)
 *
 * ACL_BLOB value format:
 *   [entry_count:4 bytes little-endian]
 *   [entry_size :4 bytes little-endian]  (size of each entry blob)
 *   [entries    : entry_count * entry_size bytes]
 *
 * Vulnerability: entry_count * entry_size can overflow 32-bit/size_t if unchecked.
 */

#pragma pack(push, 1)
typedef struct {
    uint8_t  ver;
    uint8_t  msg_type;
    uint16_t flags;
    uint32_t seq;
    uint16_t payload_len;
    uint16_t reserved;
} mgmt_hdr_t;
#pragma pack(pop)

enum {
    MSG_SET_ACL = 1
};

enum {
    TLV_IFNAME   = 0x10,
    TLV_ACL_BLOB = 0x20
};

/* ----------------------------- Helpers: endian / safe math ----------------------------- */

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static bool checked_add_size(size_t a, size_t b, size_t *out) {
    if (a > (SIZE_MAX - b)) return false;
    *out = a + b;
    return true;
}

static bool checked_mul_size(size_t a, size_t b, size_t *out) {
    if (a == 0 || b == 0) { *out = 0; return true; }
    if (a > (SIZE_MAX / b)) return false;
    *out = a * b;
    return true;
}

/* ----------------------------- Hex input (simulate external input) ----------------------------- */

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* Read hex string from stdin into buf. Returns length in bytes. */
static size_t read_hex_stdin(uint8_t *buf, size_t cap) {
    char line[8192];
    if (!fgets(line, sizeof(line), stdin)) return 0;

    size_t n = 0;
    for (size_t i = 0; line[i] && line[i] != '\n'; ) {
        while (line[i] == ' ' || line[i] == '\t') i++;
        if (!line[i] || line[i] == '\n') break;

        int hi = hexval((unsigned char)line[i++]);
        if (hi < 0) break;
        int lo = hexval((unsigned char)line[i++]);
        if (lo < 0) break;

        if (n >= cap) break;
        buf[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* ----------------------------- Pointer/address arithmetic examples ----------------------------- */

/*
 * Example of "safe pointer field-address arithmetic":
 * compute an address inside router_ctx_t for feeding to a hypothetical PPP input.
 * This is analogous to: ppp_input(&ctx->ppp_state[OFFSET], skb)
 */
static uint8_t *ppp_state_ptr(router_ctx_t *ctx, size_t offset) {
    /* base + constant-like offset inside a known object */
    if (offset >= sizeof(ctx->ppp_state)) return NULL;
    return (uint8_t *)ctx->ppp_state + offset;
}

/* ----------------------------- ACL parsing logic ----------------------------- */

static void free_acl(router_ctx_t *ctx) {
    free(ctx->acl);
    ctx->acl = NULL;
    ctx->acl_count = 0;
    ctx->acl_capacity = 0;
}

/*
 * VULNERABLE: integer overflow on allocation size.
 * entry_count and entry_size come from external input.
 * If entry_count * entry_size overflows, malloc allocates too small,
 * then memcpy copies a larger amount -> heap overflow / memory corruption.
 */
static bool apply_acl_blob_vuln(router_ctx_t *ctx, const uint8_t *val, size_t vlen) {
    if (vlen < 8) return false;

    uint32_t entry_count = rd_le32(val + 0);
    uint32_t entry_size  = rd_le32(val + 4);

    /* (external input) + (constant): can wrap in 16-bit/32-bit if done carelessly */
    uint32_t header_plus = entry_size + 0x20u; /* SAFE? not checked here */
    (void)header_plus;

    /* INTENTIONAL BUG: multiplication may overflow */
    uint32_t total_bytes32 = entry_count * entry_size; /* overflow here */
    size_t total_bytes = (size_t)total_bytes32;

    if (vlen < 8 + total_bytes) {
        /* This check is also undermined by overflow (total_bytes got smaller). */
        return false;
    }

    /* INTENTIONAL BUG: allocate based on overflowed total_bytes */
    uint8_t *raw = (uint8_t *)malloc(total_bytes);
    if (!raw) return false;

    /* INTENTIONAL BUG: memcpy uses the same overflowed total_bytes, but a later parser
       might interpret entry_count and entry_size and read past raw. For demo, we do a
       second copy using a *different* computed size to highlight the danger. */
    memcpy(raw, val + 8, total_bytes);

    /* Additional bug pattern: parse loop uses entry_count and entry_size directly,
       causing OOB reads regardless of total_bytes. */
    for (uint32_t i = 0; i < entry_count; i++) {
        size_t off = (size_t)i * (size_t)entry_size; /* may overflow too */
        if (off + entry_size > total_bytes) {
            /* In real vulnerable code, this check might be missing. */
            break;
        }
        /* pretend we parse one entry blob */
        (void)raw[off];
    }

    free_acl(ctx);
    /* Not converting to acl_entry_t for brevity; pretend raw becomes ACL backing store */
    ctx->acl = (acl_entry_t *)raw;
    ctx->acl_capacity = total_bytes / sizeof(acl_entry_t);
    ctx->acl_count = 0;
    return true;
}

/*
 * SAFE: checked arithmetic + sanity limits.
 * Demonstrates safe handling for:
 *  - external input * external input (checked_mul_size)
 *  - external input + constant (checked_add_size)
 *  - pointer arithmetic only after bounds checks
 */
static bool apply_acl_blob_safe(router_ctx_t *ctx, const uint8_t *val, size_t vlen) {
    if (vlen < 8) return false;

    uint32_t entry_count_u32 = rd_le32(val + 0);
    uint32_t entry_size_u32  = rd_le32(val + 4);

    size_t entry_count = (size_t)entry_count_u32;
    size_t entry_size  = (size_t)entry_size_u32;

    /* sanity limits (router firmware style) */
    if (entry_count == 0 || entry_count > MAX_ACL_ENTRIES) return false;
    if (entry_size == 0 || entry_size > 256) return false;

    /* external input + constant with overflow check */
    size_t entry_size_plus_hdr = 0;
    if (!checked_add_size(entry_size, 0x20u, &entry_size_plus_hdr)) return false;
    (void)entry_size_plus_hdr;

    /* external input * external input with overflow check */
    size_t total_bytes = 0;
    if (!checked_mul_size(entry_count, entry_size, &total_bytes)) return false;
    if (total_bytes > MAX_ACL_BYTES) return false;

    /* bounds check against packet length */
    size_t need = 0;
    if (!checked_add_size((size_t)8, total_bytes, &need)) return false;
    if (vlen < need) return false;

    uint8_t *raw = (uint8_t *)malloc(total_bytes);
    if (!raw) return false;
    memcpy(raw, val + 8, total_bytes);

    /* safe parsing loop (bounds checked) */
    for (size_t i = 0; i < entry_count; i++) {
        size_t off = 0, off_plus = 0;
        if (!checked_mul_size(i, entry_size, &off)) { free(raw); return false; }
        if (!checked_add_size(off, entry_size, &off_plus)) { free(raw); return false; }
        if (off_plus > total_bytes) { free(raw); return false; }

        /* parse one entry blob safely */
        (void)raw[off];
    }

    free_acl(ctx);
    ctx->acl = (acl_entry_t *)raw;
    ctx->acl_capacity = total_bytes / sizeof(acl_entry_t);
    ctx->acl_count = 0;
    return true;
}

/* ----------------------------- TLV parsing ----------------------------- */

static bool parse_tlvs(router_ctx_t *ctx, const uint8_t *p, size_t plen, bool use_safe) {
    size_t off = 0;

    while (off < plen) {
        /* Need at least 3 bytes for TLV header */
        if (plen - off < 3) return false;

        uint8_t t = p[off];
        uint16_t l = rd_be16(p + off + 1);
        off += 3;

        /* external input + constant (off + l) with safe bounds check */
        if ((size_t)l > (plen - off)) return false;

        const uint8_t *val = p + off;
        size_t vlen = (size_t)l;

        switch (t) {
            case TLV_IFNAME: {
                /* safe: copy bounded */
                size_t n = (vlen < (MAX_IFNAME - 1)) ? vlen : (MAX_IFNAME - 1);
                memcpy(ctx->ifname, val, n);
                ctx->ifname[n] = '\0';
                break;
            }
            case TLV_ACL_BLOB: {
                bool ok = use_safe
                    ? apply_acl_blob_safe(ctx, val, vlen)
                    : apply_acl_blob_vuln(ctx, val, vlen);
                if (!ok) return false;
                break;
            }
            default:
                /* ignore unknown TLVs */
                break;
        }

        off += vlen;
    }

    return true;
}

/* ----------------------------- Main packet handler ----------------------------- */

static bool handle_mgmt_packet(router_ctx_t *ctx, const uint8_t *pkt, size_t len, bool use_safe) {
    if (len < sizeof(mgmt_hdr_t)) return false;

    const mgmt_hdr_t *hdr = (const mgmt_hdr_t *)pkt;

    if (hdr->ver != 1) return false;
    if (hdr->msg_type != MSG_SET_ACL) return false;

    /* external input + constant: payload_len + header size */
    size_t payload_len = (size_t)hdr->payload_len;
    size_t need = 0;
    if (!checked_add_size(sizeof(mgmt_hdr_t), payload_len, &need)) return false;
    if (need > len) return false;

    const uint8_t *payload = pkt + sizeof(mgmt_hdr_t);

    /* pointer/address arithmetic: get pointer inside ctx->ppp_state (safe field address) */
    uint8_t *ppp_ptr = ppp_state_ptr(ctx, 0x180u % sizeof(ctx->ppp_state));
    if (ppp_ptr) {
        /* safe constant write within object */
        ppp_ptr[0] ^= 0x5A;
    }

    return parse_tlvs(ctx, payload, payload_len, use_safe);
}

/* ----------------------------- Demo harness ----------------------------- */

static void init_ctx(router_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->ifname, "br0", MAX_IFNAME - 1);
    ctx->lan_ip   = 0xC0A80101u; /* 192.168.1.1 */
    ctx->lan_mask = 0xFFFFFF00u; /* /24 */
    ctx->wan_ip   = 0x0A000002u; /* 10.0.0.2 */
}

int main(void) {
    uint8_t pkt[MAX_PKT];
    size_t n = read_hex_stdin(pkt, sizeof(pkt));
    if (n == 0) {
        fprintf(stderr, "Provide a hex packet on stdin.\n");
        return 1;
    }

    router_ctx_t ctx;
    init_ctx(&ctx);

    /* Run both paths to illustrate difference */
    bool ok_vuln = handle_mgmt_packet(&ctx, pkt, n, false);
    printf("[vuln] handle_mgmt_packet: %s (ifname=%s, acl=%p)\n",
           ok_vuln ? "OK" : "FAIL", ctx.ifname, (void*)ctx.acl);

    free_acl(&ctx);
    init_ctx(&ctx);

    bool ok_safe = handle_mgmt_packet(&ctx, pkt, n, true);
    printf("[safe] handle_mgmt_packet: %s (ifname=%s, acl=%p)\n",
           ok_safe ? "OK" : "FAIL", ctx.ifname, (void*)ctx.acl);

    free_acl(&ctx);
    return 0;
}
