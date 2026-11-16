"""Generate deterministic, fictional firmware HTTP arithmetic benchmarks."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = [
    ("cedar_router", "upload", "chunk_count", "chunk_bytes", "plan_upload", "mul", "", True, (65537, 65537), 131073,
     "Chunked upgrade staging: 32-bit product wraps before the staging quota check."),
    ("harbor_nas", "restore", "config_bytes", "index_bytes", "plan_restore", "add", "", True, (4294963200, 8192), 4096,
     "Configuration archive restore: combined section lengths wrap before allocation."),
    ("meadow_nvr", "export", "frame_count", "frame_bytes", "plan_export", "mul", "if (b > 65536u) return 400;", True, (1048577, 4096), 4096,
     "Recording export: frame size is bounded but frame count is unchecked."),
    ("birch_gateway", "upload", "chunk_count", "chunk_bytes", "plan_upload", "mul", "if (b != 0u && a > UINT32_MAX / b) return 413;", False, (65537, 65537), None,
     "Checks multiplication before calculating the allocation size."),
    ("coral_ap", "restore", "config_bytes", "index_bytes", "plan_restore", "add", "if (a > UINT32_MAX - b) return 413;", False, (4294963200, 8192), None,
     "Checks addition against remaining uint32 capacity."),
    ("willow_camera", "snapshot", "rows", "row_bytes", "plan_snapshot", "mul", "if (a > 2048u || b > 256u) return 413;", False, (65537, 65537), None,
     "Independent input bounds keep the product below 524288."),
    ("slate_switch", "backup", "config_bytes", "log_bytes", "plan_backup", "wide_add", "", False, (4294963200, 8192), None,
     "Addition is widened to uint64 and validated before narrowing."),
    ("amber_mesh", "peers", "peer_count", "record_bytes", "plan_peers", "wide_mul", "", False, (65537, 65537), None,
     "Product uses uint64 and is validated before narrowing."),
    ("brook_sensor", "history", "record_count", "scale_bits", "plan_history", "shl", "if (b > 15u || a > (UINT32_MAX >> b)) return 413;", False, (2147483648, 1), None,
     "Shift count and discarded high bits are checked before shifting."),
    ("spruce_hub", "bundle", "manifest_bytes", "payload_bytes", "plan_bundle", "add", "if (a > 65536u || b > 524288u) return 413;", False, (4294963200, 8192), None,
     "Both request lengths are bounded before addition."),
]

HEADER = r'''#ifndef HTTPD_COMMON_H
#define HTTPD_COMMON_H
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define NOINLINE __attribute__((noinline))
#define STAGING_QUOTA 1048576u

/* inetd-style request front end; one request per process, no listening socket. */
NOINLINE int read_http_target(char *target, size_t capacity)
{
    char line[2048], method[16], version[16], parsed[1024];
    if (!fgets(line, sizeof(line), stdin)) return 400;
    if (sscanf(line, "%15s %1023s %15s", method, parsed, version) != 3) return 400;
    if (strcmp(method, "POST") && strcmp(method, "GET")) return 405;
    if (strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0")) return 400;
    if (strlen(parsed) >= capacity) return 414;
    strcpy(target, parsed);
    return 200;
}

NOINLINE int query_u32(const char *query, const char *key, uint32_t *out)
{
    size_t n = strlen(key);
    const char *p = query;
    while (*p) {
        if (strncmp(p, key, n) == 0 && p[n] == '=') {
            const char *value = p + n + 1;
            char *end;
            unsigned long long number;
            if (*value < '0' || *value > '9') return 0;
            errno = 0;
            number = strtoull(value, &end, 10);
            if (errno || number > UINT32_MAX || (*end && *end != '&')) return 0;
            *out = (uint32_t)number;
            return 1;
        }
        p = strchr(p, '&');
        if (!p) break;
        ++p;
    }
    return 0;
}

NOINLINE int reserve_staging(uint32_t bytes)
{
    void *buffer;
    if (bytes == 0u || bytes > STAGING_QUOTA) return 413;
    buffer = malloc(bytes);
    if (!buffer) return 503;
    memset(buffer, 0, bytes);
    /* Hardware transfer / flash programming is outside this benchmark. */
    printf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nreserved=%" PRIu32 "\n", bytes);
    free(buffer);
    return 200;
}
#endif
'''


def generate():
    src = ROOT / "src"
    requests = ROOT / "requests"
    src.mkdir(exist_ok=True)
    requests.mkdir(exist_ok=True)
    (src / "httpd_common.h").write_text(HEADER, encoding="utf-8")
    manifest = []
    for name, route, key_a, key_b, func, op, guard, vulnerable, boundary, wrapped, reason in CASES:
        binary = name + "_httpd"
        if op.startswith("wide"):
            operator = "+" if op == "wide_add" else "*"
            calculation = f"uint64_t wide = (uint64_t)a {operator} (uint64_t)b;\n    if (wide > STAGING_QUOTA) return 413;\n    uint32_t size = (uint32_t)wide;"
        else:
            operator = {"add": "+", "mul": "*", "shl": "<<"}[op]
            calculation = f"uint32_t size = a {operator} b;"
        code = f'''#include "httpd_common.h"

NOINLINE int {func}(uint32_t a, uint32_t b, uint32_t *bytes)
{{
    {guard}
    {calculation}
    *bytes = size;
    if (size == 0u || size > STAGING_QUOTA) return 413;
    return 200;
}}

NOINLINE int handle_{route}(const char *query)
{{
    uint32_t a, b, bytes;
    if (!query_u32(query, "{key_a}", &a) || !query_u32(query, "{key_b}", &b)) return 400;
    int status = {func}(a, b, &bytes);
    if (status != 200) return status;
    return reserve_staging(bytes);
}}

NOINLINE int dispatch_request(char *target)
{{
    if (strcmp(target, "/status") == 0) {{
        puts("HTTP/1.1 200 OK\\r\\nConnection: close\\r\\n\\r\\n{ name } management service");
        return 200;
    }}
    char *query = strchr(target, '?');
    if (!query) return 404;
    *query++ = '\\0';
    if (strcmp(target, "/api/{route}") != 0) return 404;
    return handle_{route}(query);
}}

int main(void)
{{
    char target[1024];
    int status = read_http_target(target, sizeof(target));
    if (status == 200) status = dispatch_request(target);
    if (status != 200)
        printf("HTTP/1.1 %d Rejected\\r\\nConnection: close\\r\\n\\r\\nrequest rejected\\n", status);
    return status == 200 ? 0 : 1;
}}
'''
        (src / f"{binary}.c").write_text(code, encoding="utf-8")
        normal = (16, 2) if op == "shl" else (16, 32)
        for label, values in (("normal", normal), ("boundary", boundary)):
            request = f"POST /api/{route}?{key_a}={values[0]}&{key_b}={values[1]} HTTP/1.1\r\nHost: device.local\r\nContent-Length: 0\r\n\r\n"
            (requests / f"{binary}_{label}.http").write_bytes(request.encode("ascii"))
        mathematical = boundary[0] + boundary[1] if "add" in op else (boundary[0] << boundary[1] if op == "shl" else boundary[0] * boundary[1])
        manifest.append(dict(binary=binary, source=f"src/{binary}.c", target_function=func,
                             expected_cwe190=vulnerable, operation=op, reason=reason,
                             boundary_inputs=boundary, mathematical_result=mathematical,
                             expected_boundary_status=200 if vulnerable else 413,
                             expected_boundary_reserved=wrapped,
                             expected_normal_reserved=64 if op == "shl" else (48 if "add" in op else 512)))
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    generate()
