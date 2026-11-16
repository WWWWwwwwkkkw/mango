#ifndef HTTPD_COMMON_H
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
