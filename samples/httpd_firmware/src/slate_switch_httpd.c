#include "httpd_common.h"

NOINLINE int plan_backup(uint32_t a, uint32_t b, uint32_t *bytes)
{
    
    uint64_t wide = (uint64_t)a + (uint64_t)b;
    if (wide > STAGING_QUOTA) return 413;
    uint32_t size = (uint32_t)wide;
    *bytes = size;
    if (size == 0u || size > STAGING_QUOTA) return 413;
    return 200;
}

NOINLINE int handle_backup(const char *query)
{
    uint32_t a, b, bytes;
    if (!query_u32(query, "config_bytes", &a) || !query_u32(query, "log_bytes", &b)) return 400;
    int status = plan_backup(a, b, &bytes);
    if (status != 200) return status;
    return reserve_staging(bytes);
}

NOINLINE int dispatch_request(char *target)
{
    if (strcmp(target, "/status") == 0) {
        puts("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nslate_switch management service");
        return 200;
    }
    char *query = strchr(target, '?');
    if (!query) return 404;
    *query++ = '\0';
    if (strcmp(target, "/api/backup") != 0) return 404;
    return handle_backup(query);
}

int main(void)
{
    char target[1024];
    int status = read_http_target(target, sizeof(target));
    if (status == 200) status = dispatch_request(target);
    if (status != 200)
        printf("HTTP/1.1 %d Rejected\r\nConnection: close\r\n\r\nrequest rejected\n", status);
    return status == 200 ? 0 : 1;
}
