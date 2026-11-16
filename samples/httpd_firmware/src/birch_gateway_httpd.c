#include "httpd_common.h"

NOINLINE int plan_upload(uint32_t a, uint32_t b, uint32_t *bytes)
{
    if (b != 0u && a > UINT32_MAX / b) return 413;
    uint32_t size = a * b;
    *bytes = size;
    if (size == 0u || size > STAGING_QUOTA) return 413;
    return 200;
}

NOINLINE int handle_upload(const char *query)
{
    uint32_t a, b, bytes;
    if (!query_u32(query, "chunk_count", &a) || !query_u32(query, "chunk_bytes", &b)) return 400;
    int status = plan_upload(a, b, &bytes);
    if (status != 200) return status;
    return reserve_staging(bytes);
}

NOINLINE int dispatch_request(char *target)
{
    if (strcmp(target, "/status") == 0) {
        puts("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbirch_gateway management service");
        return 200;
    }
    char *query = strchr(target, '?');
    if (!query) return 404;
    *query++ = '\0';
    if (strcmp(target, "/api/upload") != 0) return 404;
    return handle_upload(query);
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
