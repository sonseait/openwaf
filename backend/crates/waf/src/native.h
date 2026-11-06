#ifndef OPENWAF_NATIVE_H
#define OPENWAF_NATIVE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct ow_finding { uint32_t rule_id; int32_t phase; int32_t severity; };
struct ow_report { struct ow_finding findings[32]; uint32_t count; uint32_t truncated; uint32_t body_inspected; };
struct ow_engine;
struct ow_header {
    const unsigned char *name;
    size_t name_len;
    const unsigned char *value;
    size_t value_len;
};
struct ow_engine *ow_engine_new(const char *path, int mode);
struct ow_engine *ow_engine_policy_new(const char *path, int mode, unsigned int paranoia, const uint32_t *exclusions, size_t count);
int ow_engine_exception(struct ow_engine *engine, uint32_t rule_id, const char *target, uint64_t expires_ms);
void ow_engine_free(struct ow_engine *engine);
int ow_inspect(struct ow_engine *engine, const char *uri, const char *method,
               const char *version, const char *client, int client_port,
               const char *server, int server_port,
               const struct ow_header *headers, size_t header_count,
               const unsigned char *body, size_t body_len, int inspect_body, struct ow_report *report);
#ifdef __cplusplus
}
#endif
#endif
