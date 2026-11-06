/* Private ABI: native objects never leave their owning Rust worker thread. */
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/rule_with_actions.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <chrono>
#include <memory>
#include "native.h"
using namespace modsecurity;

// RuleMessage changed representation between distro 3.0.9 and current v3.
// Compile against the installed headers, copying only numeric metadata.
template<class T> static auto rule_id(const T &m, int) -> decltype(m.m_rule.m_ruleId) { return m.m_rule.m_ruleId; }
template<class T> static auto rule_id(const T &m, long) -> decltype(m.m_ruleId) { return m.m_ruleId; }
template<class T> static auto rule_phase(const T &m, int) -> decltype(m.getPhase()) { return m.getPhase()+1; }
template<class T> static auto rule_phase(const T &m, long) -> decltype(m.m_phase) { return m.m_phase+1; }

struct ow_engine {
    ModSecurity *modsec;
    RulesSet *rules;
    struct exception {uint32_t id; std::string target; uint64_t expiry;};
    std::vector<exception> exceptions;
};


/* Matched rule messages may contain credentials or body/query values. */
static void discard_sensitive_log(void *context, const void *message) {
    (void)context;
    (void)message;
}

void ow_engine_free(struct ow_engine *engine) {
    if (!engine) return;
    if (engine->rules) msc_rules_cleanup(engine->rules);
    if (engine->modsec) msc_cleanup(engine->modsec);
    delete engine;
}

struct ow_engine *ow_engine_new(const char *path, int mode) {
    return ow_engine_policy_new(path, mode, 1, NULL, 0);
}

/* All configuration buffers are generated from bounded integers, never request
 * data. Parser input is borrowed only for the call; RulesSet owns parsed rules.
 * Failure cleans partial allocations; all objects stay on the owning worker. */
struct ow_engine *ow_engine_policy_new(const char *path, int mode, unsigned int paranoia,
                                      const uint32_t *exclusions, size_t count) try {
    if (mode < 0 || mode > 2 || paranoia < 1 || paranoia > 4 || count > 32 || (count && !exclusions)) return NULL;
    struct ow_engine *engine = new (std::nothrow) ow_engine{};
    std::unique_ptr<ow_engine, decltype(&ow_engine_free)> owner(engine, ow_engine_free);
    const char *error = NULL;
    const char *setting = mode == 0 ? "SecRuleEngine Off" : mode == 1 ? "SecRuleEngine DetectionOnly" : "SecRuleEngine On";
    char policy[256];
    int size;
    if (!engine) return NULL;
    engine->modsec = msc_init();
    engine->rules = msc_create_rules_set();
    if (!engine->modsec || !engine->rules) goto fail;
    msc_set_connector_info(engine->modsec, "openwaf-integration/0.1");
    msc_set_log_cb(engine->modsec, discard_sensitive_log);
    /* RulesSet::merge uses the first defined SecRuleEngine, not the last. */
    if (msc_rules_add(engine->rules, setting, &error) < 0) goto fail;
    size = snprintf(policy, sizeof(policy),
        "SecAction %cid:100000,phase:1,pass,nolog,setvar:tx.paranoia_level=%u,setvar:tx.blocking_paranoia_level=%u,setvar:tx.executing_paranoia_level=%u%c", 34, paranoia, paranoia, paranoia, 34);
    if (size < 0 || (size_t)size >= sizeof(policy)) goto fail;
    if (msc_rules_add(engine->rules, policy, &error) < 0) goto fail;
    if (msc_rules_add_file(engine->rules, path, &error) < 0) goto fail;
    for (size_t i = 0; i < count; ++i) {
        if (exclusions[i] < 900000 || exclusions[i] > 999999) goto fail;
        size = snprintf(policy, sizeof(policy), "SecRuleRemoveById %u", exclusions[i]);
        if (size < 0 || (size_t)size >= sizeof(policy)) goto fail;
        if (msc_rules_add(engine->rules, policy, &error) < 0) goto fail;
    }
    return owner.release();
fail:
    /* msc_rules_add[_file] returns strdup-allocated parser errors on failure. */
    free((void *)error);
    return NULL;
} catch (...) { return NULL; }

// Targets are validated by the schema; native code stores owned copies.
int ow_engine_exception(struct ow_engine *engine, uint32_t id, const char *target, uint64_t expiry) try {
    if (!engine || !target || engine->exceptions.size() >= 32) return -1;
    bool found=false;
    for (int phase=0;phase<8;phase++) {
        for (const auto &rule: engine->rules->m_rulesSetPhases[phase]->m_rules) {
            const auto *action=dynamic_cast<const RuleWithActions *>(rule.get());
            if (action && action->m_ruleId == id) found=true;
        }
    }
    if (!found) return -1;
    engine->exceptions.push_back({id,target,expiry});
    return 0;
} catch (...) { return -1; }

/* Return 0 (allow), 403 (disruptive intervention), or -1 (inspection error).
 * Intervention strings are allocated by libmodsecurity using malloc; free them
 * here, never expose matched data or native allocation ownership to Rust. */
static int ow_intervention(Transaction *tx) {
    ModSecurityIntervention result = {};
    result.status = 200;
    int present = msc_intervention(tx, &result);
    int decision = present && result.disruptive ? 403 : 0;
    free(result.url);
    free(result.log);
    return decision;
}

int ow_inspect(struct ow_engine *engine, const char *uri, const char *method,
               const char *version, const char *client, int client_port,
               const char *server, int server_port,
               const struct ow_header *headers, size_t header_count,
               const unsigned char *body, size_t body_len, int inspect_body, struct ow_report *report) try {
    Transaction *tx = msc_new_transaction(engine->modsec, engine->rules, NULL);
    if (!tx) return -1;
    std::unique_ptr<Transaction, decltype(&msc_transaction_cleanup)> owner(tx, msc_transaction_cleanup);
    int decision = -1;
    bool body_inspected = false;
    for (const auto &e:engine->exceptions) {
        uint64_t now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (e.expiry && e.expiry<=now) continue;
        if (e.target.empty()) tx->m_ruleRemoveById.push_back(e.id);
        else tx->m_ruleRemoveTargetById.push_back({e.id,e.target});
    }
    if (msc_process_connection(tx, client, client_port, server, server_port) < 0)
        goto done;
    if (msc_process_uri(tx, uri, method, version) < 0) goto done;
    for (size_t i = 0; i < header_count; ++i) {
        if (msc_add_n_request_header(tx, headers[i].name, headers[i].name_len,
                                    headers[i].value, headers[i].value_len) < 0)
            goto done;
    }
    if (msc_process_request_headers(tx) < 0) goto done;
    decision = ow_intervention(tx);
    if (decision) goto done;
    if (!inspect_body) tx->m_requestBodyAccess = 0;
    decision = -1;
    if (inspect_body && body_len && msc_append_request_body(tx, body, body_len) < 0) goto done;
    if (msc_process_request_body(tx) < 0) goto done;
    body_inspected = inspect_body != 0;
    decision = ow_intervention(tx);
done:
    if (report) {
        report->count = 0;
        report->truncated = 0;
        report->body_inspected = body_inspected ? 1 : 0;
        for (const auto &message : tx->m_rulesMessages) {
            if (report->count >= 32) { report->truncated = 1; break; }
            int64_t id = rule_id(message,0);
            if (id > 0 && (uint64_t)id <= UINT32_MAX) {
                auto &finding = report->findings[report->count++];
                finding.rule_id = (uint32_t)rule_id(message,0);
                finding.phase = rule_phase(message,0);
                finding.severity = message.m_severity;
            }
        }
    }
    return decision;
} catch (...) { return -1; }
