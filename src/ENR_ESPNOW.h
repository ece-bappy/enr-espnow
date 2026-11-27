#pragma once
/* Arduino-style wrapper around the ENR C API (enr.h). */
#include "enr.h"

#ifdef __cplusplus
#include <string.h>

class ENRClass {
public:
    enr_config_t config = ENR_CONFIG_DEFAULT(); /* edit fields before begin*() */

    /* Controller: call addNode() for every node, before or after begin. */
    bool beginController() { return enr_controller_begin(&config) == ESP_OK; }
    bool addNode(const uint8_t mac[6], const uint8_t kauth[32]) { return enr_controller_add_node(mac, kauth) == ESP_OK; }

    /* Node: the controller's STA MAC and this node's K_auth. */
    bool beginNode(const uint8_t controllerMac[6], const uint8_t kauth[32]) {
        return enr_node_begin(&config, controllerMac, kauth) == ESP_OK;
    }

    /* Controller: send(nodeMac, ...). Node: send(...) goes to the controller. */
    bool send(const uint8_t peer[6], const void *data, size_t len) { return enr_send(peer, data, len) == ESP_OK; }
    bool send(const void *data, size_t len) { return enr_send(nullptr, data, len) == ESP_OK; }
    bool send(const char *text) { return send(text, strlen(text)); }

    bool established(const uint8_t *peer = nullptr) { return enr_is_established(peer); }

    void onReceive(enr_recv_cb_t cb, void *ctx = nullptr) { enr_on_receive(cb, ctx); }
    void onEvent(enr_event_cb_t cb, void *ctx = nullptr) { enr_on_event(cb, ctx); }

    static void deriveNodeKey(const uint8_t master[32], const uint8_t nodeMac[6], uint8_t kauth[32]) {
        enr_derive_node_key(master, nodeMac, kauth);
    }
    static void selfMac(uint8_t mac[6]) { enr_self_mac(mac); }
    static const char *eventName(enr_event_t e) {
        static const char *n[] = {"ESTABLISHED", "REFRESHED", "REFRESH_FAILED", "DEGRADED", "LOST"};
        return (unsigned)e < 5 ? n[e] : "?";
    }
};

static ENRClass ENR;
#endif
