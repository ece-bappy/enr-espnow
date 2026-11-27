#pragma once
/*
 * ENR: authenticated, forward-secret and post-compromise-secure messaging over ESP-NOW.
 *
 * Star topology: one controller, up to ENR_MAX_NODES nodes. Each node shares a 32-byte
 * authentication key K_auth with the controller. Sessions are set up with an authenticated
 * X25519 handshake, protected with AES-128-CCM, ratcheted every t_epoch_ms (forward secrecy)
 * and re-keyed with a fresh X25519 exchange every m epochs (post-compromise security).
 *
 * C API (ESP-IDF and Arduino). Arduino users can use the ENR object in ENR_ESPNOW.h instead.
 * Callbacks run on the ENR protocol task: keep them short and do not block.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ENR_MAX_NODES
#define ENR_MAX_NODES 8           /* controller session slots (about 1.5 kB RAM each) */
#endif
#define ENR_MAX_PAYLOAD 233       /* application bytes per message */

typedef struct {
    uint32_t t_epoch_ms;          /* symmetric ratchet interval (default 30000) */
    uint16_t m;                   /* epochs per X25519 refresh, T_refresh = m * t_epoch_ms (default 10) */
    uint8_t channel;              /* Wi-Fi channel; 0 = keep the current one (default 1) */
    bool backoff;                 /* exponential handshake retransmit back-off (default false) */
    uint32_t keepalive_ms;        /* node: liveness probe after this much silence; the node re-handshakes
                                     after 3x this with no valid frame from the controller (default 5000) */
} enr_config_t;

#define ENR_CONFIG_DEFAULT() { 30000, 10, 1, false, 5000 }

typedef enum {
    ENR_EV_ESTABLISHED = 0,       /* first session with the peer (or a new one after a reset) */
    ENR_EV_REFRESHED,             /* periodic X25519 refresh committed */
    ENR_EV_REFRESH_FAILED,        /* a refresh round ran out of retries (it is retried later) */
    ENR_EV_DEGRADED,              /* no successful refresh for 2 x T_refresh: PCS guarantee lapsed */
    ENR_EV_LOST,                  /* node: controller silent, session dropped, re-handshaking */
} enr_event_t;

typedef void (*enr_recv_cb_t)(const uint8_t peer[6], const uint8_t *data, size_t len, void *ctx);
typedef void (*enr_event_cb_t)(const uint8_t peer[6], enr_event_t ev, void *ctx);

/* Derive a node's K_auth from a 32-byte master secret (for provisioning). Keep the master secret
 * off the nodes: give each node only its own K_auth. */
void enr_derive_node_key(const uint8_t master[32], const uint8_t node_mac[6], uint8_t kauth[32]);

/* Start as controller. Brings up Wi-Fi (STA) and ESP-NOW if they are not running yet. */
esp_err_t enr_controller_begin(const enr_config_t *cfg);
/* Allow a node. Can be called before or after begin. */
esp_err_t enr_controller_add_node(const uint8_t node_mac[6], const uint8_t kauth[32]);

/* Start as node, paired with the controller at ctrl_mac. */
esp_err_t enr_node_begin(const enr_config_t *cfg, const uint8_t ctrl_mac[6], const uint8_t kauth[32]);

/* Queue an encrypted message. Controller: peer = node MAC. Node: peer = NULL (the controller).
 * Returns ESP_ERR_INVALID_STATE if there is no session with the peer yet, ESP_ERR_INVALID_SIZE
 * if len > ENR_MAX_PAYLOAD, ESP_ERR_NO_MEM if the send queue is full. */
esp_err_t enr_send(const uint8_t *peer, const void *data, size_t len);

/* Controller: peer = node MAC. Node: peer = NULL. */
bool enr_is_established(const uint8_t *peer);

void enr_on_receive(enr_recv_cb_t cb, void *ctx);
void enr_on_event(enr_event_cb_t cb, void *ctx);

/* This device's STA MAC address. */
void enr_self_mac(uint8_t mac[6]);

#ifdef __cplusplus
}
#endif
