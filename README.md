# ENR ESP-NOW

Authenticated, forward-secret and post-compromise-secure messaging for ESP-NOW, as an Arduino / PlatformIO / ESP-IDF library.

ESP-NOW's built-in encryption uses one static key per peer and has no replay protection. If an attacker extracts that key, every past and future message can be read. ENR adds:

- **Mutual authentication.** An X25519 handshake authenticated with a per-node pre-shared key (K_auth).
- **Confidentiality, integrity and replay protection.** AES-128-CCM with a 64-entry sliding replay window.
- **Forward secrecy.** Message keys are ratcheted forward every `t_epoch_ms` (default 30 s), and old keys are erased.
- **Post-compromise security.** A fresh X25519 exchange every `m` epochs (default every 5 min). If a device's RAM is dumped, the attacker loses access after the next refresh.
- **DoS resistance.** Stateless cookies, an HMAC check before any public-key work, and a per-node rate limit on DH operations.
- **Liveness.** Nodes detect a rebooted or vanished controller and re-handshake automatically.

The protocol's handshake, ratchet and refresh were verified with the Tamarin prover. Measurements were taken on ESP32 and ESP32-S3 hardware. A full refresh costs about 42 ms of compute per side on an ESP32-S3, and 48 ms on a classic ESP32.

## Topology

One **controller** talks to up to `ENR_MAX_NODES` (default 8) **nodes**. Each node shares a 32-byte key `K_auth` with the controller. The usual way to set this up is to keep one master secret on the controller, derive each node's key from it, and flash each node with only its own key.

## Arduino quick start

1. Install the library: in the Library Manager, or as a ZIP via *Sketch → Include Library → Add .ZIP Library*.
2. Flash **KeyTool** to each board and note its MAC address.
3. Pick a random 32-byte master secret (`openssl rand -hex 32`). Put it in KeyTool to print each node's `K_auth`.
4. Fill in **Controller** (master secret plus node MACs) and **Node** (controller MAC plus that node's `K_auth`), then flash them.

```cpp
#include <ENR_ESPNOW.h>

// node
ENR.onReceive([](const uint8_t *, const uint8_t *data, size_t len, void *) { /* ... */ });
ENR.beginNode(CONTROLLER_MAC, KAUTH);
if (ENR.established()) ENR.send("hello", 5);

// controller
ENR.addNode(NODE_MAC, KAUTH_OF_NODE);
ENR.beginController();
ENR.send(NODE_MAC, data, len);
```

## PlatformIO

```ini
lib_deps = https://github.com/ece-bappy/enr-espnow.git
```

Works with `framework = arduino` and `framework = espidf`.

## ESP-IDF (C API)

Clone the repository into `components/enr-espnow` and include `enr.h`:

```c
enr_config_t cfg = ENR_CONFIG_DEFAULT();
enr_controller_add_node(node_mac, kauth);
enr_on_receive(on_rx, NULL);
ESP_ERROR_CHECK(enr_controller_begin(&cfg));
enr_send(node_mac, buf, len);
```

See [`src/enr.h`](src/enr.h) for the full API.

## Configuration

| Field (`ENR.config.*` / `enr_config_t`) | Default | Meaning |
|---|---|---|
| `t_epoch_ms` | 30000 | Ratchet interval: the forward-secrecy granularity. |
| `m` | 10 | Epochs per X25519 refresh. `T_refresh = m · t_epoch_ms` is the post-compromise recovery window. |
| `channel` | 1 | Wi-Fi channel, which must match on all devices. 0 keeps the current channel, for example when the STA is connected to an AP. |
| `backoff` | false | Exponential handshake retransmit (0.5, 1, 2, 4 s). In our tests it cut failed refreshes 4–5× under bursty loss, at the cost of slower worst-case completion. |
| `keepalive_ms` | 5000 | A node probes after this much silence and re-handshakes after 3× this. |

Compile-time options (`-D`): `ENR_MAX_NODES`, `ENR_T_HS_MS`, `ENR_R_MAX`, `ENR_T_GRACE_MS`, `ENR_W_E`, `ENR_T_RL_MS`, `ENR_T_SLOT_MS`.

`T_refresh` must be at least 4 s, because shorter values collide with the DH rate limit.

## Events

`ENR_EV_ESTABLISHED`, `ENR_EV_REFRESHED`, `ENR_EV_REFRESH_FAILED`, `ENR_EV_DEGRADED` (no successful refresh for 2 · T_refresh, so the post-compromise guarantee has lapsed; alert on this), and `ENR_EV_LOST` (node only: controller silent, re-handshaking).

## Notes and limits

- **Payload:** up to 233 bytes per message. Delivery is best-effort, like ESP-NOW itself: there are no retries or acknowledgements for application data.
- **Callbacks** run on the ENR task. Keep them short. Calling `ENR.send()` from a callback is fine, because it only queues the message.
- **ESP-NOW receive callback:** the library registers its own, so don't use other ESP-NOW receivers in the same sketch.
- **Key storage:** store `K_auth` and the master secret in protected storage (NVS encryption, flash encryption or the eFuse HMAC peripheral) in a real deployment. The examples hard-code them only for clarity.
- **Tested** on ESP32 (D0WD-V3) and ESP32-S3 with arduino-esp32 2.0.17 (ESP-IDF 4.4) and ESP-IDF 5.4. Other ESP32 variants should work but are untested.

## Licence

MIT, see [LICENSE](LICENSE). Bundles Monocypher 4.0.2 (BSD-2-Clause OR CC0-1.0), see [THIRD_PARTY.md](THIRD_PARTY.md).
