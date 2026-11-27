/*
 * ENR controller: accepts the listed nodes, prints their messages and answers each one.
 * Pair it with the Node example. Get MAC addresses and keys with the KeyTool example.
 */
#include <ENR_ESPNOW.h>

static const uint8_t MASTER[32] = {  // CHANGE ME (same secret as in KeyTool)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

static const uint8_t NODES[][6] = {  // CHANGE ME: your nodes' STA MAC addresses
    {0x24, 0x6f, 0x28, 0x00, 0x00, 0x01},
};

static void onMessage(const uint8_t peer[6], const uint8_t *data, size_t len, void *) {
    Serial.printf("from %02x:%02x:%02x:%02x:%02x:%02x: %.*s\n", peer[0], peer[1], peer[2], peer[3], peer[4],
                  peer[5], (int)len, (const char *)data);
    ENR.send(peer, "ack", 3);  // safe to call from the callback: it only queues the message
}

static void onEvent(const uint8_t peer[6], enr_event_t ev, void *) {
    Serial.printf("event %s for %02x:...:%02x\n", ENRClass::eventName(ev), peer[0], peer[5]);
}

void setup() {
    Serial.begin(115200);
    delay(500);
    // Optional tuning (defaults: 30 s epochs, X25519 refresh every 10 epochs = 5 min).
    // ENR.config.t_epoch_ms = 30000; ENR.config.m = 10; ENR.config.channel = 1;
    for (auto &mac : NODES) {
        uint8_t kauth[32];
        ENR.deriveNodeKey(MASTER, mac, kauth);
        ENR.addNode(mac, kauth);
    }
    ENR.onReceive(onMessage);
    ENR.onEvent(onEvent);
    if (!ENR.beginController()) Serial.println("ENR start failed");
    uint8_t me[6];
    ENR.selfMac(me);
    Serial.printf("controller MAC %02x:%02x:%02x:%02x:%02x:%02x\n", me[0], me[1], me[2], me[3], me[4], me[5]);
}

void loop() { delay(1000); }
