/*
 * ENR node: connects to the controller and sends a reading every 2 seconds.
 * Pair it with the Controller example. Get the key for this node with the KeyTool example.
 */
#include <ENR_ESPNOW.h>

static const uint8_t CONTROLLER_MAC[6] = {0x24, 0x6f, 0x28, 0x00, 0x00, 0x00};  // CHANGE ME
static const uint8_t KAUTH[32] = {  // CHANGE ME: this node's K_auth, printed by KeyTool
    0};

static void onMessage(const uint8_t *, const uint8_t *data, size_t len, void *) {
    Serial.printf("controller says: %.*s\n", (int)len, (const char *)data);
}

static void onEvent(const uint8_t *, enr_event_t ev, void *) {
    Serial.printf("event %s\n", ENRClass::eventName(ev));
}

void setup() {
    Serial.begin(115200);
    delay(500);
    ENR.onReceive(onMessage);
    ENR.onEvent(onEvent);
    if (!ENR.beginNode(CONTROLLER_MAC, KAUTH)) Serial.println("ENR start failed");
}

void loop() {
    static uint32_t n;
    if (ENR.established()) {
        char msg[48];
        float temp = 20.0f + (n % 50) / 10.0f;  // stand-in for a sensor
        int len = snprintf(msg, sizeof msg, "reading %lu: %.1f C", (unsigned long)n++, temp);
        ENR.send(msg, len);
    }
    delay(2000);
}
