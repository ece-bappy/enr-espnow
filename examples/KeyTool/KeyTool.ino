/*
 * ENR KeyTool: prints this board's MAC address and derives a node key from a master secret.
 *
 * 1. Flash this sketch to every board and note each MAC address from the Serial Monitor.
 * 2. Pick a random 32-byte MASTER secret (below) and keep it private. Only the controller
 *    sketch, or your provisioning PC, should hold it. Each node gets only its own K_auth.
 * 3. Set NODE_MAC to a node's MAC and copy the printed K_auth into that node's sketch.
 */
#include <ENR_ESPNOW.h>
#include <WiFi.h>

static const uint8_t MASTER[32] = {  // CHANGE ME: generate with e.g. `openssl rand -hex 32`
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t NODE_MAC[6] = {0x24, 0x6f, 0x28, 0x00, 0x00, 0x01};  // CHANGE ME

static void printHex(const char *label, const uint8_t *b, size_t n) {
    Serial.print(label);
    for (size_t i = 0; i < n; i++) Serial.printf("0x%02x%s", b[i], i + 1 < n ? ", " : "\n");
}

void setup() {
    Serial.begin(115200);
    delay(500);
    WiFi.mode(WIFI_STA);
    uint8_t mac[6], kauth[32];
    ENR.selfMac(mac);
    printHex("This board's MAC: ", mac, 6);
    ENR.deriveNodeKey(MASTER, NODE_MAC, kauth);
    printHex("K_auth for NODE_MAC: ", kauth, 32);
}

void loop() {}
