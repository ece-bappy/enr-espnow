# ESP-IDF component: add this repository under components/ (or via EXTRA_COMPONENT_DIRS).
idf_component_register(SRCS "src/enr_core.c" "src/enr_proto.c" "src/enr_crypto.c" "src/monocypher.c"
                       INCLUDE_DIRS "src"
                       REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_timer mbedtls)
