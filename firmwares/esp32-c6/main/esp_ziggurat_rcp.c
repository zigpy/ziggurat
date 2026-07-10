/*
 * OpenThread RCP with embedded Ziggurat, from the ESP-IDF ot_rcp example.
 */

#include "esp_event.h"
#include "esp_openthread.h"
#include "esp_vfs_eventfd.h"
#include "nvs_flash.h"

#include "esp_ot_config.h"

#if !SOC_IEEE802154_SUPPORTED
#error "RCP is only supported for the SoCs which have IEEE 802.15.4 module"
#endif

void app_main(void)
{
    // Used eventfds: the ot task queue and the radio driver.
    esp_vfs_eventfd_config_t eventfd_config = {
        .max_fds = 2,
    };

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));

    static esp_openthread_config_t config = {
        .netif_config = {0},
        .platform_config = {
            .radio_config = ESP_OPENTHREAD_DEFAULT_RADIO_CONFIG(),
            .host_config = ESP_OPENTHREAD_DEFAULT_HOST_CONFIG(),
            .port_config = ESP_OPENTHREAD_DEFAULT_PORT_CONFIG(),
        },
    };

    ESP_ERROR_CHECK(esp_openthread_start(&config));
}
