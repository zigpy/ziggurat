/*
 * RCP platform configuration, from the ESP-IDF ot_rcp example
 */

#pragma once

#include "esp_openthread_types.h"

#define ESP_OPENTHREAD_DEFAULT_RADIO_CONFIG()                   \
    {                                                           \
        .radio_mode = RADIO_MODE_NATIVE,                        \
    }

#if CONFIG_OPENTHREAD_RCP_UART
#if CONFIG_OPENTHREAD_UART_PIN_MANUAL
#define OPENTHREAD_RCP_UART_RX_PIN CONFIG_OPENTHREAD_UART_RX_PIN
#define OPENTHREAD_RCP_UART_TX_PIN CONFIG_OPENTHREAD_UART_TX_PIN
#else
#define OPENTHREAD_RCP_UART_RX_PIN UART_PIN_NO_CHANGE
#define OPENTHREAD_RCP_UART_TX_PIN UART_PIN_NO_CHANGE
#endif

#define ESP_OPENTHREAD_DEFAULT_HOST_CONFIG()                    \
    {                                                           \
        .host_connection_mode = HOST_CONNECTION_MODE_RCP_UART,  \
        .host_uart_config = {                                   \
            .port = 0,                                          \
            .uart_config =                                      \
                {                                               \
                    .baud_rate = 460800,                        \
                    .data_bits = UART_DATA_8_BITS,              \
                    .parity = UART_PARITY_DISABLE,              \
                    .stop_bits = UART_STOP_BITS_1,              \
                    .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,      \
                    .rx_flow_ctrl_thresh = 0,                   \
                    .source_clk = UART_SCLK_DEFAULT,            \
                },                                              \
            .rx_pin = OPENTHREAD_RCP_UART_RX_PIN,               \
            .tx_pin = OPENTHREAD_RCP_UART_TX_PIN,               \
        },                                                      \
    }
#else // CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
#define ESP_OPENTHREAD_DEFAULT_HOST_CONFIG()                        \
    {                                                               \
        .host_connection_mode = HOST_CONNECTION_MODE_RCP_USB,       \
        .host_usb_config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT(), \
    }
#endif

#define ESP_OPENTHREAD_DEFAULT_PORT_CONFIG()    \
    {                                           \
        .storage_partition_name = "nvs",        \
        .netif_queue_size = 10,                 \
        .task_queue_size = 10,                  \
    }
