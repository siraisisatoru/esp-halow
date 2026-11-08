/*
 * Copyright 2021-2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmhal_os.h"
#include "mmosal.h"

#include "sdkconfig.h"
#include "esp_system.h"
#include "driver/gpio.h"

void mmhal_init(void)
{
    /* We initialise the MM_RESET_N Pin here so that we can hold the MM6108 in reset regardless of
     * whether the mmhal_wlan_init/deinit function have been called. This allows us to ensure the
     * chip is in its lowest power state. You may want to revise this depending on your particular
     * hardware configuration. */
    gpio_config_t io_conf = {};
    io_conf.intr_type = GPIO_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = (1ULL << CONFIG_MM_RESET_N);
    io_conf.pull_down_en = 0;
    io_conf.pull_up_en = 0;
    gpio_config(&io_conf);

    gpio_set_level(CONFIG_MM_RESET_N, 0);

    /* A software restart (for example after a panic) resets the CPU but not the GPIO interrupt
     * configuration, and the transceiver held in reset can leave its SPI IRQ line low. The pin
     * may still be set up as a level interrupt from before the restart, which would fire
     * continuously, with no handler, as soon as the ISR service below enables GPIO interrupts.
     * Disable the transceiver's interrupt pins first; the HAL enables them when it is ready. */
    gpio_intr_disable(CONFIG_MM_SPI_IRQ);
    gpio_set_intr_type(CONFIG_MM_SPI_IRQ, GPIO_INTR_DISABLE);
#ifdef CONFIG_HALOW_PS_MODE
    gpio_intr_disable(CONFIG_MM_BUSY);
    gpio_set_intr_type(CONFIG_MM_BUSY, GPIO_INTR_DISABLE);
#endif /* CONFIG_HALOW_PS_MODE */

    /* Initialise the gpio ISR handler service. This allows per-pin GPIO interrupt handlers and is
     * what is used to register all the wlan related interrupt. */
    gpio_install_isr_service(0);
}

void mmhal_log_write(const uint8_t *data, size_t length)
{
    while (length--)
    {
        putc(*data++, stdout);
    }
}

void mmhal_log_flush(void)
{
}

void mmhal_reset(void)
{
    esp_restart();
    while (1)
    {
    }
}
