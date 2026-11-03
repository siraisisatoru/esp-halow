# Copyright 2025 Robert Carey
# Copyright 2025-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(src "mmhalow.c")

set(inc ".")

set(reqs
	esp_netif
	esp_wifi
)

# Components the shims and SDK libraries below link against directly. Listing them here keeps them
# in the build when a project trims its component list.
set(priv_reqs
	esp_driver_gpio
	esp_driver_spi
	esp_hw_support
	esp_system
	esp_timer
	freertos
	log
	mbedtls
)

idf_component_register(
	INCLUDE_DIRS
	${inc}
	SRCS
	${src}
	REQUIRES
	${reqs}
	PRIV_REQUIRES
	${priv_reqs}
)

add_subdirectory(components)
add_dependencies(${COMPONENT_TARGET} mmpktmem shims mmutils morselib regdb)
target_link_libraries(${COMPONENT_TARGET} PUBLIC mmpktmem shims mmutils morselib regdb)
