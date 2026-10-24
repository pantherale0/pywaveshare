"""Protocol implementations for Waveshare network serial adapters."""

from __future__ import annotations

from .rfc2217 import (
    RFC2217Event,
    RFC2217StreamFilter,
    build_rfc2217_configure,
    build_rfc2217_modem_pins,
    build_rfc2217_purge,
    build_waveshare_8byte_configure,
    escape_rfc2217_data,
    parse_waveshare_8byte_packet,
)
from .zlan_tcp import (
    RealComStreamFilter,
    ZlanCommandCodec,
    ZlanCommandResponse,
    build_realcom_configure,
    zlan_crc16,
)
from .zlan_udp import (
    async_configure_serial_udp,
    async_discover_devices,
    async_query_device_udp,
    async_reboot_device_udp,
    build_zlan_discover_packet,
    build_zlan_query_packet,
    build_zlan_reboot_packet,
    build_zlan_serial_update_packet,
    parse_zlan_udp_response,
)

__all__ = [
    "RFC2217Event",
    "RFC2217StreamFilter",
    "RealComStreamFilter",
    "ZlanCommandCodec",
    "ZlanCommandResponse",
    "async_configure_serial_udp",
    "async_discover_devices",
    "async_query_device_udp",
    "async_reboot_device_udp",
    "build_realcom_configure",
    "build_rfc2217_configure",
    "build_rfc2217_modem_pins",
    "build_rfc2217_purge",
    "build_waveshare_8byte_configure",
    "build_zlan_discover_packet",
    "build_zlan_query_packet",
    "build_zlan_reboot_packet",
    "build_zlan_serial_update_packet",
    "escape_rfc2217_data",
    "parse_waveshare_8byte_packet",
    "parse_zlan_udp_response",
    "zlan_crc16",
]
