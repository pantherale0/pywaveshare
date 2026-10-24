"""Tests for ZLAN UDP port 1092 protocol (170-byte SSServerParam)."""

from __future__ import annotations

import asyncio

import pytest

from pywaveshare.const import (
    SerialProxyFlowControl,
    SerialProxyParity,
    Var2ParamType,
    WaveshareAppProtocol,
    WaveshareWorkMode,
    ZlanUdpCommand,
)
from pywaveshare.exceptions import (
    WaveshareAuthenticationError,
    WaveshareConfigurationError,
    WaveshareProtocolError,
)
from pywaveshare.models import WaveshareSerialConfig
from pywaveshare.protocol.zlan_udp import (
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

# Real 167-byte SSServerParam template from VirCom param.txt
SAMPLE_PARAM_HEX = (
    "000461c0a800c8001064c0a800690010"
    "64ffffff00c0a800010000c201313038"
    "303030000b0041444d494e0000007777"
    "772e7a6c6d63752e636f6d0000000000"
    "00000000000000000000000000000000"
    "00000050000a080054759b20001c0280"
    "5d00013c010a00000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000"
)


def make_udp_response(
    cmd: ZlanUdpCommand = ZlanUdpCommand.RESPONSE,
    *,
    txd_cnt: int | None = None,
    rxd_cnt: int | None = None,
) -> bytes:
    """Create a 170-byte ZLAN UDP response packet."""
    param = bytearray(167)
    # Local IP 192.168.0.200
    param[0x00:0x04] = bytes((192, 168, 0, 200))
    # Netmask 255.255.255.0
    param[0x04:0x08] = bytes((255, 255, 255, 0))
    # Gateway 192.168.0.1
    param[0x08:0x0C] = bytes((192, 168, 0, 1))
    # Dest IP 192.168.0.105
    param[0x0C:0x10] = bytes((192, 168, 0, 105))
    # Local port 4196 (0x1064), Dest port 4196 (0x1064)
    param[0x10:0x14] = bytes((0x10, 0x64, 0x10, 0x64))
    # Work mode 0 (TCP Server)
    param[0x14] = 0
    # Device ID / MAC: 00:00:C2:01:31:30
    param[0x1F:0x25] = bytes((0x00, 0x00, 0xC2, 0x01, 0x31, 0x30))
    # Baudrate index 11 (115200)
    param[0x25] = 11
    # Name "ADMIN"
    param[0x26:0x2B] = b"ADMIN"
    # Web port 80
    param[0x62:0x64] = bytes((0x00, 80))

    if txd_cnt is not None or rxd_cnt is not None:
        offset = 0x73
        if txd_cnt is not None:
            param[offset] = Var2ParamType.TXD_CNT
            param[offset + 1] = 4
            param[offset + 2 : offset + 6] = txd_cnt.to_bytes(4, "big")
            offset += 6
        if rxd_cnt is not None:
            param[offset] = Var2ParamType.RXD_CNT
            param[offset + 1] = 4
            param[offset + 2 : offset + 6] = rxd_cnt.to_bytes(4, "big")
            offset += 6
        param[offset] = Var2ParamType.END
    return bytes([0x5A, 0x4C, int(cmd)]) + bytes(param)


def test_parse_zlan_udp_response_basic() -> None:
    """Test parsing a 170-byte ZLAN UDP response packet."""
    packet = make_udp_response(txd_cnt=1024, rxd_cnt=2048)
    info = parse_zlan_udp_response(packet)

    assert info.name == "ADMIN"
    assert info.mac_address == "00:00:C2:01:31:30"
    assert info.ip_address == "192.168.0.200"
    assert info.netmask == "255.255.255.0"
    assert info.gateway == "192.168.0.1"
    assert info.dest_ip == "192.168.0.105"
    assert info.tcp_port == 4196
    assert info.dest_port == 4196
    assert info.web_port == 80
    assert info.dhcp_enabled is False
    assert info.state is not None
    assert info.state.work_mode == WaveshareWorkMode.TCP_SERVER
    assert info.state.app_protocol == WaveshareAppProtocol.TRANSPARENT
    assert info.state.serial_config.baudrate == 115200
    assert info.state.serial_config.data_size == 8
    assert info.state.serial_config.parity == SerialProxyParity.NONE
    assert info.state.serial_config.stop_bits == 1
    assert info.state.txd_bytes == 1024
    assert info.state.rxd_bytes == 2048
    assert len(info.serial_proxies) == 1
    assert info.serial_proxies[0].instance == 0


def test_parse_zlan_udp_response_errors() -> None:
    """Test error conditions when parsing ZLAN UDP packets."""
    with pytest.raises(WaveshareProtocolError, match="too short"):
        parse_zlan_udp_response(b"ZL")

    with pytest.raises(WaveshareProtocolError, match="Invalid ZLAN UDP magic"):
        parse_zlan_udp_response(b"XX\x01" + bytes(167))

    with pytest.raises(WaveshareAuthenticationError):
        parse_zlan_udp_response(b"ZL\x0c" + bytes(167))

    with pytest.raises(WaveshareProtocolError, match="too short"):
        parse_zlan_udp_response(b"ZL\x01" + bytes(40))


def test_build_serial_update_packet() -> None:
    """Test building RAM and Flash serial update packets."""
    base_resp = make_udp_response()
    raw_params = base_resp[3:]
    device_id = raw_params[0x1F:0x25]

    config = WaveshareSerialConfig(
        baudrate=9600,
        data_size=7,
        parity=SerialProxyParity.EVEN,
        stop_bits=2,
        flow_control=SerialProxyFlowControl.CTS_RTS,
    )

    ram_pkt = build_zlan_serial_update_packet(
        device_id,
        config,
        save_to_flash=False,
        base_params=raw_params,
    )
    assert len(ram_pkt) == 170
    assert ram_pkt[:3] == b"ZL\x03"

    # Re-parse as a response to verify updated fields
    reparsed = parse_zlan_udp_response(b"ZL\x01" + ram_pkt[3:])
    assert reparsed.state is not None
    assert reparsed.state.serial_config.baudrate == 9600
    assert reparsed.state.serial_config.data_size == 7
    assert reparsed.state.serial_config.parity == SerialProxyParity.EVEN
    assert reparsed.state.serial_config.stop_bits == 2
    assert reparsed.state.serial_config.flow_control == SerialProxyFlowControl.CTS_RTS

    flash_pkt = build_zlan_serial_update_packet(
        device_id,
        config,
        save_to_flash=True,
        base_params=raw_params,
    )
    assert flash_pkt[:3] == b"ZL\x07"

    with pytest.raises(WaveshareConfigurationError, match="Unsupported baudrate"):
        build_zlan_serial_update_packet(device_id, WaveshareSerialConfig(baudrate=12345))


def test_build_query_discover_reboot_packets() -> None:
    """Test building discover, query, and reboot packets."""
    assert len(build_zlan_discover_packet()) == 170
    assert build_zlan_discover_packet()[:3] == b"ZL\x00"
    assert len(build_zlan_query_packet()) == 170
    assert build_zlan_query_packet()[:3] == b"ZL\x04"

    raw_params = make_udp_response()[3:]
    reboot_pkt = build_zlan_reboot_packet(raw_params)
    assert len(reboot_pkt) == 170
    assert reboot_pkt[:3] == b"ZL\x0b"


@pytest.mark.asyncio
async def test_async_udp_operations() -> None:
    """Test async UDP query, discovery, serial config, and reboot against a mock UDP server."""
    received_commands: list[int] = []

    class MockZlanUdpServer(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self.transport = transport  # type: ignore[assignment]

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            if data[:2] == b"ZL":
                cmd = data[2]
                received_commands.append(cmd)
                self.transport.sendto(make_udp_response(txd_cnt=100, rxd_cnt=200), addr)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        MockZlanUdpServer,
        local_addr=("127.0.0.1", 0),
    )
    udp_port = transport.get_extra_info("sockname")[1]

    try:
        # 1. Unicast query
        info = await async_query_device_udp("127.0.0.1", port=udp_port, timeout=1.0)
        assert info.name == "ADMIN"
        assert ZlanUdpCommand.QUERY_UNICAST in received_commands

        # 2. Discovery
        devices = await async_discover_devices(
            broadcast_address="127.0.0.1", port=udp_port, timeout=0.15
        )
        assert len(devices) == 1
        assert devices[0].mac_address == "00:00:C2:01:31:30"

        # 3. Configure serial UDP (RAM only)
        await async_configure_serial_udp(
            "127.0.0.1",
            info.device_id,
            WaveshareSerialConfig(baudrate=19200),
            port=udp_port,
            save_to_flash=False,
        )
        await asyncio.sleep(0.05)
        assert ZlanUdpCommand.WRITE_RAM in received_commands

        # 4. Reboot UDP
        assert info.raw_params is not None
        await async_reboot_device_udp("127.0.0.1", info.raw_params, port=udp_port)
        await asyncio.sleep(0.05)
        assert ZlanUdpCommand.REBOOT in received_commands
    finally:
        transport.close()
