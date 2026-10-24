"""Tests for WaveshareClient lifecycle, state, device_info, and serial proxy methods."""

from __future__ import annotations

import asyncio

import pytest

from pywaveshare import (
    ConfigMode,
    ConnectionClosedEvent,
    DisconnectReason,
    LineStateFlag,
    SerialProxyDataReceived,
    SerialProxyParity,
    SerialProxyStatus,
    WaveshareClient,
)
from tests.test_zlan_udp import make_udp_response


@pytest.mark.asyncio
async def test_client_lifecycle_and_serial_proxy_modes() -> None:
    """Test WaveshareClient connect, device_info, configure, write, read, flush, and modem pins."""
    server_received: list[bytes] = []
    server_writers: list[asyncio.StreamWriter] = []
    client_connected_event = asyncio.Event()

    async def handle_tcp(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        server_writers.append(writer)
        client_connected_event.set()
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                server_received.append(data)
        finally:
            writer.close()

    class MockUdpServer(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self.transport = transport  # type: ignore[assignment]

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            self.transport.sendto(make_udp_response(txd_cnt=42, rxd_cnt=84), addr)

    loop = asyncio.get_running_loop()
    tcp_server = await asyncio.start_server(handle_tcp, "127.0.0.1", 0)
    tcp_port = tcp_server.sockets[0].getsockname()[1]

    udp_transport, _ = await loop.create_datagram_endpoint(
        MockUdpServer, local_addr=("127.0.0.1", 0)
    )
    udp_port = udp_transport.get_extra_info("sockname")[1]

    try:
        client = WaveshareClient(
            "127.0.0.1",
            port=tcp_port,
            udp_port=udp_port,
            config_mode=ConfigMode.WAVESHARE_8BYTE,
        )

        closed_events: list[ConnectionClosedEvent] = []
        received_events: list[SerialProxyDataReceived] = []

        unsub_closed = client.add_connection_closed_callback(closed_events.append)
        unsub_data = client.subscribe_serial_proxy_data(received_events.append)

        await client.connect()
        assert client.is_connected
        await client_connected_event.wait()

        # Check device_info and get_device_state
        info = await client.device_info()
        assert info.name == "ADMIN"
        assert info.mac_address == "00:00:C2:01:31:30"

        state = await client.get_device_state()
        assert state.txd_bytes == 42
        assert state.rxd_bytes == 84

        # Subscribe to serial proxy instance 0
        sub_resp = await client.serial_proxy_subscribe(0)
        assert sub_resp.status == SerialProxyStatus.OK

        # Configure serial port in WAVESHARE_8BYTE mode (115200 8N1 -> 55 AA 55 01 C2 00 03 C6)
        cfg_resp = await client.serial_proxy_configure(
            0,
            baudrate=115200,
            parity=SerialProxyParity.NONE,
            stop_bits=1,
            data_size=8,
        )
        assert cfg_resp.status == SerialProxyStatus.OK

        # Write serial data
        client.serial_proxy_write(0, b"MODBUS_REQ")
        await client.serial_proxy_flush(0)

        # Wait briefly for server to receive packets
        await asyncio.sleep(0.05)
        combined_tx = b"".join(server_received)
        assert bytes.fromhex("55aa5501c20003c6") in combined_tx
        assert b"MODBUS_REQ" in combined_tx

        # Server sends serial response to client
        server_writers[0].write(b"MODBUS_RESP")
        await server_writers[0].drain()
        await asyncio.sleep(0.05)

        assert len(received_events) == 1
        assert received_events[0].instance == 0
        assert received_events[0].data == b"MODBUS_RESP"

        # Modem pins
        pin_resp = await client.serial_proxy_set_modem_pins(
            0, line_states=LineStateFlag.RTS | LineStateFlag.DTR
        )
        assert pin_resp.status in (
            SerialProxyStatus.OK,
            SerialProxyStatus.ASSUMED_SUCCESS,
        )
        pins = await client.serial_proxy_get_modem_pins(0)
        assert pins.line_states == (LineStateFlag.RTS | LineStateFlag.DTR)

        # Clean disconnect
        await client.serial_proxy_unsubscribe(0)
        await client.disconnect()
        await asyncio.sleep(0.05)

        assert not client.is_connected
        assert len(closed_events) == 1
        assert closed_events[0].expected_disconnect is True
        assert closed_events[0].reason == DisconnectReason.USER_CLOSED

        unsub_data()
        unsub_closed()
    finally:
        udp_transport.close()
        tcp_server.close()
        await tcp_server.wait_closed()
