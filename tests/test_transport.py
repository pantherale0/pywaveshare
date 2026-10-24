"""Tests for WaveshareSerial, WaveshareSerialTransport, and URI handling."""

from __future__ import annotations

import asyncio

import pytest

from pywaveshare import (
    ConfigMode,
    ModemPins,
    Parity,
    PinState,
    StopBits,
    WaveshareClient,
    WaveshareSerial,
    WaveshareSerialTransport,
    async_create_serial_connection,
    open_serial_connection,
    register_waveshare_uri_handler,
)


@pytest.mark.asyncio
async def test_open_serial_connection_uri_and_stream_io() -> None:
    """Test opening a StreamReader/StreamWriter via waveshare:// URI and exchanging data."""
    server_received: list[bytes] = []

    async def handle_tcp(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Immediately send greeting banner to verify pending_data buffering before connection_made
        writer.write(b"BOOT_BANNER\r\n")
        await writer.drain()
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                server_received.append(data)
                if b"PING" in data:
                    writer.write(b"PONG\r\n")
                    await writer.drain()
        finally:
            writer.close()

    tcp_server = await asyncio.start_server(handle_tcp, "127.0.0.1", 0)
    tcp_port = tcp_server.sockets[0].getsockname()[1]

    try:
        uri = f"waveshare://127.0.0.1:{tcp_port}/?config_mode=waveshare_8byte"
        reader, writer = await open_serial_connection(
            uri,
            baudrate=9600,
            byte_size=8,
            parity=Parity.NONE,
            stopbits=StopBits.ONE,
        )

        # Verify early boot banner was buffered and replayed without loss
        banner = await asyncio.wait_for(reader.readline(), timeout=1.0)
        assert banner == b"BOOT_BANNER\r\n"

        # Send PING and read PONG
        writer.write(b"PING\r\n")
        await writer.drain()

        reply = await asyncio.wait_for(reader.readline(), timeout=1.0)
        assert reply == b"PONG\r\n"

        # Verify 9600 8N1 Waveshare 8-byte config frame (55 AA 55 00 25 80 03 A8) was sent
        combined_tx = b"".join(server_received)
        assert bytes.fromhex("55aa5500258003a8") in combined_tx

        writer.close()
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()


@pytest.mark.asyncio
async def test_custom_subclass_with_injected_client() -> None:
    """Test subclassing WaveshareSerial and WaveshareSerialTransport with an injected client."""
    server_received: list[bytes] = []

    async def handle_tcp(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                server_received.append(data)
                writer.write(b"ACK:" + data)
                await writer.drain()
        finally:
            writer.close()

    tcp_server = await asyncio.start_server(handle_tcp, "127.0.0.1", 0)
    tcp_port = tcp_server.sockets[0].getsockname()[1]

    try:
        shared_client = WaveshareClient(
            "127.0.0.1",
            port=tcp_port,
            config_mode=ConfigMode.RAW,
        )
        await shared_client.connect(fetch_info=False)

        class CustomAppWaveshareSerial(WaveshareSerial):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, client=shared_client, **kwargs)  # type: ignore[arg-type]

        class CustomAppWaveshareTransport(WaveshareSerialTransport):
            _serial_cls = CustomAppWaveshareSerial

        register_waveshare_uri_handler(
            scheme="waveshare-custom://",
            sync_cls=CustomAppWaveshareSerial,
            async_transport_cls=CustomAppWaveshareTransport,
        )

        received_by_protocol: list[bytes] = []
        data_event = asyncio.Event()

        class TestProtocol(asyncio.Protocol):
            def data_received(self, data: bytes) -> None:
                received_by_protocol.append(data)
                data_event.set()

        loop = asyncio.get_running_loop()
        transport, _ = await async_create_serial_connection(
            loop,
            TestProtocol,
            url="waveshare-custom://device-01/0",
            transport_cls=CustomAppWaveshareTransport,
            baudrate=115200,
        )

        transport.write(b"HELLO")
        await asyncio.wait_for(data_event.wait(), timeout=1.0)
        assert b"".join(received_by_protocol) == b"ACK:HELLO"

        await transport.set_modem_pins(ModemPins(rts=PinState.HIGH, dtr=PinState.LOW))
        pins = await transport.get_modem_pins()
        assert pins.rts == PinState.HIGH
        assert pins.dtr == PinState.LOW

        await transport.flush()
        transport.close()
        await asyncio.sleep(0.05)

        # Shared client should remain connected when transport closes
        # because it was injected externally
        assert shared_client.is_connected
        await shared_client.disconnect()
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()
