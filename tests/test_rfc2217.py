"""Tests for RFC 2217 and Waveshare 8-byte synchronous baudrate protocols."""

from __future__ import annotations

import pytest

from pywaveshare.const import (
    SerialProxyFlowControl,
    SerialProxyParity,
    SerialProxyStopBits,
)
from pywaveshare.exceptions import WaveshareConfigurationError, WaveshareProtocolError
from pywaveshare.models import WaveshareSerialConfig
from pywaveshare.protocol.rfc2217 import (
    CMD_SET_BAUDRATE,
    COM_PORT_OPTION,
    DO,
    DONT,
    IAC,
    RESP_NOTIFY_LINESTATE,
    RESP_NOTIFY_MODEMSTATE,
    RESP_SET_BAUDRATE,
    SB,
    SE,
    WILL,
    WONT,
    RFC2217StreamFilter,
    build_rfc2217_configure,
    build_rfc2217_modem_pins,
    build_rfc2217_purge,
    build_waveshare_8byte_configure,
    escape_rfc2217_data,
    parse_waveshare_8byte_packet,
)


def test_waveshare_8byte_configure_vectors() -> None:
    """Verify exact Waveshare 8-byte baudrate frames against official manual test vectors."""
    # Manual example 1: 115200 8N1 -> 55 AA 55 01 C2 00 03 C6
    pkt_115200 = build_waveshare_8byte_configure(
        baudrate=115200,
        data_size=8,
        parity=SerialProxyParity.NONE,
        stop_bits=1,
    )
    assert pkt_115200.hex() == "55aa5501c20003c6"

    # Manual example 2: 9600 8N1 -> 55 AA 55 00 25 80 03 A8
    pkt_9600 = build_waveshare_8byte_configure(
        baudrate=9600,
        data_size=8,
        parity=SerialProxyParity.NONE,
        stop_bits=1,
    )
    assert pkt_9600.hex() == "55aa5500258003a8"

    # Parse back both vectors
    parsed_115200 = parse_waveshare_8byte_packet(pkt_115200)
    assert parsed_115200 == WaveshareSerialConfig(
        baudrate=115200,
        data_size=8,
        parity=SerialProxyParity.NONE,
        stop_bits=1,
    )

    parsed_9600 = parse_waveshare_8byte_packet(pkt_9600)
    assert parsed_9600 == WaveshareSerialConfig(
        baudrate=9600,
        data_size=8,
        parity=SerialProxyParity.NONE,
        stop_bits=1,
    )

    # Parity EVEN + 2 stop bits + 7 data bits
    pkt_even = build_waveshare_8byte_configure(
        baudrate=19200,
        data_size=7,
        parity=SerialProxyParity.EVEN,
        stop_bits=2,
    )
    assert parse_waveshare_8byte_packet(pkt_even) == WaveshareSerialConfig(
        baudrate=19200,
        data_size=7,
        parity=SerialProxyParity.EVEN,
        stop_bits=2,
    )


def test_waveshare_8byte_invalid_inputs() -> None:
    """Test validation errors on invalid parameters for Waveshare 8-byte packet."""
    with pytest.raises(WaveshareConfigurationError):
        build_waveshare_8byte_configure(0)

    with pytest.raises(WaveshareConfigurationError):
        build_waveshare_8byte_configure(9600, data_size=9)

    with pytest.raises(WaveshareConfigurationError):
        build_waveshare_8byte_configure(9600, stop_bits=3)

    with pytest.raises(WaveshareProtocolError):
        parse_waveshare_8byte_packet(b"short")

    with pytest.raises(WaveshareProtocolError):
        parse_waveshare_8byte_packet(b"\x55\xaa\x55\x01\xc2\x00\x03\x00")


def test_rfc2217_builders_and_escaping() -> None:
    """Test RFC 2217 subnegotiation frame generation and IAC escaping."""
    escaped = escape_rfc2217_data(b"hello\xffworld")
    assert escaped == b"hello\xff\xffworld"

    cfg = build_rfc2217_configure(
        baudrate=115200,
        data_size=8,
        parity=SerialProxyParity.NONE,
        stop_bits=SerialProxyStopBits.ONE,
        flow_control=SerialProxyFlowControl.CTS_RTS,
    )
    # Check SET_BAUDRATE subnegotiation prefix: FF FA 2C 01 00 01 C2 00 FF F0
    assert cfg.startswith(
        bytes(
            [
                IAC,
                SB,
                COM_PORT_OPTION,
                CMD_SET_BAUDRATE,
                0x00,
                0x01,
                0xC2,
                0x00,
                IAC,
                SE,
            ]
        )
    )

    pins = build_rfc2217_modem_pins(rts=True, dtr=False)
    assert len(pins) == 14

    purge = build_rfc2217_purge(purge_rx=True, purge_tx=True)
    assert purge == bytes([IAC, SB, COM_PORT_OPTION, 12, 3, IAC, SE])


def test_rfc2217_stream_filter() -> None:
    """Test RFC 2217 stream deframing, option negotiation, and subnegotiation events."""
    flt = RFC2217StreamFilter()

    # Mix serial data, escaped 0xFF, Telnet WILL/DO negotiation, and RFC2217 subnegotiations
    stream = (
        b"ABC"
        + bytes([IAC, IAC])  # literal 0xFF
        + bytes([IAC, WILL, COM_PORT_OPTION])
        + bytes([IAC, DO, 0x99])  # unknown option -> WONT
        + bytes([IAC, DONT, COM_PORT_OPTION])
        + bytes([IAC, WONT, 0x99])
        + bytes(
            [
                IAC,
                SB,
                COM_PORT_OPTION,
                RESP_SET_BAUDRATE,
                0x00,
                0x01,
                0xC2,
                0x00,
                IAC,
                SE,
            ]
        )
        + bytes([IAC, SB, COM_PORT_OPTION, RESP_NOTIFY_LINESTATE, 0x60, IAC, SE])
        + bytes([IAC, SB, COM_PORT_OPTION, RESP_NOTIFY_MODEMSTATE, 0x30, IAC, SE])
        + b"DEF"
    )

    # Feed in 3-byte chunks to exercise state transitions across chunk boundaries
    out_data = bytearray()
    events = []
    replies = bytearray()
    for i in range(0, len(stream), 3):
        d, ev, rep = flt.feed(stream[i : i + 3])
        out_data.extend(d)
        events.extend(ev)
        replies.extend(rep)

    assert bytes(out_data) == b"ABC\xffDEF"
    assert bytes([IAC, DO, COM_PORT_OPTION]) in bytes(replies)
    assert bytes([IAC, WONT, 0x99]) in bytes(replies)
    assert len(events) == 3
    assert events[0].command == RESP_SET_BAUDRATE
    assert events[0].payload == b"\x00\x01\xc2\x00"
    assert events[1].command == RESP_NOTIFY_LINESTATE
    assert flt.line_state == 0x60
    assert events[2].command == RESP_NOTIFY_MODEMSTATE
    assert flt.modem_state == 0x30
