"""RFC 2217 (Telnet Com Port Control) and Waveshare 8-byte synchronous baudrate codecs."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from ..const import (
    WAVESHARE_8BYTE_HEADER,
    LineStateFlag,
    SerialProxyFlowControl,
    SerialProxyParity,
)
from ..exceptions import WaveshareConfigurationError, WaveshareProtocolError
from ..models import WaveshareSerialConfig

# Telnet constants
IAC = 0xFF
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA
SE = 0xF0

COM_PORT_OPTION = 0x2C  # 44

# Client to server RFC 2217 subnegotiation commands
CMD_SET_BAUDRATE = 0x01
CMD_SET_DATASIZE = 0x02
CMD_SET_PARITY = 0x03
CMD_SET_STOPSIZE = 0x04
CMD_SET_CONTROL = 0x05
CMD_NOTIFY_LINESTATE = 0x06
CMD_NOTIFY_MODEMSTATE = 0x07
CMD_FLOWCONTROL_SUSPEND = 0x08
CMD_FLOWCONTROL_RESUME = 0x09
CMD_SET_LINESTATE_MASK = 0x0A
CMD_SET_MODEMSTATE_MASK = 0x0B
CMD_PURGE_DATA = 0x0C

# Server to client offset (+100 / 0x64)
SERVER_CMD_OFFSET = 100
RESP_SET_BAUDRATE = CMD_SET_BAUDRATE + SERVER_CMD_OFFSET  # 101 (0x65)
RESP_SET_DATASIZE = CMD_SET_DATASIZE + SERVER_CMD_OFFSET  # 102 (0x66)
RESP_SET_PARITY = CMD_SET_PARITY + SERVER_CMD_OFFSET  # 103 (0x67)
RESP_SET_STOPSIZE = CMD_SET_STOPSIZE + SERVER_CMD_OFFSET  # 104 (0x68)
RESP_SET_CONTROL = CMD_SET_CONTROL + SERVER_CMD_OFFSET  # 105 (0x69)
RESP_NOTIFY_LINESTATE = CMD_NOTIFY_LINESTATE + SERVER_CMD_OFFSET  # 106 (0x6A)
RESP_NOTIFY_MODEMSTATE = CMD_NOTIFY_MODEMSTATE + SERVER_CMD_OFFSET  # 107 (0x6B)
RESP_PURGE_DATA = CMD_PURGE_DATA + SERVER_CMD_OFFSET  # 112 (0x70)

# RFC 2217 SET-CONTROL values
CONTROL_FLOW_NONE = 0x01
CONTROL_FLOW_XON_XOFF = 0x02
CONTROL_FLOW_HARDWARE = 0x03
CONTROL_DTR_ON = 0x08
CONTROL_DTR_OFF = 0x09
CONTROL_RTS_ON = 0x0B
CONTROL_RTS_OFF = 0x0C
CONTROL_FLOW_DSR_DTR = 0x11

# RFC 2217 PURGE-DATA values
PURGE_RX = 0x01
PURGE_TX = 0x02
PURGE_BOTH = 0x03

RFC2217_PARITY_MAP: dict[SerialProxyParity, int] = {
    SerialProxyParity.NONE: 1,
    SerialProxyParity.ODD: 2,
    SerialProxyParity.EVEN: 3,
    SerialProxyParity.MARK: 4,
    SerialProxyParity.SPACE: 5,
}

RFC2217_STOPBITS_MAP: dict[int | float, int] = {
    1: 1,
    2: 2,
    1.5: 3,
}

RFC2217_FLOW_MAP: dict[SerialProxyFlowControl, int] = {
    SerialProxyFlowControl.NONE: CONTROL_FLOW_NONE,
    SerialProxyFlowControl.CTS_RTS: CONTROL_FLOW_HARDWARE,
    SerialProxyFlowControl.DSR_DTR: CONTROL_FLOW_DSR_DTR,
    SerialProxyFlowControl.XON_XOFF: CONTROL_FLOW_XON_XOFF,
}


def escape_rfc2217_data(data: bytes | bytearray | memoryview) -> bytes:
    """Escape 0xFF (IAC) bytes as 0xFF 0xFF for transmission over RFC 2217."""
    raw = bytes(data)
    if IAC not in raw:
        return raw
    return raw.replace(b"\xff", b"\xff\xff")


def _build_subnegotiation(command: int, payload: bytes) -> bytes:
    """Wrap a COM-PORT-OPTION subnegotiation command with IAC SB 0x2C ... IAC SE."""
    body = bytes((COM_PORT_OPTION, command)) + payload
    escaped_body = escape_rfc2217_data(body)
    return bytes((IAC, SB)) + escaped_body + bytes((IAC, SE))


def build_rfc2217_configure(
    baudrate: int,
    data_size: int = 8,
    parity: SerialProxyParity = SerialProxyParity.NONE,
    stop_bits: int | float = 1,
    flow_control: SerialProxyFlowControl = SerialProxyFlowControl.NONE,
) -> bytes:
    """Build combined RFC 2217 subnegotiation frames to configure serial parameters."""
    if baudrate <= 0 or baudrate > 0xFFFFFFFF:
        raise WaveshareConfigurationError(f"Invalid baudrate for RFC 2217: {baudrate}")
    if data_size not in (5, 6, 7, 8):
        raise WaveshareConfigurationError(f"Unsupported data_size for RFC 2217: {data_size}")
    if parity not in RFC2217_PARITY_MAP:
        raise WaveshareConfigurationError(f"Unsupported parity for RFC 2217: {parity}")
    if stop_bits not in RFC2217_STOPBITS_MAP:
        raise WaveshareConfigurationError(f"Unsupported stop_bits for RFC 2217: {stop_bits}")
    if flow_control not in RFC2217_FLOW_MAP:
        raise WaveshareConfigurationError(
            f"Unsupported flow_control for RFC 2217: {flow_control}"
        )

    frames = bytearray()
    frames.extend(_build_subnegotiation(CMD_SET_BAUDRATE, struct.pack(">I", baudrate)))
    frames.extend(_build_subnegotiation(CMD_SET_DATASIZE, bytes((data_size,))))
    frames.extend(_build_subnegotiation(CMD_SET_PARITY, bytes((RFC2217_PARITY_MAP[parity],))))
    frames.extend(
        _build_subnegotiation(CMD_SET_STOPSIZE, bytes((RFC2217_STOPBITS_MAP[stop_bits],)))
    )
    frames.extend(
        _build_subnegotiation(CMD_SET_CONTROL, bytes((RFC2217_FLOW_MAP[flow_control],)))
    )
    return bytes(frames)


def build_rfc2217_modem_pins(
    *,
    rts: bool | None = None,
    dtr: bool | None = None,
) -> bytes:
    """Build RFC 2217 SET-CONTROL frames to set RTS and/or DTR pin states."""
    frames = bytearray()
    if dtr is not None:
        frames.extend(
            _build_subnegotiation(
                CMD_SET_CONTROL,
                bytes((CONTROL_DTR_ON if dtr else CONTROL_DTR_OFF,)),
            )
        )
    if rts is not None:
        frames.extend(
            _build_subnegotiation(
                CMD_SET_CONTROL,
                bytes((CONTROL_RTS_ON if rts else CONTROL_RTS_OFF,)),
            )
        )
    return bytes(frames)


def build_rfc2217_purge(*, purge_rx: bool = False, purge_tx: bool = True) -> bytes:
    """Build an RFC 2217 PURGE-DATA subnegotiation frame."""
    if purge_rx and purge_tx:
        val = PURGE_BOTH
    elif purge_rx:
        val = PURGE_RX
    elif purge_tx:
        val = PURGE_TX
    else:
        return b""
    return _build_subnegotiation(CMD_PURGE_DATA, bytes((val,)))


@dataclass(slots=True)
class RFC2217Event:
    """Parsed RFC 2217 subnegotiation response or notification from the server."""

    command: int
    payload: bytes


class _ParserState(IntEnum):
    NORMAL = 0
    IAC = 1
    OPTION = 2
    SUBNEG = 3
    SUBNEG_IAC = 4


class RFC2217StreamFilter:
    """Incremental RFC 2217 stream parser that separates serial data from Telnet control."""

    def __init__(self) -> None:
        self._state: _ParserState = _ParserState.NORMAL
        self._option_verb: int = 0
        self._subneg_buf = bytearray()
        self.modem_state: int = 0
        self.line_state: int = 0
        self.line_states: LineStateFlag = LineStateFlag.NONE

    def reset(self) -> None:
        """Reset parser state."""
        self._state = _ParserState.NORMAL
        self._option_verb = 0
        self._subneg_buf.clear()

    def feed(
        self, chunk: bytes | bytearray | memoryview
    ) -> tuple[bytes, list[RFC2217Event], bytes]:
        """Feed raw TCP bytes into the filter.

        Returns:
            Tuple of `(serial_data, events, telnet_replies)` where:
            - `serial_data`: Unescaped raw serial payload bytes for the application.
            - `events`: List of parsed RFC 2217 server events/acknowledgments.
            - `telnet_replies`: Any automatic Telnet option negotiation replies to write back.
        """
        out_data = bytearray()
        events: list[RFC2217Event] = []
        replies = bytearray()

        for b in chunk:
            if self._state is _ParserState.NORMAL:
                if b == IAC:
                    self._state = _ParserState.IAC
                else:
                    out_data.append(b)

            elif self._state is _ParserState.IAC:
                if b == IAC:
                    out_data.append(IAC)
                    self._state = _ParserState.NORMAL
                elif b == SB:
                    self._subneg_buf.clear()
                    self._state = _ParserState.SUBNEG
                elif b in (WILL, WONT, DO, DONT):
                    self._option_verb = b
                    self._state = _ParserState.OPTION
                else:
                    # Other 2-byte Telnet command (NOP, BRK, etc.)
                    self._state = _ParserState.NORMAL

            elif self._state is _ParserState.OPTION:
                opt = b
                if self._option_verb == WILL:
                    if opt == COM_PORT_OPTION:
                        replies.extend((IAC, DO, opt))
                    else:
                        replies.extend((IAC, DONT, opt))
                elif self._option_verb == DO:
                    if opt == COM_PORT_OPTION:
                        replies.extend((IAC, WILL, opt))
                    else:
                        replies.extend((IAC, WONT, opt))
                self._state = _ParserState.NORMAL

            elif self._state is _ParserState.SUBNEG:
                if b == IAC:
                    self._state = _ParserState.SUBNEG_IAC
                else:
                    self._subneg_buf.append(b)

            elif self._state is _ParserState.SUBNEG_IAC:
                if b == IAC:
                    self._subneg_buf.append(IAC)
                    self._state = _ParserState.SUBNEG
                elif b == SE:
                    if len(self._subneg_buf) >= 2 and self._subneg_buf[0] == COM_PORT_OPTION:
                        cmd = self._subneg_buf[1]
                        payload = bytes(self._subneg_buf[2:])
                        self._handle_event(cmd, payload)
                        events.append(RFC2217Event(command=cmd, payload=payload))
                    self._subneg_buf.clear()
                    self._state = _ParserState.NORMAL
                else:
                    self._subneg_buf.clear()
                    self._state = _ParserState.NORMAL

        return bytes(out_data), events, bytes(replies)

    def _handle_event(self, cmd: int, payload: bytes) -> None:
        if cmd == RESP_NOTIFY_LINESTATE and payload:
            self.line_state = payload[0]
        elif cmd == RESP_NOTIFY_MODEMSTATE and payload:
            self.modem_state = payload[0]


# Waveshare 8-byte synchronous baudrate ("RFC2217-like") packet codec
# Format: 55 AA 55 <B2 B1 B0> <Param> <Checksum>
# Param bits:
#   [1:0]: Data bits (00=5, 01=6, 10=7, 11=8)
#   [2]:   Stop bits (0=1 stop bit, 1=2 stop bits)
#   [3]:   Parity enable (0=None, 1=Enabled)
#   [5:4]: Parity type (00=Odd, 01=Even, 10=Mark, 11=Space)

_WS8_DATASIZE_BITS: dict[int, int] = {5: 0b00, 6: 0b01, 7: 0b10, 8: 0b11}
_WS8_BITS_TO_DATASIZE: dict[int, int] = {v: k for k, v in _WS8_DATASIZE_BITS.items()}

_WS8_PARITY_BITS: dict[SerialProxyParity, int] = {
    SerialProxyParity.NONE: 0,
    SerialProxyParity.ODD: (0b00 << 4) | (1 << 3),
    SerialProxyParity.EVEN: (0b01 << 4) | (1 << 3),
    SerialProxyParity.MARK: (0b10 << 4) | (1 << 3),
    SerialProxyParity.SPACE: (0b11 << 4) | (1 << 3),
}


def build_waveshare_8byte_configure(
    baudrate: int,
    data_size: int = 8,
    parity: SerialProxyParity = SerialProxyParity.NONE,
    stop_bits: int = 1,
) -> bytes:
    """Build a Waveshare 8-byte inline synchronous baudrate control frame.

    Packet layout: `55 AA 55 <B2 B1 B0> <Param> <Checksum>`
    Example for 115200 8N1: `55 AA 55 01 C2 00 03 C6`
    Example for 9600 8N1:   `55 AA 55 00 25 80 03 A8`
    """
    if baudrate < 600 or baudrate > 0xFFFFFF:
        raise WaveshareConfigurationError(
            f"Baudrate {baudrate} out of range (600..16777215) for 8-byte frame"
        )
    if data_size not in _WS8_DATASIZE_BITS:
        raise WaveshareConfigurationError(f"Unsupported data_size: {data_size}")
    if stop_bits not in (1, 2):
        raise WaveshareConfigurationError(f"Unsupported stop_bits: {stop_bits}")
    if parity not in _WS8_PARITY_BITS:
        raise WaveshareConfigurationError(f"Unsupported parity: {parity}")

    b2 = (baudrate >> 16) & 0xFF
    b1 = (baudrate >> 8) & 0xFF
    b0 = baudrate & 0xFF

    param = _WS8_DATASIZE_BITS[data_size]
    if stop_bits == 2:
        param |= 1 << 2
    param |= _WS8_PARITY_BITS[parity]

    checksum = (b2 + b1 + b0 + param) & 0xFF
    return WAVESHARE_8BYTE_HEADER + bytes((b2, b1, b0, param, checksum))


def parse_waveshare_8byte_packet(packet: bytes) -> WaveshareSerialConfig:
    """Parse and validate an 8-byte Waveshare synchronous baudrate packet."""
    if len(packet) != 8 or not packet.startswith(WAVESHARE_8BYTE_HEADER):
        raise WaveshareProtocolError(f"Invalid 8-byte Waveshare header: {packet.hex()}")

    b2, b1, b0, param, checksum = packet[3:8]
    expected_sum = (b2 + b1 + b0 + param) & 0xFF
    # Also accept 7-bit masked sum variant (where bit 7 of param is set on some firmwares)
    if checksum != expected_sum and (checksum & 0x7F) != (expected_sum & 0x7F):
        raise WaveshareProtocolError(
            f"Checksum mismatch in 8-byte packet: got 0x{checksum:02X}, "
            f"expected 0x{expected_sum:02X}"
        )

    baudrate = (b2 << 16) | (b1 << 8) | b0
    data_size = _WS8_BITS_TO_DATASIZE[param & 0b11]
    stop_bits = 2 if (param & (1 << 2)) else 1

    if not (param & (1 << 3)):
        parity = SerialProxyParity.NONE
    else:
        parity_type = (param >> 4) & 0b11
        parity_lookup = {
            0b00: SerialProxyParity.ODD,
            0b01: SerialProxyParity.EVEN,
            0b10: SerialProxyParity.MARK,
            0b11: SerialProxyParity.SPACE,
        }
        parity = parity_lookup[parity_type]

    return WaveshareSerialConfig(
        baudrate=baudrate,
        data_size=data_size,
        parity=parity,
        stop_bits=stop_bits,
    )
