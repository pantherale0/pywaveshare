"""ZLAN RealCom and ZLAN 10-byte Gen-1/Gen-2 TCP/Serial command stream codecs."""

from __future__ import annotations

from dataclasses import dataclass

from ..const import (
    BAUDRATE_TO_INDEX,
    DATASIZE_TO_INDEX,
    ZLAN_CMD_STREAM_MAGIC,
    SerialProxyFlowControl,
    SerialProxyParity,
    ZlanStreamCommand,
)
from ..exceptions import WaveshareConfigurationError, WaveshareProtocolError

# Precompute the two 256-byte CRC-16 lookup tables used by ZLAN / VirCom firmware
_CRC16_HI: list[int] = []
_CRC16_LO: list[int] = []

for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = (_crc >> 1) ^ 0xA001
        else:
            _crc >>= 1
    _CRC16_HI.append(_crc & 0xFF)
    _CRC16_LO.append((_crc >> 8) & 0xFF)


def zlan_crc16(data: bytes | bytearray | memoryview, init: int = 0xFFFF) -> bytes:
    """Compute the 2-byte CRC-16 checksum used in ZLAN Gen-2 command frames.

    Verified against official Waveshare / ZLAN manual test vectors:
    - `80 3d 01` -> `a1 78`
    - `81 14 01 01` -> `a8 4c`
    - `0f 00 00` -> `41 c3`
    - `0e 00 00` -> `10 03`
    """
    hi = (init >> 8) & 0xFF
    lo = init & 0xFF
    for b in data:
        idx = (b ^ hi) & 0xFF
        hi = _CRC16_HI[idx] ^ lo
        lo = _CRC16_LO[idx]
    return bytes((hi, lo))


# ZLAN RealCom 12-byte configuration frame
# (`FA 10 FB <baud_3b_le> <modem> <parity> <bits> <flow> FB FB`)
_REALCOM_PARITY_ASCII: dict[SerialProxyParity, int] = {
    SerialProxyParity.NONE: ord("N"),  # 0x4E
    SerialProxyParity.EVEN: ord("E"),  # 0x45
    SerialProxyParity.ODD: ord("O"),  # 0x4F
    SerialProxyParity.MARK: ord("M"),  # 0x4D
    SerialProxyParity.SPACE: ord("S"),  # 0x53
}


def build_realcom_configure(
    baudrate: int,
    data_size: int = 8,
    parity: SerialProxyParity = SerialProxyParity.NONE,
    flow_control: SerialProxyFlowControl = SerialProxyFlowControl.NONE,
    *,
    stop_bits: int = 1,
    rts: bool = False,
    dtr: bool = False,
) -> bytes:
    """Build the 12-byte ZLAN RealCom dynamic serial configuration packet.

    Wire format verified against VirCom (`0x42f830`):
    `FA 10 FB <baud_lo> <baud_mid> <baud_hi> <modem_bits> <parity_char> <databits> <flow> FB FB`
    """
    if baudrate <= 0 or baudrate > 0xFFFFFF:
        raise WaveshareConfigurationError(f"Unsupported RealCom baudrate: {baudrate}")
    if data_size not in (5, 6, 7, 8):
        raise WaveshareConfigurationError(f"Unsupported RealCom data_size: {data_size}")
    if parity not in _REALCOM_PARITY_ASCII:
        raise WaveshareConfigurationError(f"Unsupported RealCom parity: {parity}")

    b0 = baudrate & 0xFF
    b1 = (baudrate >> 8) & 0xFF
    b2 = (baudrate >> 16) & 0xFF

    modem_bits = 0
    if rts:
        modem_bits |= 0x10
    if dtr:
        modem_bits |= 0x20

    parity_char = _REALCOM_PARITY_ASCII[parity]
    flow_byte = int(flow_control)

    return bytes(
        (
            0xFA,
            0x10,
            0xFB,
            b0,
            b1,
            b2,
            modem_bits,
            parity_char,
            data_size,
            flow_byte,
            0xFB,
            0xFB,
        )
    )


class RealComStreamFilter:
    """Stream filter for ZLAN RealCom mode (`AppPro = 2`).

    Strips:
    - Registration packet: `FA 07 13 02 FA 02 <MAC_6B> FA FF` (14 bytes)
    - Data prefix header: `FA 01 01` (3 bytes)
    - Standalone 1-byte keepalive `0x00` when arriving at frame boundary
    """

    REG_PREFIX = bytes.fromhex("fa071302fa02")
    REG_LEN = 14
    DATA_PREFIX = bytes.fromhex("fa0101")

    def __init__(self) -> None:
        self._buf = bytearray()
        self.mac_address: str | None = None

    def reset(self) -> None:
        """Clear internal state."""
        self._buf.clear()

    def feed(self, chunk: bytes | bytearray | memoryview) -> bytes:
        """Feed incoming RealCom TCP bytes and return extracted raw serial payload."""
        if not chunk:
            return b""
        # Single-byte 0x00 heartbeat packet when buffer is empty
        if len(chunk) == 1 and chunk[0] == 0x00 and not self._buf:
            return b""

        self._buf.extend(chunk)
        out = bytearray()

        while self._buf:
            if self._buf[0] != 0xFA:
                idx = self._buf.find(0xFA)
                if idx == -1:
                    out.extend(self._buf)
                    self._buf.clear()
                    break
                out.extend(self._buf[:idx])
                del self._buf[:idx]

            # Starts with 0xFA
            if len(self._buf) < 3:
                break

            if self._buf[:3] == self.DATA_PREFIX:
                del self._buf[:3]
                continue

            if self._buf[:2] == b"\xfa\x07":
                if len(self._buf) < self.REG_LEN:
                    break
                if self._buf[:6] == self.REG_PREFIX and self._buf[12:14] == b"\xfa\xff":
                    mac_bytes = bytes(self._buf[6:12])
                    self.mac_address = ":".join(f"{b:02X}" for b in mac_bytes)
                    del self._buf[: self.REG_LEN]
                    continue

            # Not a recognized RealCom header; emit the 0xFA byte as data
            out.append(self._buf.pop(0))

        return bytes(out)


@dataclass(slots=True)
class ZlanCommandResponse:
    """Parsed response from a ZLAN Gen-2 command (`ED F2 A3 56 CA DB 91 84 B0 D7 ...`)."""

    command: int
    offset: int
    length: int
    data: bytes


class ZlanCommandCodec:
    """Builder and parser for ZLAN 10-byte identification stream commands."""

    @staticmethod
    def build_read_command(offset: int, length: int, *, gen2: bool = True) -> bytes:
        """Build a parameter read command (`0x80` Gen-2 with CRC16 or `0x00` Gen-1)."""
        if not (0 <= offset <= 0xFF and 1 <= length <= 0xFF):
            raise WaveshareConfigurationError(f"Invalid offset={offset} or length={length}")
        if not gen2:
            return ZLAN_CMD_STREAM_MAGIC + bytes(
                (ZlanStreamCommand.READ_PARAM_GEN1, offset, length)
            )
        body = bytes((ZlanStreamCommand.READ_PARAM_GEN2, offset, length))
        crc = zlan_crc16(body)
        return ZLAN_CMD_STREAM_MAGIC + body + crc

    @staticmethod
    def build_write_command(
        offset: int,
        payload: bytes,
        *,
        save_to_flash: bool = False,
        reboot: bool = False,
        gen2: bool = True,
    ) -> bytes:
        """Build a parameter write command (`0x81` RAM, `0x83` Flash, `0x87` Flash+Reboot)."""
        if not (0 <= offset <= 0xFF and 1 <= len(payload) <= 0xFF):
            raise WaveshareConfigurationError(
                f"Invalid offset={offset} or payload length={len(payload)}"
            )
        if reboot:
            cmd = (
                ZlanStreamCommand.WRITE_FLASH_REBOOT_GEN2
                if gen2
                else ZlanStreamCommand.WRITE_FLASH_REBOOT_GEN1
            )
        elif save_to_flash:
            cmd = ZlanStreamCommand.WRITE_FLASH_GEN2 if gen2 else ZlanStreamCommand.WRITE_FLASH_GEN1
        else:
            cmd = ZlanStreamCommand.WRITE_RAM_GEN2 if gen2 else ZlanStreamCommand.WRITE_RAM_GEN1

        body = bytes((cmd, offset, len(payload))) + payload
        if not gen2:
            return ZLAN_CMD_STREAM_MAGIC + body
        crc = zlan_crc16(body)
        return ZLAN_CMD_STREAM_MAGIC + body + crc

    @classmethod
    def build_serial_config_ram_gen2(
        cls,
        baudrate: int,
        data_size: int = 8,
        parity: SerialProxyParity = SerialProxyParity.NONE,
        stop_bits: int = 1,
        flow_control: SerialProxyFlowControl = SerialProxyFlowControl.NONE,
    ) -> bytes:
        """Build concatenated Gen-2 RAM write commands (`0x81`) for serial parameters."""
        if baudrate not in BAUDRATE_TO_INDEX:
            raise WaveshareConfigurationError(
                f"Unsupported baudrate {baudrate} for ZLAN Gen-2 configuration"
            )
        if data_size not in DATASIZE_TO_INDEX:
            raise WaveshareConfigurationError(f"Unsupported data_size {data_size}")
        if stop_bits not in (1, 2):
            raise WaveshareConfigurationError(f"Unsupported stop_bits {stop_bits}")

        frames = bytearray()
        frames.extend(cls.build_write_command(0x25, bytes((BAUDRATE_TO_INDEX[baudrate],))))
        frames.extend(cls.build_write_command(0x30, bytes((int(parity),))))
        frames.extend(cls.build_write_command(0x37, bytes((1 if stop_bits == 2 else 0,))))
        frames.extend(cls.build_write_command(0x39, bytes((int(flow_control),))))
        frames.extend(cls.build_write_command(0x3B, bytes((DATASIZE_TO_INDEX[data_size],))))
        return bytes(frames)

    @staticmethod
    def parse_gen2_response(frame: bytes) -> ZlanCommandResponse:
        """Parse and validate a Gen-2 response frame starting with the 10-byte magic."""
        if len(frame) < 15 or not frame.startswith(ZLAN_CMD_STREAM_MAGIC):
            raise WaveshareProtocolError(f"Invalid ZLAN Gen-2 response header: {frame.hex()}")

        cmd = frame[10]
        offset = frame[11]
        length = frame[12]
        expected_total = 10 + 3 + length + 2
        if len(frame) < expected_total:
            raise WaveshareProtocolError(
                f"Truncated ZLAN Gen-2 response: got {len(frame)} bytes, expected {expected_total}"
            )

        body = frame[10 : 13 + length]
        crc_actual = frame[13 + length : 15 + length]
        crc_expected = zlan_crc16(body)
        if crc_actual != crc_expected:
            raise WaveshareProtocolError(
                f"ZLAN Gen-2 CRC mismatch: got {crc_actual.hex()}, expected {crc_expected.hex()}"
            )

        if cmd == ZlanStreamCommand.RESP_FORMAT_ERROR:
            raise WaveshareProtocolError("Device reported command format or CRC error (0x0E)")
        if cmd == ZlanStreamCommand.RESP_OUT_OF_BOUNDS:
            raise WaveshareConfigurationError(
                "Device reported parameter value out of bounds (0x10)"
            )

        data = frame[13 : 13 + length]
        return ZlanCommandResponse(command=cmd, offset=offset, length=length, data=data)
