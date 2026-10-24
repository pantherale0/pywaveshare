"""Tests for ZLAN RealCom (FA 10 FB) and ZLAN 10-byte identification stream protocols."""

from __future__ import annotations

from pywaveshare.const import (
    SerialProxyFlowControl,
    SerialProxyParity,
    ZlanStreamCommand,
)
from pywaveshare.protocol.zlan_tcp import (
    RealComStreamFilter,
    ZlanCommandCodec,
    build_realcom_configure,
    zlan_crc16,
)


def test_zlan_crc16_manual_vectors() -> None:
    """Verify ZLAN Gen-2 CRC-16 against all 4 official manual test vectors."""
    # 1. Read Web port (0x003D, len 1): 80 3d 01 -> CRC a1 78
    assert zlan_crc16(bytes.fromhex("803d01")).hex() == "a178"

    # 2. Modify Work Mode in RAM (0x0014, len 1, val 1): 81 14 01 01 -> CRC a8 4c
    assert zlan_crc16(bytes.fromhex("81140101")).hex() == "a84c"

    # 3. Response OK: 0f 00 00 -> CRC 41 c3
    assert zlan_crc16(bytes.fromhex("0f0000")).hex() == "41c3"

    # 4. Response Format Error: 0e 00 00 -> CRC 10 03
    assert zlan_crc16(bytes.fromhex("0e0000")).hex() == "1003"


def test_zlan_command_codec_gen2() -> None:
    """Test ZLAN 10-byte identification stream Gen-2 command builders and response parser."""
    codec = ZlanCommandCodec()

    read_web_port = codec.build_read_command(0x003D, 1)
    assert read_web_port.hex() == "edf2a356cadb9184b0d7803d01a178"

    write_work_mode = codec.build_write_command(0x0014, b"\x01")
    assert write_work_mode.hex() == "edf2a356cadb9184b0d781140101a84c"

    serial_ram = codec.build_serial_config_ram_gen2(
        baudrate=115200,
        data_size=8,
        parity=SerialProxyParity.NONE,
        stop_bits=1,
        flow_control=SerialProxyFlowControl.NONE,
    )
    assert serial_ram.startswith(bytes.fromhex("edf2a356cadb9184b0d78125010b"))

    # Parse Gen-2 OK response
    ok_resp = bytes.fromhex("edf2a356cadb9184b0d70f000041c3")
    parsed = codec.parse_gen2_response(ok_resp)
    assert parsed.command == ZlanStreamCommand.RESP_OK
    assert parsed.length == 0


def test_realcom_configure_and_stream_filter() -> None:
    """Test ZLAN RealCom 12-byte configuration frame and RealComStreamFilter."""
    cfg = build_realcom_configure(
        baudrate=115200,
        data_size=8,
        parity=SerialProxyParity.NONE,
        flow_control=SerialProxyFlowControl.NONE,
    )
    assert len(cfg) == 12
    assert cfg.hex() == "fa10fb00c201004e0800fbfb"

    flt = RealComStreamFilter()
    # Stream containing 14-byte registration header, 3-byte FA 01 01 data header, and serial data
    reg_pkt = bytes.fromhex("fa071302fa020000c2013130faff")
    raw = reg_pkt + b"\xfa\x01\x01hello" + b"\xfa\x01\x01world"
    out_data = flt.feed(raw)

    assert out_data == b"helloworld"
    assert flt.mac_address == "00:00:C2:01:31:30"
