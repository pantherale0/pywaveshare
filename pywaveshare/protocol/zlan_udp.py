"""ZLAN / Waveshare UDP port 1092 discovery, state query, and configuration protocol."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct

from ..const import (
    BAUDRATE_TO_INDEX,
    DATASIZE_TO_INDEX,
    DEFAULT_UDP_PORT,
    INDEX_TO_BAUDRATE,
    INDEX_TO_DATASIZE,
    ZLAN_PACKET_SIZE,
    ZLAN_PARAM_SIZE,
    ZLAN_UDP_MAGIC,
    SerialProxyFlowControl,
    SerialProxyParity,
    Var2ParamType,
    WaveshareAppProtocol,
    WaveshareWorkMode,
    ZlanUdpCommand,
)
from ..exceptions import (
    WaveshareAuthenticationError,
    WaveshareConfigurationError,
    WaveshareProtocolError,
    WaveshareTimeoutError,
)
from ..models import (
    SerialProxyInfo,
    WaveshareDeviceInfo,
    WaveshareDeviceState,
    WaveshareSerialConfig,
)


def _format_ip(raw_ip: bytes) -> str:
    return str(ipaddress.IPv4Address(raw_ip))


def _format_mac(raw_mac: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw_mac)


def parse_var2_tlv(var2_data: bytes) -> dict[int, bytes]:
    """Parse the 52-byte variable parameter area (var2 at offset 0x73..0xA6)."""
    entries: dict[int, bytes] = {}
    i = 0
    n = len(var2_data)
    while i < n:
        tag = var2_data[i]
        if tag == Var2ParamType.END or i + 1 >= n:
            break
        length = var2_data[i + 1]
        if i + 2 + length > n:
            break
        entries[tag] = bytes(var2_data[i + 2 : i + 2 + length])
        i += 2 + length
    return entries


def parse_zlan_param_block(param: bytes) -> WaveshareDeviceInfo:
    """Decode a 167-byte SSServerParam block into WaveshareDeviceInfo and WaveshareDeviceState."""
    if len(param) < 0x69:
        raise WaveshareProtocolError(
            f"ZLAN parameter block too short: got {len(param)} bytes, expected at least 105"
        )

    # Pad to 167 bytes if an older firmware returned a shorter block
    if len(param) < ZLAN_PARAM_SIZE:
        param = param + b"\x00" * (ZLAN_PARAM_SIZE - len(param))
    else:
        param = param[:ZLAN_PARAM_SIZE]

    local_ip = _format_ip(param[0x00:0x04])
    netmask = _format_ip(param[0x04:0x08])
    gateway = _format_ip(param[0x08:0x0C])
    dest_ip_raw = _format_ip(param[0x0C:0x10])

    local_port, dest_port = struct.unpack(">HH", param[0x10:0x14])
    work_mode_val = param[0x14]
    try:
        work_mode = WaveshareWorkMode(work_mode_val)
    except ValueError:
        work_mode = WaveshareWorkMode.TCP_SERVER

    device_id = bytes(param[0x1F:0x25])
    mac_address = _format_mac(device_id)

    baudrate_idx = param[0x25]
    baudrate = INDEX_TO_BAUDRATE.get(baudrate_idx, 115200)

    raw_name = param[0x26:0x30].split(b"\x00", 1)[0]
    name = raw_name.decode("ascii", errors="replace").strip() or f"Waveshare-{mac_address[-5:]}"

    parity_val = param[0x30]
    try:
        parity = SerialProxyParity(parity_val)
    except ValueError:
        parity = SerialProxyParity.NONE

    stop_bits = 2 if (param[0x37] & 0x01) else 1
    dhcp_enabled = bool(param[0x38])

    flow_val = param[0x39]
    try:
        flow_control = SerialProxyFlowControl(flow_val)
    except ValueError:
        flow_control = SerialProxyFlowControl.NONE

    datasize_idx = param[0x3B]
    data_size = INDEX_TO_DATASIZE.get(datasize_idx, 8)

    app_pro_val = param[0x3C]
    try:
        app_protocol = WaveshareAppProtocol(app_pro_val)
    except ValueError:
        app_protocol = WaveshareAppProtocol.TRANSPARENT

    status_byte = param[0x3D]
    tcp_connected = bool(status_byte & 0x01)

    dest_string_raw = param[0x42:0x60].split(b"\x00", 1)[0]
    dest_string = dest_string_raw.decode("ascii", errors="ignore").strip()
    dest_ip = dest_string or dest_ip_raw

    web_port = struct.unpack(">H", param[0x62:0x64])[0] or 80
    ver_byte = param[0x67]
    firmware_version = f"V1.{383 + ver_byte}"

    var2_entries = parse_var2_tlv(param[0x73:0xA7])
    txd_bytes = 0
    rxd_bytes = 0
    if Var2ParamType.TXD_CNT in var2_entries and len(var2_entries[Var2ParamType.TXD_CNT]) == 4:
        txd_bytes = struct.unpack(">I", var2_entries[Var2ParamType.TXD_CNT])[0]
    if Var2ParamType.RXD_CNT in var2_entries and len(var2_entries[Var2ParamType.RXD_CNT]) == 4:
        rxd_bytes = struct.unpack(">I", var2_entries[Var2ParamType.RXD_CNT])[0]

    serial_config = WaveshareSerialConfig(
        baudrate=baudrate,
        data_size=data_size,
        parity=parity,
        stop_bits=stop_bits,
        flow_control=flow_control,
    )
    state = WaveshareDeviceState(
        tcp_connected=tcp_connected,
        txd_bytes=txd_bytes,
        rxd_bytes=rxd_bytes,
        work_mode=work_mode,
        app_protocol=app_protocol,
        serial_config=serial_config,
    )

    return WaveshareDeviceInfo(
        name=name,
        mac_address=mac_address,
        device_id=device_id,
        ip_address=local_ip,
        netmask=netmask,
        gateway=gateway,
        dest_ip=dest_ip,
        tcp_port=local_port,
        dest_port=dest_port,
        web_port=web_port,
        dhcp_enabled=dhcp_enabled,
        firmware_version=firmware_version,
        model="Waveshare Serial Server",
        serial_proxies=[SerialProxyInfo(name=name, port_type="RS485", instance=0)],
        state=state,
        raw_params=bytes(param),
    )


def parse_zlan_udp_response(datagram: bytes) -> WaveshareDeviceInfo:
    """Parse a 170-byte UDP port 1092 response datagram ('ZL' + cmd + 167-byte SSServerParam)."""
    if len(datagram) < 0x29:
        raise WaveshareProtocolError(f"UDP response too short: {len(datagram)} bytes")
    if datagram[2] == ZlanUdpCommand.ERROR_KEY:
        raise WaveshareAuthenticationError("Device rejected key/password over UDP port 1092")
    if datagram[:2] != ZLAN_UDP_MAGIC:
        raise WaveshareProtocolError(f"Invalid ZLAN UDP magic: {datagram[:2].hex()}")
    if datagram[2] not in (ZlanUdpCommand.RESPONSE, ZlanUdpCommand.RESPONSE_ALT):
        raise WaveshareProtocolError(f"Unexpected ZLAN UDP command byte: 0x{datagram[2]:02X}")

    return parse_zlan_param_block(datagram[3:])


def build_zlan_discover_packet() -> bytes:
    """Build a 170-byte UDP broadcast discovery packet (`5A 4C 00` + 167 zero bytes)."""
    return ZLAN_UDP_MAGIC + bytes((ZlanUdpCommand.DISCOVER,)) + (b"\x00" * ZLAN_PARAM_SIZE)


def build_zlan_query_packet() -> bytes:
    """Build a 170-byte UDP unicast query packet (`5A 4C 04` + 167 zero bytes)."""
    return ZLAN_UDP_MAGIC + bytes((ZlanUdpCommand.QUERY_UNICAST,)) + (b"\x00" * ZLAN_PARAM_SIZE)


def build_zlan_serial_update_packet(
    device_id: bytes,
    config: WaveshareSerialConfig,
    *,
    save_to_flash: bool = False,
    rts: bool | None = None,
    dtr: bool | None = None,
    base_params: bytes | None = None,
) -> bytes:
    """Build a 170-byte UDP packet (`5A 4C 03` RAM or `5A 4C 07` Flash) to update serial settings.

    Matches VirCom's `SetComParam` implementation at `0x42f5e0` / `0x42f9f0`:
    - `0x03` updates serial parameters in RAM immediately without rebooting or wearing Flash.
    - `0x07` saves the updated parameters to Flash.
    """
    if len(device_id) != 6:
        raise WaveshareConfigurationError("device_id (MAC address) must be 6 bytes")
    if config.baudrate not in BAUDRATE_TO_INDEX:
        raise WaveshareConfigurationError(
            f"Unsupported baudrate {config.baudrate} for ZLAN UDP configuration"
        )
    if config.data_size not in DATASIZE_TO_INDEX:
        raise WaveshareConfigurationError(f"Unsupported data_size {config.data_size}")
    if config.stop_bits not in (1, 2):
        raise WaveshareConfigurationError(f"Unsupported stop_bits {config.stop_bits}")

    if base_params is not None and len(base_params) == ZLAN_PARAM_SIZE:
        param = bytearray(base_params)
    else:
        param = bytearray(ZLAN_PARAM_SIZE)

    param[0x1F:0x25] = device_id
    param[0x25] = BAUDRATE_TO_INDEX[config.baudrate]
    param[0x30] = int(config.parity)
    if config.stop_bits == 2:
        param[0x37] |= 0x01
    else:
        param[0x37] &= 0xFE
    param[0x39] = int(config.flow_control)
    param[0x3B] = DATASIZE_TO_INDEX[config.data_size]

    if rts is not None or dtr is not None:
        if rts or dtr:
            param[0x6D] |= 0x80
        else:
            param[0x6D] &= 0x7F

    cmd = ZlanUdpCommand.WRITE_FLASH if save_to_flash else ZlanUdpCommand.WRITE_RAM
    return ZLAN_UDP_MAGIC + bytes((cmd,)) + bytes(param)


def build_zlan_reboot_packet(raw_params: bytes) -> bytes:
    """Build a 170-byte UDP reboot packet (`5A 4C 0B` + 167-byte SSServerParam)."""
    if len(raw_params) != ZLAN_PARAM_SIZE:
        raise WaveshareConfigurationError(
            f"raw_params must be {ZLAN_PARAM_SIZE} bytes, got {len(raw_params)}"
        )
    return ZLAN_UDP_MAGIC + bytes((ZlanUdpCommand.REBOOT,)) + raw_params


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.devices: dict[str, WaveshareDeviceInfo] = {}

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < ZLAN_PACKET_SIZE and len(data) < 0x6C:
            return
        try:
            info = parse_zlan_udp_response(data)
            self.devices[info.mac_address] = info
        except WaveshareProtocolError:
            return


class _SingleQueryProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[WaveshareDeviceInfo]) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._future.done():
            return
        try:
            info = parse_zlan_udp_response(data)
            self._future.set_result(info)
        except Exception as exc:
            self._future.set_exception(exc)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def async_discover_devices(
    broadcast_address: str = "255.255.255.255",
    port: int = DEFAULT_UDP_PORT,
    timeout: float = 1.5,
) -> list[WaveshareDeviceInfo]:
    """Broadcast a ZLAN discovery query on UDP port 1092 and collect responding devices."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)

    transport, protocol = await loop.create_datagram_endpoint(
        _DiscoveryProtocol,
        sock=sock,
    )
    try:
        packet = build_zlan_discover_packet()
        transport.sendto(packet, (broadcast_address, port))
        await asyncio.sleep(timeout)
        return list(protocol.devices.values())
    finally:
        transport.close()


async def async_query_device_udp(
    host: str,
    port: int = DEFAULT_UDP_PORT,
    timeout: float = 2.0,
) -> WaveshareDeviceInfo:
    """Query a specific Waveshare device's parameters and state via unicast UDP port 1092."""
    loop = asyncio.get_running_loop()
    future: asyncio.Future[WaveshareDeviceInfo] = loop.create_future()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: _SingleQueryProtocol(future),
        remote_addr=(host, port),
    )
    try:
        transport.sendto(build_zlan_query_packet())
        try:
            async with asyncio.timeout(timeout):
                return await future
        except TimeoutError as exc:
            raise WaveshareTimeoutError(
                f"Timed out querying Waveshare device at {host}:{port} via UDP"
            ) from exc
    finally:
        transport.close()


async def async_configure_serial_udp(
    host: str,
    device_id: bytes,
    config: WaveshareSerialConfig,
    *,
    save_to_flash: bool = False,
    rts: bool | None = None,
    dtr: bool | None = None,
    base_params: bytes | None = None,
    port: int = DEFAULT_UDP_PORT,
) -> None:
    """Send a UDP port 1092 serial parameter update (`5A 4C 03` RAM or `5A 4C 07` Flash)."""
    loop = asyncio.get_running_loop()
    packet = build_zlan_serial_update_packet(
        device_id,
        config,
        save_to_flash=save_to_flash,
        rts=rts,
        dtr=dtr,
        base_params=base_params,
    )
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=(host, port),
    )
    try:
        transport.sendto(packet)
    finally:
        transport.close()


async def async_reboot_device_udp(
    host: str,
    raw_params: bytes,
    port: int = DEFAULT_UDP_PORT,
) -> None:
    """Send a UDP port 1092 device reboot command (`5A 4C 0B`)."""
    loop = asyncio.get_running_loop()
    packet = build_zlan_reboot_packet(raw_params)
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=(host, port),
    )
    try:
        transport.sendto(packet)
    finally:
        transport.close()
