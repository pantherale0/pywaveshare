"""Data models for Waveshare device information, state, and serial proxy operations."""

from __future__ import annotations

from dataclasses import dataclass, field

from .const import (
    DisconnectReason,
    LineStateFlag,
    SerialProxyFlowControl,
    SerialProxyParity,
    SerialProxyStatus,
    WaveshareAppProtocol,
    WaveshareWorkMode,
)


@dataclass(slots=True)
class SerialProxyInfo:
    """Metadata describing a serial proxy port exposed by a Waveshare adapter."""

    name: str
    port_type: str = "RS485"
    instance: int = 0


@dataclass(slots=True)
class SerialProxyDataReceived:
    """Event payload emitted when serial bytes arrive from a subscribed proxy port."""

    instance: int
    data: bytes


@dataclass(slots=True)
class SerialProxyRequestResponse:
    """Result of a serial proxy control request (subscribe, configure, flush, etc.)."""

    instance: int
    status: SerialProxyStatus = SerialProxyStatus.OK
    error_message: str = ""


@dataclass(slots=True)
class SerialProxyModemPins:
    """Current state of serial modem control pins (RTS/DTR)."""

    instance: int
    line_states: LineStateFlag = LineStateFlag.NONE


@dataclass(slots=True)
class ConnectionClosedEvent:
    """Event payload emitted when the connection to the Waveshare device closes."""

    expected_disconnect: bool
    reason: DisconnectReason = DisconnectReason.UNSPECIFIED
    error: Exception | None = None


@dataclass(slots=True)
class WaveshareSerialConfig:
    """Serial framing and flow-control configuration on a Waveshare port."""

    baudrate: int = 115200
    data_size: int = 8
    parity: SerialProxyParity = SerialProxyParity.NONE
    stop_bits: int = 1
    flow_control: SerialProxyFlowControl = SerialProxyFlowControl.NONE


@dataclass(slots=True)
class WaveshareDeviceState:
    """Live operational state of a Waveshare network serial adapter."""

    tcp_connected: bool = False
    txd_bytes: int = 0
    rxd_bytes: int = 0
    work_mode: WaveshareWorkMode = WaveshareWorkMode.TCP_SERVER
    app_protocol: WaveshareAppProtocol = WaveshareAppProtocol.TRANSPARENT
    serial_config: WaveshareSerialConfig = field(default_factory=WaveshareSerialConfig)


@dataclass(slots=True)
class WaveshareDeviceInfo:
    """Comprehensive device identity, network configuration, and state."""

    name: str
    mac_address: str
    device_id: bytes
    ip_address: str
    netmask: str = "255.255.255.0"
    gateway: str = "0.0.0.0"
    dest_ip: str = ""
    tcp_port: int = 4196
    dest_port: int = 4196
    web_port: int = 80
    dhcp_enabled: bool = False
    firmware_version: str = ""
    model: str = "Waveshare Serial Server"
    serial_proxies: list[SerialProxyInfo] = field(default_factory=list)
    state: WaveshareDeviceState | None = None
    raw_params: bytes | None = None
