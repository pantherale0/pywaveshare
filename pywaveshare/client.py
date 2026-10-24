"""Asynchronous client for Waveshare network serial adapters."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from .const import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT,
    ConfigMode,
    DisconnectReason,
    LineStateFlag,
    SerialProxyFlowControl,
    SerialProxyParity,
    SerialProxyStatus,
    SerialProxyStopBits,
    WaveshareAppProtocol,
    WaveshareWorkMode,
)
from .exceptions import (
    WaveshareConfigurationError,
    WaveshareConnectionError,
    WaveshareError,
    WaveshareTimeoutError,
)
from .models import (
    ConnectionClosedEvent,
    SerialProxyDataReceived,
    SerialProxyInfo,
    SerialProxyModemPins,
    SerialProxyRequestResponse,
    WaveshareDeviceInfo,
    WaveshareDeviceState,
    WaveshareSerialConfig,
)
from .protocol.rfc2217 import (
    RFC2217StreamFilter,
    build_rfc2217_configure,
    build_rfc2217_modem_pins,
    build_rfc2217_purge,
    build_waveshare_8byte_configure,
    escape_rfc2217_data,
)
from .protocol.zlan_tcp import (
    RealComStreamFilter,
    ZlanCommandCodec,
    build_realcom_configure,
)
from .protocol.zlan_udp import (
    async_configure_serial_udp,
    async_query_device_udp,
    async_reboot_device_udp,
)

LOGGER = logging.getLogger(__name__)


class _WaveshareTcpProtocol(asyncio.Protocol):
    """Internal asyncio TCP protocol handler for a Waveshare serial port."""

    def __init__(self, client: WaveshareClient) -> None:
        self._client = client
        self.transport: asyncio.Transport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport
        self._client._on_tcp_connected(transport)

    def data_received(self, data: bytes) -> None:
        self._client._on_tcp_data_received(data)

    def connection_lost(self, exc: Exception | None) -> None:
        self._client._on_tcp_connection_lost(exc)


class WaveshareClient:
    """Asynchronous control and serial proxy client for a Waveshare network serial adapter."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_TCP_PORT,
        *,
        udp_port: int = DEFAULT_UDP_PORT,
        config_mode: ConfigMode | str = ConfigMode.RFC2217,
        password: str | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        """Initialize the WaveshareClient."""
        self.host = host
        self.port = port
        self.udp_port = udp_port
        self.config_mode = ConfigMode(config_mode)
        self.password = password
        self.connect_timeout = connect_timeout
        self._loop = loop

        self._transport: asyncio.Transport | None = None
        self._protocol: _WaveshareTcpProtocol | None = None
        self._expected_disconnect: bool = False
        self._subscribed_instances: set[int] = set()

        self._data_callbacks: list[Callable[[SerialProxyDataReceived], None]] = []
        self._disconnect_callbacks: list[Callable[[ConnectionClosedEvent], None]] = []

        self._rfc2217_filter = RFC2217StreamFilter()
        self._realcom_filter = RealComStreamFilter()
        self._zlan_codec = ZlanCommandCodec()

        self._cached_device_info: WaveshareDeviceInfo | None = None
        self._serial_config = WaveshareSerialConfig()
        self._line_states: LineStateFlag = LineStateFlag.NONE
        self._txd_bytes: int = 0
        self._rxd_bytes: int = 0

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        """Return the active asyncio event loop."""
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        return self._loop

    @property
    def is_connected(self) -> bool:
        """Return True if the TCP data connection is currently established."""
        return self._transport is not None and not self._transport.is_closing()

    async def connect(self, fetch_info: bool = True) -> None:
        """Establish a connection to the Waveshare device."""
        if self.is_connected:
            return

        self._expected_disconnect = False
        self._rfc2217_filter = RFC2217StreamFilter()
        self._realcom_filter = RealComStreamFilter()

        try:
            async with asyncio.timeout(self.connect_timeout):
                transport, protocol = await self.loop.create_connection(
                    lambda: _WaveshareTcpProtocol(self),
                    host=self.host,
                    port=self.port,
                )
        except TimeoutError as err:
            raise WaveshareTimeoutError(
                f"Timed out connecting to {self.host}:{self.port} after {self.connect_timeout}s"
            ) from err
        except OSError as err:
            raise WaveshareConnectionError(
                f"Failed to connect to {self.host}:{self.port}: {err}"
            ) from err

        assert isinstance(transport, asyncio.Transport)
        assert isinstance(protocol, _WaveshareTcpProtocol)
        self._transport = transport
        self._protocol = protocol

        if fetch_info:
            try:
                await self.device_info(force_refresh=True)
            except WaveshareError as err:
                LOGGER.debug(
                    "Management metadata query skipped/failed during connect on %s: %s",
                    self.host,
                    err,
                )

    async def disconnect(self) -> None:
        """Close the connection to the Waveshare device."""
        self._expected_disconnect = True
        self._subscribed_instances.clear()
        if self._transport is not None:
            transport = self._transport
            self._transport = None
            self._protocol = None
            transport.close()

    def _on_tcp_connected(self, transport: asyncio.Transport) -> None:
        """Handle TCP transport connection establishment."""
        self._transport = transport

    def _on_tcp_data_received(self, data: bytes) -> None:
        """Handle incoming TCP bytes, applying the active protocol stream filter."""
        if not data:
            return

        if self.config_mode == ConfigMode.RFC2217:
            payload, _events, replies = self._rfc2217_filter.feed(data)
            if replies and self._transport is not None and not self._transport.is_closing():
                self._transport.write(replies)
            clean_data = payload
        elif self.config_mode == ConfigMode.REALCOM:
            clean_data = self._realcom_filter.feed(data)
        else:
            clean_data = data

        if not clean_data:
            return

        self._rxd_bytes += len(clean_data)
        if not self._subscribed_instances or not self._data_callbacks:
            return

        for instance in tuple(self._subscribed_instances):
            msg = SerialProxyDataReceived(instance=instance, data=clean_data)
            for callback in tuple(self._data_callbacks):
                try:
                    callback(msg)
                except Exception:
                    LOGGER.exception("Error in serial proxy data callback")

    def _on_tcp_connection_lost(self, exc: Exception | None) -> None:
        """Handle TCP connection closure and notify registered listeners."""
        expected = self._expected_disconnect
        self._transport = None
        self._protocol = None

        reason = (
            DisconnectReason.USER_CLOSED
            if expected
            else (DisconnectReason.ERROR if exc is not None else DisconnectReason.CONNECTION_LOST)
        )
        event = ConnectionClosedEvent(
            expected_disconnect=expected,
            reason=reason,
            error=exc,
        )
        for callback in tuple(self._disconnect_callbacks):
            try:
                callback(event)
            except Exception:
                LOGGER.exception("Error in connection closed callback")

    def add_connection_closed_callback(
        self,
        callback: Callable[[ConnectionClosedEvent], None],
    ) -> Callable[[], None]:
        """Register a callback invoked when the connection closes.

        Returns an unsubscribe callable.
        """
        self._disconnect_callbacks.append(callback)

        def _remove() -> None:
            if callback in self._disconnect_callbacks:
                self._disconnect_callbacks.remove(callback)

        return _remove

    def subscribe_serial_proxy_data(
        self,
        callback: Callable[[SerialProxyDataReceived], None],
    ) -> Callable[[], None]:
        """Register a callback to receive incoming serial proxy data.

        Returns an unsubscribe callable.
        """
        self._data_callbacks.append(callback)

        def _remove() -> None:
            if callback in self._data_callbacks:
                self._data_callbacks.remove(callback)

        return _remove

    async def device_info(self, force_refresh: bool = False) -> WaveshareDeviceInfo:
        """Query device identity, network configuration, and serial proxy information.

        Queries the native binary ZLAN protocol on UDP port 1092, and if the management
        UDP port is filtered/unreachable returns a synthesized WaveshareDeviceInfo for
        the connected TCP endpoint.
        """
        if self._cached_device_info is not None and not force_refresh:
            return self._cached_device_info

        # 1. Query native ZLAN binary protocol on UDP port 1092
        try:
            info = await async_query_device_udp(
                self.host,
                port=self.udp_port,
                timeout=min(2.0, self.connect_timeout),
            )
            self._cached_device_info = info
            if info.state is not None:
                self._serial_config = info.state.serial_config
            return info
        except WaveshareError as udp_err:
            LOGGER.debug("UDP 1092 query to %s failed: %s", self.host, udp_err)

        # 2. Synthesize default device info for the endpoint if UDP is filtered
        fallback_state = WaveshareDeviceState(
            tcp_connected=self.is_connected,
            txd_bytes=self._txd_bytes,
            rxd_bytes=self._rxd_bytes,
            work_mode=WaveshareWorkMode.TCP_SERVER,
            app_protocol=WaveshareAppProtocol.TRANSPARENT,
            serial_config=self._serial_config,
        )
        fallback_info = WaveshareDeviceInfo(
            name=f"Waveshare ({self.host}:{self.port})",
            mac_address="00:00:00:00:00:00",
            device_id=b"\x00" * 6,
            ip_address=self.host,
            tcp_port=self.port,
            serial_proxies=[
                SerialProxyInfo(
                    name=f"UART0 ({self.host}:{self.port})",
                    port_type="RS485/RS232",
                    instance=0,
                )
            ],
            state=fallback_state,
        )
        self._cached_device_info = fallback_info
        return fallback_info

    async def get_device_state(self, force_refresh: bool = True) -> WaveshareDeviceState:
        """Query the current operational state of the Waveshare device."""
        if force_refresh:
            try:
                info = await async_query_device_udp(
                    self.host,
                    port=self.udp_port,
                    timeout=min(2.0, self.connect_timeout),
                )
                self._cached_device_info = info
                if info.state is not None:
                    self._serial_config = info.state.serial_config
                    return info.state
            except WaveshareError:
                pass

        if self._cached_device_info is not None and self._cached_device_info.state is not None:
            state = self._cached_device_info.state
            return WaveshareDeviceState(
                tcp_connected=self.is_connected or state.tcp_connected,
                txd_bytes=max(self._txd_bytes, state.txd_bytes),
                rxd_bytes=max(self._rxd_bytes, state.rxd_bytes),
                work_mode=state.work_mode,
                app_protocol=state.app_protocol,
                serial_config=self._serial_config,
            )

        return WaveshareDeviceState(
            tcp_connected=self.is_connected,
            txd_bytes=self._txd_bytes,
            rxd_bytes=self._rxd_bytes,
            work_mode=WaveshareWorkMode.TCP_SERVER,
            app_protocol=WaveshareAppProtocol.TRANSPARENT,
            serial_config=self._serial_config,
        )

    async def reboot(self) -> None:
        """Reboot the Waveshare device via UDP port 1092."""
        info = await self.device_info()
        if info.raw_params is not None:
            await async_reboot_device_udp(
                self.host,
                info.raw_params,
                port=self.udp_port,
            )
            return

        # Fetch fresh UDP parameters if raw_params wasn't cached yet
        fresh_info = await async_query_device_udp(
            self.host,
            port=self.udp_port,
            timeout=min(3.0, self.connect_timeout),
        )
        if fresh_info.raw_params is None:
            raise WaveshareConfigurationError(
                "Device did not return raw parameter block for reboot"
            )
        await async_reboot_device_udp(
            self.host,
            fresh_info.raw_params,
            port=self.udp_port,
        )

    async def serial_proxy_subscribe(
        self,
        instance: int = 0,
        *,
        timeout: float | None = None,
    ) -> SerialProxyRequestResponse:
        """Subscribe to incoming serial data for a serial proxy instance."""
        if not self.is_connected:
            await self.connect(fetch_info=False)
        self._subscribed_instances.add(instance)
        return SerialProxyRequestResponse(
            instance=instance,
            status=SerialProxyStatus.OK,
        )

    # Alias for callers expecting explicit await_response naming
    serial_proxy_subscribe_await_response = serial_proxy_subscribe

    async def serial_proxy_unsubscribe(
        self,
        instance: int = 0,
    ) -> SerialProxyRequestResponse:
        """Unsubscribe from incoming serial data for a serial proxy instance."""
        self._subscribed_instances.discard(instance)
        return SerialProxyRequestResponse(
            instance=instance,
            status=SerialProxyStatus.OK,
        )

    async def serial_proxy_configure(
        self,
        instance: int,
        baudrate: int,
        *,
        flow_control: bool = False,
        parity: SerialProxyParity = SerialProxyParity.NONE,
        stop_bits: int = 1,
        data_size: int = 8,
        timeout: float | None = None,
    ) -> SerialProxyRequestResponse:
        """Dynamically configure serial port framing and baudrate."""
        if not self.is_connected or self._transport is None:
            raise WaveshareConnectionError("Cannot configure serial port when TCP is not connected")

        flow_enum = SerialProxyFlowControl.CTS_RTS if flow_control else SerialProxyFlowControl.NONE
        stop_enum = SerialProxyStopBits.TWO if stop_bits == 2 else SerialProxyStopBits.ONE
        new_config = WaveshareSerialConfig(
            baudrate=baudrate,
            data_size=data_size,
            parity=SerialProxyParity(parity),
            stop_bits=stop_bits,
            flow_control=flow_enum,
        )

        try:
            if self.config_mode == ConfigMode.RFC2217:
                payload = build_rfc2217_configure(
                    baudrate=baudrate,
                    data_size=data_size,
                    parity=SerialProxyParity(parity),
                    stop_bits=stop_enum,
                    flow_control=flow_enum,
                )
                self._transport.write(payload)
            elif self.config_mode == ConfigMode.WAVESHARE_8BYTE:
                payload = build_waveshare_8byte_configure(
                    baudrate=baudrate,
                    data_size=data_size,
                    parity=SerialProxyParity(parity),
                    stop_bits=stop_bits,
                )
                self._transport.write(payload)
            elif self.config_mode == ConfigMode.REALCOM:
                payload = build_realcom_configure(
                    baudrate=baudrate,
                    data_size=data_size,
                    parity=SerialProxyParity(parity),
                    stop_bits=stop_bits,
                    flow_control=flow_enum,
                )
                self._transport.write(payload)
            elif self.config_mode == ConfigMode.ZLAN_CMD_GEN2:
                payload = self._zlan_codec.build_serial_config_ram_gen2(
                    baudrate=baudrate,
                    data_size=data_size,
                    parity=SerialProxyParity(parity),
                    stop_bits=stop_bits,
                    flow_control=flow_enum,
                )
                self._transport.write(payload)
            elif self.config_mode == ConfigMode.UDP_1092:
                info = await self.device_info()
                await async_configure_serial_udp(
                    self.host,
                    info.device_id,
                    new_config,
                    save_to_flash=False,
                    base_params=info.raw_params,
                    port=self.udp_port,
                )
            elif self.config_mode == ConfigMode.RAW:
                # Raw transparent mode does not send in-band configuration frames
                pass
        except WaveshareConfigurationError as err:
            return SerialProxyRequestResponse(
                instance=instance,
                status=SerialProxyStatus.INVALID_ARGUMENT,
                error_message=str(err),
            )
        except WaveshareError as err:
            return SerialProxyRequestResponse(
                instance=instance,
                status=SerialProxyStatus.ERROR,
                error_message=str(err),
            )

        self._serial_config = new_config
        return SerialProxyRequestResponse(
            instance=instance,
            status=SerialProxyStatus.OK,
        )

    serial_proxy_configure_await_response = serial_proxy_configure

    def serial_proxy_write(
        self,
        instance: int,
        data: bytes | bytearray | memoryview,
    ) -> None:
        """Write raw bytes to the serial proxy port."""
        if not self.is_connected or self._transport is None:
            raise WaveshareConnectionError("Cannot write to serial proxy when TCP is not connected")

        raw_bytes = bytes(data)
        if not raw_bytes:
            return

        if self.config_mode == ConfigMode.RFC2217:
            wire_bytes = escape_rfc2217_data(raw_bytes)
        else:
            wire_bytes = raw_bytes

        self._transport.write(wire_bytes)
        self._txd_bytes += len(raw_bytes)

    async def serial_proxy_flush(
        self,
        instance: int = 0,
        *,
        timeout: float | None = None,
    ) -> SerialProxyRequestResponse:
        """Flush buffered serial data."""
        if not self.is_connected or self._transport is None:
            raise WaveshareConnectionError("Cannot flush serial proxy when TCP is not connected")

        if self.config_mode == ConfigMode.RFC2217:
            self._transport.write(build_rfc2217_purge())

        await asyncio.sleep(0)
        return SerialProxyRequestResponse(
            instance=instance,
            status=SerialProxyStatus.OK,
        )

    async def serial_proxy_set_modem_pins(
        self,
        instance: int = 0,
        *,
        line_states: LineStateFlag = LineStateFlag.NONE,
    ) -> SerialProxyRequestResponse:
        """Set RTS and/or DTR modem control pin states."""
        if not self.is_connected or self._transport is None:
            raise WaveshareConnectionError("Cannot set modem pins when TCP is not connected")

        rts = bool(line_states & LineStateFlag.RTS)
        dtr = bool(line_states & LineStateFlag.DTR)

        if self.config_mode == ConfigMode.RFC2217:
            self._transport.write(build_rfc2217_modem_pins(rts=rts, dtr=dtr))
            self._line_states = line_states
            return SerialProxyRequestResponse(
                instance=instance,
                status=SerialProxyStatus.OK,
            )

        self._line_states = line_states
        return SerialProxyRequestResponse(
            instance=instance,
            status=SerialProxyStatus.ASSUMED_SUCCESS,
        )

    serial_proxy_set_modem_pins_await_response = serial_proxy_set_modem_pins

    async def serial_proxy_get_modem_pins(
        self,
        instance: int = 0,
    ) -> SerialProxyModemPins:
        """Return the last known state of RTS and DTR modem control pins."""
        return SerialProxyModemPins(
            instance=instance,
            line_states=self._line_states,
        )
