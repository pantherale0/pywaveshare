"""Serial proxy transport and stream abstractions for Waveshare network serial adapters."""

from __future__ import annotations

import asyncio
import dataclasses
import errno
import functools
import logging
import threading
import urllib.parse
from collections.abc import Callable, Coroutine
from contextlib import suppress
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar, cast

from .client import WaveshareClient
from .const import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT,
    ConfigMode,
    DisconnectReason,
    LineStateFlag,
    SerialProxyParity,
    SerialProxyStatus,
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
)

LOGGER = logging.getLogger(__name__)

_T = TypeVar("_T")
_P = ParamSpec("_P")

if not TYPE_CHECKING:
    try:
        from serialx import SerialException, UnsupportedSetting
        from serialx.common import (
            BaseSerial,
            BaseSerialTransport,
            ModemPins,
            Parity,
            PinState,
            PortSettingsUpdate,
            SerialPortInfo,
            StopBits,
            redact_uri,
        )
        from serialx.common import (
            register_uri_handler as _serialx_register_uri_handler,
        )

        HAS_SERIALX = True
    except ImportError:
        HAS_SERIALX = False
else:
    HAS_SERIALX = False
    _serialx_register_uri_handler: Any = None

if TYPE_CHECKING or not HAS_SERIALX:

    class SerialException(OSError):
        """Base exception for serial port errors."""

    class UnsupportedSetting(SerialException):
        """Raised when a requested serial setting is unsupported."""

    class Parity(StrEnum):
        """Serial parity setting compatible with serialx."""

        NONE = "N"
        EVEN = "E"
        ODD = "O"
        MARK = "M"
        SPACE = "S"

    class StopBits(float, Enum):
        """Serial stop bits setting compatible with serialx."""

        ONE = 1
        ONE_POINT_FIVE = 1.5
        TWO = 2

    class PinState(Enum):
        """Tristate modem control pin state compatible with serialx."""

        UNSET = None
        LOW = False
        HIGH = True

        @classmethod
        def convert(cls, value: bool | None) -> PinState:
            if value is None:
                return cls.UNSET
            return cls.HIGH if value else cls.LOW

    @dataclasses.dataclass(frozen=True)
    class ModemPins:
        """Modem pin states compatible with serialx."""

        dtr: PinState = PinState.UNSET
        rts: PinState = PinState.UNSET
        cts: PinState = PinState.UNSET
        dsr: PinState = PinState.UNSET
        rng: PinState = PinState.UNSET
        cd: PinState = PinState.UNSET

    @dataclasses.dataclass(frozen=True)
    class PortSettingsUpdate:
        """Port settings update payload."""

    @dataclasses.dataclass(frozen=True)
    class SerialPortInfo:
        """Discovered serial port metadata compatible with serialx."""

        device: str
        resolved_device: str
        vid: int | None = None
        pid: int | None = None
        serial_number: str | None = None
        manufacturer: str | None = None
        product: str | None = None
        bcd_device: int | None = None
        interface_description: int | str | None = None
        interface_num: int | None = None
        port_number: int | None = None

    def redact_uri(uri: str) -> str:
        """Redact sensitive query parameters from a URI."""
        parsed = urllib.parse.urlparse(uri)
        if not parsed.query:
            return uri
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for secret in ("password", "key"):
            if secret in params:
                params[secret] = ["***"]
        return urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(params, doseq=True))
        )

    class BaseSerial:
        """Fallback synchronous serial base class when serialx is not installed."""

        def __init__(
            self,
            path: str | None = None,
            baudrate: int = 115200,
            byte_size: int = 8,
            parity: Parity | str = Parity.NONE,
            stopbits: StopBits | float = StopBits.ONE,
            xonxoff: bool = False,
            rtscts: bool = False,
            dsrdtr: bool = False,
            timeout: float | None = None,
            write_timeout: float | None = None,
            **kwargs: Any,
        ) -> None:
            self._path = path
            self._baudrate = int(baudrate)
            self._byte_size = int(byte_size)
            self._parity = Parity(parity) if not isinstance(parity, Parity) else parity
            self._stopbits = (
                StopBits(stopbits) if not isinstance(stopbits, StopBits) else stopbits
            )
            self._xonxoff = bool(xonxoff)
            self._rtscts = bool(rtscts)
            self._dsrdtr = bool(dsrdtr)
            self._timeout = timeout
            self._write_timeout = write_timeout
            self._broken_error: BaseException | None = None

        @property
        def baudrate(self) -> int:
            return self._baudrate

        @property
        def byte_size(self) -> int:
            return self._byte_size

        @property
        def parity(self) -> Parity:
            return self._parity

        @property
        def stopbits(self) -> StopBits:
            return self._stopbits

        @property
        def rtscts(self) -> bool:
            return self._rtscts

        def _mark_broken(self, exc: BaseException) -> None:
            if self._broken_error is None:
                self._broken_error = exc

        def _check_broken(self) -> None:
            if self._broken_error is not None:
                raise self._broken_error

        def open(self) -> None:
            self._open()
            self._reconfigure_port(PortSettingsUpdate())

        def close(self) -> None:
            self._close()

        def write(self, data: bytes | bytearray | memoryview) -> int:
            self._check_broken()
            return self._write(data, timeout=self._write_timeout)

        def read(self, size: int = 1) -> bytes:
            buf = bytearray(size)
            n = self._readinto(buf, timeout=self._timeout)
            return bytes(buf[:n])

        def readinto(self, b: bytearray | memoryview) -> int:
            return self._readinto(b, timeout=self._timeout)

        def flush(self) -> None:
            self._flush()

        def _open(self) -> None:
            raise NotImplementedError

        def _close(self) -> None:
            raise NotImplementedError

        def _write(
            self, b: bytes | bytearray | memoryview, *, timeout: float | None
        ) -> int:
            raise NotImplementedError

        def _readinto(
            self, b: bytearray | memoryview, *, timeout: float | None
        ) -> int:
            raise NotImplementedError

        def _flush(self) -> None:
            raise NotImplementedError

        def _reconfigure_port(self, update: PortSettingsUpdate) -> None:
            raise NotImplementedError

        def __enter__(self) -> BaseSerial:
            if not getattr(self, "is_open", False):
                self.open()
            return self

        def __exit__(self, *exc_info: Any) -> None:
            self.close()

    class BaseSerialTransport(asyncio.Transport):
        """Fallback async serial transport base class when serialx is not installed."""

        def __init__(
            self, loop: asyncio.AbstractEventLoop, protocol: asyncio.Protocol
        ) -> None:
            super().__init__()
            self._loop = loop
            self._protocol = protocol
            self._closing = False
            self._connection_lost_called = False
            self._user_initiated_close = False
            self._broken_error: BaseException | None = None

        def get_protocol(self) -> asyncio.BaseProtocol:
            return self._protocol

        def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
            assert isinstance(protocol, asyncio.Protocol)
            self._protocol = protocol

        def _mark_broken(self, exc: BaseException) -> None:
            if self._broken_error is None:
                self._broken_error = exc

        def _check_broken(self) -> None:
            if self._broken_error is not None:
                raise self._broken_error

        def _mark_user_closed(self) -> None:
            self._user_initiated_close = True

        def _arm_close_timeout(self) -> None:
            pass

        def _call_protocol_connection_made(self) -> None:
            self._protocol.connection_made(self)

        def _call_protocol_connection_lost(self, exc: Exception | None) -> None:
            if self._connection_lost_called:
                return
            self._connection_lost_called = True
            self._loop.call_soon(self._protocol.connection_lost, exc)

        async def flush(self) -> None:
            await self._flush()

        async def get_modem_pins(self) -> ModemPins:
            return await self._get_modem_pins()

        async def set_modem_pins(
            self,
            modem_pins: ModemPins | None = None,
            *,
            dtr: bool | PinState | None = None,
            rts: bool | PinState | None = None,
        ) -> None:
            if modem_pins is None:
                modem_pins = ModemPins(
                    dtr=dtr if isinstance(dtr, PinState) else PinState.convert(dtr),
                    rts=rts if isinstance(rts, PinState) else PinState.convert(rts),
                )
            await self._set_modem_pins(modem_pins)

        async def reconfigure_port(
            self,
            *,
            baudrate: int | None = None,
            byte_size: int | None = None,
            parity: Parity | None = None,
            stopbits: StopBits | None = None,
            rtscts: bool | None = None,
        ) -> None:
            serial = getattr(self, "_serial", None)
            if serial is not None:
                if baudrate is not None:
                    serial._baudrate = baudrate
                if byte_size is not None:
                    serial._byte_size = byte_size
                if parity is not None:
                    serial._parity = parity
                if stopbits is not None:
                    serial._stopbits = stopbits
                if rtscts is not None:
                    serial._rtscts = rtscts
            await self._reconfigure_port(PortSettingsUpdate())

        async def _flush(self) -> None:
            raise NotImplementedError

        async def _get_modem_pins(self) -> ModemPins:
            raise NotImplementedError

        async def _set_modem_pins(self, modem_pins: ModemPins) -> None:
            raise NotImplementedError

        async def _reconfigure_port(self, update: PortSettingsUpdate) -> None:
            raise NotImplementedError


_REGISTERED_URI_HANDLERS: dict[str, dict[str, Any]] = {}

PARITY_MAP: dict[Parity, SerialProxyParity] = {
    Parity.NONE: SerialProxyParity.NONE,
    Parity.EVEN: SerialProxyParity.EVEN,
    Parity.ODD: SerialProxyParity.ODD,
    Parity.MARK: SerialProxyParity.MARK,
    Parity.SPACE: SerialProxyParity.SPACE,
}

STOP_BITS_MAP: dict[StopBits, int] = {
    StopBits.ONE: 1,
    StopBits.TWO: 2,
}

STATUS_TO_ERROR_MAP: dict[
    SerialProxyStatus | None,
    Callable[[str], SerialException | OSError] | None,
] = {
    SerialProxyStatus.OK: None,
    SerialProxyStatus.ASSUMED_SUCCESS: None,
    SerialProxyStatus.ERROR: lambda msg: SerialException(msg),
    SerialProxyStatus.TIMEOUT: lambda msg: SerialException(f"Operation timed out: {msg}"),
    SerialProxyStatus.NOT_SUPPORTED: lambda msg: SerialException(
        f"Operation is not supported: {msg}"
    ),
    SerialProxyStatus.PORT_IN_USE: lambda msg: OSError(
        errno.EBUSY, f"Serial proxy port is already in use: {msg}"
    ),
    SerialProxyStatus.INVALID_ARGUMENT: lambda msg: SerialException(
        f"Operation is invalid: {msg}"
    ),
}


class InvalidSettingsError(SerialException):
    """Raised when the provided URI or serial proxy settings are invalid."""


def translate_waveshare_errors(
    func: Callable[_P, Coroutine[Any, Any, _T]],
) -> Callable[_P, Coroutine[Any, Any, _T]]:
    """Translate WaveshareClient exceptions into standard SerialException/TimeoutError."""

    @functools.wraps(func)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return await func(*args, **kwargs)
        except WaveshareTimeoutError as exc:
            raise TimeoutError(str(exc)) from exc
        except WaveshareConfigurationError as exc:
            raise InvalidSettingsError(str(exc)) from exc
        except (WaveshareConnectionError, WaveshareError) as exc:
            raise SerialException(str(exc)) from exc

    return cast(Callable[_P, Coroutine[Any, Any, _T]], wrapper)


def connection_closed_error(event: ConnectionClosedEvent) -> OSError:
    """Translate a closed Waveshare connection event into an EIO OSError."""
    if event.error is not None:
        exc = OSError(errno.EIO, f"Waveshare connection closed: {event.error}")
        exc.__cause__ = event.error
        return exc

    if event.reason is not DisconnectReason.UNSPECIFIED:
        return OSError(
            errno.EIO, f"Waveshare device closed the connection: {event.reason.name}"
        )

    return OSError(errno.EIO, "Waveshare connection closed")


class WaveshareSerial(BaseSerial):
    """Synchronous serial interface over a Waveshare network serial adapter."""

    def __init__(
        self,
        *args: Any,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        loop: asyncio.AbstractEventLoop | None = None,
        client: WaveshareClient | None = None,
        api: WaveshareClient | None = None,
        port_name: str | None = None,
        port_instance: int | None = None,
        config_mode: ConfigMode | str = ConfigMode.RFC2217,
        udp_port: int = DEFAULT_UDP_PORT,
        password: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the Waveshare serial port."""
        super().__init__(*args, **kwargs)

        if client is not None and api is not None and client is not api:
            raise ValueError("Cannot pass two different instances for `client` and `api`")

        resolved_client = client if client is not None else api

        self._loop = loop
        self._loop_thread: threading.Thread | None = None
        self._connect_timeout = connect_timeout

        self._client: WaveshareClient | None = resolved_client
        self._client_loop: asyncio.AbstractEventLoop | None = (
            resolved_client.loop if resolved_client is not None else None
        )
        self._port_name: str | None = port_name
        self._port_info: SerialProxyInfo | None = None
        self._instance_id: int | None = port_instance
        self._config_mode: ConfigMode = ConfigMode(config_mode)
        self._udp_port: int = udp_port
        self._password: str | None = password
        self._disconnect_client: bool = False

        self._read_buffer = bytearray()
        self._read_event = asyncio.Event()
        self._unsub: Callable[[], None] | None = None
        self._closed_unsub: Callable[[], None] | None = None
        self._instance_subscribed = False

        self._last_line_states = LineStateFlag.NONE

    @property
    def client(self) -> WaveshareClient | None:
        """Return the underlying WaveshareClient instance."""
        return self._client

    @property
    def is_open(self) -> bool:
        """Return whether the serial port is open."""
        return self._client is not None and self._client.is_connected

    def _in_event_loop(self) -> bool:
        assert self._loop is not None
        try:
            return asyncio.get_running_loop() is self._loop
        except RuntimeError:
            return False

    def _call_on_loop(self, coro: Coroutine[Any, Any, _T]) -> _T:
        assert self._loop is not None
        if self._in_event_loop():
            coro.close()
            raise RuntimeError(
                "Cannot call synchronous WaveshareSerial method from its own event "
                "loop thread; use the async transport API instead."
            )
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    async def _call_on_client_loop(self, coro: Coroutine[Any, Any, _T]) -> _T:
        client_loop = self._client_loop
        if client_loop is None or client_loop is self._loop:
            return await coro
        return await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(coro, client_loop)
        )

    async def _call_on_client_loop_validated(self, coro: Coroutine[Any, Any, _T]) -> _T:
        result = await self._call_on_client_loop(coro)
        status = getattr(result, "status", None)
        if status is not None:
            error_factory = STATUS_TO_ERROR_MAP.get(status)
            if error_factory is not None:
                raise error_factory(getattr(result, "error_message", ""))
        return result

    def _schedule_on_client_loop(
        self,
        fn: Callable[_P, Any],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> None:
        client_loop = self._client_loop
        if client_loop is None or client_loop is self._loop:
            fn(*args, **kwargs)
            return
        client_loop.call_soon_threadsafe(functools.partial(fn, *args, **kwargs))

    def _maybe_start_new_event_loop(self) -> None:
        if self._loop is not None:
            return
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._loop_thread.start()

    def _on_data(self, msg: SerialProxyDataReceived) -> None:
        if self._instance_id is not None and msg.instance != self._instance_id:
            return
        client_loop = self._client_loop
        if client_loop is None or client_loop is self._loop:
            self._handle_incoming_data(msg.data)
        else:
            assert self._loop is not None
            self._loop.call_soon_threadsafe(self._handle_incoming_data, msg.data)

    def _handle_incoming_data(self, data: bytes) -> None:
        self._read_buffer.extend(data)
        self._read_event.set()

    def _on_connection_closed(self, event: ConnectionClosedEvent) -> None:
        client_loop = self._client_loop
        if client_loop is None or client_loop is self._loop:
            self._handle_connection_closed(event)
        else:
            assert self._loop is not None
            self._loop.call_soon_threadsafe(self._handle_connection_closed, event)

    def _handle_connection_closed(self, event: ConnectionClosedEvent) -> None:
        self._instance_subscribed = False
        self._mark_broken(connection_closed_error(event))
        self._read_event.set()
        self._unsubscribe_connection_closed()

    def _open(self) -> None:
        self._maybe_start_new_event_loop()
        self._read_event = asyncio.Event()
        self._call_on_loop(self._async_open())
        self._call_on_loop(self._async_register_data_handler())

    @translate_waveshare_errors
    async def _async_open(self) -> None:
        if self._client is None:
            if self._path is None:
                raise InvalidSettingsError(
                    "Cannot open a connection without a URI or a WaveshareClient instance"
                )

            parsed = urllib.parse.urlparse(str(self._path))
            params = urllib.parse.parse_qs(parsed.query)

            if "port_name" in params:
                port_value = params["port_name"][0]
            else:
                port_value = urllib.parse.unquote(parsed.path.strip("/"))

            if port_value.isdigit():
                self._instance_id = int(port_value)
            elif port_value and not self._port_name:
                self._port_name = port_value

            if "config_mode" in params:
                try:
                    self._config_mode = ConfigMode(params["config_mode"][0])
                except ValueError as err:
                    valid = ", ".join(m.value for m in ConfigMode)
                    mode_val = params["config_mode"][0]
                    raise InvalidSettingsError(
                        f"Invalid config_mode {mode_val!r}, expected one of: {valid}"
                    ) from err

            if "udp_port" in params:
                self._udp_port = int(params["udp_port"][0])

            if "password" in params:
                self._password = params["password"][0]

            if parsed.hostname is None:
                raise InvalidSettingsError(
                    f"URI {redact_uri(str(self._path))!r} is missing a hostname"
                )

            self._client = WaveshareClient(
                host=parsed.hostname,
                port=parsed.port or DEFAULT_TCP_PORT,
                udp_port=self._udp_port,
                config_mode=self._config_mode,
                password=self._password,
                connect_timeout=self._connect_timeout,
                loop=self._loop,
            )
            self._client_loop = self._client.loop
            self._disconnect_client = True
            await self._call_on_client_loop(self._client.connect(fetch_info=False))
        else:
            self._disconnect_client = False
            self._client_loop = self._client.loop
            if not self._client.is_connected:
                await self._call_on_client_loop(self._client.connect(fetch_info=False))

        if self._closed_unsub is None:
            self._closed_unsub = await self._call_on_client_loop(
                self._register_closed_handler()
            )

    async def _register_closed_handler(self) -> Callable[[], None]:
        assert self._client is not None
        return self._client.add_connection_closed_callback(self._on_connection_closed)

    @translate_waveshare_errors
    async def _async_register_data_handler(self) -> None:
        assert self._client is not None
        if self._unsub is not None:
            return
        self._unsub = await self._call_on_client_loop(self._register_data_handler())

    async def _register_data_handler(self) -> Callable[[], None]:
        assert self._client is not None
        return self._client.subscribe_serial_proxy_data(self._on_data)

    async def _resolve_instance_id(self) -> None:
        if self._client is None:
            return

        if self._instance_id is not None:
            return

        if self._port_name is None:
            # Waveshare adapters expose 1 UART per TCP port by default (instance 0)
            self._instance_id = 0
            return

        info = await self._call_on_client_loop(self._client.device_info())
        name_to_info = {
            proxy.name: (proxy.instance, proxy) for proxy in info.serial_proxies
        }
        if self._port_name not in name_to_info:
            known = list(name_to_info)
            raise ValueError(
                f"Serial proxy with name {self._port_name!r} does not exist in {known!r}"
            )
        self._instance_id, self._port_info = name_to_info[self._port_name]

    async def _subscribe_instance(self) -> None:
        if self._client is None or self._instance_subscribed:
            return

        await self._resolve_instance_id()
        assert self._instance_id is not None

        await self._call_on_client_loop_validated(
            self._client.serial_proxy_subscribe_await_response(
                self._instance_id,
                timeout=self._connect_timeout,
            )
        )
        self._instance_subscribed = True

    def _unsubscribe_instance(self) -> None:
        if self._client is None or not self._instance_subscribed:
            return

        assert self._instance_id is not None
        with suppress(WaveshareError):
            self._schedule_on_client_loop(
                lambda: asyncio.create_task(
                    self._client.serial_proxy_unsubscribe(self._instance_id)  # type: ignore[union-attr,arg-type]
                )
            )
        self._instance_subscribed = False

    def _reconfigure_port(self, update: PortSettingsUpdate) -> None:
        self._call_on_loop(self._async_configure_port())

    @translate_waveshare_errors
    async def _async_configure_port(self) -> None:
        if self._parity not in PARITY_MAP:
            raise UnsupportedSetting(f"Unsupported parity: {self._parity}")

        if self._stopbits not in STOP_BITS_MAP:
            raise UnsupportedSetting(f"Unsupported stop bits: {self._stopbits}")

        assert self._client is not None
        await self._resolve_instance_id()
        assert self._instance_id is not None

        await self._subscribe_instance()

        await self._call_on_client_loop_validated(
            self._client.serial_proxy_configure_await_response(
                instance=self._instance_id,
                baudrate=self._baudrate,
                flow_control=self._rtscts,
                parity=PARITY_MAP[self._parity],
                stop_bits=STOP_BITS_MAP[self._stopbits],
                data_size=self._byte_size,
                timeout=self._connect_timeout,
            )
        )

    def _compute_line_states(self, modem_pins: ModemPins) -> LineStateFlag:
        line_states = self._last_line_states
        if modem_pins.rts is PinState.HIGH:
            line_states |= LineStateFlag.RTS
        elif modem_pins.rts is PinState.LOW:
            line_states &= ~LineStateFlag.RTS

        if modem_pins.dtr is PinState.HIGH:
            line_states |= LineStateFlag.DTR
        elif modem_pins.dtr is PinState.LOW:
            line_states &= ~LineStateFlag.DTR

        self._last_line_states = line_states
        return line_states

    @translate_waveshare_errors
    async def _async_set_modem_pins(self, modem_pins: ModemPins) -> None:
        assert self._client is not None
        await self._resolve_instance_id()
        assert self._instance_id is not None

        line_states = self._compute_line_states(modem_pins)
        await self._call_on_client_loop_validated(
            self._client.serial_proxy_set_modem_pins_await_response(
                instance=self._instance_id,
                line_states=line_states,
            )
        )

    def _set_modem_pins(self, modem_pins: ModemPins) -> None:
        self._call_on_loop(self._async_set_modem_pins(modem_pins))

    def _get_modem_pins(self) -> ModemPins:
        return self._call_on_loop(self._async_get_modem_pins())

    @translate_waveshare_errors
    async def _async_get_modem_pins(self) -> ModemPins:
        assert self._client is not None
        await self._resolve_instance_id()
        assert self._instance_id is not None

        rsp = await self._call_on_client_loop(
            self._client.serial_proxy_get_modem_pins(instance=self._instance_id)
        )
        self._last_line_states = LineStateFlag(rsp.line_states)
        return ModemPins(
            dtr=PinState.convert(bool(rsp.line_states & LineStateFlag.DTR)),
            rts=PinState.convert(bool(rsp.line_states & LineStateFlag.RTS)),
        )

    def num_unread_bytes(self) -> int:
        return len(self._read_buffer)

    def num_unwritten_bytes(self) -> int:
        return 0

    def _reset_read_buffer(self) -> None:
        self._read_buffer.clear()

    def _reset_write_buffer(self) -> None:
        pass

    @translate_waveshare_errors
    async def _async_flush(self) -> None:
        assert self._client is not None
        await self._resolve_instance_id()
        assert self._instance_id is not None
        await self._call_on_client_loop_validated(
            self._client.serial_proxy_flush(instance=self._instance_id)
        )

    def _flush(self) -> None:
        self._call_on_loop(self._async_flush())

    def _write(
        self, b: bytes | bytearray | memoryview, *, timeout: float | None
    ) -> int:
        assert self._client is not None
        instance_id = self._instance_id if self._instance_id is not None else 0
        data = bytes(b)
        self._schedule_on_client_loop(
            self._client.serial_proxy_write, instance=instance_id, data=data
        )
        return len(data)

    def _readinto(
        self, b: bytearray | memoryview, *, timeout: float | None
    ) -> int:
        try:
            return self._call_on_loop(self._async_readinto(b, timeout))
        except TimeoutError:
            return 0

    async def _async_readinto(
        self, b: bytearray | memoryview, timeout: float | None
    ) -> int:
        async with asyncio.timeout(timeout):
            while not self._read_buffer:
                self._check_broken()
                self._read_event.clear()
                await self._read_event.wait()

        m = memoryview(b).cast("B")
        n = min(len(m), len(self._read_buffer))
        m[:n] = self._read_buffer[:n]
        del self._read_buffer[:n]
        return n

    @translate_waveshare_errors
    async def _async_list_serial_ports(self) -> list[SerialPortInfo]:
        assert self._client is not None
        info = await self._call_on_client_loop(self._client.device_info())
        ports: list[SerialPortInfo] = []
        for proxy in info.serial_proxies:
            query = {"port_name": proxy.name}
            url = urllib.parse.urlunparse(
                urllib.parse.ParseResult(
                    scheme="waveshare",
                    netloc=f"{self._client.host}:{self._client.port}",
                    path="/",
                    params="",
                    query=urllib.parse.urlencode(query),
                    fragment="",
                )
            )
            ports.append(
                SerialPortInfo(
                    device=url,
                    resolved_device=url,
                    manufacturer="Waveshare",
                    product=info.model,
                    serial_number=info.mac_address,
                    interface_description=proxy.name,
                )
            )
        return ports

    def _list_serial_ports(self) -> list[SerialPortInfo]:
        return self._call_on_loop(self._async_list_serial_ports())

    def _unsubscribe_connection_closed(self) -> None:
        if self._closed_unsub is not None:
            self._schedule_on_client_loop(self._closed_unsub)
            self._closed_unsub = None

    def _unsubscribe_callbacks(self) -> None:
        if self._unsub is not None:
            self._schedule_on_client_loop(self._unsub)
            self._unsub = None
        self._unsubscribe_connection_closed()

    async def _async_close(self) -> None:
        self._unsubscribe_callbacks()
        if self._disconnect_client and self._client is not None:
            self._unsubscribe_instance()
            await self._call_on_client_loop(self._client.disconnect())
            self._client = None

    def _close(self) -> None:
        self._unsubscribe_callbacks()
        if self._disconnect_client and self._client is not None:
            self._unsubscribe_instance()
            self._call_on_loop(self._call_on_client_loop(self._client.disconnect()))
            self._client = None

        if self._loop_thread is not None:
            assert self._loop is not None
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._loop_thread.join()
            self._loop.close()
            self._loop = None
            self._loop_thread = None


class WaveshareSerialTransport(BaseSerialTransport):
    """Asynchronous serial transport over a Waveshare network serial adapter."""

    transport_name = "waveshare"
    _serial_cls: type[WaveshareSerial] = WaveshareSerial
    _serial: WaveshareSerial | None

    def __init__(
        self, loop: asyncio.AbstractEventLoop, protocol: asyncio.Protocol
    ) -> None:
        """Initialize the Waveshare serial transport."""
        super().__init__(loop, protocol)
        self._serial = None
        self._unsub: Callable[[], None] | None = None
        self._closed_unsub: Callable[[], None] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._pending_data: list[bytes] | None = []
        if not hasattr(self, "_extra"):
            self._extra: dict[str, Any] = {}

    @translate_waveshare_errors
    async def _connect(
        self, *, path: str | None = None, **kwargs: Any
    ) -> None:
        self._serial = self._serial_cls(loop=self._loop, path=path, **kwargs)
        self._extra["serial"] = self._serial

        assert self._serial is not None
        await self._serial._async_open()

        assert self._serial._client is not None
        # Install data & disconnect handlers BEFORE subscribing and configuring the port
        # so any immediate bytes from the UART are buffered and replayed cleanly after
        # connection_made().
        self._unsub = await self._serial._call_on_client_loop(
            self._register_transport_data_handler()
        )
        self._closed_unsub = await self._serial._call_on_client_loop(
            self._register_transport_closed_handler()
        )

        if not self._serial._client.is_connected:
            raise SerialException("Waveshare TCP connection closed while connecting")

        await self._serial._async_configure_port()

        self._call_protocol_connection_made()

        pending_data, self._pending_data = self._pending_data, None
        assert pending_data is not None
        for data in pending_data:
            self._protocol.data_received(data)

    async def _register_transport_closed_handler(self) -> Callable[[], None]:
        assert self._serial is not None
        assert self._serial._client is not None
        return self._serial._client.add_connection_closed_callback(
            self._on_client_connection_closed
        )

    def _on_client_connection_closed(self, event: ConnectionClosedEvent) -> None:
        assert self._serial is not None
        client_loop = self._serial._client_loop
        if client_loop is None or client_loop is self._loop:
            self._client_connection_lost(event)
        else:
            self._loop.call_soon_threadsafe(self._client_connection_lost, event)

    def _client_connection_lost(self, event: ConnectionClosedEvent) -> None:
        if self._connection_lost_called:
            return

        self._closing = True
        if not self._user_initiated_close:
            self._mark_broken(connection_closed_error(event))

        exc = None if event.expected_disconnect else connection_closed_error(event)
        self._call_protocol_connection_lost(exc)

        if self._closed_unsub is not None:
            self._schedule_unsub(self._closed_unsub)
            self._closed_unsub = None

    def _schedule_unsub(self, unsub: Callable[[], None]) -> None:
        serial = self._serial
        if serial is not None:
            serial._schedule_on_client_loop(unsub)
        else:
            unsub()

    async def _register_transport_data_handler(self) -> Callable[[], None]:
        assert self._serial is not None
        assert self._serial._client is not None
        return self._serial._client.subscribe_serial_proxy_data(self._on_data)

    def _on_data(self, msg: SerialProxyDataReceived) -> None:
        assert self._serial is not None
        if (
            self._serial._instance_id is not None
            and msg.instance != self._serial._instance_id
        ):
            return

        client_loop = self._serial._client_loop
        if client_loop is None or client_loop is self._loop:
            self._deliver_data(msg.data)
        else:
            self._loop.call_soon_threadsafe(self._deliver_data, msg.data)

    def _deliver_data(self, data: bytes) -> None:
        if self._pending_data is not None:
            self._pending_data.append(data)
            return
        self._protocol.data_received(data)

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Write data to the Waveshare serial proxy."""
        self._check_broken()
        if self._closing:
            return
        assert self._serial is not None
        self._serial.write(data)

    def is_closing(self) -> bool:
        """Return whether the transport is closing."""
        return self._closing

    def close(self) -> None:
        """Close the transport."""
        if self._closing:
            return
        self._mark_user_closed()
        self._arm_close_timeout()
        self._close_with(None)

    def _close_with(self, exc: OSError | None) -> None:
        self._closing = True

        serial = self._serial
        if self._unsub is not None:
            self._schedule_unsub(self._unsub)
            self._unsub = None

        if self._closed_unsub is not None:
            self._schedule_unsub(self._closed_unsub)
            self._closed_unsub = None

        if serial is None:
            self._call_protocol_connection_lost(exc)
            return

        serial._unsubscribe_instance()
        serial._unsubscribe_callbacks()

        if not serial._disconnect_client:
            self._call_protocol_connection_lost(exc)
            return

        client = serial._client
        serial._client = None
        if client is None:
            self._call_protocol_connection_lost(exc)
            return

        self._close_task = self._loop.create_task(self._async_close(client, exc))

    def abort(self) -> None:
        """Abort the transport immediately."""
        self.close()

    async def _async_close(
        self, client: WaveshareClient, exc: OSError | None
    ) -> None:
        assert self._serial is not None
        try:
            await self._serial._call_on_client_loop(client.disconnect())
        finally:
            self._call_protocol_connection_lost(exc)

    async def _flush(self) -> None:
        assert self._serial is not None
        await self._serial._async_flush()

    async def _get_modem_pins(self) -> ModemPins:
        assert self._serial is not None
        return await self._serial._async_get_modem_pins()

    async def _set_modem_pins(self, modem_pins: ModemPins) -> None:
        assert self._serial is not None
        await self._serial._async_set_modem_pins(modem_pins)

    def get_write_buffer_size(self) -> int:
        return 0

    async def _reconfigure_port(self, update: PortSettingsUpdate) -> None:
        assert self._serial is not None
        await self._serial._async_configure_port()


def waveshare_list_serial_ports(*args: Any, **kwargs: Any) -> list[SerialPortInfo]:
    """List serial ports exposed by a Waveshare adapter synchronously."""
    serial = WaveshareSerial(*args, **kwargs)
    serial._maybe_start_new_event_loop()
    try:
        try:
            serial._call_on_loop(serial._async_open())
        except InvalidSettingsError:
            return []
        return serial._list_serial_ports()
    finally:
        serial._close()


async def async_waveshare_list_serial_ports(
    *args: Any, **kwargs: Any
) -> list[SerialPortInfo]:
    """List serial ports exposed by a Waveshare adapter asynchronously."""
    serial = WaveshareSerial(*args, **kwargs)
    try:
        await serial._async_open()
    except InvalidSettingsError:
        return []

    try:
        return await serial._async_list_serial_ports()
    finally:
        await serial._async_close()


def register_waveshare_uri_handler(
    scheme: str = "waveshare://",
    unique_scheme: str | None = None,
    sync_cls: type[WaveshareSerial] = WaveshareSerial,
    async_transport_cls: type[WaveshareSerialTransport] = WaveshareSerialTransport,
) -> None:
    """Register a URI handler for Waveshare serial ports with serialx (if installed)."""
    resolved_unique = unique_scheme or scheme
    _REGISTERED_URI_HANDLERS[scheme] = {
        "scheme": scheme,
        "unique_scheme": resolved_unique,
        "sync_cls": sync_cls,
        "async_transport_cls": async_transport_cls,
    }
    if HAS_SERIALX:
        _serialx_register_uri_handler(
            scheme=scheme,
            unique_scheme=resolved_unique,
            sync_cls=sync_cls,
            async_transport_cls=async_transport_cls,
            list_serial_ports_func=waveshare_list_serial_ports,
            async_list_serial_ports_func=async_waveshare_list_serial_ports,
        )


register_waveshare_uri_handler()


async def async_create_serial_connection(
    loop: asyncio.AbstractEventLoop,
    protocol_factory: Callable[[], asyncio.Protocol],
    url: str | None = None,
    *,
    transport_cls: type[WaveshareSerialTransport] = WaveshareSerialTransport,
    **kwargs: Any,
) -> tuple[WaveshareSerialTransport, asyncio.Protocol]:
    """Create an asynchronous serial transport and protocol connection."""
    protocol = protocol_factory()
    transport = transport_cls(loop, protocol)
    await transport._connect(path=url, **kwargs)
    return transport, protocol


async def open_serial_connection(
    url: str | None = None,
    *,
    loop: asyncio.AbstractEventLoop | None = None,
    limit: int = 65536,
    **kwargs: Any,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open an asyncio (StreamReader, StreamWriter) pair over a Waveshare serial proxy."""
    active_loop = loop or asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=limit, loop=active_loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=active_loop)
    transport, _ = await async_create_serial_connection(
        active_loop,
        lambda: protocol,
        url=url,
        **kwargs,
    )
    writer = asyncio.StreamWriter(transport, protocol, reader, active_loop)
    return reader, writer


__all__ = [
    "HAS_SERIALX",
    "BaseSerial",
    "BaseSerialTransport",
    "InvalidSettingsError",
    "ModemPins",
    "Parity",
    "PinState",
    "PortSettingsUpdate",
    "SerialException",
    "SerialPortInfo",
    "StopBits",
    "UnsupportedSetting",
    "WaveshareSerial",
    "WaveshareSerialTransport",
    "async_create_serial_connection",
    "async_waveshare_list_serial_ports",
    "open_serial_connection",
    "register_waveshare_uri_handler",
    "waveshare_list_serial_ports",
]
