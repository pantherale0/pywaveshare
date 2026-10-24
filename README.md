# pywaveshare

Asynchronous Python library for connecting to, inspecting, controlling, and exposing serial proxy transports for **Waveshare Network RS232/RS485/RS422 adapters** running standard Waveshare / ZLAN (`VirCom`) firmware (such as `RS485 TO ETH (B)`, `RS485 TO POE ETH (B)`, `RS232 TO ETH (B)`, `RS232/485/422 TO POE ETH (B)`, and multi-channel `2-CH` / `4-CH` / `8-CH RS485 TO ETH (B)` models).

## Features

- **Device Discovery & State Inspection**:
  - Broadcast LAN discovery and unicast status polling over UDP management port `1092` (170-byte `ZL` / `SSServerParam` binary protocol).
  - Exposes device name, MAC address / Device ID, firmware version, hardware model, active TCP connection status, TX/RX byte counters, and current serial framing configuration.
- **Dynamic Serial Configuration**:
  - **Standard RFC 2217 (`ConfigMode.RFC2217`)**: Telnet Com Port Control (`IAC SB 0x2C ... IAC SE`) for on-the-fly baudrate, data bits, parity, stop bits, flow control, RTS/DTR modem pins, and buffer purge.
  - **Waveshare 8-Byte Synchronous Baudrate (`ConfigMode.WAVESHARE_8BYTE`)**: Inline `55 AA 55` 8-byte control frame.
  - **ZLAN RealCom (`ConfigMode.REALCOM`)**: Native `FA 10 FB` 12-byte dynamic serial configuration and stream deframing (`FA 07 ...`, `FA 01 01`).
  - **ZLAN Gen-2 Command Stream (`ConfigMode.ZLAN_CMD_GEN2`)**: 10-byte identification header (`ED F2 A3 56 CA DB 91 84 B0 D7`) with CRC-16 verification.
  - **Out-of-Band UDP RAM Configuration (`ConfigMode.UDP_1092`)**: Updates serial parameters in device RAM via UDP port `1092` (`5A 4C 03`) without wearing flash or injecting bytes into transparent TCP streams.
- **Async Control API & Serial Proxy Transport**:
  - Clean `WaveshareClient` API with `connect()`, `device_info()`, `get_device_state()`, `serial_proxy_subscribe()`, `serial_proxy_configure()`, `serial_proxy_write()`, `serial_proxy_flush()`, `subscribe_serial_proxy_data()`, and `add_connection_closed_callback()`.
  - Native `serialx` transport (`WaveshareSerial` and `WaveshareSerialTransport`) and URI handler registration (`register_waveshare_uri_handler`) supporting both `waveshare://` URIs and externally managed `WaveshareClient` instances.
  - Built-in `asyncio` transport and stream helpers (`async_create_serial_connection` and `open_serial_connection`).

## Quick Start

### 1. Discover Devices & Query State

```python
import asyncio
from pywaveshare import WaveshareClient, async_discover_devices

async def main() -> None:
    devices = await async_discover_devices(timeout=2.0)
    for dev in devices:
        print(f"Found {dev.name} ({dev.model}) at {dev.ip_address}:{dev.tcp_port} [{dev.mac_address}]")

    client = WaveshareClient("192.168.1.200", port=4196)
    await client.connect()
    info = await client.device_info()
    state = await client.get_device_state()
    print(f"Connected: {state.tcp_connected}, TX={state.txd_bytes}, RX={state.rxd_bytes}")
    await client.disconnect()

asyncio.run(main())
```

### 2. Async Serial Proxy Client

```python
import asyncio
from pywaveshare import ConfigMode, SerialProxyParity, WaveshareClient

async def main() -> None:
    client = WaveshareClient(
        "192.168.1.200",
        port=4196,
        config_mode=ConfigMode.RFC2217,
    )
    await client.connect()

    unsub = client.subscribe_serial_proxy_data(
        lambda msg: print(f"Received on port {msg.instance}: {msg.data.hex()}")
    )

    await client.serial_proxy_subscribe(0)
    await client.serial_proxy_configure(
        0,
        baudrate=115200,
        parity=SerialProxyParity.NONE,
        stop_bits=1,
        data_size=8,
    )
    client.serial_proxy_write(0, b"\x01\x03\x00\x00\x00\x02\xc4\x0b")
    await client.serial_proxy_flush(0)

    unsub()
    await client.disconnect()

asyncio.run(main())
```

### 3. Using with `serialx` or Custom Integrator URI Schemes

```python
from pywaveshare import WaveshareClient, register_waveshare_uri_handler
from serialx import open_serial_connection

# Register the waveshare:// scheme with serialx
unregister = register_waveshare_uri_handler()

# Connect directly via URI:
# reader, writer = await open_serial_connection(
#     url="waveshare://192.168.1.200:4196/?config_mode=rfc2217",
#     baudrate=115200,
# )

# Or pass an existing WaveshareClient instance:
# client = WaveshareClient("192.168.1.200", 4196)
# await client.connect()
# reader, writer = await open_serial_connection(
#     client=client,
#     baudrate=115200,
# )
```
