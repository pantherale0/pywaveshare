#!/usr/bin/env python3
"""Read-only diagnostic script to inspect a Waveshare network serial adapter by IP address."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Allow running directly from the repository root without installing first
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pywaveshare import (
    DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT,
    ConfigMode,
    SerialProxyDataReceived,
    WaveshareClient,
    WaveshareError,
    async_query_device_udp,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only inspection tool for a Waveshare network RS232/RS485/RS422 adapter. "
            "Queries device metadata and live state via UDP port 1092 and optionally "
            "verifies TCP serial port reachability without writing any data or changing settings."
        )
    )
    parser.add_argument(
        "ip_address",
        help="IPv4 address or hostname of the Waveshare device (e.g. 192.168.1.200)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_TCP_PORT,
        help=f"TCP serial data port (default: {DEFAULT_TCP_PORT})",
    )
    parser.add_argument(
        "-u",
        "--udp-port",
        type=int,
        default=DEFAULT_UDP_PORT,
        help=f"UDP management port (default: {DEFAULT_UDP_PORT})",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=3.0,
        help="Connection and query timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--no-tcp",
        action="store_true",
        help="Only query UDP port 1092; do not open a TCP connection to the serial port",
    )
    parser.add_argument(
        "--listen",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Passively listen for incoming serial bytes for N seconds (read-only)",
    )
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> int:
    host: str = args.ip_address
    tcp_port: int = args.port
    udp_port: int = args.udp_port
    timeout: float = args.timeout

    print(f"=== Inspecting Waveshare Device at {host} (Read-Only) ===")

    # 1. Read-only unicast UDP query on port 1092 (0x5A 0x4C 0x04)
    print(f"\n[1/2] Querying UDP management port {host}:{udp_port} ...")
    try:
        info = await async_query_device_udp(host, port=udp_port, timeout=timeout)
    except WaveshareError as err:
        print(f"  UDP query failed: {err}")
        info = None
    else:
        print(f"  Device Name      : {info.name}")
        print(f"  Model            : {info.model}")
        print(f"  MAC Address      : {info.mac_address}")
        print(f"  Firmware Version : {info.firmware_version}")
        print(f"  IP Address       : {info.ip_address}")
        print(f"  Netmask          : {info.netmask}")
        print(f"  Gateway          : {info.gateway}")
        print(f"  DHCP Enabled     : {info.dhcp_enabled}")
        print(f"  Local TCP Port   : {info.tcp_port}")
        print(f"  Destination      : {info.dest_ip}:{info.dest_port}")
        print(f"  Web Server Port  : {info.web_port}")

        if info.state is not None:
            st = info.state
            sc = st.serial_config
            print("\n  --- Live Operational State ---")
            print(f"  TCP Connected    : {st.tcp_connected}")
            print(f"  Work Mode        : {st.work_mode.name} ({int(st.work_mode)})")
            print(f"  App Protocol     : {st.app_protocol.name} ({int(st.app_protocol)})")
            print(f"  TX Bytes Counter : {st.txd_bytes}")
            print(f"  RX Bytes Counter : {st.rxd_bytes}")
            print(
                f"  Serial Framing   : {sc.baudrate} baud, {sc.data_size} data bits, "
                f"parity={sc.parity.name}, stop_bits={sc.stop_bits}, "
                f"flow_control={sc.flow_control.name}"
            )

        if info.serial_proxies:
            print("\n  --- Exposed Serial Proxies ---")
            for proxy in info.serial_proxies:
                print(f"  Instance {proxy.instance}: name={proxy.name!r}, type={proxy.port_type}")

        # If the user left --port at default and the device reports a custom TCP port, note it
        if args.port == DEFAULT_TCP_PORT and info.tcp_port != DEFAULT_TCP_PORT:
            tcp_port = info.tcp_port

    if args.no_tcp:
        return 0 if info is not None else 1

    # 2. Read-only TCP connection check (ConfigMode.RAW ensures zero bytes are transmitted)
    print(f"\n[2/2] Testing read-only TCP connection to {host}:{tcp_port} ...")
    client = WaveshareClient(
        host=host,
        port=tcp_port,
        udp_port=udp_port,
        config_mode=ConfigMode.RAW,
        connect_timeout=timeout,
    )

    try:
        await client.connect(fetch_info=False)
        print(f"  TCP Connection   : Connected ({client.is_connected})")

        state = await client.get_device_state(force_refresh=info is not None)
        print(
            f"  Device State     : tcp_connected={state.tcp_connected}, "
            f"txd={state.txd_bytes}, rxd={state.rxd_bytes}"
        )

        if args.listen > 0:
            print(
                f"\n  Passively listening for incoming serial data for {args.listen:.1f}s "
                "(read-only)..."
            )

            def _on_data(msg: SerialProxyDataReceived) -> None:
                ascii_preview = msg.data.decode("ascii", errors="replace")
                print(
                    f"  [RX instance={msg.instance}] {len(msg.data)} bytes: "
                    f"hex={msg.data.hex(' ')} | ascii={ascii_preview!r}"
                )

            unsub = client.subscribe_serial_proxy_data(_on_data)
            await client.serial_proxy_subscribe(0)
            try:
                await asyncio.sleep(args.listen)
            finally:
                await client.serial_proxy_unsubscribe(0)
                unsub()
    except WaveshareError as err:
        print(f"  TCP connection failed: {err}")
        return 1
    finally:
        await client.disconnect()
        print("  TCP Connection   : Closed cleanly")

    return 0


def main() -> None:
    args = _parse_args()
    try:
        exit_code = asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
