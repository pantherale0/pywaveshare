"""Constants and enumerations for pywaveshare."""

from __future__ import annotations

from enum import IntEnum, IntFlag, StrEnum

DEFAULT_TCP_PORT = 4196
DEFAULT_UDP_PORT = 1092
DEFAULT_CONNECT_TIMEOUT = 10.0

ZLAN_UDP_MAGIC = b"ZL"  # 0x5A 0x4C
ZLAN_PARAM_SIZE = 167
ZLAN_PACKET_SIZE = 170  # 3-byte header + 167-byte SSServerParam

ZLAN_CMD_STREAM_MAGIC = bytes.fromhex("edf2a356cadb9184b0d7")
WAVESHARE_8BYTE_HEADER = b"\x55\xaa\x55"


class ZlanUdpCommand(IntEnum):
    """Command byte values in the 3-byte ZLAN UDP port 1092 header ('ZL' + cmd)."""

    DISCOVER = 0x00
    RESPONSE = 0x01
    RESPONSE_ALT = 0x02
    WRITE_RAM = 0x03
    QUERY_UNICAST = 0x04
    WRITE_FLASH = 0x07
    REBOOT = 0x0B
    ERROR_KEY = 0x0C


class ZlanStreamCommand(IntEnum):
    """Command byte values in the ZLAN 10-byte identification stream protocol."""

    READ_PARAM_GEN1 = 0x00
    WRITE_RAM_GEN1 = 0x01
    WRITE_MDIP_GEN1 = 0x02
    WRITE_FLASH_GEN1 = 0x03
    WRITE_FLASH_KEEP_TCP_GEN1 = 0x05
    WRITE_FLASH_REBOOT_GEN1 = 0x07
    READ_REG_GEN1 = 0x12
    WRITE_REG_GEN1 = 0x13

    # Gen-2 commands (with CRC-16)
    READ_PARAM_GEN2 = 0x80
    WRITE_RAM_GEN2 = 0x81
    WRITE_FLASH_GEN2 = 0x83
    WRITE_FLASH_REBOOT_GEN2 = 0x87
    READ_REG_GEN2 = 0x92
    WRITE_REG_GEN2 = 0x93

    # Gen-2 response codes
    RESP_FORMAT_ERROR = 0x0E
    RESP_OK = 0x0F
    RESP_OUT_OF_BOUNDS = 0x10


class Var2ParamType(IntEnum):
    """Variable parameter area (var2 at offset 115..166) TLV tag types."""

    END = 0
    FUN_SEL1 = 1
    WIFI_SSID = 2
    WIFI_CHANNEL = 3
    WIFI_KEY = 4
    WIFI_KEY_TYPE = 5
    VLAN_TCI = 6
    MULTI_DEST_IP = 7
    SOCKS5 = 8
    TXD_CNT = 9
    RXD_CNT = 10
    DEST_DNS_STRING = 11
    USER_DEF = 255


class ConfigMode(StrEnum):
    """Serial parameter configuration protocol mode."""

    RFC2217 = "rfc2217"
    WAVESHARE_8BYTE = "waveshare_8byte"
    REALCOM = "realcom"
    ZLAN_CMD_GEN2 = "zlan_cmd_gen2"
    UDP_1092 = "udp_1092"
    RAW = "raw"


class SerialProxyParity(IntEnum):
    """Serial parity setting."""

    NONE = 0
    ODD = 1
    EVEN = 2
    MARK = 3
    SPACE = 4


class SerialProxyStopBits(IntEnum):
    """Serial stop bits setting."""

    ONE = 1
    TWO = 2
    ONE_POINT_FIVE = 3


class SerialProxyFlowControl(IntEnum):
    """Serial flow control setting."""

    NONE = 0
    CTS_RTS = 1
    DSR_DTR = 2
    XON_XOFF = 3


class SerialProxyStatus(IntEnum):
    """Status codes returned by serial proxy operations."""

    OK = 0
    ASSUMED_SUCCESS = 1
    ERROR = 2
    TIMEOUT = 3
    NOT_SUPPORTED = 4
    PORT_IN_USE = 5
    INVALID_ARGUMENT = 6


class LineStateFlag(IntFlag):
    """Bitmap of serial modem control line states."""

    NONE = 0
    RTS = 1
    DTR = 2


class WaveshareWorkMode(IntEnum):
    """Network working mode of the Waveshare serial server."""

    TCP_SERVER = 0
    TCP_CLIENT = 1
    UDP = 2
    UDP_GROUP = 3


class WaveshareAppProtocol(IntEnum):
    """Application conversion protocol configured on the Waveshare serial server."""

    TRANSPARENT = 0
    MODBUS_TCP_RTU = 1
    REAL_COM = 2


class DisconnectReason(IntEnum):
    """Reason a client or serial proxy connection closed."""

    UNSPECIFIED = 0
    USER_CLOSED = 1
    CONNECTION_LOST = 2
    DEVICE_REBOOTED = 3
    ERROR = 4


# Baudrate index table used in SSServerParam (offset 0x25) and VirCom
INDEX_TO_BAUDRATE: dict[int, int] = {
    0: 1200,
    1: 2400,
    2: 4800,
    3: 7200,
    4: 9600,
    5: 14400,
    6: 19200,
    7: 28800,
    8: 38400,
    9: 57600,
    10: 76800,
    11: 115200,
    12: 230400,
    13: 460800,
    14: 300,
    15: 600,
}

BAUDRATE_TO_INDEX: dict[int, int] = {baud: idx for idx, baud in INDEX_TO_BAUDRATE.items()}

# Data bits index mapping in SSServerParam (offset 0x3B): 0=8, 1=7, 2=6, 3=5
INDEX_TO_DATASIZE: dict[int, int] = {
    0: 8,
    1: 7,
    2: 6,
    3: 5,
}

DATASIZE_TO_INDEX: dict[int, int] = {bits: idx for idx, bits in INDEX_TO_DATASIZE.items()}
