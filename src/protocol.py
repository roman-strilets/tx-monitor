from enum import IntEnum

Address = tuple[str, int]

PROTO_MAGIC = b"\x42\x6D\x0A"
HEADER_SIZE = 8
MAC_SIZE = 8
MAX_FRAME_SIZE = 10 * 1024 * 1024

DEFAULT_PORT = 10000
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_REQUEST_TIMEOUT = 10.0
DEFAULT_IDLE_TIMEOUT = 3.0
DEFAULT_RECONNECT_DELAY = 5.0
EXTENSION_VERSION = 11

LOGIN_FLAG_SPREADING_TRANSACTIONS = 0x01
LOGIN_FLAG_SEND_PEERS = 0x04


class MessageType(IntEnum):
    """Beam protocol message type codes."""

    BYE = 0x01
    PING = 0x02
    PONG = 0x03
    SCHANNEL_INIT = 0x04
    SCHANNEL_READY = 0x05
    AUTHENTICATION = 0x06
    PEER_INFO = 0x08
    GET_TIME = 0x0B
    TIME = 0x0C
    LOGIN = 0x0F
    NEW_TIP = 0x10
    HAVE_TRANSACTION = 0x31
    GET_TRANSACTION = 0x32
    STATUS = 0x44
    NEW_TRANSACTION = 0x49


MESSAGE_NAMES = {
    MessageType.BYE: "Bye",
    MessageType.PING: "Ping",
    MessageType.PONG: "Pong",
    MessageType.SCHANNEL_INIT: "SChannelInitiate",
    MessageType.SCHANNEL_READY: "SChannelReady",
    MessageType.AUTHENTICATION: "Authentication",
    MessageType.PEER_INFO: "PeerInfo",
    MessageType.GET_TIME: "GetTime",
    MessageType.TIME: "Time",
    MessageType.LOGIN: "Login",
    MessageType.NEW_TIP: "NewTip",
    MessageType.HAVE_TRANSACTION: "HaveTransaction",
    MessageType.GET_TRANSACTION: "GetTransaction",
    MessageType.STATUS: "Status",
    MessageType.NEW_TRANSACTION: "NewTransaction",
}


def message_name(message_type: int | MessageType) -> str:
    """Get human-readable name for a message type.
    
    Returns the friendly name for known message types, or a hex representation
    for unknown codes. This allows the code to handle future protocol extensions
    gracefully.
    
    Args:
        message_type: Message type code (int or MessageType enum member)
    
    Returns:
        Human-readable message type name
    """
    if message_type in MESSAGE_NAMES:
        return MESSAGE_NAMES[message_type]
    return f"0x{message_type:02X}"