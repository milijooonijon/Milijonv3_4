import asyncio
import struct
import socket
import uuid
import logging
from typing import Optional, Tuple
from fastapi import WebSocket, WebSocketDisconnect
from app.database import get_user_by_uuid, get_user_by_password_hash, add_traffic

logger = logging.getLogger("milijon.proxy")

CHUNK_SIZE = 32768  # 32 KB buffer

async def pipe_ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, user_id: int):
    uploaded = 0
    try:
        while True:
            data = await websocket.receive_bytes()
            if not data:
                break
            writer.write(data)
            await writer.drain()
            uploaded += len(data)
    except (WebSocketDisconnect, asyncio.CancelledError, ConnectionResetError):
        pass
    except Exception as e:
        logger.debug(f"WS->TCP error: {e}")
    finally:
        if uploaded > 0:
            add_traffic(user_id, up=uploaded, down=0)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def pipe_tcp_to_ws(reader: asyncio.StreamReader, websocket: WebSocket, user_id: int, initial_prefix: bytes = b""):
    downloaded = 0
    first_packet = True
    try:
        while True:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                break
            if first_packet and initial_prefix:
                await websocket.send_bytes(initial_prefix + data)
                first_packet = False
            else:
                await websocket.send_bytes(data)
            downloaded += len(data)
    except (WebSocketDisconnect, asyncio.CancelledError, ConnectionResetError):
        pass
    except Exception as e:
        logger.debug(f"TCP->WS error: {e}")
    finally:
        if downloaded > 0:
            add_traffic(user_id, up=0, down=downloaded)
        try:
            await websocket.close()
        except Exception:
            pass

def parse_vless_header(data: bytes) -> Optional[Tuple[uuid.UUID, int, str, int, bytes]]:
    """
    Parses VLESS Request Header:
    Byte 0: Version (0x00)
    Bytes 1-16: UUID
    Byte 17: Protobuf addon len m
    Bytes 18..(18+m-1): Addons
    Next Byte: Command (0x01 = TCP, 0x02 = UDP, 0x03 = MUX)
    Next 2 Bytes: Port (Big Endian)
    Next Byte: Address Type (1: IPv4, 2: Domain, 3: IPv6)
    Next: Address
    Rest: Payload
    """
    if len(data) < 22:
        return None
    try:
        version = data[0]
        req_uuid = uuid.UUID(bytes=data[1:17])
        addon_len = data[17]
        idx = 18 + addon_len
        if len(data) < idx + 4:
            return None

        cmd = data[idx]
        port = struct.unpack("!H", data[idx+1 : idx+3])[0]
        addr_type = data[idx+3]
        idx += 4

        if addr_type == 1:  # IPv4
            if len(data) < idx + 4:
                return None
            host = socket.inet_ntoa(data[idx:idx+4])
            idx += 4
        elif addr_type == 2:  # Domain
            if len(data) < idx + 1:
                return None
            d_len = data[idx]
            idx += 1
            if len(data) < idx + d_len:
                return None
            host = data[idx:idx+d_len].decode("utf-8", errors="ignore")
            idx += d_len
        elif addr_type == 3:  # IPv6
            if len(data) < idx + 16:
                return None
            host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
            idx += 16
        else:
            return None

        payload = data[idx:]
        return req_uuid, cmd, host, port, payload
    except Exception as e:
        logger.debug(f"VLESS parse error: {e}")
        return None

async def handle_vless_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        initial_data = await asyncio.wait_for(websocket.receive_bytes(), timeout=10.0)
    except Exception:
        await websocket.close(code=1008)
        return

    parsed = parse_vless_header(initial_data)
    if not parsed:
        await websocket.close(code=1008)
        return

    req_uuid, cmd, host, port, payload = parsed
    user = get_user_by_uuid(str(req_uuid))
    if not user:
        logger.warning(f"VLESS auth failed for UUID: {req_uuid}")
        await websocket.close(code=1008)
        return

    user_id = user["id"]

    # Open TCP connection to target
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=10.0
        )
    except Exception as e:
        logger.warning(f"Failed to connect to {host}:{port} - {e}")
        # Send empty VLESS response header before closing
        try:
            await websocket.send_bytes(b"\x00\x00")
            await websocket.close()
        except Exception:
            pass
        return

    # If initial payload exists, forward to destination
    if payload:
        writer.write(payload)
        await writer.drain()
        add_traffic(user_id, up=len(payload), down=0)

    # VLESS response header: version 0, addon len 0
    vless_response_header = b"\x00\x00"

    # Pipe data concurrently
    task_ws_tcp = asyncio.create_task(pipe_ws_to_tcp(websocket, writer, user_id))
    task_tcp_ws = asyncio.create_task(pipe_tcp_to_ws(reader, websocket, user_id, initial_prefix=vless_response_header))

    await asyncio.gather(task_ws_tcp, task_tcp_ws, return_exceptions=True)

def parse_trojan_header(data: bytes) -> Optional[Tuple[str, int, str, int, bytes]]:
    """
    Parses Trojan Request Header:
    Bytes 0-55: 56 hex chars of SHA224(password)
    Bytes 56-57: \r\n
    Byte 58: Command (0x01 = TCP, 0x03 = UDP)
    Byte 59: Address Type (1: IPv4, 3: Domain, 4: IPv6)
    Next: Address
    Next 2 Bytes: Port
    Next 2 Bytes: \r\n
    Rest: Payload
    """
    if len(data) < 62:
        return None
    try:
        pass_hash = data[:56].decode("ascii", errors="ignore")
        if data[56:58] != b"\r\n":
            return None
        
        cmd = data[58]
        addr_type = data[59]
        idx = 60

        if addr_type == 1:  # IPv4
            if len(data) < idx + 4:
                return None
            host = socket.inet_ntoa(data[idx:idx+4])
            idx += 4
        elif addr_type == 3:  # Domain
            if len(data) < idx + 1:
                return None
            d_len = data[idx]
            idx += 1
            if len(data) < idx + d_len:
                return None
            host = data[idx:idx+d_len].decode("utf-8", errors="ignore")
            idx += d_len
        elif addr_type == 4:  # IPv6
            if len(data) < idx + 16:
                return None
            host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
            idx += 16
        else:
            return None

        if len(data) < idx + 4:
            return None
        port = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2

        if data[idx:idx+2] == b"\r\n":
            idx += 2

        payload = data[idx:]
        return pass_hash, cmd, host, port, payload
    except Exception as e:
        logger.debug(f"Trojan parse error: {e}")
        return None

async def handle_trojan_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        initial_data = await asyncio.wait_for(websocket.receive_bytes(), timeout=10.0)
    except Exception:
        await websocket.close(code=1008)
        return

    parsed = parse_trojan_header(initial_data)
    if not parsed:
        await websocket.close(code=1008)
        return

    pass_hash, cmd, host, port, payload = parsed
    user = get_user_by_password_hash(pass_hash)
    if not user:
        logger.warning(f"Trojan auth failed for hash: {pass_hash[:10]}...")
        await websocket.close(code=1008)
        return

    user_id = user["id"]

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=10.0
        )
    except Exception as e:
        logger.warning(f"Failed to connect to {host}:{port} - {e}")
        await websocket.close()
        return

    if payload:
        writer.write(payload)
        await writer.drain()
        add_traffic(user_id, up=len(payload), down=0)

    # Trojan does not require extra response header for TCP stream
    task_ws_tcp = asyncio.create_task(pipe_ws_to_tcp(websocket, writer, user_id))
    task_tcp_ws = asyncio.create_task(pipe_tcp_to_ws(reader, websocket, user_id, initial_prefix=b""))

    await asyncio.gather(task_ws_tcp, task_tcp_ws, return_exceptions=True)
