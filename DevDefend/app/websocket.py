from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict

router = APIRouter()
_connections: Dict[str, WebSocket] = {}

@router.websocket("/ws/scan/{channel}")
async def scan_progress_ws(websocket: WebSocket, channel: str):
    await websocket.accept()
    _connections[channel] = websocket
    try:
        await websocket.send_text(f"connected:{channel}")
        while True:
            # This keeps the socket alive; in real use, you can receive pings or control messages
            msg = await websocket.receive_text()
            await websocket.send_text(f"echo:{msg}")
    except WebSocketDisconnect:
        _connections.pop(channel, None)

async def push_progress(channel: str, message: str):
    ws = _connections.get(channel)
    if ws:
        try:
            await ws.send_text(message)
        except Exception:
            _connections.pop(channel, None)
