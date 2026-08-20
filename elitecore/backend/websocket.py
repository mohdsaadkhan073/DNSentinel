"""WebSocket connection manager for /ws/telemetry."""

import logging
from fastapi import WebSocket

logger = logging.getLogger("elitecore.websocket")


class ConnectionManager:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.clients.add(websocket)
        logger.info("Client connected. Total clients: %d", len(self.clients))

    def disconnect(self, websocket: WebSocket):
        self.clients.discard(websocket)
        logger.info("Client disconnected. Total clients: %d", len(self.clients))

    async def broadcast(self, event: dict):
        dead = []
        for client in self.clients:
            try:
                await client.send_json(event)
            except Exception:
                dead.append(client)
        for client in dead:
            self.disconnect(client)


manager = ConnectionManager()
