"""WebSocket connection management

Features:
- Manage WebSocket connections
- Broadcast health status changes
- Broadcast service added/removed events
"""

import asyncio
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Set, Optional, Any, Dict

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class WSMessageType(str, Enum):
    """WebSocket message types"""
    HEALTH_UPDATE = "health_update"
    SERVICE_ADDED = "service_added"
    SERVICE_REMOVED = "service_removed"
    SERVICE_UPDATED = "service_updated"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"


@dataclass
class WSMessage:
    """WebSocket message"""
    type: WSMessageType
    service_id: Optional[str] = None
    service_name: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_json(self) -> str:
        """Convert to a JSON string."""
        d = asdict(self)
        d["type"] = self.type.value
        return json.dumps(d)


class WSManager:
    """WebSocket connection manager

    Manages all WebSocket connections and provides broadcasting.
    """

    def __init__(self):
        """Initialize the WebSocket manager."""
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        """Get the number of connections."""
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection.

        Args:
            websocket: WebSocket connection
        """
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {self.connection_count}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection.

        Args:
            websocket: WebSocket connection
        """
        async with self._lock:
            self._connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {self.connection_count}")

    async def broadcast(self, message: WSMessage) -> int:
        """Broadcast a message to all connections.

        Args:
            message: WSMessage to send

        Returns:
            Number of connections the message was sent to successfully
        """
        if not self._connections:
            return 0

        message_json = message.to_json()
        sent_count = 0
        failed_connections = []

        async with self._lock:
            connections = list(self._connections)

        for websocket in connections:
            try:
                await websocket.send_text(message_json)
                sent_count += 1
            except Exception as e:
                logger.warning(f"Failed to send message to WebSocket: {e}")
                failed_connections.append(websocket)

        # Remove failed connections
        if failed_connections:
            async with self._lock:
                for ws in failed_connections:
                    self._connections.discard(ws)

        return sent_count

    async def broadcast_health_update(
        self,
        service_id: str,
        service_name: str,
        health: Dict[str, Any]
    ) -> int:
        """Broadcast a health status update.

        Args:
            service_id: Service ID
            service_name: Service name
            health: Health status data

        Returns:
            Number of connections the message was sent to successfully
        """
        message = WSMessage(
            type=WSMessageType.HEALTH_UPDATE,
            service_id=service_id,
            service_name=service_name,
            data=health
        )
        return await self.broadcast(message)

    async def broadcast_service_added(
        self,
        service_id: str,
        service_name: str,
        service_data: Optional[Dict[str, Any]] = None
    ) -> int:
        """Broadcast a service-added event.

        Args:
            service_id: Service ID
            service_name: Service name
            service_data: Service data (optional)

        Returns:
            Number of connections the message was sent to successfully
        """
        message = WSMessage(
            type=WSMessageType.SERVICE_ADDED,
            service_id=service_id,
            service_name=service_name,
            data=service_data
        )
        return await self.broadcast(message)

    async def broadcast_service_removed(
        self,
        service_id: str,
        service_name: str
    ) -> int:
        """Broadcast a service-removed event.

        Args:
            service_id: Service ID
            service_name: Service name

        Returns:
            Number of connections the message was sent to successfully
        """
        message = WSMessage(
            type=WSMessageType.SERVICE_REMOVED,
            service_id=service_id,
            service_name=service_name
        )
        return await self.broadcast(message)

    async def broadcast_service_updated(
        self,
        service_id: str,
        service_name: str,
        service_data: Optional[Dict[str, Any]] = None
    ) -> int:
        """Broadcast a service-updated event.

        Args:
            service_id: Service ID
            service_name: Service name
            service_data: Updated service data (optional)

        Returns:
            Number of connections the message was sent to successfully
        """
        message = WSMessage(
            type=WSMessageType.SERVICE_UPDATED,
            service_id=service_id,
            service_name=service_name,
            data=service_data
        )
        return await self.broadcast(message)

    async def send_to(self, websocket: WebSocket, message: WSMessage) -> bool:
        """Send a message to a specific connection.

        Args:
            websocket: Target WebSocket connection
            message: WSMessage to send

        Returns:
            Whether the send succeeded
        """
        try:
            await websocket.send_text(message.to_json())
            return True
        except Exception as e:
            logger.warning(f"Failed to send message: {e}")
            return False

    async def handle_connection(self, websocket: WebSocket) -> None:
        """Handle the full lifecycle of a WebSocket connection.

        A convenience method that handles connecting, receiving messages, disconnecting, etc.

        Args:
            websocket: WebSocket connection
        """
        await self.connect(websocket)
        try:
            while True:
                # Receive a message
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                    msg_type = msg.get("type")

                    # Handle ping
                    if msg_type == "ping":
                        await self.send_to(
                            websocket,
                            WSMessage(type=WSMessageType.PONG)
                        )
                except json.JSONDecodeError:
                    await self.send_to(
                        websocket,
                        WSMessage(
                            type=WSMessageType.ERROR,
                            data={"message": "Invalid JSON"}
                        )
                    )

        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            await self.disconnect(websocket)


# Global WebSocket manager instance
_ws_manager: Optional[WSManager] = None


def get_ws_manager() -> WSManager:
    """Get the WSManager singleton instance."""
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = WSManager()
    return _ws_manager
