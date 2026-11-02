"""Port allocator for Managed MCP bridges

Allocates a free TCP port for the supergateway bridge subprocess. Rules:
  1. Scan the default range (500 ports starting at 3457), skipping ports already taken by
     other Managed Processes in the DB and ports currently listening on the host
  2. Allocate the first port that passes both checks
  3. If the whole range is full, raise PortAllocationError

A process that already has a port keeps it (preferred_port) as long as it passes the same two checks:
clients have its URL configured, so a restart must not silently move it to the lowest free port.

Design considerations:
  - The double check (DB + socket bind) avoids race conditions: the DB alone could hand out
    a port that another process is using but has not yet written to the DB; the bind test
    alone could hand out a port reserved in the DB whose container has not started yet
"""

from __future__ import annotations

import socket
import uuid
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from db.models import ManagedMcpProcess


class PortAllocationError(Exception):
    """No free port available"""


class PortAllocator:
    """Allocate TCP ports within a range

    Default range starts at 3457 with 500 ports (i.e. 3457-3956) -- far more than enough for
    a single-vendor environment. To extend it later, just change the __init__ parameters.
    """

    def __init__(self, start_port: int = 3457, range_size: int = 500):
        if start_port < 1024:
            raise ValueError("start_port must be >= 1024")
        if range_size <= 0:
            raise ValueError("range_size must be positive")
        self.start_port = start_port
        self.range_size = range_size

    def _port_range(self) -> Iterable[int]:
        return range(self.start_port, self.start_port + self.range_size)

    @staticmethod
    def _is_port_listening(port: int) -> bool:
        """Check whether another process is already listening on 127.0.0.1:<port>"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return False
            except OSError:
                return True

    @staticmethod
    def _own_uuid(process_id: Optional[str]) -> Optional[uuid.UUID]:
        if not process_id:
            return None
        try:  # the id column is a native UUID; a string would make the driver choke on .hex
            return uuid.UUID(str(process_id))
        except ValueError:
            return None

    @classmethod
    def _db_used_ports(cls, db: Session, exclude_process_id: Optional[str] = None) -> set:
        """Managed Process ports already allocated in the DB (non-NULL port), other than exclude_process_id's"""
        q = db.query(ManagedMcpProcess.port).filter(ManagedMcpProcess.port.isnot(None))
        own_id = cls._own_uuid(exclude_process_id)
        if own_id is not None:
            q = q.filter(ManagedMcpProcess.id != own_id)
        return {r[0] for r in q.all() if r[0] is not None}

    def unavailable_reason(self, db: Session, port: int, exclude_process_id: Optional[str] = None) -> Optional[str]:
        """Why ``port`` cannot be used by ``exclude_process_id``'s instance, or None when it can.

        The caller is expected to have removed that process's own leftover instance first, so anything
        still bound to the port belongs to someone else."""
        if port in self._db_used_ports(db, exclude_process_id):
            return f"port {port} is assigned to another managed process"
        if self._is_port_listening(port):
            return f"port {port} is already in use on the host"
        return None

    def allocate(
        self, db: Session, exclude_process_id: Optional[str] = None, preferred_port: Optional[int] = None,
    ) -> int:
        """Return a free port

        Args:
            db: SQLAlchemy session
            exclude_process_id: allocating for an existing process -- its own DB port does not count as taken
            preferred_port: returned as-is when it is usable (e.g. the port the process already has, so a
                restart keeps its URL); otherwise the range is scanned for the lowest free port
        """
        used = self._db_used_ports(db, exclude_process_id)
        if preferred_port is not None and preferred_port not in used and not self._is_port_listening(preferred_port):
            return preferred_port

        for port in self._port_range():
            if port in used:
                continue
            if self._is_port_listening(port):
                continue
            return port

        raise PortAllocationError(
            f"No free port in range {self.start_port}-"
            f"{self.start_port + self.range_size - 1}"
        )
