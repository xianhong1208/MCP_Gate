"""Port allocator for Managed MCP bridges

Allocates a free TCP port for the supergateway bridge subprocess. Rules:
  1. Scan the default range (500 ports starting at 3457), skipping ports already taken by
     other Managed Processes in the DB and ports currently listening on the host
  2. Allocate the first port that passes both checks
  3. If the whole range is full, raise PortAllocationError

Design considerations:
  - Manually specifying a port is not supported (MVP stage; to add vendor customisation
    later, just extend allocate() to accept a preferred_port parameter)
  - The double check (DB + socket bind) avoids race conditions: the DB alone could hand out
    a port that another process is using but has not yet written to the DB; the bind test
    alone could hand out a port reserved in the DB whose container has not started yet
"""

from __future__ import annotations

import socket
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
    def _db_used_ports(db: Session) -> set:
        """Managed Process ports already allocated in the DB (non-NULL port)"""
        rows = db.query(ManagedMcpProcess.port).filter(
            ManagedMcpProcess.port.isnot(None)
        ).all()
        return {r[0] for r in rows if r[0] is not None}

    def allocate(self, db: Session, exclude_process_id: Optional[str] = None) -> int:
        """Return a free port

        Args:
            db: SQLAlchemy session
            exclude_process_id: when re-allocating for an existing process, treat its
                current port as available (so it can "restart keeping the original port")
        """
        used = self._db_used_ports(db)
        if exclude_process_id:
            own = db.query(ManagedMcpProcess.port).filter(
                ManagedMcpProcess.id == exclude_process_id
            ).first()
            if own and own[0] is not None:
                used.discard(own[0])

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
