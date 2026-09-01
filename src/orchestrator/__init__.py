"""Managed MCP Orchestrator

Responsibility: start / stop / monitor sibling containers from the marketplace catalog,
and manage the supergateway bridge subprocess.

Architecture summary (see project discussion notes):
  - MCP Center runs with --network host
  - stdio MCPs such as Perplexity are started as siblings via /var/run/docker.sock
  - a supergateway Node.js subprocess is spawned as the stdio <-> HTTP bridge
  - the bridge binds to 127.0.0.1:<port>; agents connect directly, traffic bypasses MCP Center
"""

from src.orchestrator.port_allocator import PortAllocator, PortAllocationError

__all__ = ["PortAllocator", "PortAllocationError"]
