# Controlled base image: the runtime environment for BYO (bring-your-own launch command) MCPs
#
# Contains: node (supergateway dependency), python + uv (for uvx MCPs), supergateway (stdio<->HTTP bridge).
# The orchestrator runs containers from this image with command = supergateway --stdio "<inner MCP command>".
#
# Build (on a machine with network access):
#   docker build -t mcp-runtime:1 deploy/mcp-runtime
# Offline deployment: save a tar -> load it once on the target host (one-time platform setup):
#   docker save -o mcp-runtime.tar mcp-runtime:1
#   # on the target host: docker load -i mcp-runtime.tar
#
# node 24 (current LTS): several MCP packages (e.g. firecrawl-mcp's dependency
# @mendable/firecrawl-js) require node >= 22; node 20 produces EBADENGINE warnings,
# and node 24 is the environment in which this project verified firecrawl-mcp working.
#
# The version is pinned by tag; when upgrading, also update src/orchestrator/launch_spec.MCP_RUNTIME_IMAGE
# or set the MCP_RUNTIME_IMAGE environment variable.
FROM node:24-slim

# python3 + uv (uvx) for python-based BYO MCPs;
# plus common system tools: MCPs from the npm ecosystem often shell out to them directly
# (example: @browsermcp/mcp runs `lsof -ti:PORT | xargs kill -9` at startup;
#  the slim image lacks lsof/kill, which makes that MCP fail to start).
#   lsof   -- find the process occupying a port
#   procps -- provides kill / ps / pgrep
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv curl ca-certificates lsof procps \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv \
    && ln -s /root/.local/bin/uvx /usr/local/bin/uvx

# supergateway: stdio <-> HTTP (SSE) bridge; installed globally so the orchestrator can invoke it as `supergateway`
RUN npm install -g supergateway

# Run as non-root (defence in depth; the BYO inner command is spawned by supergateway under this user)
RUN useradd -m -u 10001 mcp
USER mcp
WORKDIR /home/mcp

# No fixed ENTRYPOINT: the actual command is supplied by the orchestrator in containers.run
#   ["supergateway", "--stdio", "<inner cmd>", "--port", "<port>", "--host", "0.0.0.0"]
