"""
MCP (Model Context Protocol) server integration for KEA DHCP Reservations.

Implements JSON-RPC over SSE transport directly in Flask, avoiding
async/ASGI complexity. Provides tools for managing DHCP leases,
reservations, and subnets via MCP-compatible clients.
"""

import json
import uuid
import queue
import logging
import time
from flask import request, jsonify, Response, Blueprint, stream_with_context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------

MCP_TOOLS = [
    {
        "name": "list_leases",
        "description": "List active DHCP leases. Optionally filter by subnet ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "subnet_id": {
                    "type": "integer",
                    "description": "Optional subnet ID to filter leases"
                }
            }
        }
    },
    {
        "name": "list_reservations",
        "description": "List all DHCP reservations. Optionally filter by subnet ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "subnet_id": {
                    "type": "integer",
                    "description": "Optional subnet ID to filter reservations"
                }
            }
        }
    },
    {
        "name": "create_reservation",
        "description": "Create a new DHCP reservation for an IP/MAC pair.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IP address to reserve"
                },
                "hw_address": {
                    "type": "string",
                    "description": "Hardware (MAC) address"
                },
                "hostname": {
                    "type": "string",
                    "description": "Optional hostname for the reservation"
                },
                "subnet_id": {
                    "type": "integer",
                    "description": "Optional subnet ID"
                },
                "dns_servers": {
                    "type": "string",
                    "description": "Optional comma-separated DNS server IPs"
                }
            },
            "required": ["ip_address", "hw_address"]
        }
    },
    {
        "name": "delete_reservation",
        "description": "Delete a DHCP reservation by IP address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IP address of the reservation to delete"
                },
                "subnet_id": {
                    "type": "integer",
                    "description": "Optional subnet ID"
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "promote_lease",
        "description": "Promote an active DHCP lease to a permanent reservation. Finds the lease by IP and creates a reservation with the lease's MAC address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IP address of the lease to promote"
                },
                "hostname": {
                    "type": "string",
                    "description": "Optional hostname for the reservation"
                },
                "subnet_id": {
                    "type": "integer",
                    "description": "Optional subnet ID"
                },
                "dns_servers": {
                    "type": "string",
                    "description": "Optional comma-separated DNS server IPs"
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "list_subnets",
        "description": "List all configured DHCP subnets.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "delete_lease_by_ip",
        "description": "Delete a DHCP lease by IP address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IP address of the lease to delete"
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "delete_leases_by_mac",
        "description": "Delete all DHCP leases for a given MAC address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "Hardware (MAC) address whose leases should be deleted"
                }
            },
            "required": ["mac_address"]
        }
    },
    {
        "name": "export_reservations",
        "description": "Export all DHCP reservations as JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "import_reservations",
        "description": "Import DHCP reservations from a JSON array. Each item needs ip_address, hw_address, and optionally hostname, subnet_id, dns_servers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reservations": {
                    "type": "array",
                    "description": "Array of reservation objects to import",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ip_address": {"type": "string"},
                            "hw_address": {"type": "string"},
                            "hostname": {"type": "string"},
                            "subnet_id": {"type": "integer"},
                            "dns_servers": {"type": "string"}
                        },
                        "required": ["ip_address", "hw_address"]
                    }
                }
            },
            "required": ["reservations"]
        }
    },
    {
        "name": "health_check",
        "description": "Check connectivity to the KEA DHCP server and return status.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
]

# ---------------------------------------------------------------------------
# MCP Session Management
# ---------------------------------------------------------------------------

class McpSession:
    """Tracks a single MCP SSE session with a message queue."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.queue: queue.Queue = queue.Queue()
        self.created_at = time.time()

    def push(self, event: str, data: str):
        self.queue.put((event, data))

    def stream(self):
        """Generator that yields SSE frames."""
        # Send the endpoint event so the client knows where to POST messages
        endpoint_url = f"/mcp/messages?session_id={self.session_id}"
        yield f"event: endpoint\ndata: {endpoint_url}\n\n"

        while True:
            try:
                event, data = self.queue.get(timeout=30)
                yield f"event: {event}\ndata: {data}\n\n"
            except queue.Empty:
                # Send keepalive comment to prevent connection timeout
                yield ": keepalive\n\n"


# Active sessions keyed by session_id
_sessions: dict[str, McpSession] = {}

# ---------------------------------------------------------------------------
# Auth Helper
# ---------------------------------------------------------------------------

def validate_bearer_token(req):
    """Validate Bearer token using the same logic as the main app."""
    from app import load_config, AUTH_TOKEN, is_valid_session
    auth_header = req.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return False
    token = auth_header[7:]
    if is_valid_session(token):
        return True
    api_token = load_config().get('app', {}).get('api_token') or AUTH_TOKEN
    return token == api_token

# ---------------------------------------------------------------------------
# Tool Dispatch
# ---------------------------------------------------------------------------

def _build_option_data(dns_servers: str | None) -> list | None:
    """Build KEA option-data list from a DNS servers string."""
    if not dns_servers:
        return None
    return [{"name": "domain-name-servers", "data": dns_servers}]


def call_tool(name: str, arguments: dict) -> dict:
    """Dispatch an MCP tool call to the appropriate KeaClient method."""
    from app import get_kea_client

    client = get_kea_client()

    try:
        if name == "list_leases":
            subnet_id = arguments.get("subnet_id")
            leases = client.get_leases(subnet_id=subnet_id)
            return {"content": [{"type": "text", "text": json.dumps(leases, indent=2)}]}

        elif name == "list_reservations":
            subnet_id = arguments.get("subnet_id")
            reservations = client.get_reservations(subnet_id=subnet_id)
            return {"content": [{"type": "text", "text": json.dumps(reservations, indent=2)}]}

        elif name == "create_reservation":
            option_data = _build_option_data(arguments.get("dns_servers"))
            result = client.create_reservation(
                ip_address=arguments["ip_address"],
                hw_address=arguments["hw_address"],
                hostname=arguments.get("hostname", ""),
                subnet_id=arguments.get("subnet_id"),
                option_data=option_data,
            )
            return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

        elif name == "delete_reservation":
            client.delete_reservation(
                ip_address=arguments["ip_address"],
                subnet_id=arguments.get("subnet_id"),
            )
            return {"content": [{"type": "text", "text": f"Reservation for {arguments['ip_address']} deleted."}]}

        elif name == "promote_lease":
            ip = arguments["ip_address"]
            leases = client.get_leases()
            lease = next((l for l in leases if l.get("ip-address") == ip), None)
            if not lease:
                return {
                    "content": [{"type": "text", "text": f"No active lease found for IP {ip}"}],
                    "isError": True,
                }
            hw_address = lease.get("hw-address")
            option_data = _build_option_data(arguments.get("dns_servers"))
            result = client.create_reservation(
                ip_address=ip,
                hw_address=hw_address,
                hostname=arguments.get("hostname", lease.get("hostname", "")),
                subnet_id=arguments.get("subnet_id", lease.get("subnet-id")),
                option_data=option_data,
            )
            return {"content": [{"type": "text", "text": json.dumps({
                "promoted": True,
                "ip_address": ip,
                "hw_address": hw_address,
                "reservation": result,
            }, indent=2)}]}

        elif name == "list_subnets":
            subnets = client.get_subnets()
            return {"content": [{"type": "text", "text": json.dumps(subnets, indent=2)}]}

        elif name == "delete_lease_by_ip":
            count = client.delete_lease_by_ip(arguments["ip_address"])
            return {"content": [{"type": "text", "text": f"Deleted {count} lease(s) for IP {arguments['ip_address']}"}]}

        elif name == "delete_leases_by_mac":
            count = client.delete_leases_by_mac(arguments["mac_address"])
            return {"content": [{"type": "text", "text": f"Deleted {count} lease(s) for MAC {arguments['mac_address']}"}]}

        elif name == "export_reservations":
            reservations = client.get_reservations()
            return {"content": [{"type": "text", "text": json.dumps(reservations, indent=2)}]}

        elif name == "import_reservations":
            results = []
            for res in arguments["reservations"]:
                try:
                    option_data = _build_option_data(res.get("dns_servers"))
                    created = client.create_reservation(
                        ip_address=res["ip_address"],
                        hw_address=res["hw_address"],
                        hostname=res.get("hostname", ""),
                        subnet_id=res.get("subnet_id"),
                        option_data=option_data,
                    )
                    results.append({"ip_address": res["ip_address"], "status": "created"})
                except Exception as e:
                    results.append({"ip_address": res["ip_address"], "status": "error", "error": str(e)})
            return {"content": [{"type": "text", "text": json.dumps(results, indent=2)}]}

        elif name == "health_check":
            try:
                version = client.get_version()
                subnets = client.get_subnets()
                return {"content": [{"type": "text", "text": json.dumps({
                    "status": "healthy",
                    "kea_version": version,
                    "subnet_count": len(subnets),
                }, indent=2)}]}
            except Exception as e:
                return {
                    "content": [{"type": "text", "text": json.dumps({
                        "status": "unhealthy",
                        "error": str(e),
                    }, indent=2)}],
                    "isError": True,
                }

        else:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }

    except Exception as e:
        logger.exception(f"MCP tool {name} failed")
        return {
            "content": [{"type": "text", "text": f"Error: {str(e)}"}],
            "isError": True,
        }

# ---------------------------------------------------------------------------
# JSON-RPC Message Handler
# ---------------------------------------------------------------------------

def handle_mcp_message(message: dict) -> dict | None:
    """Process a single JSON-RPC 2.0 MCP message and return a response (or None for notifications)."""
    method = message.get("method", "")
    msg_id = message.get("id")
    params = message.get("params", {})

    # Notifications (no id) get no response
    is_notification = msg_id is None

    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": "kea-dhcp-mcp",
                "version": "1.0.0",
            },
        }
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    elif method == "notifications/initialized":
        return None  # client notification, no response

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": MCP_TOOLS},
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        result = call_tool(tool_name, tool_args)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result,
        }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    else:
        if is_notification:
            return None
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

# ---------------------------------------------------------------------------
# MCP Documentation Page
# ---------------------------------------------------------------------------

MCPDOCS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KEA DHCP - MCP Tools</title>
<style>
  :root { --bg: #0f1117; --surface: #1a1d27; --border: #2d3148; --text: #e1e4ed; --muted: #8b8fa3; --accent: #6c8cff; --accent2: #4fc1a6; --danger: #f87171; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
  .subtitle { color: var(--muted); margin-bottom: 2rem; font-size: 0.95rem; }
  .endpoint-info { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 2rem; }
  .endpoint-info code { background: var(--bg); padding: 2px 6px; border-radius: 4px; font-size: 0.9rem; color: var(--accent); }
  .tool { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
  .tool-name { font-size: 1.1rem; font-weight: 600; color: var(--accent2); font-family: monospace; }
  .tool-desc { color: var(--muted); margin: 0.5rem 0; font-size: 0.9rem; }
  .params { margin-top: 0.75rem; }
  .params-title { font-size: 0.8rem; text-transform: uppercase; color: var(--muted); letter-spacing: 0.05em; margin-bottom: 0.4rem; }
  .param { display: flex; gap: 0.75rem; padding: 0.3rem 0; font-size: 0.88rem; }
  .param-name { font-family: monospace; color: var(--accent); min-width: 120px; }
  .param-type { color: var(--muted); min-width: 70px; }
  .param-desc { color: var(--text); }
  .required { color: var(--danger); font-size: 0.75rem; margin-left: 4px; }
  .no-params { color: var(--muted); font-size: 0.85rem; font-style: italic; }
  a { color: var(--accent); }
</style>
</head>
<body>
<h1>KEA DHCP MCP Server</h1>
<p class="subtitle">Model Context Protocol tools for managing DHCP leases and reservations</p>

<div class="endpoint-info">
  <strong>SSE Endpoint:</strong> <code>GET /mcp/sse</code><br>
  <strong>Messages Endpoint:</strong> <code>POST /mcp/messages?session_id=...</code><br>
  <strong>Auth:</strong> Bearer token required (same as API). See <a href="/apidocs">/apidocs</a> for API docs.
</div>

TOOL_LIST_PLACEHOLDER
</body>
</html>"""


def _render_mcpdocs():
    """Build the /mcpdocs HTML from tool definitions."""
    parts = []
    for tool in MCP_TOOLS:
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        required = set(schema.get("required", []))

        params_html = ""
        if props:
            rows = []
            for pname, pinfo in props.items():
                req_badge = '<span class="required">required</span>' if pname in required else ""
                ptype = pinfo.get("type", "any")
                if ptype == "array":
                    ptype = "array"
                pdesc = pinfo.get("description", "")
                rows.append(
                    f'<div class="param">'
                    f'<span class="param-name">{pname}{req_badge}</span>'
                    f'<span class="param-type">{ptype}</span>'
                    f'<span class="param-desc">{pdesc}</span>'
                    f'</div>'
                )
            params_html = (
                '<div class="params">'
                '<div class="params-title">Parameters</div>'
                + "".join(rows)
                + '</div>'
            )
        else:
            params_html = '<div class="params"><span class="no-params">No parameters</span></div>'

        parts.append(
            f'<div class="tool">'
            f'<div class="tool-name">{tool["name"]}</div>'
            f'<div class="tool-desc">{tool["description"]}</div>'
            f'{params_html}'
            f'</div>'
        )

    html = MCPDOCS_HTML.replace("TOOL_LIST_PLACEHOLDER", "\n".join(parts))
    return html


# ---------------------------------------------------------------------------
# Flask Route Registration
# ---------------------------------------------------------------------------

def register_mcp_routes(app):
    """Register MCP SSE and message routes on the Flask app."""

    @app.route("/mcpdocs")
    def mcpdocs():
        from app import is_mcp_enabled
        html = _render_mcpdocs()
        if not is_mcp_enabled():
            banner = (
                '<div style="background:#b91c1c;color:#fff;padding:0.75rem 1.25rem;'
                'border-radius:8px;margin-bottom:1.5rem;font-weight:600;">'
                'MCP is currently disabled. Enable it in Settings or set '
                'MCP_ENABLED=true to use MCP endpoints.</div>'
            )
            html = html.replace('<div class="endpoint-info">', banner + '<div class="endpoint-info">')
        return html, 200, {"Content-Type": "text/html"}

    @app.route("/mcp/sse")
    def mcp_sse():
        from app import is_mcp_enabled
        if not is_mcp_enabled():
            return jsonify({"error": "MCP is not enabled. Enable it in Settings or set MCP_ENABLED=true"}), 404
        if not validate_bearer_token(request):
            return jsonify({"error": "Unauthorized"}), 401

        session_id = str(uuid.uuid4())
        session = McpSession(session_id)
        _sessions[session_id] = session
        logger.info(f"MCP SSE session created: {session_id}")

        def on_close(response):
            _sessions.pop(session_id, None)
            logger.info(f"MCP SSE session closed: {session_id}")
            return response

        resp = Response(stream_with_context(session.stream()), mimetype="text/event-stream")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Connection"] = "keep-alive"
        resp.headers["X-Accel-Buffering"] = "no"
        resp.call_on_close(lambda: _sessions.pop(session_id, None))
        return resp

    @app.route("/mcp/messages", methods=["POST"])
    def mcp_messages():
        from app import is_mcp_enabled
        if not is_mcp_enabled():
            return jsonify({"error": "MCP is not enabled. Enable it in Settings or set MCP_ENABLED=true"}), 404
        if not validate_bearer_token(request):
            return jsonify({"error": "Unauthorized"}), 401

        session_id = request.args.get("session_id")
        if not session_id or session_id not in _sessions:
            return jsonify({"error": "Invalid or missing session_id"}), 400

        session = _sessions[session_id]
        message = request.get_json(force=True)
        logger.info(f"MCP message [{session_id}]: method={message.get('method')}")

        response = handle_mcp_message(message)

        if response is not None:
            session.push("message", json.dumps(response))

        return "", 202

    logger.info("MCP routes registered: /mcp/sse, /mcp/messages, /mcpdocs")
