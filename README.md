# KEA DHCP Lease to Reservation Promotion GUI

A web-based GUI for promoting KEA DHCP leases to permanent reservations.

## Features

- Connect to KEA DHCP server via Control Agent API
- View active DHCPv4 leases
- Promote leases to permanent reservations with a single click
- **Import/Export DHCP reservations** - Backup and restore reservations easily
- Simple, intuitive web interface

## Architecture

- **Backend**: Python Flask application
- **Frontend**: HTML/JavaScript with Bootstrap
- **KEA Integration**: KEA Control Agent REST API
- **Deployment**: Docker container

## Prerequisites

- KEA DHCP server with Control Agent enabled
- **KEA Hook Libraries** (required):
  - `lease_cmds` - For viewing leases
  - `host_cmds` - For creating/managing reservations
- Docker (for containerized deployment)

## KEA Configuration Requirements

### 1. Enable Control Agent

Your KEA server must have the Control Agent running. Add this to your KEA configuration (`/etc/kea/kea-ctrl-agent.conf`):

```json
{
  "Control-agent": {
    "http-host": "0.0.0.0",
    "http-port": 8000,
    "control-sockets": {
      "dhcp4": {
        "socket-type": "unix",
        "socket-name": "/tmp/kea4-ctrl-socket"
      }
    }
  }
}
```

### 2. Enable Required Hook Libraries (CRITICAL)

**Both of these libraries are essential for the GUI to work!**

Edit your DHCPv4 configuration (`/etc/kea/kea-dhcp4.conf`) and add both hook libraries:

```json
{
  "Dhcp4": {
    "hooks-libraries": [
      {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so",
        "parameters": {}
      },
      {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_host_cmds.so",
        "parameters": {}
      }
    ],
    // ... rest of your configuration
  }
}
```

**Common hook library paths:**
- **Debian/Ubuntu**: `/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_*.so`
- **CentOS/RHEL**: `/usr/lib64/kea/hooks/libdhcp_*.so`
- **FreeBSD**: `/usr/local/lib/kea/hooks/libdhcp_*.so`
- **Alpine Linux**: `/usr/lib/kea/hooks/libdhcp_*.so`

After modifying the configuration, restart KEA:

```bash
sudo systemctl restart kea-dhcp4-server
sudo systemctl restart kea-ctrl-agent
```

**To verify it's working:**

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"command": "list-commands", "service": ["dhcp4"]}' \
  http://localhost:8000

# You should see these commands:
# - lease4-get-all (from lease_cmds)
# - reservation-add (from host_cmds)
```

## Configuration

Edit `config.yaml` with your KEA server details:

```yaml
kea:
  control_agent_url: "http://your-kea-server:8000"
  # Optional authentication
  username: ""
  password: ""
```

## Running Locally

```bash
pip install -r requirements.txt
python app.py
```

Visit:
- **Web UI:** `http://localhost:5000`
- **API Documentation:** `http://localhost:5000/apidocs`

## Running with Docker

### Using Pre-built Image (Recommended)

**Important:** You must mount a configuration file for the container to work properly!

```bash
# 1. Create a config.yaml file on your host
cat > config.yaml << 'EOF'
kea:
  control_agent_url: "https://your-kea-server:8000"
  username: "admin"
  password: "your-password"
  default_subnet_id: 1

app:
  host: "0.0.0.0"
  port: 5000
  debug: false
  
logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
EOF

# 2. Pull the latest image
docker pull awkto/kea-gui-reservations:latest

# 3. Run with your config mounted
docker run -d \
  --name kea-gui \
  -p 5000:5000 \
  -v $(pwd)/config.yaml:/app/config/config.yaml:ro \
  awkto/kea-gui-reservations:latest

# 4. Check logs to verify config was loaded
docker logs kea-gui | head -20
# Should see: "✅ Loaded configuration from /app/config/config.yaml"
```

**⚠️ Common Mistake:** Forgetting to mount the config file will cause the container to use default settings (localhost), which will fail!

### Using Docker Compose (Easiest)

```bash
# 1. Clone the repository or create these files:
# - docker-compose.yml
# - config.yaml

# 2. Edit config.yaml with your KEA server details

# 3. Start the container
docker-compose up -d

# 4. View logs
docker-compose logs -f
```

### Verifying Configuration

After starting the container, verify the config was loaded:

```bash
# Check config file exists in container
docker exec kea-gui cat /app/config/config.yaml

# Check via API
curl http://localhost:5000/api/config | jq '.config.kea.control_agent_url'

# Check health
curl http://localhost:5000/api/health
```

**Troubleshooting:** If you see errors connecting to localhost when you configured a different server, see [DOCKER_CONFIG_TROUBLESHOOTING.md](DOCKER_CONFIG_TROUBLESHOOTING.md)

### Building from Source

```bash
docker build -t kea-gui .
docker run -d -p 5000:5000 -v $(pwd)/config.yaml:/app/config/config.yaml:ro kea-gui
```

## API Documentation

### Interactive API Explorer

This application includes **Swagger/OpenAPI documentation** with an interactive API explorer:

**📚 Access the API documentation at: `http://localhost:5000/apidocs`**

The Swagger UI provides:
- Complete API reference with request/response schemas
- Interactive "Try it out" functionality to test endpoints directly
- Example requests and responses for each endpoint
- Parameter descriptions and validation rules

### API Endpoints Summary

- `GET /api/health` - Health check and KEA connectivity status
- `GET /api/leases` - Fetch all DHCPv4 leases (optional: filter by subnet)
- `GET /api/reservations` - List current reservations (optional: filter by subnet)
- `POST /api/reservations` - Create a new reservation
- `POST /api/promote` - Promote a lease to permanent reservation
- `DELETE /api/reservation/<ip>` - Delete a reservation
- `GET /api/reservations/export` - Export all reservations to JSON file
- `POST /api/reservations/import` - Import reservations from JSON file
- `GET /api/subnets` - Get configured DHCP subnets
- `POST /api/validate-ip` - Validate IP address against subnet
- `GET /api/config` - Get current configuration (sanitized)
- `POST /api/config` - Save configuration to file

For detailed documentation including request/response schemas, visit `/apidocs` when the application is running.

## Usage

### Managing Leases and Reservations

1. Access the web interface
2. View the list of active DHCP leases
3. Click "Promote" next to any lease
4. Confirm the action
5. The lease is converted to a permanent reservation in KEA

### Import/Export Reservations

**Export Reservations:**
1. Click the "Import/Export" dropdown button
2. Select "Export Reservations"
3. A JSON file will be downloaded to your machine containing all current reservations
4. You can optionally filter by subnet before exporting

**Import Reservations:**
1. Click the "Import/Export" dropdown button
2. Select "Import Reservations"
3. Choose a JSON file from your computer (see `sample_reservations.json` for format)
4. Click "Import" to begin the process
5. The system will:
   - Process each reservation one by one
   - Continue importing even if individual reservations fail
   - Display a summary showing:
     - Number of successfully imported reservations
     - Number of failed imports
     - Details of any failures (duplicate IPs, subnet mismatches, etc.)

**Import File Format:**
The import file should be a JSON file with this structure:
```json
{
  "reservations": [
    {
      "ip-address": "192.168.1.100",
      "hw-address": "aa:bb:cc:dd:ee:01",
      "hostname": "device1",
      "subnet-id": 1
    }
  ]
}
```

Or simply an array of reservations:
```json
[
  {
    "ip-address": "192.168.1.100",
    "hw-address": "aa:bb:cc:dd:ee:01",
    "hostname": "device1",
    "subnet-id": 1
  }
]
```

See `sample_reservations.json` in the repository for a complete example.

**Note:** Import failures can occur due to:
- Duplicate IP addresses (reservation already exists)
- IP addresses outside the subnet range
- Invalid MAC addresses
- Missing required fields

The import process will continue even if individual reservations fail, and you'll receive a detailed report at the end.

## MCP (Model Context Protocol) Integration

This app includes a built-in MCP server for AI agent integration (e.g., Claude Code). MCP allows AI assistants to manage DHCP leases and reservations programmatically.

### Enabling MCP

Set the `MCP_ENABLED` environment variable:

```bash
docker run -d -p 5000:5000 \
  -e MCP_ENABLED=true \
  -v $(pwd)/config.yaml:/app/config/config.yaml:ro \
  awkto/kea-gui-reservations:latest
```

### MCP Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /mcp/sse` | SSE transport (requires Bearer token) |
| `POST /mcp/messages` | JSON-RPC messages (requires Bearer token) |
| `GET /mcpdocs` | Interactive MCP tool documentation |

### MCP Tools

| Tool | Description |
|------|-------------|
| `list_leases` | List all active DHCP leases |
| `list_reservations` | List all DHCP reservations |
| `create_reservation` | Create a new reservation |
| `delete_reservation` | Delete a reservation by IP |
| `promote_lease` | Promote a lease to a reservation |
| `list_subnets` | List configured subnets |
| `delete_lease_by_ip` | Delete a lease by IP address |
| `delete_leases_by_mac` | Delete leases by MAC address |
| `export_reservations` | Export reservations to JSON |
| `import_reservations` | Import reservations from JSON |
| `health_check` | Check health and KEA connectivity |

### Claude Code Configuration

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "kea": {
      "type": "url",
      "url": "https://your-kea-host/mcp/sse",
      "headers": {
        "Authorization": "Bearer YOUR_API_TOKEN"
      }
    }
  }
}
```

The MCP server uses the same API token as the REST API.

## Security Considerations

- Use HTTPS in production
- Secure your KEA Control Agent with authentication
- Run container with appropriate user permissions
- Consider network isolation

## CI/CD

This project includes GitHub Actions for automated Docker image builds. See [CICD_SETUP.md](CICD_SETUP.md) for setup instructions.

Docker images are automatically published to Docker Hub on tagged releases.

## License

MIT
