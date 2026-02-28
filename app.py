"""
KEA DHCP Lease to Reservation Promotion GUI
Main Flask application
"""

import os
import secrets
import hashlib
import hmac
import time
import logging
from flask import Flask, render_template, jsonify, request
import yaml
from flasgger import Swagger
from filelock import FileLock, Timeout as FileLockTimeout

from kea_client import KeaClient

# Initialize Flask app
app = Flask(__name__)

# Cross-process lock to prevent TOCTOU race conditions when multiple Gunicorn
# workers check-then-create reservations concurrently.
RESERVATION_LOCK = FileLock("/tmp/kea_reservation.lock", timeout=15)

# Initialize Swagger
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "KEA DHCP Reservations API",
        "description": "API for managing KEA DHCP leases and reservations. Allows creating, listing, and promoting leases to permanent reservations.",
        "version": "1.5.0",
        "contact": {
            "name": "KEA GUI Reservations",
            "url": "https://github.com/awkto/kea-gui-reservations"
        }
    },
    "schemes": ["http", "https"],
    "tags": [
        {
            "name": "Health",
            "description": "Health check and system status"
        },
        {
            "name": "Leases",
            "description": "DHCP lease operations"
        },
        {
            "name": "Reservations",
            "description": "DHCP reservation management"
        },
        {
            "name": "Configuration",
            "description": "System configuration"
        },
        {
            "name": "Subnets",
            "description": "Subnet information"
        }
    ]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

# Default configuration
DEFAULT_CONFIG = {
    'kea': {
        'control_agent_url': 'http://localhost:8000',
        'username': '',
        'password': '',
        'default_subnet_id': 1
    },
    'app': {
        'host': '0.0.0.0',
        'port': 5000,
        'debug': False
    },
    'logging': {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    }
}

# Load configuration
config_path = os.environ.get('CONFIG_PATH', 'config.yaml')
config = DEFAULT_CONFIG.copy()
_config_cache = {'mtime': 0, 'config': None}

# Setup basic logging first (will be reconfigured after loading config)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_version():
    """
    Read version from version.txt file.
    Returns version string or 'unknown' if file not found.
    """
    version_file = os.path.join(os.path.dirname(__file__), 'version.txt')
    try:
        with open(version_file, 'r') as f:
            return f.read().strip()
    except Exception as e:
        logger.warning(f"Could not read version file: {e}")
        return 'unknown'

def load_config():
    """
    Load configuration from file, with caching based on file modification time.
    This ensures all worker processes see config updates while avoiding excessive disk I/O.
    """
    global config, _config_cache
    
    # Check if file exists and get modification time
    if os.path.exists(config_path):
        current_mtime = os.path.getmtime(config_path)
        
        # Return cached config if file hasn't changed
        if _config_cache['mtime'] == current_mtime and _config_cache['config'] is not None:
            return _config_cache['config']
        
        # File changed or first load - reload from disk
        try:
            with open(config_path, 'r') as f:
                loaded_config = yaml.safe_load(f)
                
            if loaded_config:
                # Deep merge loaded config with defaults
                new_config = DEFAULT_CONFIG.copy()
                for key in loaded_config:
                    if isinstance(loaded_config[key], dict) and key in new_config:
                        new_config[key].update(loaded_config[key])
                    else:
                        new_config[key] = loaded_config[key]
                
                # Update cache
                _config_cache['mtime'] = current_mtime
                _config_cache['config'] = new_config
                config = new_config
                
                logger.debug(f"✅ Reloaded config from {config_path} (mtime: {current_mtime})")
                logger.debug(f"   KEA URL: {config['kea']['control_agent_url']}")
                return new_config
        except Exception as e:
            logger.error(f"❌ Error loading config from {config_path}: {e}")
    
    # Fall back to defaults if file doesn't exist or load failed
    if _config_cache['config'] is None:
        logger.warning(f"⚠️  Using default configuration")
        _config_cache['config'] = DEFAULT_CONFIG.copy()
        config = _config_cache['config']
    
    return config

# Initial load at startup
initial_config = load_config()

# Reconfigure logging with loaded config
logging.basicConfig(
    level=getattr(logging, initial_config['logging']['level']),
    format=initial_config['logging']['format'],
    force=True  # Force reconfiguration
)

logger_msg = f"✅ Initial configuration loaded"
logger_msg += f"\n   Config path: {config_path}"
logger_msg += f"\n   KEA URL: {initial_config['kea']['control_agent_url']}"
if not os.path.exists(config_path):
    logger_msg += f"\n   💡 Tip: Mount your config.yaml to /app/config/config.yaml in Docker"

logger.info(logger_msg)

# Long-lived API token for programmatic/script access (loaded from config)
AUTH_TOKEN = None

# Short-lived web session store: {session_token: expiry_timestamp}
# In-memory — sessions do not survive a server restart.
SESSIONS = {}
SESSION_TTL = 12 * 60 * 60  # 12 hours


def create_session() -> str:
    """Generate a new session token valid for SESSION_TTL seconds."""
    token = 'sess_' + secrets.token_hex(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token


def is_valid_session(token: str) -> bool:
    """Return True if the token is a known, unexpired session."""
    expiry = SESSIONS.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        SESSIONS.pop(token, None)
        return False
    return True


def revoke_session(token: str) -> None:
    """Remove a session token, if present."""
    SESSIONS.pop(token, None)


# Lock to prevent multiple Gunicorn workers from simultaneously generating a new token
AUTH_INIT_LOCK = FileLock("/tmp/kea_auth_init.lock", timeout=30)


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 260000)
    return f"pbkdf2:sha256:{salt}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash. Timing-safe comparison."""
    try:
        parts = stored_hash.split(':', 3)
        if len(parts) != 4 or parts[0] != 'pbkdf2' or parts[1] != 'sha256':
            return False
        _, _, salt, key_hex = parts
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 260000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


def load_or_init_auth():
    """Load or initialize authentication state on startup.

    Loads the API token from config (api_token field). Falls back to the legacy
    auth_token field for migration from older versions. If neither exists,
    generates a token in memory only — it is persisted when first-run setup completes.
    """
    global AUTH_TOKEN
    with AUTH_INIT_LOCK:
        file_config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    file_config = yaml.safe_load(f) or {}
            except Exception:
                pass

        app_cfg = file_config.get('app', {})
        # Prefer new api_token field; fall back to legacy auth_token for migration
        api_token = app_cfg.get('api_token', '') or app_cfg.get('auth_token', '')

        if api_token:
            AUTH_TOKEN = api_token
            logger.info("🔐 API token loaded from config")
        else:
            AUTH_TOKEN = secrets.token_hex(32)
            logger.info("🔐 API token generated in memory — complete first-run setup to persist")

        if not app_cfg.get('password_hash'):
            logger.info("⚙️  First-run setup required: open the web UI to set a password")


load_or_init_auth()


def init_config_file():
    """Create a default config.yaml if it doesn't exist yet.

    Called at startup so the config directory always contains a config file
    after the first boot. Subsequent startups are a no-op.
    """
    if os.path.exists(config_path):
        return
    parent = os.path.dirname(os.path.abspath(config_path))
    if not os.path.isdir(parent):
        logger.warning(f"⚠️  Config directory {parent} not found — config will be in-memory only")
        return
    try:
        with open(config_path, 'w') as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
        logger.info(f"✅ Created default config file at {config_path}")
    except Exception as e:
        logger.warning(f"⚠️  Could not create config file: {e}")


init_config_file()


@app.before_request
def check_auth():
    """Enforce authentication on all API routes.

    Accepts either:
      - A valid (unexpired) web session token issued by /api/login or /api/setup
      - The long-lived API token stored in config (for scripts/integrations)
    """
    open_paths = {'/', '/api/login', '/api/logout', '/api/first-run', '/api/setup',
                  '/apidocs', '/apispec.json'}
    if request.path in open_paths or request.path.startswith('/flasgger_static'):
        return None
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    token = auth_header[len('Bearer '):]
    if is_valid_session(token):
        return None
    # Check api_token from config (authoritative) so it stays correct
    # after worker restarts or if in-memory AUTH_TOKEN is stale.
    api_token = load_config().get('app', {}).get('api_token') or AUTH_TOKEN
    if token == api_token:
        return None
    return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401


def get_kea_client():
    """
    Get KEA client instance with current configuration.
    Reloads config from file to ensure all worker processes see updates.
    """
    current_config = load_config()
    return KeaClient(
        url=current_config['kea']['control_agent_url'],
        username=current_config['kea'].get('username'),
        password=current_config['kea'].get('password')
    )


def is_config_valid():
    """
    Check if the configuration is valid (not in first-start/unconfigured state).
    Returns True if config is properly set up, False if it's still using defaults.
    """
    current_config = load_config()
    kea_url = current_config['kea']['control_agent_url']

    # Check if using empty URL
    if not kea_url or kea_url.strip() == '':
        return False

    # Check if it's still pointing to localhost (default/unconfigured)
    # This is OK for development but indicates first-start state in production
    if 'localhost' in kea_url.lower() or '127.0.0.1' in kea_url:
        # But if running in Docker and localhost is intentional, that's fine
        # We'll be lenient and only reject if it's the exact default
        if kea_url == 'http://localhost:8000':
            return False

    return True


def validate_dns_servers(dns_string: str) -> tuple[bool, str, list]:
    """
    Validate DNS server IP addresses string

    Args:
        dns_string: Comma-separated IP addresses (e.g., "8.8.8.8, 8.8.4.4")

    Returns:
        Tuple of (is_valid, error_message, cleaned_dns_list)
    """
    if not dns_string or dns_string.strip() == '':
        return True, '', []

    import ipaddress

    # Split by comma and clean whitespace
    dns_ips = [ip.strip() for ip in dns_string.split(',') if ip.strip()]

    if len(dns_ips) == 0:
        return True, '', []

    if len(dns_ips) > 4:
        return False, 'Maximum of 4 DNS servers allowed', []

    # Validate each IP address
    for dns_ip in dns_ips:
        try:
            ipaddress.IPv4Address(dns_ip)
        except ValueError:
            return False, f'Invalid IP address: {dns_ip}', []

    return True, '', dns_ips


@app.route('/')
def index():
    """Render the main page"""
    version = get_version()
    return render_template('index.html', version=version)


@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate with admin password
    ---
    tags:
      - Auth
    summary: Authenticate with password
    description: Verify the admin password. On success, returns the API token to use as a Bearer token for all subsequent requests.
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - password
          properties:
            password:
              type: string
              example: "mysecretpassword"
    responses:
      200:
        description: Authentication successful — returns a short-lived session token
        schema:
          type: object
          properties:
            success:
              type: boolean
            session_token:
              type: string
            expires_in:
              type: integer
              description: Session lifetime in seconds
      401:
        description: Invalid password
      403:
        description: No password configured — complete first-run setup first
    """
    data = request.get_json()
    if not data or not data.get('password'):
        return jsonify({'success': False, 'error': 'Password required'}), 400

    current_config = load_config()
    password_hash = current_config.get('app', {}).get('password_hash', '')
    if not password_hash:
        return jsonify({'success': False, 'error': 'No password configured. Complete first-run setup.'}), 403

    if not verify_password(data['password'], password_hash):
        return jsonify({'success': False, 'error': 'Invalid password'}), 401

    session_token = create_session()
    return jsonify({'success': True, 'session_token': session_token, 'expires_in': SESSION_TTL}), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    """Revoke the current web session
    ---
    tags:
      - Auth
    summary: Logout
    description: Revokes the session token supplied in the Authorization header. Safe to call even if the session has already expired.
    responses:
      200:
        description: Session revoked (or was already invalid)
    """
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        revoke_session(auth_header[len('Bearer '):])
    return jsonify({'success': True}), 200


@app.route('/api/first-run', methods=['GET'])
def first_run_status():
    """Check if first-run password setup is required
    ---
    tags:
      - Auth
    summary: First-run status
    description: Returns whether the admin password has been configured. Used by the frontend to decide whether to show the setup wizard or the login form.
    responses:
      200:
        description: First-run status
        schema:
          type: object
          properties:
            first_run:
              type: boolean
              description: True if no password has been set yet
    """
    file_config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
        except Exception:
            pass
    has_password = bool(file_config.get('app', {}).get('password_hash', ''))
    return jsonify({'first_run': not has_password}), 200


@app.route('/api/setup', methods=['POST'])
def first_run_setup():
    """Complete first-run setup by setting the admin password
    ---
    tags:
      - Auth
    summary: First-run setup
    description: Sets the initial admin password. Only available when no password has been configured yet. Returns the API token to use for all subsequent requests.
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - password
          properties:
            password:
              type: string
              minLength: 8
              example: "mysecretpassword"
    responses:
      200:
        description: Setup completed
        schema:
          type: object
          properties:
            success:
              type: boolean
            api_token:
              type: string
      400:
        description: Password too short or missing
      403:
        description: Setup already completed
    """
    file_config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
        except Exception:
            pass

    if file_config.get('app', {}).get('password_hash'):
        return jsonify({'success': False, 'error': 'Setup already completed'}), 403

    data = request.get_json()
    password = (data or {}).get('password', '').strip()

    if not password or len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

    global AUTH_TOKEN

    pw_hash = hash_password(password)

    current_config = load_config()
    app_section = current_config.setdefault('app', {})
    app_section['password_hash'] = pw_hash

    # Persist the API token (migrate from legacy auth_token if present)
    if not app_section.get('api_token'):
        legacy = app_section.pop('auth_token', None) or AUTH_TOKEN
        app_section['api_token'] = legacy
    app_section.pop('auth_token', None)

    try:
        with open(config_path, 'w') as f:
            yaml.dump(current_config, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        logger.error(f"❌ Failed to write config during setup: {e}")
        return jsonify({'success': False, 'error': f'Could not write config file: {e}'}), 500

    AUTH_TOKEN = app_section['api_token']
    _config_cache['mtime'] = 0
    _config_cache['config'] = None

    logger.info("✅ First-run setup completed: admin password configured")
    session_token = create_session()
    return jsonify({'success': True, 'session_token': session_token, 'expires_in': SESSION_TTL}), 200


@app.route('/api/auth/token/regenerate', methods=['POST'])
def regenerate_api_token():
    """Regenerate the API token
    ---
    tags:
      - Auth
    summary: Regenerate API token
    description: Generates a new random API token and saves it. All existing sessions using the old token are invalidated. The frontend automatically updates its stored token.
    responses:
      200:
        description: New token generated
        schema:
          type: object
          properties:
            success:
              type: boolean
            api_token:
              type: string
    """
    global AUTH_TOKEN
    new_token = secrets.token_hex(32)

    current_config = load_config()
    app_section = current_config.setdefault('app', {})
    app_section['api_token'] = new_token
    app_section.pop('auth_token', None)

    try:
        with open(config_path, 'w') as f:
            yaml.dump(current_config, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        logger.error(f"❌ Failed to write config during token regeneration: {e}")
        return jsonify({'success': False, 'error': f'Could not write config file: {e}'}), 500

    AUTH_TOKEN = new_token
    _config_cache['mtime'] = 0
    _config_cache['config'] = None

    logger.info("🔄 API token regenerated")
    return jsonify({'success': True, 'api_token': new_token}), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint
    ---
    tags:
      - Health
    summary: Check system health and KEA connectivity
    description: Verifies that the application can connect to the KEA DHCP server and returns the connection status.
    responses:
      200:
        description: Health check completed
        schema:
          type: object
          properties:
            status:
              type: string
              enum: [healthy, unhealthy, unconfigured]
              description: Overall system status
            kea_connection:
              type: string
              enum: [ok, failed, not_configured]
              description: KEA server connection status
            message:
              type: string
              description: Additional status message (if unconfigured)
            error:
              type: string
              description: Error message (if unhealthy)
        examples:
          healthy:
            status: healthy
            kea_connection: ok
          unhealthy:
            status: unhealthy
            kea_connection: failed
            error: Connection refused
      503:
        description: Service unavailable - KEA connection failed
    """
    # Check if configuration is valid first
    if not is_config_valid():
        return jsonify({
            'status': 'unconfigured',
            'kea_connection': 'not_configured',
            'message': 'KEA server not configured. Please update configuration.'
        }), 200
    
    try:
        # Test connection to KEA
        client = get_kea_client()
        client.get_version()
        return jsonify({
            'status': 'healthy',
            'kea_connection': 'ok'
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'kea_connection': 'failed',
            'error': str(e)
        }), 503


@app.route('/api/leases', methods=['GET'])
def get_leases():
    """Fetch all DHCPv4 leases
    ---
    tags:
      - Leases
    summary: Get all DHCP leases
    description: Retrieves all active DHCPv4 leases from the KEA DHCP server. Optionally filter by subnet ID.
    parameters:
      - name: subnet_id
        in: query
        type: integer
        required: false
        description: Filter leases by subnet ID
        example: 1
    responses:
      200:
        description: Leases retrieved successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            leases:
              type: array
              description: List of DHCP leases
              items:
                type: object
                properties:
                  ip-address:
                    type: string
                    description: Leased IP address
                  hw-address:
                    type: string
                    description: MAC address of the client
                  hostname:
                    type: string
                    description: Client hostname (if available)
                  subnet-id:
                    type: integer
                    description: Subnet ID
                  valid-lifetime:
                    type: integer
                    description: Lease validity duration in seconds
            count:
              type: integer
              description: Total number of leases returned
            unconfigured:
              type: boolean
              description: True if KEA server is not configured
            error:
              type: string
              description: Error message (if failed)
        examples:
          success:
            success: true
            leases:
              - ip-address: "192.168.1.100"
                hw-address: "aa:bb:cc:dd:ee:01"
                hostname: "client1"
                subnet-id: 1
            count: 1
      500:
        description: Internal server error
    """
    # Check if configuration is valid first
    if not is_config_valid():
        return jsonify({
            'success': False,
            'unconfigured': True,
            'error': 'KEA server not configured. Please update configuration to connect.'
        }), 200
    
    try:
        client = get_kea_client()
        subnet_id = request.args.get('subnet_id', type=int)
        leases = client.get_leases(subnet_id=subnet_id)
        return jsonify({
            'success': True,
            'leases': leases,
            'count': len(leases)
        }), 200
    except Exception as e:
        logger.error(f"Error fetching leases: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/reservations', methods=['GET'])
def get_reservations():
    """Fetch all DHCPv4 reservations
    ---
    tags:
      - Reservations
    summary: Get all DHCP reservations
    description: Retrieves all permanent DHCPv4 reservations from the KEA DHCP server. Optionally filter by subnet ID.
    parameters:
      - name: subnet_id
        in: query
        type: integer
        required: false
        description: Filter reservations by subnet ID
        example: 1
    responses:
      200:
        description: Reservations retrieved successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            reservations:
              type: array
              description: List of DHCP reservations
              items:
                type: object
                properties:
                  ip-address:
                    type: string
                    description: Reserved IP address
                  hw-address:
                    type: string
                    description: MAC address bound to this reservation
                  hostname:
                    type: string
                    description: Hostname for this reservation
                  subnet-id:
                    type: integer
                    description: Subnet ID
            count:
              type: integer
              description: Total number of reservations returned
            error:
              type: string
              description: Error message (if failed)
        examples:
          success:
            success: true
            reservations:
              - ip-address: "192.168.1.10"
                hw-address: "aa:bb:cc:dd:ee:ff"
                hostname: "server1"
                subnet-id: 1
            count: 1
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        subnet_id = request.args.get('subnet_id', type=int)
        reservations = client.get_reservations(subnet_id=subnet_id)
        return jsonify({
            'success': True,
            'reservations': reservations,
            'count': len(reservations)
        }), 200
    except Exception as e:
        logger.error(f"Error fetching reservations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/reservations', methods=['POST'])
def create_reservation():
    """Create a new DHCP reservation
    ---
    tags:
      - Reservations
    summary: Create a new DHCP reservation
    description: |
      Creates a permanent DHCP reservation for a specific IP and MAC address combination.

      By default, the API rejects requests that would overwrite an existing reservation
      for a different MAC address (returns 409 Conflict). Use the `force` flag to explicitly
      allow overwriting an existing reservation.

      If the same MAC already has a reservation for the requested IP, the request is treated
      as idempotent and succeeds without changes.
    parameters:
      - name: body
        in: body
        required: true
        description: Reservation details
        schema:
          type: object
          required:
            - ip_address
            - hw_address
          properties:
            ip_address:
              type: string
              description: IP address to reserve
              example: "192.168.1.100"
            hw_address:
              type: string
              description: MAC address to bind to the reservation
              example: "aa:bb:cc:dd:ee:ff"
            hostname:
              type: string
              description: Hostname for the reservation (optional)
              example: "server1"
            subnet_id:
              type: integer
              description: Subnet ID (optional, uses default if not specified)
              example: 1
            dns_servers:
              type: string
              description: Comma-separated DNS server IPs (optional, e.g., "8.8.8.8, 8.8.4.4")
              example: "8.8.8.8, 8.8.4.4"
            force:
              type: boolean
              description: Force overwrite of existing reservation for a different MAC (default false)
              example: false
    responses:
      200:
        description: Reservation created successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            message:
              type: string
              description: Success message
            reservation:
              type: object
              description: Details of the created reservation
        examples:
          success:
            success: true
            message: "Successfully created reservation for 192.168.1.100"
            reservation:
              ip-address: "192.168.1.100"
              hw-address: "aa:bb:cc:dd:ee:ff"
              hostname: "server1"
      400:
        description: Bad request - missing required fields
        schema:
          type: object
          properties:
            success:
              type: boolean
            error:
              type: string
      409:
        description: Conflict - reservation already exists for this IP with a different MAC
        schema:
          type: object
          properties:
            success:
              type: boolean
              example: false
            error:
              type: string
              example: "DHCP reservation already exists for IP 192.168.1.100 with a different MAC (aa:bb:cc:dd:ee:01). Use 'force' to overwrite."
            existing_reservation:
              type: object
              description: The existing conflicting reservation
              properties:
                ip-address:
                  type: string
                hw-address:
                  type: string
                hostname:
                  type: string
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        ip_address = data.get('ip_address')
        hw_address = data.get('hw_address')
        hostname = data.get('hostname', '')
        subnet_id = data.get('subnet_id')
        dns_servers = data.get('dns_servers', '')
        force = data.get('force', False)

        if not ip_address or not hw_address:
            return jsonify({
                'success': False,
                'error': 'ip_address and hw_address are required'
            }), 400

        # Normalize MAC to lowercase for comparison
        hw_address_lower = hw_address.lower()

        try:
            with RESERVATION_LOCK:
                # Check for existing reservation conflicts (unless force=true)
                try:
                    reservations = client.get_reservations(subnet_id=subnet_id)

                    # Check for IP conflict
                    existing_by_ip = next(
                        (r for r in reservations if r.get('ip-address') == ip_address), None
                    )

                    if existing_by_ip:
                        existing_mac = existing_by_ip.get('hw-address', '').lower()

                        if existing_mac == hw_address_lower:
                            # Same MAC already has this IP — idempotent, return success
                            logger.info(f"Reservation already exists for IP={ip_address}, MAC={hw_address} — no changes needed")
                            return jsonify({
                                'success': True,
                                'message': f'Reservation already exists for {ip_address} with this MAC',
                                'reservation': existing_by_ip
                            }), 200

                        if not force:
                            # Different MAC — conflict
                            logger.warning(
                                f"Conflict: IP {ip_address} already reserved for MAC {existing_mac}, "
                                f"requested by MAC {hw_address_lower}"
                            )
                            return jsonify({
                                'success': False,
                                'error': (
                                    f"DHCP reservation already exists for IP {ip_address} "
                                    f"with a different MAC ({existing_mac}). "
                                    f"Use 'force' to overwrite."
                                ),
                                'existing_reservation': existing_by_ip
                            }), 409

                        # force=true — log and proceed to overwrite
                        logger.info(
                            f"Force overwriting reservation for IP {ip_address}: "
                            f"old MAC={existing_mac}, new MAC={hw_address_lower}"
                        )

                    # Check for MAC conflict (same MAC, different IP)
                    existing_by_mac = next(
                        (r for r in reservations if r.get('hw-address', '').lower() == hw_address_lower), None
                    )

                    if existing_by_mac and existing_by_mac.get('ip-address') != ip_address:
                        existing_ip = existing_by_mac.get('ip-address')
                        if not force:
                            logger.warning(
                                f"Conflict: MAC {hw_address} already has reservation for IP {existing_ip}, "
                                f"requested IP {ip_address}"
                            )
                            return jsonify({
                                'success': False,
                                'error': (
                                    f"MAC {hw_address} already has a reservation for a different IP ({existing_ip}). "
                                    f"Use 'force' to overwrite."
                                ),
                                'existing_reservation': existing_by_mac
                            }), 409

                        logger.info(
                            f"Force overwriting reservation for MAC {hw_address}: "
                            f"old IP={existing_ip}, new IP={ip_address}"
                        )

                except Exception as e:
                    logger.warning(f"Could not verify existing reservations: {e}")
                    # Continue anyway if reservation check fails

                # Validate DNS servers if provided
                option_data = None
                if dns_servers:
                    is_valid, error_msg, dns_list = validate_dns_servers(dns_servers)
                    if not is_valid:
                        return jsonify({
                            'success': False,
                            'error': f'Invalid DNS servers: {error_msg}'
                        }), 400

                    if dns_list:
                        # Convert to Kea option-data format
                        option_data = [{
                            "name": "domain-name-servers",
                            "data": ", ".join(dns_list)
                        }]

                logger.info(f"Creating reservation: IP={ip_address}, MAC={hw_address}")

                result = client.create_reservation(
                    ip_address=ip_address,
                    hw_address=hw_address,
                    hostname=hostname,
                    subnet_id=subnet_id,
                    option_data=option_data
                )

                return jsonify({
                    'success': True,
                    'message': f'Successfully created reservation for {ip_address}',
                    'reservation': result
                }), 200
        except FileLockTimeout:
            logger.error(f"Reservation lock timeout for IP={ip_address}, MAC={hw_address}")
            return jsonify({
                'success': False,
                'error': 'Server busy processing another reservation request, please retry'
            }), 503

    except Exception as e:
        logger.error(f"Error creating reservation: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/promote', methods=['POST'])
def promote_lease():
    """Promote a lease to a permanent reservation
    ---
    tags:
      - Leases
      - Reservations
    summary: Promote an active lease to a permanent reservation
    description: |
      Converts an active DHCP lease into a permanent reservation. This ensures the same IP address
      will always be assigned to the specified MAC address. Includes duplicate checking to prevent
      overwriting existing reservations.
    parameters:
      - name: body
        in: body
        required: true
        description: Lease details to promote
        schema:
          type: object
          required:
            - ip_address
            - hw_address
          properties:
            ip_address:
              type: string
              description: IP address from the active lease
              example: "192.168.1.100"
            hw_address:
              type: string
              description: MAC address from the active lease
              example: "aa:bb:cc:dd:ee:01"
            hostname:
              type: string
              description: Hostname from the lease (optional)
              example: "client1"
            subnet_id:
              type: integer
              description: Subnet ID (optional)
              example: 1
            dns_servers:
              type: string
              description: Comma-separated DNS server IPs (optional, e.g., "8.8.8.8, 8.8.4.4")
              example: "8.8.8.8, 8.8.4.4"
    responses:
      200:
        description: Lease promoted successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            message:
              type: string
              description: Success message
            reservation:
              type: object
              description: Details of the created reservation
        examples:
          success:
            success: true
            message: "Successfully promoted 192.168.1.100 to reservation"
      400:
        description: Bad request - missing fields or reservation already exists
        schema:
          type: object
          properties:
            success:
              type: boolean
            error:
              type: string
        examples:
          duplicate:
            success: false
            error: "A reservation already exists for IP 192.168.1.100. Please choose a different IP address."
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        ip_address = data.get('ip_address')
        hw_address = data.get('hw_address')
        hostname = data.get('hostname', '')
        subnet_id = data.get('subnet_id')
        dns_servers = data.get('dns_servers', '')

        if not ip_address or not hw_address:
            return jsonify({
                'success': False,
                'error': 'ip_address and hw_address are required'
            }), 400

        # Validate DNS servers if provided
        option_data = None
        if dns_servers:
            is_valid, error_msg, dns_list = validate_dns_servers(dns_servers)
            if not is_valid:
                return jsonify({
                    'success': False,
                    'error': f'Invalid DNS servers: {error_msg}'
                }), 400

            if dns_list:
                # Convert to Kea option-data format
                option_data = [{
                    "name": "domain-name-servers",
                    "data": ", ".join(dns_list)
                }]

        try:
            with RESERVATION_LOCK:
                # Check if a reservation already exists for this IP
                try:
                    reservations = client.get_reservations(subnet_id=subnet_id)
                    existing_reservation = next((r for r in reservations if r.get('ip-address') == ip_address), None)

                    if existing_reservation:
                        logger.warning(f"Cannot promote: reservation already exists for IP {ip_address}")
                        return jsonify({
                            'success': False,
                            'error': f'A reservation already exists for IP {ip_address}. Please choose a different IP address.'
                        }), 400
                except Exception as e:
                    logger.warning(f"Could not verify existing reservations: {e}")
                    # Continue anyway if reservation check fails

                logger.info(f"Promoting lease: IP={ip_address}, MAC={hw_address}")

                result = client.create_reservation(
                    ip_address=ip_address,
                    hw_address=hw_address,
                    hostname=hostname,
                    subnet_id=subnet_id,
                    option_data=option_data
                )

                return jsonify({
                    'success': True,
                    'message': f'Successfully promoted {ip_address} to reservation',
                    'reservation': result
                }), 200
        except FileLockTimeout:
            logger.error(f"Reservation lock timeout for promote IP={ip_address}, MAC={hw_address}")
            return jsonify({
                'success': False,
                'error': 'Server busy processing another reservation request, please retry'
            }), 503

    except Exception as e:
        logger.error(f"Error promoting lease: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/subnets', methods=['GET'])
def get_subnets():
    """Fetch configured subnets
    ---
    tags:
      - Subnets
    summary: Get configured DHCP subnets
    description: Retrieves all configured subnets from the KEA DHCP server with their network ranges and settings.
    responses:
      200:
        description: Subnets retrieved successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            subnets:
              type: array
              description: List of configured subnets
              items:
                type: object
                properties:
                  id:
                    type: integer
                    description: Subnet ID
                  subnet:
                    type: string
                    description: Subnet CIDR notation
                  pools:
                    type: array
                    description: IP address pools
            unconfigured:
              type: boolean
              description: True if KEA server is not configured
            error:
              type: string
              description: Error message (if failed)
        examples:
          success:
            success: true
            subnets:
              - id: 1
                subnet: "192.168.1.0/24"
                pools:
                  - pool: "192.168.1.100 - 192.168.1.200"
      500:
        description: Internal server error
    """
    # Check if configuration is valid first
    if not is_config_valid():
        return jsonify({
            'success': False,
            'unconfigured': True,
            'error': 'KEA server not configured',
            'subnets': []
        }), 200
    
    try:
        client = get_kea_client()
        subnets = client.get_subnets()
        return jsonify({
            'success': True,
            'subnets': subnets
        }), 200
    except Exception as e:
        logger.error(f"Error fetching subnets: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/validate-ip', methods=['POST'])
def validate_ip():
    """Validate if an IP address belongs to a subnet
    ---
    tags:
      - Subnets
    summary: Validate IP address against subnet
    description: |
      Checks if an IP address is valid for a specific subnet. Validates that:
      - IP is within the subnet range
      - IP is not the network address
      - IP is not the broadcast address
    parameters:
      - name: body
        in: body
        required: true
        description: IP address and subnet to validate
        schema:
          type: object
          required:
            - ip_address
          properties:
            ip_address:
              type: string
              description: IP address to validate
              example: "192.168.1.100"
            subnet_id:
              type: integer
              description: Subnet ID to validate against
              example: 1
    responses:
      200:
        description: Validation completed
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the validation check completed
            valid:
              type: boolean
              description: Whether the IP is valid for the subnet
            subnet:
              type: string
              description: Subnet CIDR that was checked
            error:
              type: string
              description: Error message if invalid
        examples:
          valid:
            success: true
            valid: true
            subnet: "192.168.1.0/24"
          invalid:
            success: true
            valid: false
            error: "IP 192.168.1.255 is the broadcast address and cannot be used"
            subnet: "192.168.1.0/24"
      400:
        description: Bad request - missing required fields or subnet not found
      500:
        description: Internal server error
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        ip_address = data.get('ip_address')
        subnet_id = data.get('subnet_id')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'ip_address is required'
            }), 400
        
        # Get subnet information
        client = get_kea_client()
        subnets = client.get_subnets()
        
        # Find the target subnet
        target_subnet = None
        if subnet_id is not None:
            target_subnet = next((s for s in subnets if s['id'] == subnet_id), None)
        
        if not target_subnet:
            return jsonify({
                'success': False,
                'valid': False,
                'error': f'Subnet {subnet_id} not found'
            }), 400
        
        # Parse subnet CIDR
        import ipaddress
        try:
            subnet_cidr = target_subnet['subnet']
            network = ipaddress.IPv4Network(subnet_cidr, strict=False)
            ip_obj = ipaddress.IPv4Address(ip_address)
            
            # Check if IP is in subnet range
            is_in_subnet = ip_obj in network
            
            # Check if IP is network or broadcast address
            is_network_addr = ip_obj == network.network_address
            is_broadcast_addr = ip_obj == network.broadcast_address
            
            if is_network_addr:
                return jsonify({
                    'success': True,
                    'valid': False,
                    'error': f'IP {ip_address} is the network address and cannot be used',
                    'subnet': subnet_cidr
                }), 200
            
            if is_broadcast_addr:
                return jsonify({
                    'success': True,
                    'valid': False,
                    'error': f'IP {ip_address} is the broadcast address and cannot be used',
                    'subnet': subnet_cidr
                }), 200
            
            if not is_in_subnet:
                return jsonify({
                    'success': True,
                    'valid': False,
                    'error': f'IP {ip_address} is not in subnet {subnet_cidr}',
                    'subnet': subnet_cidr
                }), 200
            
            # IP is valid
            return jsonify({
                'success': True,
                'valid': True,
                'subnet': subnet_cidr
            }), 200
            
        except ValueError as e:
            return jsonify({
                'success': False,
                'valid': False,
                'error': f'Invalid IP address or subnet format: {str(e)}'
            }), 400
        
    except Exception as e:
        logger.error(f"Error validating IP: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration (sanitized)
    ---
    tags:
      - Configuration
    summary: Get current application configuration
    description: Retrieves the current configuration settings. Passwords are sanitized (masked) in the response.
    responses:
      200:
        description: Configuration retrieved successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            config:
              type: object
              description: Current configuration (with password masked)
              properties:
                kea:
                  type: object
                  properties:
                    control_agent_url:
                      type: string
                    username:
                      type: string
                    password:
                      type: string
                      description: Masked as '***' if set
                    default_subnet_id:
                      type: integer
                app:
                  type: object
                  properties:
                    host:
                      type: string
                    port:
                      type: integer
                    debug:
                      type: boolean
            config_path:
              type: string
              description: Path to the configuration file
            config_exists:
              type: boolean
              description: Whether the config file exists on disk
      500:
        description: Internal server error
    """
    try:
        # Load current config from file
        current_config = load_config()
        
        # Return sanitized config (hide password)
        sanitized_config = {}
        for key in current_config:
            if isinstance(current_config[key], dict):
                sanitized_config[key] = current_config[key].copy()
            else:
                sanitized_config[key] = current_config[key]
        
        if 'kea' in sanitized_config and 'password' in sanitized_config['kea']:
            sanitized_config['kea']['password'] = '***' if sanitized_config['kea']['password'] else ''

        # Strip sensitive auth fields; expose api_token for the settings UI
        if 'app' in sanitized_config:
            sanitized_config['app'].pop('password_hash', None)
            sanitized_config['app'].pop('auth_token', None)
            if 'api_token' not in sanitized_config['app']:
                sanitized_config['app']['api_token'] = AUTH_TOKEN

        return jsonify({
            'success': True,
            'config': sanitized_config,
            'config_path': config_path,
            'config_exists': os.path.exists(config_path)
        }), 200
    except Exception as e:
        logger.error(f"Error fetching config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/kea-config', methods=['GET'])
def get_kea_config():
    """Get KEA DHCP server configuration
    ---
    tags:
      - Configuration
    summary: Get KEA DHCP server configuration
    description: |
      Retrieves the full KEA DHCP4 configuration from the server.
      Returns both the raw configuration and a curated view with formatted settings.
    responses:
      200:
        description: KEA configuration retrieved successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Whether the operation succeeded
            config:
              type: object
              description: Full Dhcp4 configuration for raw view
            curated:
              type: object
              description: Curated configuration with formatted settings
              properties:
                global:
                  type: object
                  description: Global DHCP settings
                subnets:
                  type: array
                  description: Subnet configurations
                advanced:
                  type: object
                  description: Advanced settings (hooks, control socket)
      500:
        description: Internal server error
    """
    # Check if configuration is valid first
    if not is_config_valid():
        return jsonify({
            'success': False,
            'error': 'KEA server not configured. Please update configuration.'
        }), 200

    try:
        client = get_kea_client()
        kea_config = client.get_config()

        # Extract Dhcp4 configuration
        dhcp4_config = kea_config.get('Dhcp4', {})

        # Always return raw config, even if curation fails
        response = {
            'success': True,
            'config': dhcp4_config,
            'curated': None,
            'curation_error': None
        }

        # Try to build curated view, but don't fail if parsing breaks
        try:
            curated = {
                'global': {},
                'subnets': [],
                'advanced': {}
            }

            # Global settings
            def format_time(seconds):
                """Format seconds into human-readable time"""
                if seconds is None:
                    return None
                if seconds < 60:
                    return f"{seconds}s"
                elif seconds < 3600:
                    minutes = seconds // 60
                    return f"{minutes} min" if minutes == 1 else f"{minutes} mins"
                else:
                    hours = seconds // 3600
                    return f"{hours} hour" if hours == 1 else f"{hours} hours"

            valid_lifetime = dhcp4_config.get('valid-lifetime')
            renew_timer = dhcp4_config.get('renew-timer')
            rebind_timer = dhcp4_config.get('rebind-timer')

            curated['global'] = {
                'valid_lifetime': valid_lifetime,
                'valid_lifetime_formatted': format_time(valid_lifetime),
                'renew_timer': renew_timer,
                'renew_timer_formatted': format_time(renew_timer),
                'rebind_timer': rebind_timer,
                'rebind_timer_formatted': format_time(rebind_timer),
                'interfaces': dhcp4_config.get('interfaces-config', {}).get('interfaces', []),
                'lease_database': dhcp4_config.get('lease-database', {})
            }

            # Subnet settings
            subnets = dhcp4_config.get('subnet4', [])
            for subnet in subnets:
                pools = []
                for pool in subnet.get('pools', []):
                    if isinstance(pool, dict):
                        pools.append(pool.get('pool', ''))
                    else:
                        pools.append(str(pool))

                # Extract options
                options = {}
                for opt in subnet.get('option-data', []):
                    if opt.get('code') == 3 or opt.get('name') == 'routers':
                        options['routers'] = opt.get('data', '')
                    elif opt.get('code') == 6 or opt.get('name') == 'domain-name-servers':
                        options['dns_servers'] = opt.get('data', '')

                subnet_lifetime = subnet.get('valid-lifetime')
                curated['subnets'].append({
                    'id': subnet.get('id'),
                    'subnet': subnet.get('subnet'),
                    'pools': pools,
                    'valid_lifetime': subnet_lifetime,
                    'valid_lifetime_formatted': format_time(subnet_lifetime) if subnet_lifetime else None,
                    'reservation_count': len(subnet.get('reservations', [])),
                    'options': options
                })

            # Advanced settings
            hooks = []
            for hook in dhcp4_config.get('hooks-libraries', []):
                library_path = hook.get('library', '')
                # Extract just the filename
                library_name = library_path.split('/')[-1] if library_path else ''
                hooks.append(library_name)

            control_socket = dhcp4_config.get('control-socket', {})
            curated['advanced'] = {
                'hooks_libraries': hooks,
                'control_socket': {
                    'type': control_socket.get('socket-type', ''),
                    'path': control_socket.get('socket-name', '')
                },
                'host_reservation_identifiers': dhcp4_config.get('host-reservation-identifiers', [])
            }

            # Curation succeeded, add to response
            response['curated'] = curated

        except Exception as curation_error:
            # Curation failed, but we still have raw config
            logger.warning(f"Failed to curate KEA config (raw config still available): {curation_error}")
            response['curation_error'] = f"Could not parse configuration structure: {str(curation_error)}"

        return jsonify(response), 200

    except Exception as e:
        # Complete failure - couldn't even get config from KEA
        logger.error(f"Error fetching KEA config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/config', methods=['POST'])
def save_config():
    """Save configuration to file
    ---
    tags:
      - Configuration
    summary: Save application configuration
    description: |
      Updates and saves the application configuration to disk. All workers will immediately use the new configuration.
      If the password field is '***', the existing password is preserved.
    parameters:
      - name: body
        in: body
        required: true
        description: New configuration to save
        schema:
          type: object
          required:
            - config
          properties:
            config:
              type: object
              required:
                - kea
                - app
              properties:
                kea:
                  type: object
                  properties:
                    control_agent_url:
                      type: string
                      example: "http://kea-server:8000"
                    username:
                      type: string
                      example: "admin"
                    password:
                      type: string
                      description: Use '***' to keep existing password
                      example: "password123"
                    default_subnet_id:
                      type: integer
                      example: 1
                app:
                  type: object
                  properties:
                    host:
                      type: string
                      example: "0.0.0.0"
                    port:
                      type: integer
                      example: 5000
                    debug:
                      type: boolean
                      example: false
    responses:
      200:
        description: Configuration saved successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
        examples:
          success:
            success: true
            message: "Configuration saved successfully. All workers will use the new config immediately."
      400:
        description: Bad request - invalid or incomplete configuration
      500:
        description: Internal server error
    """
    global config, _config_cache
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No configuration data provided'
            }), 400
        
        new_config = data.get('config')
        if not new_config:
            return jsonify({
                'success': False,
                'error': 'Configuration object is required'
            }), 400
        
        # Validate required structure
        if 'kea' not in new_config or 'app' not in new_config:
            return jsonify({
                'success': False,
                'error': 'Configuration must include "kea" and "app" sections'
            }), 400
        
        # If password is masked, keep the existing password
        current_config = load_config()
        if new_config['kea'].get('password') == '***' and current_config['kea'].get('password'):
            new_config['kea']['password'] = current_config['kea']['password']

        # Always preserve auth credentials — never allow clearing via config save
        existing_app = current_config.get('app', {})
        new_app = new_config.setdefault('app', {})
        new_app['api_token'] = existing_app.get('api_token') or AUTH_TOKEN
        if existing_app.get('password_hash'):
            new_app['password_hash'] = existing_app['password_hash']
        new_app.pop('auth_token', None)  # Remove legacy field

        # Write to file
        with open(config_path, 'w') as f:
            yaml.dump(new_config, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"✅ Configuration saved to {config_path}")
        logger.info(f"   New KEA URL: {new_config['kea']['control_agent_url']}")
        
        # Invalidate cache so all workers reload on next request
        _config_cache['mtime'] = 0
        _config_cache['config'] = None
        
        # Force immediate reload
        load_config()
        
        return jsonify({
            'success': True,
            'message': f'Configuration saved successfully. All workers will use the new config immediately.'
        }), 200
        
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/reservation/<ip_address>', methods=['DELETE'])
def delete_reservation(ip_address):
    """Delete a reservation
    ---
    tags:
      - Reservations
    summary: Delete a DHCP reservation
    description: Removes a permanent DHCP reservation for the specified IP address.
    parameters:
      - name: ip_address
        in: path
        type: string
        required: true
        description: IP address of the reservation to delete
        example: "192.168.1.100"
      - name: subnet_id
        in: query
        type: integer
        required: false
        description: Subnet ID (optional)
        example: 1
    responses:
      200:
        description: Reservation deleted successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
        examples:
          success:
            success: true
            message: "Successfully deleted reservation for 192.168.1.100"
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        subnet_id = request.args.get('subnet_id', type=int)
        client.delete_reservation(ip_address, subnet_id)
        return jsonify({
            'success': True,
            'message': f'Successfully deleted reservation for {ip_address}'
        }), 200
    except Exception as e:
        logger.error(f"Error deleting reservation: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/leases/ip/<ip_address>', methods=['DELETE'])
def delete_lease_by_ip(ip_address):
    """Delete the lease for a specific IP address
    ---
    tags:
      - Leases
    summary: Delete DHCP lease by IP address
    description: Deletes the lease for the given IP address regardless of which client owns it. Used to clear a conflicting lease before a VM boots with a reservation for that IP.
    parameters:
      - name: ip_address
        in: path
        type: string
        required: true
        description: IP address (e.g. 10.33.11.17)
    responses:
      200:
        description: Lease deleted (deleted=0 if none existed)
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        count = client.delete_lease_by_ip(ip_address)
        return jsonify({
            'success': True,
            'deleted': count,
            'message': f'Deleted {count} lease(s) for IP {ip_address}'
        }), 200
    except Exception as e:
        logger.error(f"Error deleting lease for IP {ip_address}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/leases/mac/<mac_address>', methods=['DELETE'])
def delete_leases_by_mac(mac_address):
    """Delete all leases for a given MAC address
    ---
    tags:
      - Leases
    summary: Delete all DHCP leases for a MAC address
    description: Finds and deletes every active lease for the given MAC address. Used to clear stale dynamic leases before booting a VM that has a reservation.
    parameters:
      - name: mac_address
        in: path
        type: string
        required: true
        description: MAC address (e.g. bc:24:11:xx:xx:xx)
    responses:
      200:
        description: Leases deleted (count may be 0 if none existed)
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        count = client.delete_leases_by_mac(mac_address)
        return jsonify({
            'success': True,
            'deleted': count,
            'message': f'Deleted {count} lease(s) for MAC {mac_address}'
        }), 200
    except Exception as e:
        logger.error(f"Error deleting leases for MAC {mac_address}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/reservations/export', methods=['GET'])
def export_reservations():
    """Export all DHCP reservations to JSON file
    ---
    tags:
      - Reservations
    summary: Export reservations to JSON file
    description: |
      Downloads all DHCP reservations as a JSON file. The file includes metadata (export date, count)
      and can be used for backup or importing to another system.
    parameters:
      - name: subnet_id
        in: query
        type: integer
        required: false
        description: Filter reservations by subnet ID
        example: 1
    produces:
      - application/json
    responses:
      200:
        description: JSON file download containing all reservations
        headers:
          Content-Disposition:
            type: string
            description: "attachment; filename=dhcp_reservations_export.json"
        schema:
          type: object
          properties:
            export_date:
              type: string
              format: date-time
              description: ISO timestamp of export
            total_count:
              type: integer
              description: Number of reservations exported
            reservations:
              type: array
              description: List of all reservations
              items:
                type: object
                properties:
                  ip-address:
                    type: string
                  hw-address:
                    type: string
                  hostname:
                    type: string
                  subnet-id:
                    type: integer
      500:
        description: Internal server error
    """
    try:
        client = get_kea_client()
        subnet_id = request.args.get('subnet_id', type=int)
        reservations = client.get_reservations(subnet_id=subnet_id)
        
        # Format reservations for export
        export_data = {
            'export_date': __import__('datetime').datetime.now().isoformat(),
            'total_count': len(reservations),
            'reservations': reservations
        }
        
        from flask import make_response
        import json
        
        response = make_response(json.dumps(export_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = 'attachment; filename=dhcp_reservations_export.json'
        
        logger.info(f"Exported {len(reservations)} reservations")
        return response
        
    except Exception as e:
        logger.error(f"Error exporting reservations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/reservations/import', methods=['POST'])
def import_reservations():
    """Import DHCP reservations from uploaded JSON file
    ---
    tags:
      - Reservations
    summary: Import reservations from JSON file
    description: |
      Bulk import DHCP reservations from an uploaded JSON file. The import process:
      - Validates each reservation before creating it
      - Continues processing even if individual reservations fail
      - Returns a detailed summary of successes and failures

      Accepts JSON in two formats:
      1. Object with 'reservations' array: `{"reservations": [...]}`
      2. Direct array of reservations: `[...]`

      Common failure reasons:
      - Duplicate IP addresses (reservation already exists)
      - IP addresses outside subnet range
      - Invalid MAC addresses
      - Missing required fields (ip-address, hw-address)
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: JSON file containing reservations to import
    responses:
      200:
        description: Import completed (may include partial failures)
        schema:
          type: object
          properties:
            success:
              type: boolean
              description: Overall import process succeeded
            total:
              type: integer
              description: Total number of reservations in file
            success_count:
              type: integer
              description: Number of successfully imported reservations
            failed_count:
              type: integer
              description: Number of failed imports
            message:
              type: string
              description: Summary message
            failed_items:
              type: array
              description: Details of failed imports (if any)
              items:
                type: object
                properties:
                  index:
                    type: integer
                    description: Line number in import file
                  ip:
                    type: string
                    description: IP address that failed
                  mac:
                    type: string
                    description: MAC address (if available)
                  error:
                    type: string
                    description: Error message
            hint:
              type: string
              description: Troubleshooting hint (if failures occurred)
        examples:
          complete_success:
            success: true
            total: 10
            success_count: 10
            failed_count: 0
            message: "10 reservation(s) imported successfully. 0 reservation(s) failed to import."
          partial_success:
            success: true
            total: 10
            success_count: 8
            failed_count: 2
            message: "8 reservation(s) imported successfully. 2 reservation(s) failed to import."
            failed_items:
              - index: 3
                ip: "192.168.1.50"
                mac: "aa:bb:cc:dd:ee:03"
                error: "Reservation already exists for this IP"
            hint: "Check if you have duplicates or reservations outside the subnet range."
      400:
        description: Bad request - no file provided or invalid JSON format
      500:
        description: Internal server error
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Read and parse JSON file
        import json
        try:
            file_content = file.read().decode('utf-8')
            import_data = json.loads(file_content)
        except json.JSONDecodeError as e:
            return jsonify({
                'success': False,
                'error': f'Invalid JSON file: {str(e)}'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to read file: {str(e)}'
            }), 400
        
        # Extract reservations from import data
        if isinstance(import_data, dict) and 'reservations' in import_data:
            reservations_to_import = import_data['reservations']
        elif isinstance(import_data, list):
            reservations_to_import = import_data
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid file format. Expected JSON with "reservations" array or array of reservations.'
            }), 400
        
        if not isinstance(reservations_to_import, list):
            return jsonify({
                'success': False,
                'error': 'Reservations data must be an array'
            }), 400
        
        # Import reservations one by one
        client = get_kea_client()
        success_count = 0
        failed_count = 0
        failed_items = []
        
        for idx, reservation in enumerate(reservations_to_import):
            try:
                # Validate required fields
                ip_address = reservation.get('ip-address')
                hw_address = reservation.get('hw-address')

                if not ip_address or not hw_address:
                    failed_count += 1
                    failed_items.append({
                        'index': idx + 1,
                        'ip': ip_address or 'N/A',
                        'error': 'Missing required fields (ip-address or hw-address)'
                    })
                    continue

                hostname = reservation.get('hostname', '')
                subnet_id = reservation.get('subnet-id')

                # Handle DNS servers - support both formats
                option_data = None

                # Check for option-data format (Kea native format)
                if 'option-data' in reservation:
                    option_data = reservation.get('option-data')

                # Check for simplified dns-servers format
                elif 'dns-servers' in reservation:
                    dns_servers = reservation.get('dns-servers', '')
                    if dns_servers:
                        is_valid, error_msg, dns_list = validate_dns_servers(dns_servers)
                        if not is_valid:
                            failed_count += 1
                            failed_items.append({
                                'index': idx + 1,
                                'ip': ip_address,
                                'mac': hw_address,
                                'error': f'Invalid DNS servers: {error_msg}'
                            })
                            continue

                        if dns_list:
                            option_data = [{
                                "name": "domain-name-servers",
                                "data": ", ".join(dns_list)
                            }]

                # Attempt to create reservation (lock prevents concurrent config-set clobber)
                with RESERVATION_LOCK:
                    client.create_reservation(
                        ip_address=ip_address,
                        hw_address=hw_address,
                        hostname=hostname,
                        subnet_id=subnet_id,
                        option_data=option_data
                    )

                success_count += 1
                logger.info(f"Imported reservation: IP={ip_address}, MAC={hw_address}")

            except Exception as e:
                failed_count += 1
                error_msg = str(e)
                failed_items.append({
                    'index': idx + 1,
                    'ip': reservation.get('ip-address', 'N/A'),
                    'mac': reservation.get('hw-address', 'N/A'),
                    'error': error_msg
                })
                logger.warning(f"Failed to import reservation {idx + 1}: {error_msg}")
                # Continue with next reservation
        
        # Prepare response
        response_data = {
            'success': True,
            'total': len(reservations_to_import),
            'success_count': success_count,
            'failed_count': failed_count,
            'message': f'{success_count} reservation(s) imported successfully. {failed_count} reservation(s) failed to import.'
        }
        
        if failed_count > 0:
            response_data['failed_items'] = failed_items
            response_data['hint'] = 'Check if you have duplicates or reservations outside the subnet range.'
        
        logger.info(f"Import completed: {success_count} succeeded, {failed_count} failed")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error importing reservations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    runtime_config = load_config()
    app.run(
        host=runtime_config['app']['host'],
        port=runtime_config['app']['port'],
        debug=runtime_config['app']['debug']
    )
