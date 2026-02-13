"""
KEA DHCP Control Agent API Client
Handles communication with KEA DHCP server via Control Agent REST API
"""

import requests
import logging
from typing import List, Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class CommandNotSupportedException(Exception):
    """Exception raised when a KEA command is not supported"""
    pass


class KeaClient:
    """Client for interacting with KEA DHCP Control Agent API"""
    
    def __init__(self, url: str, username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize KEA client
        
        Args:
            url: KEA Control Agent URL (e.g., http://localhost:8000)
            username: Optional username for authentication
            password: Optional password for authentication
        """
        self.url = url.rstrip('/')
        self.auth = (username, password) if username and password else None
        self.session = requests.Session()
        if self.auth:
            self.session.auth = self.auth
        
        # Configure retry strategy for transient SSL/network errors
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10,
            pool_block=False
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Disable SSL verification warnings if needed (not recommended for production)
        # import urllib3
        # urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session"""
        self.close()
    
    def close(self):
        """Close the session and release connections"""
        if self.session:
            self.session.close()
            logger.debug("KEA client session closed")
    
    def _send_command(self, command: str, service: List[str], arguments: Optional[Dict] = None, 
                     raise_on_unsupported: bool = True) -> Dict:
        """
        Send a command to KEA Control Agent
        
        Args:
            command: KEA command name
            service: Target service(s) - e.g., ["dhcp4"]
            arguments: Optional command arguments
            raise_on_unsupported: Whether to raise exception for unsupported commands
            
        Returns:
            Response from KEA
        """
        payload = {
            "command": command,
            "service": service
        }
        
        if arguments:
            payload["arguments"] = arguments
        
        logger.debug(f"Sending command '{command}' to KEA at {self.url}")
        
        try:
            response = self.session.post(
                self.url,
                json=payload,
                timeout=30,  # Increased timeout for reliability
                verify=True  # Keep SSL verification enabled for security
            )
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL Error communicating with KEA at {self.url}: {e}")
            raise Exception(f"Failed to communicate with KEA server: {e}")
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout communicating with KEA at {self.url}: {e}")
            raise Exception(f"KEA server timeout: {e}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error with KEA at {self.url}: {e}")
            raise Exception(f"Failed to connect to KEA server: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to communicate with KEA at {self.url}: {e}")
            raise Exception(f"Failed to communicate with KEA server: {e}")
        
        # Check if command was successful
        if isinstance(result, list) and len(result) > 0:
            result_code = result[0].get('result', 0)
            error_msg = result[0].get('text', 'Unknown error')
            
            logger.info(f"KEA response for {command}: result_code={result_code}, msg={error_msg}")
            
            # Result code 2 = command not supported
            if result_code == 2:
                logger.info(f"Command {command} not supported (result code 2)")
                if raise_on_unsupported:
                    raise CommandNotSupportedException(f"Command '{command}' not supported: {error_msg}")
                else:
                    return None
            elif result_code != 0:
                # Check if error message indicates unsupported command
                if 'not supported' in error_msg.lower() or 'command not found' in error_msg.lower():
                    logger.info(f"Command {command} appears unsupported based on error message")
                    if raise_on_unsupported:
                        raise CommandNotSupportedException(f"Command '{command}' not supported: {error_msg}")
                    else:
                        return None
                logger.error(f"KEA command {command} failed with code {result_code}: {error_msg}")
                raise Exception(f"KEA command failed: {error_msg}")
                
            return result[0]
        
        return result
    
    def get_version(self) -> str:
        """Get KEA version"""
        result = self._send_command("version-get", ["dhcp4"])
        return result.get('arguments', {}).get('extended', 'unknown')
    
    def get_leases(self, subnet_id: Optional[int] = None) -> List[Dict]:
        """
        Get all DHCPv4 leases
        
        Args:
            subnet_id: Optional subnet ID to filter leases
            
        Returns:
            List of lease dictionaries
        """
        all_leases = []
        
        # Try lease4-get-all first (requires lease_cmds hook library)
        try:
            result = self._send_command("lease4-get-all", ["dhcp4"], arguments={})
            all_leases = result.get('arguments', {}).get('leases', [])
            logger.info(f"Retrieved {len(all_leases)} leases using lease4-get-all")
        except CommandNotSupportedException as e:
            logger.info(f"lease4-get-all not supported, using fallback method")
            
            # Fallback: Try lease4-get-page
            try:
                subnets = self.get_subnets()
                subnet_ids = [subnet_id] if subnet_id else [s['id'] for s in subnets]
                
                for sid in subnet_ids:
                    page_leases = self._get_leases_by_subnet_paged(sid)
                    all_leases.extend(page_leases)
                
                logger.info(f"Retrieved {len(all_leases)} leases using lease4-get-page")
                    
            except (CommandNotSupportedException, Exception) as page_error:
                logger.warning(f"lease4-get-page not supported: {page_error}")
                
                # Last fallback: Try to get lease database info and suggest manual approach
                logger.error("No lease query commands available. Lease database must be queried directly.")
                
                try:
                    db_info = self._get_lease_database_info()
                    raise Exception(
                        f"KEA lease commands not available. Your KEA uses {db_info['type']} backend. "
                        f"To enable lease queries, add the lease_cmds hook library to your KEA configuration:\n"
                        f'"hooks-libraries": [{{"library": "/path/to/libdhcp_lease_cmds.so"}}]'
                    )
                except Exception as db_error:
                    raise Exception(
                        "Unable to retrieve leases. KEA lease commands (lease4-get-all, lease4-get-page) are not supported. "
                        "Please enable the 'lease_cmds' hook library in your KEA configuration."
                    )
        
        # Filter by subnet if specified
        if subnet_id is not None:
            all_leases = [l for l in all_leases if l.get('subnet-id') == subnet_id]
        
        # Enrich lease data
        for lease in all_leases:
            lease['hw-address'] = lease.get('hw-address', 'unknown')
            lease['hostname'] = lease.get('hostname', '')
            lease['state'] = lease.get('state', 0)
            
        return all_leases
    
    def _get_leases_by_subnet_paged(self, subnet_id: int) -> List[Dict]:
        """
        Get leases for a specific subnet using pagination
        
        Args:
            subnet_id: Subnet ID to fetch leases from
            
        Returns:
            List of lease dictionaries for the subnet
        """
        all_leases = []
        from_address = "0.0.0.0"
        limit = 1000  # Get up to 1000 leases per page
        
        while True:
            try:
                arguments = {
                    "subnets": [subnet_id],
                    "from": from_address,
                    "limit": limit
                }
                
                logger.debug(f"Fetching lease page for subnet {subnet_id} from {from_address}")
                result = self._send_command("lease4-get-page", ["dhcp4"], arguments)
                
                if result is None:
                    logger.warning(f"lease4-get-page returned None for subnet {subnet_id}")
                    break
                    
                page_leases = result.get('arguments', {}).get('leases', [])
                logger.debug(f"Got {len(page_leases)} leases for subnet {subnet_id}")
                
                if not page_leases:
                    break
                
                all_leases.extend(page_leases)
                
                # Check if we got a full page (might be more to fetch)
                if len(page_leases) < limit:
                    break
                
                # Set next page starting point
                last_lease = page_leases[-1]
                from_address = last_lease.get('ip-address')
                
                # Safety check to avoid infinite loops
                if not from_address:
                    break
                    
            except CommandNotSupportedException as e:
                logger.error(f"lease4-get-page not supported for subnet {subnet_id}: {e}")
                raise  # Re-raise to trigger alternative methods
            except Exception as e:
                logger.error(f"Error fetching lease page for subnet {subnet_id}: {e}")
                break
        
        logger.info(f"Fetched {len(all_leases)} leases for subnet {subnet_id}")
        return all_leases
    
    def _get_lease_database_info(self) -> Dict:
        """
        Get information about the lease database configuration

        Returns:
            Dictionary with database type and configuration (defaults to memfile on errors)
        """
        try:
            result = self._send_command("config-get", ["dhcp4"])
            config = result.get('arguments', {})
            dhcp4_config = config.get('Dhcp4', {})

            lease_db = dhcp4_config.get('lease-database', {})
            db_type = lease_db.get('type', 'memfile')

            return {
                'type': db_type,
                'config': lease_db
            }
        except Exception as e:
            logger.warning(f"Failed to parse lease database info from KEA config: {e}")
            return {
                'type': 'unknown',
                'config': {}
            }
    
    def get_reservations(self, subnet_id: Optional[int] = None) -> List[Dict]:
        """
        Get all DHCPv4 reservations

        Args:
            subnet_id: Optional subnet ID to filter reservations

        Returns:
            List of reservation dictionaries
        """
        try:
            # Get config to extract reservations
            result = self._send_command("config-get", ["dhcp4"])
            config = result.get('arguments', {})

            reservations = []

            # Extract reservations from subnet configurations
            dhcp4_config = config.get('Dhcp4', {})
            subnets = dhcp4_config.get('subnet4', [])

            for subnet in subnets:
                current_subnet_id = subnet.get('id')

                # Filter by subnet if specified
                if subnet_id is not None and current_subnet_id != subnet_id:
                    continue

                subnet_prefix = subnet.get('subnet', '')

                for reservation in subnet.get('reservations', []):
                    res_data = {
                        'ip-address': reservation.get('ip-address'),
                        'hw-address': reservation.get('hw-address'),
                        'hostname': reservation.get('hostname', ''),
                        'subnet-id': current_subnet_id,
                        'subnet': subnet_prefix
                    }

                    # Extract option-data if present
                    option_data = reservation.get('option-data', [])
                    if option_data:
                        res_data['option-data'] = option_data

                        # Extract DNS servers specifically for easy access
                        for option in option_data:
                            if option.get('name') == 'domain-name-servers':
                                res_data['dns-servers'] = option.get('data', '')
                                break

                    reservations.append(res_data)

            return reservations

        except Exception as e:
            logger.warning(f"Could not fetch reservations: {e}")
            return []
    
    def create_reservation(self, ip_address: str, hw_address: str,
                          hostname: str = "", subnet_id: Optional[int] = None,
                          option_data: Optional[List[Dict]] = None) -> Dict:
        """
        Create a new DHCPv4 reservation

        Args:
            ip_address: IP address to reserve
            hw_address: Hardware (MAC) address
            hostname: Optional hostname
            subnet_id: Subnet ID where the reservation should be created
            option_data: Optional list of DHCP options (e.g., DNS servers)

        Returns:
            Result of the reservation creation
        """
        reservation = {
            "ip-address": ip_address,
            "hw-address": hw_address
        }

        if hostname:
            reservation["hostname"] = hostname

        if subnet_id is not None:
            reservation["subnet-id"] = subnet_id

        if option_data:
            reservation["option-data"] = option_data

        arguments = {
            "reservation": reservation
        }

        try:
            result = self._send_command("reservation-add", ["dhcp4"], arguments)
            logger.info(f"Created reservation: IP={ip_address}, MAC={hw_address}")
            return reservation
        except CommandNotSupportedException as e:
            logger.warning(f"reservation-add not supported, using config-set fallback: {e}")
            # Fallback: Add reservation via config modification
            return self._create_reservation_via_config(ip_address, hw_address, hostname, subnet_id, option_data)
        except Exception as e:
            logger.error(f"Unexpected error in create_reservation: {type(e).__name__}: {e}")
            raise
    
    def _create_reservation_via_config(self, ip_address: str, hw_address: str,
                                       hostname: str = "", subnet_id: Optional[int] = None,
                                       option_data: Optional[List[Dict]] = None) -> Dict:
        """
        Create reservation by modifying the configuration (fallback when host_cmds not available)

        Args:
            ip_address: IP address to reserve
            hw_address: Hardware (MAC) address
            hostname: Optional hostname
            subnet_id: Subnet ID where the reservation should be created
            option_data: Optional list of DHCP options

        Returns:
            Created reservation dictionary
        """
        # Get current configuration
        result = self._send_command("config-get", ["dhcp4"])
        config = result.get('arguments', {})
        dhcp4_config = config.get('Dhcp4', {})

        # Find the target subnet
        subnets = dhcp4_config.get('subnet4', [])
        target_subnet = None

        for subnet in subnets:
            if subnet_id is None or subnet.get('id') == subnet_id:
                target_subnet = subnet
                if subnet_id is not None:
                    break
                # If no subnet_id specified, use first subnet
                if target_subnet is None:
                    target_subnet = subnet

        if target_subnet is None:
            raise Exception(f"Subnet {subnet_id} not found in configuration")

        # Create reservation object
        new_reservation = {
            "hw-address": hw_address,
            "ip-address": ip_address
        }
        if hostname:
            new_reservation["hostname"] = hostname

        if option_data:
            new_reservation["option-data"] = option_data

        # Add reservation to subnet
        if 'reservations' not in target_subnet:
            target_subnet['reservations'] = []

        # Check if reservation already exists and remove it (to enable overwrite)
        existing_reservations = target_subnet['reservations'][:]
        target_subnet['reservations'] = [
            res for res in existing_reservations
            if res.get('ip-address') != ip_address and res.get('hw-address') != hw_address
        ]

        target_subnet['reservations'].append(new_reservation)

        # Apply the updated configuration
        set_arguments = {
            "Dhcp4": dhcp4_config
        }

        self._send_command("config-set", ["dhcp4"], set_arguments)
        logger.info(f"Created reservation via config-set: IP={ip_address}, MAC={hw_address}")

        return new_reservation
    
    def delete_reservation(self, ip_address: str, subnet_id: Optional[int] = None):
        """
        Delete a DHCPv4 reservation
        
        Args:
            ip_address: IP address of the reservation to delete
            subnet_id: Optional subnet ID
        """
        arguments = {
            "ip-address": ip_address
        }
        
        if subnet_id is not None:
            arguments["subnet-id"] = subnet_id
        
        try:
            self._send_command("reservation-del", ["dhcp4"], arguments)
            logger.info(f"Deleted reservation: IP={ip_address}")
        except CommandNotSupportedException as e:
            logger.warning(f"reservation-del not supported, using config-set fallback: {e}")
            # Fallback: Delete reservation via config modification
            self._delete_reservation_via_config(ip_address, subnet_id)
        except Exception as e:
            logger.error(f"Unexpected error in delete_reservation: {type(e).__name__}: {e}")
            raise

    def delete_leases_by_mac(self, hw_address: str) -> int:
        """
        Delete all DHCPv4 leases for a given MAC address.

        Args:
            hw_address: Hardware (MAC) address (e.g. "bc:24:11:xx:xx:xx")

        Returns:
            Number of leases deleted
        """
        hw_address = hw_address.lower()
        all_leases = self.get_leases()
        matching = [l for l in all_leases if l.get('hw-address', '').lower() == hw_address]

        deleted = 0
        for lease in matching:
            ip = lease.get('ip-address')
            if ip:
                try:
                    self._send_command("lease4-del", ["dhcp4"], arguments={"ip-address": ip})
                    logger.info(f"Deleted lease: IP={ip}, MAC={hw_address}")
                    deleted += 1
                except Exception as e:
                    logger.warning(f"Failed to delete lease {ip} for MAC {hw_address}: {e}")

        return deleted


    def _delete_reservation_via_config(self, ip_address: str, subnet_id: Optional[int] = None):
        """
        Delete reservation by modifying the configuration (fallback when host_cmds not available)
        
        Args:
            ip_address: IP address of the reservation to delete
            subnet_id: Optional subnet ID
        """
        # Get current configuration
        result = self._send_command("config-get", ["dhcp4"])
        config = result.get('arguments', {})
        dhcp4_config = config.get('Dhcp4', {})
        
        # Find the target subnet and reservation
        subnets = dhcp4_config.get('subnet4', [])
        reservation_found = False
        
        for subnet in subnets:
            current_subnet_id = subnet.get('id')
            
            # If subnet_id specified, only look in that subnet
            if subnet_id is not None and current_subnet_id != subnet_id:
                continue
            
            # Check if this subnet has the reservation
            if 'reservations' in subnet:
                original_count = len(subnet['reservations'])
                # Filter out the reservation with matching IP
                subnet['reservations'] = [
                    r for r in subnet['reservations'] 
                    if r.get('ip-address') != ip_address
                ]
                new_count = len(subnet['reservations'])
                
                if new_count < original_count:
                    reservation_found = True
                    logger.info(f"Found and removed reservation for {ip_address} from subnet {current_subnet_id}")
                    
                    # If subnet_id was specified, we can stop searching
                    if subnet_id is not None:
                        break
        
        if not reservation_found:
            raise Exception(f"Reservation for IP {ip_address} not found")
        
        # Apply the updated configuration
        set_arguments = {
            "Dhcp4": dhcp4_config
        }
        
        self._send_command("config-set", ["dhcp4"], set_arguments)
        logger.info(f"Deleted reservation via config-set: IP={ip_address}")
    
    def get_config(self) -> Dict:
        """
        Get full KEA DHCPv4 configuration

        Returns:
            Full configuration dictionary
        """
        result = self._send_command("config-get", ["dhcp4"])
        config = result.get('arguments', {})
        return config

    def get_subnets(self) -> List[Dict]:
        """
        Get configured DHCPv4 subnets

        Returns:
            List of subnet dictionaries (empty list on parsing errors)
        """
        try:
            result = self._send_command("config-get", ["dhcp4"])
            config = result.get('arguments', {})

            dhcp4_config = config.get('Dhcp4', {})
            subnets = dhcp4_config.get('subnet4', [])

            subnet_list = []
            for subnet in subnets:
                subnet_list.append({
                    'id': subnet.get('id'),
                    'subnet': subnet.get('subnet'),
                    'pools': subnet.get('pools', [])
                })

            return subnet_list
        except Exception as e:
            logger.warning(f"Failed to parse subnets from KEA config: {e}")
            return []
