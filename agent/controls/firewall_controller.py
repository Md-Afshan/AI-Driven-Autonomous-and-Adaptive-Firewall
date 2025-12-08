"""
Firewall Controller - Manages low-level packet filtering and blocking using ipset
Uses ipset for high-performance IP blocking instead of raw iptables
"""

import subprocess
import logging
from typing import List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class FirewallController:
    """Control firewall rules using ipset for performance"""
    
    BLACKLIST_SET = 'blacklist'
    WHITELIST_SET = 'whitelist'
    
    def __init__(self):
        """Initialize firewall controller"""
        self._ensure_ipset_exists()
    
    def _ensure_ipset_exists(self):
        """Ensure required ipset lists exist"""
        for ipset_name in [self.BLACKLIST_SET, self.WHITELIST_SET]:
            try:
                subprocess.run(
                    ['ipset', 'list', ipset_name],
                    check=True,
                    capture_output=True
                )
                logger.debug(f"ipset '{ipset_name}' already exists")
            except subprocess.CalledProcessError:
                try:
                    # Create with timeout for automatic expiry
                    subprocess.run(
                        ['ipset', 'create', ipset_name, 'hash:ip', 'timeout', '3600'],
                        check=True,
                        capture_output=True
                    )
                    logger.info(f"Created ipset '{ipset_name}' with 1-hour timeout")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to create ipset '{ipset_name}': {str(e)}")
    
    def block_ip(self, ip_address: str, timeout: int = 3600) -> bool:
        """
        Add IP to blacklist using ipset
        
        Args:
            ip_address: IP address to block
            timeout: Timeout in seconds (default 1 hour)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if self._is_ip_blocked(ip_address):
                logger.debug(f"IP {ip_address} is already blocked")
                return True
            
            # Add IP to blacklist set with timeout
            subprocess.run(
                ['ipset', 'add', self.BLACKLIST_SET, ip_address, 'timeout', str(timeout)],
                check=True,
                capture_output=True
            )
            logger.warning(f"Blocked IP: {ip_address} (timeout: {timeout}s)")
            return True
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {str(e)}")
            return False
        except FileNotFoundError:
            logger.error("ipset command not found. Ensure ipset is installed.")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Remove IP from blacklist
        
        Args:
            ip_address: IP address to unblock
        
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ['ipset', 'del', self.BLACKLIST_SET, ip_address],
                check=True,
                capture_output=True
            )
            logger.info(f"Unblocked IP: {ip_address}")
            return True
        
        except subprocess.CalledProcessError:
            logger.warning(f"IP {ip_address} not in blacklist or already removed")
            return False
        except FileNotFoundError:
            logger.error("ipset command not found.")
            return False
    
    def whitelist_ip(self, ip_address: str, permanent: bool = False) -> bool:
        """
        Add IP to whitelist (trusted/safe IPs)
        
        Args:
            ip_address: IP address to whitelist
            permanent: If True, no timeout. If False, 24-hour timeout
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if permanent:
                subprocess.run(
                    ['ipset', 'add', self.WHITELIST_SET, ip_address],
                    check=True,
                    capture_output=True
                )
            else:
                # 24 hour timeout
                subprocess.run(
                    ['ipset', 'add', self.WHITELIST_SET, ip_address, 'timeout', '86400'],
                    check=True,
                    capture_output=True
                )
            logger.info(f"Whitelisted IP: {ip_address}")
            return True
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to whitelist IP {ip_address}: {str(e)}")
            return False
    
    def is_ip_whitelisted(self, ip_address: str) -> bool:
        """
        Check if IP is in whitelist
        
        Args:
            ip_address: IP to check
        
        Returns:
            True if whitelisted, False otherwise
        """
        try:
            subprocess.run(
                ['ipset', 'test', self.WHITELIST_SET, ip_address],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if IP is already blocked
        
        Args:
            ip_address: IP to check
        
        Returns:
            True if blocked, False otherwise
        """
        try:
            subprocess.run(
                ['ipset', 'test', self.BLACKLIST_SET, ip_address],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get list of all blocked IPs
        
        Returns:
            List of blocked IP addresses
        """
        try:
            result = subprocess.run(
                ['ipset', 'list', self.BLACKLIST_SET],
                check=True,
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')
            blocked_ips = []
            in_members = False
            
            for line in lines:
                if line.startswith('Members:'):
                    in_members = True
                    continue
                if in_members and line.strip():
                    blocked_ips.append(line.strip())
            
            return blocked_ips
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get blocked IPs: {str(e)}")
            return []
    
    def get_whitelisted_ips(self) -> List[str]:
        """
        Get list of all whitelisted IPs
        
        Returns:
            List of whitelisted IP addresses
        """
        try:
            result = subprocess.run(
                ['ipset', 'list', self.WHITELIST_SET],
                check=True,
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')
            whitelisted_ips = []
            in_members = False
            
            for line in lines:
                if line.startswith('Members:'):
                    in_members = True
                    continue
                if in_members and line.strip():
                    whitelisted_ips.append(line.strip())
            
            return whitelisted_ips
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get whitelisted IPs: {str(e)}")
            return []
    
    def flush_blacklist(self) -> bool:
        """
        Clear all blocked IPs
        
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ['ipset', 'flush', self.BLACKLIST_SET],
                check=True,
                capture_output=True
            )
            logger.info("Blacklist flushed")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to flush blacklist: {str(e)}")
            return False
    
    def flush_whitelist(self) -> bool:
        """
        Clear all whitelisted IPs
        
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ['ipset', 'flush', self.WHITELIST_SET],
                check=True,
                capture_output=True
            )
            logger.info("Whitelist flushed")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to flush whitelist: {str(e)}")
            return False
    
    def block_subnet(self, subnet: str, timeout: int = 3600) -> bool:
        """
        Block an entire subnet
        
        Args:
            subnet: Subnet in CIDR notation (e.g., 192.168.1.0/24)
            timeout: Timeout in seconds
        
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ['ipset', 'add', self.BLACKLIST_SET, subnet, 'timeout', str(timeout)],
                check=True,
                capture_output=True
            )
            logger.warning(f"Blocked subnet: {subnet} (timeout: {timeout}s)")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block subnet {subnet}: {str(e)}")
            return False


if __name__ == '__main__':
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    controller = FirewallController()
    
    # Block an IP
    controller.block_ip('192.168.1.100', timeout=1800)
    
    # Whitelist an IP
    controller.whitelist_ip('10.0.0.1', permanent=True)
    
    # Get lists
    print("Blocked IPs:", controller.get_blocked_ips())
    print("Whitelisted IPs:", controller.get_whitelisted_ips())
    
    # Check status
    print("192.168.1.100 is blocked:", controller._is_ip_blocked('192.168.1.100'))
    print("10.0.0.1 is whitelisted:", controller.is_ip_whitelisted('10.0.0.1'))
