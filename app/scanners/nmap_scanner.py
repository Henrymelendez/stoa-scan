# app/scanners/nmap_scanner.py
"""
Nmap integration module for PentestSaaS
Provides network discovery and port scanning functionality
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import socket
import asyncio
import concurrent.futures

try:
    import nmap
except ImportError:
    nmap = None

from app.models import ToolResult, Vulnerability, db


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NmapScannerError(Exception):
    """Custom exception for Nmap scanner errors"""
    pass


class NmapScanner:
    """
    Nmap scanner wrapper with async support and database integration
    """
    
    def __init__(self):
        if nmap is None:
            raise NmapScannerError("python-nmap library not installed. Run: pip install python-nmap")
        
        self.nm = nmap.PortScanner()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    
    def extract_ip_from_url(self, target: str) -> str:
        """
        Extract IP address or hostname from URL or return as-is if already IP/hostname
        """
        try:
            # If it looks like a URL, parse it
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
                if not hostname:
                    raise ValueError("Invalid URL format")
                return hostname
            
            # If it's already an IP or hostname, return as-is
            # Validate it's a reasonable target
            if self._is_valid_target(target):
                return target
            
            raise ValueError(f"Invalid target format: {target}")
            
        except Exception as e:
            logger.error(f"Error extracting IP from target {target}: {str(e)}")
            raise NmapScannerError(f"Invalid target: {target}")
    
    def _is_valid_target(self, target: str) -> bool:
        """
        Validate if target is a valid IP address or hostname
        """
        try:
            # Try to resolve hostname or validate IP
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
    
    def _parse_nmap_results(self, scan_results: Dict) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse nmap scan results into structured format
        Returns: (vulnerabilities, host_info)
        """
        vulnerabilities = []
        host_info = []
        
        for host in scan_results.get('scan', {}):
            host_data = scan_results['scan'][host]
            
            # Extract host information
            host_info.append({
                'ip': host,
                'hostname': host_data.get('hostnames', [{}])[0].get('name', ''),
                'state': host_data.get('status', {}).get('state', 'unknown'),
                'os': host_data.get('osmatch', [{}])[0].get('name', 'Unknown') if host_data.get('osmatch') else 'Unknown'
            })
            
            # Check for open ports (potential vulnerabilities)
            tcp_ports = host_data.get('tcp', {})
            for port, port_data in tcp_ports.items():
                if port_data.get('state') == 'open':
                    service = port_data.get('name', 'unknown')
                    version = port_data.get('version', '')
                    
                    # Determine severity based on port and service
                    severity = self._assess_port_severity(port, service, version)
                    
                    vulnerabilities.append({
                        'vuln_type': 'open_port',
                        'severity': severity,
                        'title': f'Open Port {port}/{service}',
                        'description': f'Open {service} service detected on port {port}',
                        'affected_url': f"{host}:{port}",
                        'evidence': json.dumps({
                            'port': port,
                            'service': service,
                            'version': version,
                            'state': port_data.get('state'),
                            'reason': port_data.get('reason', '')
                        }),
                        'remediation': self._get_port_remediation(port, service)
                    })
        
        return vulnerabilities, host_info
    
    def _assess_port_severity(self, port: int, service: str, version: str) -> str:
        """
        Assess severity of open port based on port number and service
        """
        # High-risk ports/services
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900, 6379]
        high_risk_services = ['ftp', 'telnet', 'smtp', 'pop3', 'imap', 'mssql', 'mysql', 'postgresql']
        
        # Medium-risk ports
        medium_risk_ports = [22, 25, 53, 110, 143, 993, 995, 1080, 3306, 5432]
        
        # Check for high-risk indicators
        if port in high_risk_ports or service.lower() in high_risk_services:
            return 'high'
        
        # Check for known vulnerable versions (basic examples)
        if version and any(vuln in version.lower() for vuln in ['vulnerable', 'exploit', 'backdoor']):
            return 'critical'
        
        # Medium risk ports
        if port in medium_risk_ports:
            return 'medium'
        
        # Well-known ports that are commonly expected
        if port in [80, 443, 8080, 8443]:
            return 'low'
        
        # Default for other open ports
        return 'medium'
    
    def _get_port_remediation(self, port: int, service: str) -> str:
        """
        Get remediation advice for open ports
        """
        remediation_map = {
            21: "Disable FTP if not required. Use SFTP/SCP instead. If required, use secure configuration.",
            22: "Ensure SSH is properly configured with key-based auth and disable password auth.",
            23: "Disable Telnet service immediately. Use SSH instead.",
            25: "Secure SMTP configuration. Use authentication and encryption.",
            53: "Secure DNS configuration. Prevent DNS amplification attacks.",
            80: "Ensure web server is updated and properly configured. Consider HTTPS redirect.",
            135: "Disable RPC endpoint mapper if not required. Use Windows firewall.",
            139: "Disable NetBIOS if not required. Use SMBv3 with signing.",
            443: "Ensure SSL/TLS is properly configured with strong ciphers.",
            445: "Disable SMBv1. Use SMBv3 with signing and encryption.",
            1433: "Secure SQL Server. Use SQL authentication, encrypt connections.",
            1521: "Secure Oracle database. Change default ports and credentials.",
            3389: "Secure RDP. Use Network Level Authentication, strong passwords.",
            5432: "Secure PostgreSQL. Change default credentials and restrict access.",
            5900: "Secure VNC. Use strong authentication and encryption.",
            6379: "Secure Redis. Enable authentication and bind to localhost."
        }
        
        return remediation_map.get(port, 
            f"Review if {service} service on port {port} is necessary. "
            "If required, ensure it's properly secured and updated.")
    
    async def run_nmap_scan(self, scan_id: int, target: str, scan_arguments: str = '-T4 -F') -> Dict:
        """
        Run asynchronous Nmap scan and save results to database
        
        Args:
            scan_id: Database scan ID
            target: Target host/URL to scan
            scan_arguments: Nmap arguments (default: fast scan)
        
        Returns:
            Dict containing scan results and metadata
        """
        tool_result = None
        
        try:
            # Extract IP/hostname from target
            host = self.extract_ip_from_url(target)
            logger.info(f"Starting Nmap scan for {host} with arguments: {scan_arguments}")
            
            # Create ToolResult entry
            tool_result = ToolResult(
                scan_id=scan_id,
                tool_name='nmap',
                status='running',
                started_at=datetime.now(timezone.utc)
            )
            db.session.add(tool_result)
            db.session.commit()
            
            # Run Nmap scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            scan_results = await loop.run_in_executor(
                self.executor, 
                self._run_nmap_sync, 
                host, 
                scan_arguments
            )
            
            # Parse results
            vulnerabilities, host_info = self._parse_nmap_results(scan_results)
            
            # Save vulnerabilities to database
            vuln_objects = []
            for vuln_data in vulnerabilities:
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    tool_result_id=tool_result.id,
                    **vuln_data
                )
                vuln_objects.append(vulnerability)
                db.session.add(vulnerability)
            
            # Update tool result with success
            tool_result.status = 'completed'
            tool_result.completed_at = datetime.now(timezone.utc)
            tool_result.raw_output = json.dumps({
                'nmap_results': scan_results,
                'host_info': host_info,
                'vulnerabilities_found': len(vulnerabilities)
            }, default=str)
            
            db.session.commit()
            
            result = {
                'status': 'completed',
                'host': host,
                'vulnerabilities_found': len(vulnerabilities),
                'hosts_scanned': len(scan_results.get('scan', {})),
                'scan_info': scan_results.get('nmap', {}),
                'vulnerabilities': vulnerabilities,
                'host_info': host_info
            }
            
            logger.info(f"Nmap scan completed for {host}. Found {len(vulnerabilities)} vulnerabilities.")
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Nmap scan failed for {target}: {error_msg}")
            
            # Update tool result with error
            if tool_result:
                tool_result.status = 'failed'
                tool_result.completed_at = datetime.now(timezone.utc)
                tool_result.error_message = error_msg
                db.session.commit()
            
            return {
                'status': 'failed',
                'error': error_msg,
                'target': target
            }
    
    def _run_nmap_sync(self, host: str, arguments: str) -> Dict:
        """
        Synchronous Nmap scan (runs in thread pool)
        """
        try:
            # Validate arguments for security (prevent command injection)
            safe_args = self._validate_nmap_arguments(arguments)
            
            # Run the scan
            self.nm.scan(hosts=host, arguments=safe_args)
            
            # Return raw results
            return dict(self.nm._scan_result)
            
        except Exception as e:
            logger.error(f"Nmap scan error: {str(e)}")
            raise NmapScannerError(f"Nmap scan failed: {str(e)}")
    
    def _validate_nmap_arguments(self, arguments: str) -> str:
        """
        Validate and sanitize Nmap arguments to prevent command injection
        """
        # Remove potentially dangerous characters and commands
        dangerous_chars = ['|', '&', ';', '`', ',', '(', ')', '<', '>', '!']
        dangerous_commands = ['rm', 'del', 'format', 'shutdown', 'reboot']
        
        clean_args = arguments
        
        # Remove dangerous characters
        for char in dangerous_chars:
            clean_args = clean_args.replace(char, '')
        
        # Check for dangerous commands
        for cmd in dangerous_commands:
            if cmd in clean_args.lower():
                logger.warning(f"Dangerous command '{cmd}' detected in arguments. Removing.")
                clean_args = clean_args.lower().replace(cmd, '')
        
        # Ensure we don't have empty arguments
        if not clean_args.strip():
            clean_args = '-T4 -F'  # Default safe arguments
        
        logger.debug(f"Sanitized Nmap arguments: {clean_args}")
        return clean_args
    
    def get_scan_presets(self) -> Dict[str, Dict]:
        """
        Get predefined scan presets for different use cases
        """
        return {
            'quick': {
                'name': 'Quick Scan',
                'arguments': '-T4 -F',
                'description': 'Fast scan of most common ports',
                'estimated_time': '1-2 minutes'
            },
            'comprehensive': {
                'name': 'Comprehensive Scan',
                'arguments': '-T4 -A -p-',
                'description': 'Detailed scan of all ports with OS detection',
                'estimated_time': '15-30 minutes'
            },
            'stealth': {
                'name': 'Stealth Scan',
                'arguments': '-sS -T2 -f',
                'description': 'Slow, fragmented SYN scan to avoid detection',
                'estimated_time': '10-20 minutes'
            },
            'service_detection': {
                'name': 'Service Detection',
                'arguments': '-sV -T4 -p 1-1000',
                'description': 'Service version detection on common ports',
                'estimated_time': '3-5 minutes'
            },
            'vulnerability_scan': {
                'name': 'Vulnerability Scan',
                'arguments': '-sV --script vuln -T4',
                'description': 'Service detection with vulnerability scripts',
                'estimated_time': '5-10 minutes'
            }
        }


# Convenience functions for easy integration
async def run_nmap(scan_id: int, target: str, scan_type: str = 'quick') -> Dict:
    """
    Convenience function to run Nmap scan
    
    Args:
        scan_id: Database scan ID
        target: Target to scan
        scan_type: Preset scan type ('quick', 'comprehensive', etc.)
    
    Returns:
        Dict with scan results
    """
    scanner = NmapScanner()
    presets = scanner.get_scan_presets()
    
    if scan_type not in presets:
        logger.warning(f"Unknown scan type '{scan_type}', using 'quick'")
        scan_type = 'quick'
    
    arguments = presets[scan_type]['arguments']
    return await scanner.run_nmap_scan(scan_id, target, arguments)


def validate_target(target: str) -> bool:
    """
    Validate if target is safe and legal to scan
    
    Args:
        target: Target URL or IP to validate
    
    Returns:
        True if target appears valid and safe
    """
    try:
        scanner = NmapScanner()
        host = scanner.extract_ip_from_url(target)
        
        # Check if it's a private IP (safer for testing)
        import ipaddress
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                return True
        except ValueError:
            pass  # Not an IP address, might be hostname
        
        # Additional validation could go here
        # For production, you might want to check against blacklists,
        # require explicit user consent, etc.
        
        return scanner._is_valid_target(host)
        
    except Exception as e:
        logger.error(f"Target validation failed: {str(e)}")
        return False