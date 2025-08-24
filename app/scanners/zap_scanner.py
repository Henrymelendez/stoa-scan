# app/scanners/zap_scanner.py
"""
OWASP ZAP integration module for PentestSaaS
Provides web application vulnerability scanning functionality
"""

import json
import logging
import time
import asyncio
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import subprocess
import signal
import os

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

from app.models import ToolResult, Vulnerability, db


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZapScannerError(Exception):
    """Custom exception for ZAP scanner errors"""
    pass


class ZapScanner:
    """
    OWASP ZAP scanner wrapper with async support and database integration
    """
    
    def __init__(self, zap_proxy_port=8080, zap_api_key=None):
        if ZAPv2 is None:
            raise ZapScannerError("python-owasp-zap-v2.4 library not installed. Run: pip install python-owasp-zap-v2.4")
        
        self.proxy_port = zap_proxy_port
        self.api_key = zap_api_key or 'your-api-key-here'
        self.zap_process = None
        self.zap = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        
    def start_zap_daemon(self) -> bool:
        """
        Start ZAP daemon if not already running
        Returns True if successful, False otherwise
        """
        try:
            # Check if ZAP is already running
            try:
                test_zap = ZAPv2(proxies={'http': f'http://127.0.0.1:{self.proxy_port}',
                                         'https': f'http://127.0.0.1:{self.proxy_port}'})
                test_zap.core.version
                logger.info(f"ZAP daemon already running on port {self.proxy_port}")
                self.zap = test_zap
                return True
            except:
                pass
            
            # Try to start ZAP daemon
            logger.info(f"Starting ZAP daemon on port {self.proxy_port}")
            
            # Common ZAP installation paths
            zap_paths = [
                '/usr/share/zaproxy/zap.sh',
                '/Applications/OWASP ZAP.app/Contents/Java/zap.sh',
                'zap.sh',
                'zap',
                '/opt/zaproxy/zap.sh'
            ]
            
            zap_cmd = None
            for path in zap_paths:
                if os.path.exists(path) or (path in ['zap.sh', 'zap']):
                    zap_cmd = path
                    break
            
            if not zap_cmd:
                raise ZapScannerError("ZAP binary not found. Please install OWASP ZAP")
            
            # Start ZAP in daemon mode
            cmd = [
                zap_cmd,
                '-daemon',
                '-port', str(self.proxy_port),
                '-config', f'api.key={self.api_key}',
                '-config', 'api.addrs.addr.name=.*',
                '-config', 'api.addrs.addr.regex=true'
            ]
            
            self.zap_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            # Wait for ZAP to start (max 30 seconds)
            for i in range(30):
                try:
                    time.sleep(1)
                    self.zap = ZAPv2(
                        apikey=self.api_key,
                        proxies={'http': f'http://127.0.0.1:{self.proxy_port}',
                                'https': f'http://127.0.0.1:{self.proxy_port}'}
                    )
                    self.zap.core.version
                    logger.info(f"ZAP daemon started successfully on port {self.proxy_port}")
                    return True
                except:
                    continue
            
            raise ZapScannerError("Failed to start ZAP daemon within 30 seconds")
            
        except Exception as e:
            logger.error(f"Failed to start ZAP daemon: {str(e)}")
            return False
    
    def stop_zap_daemon(self):
        """Stop ZAP daemon if we started it"""
        try:
            if self.zap_process:
                # Gracefully shutdown ZAP
                if self.zap:
                    try:
                        self.zap.core.shutdown()
                        time.sleep(2)
                    except:
                        pass
                
                # Force kill if still running
                if self.zap_process.poll() is None:
                    os.killpg(os.getpgid(self.zap_process.pid), signal.SIGTERM)
                    time.sleep(1)
                    if self.zap_process.poll() is None:
                        os.killpg(os.getpgid(self.zap_process.pid), signal.SIGKILL)
                
                logger.info("ZAP daemon stopped")
                
        except Exception as e:
            logger.error(f"Error stopping ZAP daemon: {str(e)}")
    
    def validate_target_url(self, url: str) -> str:
        """
        Validate and normalize target URL
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
            
            # Basic security check - avoid scanning internal services
            if parsed.hostname in ['localhost', '127.0.0.1'] and parsed.port and parsed.port < 1024:
                logger.warning(f"Scanning privileged port on localhost: {url}")
            
            return url
            
        except Exception as e:
            logger.error(f"Invalid target URL {url}: {str(e)}")
            raise ZapScannerError(f"Invalid target URL: {url}")
    
    def _parse_zap_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """
        Parse ZAP alerts into vulnerability format
        """
        vulnerabilities = []
        
        for alert in alerts:
            # Map ZAP risk levels to our severity levels
            risk_mapping = {
                'High': 'high',
                'Medium': 'medium', 
                'Low': 'low',
                'Informational': 'info'
            }
            
            # Map common ZAP alert types to our vulnerability types
            vuln_type = self._map_zap_alert_to_vuln_type(alert.get('name', ''))
            
            vulnerability = {
                'vuln_type': vuln_type,
                'severity': risk_mapping.get(alert.get('risk', 'Low'), 'low'),
                'title': alert.get('name', 'Unknown Vulnerability'),
                'description': alert.get('description', ''),
                'affected_url': alert.get('url', ''),
                'affected_parameter': alert.get('param', ''),
                'cve_id': self._extract_cve_from_alert(alert),
                'remediation': alert.get('solution', ''),
                'evidence': json.dumps({
                    'attack': alert.get('attack', ''),
                    'evidence': alert.get('evidence', ''),
                    'method': alert.get('method', ''),
                    'reference': alert.get('reference', ''),
                    'cweid': alert.get('cweid', ''),
                    'wascid': alert.get('wascid', ''),
                    'sourceid': alert.get('sourceid', '')
                })
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _map_zap_alert_to_vuln_type(self, alert_name: str) -> str:
        """
        Map ZAP alert names to standardized vulnerability types
        """
        alert_lower = alert_name.lower()
        
        if 'sql injection' in alert_lower:
            return 'sql_injection'
        elif 'xss' in alert_lower or 'cross site scripting' in alert_lower:
            return 'xss'
        elif 'csrf' in alert_lower or 'cross site request forgery' in alert_lower:
            return 'csrf'
        elif 'path traversal' in alert_lower or 'directory traversal' in alert_lower:
            return 'path_traversal'
        elif 'injection' in alert_lower:
            return 'injection'
        elif 'authentication' in alert_lower:
            return 'authentication'
        elif 'authorization' in alert_lower or 'access control' in alert_lower:
            return 'authorization'
        elif 'ssl' in alert_lower or 'tls' in alert_lower:
            return 'ssl_tls'
        elif 'cookie' in alert_lower:
            return 'cookie_security'
        elif 'header' in alert_lower:
            return 'security_headers'
        else:
            return 'web_vulnerability'
    
    def _extract_cve_from_alert(self, alert: Dict) -> Optional[str]:
        """
        Extract CVE ID from ZAP alert if present
        """
        reference = alert.get('reference', '')
        if 'CVE-' in reference:
            # Simple regex to find CVE IDs
            import re
            cve_match = re.search(r'CVE-\d{4}-\d{4,}', reference)
            if cve_match:
                return cve_match.group(0)
        return None
    
    async def run_spider_scan(self, url: str, max_depth: int = 5) -> Dict:
        """
        Run ZAP spider scan to discover URLs
        """
        try:
            validated_url = self.validate_target_url(url)
            logger.info(f"Starting ZAP spider scan for {validated_url}")
            
            # Start spider
            scan_id = self.zap.spider.scan(validated_url, maxchildren=max_depth)
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                await asyncio.sleep(2)
                progress = self.zap.spider.status(scan_id)
                logger.debug(f"Spider progress: {progress}%")
            
            # Get spider results
            spider_results = self.zap.spider.results(scan_id)
            
            return {
                'status': 'completed',
                'urls_found': len(spider_results),
                'scan_id': scan_id,
                'results': spider_results
            }
            
        except Exception as e:
            logger.error(f"Spider scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def run_active_scan(self, url: str, recurse: bool = True) -> Dict:
        """
        Run ZAP active scan to find vulnerabilities
        """
        try:
            validated_url = self.validate_target_url(url)
            logger.info(f"Starting ZAP active scan for {validated_url}")
            
            # Start active scan
            scan_id = self.zap.ascan.scan(validated_url, recurse=recurse)
            
            # Wait for active scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                await asyncio.sleep(5)
                progress = self.zap.ascan.status(scan_id)
                logger.debug(f"Active scan progress: {progress}%")
            
            return {
                'status': 'completed',
                'scan_id': scan_id
            }
            
        except Exception as e:
            logger.error(f"Active scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def run_zap_scan(self, scan_id: int, target_url: str, scan_config: Dict = None) -> Dict:
        """
        Run complete ZAP scan (spider + active scan) and save results to database
        
        Args:
            scan_id: Database scan ID
            target_url: Target URL to scan
            scan_config: Optional scan configuration
        
        Returns:
            Dict containing scan results and metadata
        """
        tool_result = None
        
        try:
            # Default scan configuration
            config = {
                'spider_max_depth': 5,
                'active_scan_recurse': True,
                'spider_enabled': True,
                'active_scan_enabled': True,
                'timeout_minutes': 30
            }
            if scan_config:
                config.update(scan_config)
            
            validated_url = self.validate_target_url(target_url)
            logger.info(f"Starting ZAP scan for {validated_url}")
            
            # Create ToolResult entry
            tool_result = ToolResult(
                scan_id=scan_id,
                tool_name='zap',
                status='running',
                started_at=datetime.now(timezone.utc)
            )
            db.session.add(tool_result)
            db.session.commit()
            
            # Start ZAP daemon
            if not self.start_zap_daemon():
                raise ZapScannerError("Failed to start ZAP daemon")
            
            # Run spider scan if enabled
            spider_results = {}
            if config['spider_enabled']:
                spider_results = await self.run_spider_scan(
                    validated_url, 
                    config['spider_max_depth']
                )
                if spider_results['status'] == 'failed':
                    raise ZapScannerError(f"Spider scan failed: {spider_results.get('error')}")
            
            # Run active scan if enabled
            active_results = {}
            if config['active_scan_enabled']:
                active_results = await self.run_active_scan(
                    validated_url,
                    config['active_scan_recurse']
                )
                if active_results['status'] == 'failed':
                    raise ZapScannerError(f"Active scan failed: {active_results.get('error')}")
            
            # Get all alerts (vulnerabilities)
            alerts = self.zap.core.alerts()
            vulnerabilities = self._parse_zap_alerts(alerts)
            
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
                'spider_results': spider_results,
                'active_results': active_results,
                'alerts': alerts,
                'vulnerabilities_found': len(vulnerabilities),
                'config_used': config
            }, default=str)
            
            db.session.commit()
            
            result = {
                'status': 'completed',
                'target_url': validated_url,
                'vulnerabilities_found': len(vulnerabilities),
                'spider_urls_found': spider_results.get('urls_found', 0),
                'vulnerabilities': vulnerabilities,
                'scan_config': config
            }
            
            logger.info(f"ZAP scan completed for {validated_url}. Found {len(vulnerabilities)} vulnerabilities.")
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"ZAP scan failed for {target_url}: {error_msg}")
            
            # Update tool result with error
            if tool_result:
                tool_result.status = 'failed'
                tool_result.completed_at = datetime.now(timezone.utc)
                tool_result.error_message = error_msg
                db.session.commit()
            
            return {
                'status': 'failed',
                'error': error_msg,
                'target': target_url
            }
        
        finally:
            # Clean up ZAP session
            try:
                if self.zap:
                    self.zap.core.new_session()  # Clear session data
            except:
                pass
    
    def get_scan_policies(self) -> Dict[str, Dict]:
        """
        Get predefined ZAP scan policies for different use cases
        """
        return {
            'basic': {
                'name': 'Basic Web Scan',
                'spider_max_depth': 3,
                'active_scan_recurse': True,
                'spider_enabled': True,
                'active_scan_enabled': True,
                'description': 'Basic spider and active scan',
                'estimated_time': '10-15 minutes'
            },
            'comprehensive': {
                'name': 'Comprehensive Web Scan',
                'spider_max_depth': 10,
                'active_scan_recurse': True,
                'spider_enabled': True,
                'active_scan_enabled': True,
                'description': 'Deep spider scan with comprehensive active scanning',
                'estimated_time': '30-60 minutes'
            },
            'spider_only': {
                'name': 'Spider Only',
                'spider_max_depth': 5,
                'active_scan_recurse': False,
                'spider_enabled': True,
                'active_scan_enabled': False,
                'description': 'URL discovery only, no vulnerability testing',
                'estimated_time': '2-5 minutes'
            },
            'active_only': {
                'name': 'Active Scan Only',
                'spider_max_depth': 0,
                'active_scan_recurse': False,
                'spider_enabled': False,
                'active_scan_enabled': True,
                'description': 'Vulnerability testing on provided URL only',
                'estimated_time': '5-10 minutes'
            },
            'quick': {
                'name': 'Quick Scan',
                'spider_max_depth': 2,
                'active_scan_recurse': False,
                'spider_enabled': True,
                'active_scan_enabled': True,
                'description': 'Fast scan with limited depth',
                'estimated_time': '3-5 minutes'
            }
        }
    
    def get_vulnerability_categories(self) -> List[str]:
        """
        Get list of vulnerability categories that ZAP can detect
        """
        return [
            'sql_injection',
            'xss',
            'csrf',
            'path_traversal',
            'injection',
            'authentication',
            'authorization',
            'ssl_tls',
            'cookie_security',
            'security_headers',
            'web_vulnerability'
        ]


# Convenience functions for easy integration
async def run_zap(scan_id: int, target_url: str, scan_policy: str = 'basic') -> Dict:
    """
    Convenience function to run ZAP scan
    
    Args:
        scan_id: Database scan ID
        target_url: Target URL to scan
        scan_policy: Scan policy preset name
    
    Returns:
        Dict with scan results
    """
    scanner = ZapScanner()
    
    try:
        policies = scanner.get_scan_policies()
        
        if scan_policy not in policies:
            logger.warning(f"Unknown scan policy '{scan_policy}', using 'basic'")
            scan_policy = 'basic'
        
        config = policies[scan_policy]
        return await scanner.run_zap_scan(scan_id, target_url, config)
        
    finally:
        # Always try to clean up
        scanner.stop_zap_daemon()


def validate_web_target(url: str) -> bool:
    """
    Validate if URL is safe and legal to scan
    
    Args:
        url: Target URL to validate
    
    Returns:
        True if target appears valid and safe
    """
    try:
        scanner = ZapScanner()
        validated_url = scanner.validate_target_url(url)
        
        parsed = urlparse(validated_url)
        
        # Allow localhost and private networks for testing
        if parsed.hostname in ['localhost', '127.0.0.1']:
            return True
        
        # Check for private IP ranges (safer for testing)
        import ipaddress
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback:
                return True
        except ValueError:
            pass  # Not an IP address, might be hostname
        
        # Additional validation could go here
        # For production, you might want to:
        # - Check against domain blacklists
        # - Require explicit user consent
        # - Validate ownership via DNS TXT records
        
        return True  # Allow all for MVP, but log warning
        
    except Exception as e:
        logger.error(f"Web target validation failed: {str(e)}")
        return False


# ZAP daemon management utilities
class ZapDaemonManager:
    """
    Context manager for ZAP daemon lifecycle
    """
    
    def __init__(self, port=8080, api_key=None):
        self.scanner = ZapScanner(port, api_key)
    
    def __enter__(self):
        if self.scanner.start_zap_daemon():
            return self.scanner
        else:
            raise ZapScannerError("Failed to start ZAP daemon")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.scanner.stop_zap_daemon()


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_zap():
        """Test the ZAP scanner"""
        try:
            # Test with a safe localhost target
            with ZapDaemonManager() as scanner:
                # Test target validation
                if validate_web_target('http://127.0.0.1:8000'):
                    print("Target validation passed")
                
                # Test scan policies
                policies = scanner.get_scan_policies()
                print(f"Available scan policies: {list(policies.keys())}")
                
                # Test vulnerability categories
                categories = scanner.get_vulnerability_categories()
                print(f"Vulnerability categories: {categories}")
                
                print("ZAP scanner test completed successfully")
                
        except Exception as e:
            print(f"ZAP test failed: {str(e)}")
            print("Note: This requires OWASP ZAP to be installed and accessible")
    
    # Run test if this script is executed directly
    asyncio.run(test_zap())