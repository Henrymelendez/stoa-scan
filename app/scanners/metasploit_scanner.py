# app/scanners/metasploit_scanner.py
"""
Metasploit integration module for PentestSaaS
Provides exploit simulation and vulnerability validation functionality
"""

import json
import logging
import time
import asyncio
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import subprocess
import os

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    MsfRpcClient = None

from app.models import ToolResult, Vulnerability, db


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MetasploitScannerError(Exception):
    """Custom exception for Metasploit scanner errors"""
    pass


class MetasploitScanner:
    """
    Metasploit scanner wrapper with async support and database integration
    Focus on safe exploit verification rather than actual exploitation
    """
    
    def __init__(self, msf_host='127.0.0.1', msf_port=55553, msf_password='msf123'):
        if MsfRpcClient is None:
            raise MetasploitScannerError("pymetasploit3 library not installed. Run: pip install pymetasploit3")
        
        self.msf_host = msf_host
        self.msf_port = msf_port
        self.msf_password = msf_password
        self.client = None
        self.msf_process = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        
        # Safe exploit modules for verification (no destructive payloads)
        self.safe_modules = {
            'web': [
                'auxiliary/scanner/http/dir_scanner',
                'auxiliary/scanner/http/http_version',
                'auxiliary/scanner/http/options',
                'auxiliary/scanner/http/robots_txt',
                'auxiliary/scanner/http/ssl',
                'auxiliary/scanner/http/title',
                'auxiliary/scanner/http/wordpress_scanner',
                'auxiliary/scanner/http/apache_mod_cgi_bash_env_exec'
            ],
            'network': [
                'auxiliary/scanner/portscan/syn',
                'auxiliary/scanner/portscan/tcp',
                'auxiliary/scanner/discovery/udp_sweep',
                'auxiliary/scanner/netbios/nbname',
                'auxiliary/scanner/smb/smb_version',
                'auxiliary/scanner/ssh/ssh_version',
                'auxiliary/scanner/ftp/ftp_version',
                'auxiliary/scanner/telnet/telnet_version'
            ],
            'database': [
                'auxiliary/scanner/mssql/mssql_ping',
                'auxiliary/scanner/mysql/mysql_version',
                'auxiliary/scanner/postgres/postgres_version',
                'auxiliary/scanner/oracle/oracle_version'
            ],
            'verification': [
                'auxiliary/scanner/http/sqli_scanner',
                'auxiliary/scanner/http/blind_sql_injection',
                'auxiliary/scanner/http/xpath',
                'auxiliary/scanner/http/coldfusion_version',
                'auxiliary/scanner/http/joomla_version'
            ]
        }
    
    def start_msf_rpc(self) -> bool:
        """
        Start Metasploit RPC server if not already running
        Returns True if successful, False otherwise
        """
        try:
            # Check if MSF RPC is already running
            try:
                test_client = MsfRpcClient(
                    password=self.msf_password,
                    server=self.msf_host,
                    port=self.msf_port
                )
                test_client.core.version()
                logger.info(f"MSF RPC server already running on {self.msf_host}:{self.msf_port}")
                self.client = test_client
                return True
            except:
                pass
            
            # Try to start MSF RPC daemon
            logger.info(f"Starting MSF RPC server on port {self.msf_port}")
            
            # Common MSF installation paths
            msf_paths = [
                '/usr/bin/msfrpcd',
                '/opt/metasploit-framework/msfrpcd',
                '/usr/local/bin/msfrpcd',
                'msfrpcd'
            ]
            
            msf_cmd = None
            for path in msf_paths:
                if os.path.exists(path) or (path == 'msfrpcd'):
                    msf_cmd = path
                    break
            
            if not msf_cmd:
                raise MetasploitScannerError("msfrpcd binary not found. Please install Metasploit Framework")
            
            # Start MSF RPC daemon
            cmd = [
                msf_cmd,
                '-P', self.msf_password,
                '-S',  # Use SSL
                '-p', str(self.msf_port),
                '-a', self.msf_host,
                '-f'   # Run in foreground (we'll capture output)
            ]
            
            self.msf_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for MSF RPC to start (max 60 seconds)
            for i in range(60):
                try:
                    time.sleep(1)
                    self.client = MsfRpcClient(
                        password=self.msf_password,
                        server=self.msf_host,
                        port=self.msf_port
                    )
                    self.client.core.version()
                    logger.info(f"MSF RPC server started successfully on {self.msf_host}:{self.msf_port}")
                    return True
                except Exception as e:
                    if i == 59:  # Last attempt
                        logger.error(f"Failed to connect to MSF RPC: {str(e)}")
                    continue
            
            raise MetasploitScannerError("Failed to start MSF RPC server within 60 seconds")
            
        except Exception as e:
            logger.error(f"Failed to start MSF RPC server: {str(e)}")
            return False
    
    def stop_msf_rpc(self):
        """Stop MSF RPC server if we started it"""
        try:
            if self.client:
                try:
                    self.client.core.stop()
                    time.sleep(2)
                except:
                    pass
                self.client = None
            
            if self.msf_process:
                self.msf_process.terminate()
                time.sleep(2)
                if self.msf_process.poll() is None:
                    self.msf_process.kill()
                logger.info("MSF RPC server stopped")
                
        except Exception as e:
            logger.error(f"Error stopping MSF RPC server: {str(e)}")
    
    def validate_target(self, target: str) -> str:
        """
        Validate and normalize target for safe exploitation testing
        """
        try:
            # Parse URL or IP
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                if not parsed.netloc:
                    raise ValueError("Invalid URL format")
                return target
            
            # Validate IP/hostname
            import ipaddress
            try:
                # Try as IP address
                ip = ipaddress.ip_address(target)
                # Only allow private IPs and loopback for safety
                if not (ip.is_private or ip.is_loopback):
                    logger.warning(f"Target {target} is not a private IP. Ensure you have permission to test.")
                return str(ip)
            except ValueError:
                # Not an IP, treat as hostname
                if not target.replace('.', '').replace('-', '').isalnum():
                    raise ValueError("Invalid hostname format")
                return target
            
        except Exception as e:
            logger.error(f"Invalid target {target}: {str(e)}")
            raise MetasploitScannerError(f"Invalid target: {target}")
    
    def get_safe_modules_for_target(self, target_type: str, vulnerability_hints: List[str] = None) -> List[str]:
        """
        Get list of safe auxiliary modules for target verification
        
        Args:
            target_type: 'web', 'network', 'database', 'verification'
            vulnerability_hints: List of suspected vulnerabilities to focus on
        
        Returns:
            List of safe module names
        """
        modules = self.safe_modules.get(target_type, [])
        
        if vulnerability_hints:
            # Filter modules based on vulnerability hints
            filtered_modules = []
            for hint in vulnerability_hints:
                hint_lower = hint.lower()
                for module in modules:
                    if any(keyword in module.lower() for keyword in hint_lower.split('_')):
                        if module not in filtered_modules:
                            filtered_modules.append(module)
            return filtered_modules if filtered_modules else modules[:3]  # Fallback to first 3
        
        return modules
    
    def run_auxiliary_module(self, module_name: str, options: Dict[str, Any]) -> Dict:
        """
        Run a single auxiliary module safely
        """
        try:
            logger.info(f"Running auxiliary module: {module_name}")
            
            # Create job
            module = self.client.modules.use('auxiliary', module_name)
            if not module:
                raise MetasploitScannerError(f"Failed to load module: {module_name}")
            
            # Set options
            for key, value in options.items():
                module[key] = value
            
            # Set safe defaults
            module['THREADS'] = '1'  # Single thread to be gentle
            module['ShowProgress'] = 'false'
            
            # Execute module
            result = module.execute()
            
            # Wait for completion (with timeout)
            start_time = time.time()
            timeout = 60  # 1 minute timeout per module
            
            while True:
                if time.time() - start_time > timeout:
                    logger.warning(f"Module {module_name} timed out")
                    return {
                        'status': 'timeout',
                        'module': module_name,
                        'error': f'Module execution timed out after {timeout} seconds'
                    }
                
                # Check if job completed
                jobs = self.client.jobs.list
                if str(result['job_id']) not in jobs:
                    break
                
                time.sleep(1)
            
            # Get results (this varies by module type)
            output = []
            try:
                # Try to get console output
                console_id = self.client.consoles.console().cid
                console = self.client.consoles.console(console_id)
                if hasattr(console, 'read'):
                    output.append(console.read()['data'])
            except:
                pass
            
            return {
                'status': 'completed',
                'module': module_name,
                'job_id': result.get('job_id'),
                'output': output,
                'options_used': options
            }
            
        except Exception as e:
            logger.error(f"Error running module {module_name}: {str(e)}")
            return {
                'status': 'failed',
                'module': module_name,
                'error': str(e),
                'options_used': options
            }
    
    def parse_module_results(self, results: List[Dict]) -> List[Dict]:
        """
        Parse auxiliary module results into vulnerability format
        """
        vulnerabilities = []
        
        for result in results:
            if result['status'] != 'completed':
                continue
            
            module_name = result['module']
            output = result.get('output', [])
            
            # Basic vulnerability detection based on module results
            vuln_info = self._analyze_module_output(module_name, output, result.get('options_used', {}))
            
            if vuln_info:
                vulnerabilities.append(vuln_info)
        
        return vulnerabilities
    
    def _analyze_module_output(self, module_name: str, output: List[str], options: Dict) -> Optional[Dict]:
        """
        Analyze module output to determine if vulnerability exists
        """
        output_text = ' '.join(output).lower() if output else ''
        target = options.get('RHOSTS', options.get('RHOST', 'unknown'))
        
        # Module-specific analysis
        if 'sqli' in module_name or 'sql_injection' in module_name:
            if any(indicator in output_text for indicator in ['vulnerable', 'injection', 'error', 'mysql', 'oracle']):
                return {
                    'vuln_type': 'sql_injection',
                    'severity': 'high',
                    'title': 'Potential SQL Injection Detected',
                    'description': f'Module {module_name} detected possible SQL injection vulnerability',
                    'affected_url': target,
                    'remediation': 'Implement parameterized queries and input validation',
                    'evidence': json.dumps({
                        'module': module_name,
                        'detection_method': 'auxiliary_scanner',
                        'output_snippet': output_text[:500] if output_text else 'No output captured'
                    })
                }
        
        elif 'wordpress' in module_name:
            if 'version' in output_text or 'wp-' in output_text:
                return {
                    'vuln_type': 'web_vulnerability',
                    'severity': 'medium',
                    'title': 'WordPress Installation Detected',
                    'description': 'WordPress installation found - may have known vulnerabilities',
                    'affected_url': target,
                    'remediation': 'Keep WordPress and plugins updated to latest versions',
                    'evidence': json.dumps({
                        'module': module_name,
                        'detection_method': 'auxiliary_scanner',
                        'output_snippet': output_text[:500] if output_text else 'WordPress detected'
                    })
                }
        
        elif 'ssl' in module_name:
            if any(indicator in output_text for indicator in ['weak', 'deprecated', 'vulnerable', 'ssl']):
                return {
                    'vuln_type': 'ssl_tls',
                    'severity': 'medium',
                    'title': 'SSL/TLS Configuration Issue',
                    'description': f'SSL/TLS scanner detected potential configuration issues',
                    'affected_url': target,
                    'remediation': 'Review SSL/TLS configuration and disable weak ciphers',
                    'evidence': json.dumps({
                        'module': module_name,
                        'detection_method': 'auxiliary_scanner',
                        'output_snippet': output_text[:500] if output_text else 'SSL issues detected'
                    })
                }
        
        elif any(db in module_name for db in ['mysql', 'mssql', 'postgres', 'oracle']):
            if any(indicator in output_text for indicator in ['version', 'database', 'connection', 'accessible']):
                return {
                    'vuln_type': 'database_exposure',
                    'severity': 'high',
                    'title': 'Database Service Exposed',
                    'description': f'Database service detected and potentially accessible',
                    'affected_url': target,
                    'remediation': 'Restrict database access to authorized networks only',
                    'evidence': json.dumps({
                        'module': module_name,
                        'detection_method': 'auxiliary_scanner',
                        'output_snippet': output_text[:500] if output_text else 'Database service found'
                    })
                }
        
        # Generic service detection
        elif 'version' in module_name or 'scanner' in module_name:
            if output_text and len(output_text) > 10:  # Has meaningful output
                return {
                    'vuln_type': 'information_disclosure',
                    'severity': 'low',
                    'title': f'Service Information Disclosure',
                    'description': f'Service enumeration revealed system information',
                    'affected_url': target,
                    'remediation': 'Review service configurations to minimize information disclosure',
                    'evidence': json.dumps({
                        'module': module_name,
                        'detection_method': 'auxiliary_scanner',
                        'output_snippet': output_text[:500]
                    })
                }
        
        return None
    
    async def run_metasploit_scan(self, scan_id: int, target: str, scan_config: Dict = None) -> Dict:
        """
        Run Metasploit auxiliary scan and save results to database
        
        Args:
            scan_id: Database scan ID
            target: Target to scan
            scan_config: Optional scan configuration
        
        Returns:
            Dict containing scan results and metadata
        """
        tool_result = None
        
        try:
            # Default scan configuration
            config = {
                'target_type': 'web',  # web, network, database, verification
                'vulnerability_hints': [],  # e.g., ['sql_injection', 'wordpress']
                'max_modules': 5,
                'timeout_per_module': 60
            }
            if scan_config:
                config.update(scan_config)
            
            validated_target = self.validate_target(target)
            logger.info(f"Starting Metasploit scan for {validated_target}")
            
            # Create ToolResult entry
            tool_result = ToolResult(
                scan_id=scan_id,
                tool_name='metasploit',
                status='running',
                started_at=datetime.now(timezone.utc)
            )
            db.session.add(tool_result)
            db.session.commit()
            
            # Start MSF RPC server
            if not self.start_msf_rpc():
                raise MetasploitScannerError("Failed to start MSF RPC server")
            
            # Get safe modules for target
            modules = self.get_safe_modules_for_target(
                config['target_type'],
                config.get('vulnerability_hints')
            )[:config['max_modules']]  # Limit number of modules
            
            # Run modules
            module_results = []
            for module_name in modules:
                # Prepare module options
                options = {}
                if config['target_type'] == 'web':
                    if target.startswith(('http://', 'https://')):
                        parsed = urlparse(target)
                        options.update({
                            'RHOSTS': parsed.hostname,
                            'RPORT': parsed.port or (443 if parsed.scheme == 'https' else 80),
                            'TARGETURI': parsed.path or '/',
                            'SSL': 'true' if parsed.scheme == 'https' else 'false'
                        })
                    else:
                        options.update({
                            'RHOSTS': validated_target,
                            'RPORT': '80'
                        })
                else:
                    options.update({
                        'RHOSTS': validated_target
                    })
                
                # Run module in thread pool
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.executor,
                    self.run_auxiliary_module,
                    module_name,
                    options
                )
                
                module_results.append(result)
                
                # Small delay between modules
                await asyncio.sleep(1)
            
            # Parse results into vulnerabilities
            vulnerabilities = self.parse_module_results(module_results)
            
            # Save vulnerabilities to database
            for vuln_data in vulnerabilities:
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    tool_result_id=tool_result.id,
                    **vuln_data
                )
                db.session.add(vulnerability)
            
            # Update tool result with success
            tool_result.status = 'completed'
            tool_result.completed_at = datetime.now(timezone.utc)
            tool_result.raw_output = json.dumps({
                'modules_run': [r['module'] for r in module_results],
                'module_results': module_results,
                'vulnerabilities_found': len(vulnerabilities),
                'config_used': config
            }, default=str)
            
            db.session.commit()
            
            result = {
                'status': 'completed',
                'target': validated_target,
                'modules_executed': len(module_results),
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities': vulnerabilities,
                'scan_config': config
            }
            
            logger.info(f"Metasploit scan completed for {validated_target}. "
                       f"Ran {len(module_results)} modules, found {len(vulnerabilities)} issues.")
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Metasploit scan failed for {target}: {error_msg}")
            
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
        
        finally:
            # Always try to clean up MSF RPC connection
            try:
                if self.client:
                    # Clear any running jobs
                    jobs = self.client.jobs.list
                    for job_id in jobs.keys():
                        try:
                            self.client.jobs.stop(job_id)
                        except:
                            pass
            except:
                pass
    
    def get_scan_configurations(self) -> Dict[str, Dict]:
        """
        Get predefined scan configurations for different scenarios
        """
        return {
            'web_basic': {
                'name': 'Basic Web Application Scan',
                'target_type': 'web',
                'vulnerability_hints': [],
                'max_modules': 5,
                'description': 'Basic web application security verification',
                'estimated_time': '5-10 minutes'
            },
            'web_sqli_check': {
                'name': 'SQL Injection Verification',
                'target_type': 'verification',
                'vulnerability_hints': ['sqli', 'sql_injection'],
                'max_modules': 3,
                'description': 'Focused SQL injection vulnerability verification',
                'estimated_time': '2-5 minutes'
            },
            'network_discovery': {
                'name': 'Network Service Discovery',
                'target_type': 'network',
                'vulnerability_hints': [],
                'max_modules': 8,
                'description': 'Network service enumeration and version detection',
                'estimated_time': '5-15 minutes'
            },
            'database_check': {
                'name': 'Database Service Check',
                'target_type': 'database',
                'vulnerability_hints': [],
                'max_modules': 4,
                'description': 'Database service detection and accessibility check',
                'estimated_time': '3-8 minutes'
            },
            'wordpress_audit': {
                'name': 'WordPress Security Audit',
                'target_type': 'web',
                'vulnerability_hints': ['wordpress'],
                'max_modules': 3,
                'description': 'WordPress-specific security verification',
                'estimated_time': '3-7 minutes'
            }
        }
    
    def get_available_modules(self, category: str = None) -> Dict[str, List[str]]:
        """
        Get list of available safe modules by category
        """
        if category:
            return {category: self.safe_modules.get(category, [])}
        return self.safe_modules.copy()


# Convenience functions for easy integration
async def run_metasploit(scan_id: int, target: str, scan_config: str = 'web_basic') -> Dict:
    """
    Convenience function to run Metasploit scan
    
    Args:
        scan_id: Database scan ID
        target: Target to scan
        scan_config: Scan configuration preset name
    
    Returns:
        Dict with scan results
    """
    scanner = MetasploitScanner()
    
    try:
        configurations = scanner.get_scan_configurations()
        
        if scan_config not in configurations:
            logger.warning(f"Unknown scan config '{scan_config}', using 'web_basic'")
            scan_config = 'web_basic'
        
        config = configurations[scan_config]
        return await scanner.run_metasploit_scan(scan_id, target, config)
        
    finally:
        # Always try to clean up
        scanner.stop_msf_rpc()


def validate_exploit_target(target: str) -> bool:
    """
    Validate if target is safe and legal for exploit testing
    
    Args:
        target: Target to validate
    
    Returns:
        True if target appears safe for testing
    """
    try:
        scanner = MetasploitScanner()
        validated_target = scanner.validate_target(target)
        
        # Additional safety checks
        import ipaddress
        try:
            ip = ipaddress.ip_address(validated_target)
            # Only allow private networks and loopback
            if not (ip.is_private or ip.is_loopback):
                logger.warning(f"Target {target} is not in a private network. "
                             "Ensure you have explicit permission to test this target.")
                return False
            return True
        except ValueError:
            # Not an IP, might be hostname - allow for testing
            # In production, you might want stricter validation
            logger.info(f"Hostname target {validated_target} - ensure you have permission to test")
            return True
            
    except Exception as e:
        logger.error(f"Target validation failed: {str(e)}")
        return False


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_metasploit():
        """Test the Metasploit scanner"""
        try:
            scanner = MetasploitScanner()
            
            # Test configurations
            configs = scanner.get_scan_configurations()
            print(f"Available scan configurations: {list(configs.keys())}")
            
            # Test module listing
            modules = scanner.get_available_modules('web')
            print(f"Web modules: {modules}")
            
            # Test target validation
            if validate_exploit_target('127.0.0.1'):
                print("Target validation passed for localhost")
            
            print("Metasploit scanner test completed successfully")
            print("Note: This requires Metasploit Framework to be installed")
            
        except Exception as e:
            print(f"Metasploit test failed: {str(e)}")
    
    # Run test if this script is executed directly
    asyncio.run(test_metasploit())