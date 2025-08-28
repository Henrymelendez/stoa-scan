# app/scans/forms.py
from flask_wtf import FlaskForm
from wtforms import (
    StringField, SelectField, TextAreaField, SubmitField, 
    BooleanField, ValidationError
)
from wtforms.validators import DataRequired, Length, URL, Optional
from urllib.parse import urlparse
import re
from app import db
import sqlalchemy as sa
from app.models import Scan


class NewScanForm(FlaskForm):
    """Form for creating new security scans"""
    
    target_url = StringField(
        'Target URL or IP Address', 
        validators=[DataRequired(), Length(min=3, max=500)],
        render_kw={'placeholder': 'https://example.com or 192.168.1.1'}
    )
    
    scan_name = StringField(
        'Scan Name (Optional)',
        validators=[Optional(), Length(max=200)],
        render_kw={'placeholder': 'My security scan'}
    )
    
    scan_type = SelectField(
        'Scan Type',
        choices=[
            ('web', 'Web Application Scan'),
            ('network', 'Network/Infrastructure Scan'),
            ('exploit', 'Exploit Verification Scan'),
            ('comprehensive', 'Comprehensive Multi-Tool Scan')
        ],
        default='web'
    )
    
    scan_preset = SelectField(
        'Scan Intensity',
        choices=[
            ('quick', 'Quick Scan (2-5 minutes)'),
            ('standard', 'Standard Scan (10-20 minutes)'),
            ('thorough', 'Thorough Scan (30+ minutes)')
        ],
        default='standard'
    )
    
    # Tool selection for comprehensive scans
    enable_nmap = BooleanField('Enable Network Scanning (Nmap)', default=True)
    enable_zap = BooleanField('Enable Web Vulnerability Scanning (ZAP)', default=True)
    enable_metasploit = BooleanField('Enable Exploit Verification (Metasploit)', default=False)
    
    submit = SubmitField('Start Scan')
    
    def validate_target_url(self, target_url):
        """Validate target URL or IP address"""
        target = target_url.data.strip()
        
        # Check for obviously malicious targets
        dangerous_patterns = [
            r'[;&|`]',  # Command injection chars
            r'\.\./',   # Path traversal
            r'<script', # XSS attempt
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                raise ValidationError('Target contains potentially dangerous characters.')
        
        # Basic format validation
        if target.startswith(('http://', 'https://')):
            # URL validation
            try:
                parsed = urlparse(target)
                if not parsed.netloc:
                    raise ValidationError('Invalid URL format.')
                
                # Check for suspicious ports
                if parsed.port and parsed.port < 80 and parsed.port != 21:
                    raise ValidationError('Scanning system ports is not allowed.')
                    
            except Exception:
                raise ValidationError('Invalid URL format.')
        else:
            # IP/hostname validation
            import socket
            import ipaddress
            
            try:
                # Try as IP address first
                ip = ipaddress.ip_address(target)
                # Only allow private IPs and localhost for safety
                if not (ip.is_private or ip.is_loopback):
                    raise ValidationError('Only private IP addresses and localhost are allowed for security scanning.')
            except ipaddress.AddressValueError:
                # Not an IP, try as hostname
                if not target.replace('.', '').replace('-', '').isalnum():
                    raise ValidationError('Invalid hostname format.')
                
                # Check if hostname resolves (basic validation)
                try:
                    socket.gethostbyname(target)
                except socket.gaierror:
                    raise ValidationError('Hostname does not resolve.')
    
    def validate_scan_type(self, scan_type):
        """Validate scan type selection"""
        valid_types = ['web', 'network', 'exploit', 'comprehensive']
        if scan_type.data not in valid_types:
            raise ValidationError('Invalid scan type selected.')
    
    def validate(self, extra_validators=None):
        """Custom validation logic"""
        rv = FlaskForm.validate(self, extra_validators)
        if not rv:
            return False
        
        # Cross-field validation
        scan_type = self.scan_type.data
        target = self.target_url.data
        
        # Web scans should have HTTP(S) URLs
        if scan_type == 'web' and not target.startswith(('http://', 'https://')):
            self.target_url.errors.append('Web application scans require HTTP or HTTPS URLs.')
            return False
        
        # Network scans should NOT have HTTP(S) URLs (prefer IP/hostname)
        if scan_type == 'network' and target.startswith(('http://', 'https://')):
            self.scan_type.errors.append('Network scans work better with IP addresses or hostnames.')
        
        # Exploit scans require explicit acknowledgment
        if scan_type == 'exploit' and self.enable_metasploit.data:
            # This would be handled by a consent form in a real application
            pass
        
        return True


class ScanConfigForm(FlaskForm):
    """Advanced scan configuration form"""
    
    # Nmap configuration
    nmap_enabled = BooleanField('Enable Nmap Scanning', default=True)
    nmap_preset = SelectField(
        'Nmap Scan Type',
        choices=[
            ('quick', 'Quick Port Scan'),
            ('comprehensive', 'Comprehensive Port Scan'),
            ('stealth', 'Stealth Scan'),
            ('service_detection', 'Service Version Detection'),
            ('vulnerability_scan', 'Vulnerability Scripts')
        ],
        default='quick'
    )
    nmap_custom_args = StringField(
        'Custom Nmap Arguments (Advanced)',
        validators=[Optional(), Length(max=200)],
        render_kw={'placeholder': '-T4 -A -p 1-1000'}
    )
    
    # ZAP configuration
    zap_enabled = BooleanField('Enable ZAP Web Scanning', default=True)
    zap_preset = SelectField(
        'ZAP Scan Policy',
        choices=[
            ('basic', 'Basic Web Scan'),
            ('comprehensive', 'Comprehensive Web Scan'),
            ('spider_only', 'URL Discovery Only'),
            ('active_only', 'Vulnerability Testing Only'),
            ('quick', 'Quick Web Scan')
        ],
        default='basic'
    )
    zap_spider_depth = SelectField(
        'Spider Crawl Depth',
        choices=[
            ('2', 'Shallow (2 levels)'),
            ('5', 'Standard (5 levels)'),
            ('10', 'Deep (10 levels)'),
            ('0', 'Single Page Only')
        ],
        default='5'
    )
    
    # Metasploit configuration
    metasploit_enabled = BooleanField('Enable Metasploit Verification', default=False)
    metasploit_preset = SelectField(
        'Metasploit Configuration',
        choices=[
            ('web_basic', 'Basic Web Application Tests'),
            ('web_sqli_check', 'SQL Injection Verification'),
            ('network_discovery', 'Network Service Discovery'),
            ('database_check', 'Database Service Check'),
            ('wordpress_audit', 'WordPress Security Audit')
        ],
        default='web_basic'
    )
    metasploit_safe_mode = BooleanField(
        'Safe Mode (Auxiliary modules only)', 
        default=True,
        description='Only run safe reconnaissance modules'
    )
    
    # General configuration
    scan_timeout = SelectField(
        'Maximum Scan Duration',
        choices=[
            ('15', '15 minutes'),
            ('30', '30 minutes'),
            ('60', '1 hour'),
            ('120', '2 hours')
        ],
        default='30'
    )
    
    concurrent_tools = BooleanField(
        'Run Tools Concurrently', 
        default=True,
        description='Run multiple tools simultaneously for faster results'
    )
    
    generate_report = BooleanField('Auto-generate PDF Report', default=True)
    
    submit = SubmitField('Configure and Start Scan')
    
    def validate_nmap_custom_args(self, nmap_custom_args):
        """Validate custom Nmap arguments for security"""
        if not nmap_custom_args.data:
            return
        
        args = nmap_custom_args.data.strip()
        
        # Check for dangerous arguments
        dangerous_args = [
            '--script', '|', ';', '&', '`', '$(', 
            '--resume', '--datadir', '--servicedb'
        ]
        
        for dangerous in dangerous_args:
            if dangerous in args:
                raise ValidationError(f'Argument "{dangerous}" is not allowed for security reasons.')
        
        # Check argument length
        if len(args) > 200:
            raise ValidationError('Custom arguments are too long.')
    
    def validate_metasploit_enabled(self, metasploit_enabled):
        """Validate Metasploit usage"""
        if metasploit_enabled.data and not self.metasploit_safe_mode.data:
            raise ValidationError('Unsafe Metasploit mode requires explicit administrator approval.')


class ConsentForm(FlaskForm):
    """Legal consent form for security scanning"""
    
    target_url = StringField('Target URL', render_kw={'readonly': True})
    
    consent_text = TextAreaField(
        'Consent Agreement',
        render_kw={'readonly': True, 'rows': 10},
        default="""I hereby acknowledge and agree to the following terms for security scanning:

1. I own or have explicit written authorization to conduct security testing on the specified target.

2. I understand that security scanning may temporarily impact system performance.

3. I will only use scan results for legitimate security assessment purposes.

4. I will not use any discovered vulnerabilities for malicious purposes.

5. I understand that I am solely responsible for compliance with all applicable laws and regulations.

6. I agree to indemnify PentestSaaS against any claims arising from unauthorized scanning.

By proceeding, I confirm that I have read, understood, and agree to these terms."""
    )
    
    i_agree = BooleanField(
        'I agree to the above terms and confirm I have authorization to scan this target',
        validators=[DataRequired()]
    )
    
    acknowledge_legal = BooleanField(
        'I acknowledge that unauthorized security scanning may violate laws',
        validators=[DataRequired()]
    )
    
    submit = SubmitField('Provide Consent and Proceed')
    
    def validate_i_agree(self, i_agree):
        """Ensure user provides consent"""
        if not i_agree.data:
            raise ValidationError('You must agree to the terms to proceed with scanning.')
    
    def validate_acknowledge_legal(self, acknowledge_legal):
        """Ensure user acknowledges legal responsibilities"""
        if not acknowledge_legal.data:
            raise ValidationError('You must acknowledge the legal requirements.')


class ScanFilterForm(FlaskForm):
    """Form for filtering scan results"""
    
    status = SelectField(
        'Status',
        choices=[
            ('', 'All Statuses'),
            ('queued', 'Queued'),
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
            ('cancelled', 'Cancelled')
        ],
        default=''
    )
    
    scan_type = SelectField(
        'Scan Type',
        choices=[
            ('', 'All Types'),
            ('web', 'Web Application'),
            ('network', 'Network/Infrastructure'),
            ('exploit', 'Exploit Verification'),
            ('comprehensive', 'Comprehensive')
        ],
        default=''
    )
    
    severity = SelectField(
        'Minimum Severity',
        choices=[
            ('', 'All Severities'),
            ('info', 'Info and above'),
            ('low', 'Low and above'),
            ('medium', 'Medium and above'),
            ('high', 'High and above'),
            ('critical', 'Critical only')
        ],
        default=''
    )
    
    date_range = SelectField(
        'Date Range',
        choices=[
            ('', 'All Time'),
            ('today', 'Today'),
            ('week', 'This Week'),
            ('month', 'This Month'),
            ('quarter', 'This Quarter')
        ],
        default=''
    )
    
    submit = SubmitField('Apply Filters')


class VulnerabilityFilterForm(FlaskForm):
    """Form for filtering vulnerability results"""
    
    vuln_type = SelectField(
        'Vulnerability Type',
        choices=[
            ('', 'All Types'),
            ('sql_injection', 'SQL Injection'),
            ('xss', 'Cross-Site Scripting'),
            ('csrf', 'Cross-Site Request Forgery'),
            ('open_port', 'Open Ports'),
            ('ssl_tls', 'SSL/TLS Issues'),
            ('authentication', 'Authentication Issues'),
            ('authorization', 'Authorization Issues'),
            ('injection', 'Code Injection'),
            ('path_traversal', 'Path Traversal'),
            ('information_disclosure', 'Information Disclosure'),
            ('web_vulnerability', 'Web Vulnerabilities'),
            ('database_exposure', 'Database Exposure'),
            ('exploit_success', 'Successful Exploits')
        ],
        default=''
    )
    
    severity = SelectField(
        'Severity Level',
        choices=[
            ('', 'All Severities'),
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
            ('info', 'Informational')
        ],
        default=''
    )
    
    false_positives = SelectField(
        'False Positives',
        choices=[
            ('all', 'Show All'),
            ('exclude', 'Hide False Positives'),
            ('only', 'Show Only False Positives')
        ],
        default='exclude'
    )
    
    has_cve = BooleanField('Has CVE ID')
    
    submit = SubmitField('Filter Results')


class BulkScanForm(FlaskForm):
    """Form for creating multiple scans from a list of targets"""
    
    targets_list = TextAreaField(
        'Target URLs/IPs (one per line)',
        validators=[DataRequired()],
        render_kw={
            'placeholder': 'https://example1.com\nhttps://example2.com\n192.168.1.100',
            'rows': 10
        }
    )
    
    scan_type = SelectField(
        'Scan Type for All Targets',
        choices=[
            ('web', 'Web Application Scan'),
            ('network', 'Network Scan'),
            ('comprehensive', 'Comprehensive Scan')
        ],
        default='web'
    )
    
    scan_preset = SelectField(
        'Scan Intensity',
        choices=[
            ('quick', 'Quick Scan'),
            ('standard', 'Standard Scan'),
            ('thorough', 'Thorough Scan')
        ],
        default='quick'
    )
    
    name_prefix = StringField(
        'Scan Name Prefix',
        validators=[Optional(), Length(max=100)],
        render_kw={'placeholder': 'Bulk scan'}
    )
    
    submit = SubmitField('Create Bulk Scans')
    
    def validate_targets_list(self, targets_list):
        """Validate target list"""
        targets = [t.strip() for t in targets_list.data.split('\n') if t.strip()]
        
        if not targets:
            raise ValidationError('At least one target is required.')
        
        if len(targets) > 50:  # Reasonable limit
            raise ValidationError('Maximum 50 targets allowed in bulk scan.')
        
        # Validate each target
        invalid_targets = []
        for target in targets:
            if not self._validate_single_target(target):
                invalid_targets.append(target)
        
        if invalid_targets:
            raise ValidationError(f'Invalid targets: {", ".join(invalid_targets[:5])}')
    
    def _validate_single_target(self, target):
        """Validate a single target URL/IP"""
        try:
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                return bool(parsed.netloc)
            else:
                import ipaddress
                import socket
                try:
                    # Try as IP
                    ip = ipaddress.ip_address(target)
                    return ip.is_private or ip.is_loopback
                except ipaddress.AddressValueError:
                    # Try as hostname
                    socket.gethostbyname(target)
                    return True
        except:
            return False


class ScheduledScanForm(FlaskForm):
    """Form for scheduling recurring scans"""
    
    target_url = StringField(
        'Target URL',
        validators=[DataRequired(), Length(max=500)],
        render_kw={'placeholder': 'https://example.com'}
    )
    
    scan_name = StringField(
        'Schedule Name',
        validators=[DataRequired(), Length(max=200)],
        render_kw={'placeholder': 'Weekly security scan'}
    )
    
    scan_type = SelectField(
        'Scan Type',
        choices=[
            ('web', 'Web Application'),
            ('network', 'Network'),
            ('comprehensive', 'Comprehensive')
        ],
        default='web'
    )
    
    frequency = SelectField(
        'Frequency',
        choices=[
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
            ('biweekly', 'Bi-weekly'),
            ('monthly', 'Monthly')
        ],
        default='weekly'
    )
    
    time_of_day = SelectField(
        'Time of Day',
        choices=[
            ('00:00', '12:00 AM'),
            ('02:00', '2:00 AM'),
            ('04:00', '4:00 AM'),
            ('06:00', '6:00 AM'),
            ('08:00', '8:00 AM'),
            ('12:00', '12:00 PM'),
            ('18:00', '6:00 PM'),
            ('22:00', '10:00 PM')
        ],
        default='02:00'
    )
    
    enabled = BooleanField('Schedule Enabled', default=True)
    
    notify_on_completion = BooleanField('Email Notifications', default=True)
    notify_on_high_severity = BooleanField('Alert on High Severity Findings', default=True)
    
    submit = SubmitField('Create Schedule')


class ExportScanForm(FlaskForm):
    """Form for exporting scan results"""
    
    export_format = SelectField(
        'Export Format',
        choices=[
            ('pdf', 'PDF Report'),
            ('html', 'HTML Report'),
            ('json', 'JSON Data'),
            ('csv', 'CSV (Vulnerabilities Only)'),
            ('xml', 'XML Report')
        ],
        default='pdf'
    )
    
    include_false_positives = BooleanField('Include False Positives', default=False)
    include_tool_output = BooleanField('Include Raw Tool Output', default=False)
    include_remediation = BooleanField('Include Remediation Advice', default=True)
    
    severity_filter = SelectField(
        'Minimum Severity',
        choices=[
            ('all', 'All Severities'),
            ('info', 'Info and above'),
            ('low', 'Low and above'),
            ('medium', 'Medium and above'),
            ('high', 'High and above'),
            ('critical', 'Critical only')
        ],
        default='all'
    )
    
    submit = SubmitField('Generate Export')


class ApiKeyForm(FlaskForm):
    """Form for creating API keys"""
    
    key_name = StringField(
        'API Key Name',
        validators=[DataRequired(), Length(min=3, max=100)],
        render_kw={'placeholder': 'Production API Key'}
    )
    
    rate_limit = SelectField(
        'Rate Limit (requests per hour)',
        choices=[
            ('50', '50 requests/hour'),
            ('100', '100 requests/hour'),
            ('500', '500 requests/hour'),
            ('1000', '1000 requests/hour'),
            ('5000', '5000 requests/hour (Enterprise)')
        ],
        default='100'
    )
    
    expires_in = SelectField(
        'Expires In',
        choices=[
            ('30', '30 days'),
            ('90', '90 days'),
            ('365', '1 year'),
            ('0', 'Never expires')
        ],
        default='90'
    )
    
    permissions = SelectField(
        'Permissions',
        choices=[
            ('read', 'Read Only'),
            ('scan', 'Read + Create Scans'),
            ('full', 'Full Access')
        ],
        default='scan'
    )
    
    submit = SubmitField('Create API Key')
    
    def validate_key_name(self, key_name):
        """Validate API key name uniqueness for user"""
        from flask_login import current_user
        from app.models import ApiKey
        
        existing = db.session.scalar(
            sa.select(ApiKey).where(
                ApiKey.user_id == current_user.id,
                ApiKey.key_name == key_name.data
            )
        )
        
        if existing:
            raise ValidationError('You already have an API key with this name.')


class ScanComparisonForm(FlaskForm):
    """Form for comparing multiple scans"""
    
    primary_scan_id = SelectField(
        'Primary Scan',
        coerce=int,
        validators=[DataRequired()]
    )
    
    comparison_scan_ids = SelectField(
        'Compare With',
        coerce=int,
        validators=[DataRequired()]
    )
    
    comparison_type = SelectField(
        'Comparison Type',
        choices=[
            ('vulnerabilities', 'Vulnerability Differences'),
            ('timeline', 'Timeline Comparison'),
            ('severity_trends', 'Severity Trends'),
            ('tool_performance', 'Tool Performance')
        ],
        default='vulnerabilities'
    )
    
    submit = SubmitField('Generate Comparison')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Populate scan choices with user's completed scans
        self._populate_scan_choices()
    
    def _populate_scan_choices(self):
        """Populate scan selection with user's scans"""
        from flask_login import current_user
        
        completed_scans = list(db.session.scalars(
            sa.select(Scan)
            .where(Scan.user_id == current_user.id)
            .where(Scan.status == 'completed')
            .order_by(Scan.completed_at.desc())
            .limit(50)
        ))
        
        choices = [
            (scan.id, f"{scan.scan_name} - {scan.target_url} ({scan.completed_at.strftime('%Y-%m-%d')})")
            for scan in completed_scans
        ]
        
        self.primary_scan_id.choices = choices
        self.comparison_scan_ids.choices = choices


# Utility functions for form validation
def validate_target_ownership(target_url):
    """
    Validate that user owns or has permission to scan target
    In production, this might check DNS TXT records, domain ownership, etc.
    """
    # Basic checks for obviously external domains
    parsed = urlparse(target_url) if target_url.startswith(('http://', 'https://')) else None
    
    if parsed and parsed.hostname:
        # Check if it's a localhost/private target (safer)
        import ipaddress
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            return ip.is_private or ip.is_loopback
        except ipaddress.AddressValueError:
            # It's a hostname - in production you'd want stricter validation
            if parsed.hostname in ['localhost', '127.0.0.1']:
                return True
            
            # For external domains, you might require:
            # - DNS TXT record verification
            # - Domain ownership proof
            # - Explicit whitelist approval
            return False  # Conservative default
    
    return True  # Allow IP addresses (with other validation)


def get_scan_recommendations(target_url, scan_type):
    """
    Get recommended scan configuration based on target and type
    """
    recommendations = {
        'tools': [],
        'presets': {},
        'estimated_time': '5-10 minutes',
        'warnings': []
    }
    
    # Analyze target
    is_web_target = target_url.startswith(('http://', 'https://'))
    is_https = target_url.startswith('https://')
    
    # Tool recommendations
    if scan_type in ['web', 'comprehensive']:
        if is_web_target:
            recommendations['tools'].extend(['nmap', 'zap'])
            recommendations['presets']['nmap'] = 'service_detection'
            recommendations['presets']['zap'] = 'basic'
        else:
            recommendations['warnings'].append('Web scan selected but target is not a URL')
    
    if scan_type in ['network', 'comprehensive']:
        recommendations['tools'].append('nmap')
        recommendations['presets']['nmap'] = 'comprehensive'
        recommendations['estimated_time'] = '15-30 minutes'
    
    if scan_type == 'exploit':
        recommendations['tools'].append('metasploit')
        recommendations['presets']['metasploit'] = 'web_basic'
        recommendations['warnings'].append('Exploit scans require explicit target authorization')
    
    # Security warnings
    if not is_https and is_web_target:
        recommendations['warnings'].append('Target uses HTTP - consider HTTPS security implications')
    
    return recommendations