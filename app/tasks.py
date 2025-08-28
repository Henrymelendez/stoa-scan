# app/tasks.py
import os
import json
import asyncio
import logging
from datetime import datetime, timezone
from celery import Celery, Task
from flask import Flask
from app import db
from app.models import Scan

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlaskTask(Task):
    """Custom Celery task that maintains Flask app context"""
    def __call__(self, *args, **kwargs):
        with self.app.app_context():
            return self.run(*args, **kwargs)


def make_celery(app):
    """Factory function to create Celery instance with Flask integration"""
    celery = Celery(
        app.import_name,
        backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
        broker=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
        task_cls=FlaskTask
    )
    
    # Update configuration
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 minute timeout
        task_soft_time_limit=25 * 60,  # 25 minute soft limit
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=50
    )
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    celery.app = app
    return celery


# Initialize Celery (will be properly configured in app factory)
celery = Celery('pentest_saas')


@celery.task(bind=True, name='execute_scan')
def execute_scan(self, scan_id):
    """
    Main task for executing security scans
    
    Args:
        scan_id: Database ID of the scan to execute
    
    Returns:
        Dict with scan results and statistics
    """
    from app import db
    from app.models import Scan, Vulnerability
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        logger.error(f"Scan {scan_id} not found")
        return {'error': 'Scan not found'}
    
    try:
        # Update scan status
        scan.status = 'running'
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()
        
        logger.info(f"Starting scan {scan_id}: {scan.scan_name}")
        
        # Parse scan configuration
        config = json.loads(scan.scan_config) if scan.scan_config else {}
        
        # Execute scan based on type
        results = {}
        
        if scan.scan_type == 'comprehensive':
            results = _execute_comprehensive_scan(scan_id, scan.target_url, config)
        elif scan.scan_type == 'network':
            results = _execute_network_scan(scan_id, scan.target_url, config)
        elif scan.scan_type == 'web':
            results = _execute_web_scan(scan_id, scan.target_url, config)
        elif scan.scan_type == 'exploit':
            results = _execute_exploit_scan(scan_id, scan.target_url, config)
        else:
            raise ValueError(f"Unknown scan type: {scan.scan_type}")
        
        # Update scan completion
        scan.status = 'completed'
        scan.completed_at = datetime.now(timezone.utc)
        
        # Update vulnerability counts
        _update_scan_statistics(scan_id)
        
        db.session.commit()
        
        logger.info(f"Scan {scan_id} completed successfully. Found {results.get('total_vulnerabilities', 0)} vulnerabilities")
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'results': results
        }
        
    except Exception as e:
        # Mark scan as failed
        scan.status = 'failed'
        scan.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        
        error_msg = str(e)
        logger.error(f"Scan {scan_id} failed: {error_msg}")
        
        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': error_msg
        }


def _execute_comprehensive_scan(scan_id, target_url, config):
    """Execute comprehensive scan using multiple tools"""
    from app.scanners.nmap_scanner import run_nmap
    from app.scanners.zap_scanner import run_zap, validate_web_target
    from app.scanners.metasploit_scanner import run_metasploit, validate_exploit_target
    
    results = {
        'tools_run': [],
        'total_vulnerabilities': 0,
        'errors': []
    }
    
    # Create new event loop for async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Run Nmap (network discovery)
        if config.get('enable_nmap', True):
            try:
                logger.info(f"Running Nmap scan for {target_url}")
                nmap_result = loop.run_until_complete(
                    run_nmap(scan_id, target_url, config.get('scan_preset', 'quick'))
                )
                
                if nmap_result['status'] == 'completed':
                    results['tools_run'].append('nmap')
                    results['total_vulnerabilities'] += nmap_result['vulnerabilities_found']
                    results['nmap'] = nmap_result
                else:
                    results['errors'].append(f"Nmap: {nmap_result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                results['errors'].append(f"Nmap scan failed: {str(e)}")
        
        # Run ZAP (web application testing)
        if config.get('enable_zap', True) and validate_web_target(target_url):
            try:
                logger.info(f"Running ZAP scan for {target_url}")
                zap_preset = 'quick' if config.get('scan_preset') == 'quick' else 'basic'
                zap_result = loop.run_until_complete(
                    run_zap(scan_id, target_url, zap_preset)
                )
                
                if zap_result['status'] == 'completed':
                    results['tools_run'].append('zap')
                    results['total_vulnerabilities'] += zap_result['vulnerabilities_found']
                    results['zap'] = zap_result
                else:
                    results['errors'].append(f"ZAP: {zap_result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                results['errors'].append(f"ZAP scan failed: {str(e)}")
        
        # Run Metasploit (exploit verification) if enabled and safe
        if config.get('enable_metasploit', False) and validate_exploit_target(target_url):
            try:
                logger.info(f"Running Metasploit verification for {target_url}")
                msf_preset = 'web_basic' if target_url.startswith(('http://', 'https://')) else 'network_discovery'
                msf_result = loop.run_until_complete(
                    run_metasploit(scan_id, target_url, msf_preset)
                )
                
                if msf_result['status'] == 'completed':
                    results['tools_run'].append('metasploit')
                    results['total_vulnerabilities'] += msf_result['vulnerabilities_found']
                    results['metasploit'] = msf_result
                else:
                    results['errors'].append(f"Metasploit: {msf_result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                results['errors'].append(f"Metasploit scan failed: {str(e)}")
        
    finally:
        loop.close()
    
    return results


def _execute_network_scan(scan_id, target_url, config):
    """Execute network-focused scan using Nmap"""
    from app.scanners.nmap_scanner import run_nmap
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        preset = config.get('scan_preset', 'comprehensive')
        result = loop.run_until_complete(run_nmap(scan_id, target_url, preset))
        
        return {
            'tools_run': ['nmap'],
            'total_vulnerabilities': result.get('vulnerabilities_found', 0),
            'nmap': result
        }
    finally:
        loop.close()


def _execute_web_scan(scan_id, target_url, config):
    """Execute web application scan using ZAP"""
    from app.scanners.zap_scanner import run_zap
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        preset = config.get('scan_preset', 'basic')
        result = loop.run_until_complete(run_zap(scan_id, target_url, preset))
        
        return {
            'tools_run': ['zap'],
            'total_vulnerabilities': result.get('vulnerabilities_found', 0),
            'zap': result
        }
    finally:
        loop.close()


def _execute_exploit_scan(scan_id, target_url, config):
    """Execute exploit verification scan using Metasploit"""
    from app.scanners.metasploit_scanner import run_metasploit
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        preset = config.get('scan_preset', 'web_basic')
        result = loop.run_until_complete(run_metasploit(scan_id, target_url, preset))
        
        return {
            'tools_run': ['metasploit'],
            'total_vulnerabilities': result.get('vulnerabilities_found', 0),
            'metasploit': result
        }
    finally:
        loop.close()


def _update_scan_statistics(scan_id):
    """Update scan statistics based on found vulnerabilities"""
    from app.models import Scan, Vulnerability
    import sqlalchemy as sa
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return
    
    # Count vulnerabilities by severity
    severity_counts = dict(db.session.execute(
        sa.select(Vulnerability.severity, sa.func.count(Vulnerability.id))
        .where(Vulnerability.scan_id == scan_id)
        .where(Vulnerability.false_positive == False)
        .group_by(Vulnerability.severity)
    ).fetchall())
    
    # Update scan record
    scan.total_vulnerabilities = sum(severity_counts.values())
    scan.high_severity_count = (
        severity_counts.get('critical', 0) + 
        severity_counts.get('high', 0)
    )
    scan.medium_severity_count = severity_counts.get('medium', 0)
    scan.low_severity_count = (
        severity_counts.get('low', 0) + 
        severity_counts.get('info', 0)
    )
    
    db.session.commit()


@celery.task(bind=True, name='generate_report')
def generate_report(self, scan_id, report_type='pdf'):
    """
    Generate scan report in specified format
    
    Args:
        scan_id: Database ID of the scan
        report_type: Type of report (pdf, html, json, csv)
    
    Returns:
        Dict with report generation results
    """
    from app import db
    from app.models import Scan, Report, Vulnerability
    from app.utils.report_generator import ReportGenerator
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        logger.error(f"Scan {scan_id} not found for report generation")
        return {'error': 'Scan not found'}
    
    try:
        logger.info(f"Generating {report_type} report for scan {scan_id}")
        
        # Create report record
        report = Report(
            scan_id=scan_id,
            report_type=report_type,
            generated_at=datetime.now(timezone.utc)
        )
        db.session.add(report)
        db.session.commit()
        
        # Generate report
        generator = ReportGenerator(scan, report_type)
        file_path, file_size = generator.generate()
        
        # Update report record
        report.file_path = file_path
        report.file_size = file_size
        db.session.commit()
        
        logger.info(f"Report generated successfully: {file_path}")
        
        return {
            'report_id': report.id,
            'file_path': file_path,
            'file_size': file_size,
            'status': 'completed'
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Report generation failed for scan {scan_id}: {error_msg}")
        
        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': error_msg
        }


@celery.task(bind=True, name='cleanup_old_scans')
def cleanup_old_scans(self, days_old=30):
    """
    Cleanup old scan data and reports
    
    Args:
        days_old: Delete scans older than this many days
    """
    from app import db
    from app.models import Scan, Report
    import sqlalchemy as sa
    from datetime import timedelta
    import os
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
    
    try:
        logger.info(f"Starting cleanup of scans older than {cutoff_date}")
        
        # Find old scans
        old_scans = list(db.session.scalars(
            sa.select(Scan)
            .where(Scan.created_at < cutoff_date)
            .where(Scan.status.in_(['completed', 'failed', 'cancelled']))
        ))
        
        cleanup_stats = {
            'scans_deleted': 0,
            'reports_deleted': 0,
            'files_deleted': 0,
            'space_freed': 0
        }
        
        for scan in old_scans:
            # Delete associated report files
            reports = list(db.session.scalars(
                sa.select(Report).where(Report.scan_id == scan.id)
            ))
            
            for report in reports:
                if report.file_path and os.path.exists(report.file_path):
                    try:
                        file_size = os.path.getsize(report.file_path)
                        os.remove(report.file_path)
                        cleanup_stats['files_deleted'] += 1
                        cleanup_stats['space_freed'] += file_size
                    except OSError as e:
                        logger.warning(f"Failed to delete report file {report.file_path}: {e}")
            
            # Delete scan (cascades to vulnerabilities, tool results, reports)
            db.session.delete(scan)
            cleanup_stats['scans_deleted'] += 1
            cleanup_stats['reports_deleted'] += len(reports)
        
        db.session.commit()
        
        logger.info(f"Cleanup completed: {cleanup_stats}")
        return cleanup_stats
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        logger.error(f"Cleanup task failed: {error_msg}")
        return {'error': error_msg}


@celery.task(bind=True, name='send_scan_notification')
def send_scan_notification(self, scan_id, notification_type='completion'):
    """
    Send email notifications for scan events
    
    Args:
        scan_id: Database ID of the scan
        notification_type: Type of notification (completion, high_severity, failure)
    """
    from app import db
    from app.models import Scan, User, Vulnerability
    from app.email import send_email
    from flask import render_template, current_app
    import sqlalchemy as sa
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return {'error': 'Scan not found'}
    
    user = db.session.get(User, scan.user_id)
    if not user or not user.email:
        return {'error': 'User or email not found'}
    
    try:
        if notification_type == 'completion':
            subject = f'[PentestSaaS] Scan Completed: {scan.scan_name}'
            
            # Get high severity vulnerabilities
            high_severity_vulns = list(db.session.scalars(
                sa.select(Vulnerability)
                .where(Vulnerability.scan_id == scan_id)
                .where(Vulnerability.severity.in_(['critical', 'high']))
                .limit(5)
            ))
            
            template_data = {
                'user': user,
                'scan': scan,
                'high_severity_vulns': high_severity_vulns,
                'total_vulnerabilities': scan.total_vulnerabilities
            }
            
            send_email(
                subject=subject,
                sender=current_app.config['ADMINS'][0],
                recipients=[user.email],
                text_body=render_template('email/scan_completion.txt', **template_data),
                html_body=render_template('email/scan_completion.html', **template_data)
            )
            
        elif notification_type == 'high_severity':
            critical_vulns = list(db.session.scalars(
                sa.select(Vulnerability)
                .where(Vulnerability.scan_id == scan_id)
                .where(Vulnerability.severity == 'critical')
            ))
            
            if critical_vulns:
                subject = f'[PentestSaaS] CRITICAL Vulnerabilities Found: {scan.scan_name}'
                
                template_data = {
                    'user': user,
                    'scan': scan,
                    'critical_vulns': critical_vulns
                }
                
                send_email(
                    subject=subject,
                    sender=current_app.config['ADMINS'][0],
                    recipients=[user.email],
                    text_body=render_template('email/critical_vulns.txt', **template_data),
                    html_body=render_template('email/critical_vulns.html', **template_data)
                )
        
        elif notification_type == 'failure':
            subject = f'[PentestSaaS] Scan Failed: {scan.scan_name}'
            
            template_data = {
                'user': user,
                'scan': scan
            }
            
            send_email(
                subject=subject,
                sender=current_app.config['ADMINS'][0],
                recipients=[user.email],
                text_body=render_template('email/scan_failure.txt', **template_data),
                html_body=render_template('email/scan_failure.html', **template_data)
            )
        
        return {'status': 'sent', 'notification_type': notification_type}
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Failed to send notification for scan {scan_id}: {error_msg}")
        return {'error': error_msg}


@celery.task(bind=True, name='update_scan_progress')
def update_scan_progress(self, scan_id, tool_name, progress_percentage):
    """
    Update scan progress for real-time UI updates
    
    Args:
        scan_id: Database ID of the scan
        tool_name: Name of the tool reporting progress
        progress_percentage: Current progress (0-100)
    """
    from app import db
    from app.models import ToolResult
    import sqlalchemy as sa
    
    try:
        # Update tool result progress
        tool_result = db.session.scalar(
            sa.select(ToolResult)
            .where(ToolResult.scan_id == scan_id)
            .where(ToolResult.tool_name == tool_name)
            .where(ToolResult.status == 'running')
        )
        
        if tool_result:
            # Store progress in raw_output as JSON
            progress_data = {
                'progress_percentage': progress_percentage,
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            try:
                # Merge with existing data if present
                if tool_result.raw_output:
                    existing_data = json.loads(tool_result.raw_output)
                    existing_data.update(progress_data)
                    tool_result.raw_output = json.dumps(existing_data)
                else:
                    tool_result.raw_output = json.dumps(progress_data)
                    
                db.session.commit()
                
            except json.JSONDecodeError:
                # If existing data isn't valid JSON, replace it
                tool_result.raw_output = json.dumps(progress_data)
                db.session.commit()
        
        return {'status': 'updated', 'progress': progress_percentage}
        
    except Exception as e:
        logger.error(f"Failed to update progress for scan {scan_id}, tool {tool_name}: {str(e)}")
        return {'error': str(e)}


@celery.task(bind=True, name='schedule_periodic_scans')
def schedule_periodic_scans(self):
    """
    Check for and execute scheduled recurring scans
    This task should be run periodically (e.g., every hour)
    """
    from app import db
    from app.models import ScheduledScan, User
    import sqlalchemy as sa
    from datetime import datetime, timezone
    
    try:
        logger.info("Checking for scheduled scans to execute")
        
        # This would require a ScheduledScan model (not in current schema)
        # For now, return placeholder
        
        scheduled_scans = []  # Would query ScheduledScan table
        
        executed_count = 0
        for scheduled_scan in scheduled_scans:
            # Check if it's time to run
            if scheduled_scan.should_run_now():
                # Create new scan from schedule
                new_scan = Scan(
                    user_id=scheduled_scan.user_id,
                    target_url=scheduled_scan.target_url,
                    scan_type=scheduled_scan.scan_type,
                    scan_name=f"{scheduled_scan.name} (Scheduled)",
                    scan_config=scheduled_scan.scan_config,
                    status='queued'
                )
                
                db.session.add(new_scan)
                db.session.commit()
                
                # Queue scan execution
                execute_scan.delay(new_scan.id)
                executed_count += 1
        
        logger.info(f"Executed {executed_count} scheduled scans")
        return {'executed_scans': executed_count}
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Scheduled scan task failed: {error_msg}")
        return {'error': error_msg}


@celery.task(bind=True, name='analyze_vulnerability_trends')
def analyze_vulnerability_trends(self, user_id=None, time_period_days=30):
    """
    Analyze vulnerability trends for reporting and insights
    
    Args:
        user_id: Specific user ID (None for all users)
        time_period_days: Period to analyze
    """
    from app import db
    from app.models import Scan, Vulnerability, User
    import sqlalchemy as sa
    from datetime import timedelta
    
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=time_period_days)
        
        # Build base query
        query = (
            sa.select(
                Vulnerability.vuln_type,
                Vulnerability.severity,
                sa.func.count(Vulnerability.id).label('count'),
                sa.func.avg(Vulnerability.cvss_score).label('avg_cvss')
            )
            .join(Scan)
            .where(Scan.created_at >= cutoff_date)
            .where(Vulnerability.false_positive == False)
            .group_by(Vulnerability.vuln_type, Vulnerability.severity)
        )
        
        if user_id:
            query = query.where(Scan.user_id == user_id)
        
        # Execute analysis
        trend_data = {}
        for vuln_type, severity, count, avg_cvss in db.session.execute(query):
            if vuln_type not in trend_data:
                trend_data[vuln_type] = {}
            
            trend_data[vuln_type][severity] = {
                'count': count,
                'avg_cvss': float(avg_cvss) if avg_cvss else 0.0
            }
        
        # Calculate top vulnerability types
        vuln_totals = {}
        for vuln_type, severities in trend_data.items():
            vuln_totals[vuln_type] = sum(s['count'] for s in severities.values())
        
        # Sort by frequency
        top_vulns = sorted(vuln_totals.items(), key=lambda x: x[1], reverse=True)[:10]
        
        results = {
            'time_period_days': time_period_days,
            'analysis_date': datetime.now(timezone.utc).isoformat(),
            'trend_data': trend_data,
            'top_vulnerability_types': top_vulns,
            'total_vulnerabilities': sum(vuln_totals.values())
        }
        
        logger.info(f"Vulnerability trend analysis completed. Found {len(trend_data)} vulnerability types")
        return results
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Vulnerability trend analysis failed: {error_msg}")
        return {'error': error_msg}


@celery.task(bind=True, name='health_check_scanners')
def health_check_scanners(self):
    """
    Check health status of all scanner tools
    """
    health_status = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'scanners': {}
    }
    
    # Check Nmap
    try:
        from app.scanners.nmap_scanner import NmapScanner
        scanner = NmapScanner()
        # Basic validation check
        scanner._validate_nmap_arguments('-T4 -F')
        health_status['scanners']['nmap'] = {
            'status': 'healthy',
            'version': 'available'
        }
    except Exception as e:
        health_status['scanners']['nmap'] = {
            'status': 'error',
            'error': str(e)
        }
    
    # Check ZAP
    try:
        from app.scanners.zap_scanner import ZapScanner, validate_web_target
        # Basic validation check
        validate_web_target('http://127.0.0.1')
        health_status['scanners']['zap'] = {
            'status': 'healthy',
            'note': 'ZAP daemon requires separate startup'
        }
    except Exception as e:
        health_status['scanners']['zap'] = {
            'status': 'error',
            'error': str(e)
        }
    
    # Check Metasploit
    try:
        from app.scanners.metasploit_scanner import MetasploitScanner, validate_exploit_target
        # Basic validation check
        validate_exploit_target('127.0.0.1')
        health_status['scanners']['metasploit'] = {
            'status': 'healthy',
            'note': 'MSF RPC requires separate startup'
        }
    except Exception as e:
        health_status['scanners']['metasploit'] = {
            'status': 'error',
            'error': str(e)
        }
    
    logger.info(f"Scanner health check completed: {health_status}")
    return health_status


@celery.task(bind=True, name='export_scan_data')
def export_scan_data(self, scan_id, export_format, include_false_positives=False):
    """
    Export scan data in various formats
    
    Args:
        scan_id: Database ID of the scan
        export_format: Format for export (json, csv, xml)
        include_false_positives: Whether to include false positives
    """
    from app import db
    from app.models import Scan, Vulnerability, ToolResult
    import sqlalchemy as sa
    import csv
    import xml.etree.ElementTree as ET
    import io
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return {'error': 'Scan not found'}
    
    try:
        # Get vulnerabilities
        vuln_query = sa.select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        if not include_false_positives:
            vuln_query = vuln_query.where(Vulnerability.false_positive == False)
        
        vulnerabilities = list(db.session.scalars(vuln_query))
        
        export_data = {
            'scan_info': {
                'id': scan.id,
                'name': scan.scan_name,
                'target_url': scan.target_url,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'total_vulnerabilities': scan.total_vulnerabilities
            },
            'vulnerabilities': [
                {
                    'id': v.id,
                    'vuln_type': v.vuln_type,
                    'severity': v.severity,
                    'title': v.title,
                    'description': v.description,
                    'affected_url': v.affected_url,
                    'affected_parameter': v.affected_parameter,
                    'cve_id': v.cve_id,
                    'cvss_score': float(v.cvss_score) if v.cvss_score else None,
                    'remediation': v.remediation,
                    'false_positive': v.false_positive,
                    'created_at': v.created_at.isoformat()
                }
                for v in vulnerabilities
            ]
        }
        
        # Generate export based on format
        if export_format == 'json':
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(export_data, f, indent=2, default=str)
                file_path = f.name
        
        elif export_format == 'csv':
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'id', 'vuln_type', 'severity', 'title', 'description',
                    'affected_url', 'cve_id', 'cvss_score', 'remediation', 'false_positive'
                ])
                writer.writeheader()
                for vuln in export_data['vulnerabilities']:
                    writer.writerow(vuln)
                file_path = f.name
        
        elif export_format == 'xml':
            root = ET.Element('scan_results')
            scan_elem = ET.SubElement(root, 'scan')
            for key, value in export_data['scan_info'].items():
                elem = ET.SubElement(scan_elem, key)
                elem.text = str(value) if value is not None else ''
            
            vulns_elem = ET.SubElement(root, 'vulnerabilities')
            for vuln in export_data['vulnerabilities']:
                vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
                for key, value in vuln.items():
                    elem = ET.SubElement(vuln_elem, key)
                    elem.text = str(value) if value is not None else ''
            
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                tree = ET.ElementTree(root)
                tree.write(f, encoding='unicode', xml_declaration=True)
                file_path = f.name
        
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        file_size = os.path.getsize(file_path)
        
        logger.info(f"Exported scan {scan_id} to {export_format}: {file_path}")
        
        return {
            'status': 'completed',
            'file_path': file_path,
            'file_size': file_size,
            'format': export_format,
            'vulnerabilities_exported': len(vulnerabilities)
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Export failed for scan {scan_id}: {error_msg}")
        return {'error': error_msg}


# Celery configuration for different environments
def configure_celery(app):
    """Configure Celery with Flask app"""
    
    # Production configuration
    if app.config.get('ENV') == 'production':
        broker_url = app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
        result_backend = app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    else:
        # Development configuration
        broker_url = 'redis://localhost:6379/1'  # Different DB for dev
        result_backend = 'redis://localhost:6379/1'
    
    celery.conf.update(
        broker_url=broker_url,
        result_backend=result_backend,
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        
        # Task routing
        task_routes={
            'execute_scan': {'queue': 'scans'},
            'generate_report': {'queue': 'reports'},
            'send_scan_notification': {'queue': 'notifications'},
            'cleanup_old_scans': {'queue': 'maintenance'},
            'health_check_scanners': {'queue': 'maintenance'}
        },
        
        # Worker configuration
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=50,
        worker_disable_rate_limits=True,
        
        # Task time limits
        task_time_limit=30 * 60,  # 30 minutes
        task_soft_time_limit=25 * 60,  # 25 minutes
        
        # Result expiration
        result_expires=60 * 60 * 24,  # 24 hours
        
        # Beat schedule for periodic tasks
        beat_schedule={
            'cleanup-old-scans': {
                'task': 'cleanup_old_scans',
                'schedule': 60 * 60 * 24,  # Daily
                'args': (30,)  # Delete scans older than 30 days
            },
            'health-check': {
                'task': 'health_check_scanners',
                'schedule': 60 * 15,  # Every 15 minutes
            },
            'process-scheduled-scans': {
                'task': 'schedule_periodic_scans',
                'schedule': 60 * 60,  # Hourly
            }
        }
    )
    
    # Update task base to include Flask app context
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery


# Task monitoring and management utilities
def get_task_status(task_id):
    """Get status of a Celery task"""
    try:
        task_result = celery.AsyncResult(task_id)
        return {
            'task_id': task_id,
            'status': task_result.status,
            'result': task_result.result,
            'info': task_result.info
        }
    except Exception as e:
        return {
            'task_id': task_id,
            'status': 'error',
            'error': str(e)
        }


def cancel_task(task_id):
    """Cancel a running Celery task"""
    try:
        celery.control.revoke(task_id, terminate=True)
        return {'status': 'cancelled'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def get_queue_info():
    """Get information about Celery queues"""
    try:
        inspect = celery.control.inspect()
        
        return {
            'active_tasks': inspect.active(),
            'scheduled_tasks': inspect.scheduled(),
            'reserved_tasks': inspect.reserved(),
            'stats': inspect.stats()
        }
    except Exception as e:
        return {'error': str(e)}


# Development utilities
def run_scan_sync(scan_id):
    """
    Run scan synchronously for development/testing
    This bypasses Celery and runs the scan directly
    """
    from app import create_app
    
    app = create_app()
    with app.app_context():
        return execute_scan.run(scan_id)


if __name__ == '__main__':
    # For testing tasks directly
    import sys
    if len(sys.argv) > 1:
        scan_id = int(sys.argv[1])
        result = run_scan_sync(scan_id)
        print(f"Scan result: {result}")