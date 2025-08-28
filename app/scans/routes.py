# app/scans/routes.py
from datetime import datetime, timezone
from flask import render_template, redirect, flash, url_for, request, jsonify, current_app
from flask_login import current_user, login_required
import sqlalchemy as sa
import json
import asyncio
from app import db
from app.scans.forms import NewScanForm, ScanConfigForm
from app.models import Scan, ToolResult, Vulnerability, can_user_create_scan, get_user_scans
from app.scans import bp
from app.scanners.nmap_scanner import run_nmap, validate_target
from app.scanners.zap_scanner import run_zap, validate_web_target
from app.scanners.metasploit_scanner import run_metasploit, validate_exploit_target


@bp.route('/scans')
@login_required
def scans_list():
    """Display user's scans with pagination and filtering"""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    scan_type_filter = request.args.get('type', '')
    
    # Build query with filters
    query = sa.select(Scan).where(Scan.user_id == current_user.id)
    
    if status_filter:
        query = query.where(Scan.status == status_filter)
    if scan_type_filter:
        query = query.where(Scan.scan_type == scan_type_filter)
    
    query = query.order_by(Scan.created_at.desc())
    
    scans = db.paginate(
        query, page=page, per_page=10, error_out=False
    )
    
    # Get filter options
    status_options = ['queued', 'running', 'completed', 'failed', 'cancelled']
    type_options = ['web', 'network', 'exploit', 'comprehensive']
    
    return render_template('scans/list.html', 
                         scans=scans,
                         status_filter=status_filter,
                         scan_type_filter=scan_type_filter,
                         status_options=status_options,
                         type_options=type_options)


@bp.route('/scans/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Create a new security scan"""
    if not can_user_create_scan(current_user.id):
        flash('You have reached your monthly scan limit. Please upgrade your subscription.', 'warning')
        return redirect(url_for('scans.scans_list'))
    
    form = NewScanForm()
    
    if form.validate_on_submit():
        # Validate target based on scan type
        target = form.target_url.data.strip()
        scan_type = form.scan_type.data
        
        # Perform target validation
        target_valid = False
        validation_error = None
        
        try:
            if scan_type == 'web':
                target_valid = validate_web_target(target)
            elif scan_type == 'network':
                target_valid = validate_target(target)
            elif scan_type == 'exploit':
                target_valid = validate_exploit_target(target)
            elif scan_type == 'comprehensive':
                # For comprehensive scans, try web validation first, then network
                target_valid = validate_web_target(target) or validate_target(target)
            
            if not target_valid:
                validation_error = f"Invalid target for {scan_type} scan type"
                
        except Exception as e:
            validation_error = f"Target validation failed: {str(e)}"
        
        if validation_error:
            flash(validation_error, 'error')
            return render_template('scans/new.html', form=form)
        
        # Create scan record
        scan = Scan(
            user_id=current_user.id,
            target_url=target,
            scan_type=scan_type,
            scan_name=form.scan_name.data or f"{scan_type.title()} scan of {target}",
            scan_config=json.dumps({
                'scan_preset': form.scan_preset.data,
                'enable_nmap': form.enable_nmap.data,
                'enable_zap': form.enable_zap.data,
                'enable_metasploit': form.enable_metasploit.data,
                'created_via': 'web_ui'
            }),
            status='queued'
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Start scan execution asynchronously
        try:
            from app.tasks import execute_scan
            task = execute_scan.delay(scan.id)
            scan.celery_task_id = task.id
            db.session.commit()
            
            flash(f'Scan "{scan.scan_name}" has been queued successfully!', 'success')
        except ImportError:
            # If Celery is not available, run synchronously (for development)
            flash('Scan created. Running in development mode...', 'info')
            # You could call _run_scan_sync(scan.id) here for dev testing
        
        return redirect(url_for('scans.scan_detail', scan_id=scan.id))
    
    return render_template('scans/new.html', form=form)


@bp.route('/scans/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    """Display detailed scan results"""
    scan = db.session.get(Scan, scan_id)
    
    if not scan or scan.user_id != current_user.id:
        flash('Scan not found or access denied.', 'error')
        return redirect(url_for('scans.scans_list'))
    
    # Get vulnerabilities grouped by severity
    vulnerabilities = list(db.session.scalars(
        sa.select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity_score.desc(), Vulnerability.created_at.desc())
    ))
    
    # Get tool results
    tool_results = list(db.session.scalars(
        sa.select(ToolResult)
        .where(ToolResult.scan_id == scan_id)
        .order_by(ToolResult.created_at.desc())
    ))
    
    # Group vulnerabilities by severity
    vuln_by_severity = {
        'critical': [v for v in vulnerabilities if v.severity == 'critical'],
        'high': [v for v in vulnerabilities if v.severity == 'high'],
        'medium': [v for v in vulnerabilities if v.severity == 'medium'],
        'low': [v for v in vulnerabilities if v.severity == 'low'],
        'info': [v for v in vulnerabilities if v.severity == 'info']
    }
    
    return render_template('scans/detail.html', 
                         scan=scan, 
                         vulnerabilities=vulnerabilities,
                         vuln_by_severity=vuln_by_severity,
                         tool_results=tool_results)


@bp.route('/scans/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """Delete a scan and all associated data"""
    scan = db.session.get(Scan, scan_id)
    
    if not scan or scan.user_id != current_user.id:
        flash('Scan not found or access denied.', 'error')
        return redirect(url_for('scans.scans_list'))
    
    try:
        # Cancel running scan if needed
        if scan.status == 'running' and scan.celery_task_id:
            try:
                from app.tasks import celery
                celery.control.revoke(scan.celery_task_id, terminate=True)
            except ImportError:
                pass
        
        scan_name = scan.scan_name
        db.session.delete(scan)
        db.session.commit()
        
        flash(f'Scan "{scan_name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting scan: {str(e)}', 'error')
    
    return redirect(url_for('scans.scans_list'))


@bp.route('/scans/<int:scan_id>/retry', methods=['POST'])
@login_required
def retry_scan(scan_id):
    """Retry a failed scan"""
    scan = db.session.get(Scan, scan_id)
    
    if not scan or scan.user_id != current_user.id:
        flash('Scan not found or access denied.', 'error')
        return redirect(url_for('scans.scans_list'))
    
    if scan.status not in ['failed', 'cancelled']:
        flash('Only failed or cancelled scans can be retried.', 'warning')
        return redirect(url_for('scans.scan_detail', scan_id=scan_id))
    
    if not can_user_create_scan(current_user.id):
        flash('You have reached your monthly scan limit.', 'warning')
        return redirect(url_for('scans.scan_detail', scan_id=scan_id))
    
    try:
        # Reset scan status
        scan.status = 'queued'
        scan.started_at = None
        scan.completed_at = None
        scan.celery_task_id = None
        
        # Clear previous results
        db.session.execute(
            sa.delete(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        db.session.execute(
            sa.delete(ToolResult).where(ToolResult.scan_id == scan_id)
        )
        
        db.session.commit()
        
        # Start scan execution
        try:
            from app.tasks import execute_scan
            task = execute_scan.delay(scan.id)
            scan.celery_task_id = task.id
            db.session.commit()
        except ImportError:
            pass
        
        flash(f'Scan "{scan.scan_name}" has been queued for retry.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error retrying scan: {str(e)}', 'error')
    
    return redirect(url_for('scans.scan_detail', scan_id=scan_id))


@bp.route('/api/scans/<int:scan_id>/status')
@login_required
def scan_status_api(scan_id):
    """API endpoint for real-time scan status updates"""
    scan = db.session.get(Scan, scan_id)
    
    if not scan or scan.user_id != current_user.id:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Get latest tool results
    tool_results = list(db.session.scalars(
        sa.select(ToolResult)
        .where(ToolResult.scan_id == scan_id)
        .order_by(ToolResult.created_at.desc())
    ))
    
    return jsonify({
        'scan_id': scan.id,
        'status': scan.status,
        'progress': scan.progress_percentage,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'vulnerabilities_found': scan.total_vulnerabilities,
        'tool_results': [
            {
                'tool_name': tr.tool_name,
                'status': tr.status,
                'started_at': tr.started_at.isoformat() if tr.started_at else None,
                'completed_at': tr.completed_at.isoformat() if tr.completed_at else None,
                'error_message': tr.error_message
            } for tr in tool_results
        ]
    })


@bp.route('/api/scans/<int:scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan_api(scan_id):
    """API endpoint to cancel running scan"""
    scan = db.session.get(Scan, scan_id)
    
    if not scan or scan.user_id != current_user.id:
        return jsonify({'error': 'Scan not found'}), 404
    
    if scan.status != 'running':
        return jsonify({'error': 'Only running scans can be cancelled'}), 400
    
    try:
        # Cancel Celery task
        if scan.celery_task_id:
            try:
                from app.tasks import celery
                celery.control.revoke(scan.celery_task_id, terminate=True)
            except ImportError:
                pass
        
        # Update scan status
        scan.status = 'cancelled'
        scan.completed_at = datetime.now(timezone.utc)
        
        # Mark any running tool results as cancelled
        db.session.execute(
            sa.update(ToolResult)
            .where(ToolResult.scan_id == scan_id)
            .where(ToolResult.status == 'running')
            .values(status='cancelled', completed_at=datetime.now(timezone.utc))
        )
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Scan cancelled successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to cancel scan: {str(e)}'}), 500


@bp.route('/scans/presets')
@login_required
def scan_presets():
    """Get available scan presets for different tools"""
    try:
        from app.scanners.nmap_scanner import NmapScanner
        from app.scanners.zap_scanner import ZapScanner
        from app.scanners.metasploit_scanner import MetasploitScanner
        
        # Get presets from each scanner
        nmap_scanner = NmapScanner()
        zap_scanner = ZapScanner()
        msf_scanner = MetasploitScanner()
        
        presets = {
            'nmap': nmap_scanner.get_scan_presets(),
            'zap': zap_scanner.get_scan_policies(),
            'metasploit': msf_scanner.get_scan_configurations()
        }
        
        return jsonify(presets)
        
    except Exception as e:
        current_app.logger.error(f"Error getting scan presets: {str(e)}")
        return jsonify({'error': 'Failed to load scan presets'}), 500


# Internal helper functions for scan execution
async def _run_comprehensive_scan(scan_id: int, target: str, config: dict) -> dict:
    """Run comprehensive scan using multiple tools"""
    results = {
        'nmap': None,
        'zap': None, 
        'metasploit': None,
        'total_vulnerabilities': 0,
        'errors': []
    }
    
    # Run Nmap if enabled
    if config.get('enable_nmap', True):
        try:
            nmap_preset = config.get('nmap_preset', 'quick')
            results['nmap'] = await run_nmap(scan_id, target, nmap_preset)
            if results['nmap']['status'] == 'completed':
                results['total_vulnerabilities'] += results['nmap']['vulnerabilities_found']
        except Exception as e:
            results['errors'].append(f"Nmap scan failed: {str(e)}")
    
    # Run ZAP for web targets if enabled
    if config.get('enable_zap', True) and validate_web_target(target):
        try:
            zap_preset = config.get('zap_preset', 'basic')
            results['zap'] = await run_zap(scan_id, target, zap_preset)
            if results['zap']['status'] == 'completed':
                results['total_vulnerabilities'] += results['zap']['vulnerabilities_found']
        except Exception as e:
            results['errors'].append(f"ZAP scan failed: {str(e)}")
    
    # Run Metasploit if enabled and target is safe
    if config.get('enable_metasploit', False) and validate_exploit_target(target):
        try:
            msf_preset = config.get('metasploit_preset', 'web_basic')
            results['metasploit'] = await run_metasploit(scan_id, target, msf_preset)
            if results['metasploit']['status'] == 'completed':
                results['total_vulnerabilities'] += results['metasploit']['vulnerabilities_found']
        except Exception as e:
            results['errors'].append(f"Metasploit scan failed: {str(e)}")
    
    return results


def _run_scan_sync(scan_id: int):
    """Synchronous scan execution for development/testing"""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return
    
    try:
        # Update scan status
        scan.status = 'running'
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()
        
        # Parse scan configuration
        config = json.loads(scan.scan_config) if scan.scan_config else {}
        
        # Run appropriate scan type
        if scan.scan_type == 'comprehensive':
            # Run comprehensive scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(
                    _run_comprehensive_scan(scan.id, scan.target_url, config)
                )
                total_vulns = results['total_vulnerabilities']
            finally:
                loop.close()
                
        elif scan.scan_type == 'network':
            # Run Nmap only
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                nmap_preset = config.get('scan_preset', 'quick')
                result = loop.run_until_complete(run_nmap(scan.id, scan.target_url, nmap_preset))
                total_vulns = result.get('vulnerabilities_found', 0)
            finally:
                loop.close()
                
        elif scan.scan_type == 'web':
            # Run ZAP only
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                zap_preset = config.get('scan_preset', 'basic')
                result = loop.run_until_complete(run_zap(scan.id, scan.target_url, zap_preset))
                total_vulns = result.get('vulnerabilities_found', 0)
            finally:
                loop.close()
                
        elif scan.scan_type == 'exploit':
            # Run Metasploit only
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                msf_preset = config.get('scan_preset', 'web_basic')
                result = loop.run_until_complete(run_metasploit(scan.id, scan.target_url, msf_preset))
                total_vulns = result.get('vulnerabilities_found', 0)
            finally:
                loop.close()
        
        # Update scan completion
        scan.status = 'completed'
        scan.completed_at = datetime.now(timezone.utc)
        scan.total_vulnerabilities = total_vulns
        
        # Update severity counts
        _update_scan_severity_counts(scan.id)
        
        db.session.commit()
        
    except Exception as e:
        # Mark scan as failed
        scan.status = 'failed'
        scan.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        
        current_app.logger.error(f"Scan {scan_id} failed: {str(e)}")


def _update_scan_severity_counts(scan_id: int):
    """Update vulnerability severity counts for a scan"""
    # Count vulnerabilities by severity
    severity_counts = {}
    
    vulnerabilities = list(db.session.scalars(
        sa.select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    ))
    
    for vuln in vulnerabilities:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
    
    # Update scan record
    scan = db.session.get(Scan, scan_id)
    if scan:
        scan.high_severity_count = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        scan.medium_severity_count = severity_counts.get('medium', 0)
        scan.low_severity_count = severity_counts.get('low', 0) + severity_counts.get('info', 0)
        scan.total_vulnerabilities = sum(severity_counts.values())
        db.session.commit()


@bp.route('/scans/<int:scan_id>/vulnerability/<int:vuln_id>')
@login_required
def vulnerability_detail(scan_id, vuln_id):
    """Display detailed vulnerability information"""
    # Verify user owns the scan
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        flash('Scan not found or access denied.', 'error')
        return redirect(url_for('scans.scans_list'))
    
    # Get vulnerability
    vulnerability = db.session.get(Vulnerability, vuln_id)
    if not vulnerability or vulnerability.scan_id != scan_id:
        flash('Vulnerability not found.', 'error')
        return redirect(url_for('scans.scan_detail', scan_id=scan_id))
    
    # Parse evidence JSON if present
    evidence_data = None
    if vulnerability.evidence:
        try:
            evidence_data = json.loads(vulnerability.evidence)
        except json.JSONDecodeError:
            pass
    
    return render_template('scans/vulnerability_detail.html',
                         scan=scan,
                         vulnerability=vulnerability,
                         evidence_data=evidence_data)


@bp.route('/scans/<int:scan_id>/vulnerability/<int:vuln_id>/false-positive', methods=['POST'])
@login_required
def mark_false_positive(scan_id, vuln_id):
    """Mark vulnerability as false positive"""
    # Verify ownership
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    vulnerability = db.session.get(Vulnerability, vuln_id)
    if not vulnerability or vulnerability.scan_id != scan_id:
        return jsonify({'error': 'Vulnerability not found'}), 404
    
    try:
        vulnerability.false_positive = not vulnerability.false_positive
        db.session.commit()
        
        return jsonify({
            'success': True,
            'false_positive': vulnerability.false_positive,
            'message': f'Vulnerability marked as {"false positive" if vulnerability.false_positive else "valid vulnerability"}'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/scans/quick-scan')
@login_required
def quick_scan_page():
    """Quick scan page with simplified interface"""
    if not can_user_create_scan(current_user.id):
        flash('You have reached your monthly scan limit. Please upgrade your subscription.', 'warning')
        return redirect(url_for('main.index'))
    
    return render_template('scans/quick_scan.html')


@bp.route('/api/quick-scan', methods=['POST'])
@login_required
def quick_scan_api():
    """API endpoint for quick scans"""
    if not can_user_create_scan(current_user.id):
        return jsonify({'error': 'Scan limit reached'}), 403
    
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    
    try:
        # Auto-detect scan type based on target
        scan_type = 'web'
        if not target.startswith(('http://', 'https://')):
            scan_type = 'network'
        
        # Create quick scan
        scan = Scan(
            user_id=current_user.id,
            target_url=target,
            scan_type=scan_type,
            scan_name=f"Quick {scan_type} scan of {target}",
            scan_config=json.dumps({
                'scan_preset': 'quick',
                'enable_nmap': True,
                'enable_zap': scan_type == 'web',
                'enable_metasploit': False,
                'created_via': 'quick_scan'
            }),
            status='queued'
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Start scan
        try:
            from app.tasks import execute_scan
            task = execute_scan.delay(scan.id)
            scan.celery_task_id = task.id
            db.session.commit()
        except ImportError:
            pass
        
        return jsonify({
            'success': True,
            'scan_id': scan.id,
            'message': 'Quick scan started successfully',
            'redirect_url': url_for('scans.scan_detail', scan_id=scan.id)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/scans/dashboard')
@login_required  
def dashboard():
    """Scan dashboard with overview and recent scans"""
    # Get user's recent scans
    recent_scans = get_user_scans(current_user.id, limit=5)
    
    # Calculate stats
    total_scans = db.session.scalar(
        sa.select(sa.func.count(Scan.id)).where(Scan.user_id == current_user.id)
    ) or 0
    
    total_vulnerabilities = db.session.scalar(
        sa.select(sa.func.sum(Scan.total_vulnerabilities))
        .where(Scan.user_id == current_user.id)
    ) or 0
    
    # Get scan status distribution
    status_counts = dict(db.session.execute(
        sa.select(Scan.status, sa.func.count(Scan.id))
        .where(Scan.user_id == current_user.id)
        .group_by(Scan.status)
    ).fetchall())
    
    # Get vulnerability severity distribution
    severity_counts = dict(db.session.execute(
        sa.select(
            Vulnerability.severity, 
            sa.func.count(Vulnerability.id)
        )
        .join(Scan)
        .where(Scan.user_id == current_user.id)
        .group_by(Vulnerability.severity)
    ).fetchall())
    
    return render_template('scans/dashboard.html',
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         total_vulnerabilities=total_vulnerabilities,
                         status_counts=status_counts,
                         severity_counts=severity_counts)