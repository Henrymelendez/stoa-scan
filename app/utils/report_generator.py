# app/utils/report_generator.py
"""
Report generation utilities for PentestSaaS
Generates professional security scan reports in various formats
"""

import os
import json
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
import logging

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.platypus import PageBreak, Image, KeepTogether
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
except ImportError:
    # ReportLab not available - PDF generation will be disabled
    pass

from app.models import Scan, Vulnerability, ToolResult, User


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate security scan reports in various formats
    """
    
    def __init__(self, scan: Scan, report_type: str = 'pdf'):
        self.scan = scan
        self.report_type = report_type.lower()
        self.vulnerabilities = list(scan.vulnerabilities)
        self.tool_results = list(scan.tool_results)
        self.user = scan.user
        
        # Filter out false positives for reports
        self.active_vulnerabilities = [v for v in self.vulnerabilities if not v.false_positive]
        
        # Group vulnerabilities by severity
        self.vuln_by_severity = self._group_vulnerabilities_by_severity()
        
        # Report metadata
        self.report_data = {
            'generated_at': datetime.now(timezone.utc),
            'scan_info': {
                'id': scan.id,
                'name': scan.scan_name,
                'target': scan.target_url,
                'type': scan.scan_type,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at,
                'duration': scan.duration
            },
            'statistics': self._calculate_statistics(),
            'executive_summary': self._generate_executive_summary()
        }
    
    def generate(self) -> Tuple[str, int]:
        """
        Generate report and return file path and size
        
        Returns:
            Tuple of (file_path, file_size_bytes)
        """
        if self.report_type == 'pdf':
            return self._generate_pdf_report()
        elif self.report_type == 'html':
            return self._generate_html_report()
        elif self.report_type == 'json':
            return self._generate_json_report()
        elif self.report_type == 'csv':
            return self._generate_csv_report()
        elif self.report_type == 'xml':
            return self._generate_xml_report()
        else:
            raise ValueError(f"Unsupported report type: {self.report_type}")
    
    def _group_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group active vulnerabilities by severity level"""
        groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for vuln in self.active_vulnerabilities:
            severity = vuln.severity.lower()
            if severity in groups:
                groups[severity].append(vuln)
        
        return groups
    
    def _calculate_statistics(self) -> Dict:
        """Calculate scan statistics for reporting"""
        total_vulns = len(self.active_vulnerabilities)
        
        severity_counts = {}
        vuln_type_counts = {}
        
        for vuln in self.active_vulnerabilities:
            # Count by severity
            severity = vuln.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln.vuln_type
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
        
        # Calculate security score (0-100)
        score = max(0, 100 - (
            severity_counts.get('critical', 0) * 15 +
            severity_counts.get('high', 0) * 10 +
            severity_counts.get('medium', 0) * 5 +
            severity_counts.get('low', 0) * 2 +
            severity_counts.get('info', 0) * 1
        ))
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_counts,
            'vulnerability_types': vuln_type_counts,
            'security_score': score,
            'tools_used': len(self.tool_results),
            'false_positives': len([v for v in self.vulnerabilities if v.false_positive])
        }
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary text"""
        stats = self._calculate_statistics()
        target_host = self._get_target_hostname()
        
        summary_parts = []
        
        # Opening
        summary_parts.append(
            f"A comprehensive security assessment was conducted on {target_host} "
            f"on {self.scan.completed_at.strftime('%B %d, %Y') if self.scan.completed_at else 'recently'}."
        )
        
        # Overall findings
        total_vulns = stats['total_vulnerabilities']
        if total_vulns == 0:
            summary_parts.append(
                "The assessment found no significant security vulnerabilities, "
                "indicating a strong security posture for the tested components."
            )
        else:
            critical_high = stats['severity_distribution'].get('critical', 0) + stats['severity_distribution'].get('high', 0)
            
            if critical_high > 0:
                summary_parts.append(
                    f"The assessment identified {total_vulns} security vulnerabilities, "
                    f"including {critical_high} high or critical severity issues that require immediate attention."
                )
            else:
                summary_parts.append(
                    f"The assessment identified {total_vulns} security vulnerabilities "
                    f"of medium to low severity that should be addressed as part of regular security maintenance."
                )
        
        # Security score
        score = stats['security_score']
        if score >= 90:
            score_assessment = "excellent security posture"
        elif score >= 75:
            score_assessment = "good security posture with minor improvements needed"
        elif score >= 60:
            score_assessment = "moderate security posture requiring attention"
        else:
            score_assessment = "security posture requiring significant improvements"
        
        summary_parts.append(f"The target demonstrates {score_assessment} with a security score of {score}/100.")
        
        # Tools used
        tools_used = [tr.tool_name.upper() for tr in self.tool_results if tr.status == 'completed']
        if tools_used:
            summary_parts.append(f"This assessment utilized {', '.join(tools_used)} for comprehensive coverage.")
        
        return ' '.join(summary_parts)
    
    def _get_target_hostname(self) -> str:
        """Extract clean hostname from target URL"""
        try:
            if self.scan.target_url.startswith(('http://', 'https://')):
                return urlparse(self.scan.target_url).netloc
            return self.scan.target_url
        except:
            return self.scan.target_url
    
    def _generate_pdf_report(self) -> Tuple[str, int]:
        """Generate comprehensive PDF report using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.platypus import PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            raise ImportError("ReportLab library required for PDF generation. Run: pip install reportlab")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            temp_file.name,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1f2937'),
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#dc2626'),
            keepWithNext=True
        )
        
        # Build document content
        story = []
        
        # Title page
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Report header table
        header_data = [
            ['Target:', self.scan.target_url],
            ['Scan Type:', self.scan.scan_type.title()],
            ['Generated:', self.report_data['generated_at'].strftime('%B %d, %Y at %I:%M %p UTC')],
            ['Scan Duration:', f"{self.scan.duration / 60:.1f} minutes" if self.scan.duration else "Unknown"],
            ['Security Score:', f"{self.report_data['statistics']['security_score']}/100"]
        ]
        
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(header_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(self.report_data['executive_summary'], styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Vulnerability Summary
        story.append(Paragraph("Vulnerability Summary", heading_style))
        
        if self.active_vulnerabilities:
            # Severity breakdown table
            severity_data = [['Severity', 'Count', 'Description']]
            severity_colors = {
                'critical': HexColor('#dc2626'),
                'high': HexColor('#f59e0b'),
                'medium': HexColor('#3b82f6'),
                'low': HexColor('#6b7280'),
                'info': HexColor('#9ca3af')
            }
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = len(self.vuln_by_severity[severity])
                if count > 0:
                    descriptions = {
                        'critical': 'Immediate action required',
                        'high': 'Should be addressed promptly',
                        'medium': 'Should be addressed in next cycle',
                        'low': 'Address when convenient',
                        'info': 'Informational findings'
                    }
                    severity_data.append([severity.title(), str(count), descriptions[severity]])
            
            if len(severity_data) > 1:  # Has data beyond header
                severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1f2937')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
                    ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
                ]))
                
                story.append(severity_table)
                story.append(Spacer(1, 20))
        else:
            story.append(Paragraph("No security vulnerabilities were identified during this assessment.", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Detailed Findings
        if self.active_vulnerabilities:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerability Findings", heading_style))
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                vulns = self.vuln_by_severity[severity]
                if not vulns:
                    continue
                
                # Severity section header
                section_title = f"{severity.title()} Severity Vulnerabilities ({len(vulns)})"
                story.append(Paragraph(section_title, styles['Heading3']))
                story.append(Spacer(1, 10))
                
                # Vulnerability details
                for i, vuln in enumerate(vulns, 1):
                    vuln_content = []
                    
                    # Vulnerability title
                    vuln_title = f"{i}. {vuln.title}"
                    if vuln.cve_id:
                        vuln_title += f" ({vuln.cve_id})"
                    
                    vuln_content.append(Paragraph(vuln_title, styles['Heading4']))
                    
                    # Description
                    if vuln.description:
                        vuln_content.append(Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal']))
                    
                    # Technical details
                    details = []
                    if vuln.affected_url:
                        details.append(f"<b>Affected URL:</b> {vuln.affected_url}")
                    if vuln.affected_parameter:
                        details.append(f"<b>Parameter:</b> {vuln.affected_parameter}")
                    if vuln.cvss_score:
                        details.append(f"<b>CVSS Score:</b> {vuln.cvss_score}")
                    
                    if details:
                        vuln_content.append(Paragraph("<br/>".join(details), styles['Normal']))
                    
                    # Remediation
                    if vuln.remediation:
                        vuln_content.append(Paragraph(f"<b>Remediation:</b> {vuln.remediation}", styles['Normal']))
                    
                    # Group vulnerability content
                    story.append(KeepTogether(vuln_content))
                    story.append(Spacer(1, 15))
        
        # Tool Results Summary
        story.append(PageBreak())
        story.append(Paragraph("Tool Execution Summary", heading_style))
        
        if self.tool_results:
            tool_data = [['Tool', 'Status', 'Duration', 'Findings']]
            
            for tool in self.tool_results:
                duration = f"{tool.duration / 60:.1f}m" if tool.duration else "N/A"
                vuln_count = len([v for v in self.active_vulnerabilities if v.tool_result_id == tool.id])
                
                tool_data.append([
                    tool.tool_name.upper(),
                    tool.status.title(),
                    duration,
                    str(vuln_count)
                ])
            
            tool_table = Table(tool_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            tool_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1f2937')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ]))
            
            story.append(tool_table)
        
        # Build PDF
        doc.build(story)
        
        # Get file size
        file_size = os.path.getsize(temp_file.name)
        
        return temp_file.name, file_size
    
    def _generate_html_report(self) -> Tuple[str, int]:
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {self.scan.scan_name}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background: #f8fafc;
                }}
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 2rem;
                }}
                .report-header {{
                    background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
                    color: white;
                    padding: 2rem;
                    border-radius: 12px;
                    margin-bottom: 2rem;
                }}
                .report-title {{
                    font-size: 2.5rem;
                    margin: 0 0 1rem 0;
                    text-align: center;
                }}
                .report-meta {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 1rem;
                    background: rgba(255, 255, 255, 0.1);
                    padding: 1rem;
                    border-radius: 8px;
                }}
                .meta-item {{
                    text-align: center;
                }}
                .meta-label {{
                    display: block;
                    font-size: 0.9rem;
                    opacity: 0.8;
                }}
                .meta-value {{
                    display: block;
                    font-size: 1.2rem;
                    font-weight: 600;
                }}
                .section {{
                    background: white;
                    padding: 2rem;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    margin-bottom: 2rem;
                }}
                .section h2 {{
                    color: #1f2937;
                    border-bottom: 2px solid #dc2626;
                    padding-bottom: 0.5rem;
                    margin-bottom: 1.5rem;
                }}
                .vulnerability-card {{
                    border: 1px solid #e2e8f0;
                    border-radius: 8px;
                    padding: 1rem;
                    margin-bottom: 1rem;
                    border-left: 4px solid #dc2626;
                }}
                .vulnerability-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 1rem;
                }}
                .vulnerability-title {{
                    font-size: 1.2rem;
                    font-weight: 600;
                    color: #1f2937;
                    margin: 0;
                }}
                .severity-badge {{
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    font-size: 0.8rem;
                    font-weight: 600;
                    text-transform: uppercase;
                }}
                .severity-critical {{ background: #fef2f2; color: #991b1b; }}
                .severity-high {{ background: #fffbeb; color: #92400e; }}
                .severity-medium {{ background: #eff6ff; color: #1e40af; }}
                .severity-low {{ background: #f3f4f6; color: #4b5563; }}
                .severity-info {{ background: #f9fafb; color: #6b7280; }}
                .vuln-details {{
                    margin-top: 1rem;
                }}
                .vuln-detail-item {{
                    margin-bottom: 0.5rem;
                }}
                .security-score {{
                    text-align: center;
                    padding: 2rem;
                    background: linear-gradient(135deg, #059669 0%, #10b981 100%);
                    color: white;
                    border-radius: 12px;
                    margin: 2rem 0;
                }}
                .score-value {{
                    font-size: 4rem;
                    font-weight: 700;
                    margin: 0;
                }}
                .score-label {{
                    font-size: 1.2rem;
                    opacity: 0.9;
                }}
                @media print {{
                    body {{ background: white; }}
                    .container {{ padding: 1rem; }}
                    .section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="report-header">
                    <h1 class="report-title">Security Assessment Report</h1>
                    <div class="report-meta">
                        <div class="meta-item">
                            <span class="meta-label">Target</span>
                            <span class="meta-value">{self._get_target_hostname()}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Scan Type</span>
                            <span class="meta-value">{self.scan.scan_type.title()}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Vulnerabilities</span>
                            <span class="meta-value">{len(self.active_vulnerabilities)}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Security Score</span>
                            <span class="meta-value">{self.report_data['statistics']['security_score']}/100</span>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Executive Summary</h2>
                    <p>{self.report_data['executive_summary']}</p>
                </div>
                
                {"".join(self._generate_html_vulnerability_sections())}
                
                <div class="section">
                    <h2>Recommendations</h2>
                    {self._generate_html_recommendations()}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save HTML file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html')
        temp_file.write(html_content)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _generate_html_vulnerability_sections(self) -> List[str]:
        """Generate HTML sections for vulnerabilities by severity"""
        sections = []
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = self.vuln_by_severity[severity]
            if not vulns:
                continue
            
            section_html = f"""
            <div class="section">
                <h2>{severity.title()} Severity Vulnerabilities ({len(vulns)})</h2>
                {"".join(self._generate_html_vulnerability_card(vuln) for vuln in vulns)}
            </div>
            """
            sections.append(section_html)
        
        return sections
    
    def _generate_html_vulnerability_card(self, vuln: Vulnerability) -> str:
        """Generate HTML for individual vulnerability"""
        return f"""
        <div class="vulnerability-card">
            <div class="vulnerability-header">
                <h3 class="vulnerability-title">{vuln.title}</h3>
                <span class="severity-badge severity-{vuln.severity.lower()}">{vuln.severity}</span>
            </div>
            
            {f'<p><strong>Description:</strong> {vuln.description}</p>' if vuln.description else ''}
            
            <div class="vuln-details">
                {f'<div class="vuln-detail-item"><strong>Affected URL:</strong> <code>{vuln.affected_url}</code></div>' if vuln.affected_url else ''}
                {f'<div class="vuln-detail-item"><strong>Parameter:</strong> <code>{vuln.affected_parameter}</code></div>' if vuln.affected_parameter else ''}
                {f'<div class="vuln-detail-item"><strong>CVE ID:</strong> {vuln.cve_id}</div>' if vuln.cve_id else ''}
                {f'<div class="vuln-detail-item"><strong>CVSS Score:</strong> {vuln.cvss_score}/10</div>' if vuln.cvss_score else ''}
                {f'<div class="vuln-detail-item"><strong>Remediation:</strong> {vuln.remediation}</div>' if vuln.remediation else ''}
            </div>
        </div>
        """
    
    def _generate_html_recommendations(self) -> str:
        """Generate HTML recommendations section"""
        stats = self.report_data['statistics']
        recommendations = []
        
        # Priority recommendations based on findings
        if stats['severity_distribution'].get('critical', 0) > 0:
            recommendations.append("🔴 <strong>CRITICAL:</strong> Address critical vulnerabilities immediately to prevent potential system compromise.")
        
        if stats['severity_distribution'].get('high', 0) > 0:
            recommendations.append("🟠 <strong>HIGH PRIORITY:</strong> Schedule high-severity vulnerability remediation within the next sprint.")
        
        # General recommendations
        recommendations.extend([
            "🔄 <strong>Regular Scanning:</strong> Implement regular security scanning as part of your development cycle.",
            "📚 <strong>Security Training:</strong> Ensure development teams receive security awareness training.",
            "🛡️ <strong>Defense in Depth:</strong> Implement multiple layers of security controls.",
            "📊 <strong>Monitoring:</strong> Set up continuous security monitoring and alerting."
        ])
        
        return "<ul>" + "".join(f"<li>{rec}</li>" for rec in recommendations) + "</ul>"
    
    def _generate_json_report(self) -> Tuple[str, int]:
        """Generate JSON report with complete data"""
        report_json = {
            'metadata': {
                'report_type': 'json',
                'generated_at': self.report_data['generated_at'].isoformat(),
                'generator': 'PentestSaaS Report Generator v1.0'
            },
            'scan': {
                'id': self.scan.id,
                'name': self.scan.scan_name,
                'target_url': self.scan.target_url,
                'target_ip': self.scan.target_ip,
                'scan_type': self.scan.scan_type,
                'status': self.scan.status,
                'started_at': self.scan.started_at.isoformat() if self.scan.started_at else None,
                'completed_at': self.scan.completed_at.isoformat() if self.scan.completed_at else None,
                'duration_seconds': self.scan.duration,
                'scan_config': json.loads(self.scan.scan_config) if self.scan.scan_config else None
            },
            'statistics': self.report_data['statistics'],
            'executive_summary': self.report_data['executive_summary'],
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
                    'evidence': json.loads(v.evidence) if v.evidence else None,
                    'false_positive': v.false_positive,
                    'created_at': v.created_at.isoformat(),
                    'tool_source': next((tr.tool_name for tr in self.tool_results if tr.id == v.tool_result_id), None)
                }
                for v in self.vulnerabilities  # Include all vulnerabilities, not just active ones
            ],
            'tool_results': [
                {
                    'tool_name': tr.tool_name,
                    'status': tr.status,
                    'started_at': tr.started_at.isoformat() if tr.started_at else None,
                    'completed_at': tr.completed_at.isoformat() if tr.completed_at else None,
                    'duration_seconds': tr.duration,
                    'error_message': tr.error_message,
                    'raw_output': json.loads(tr.raw_output) if tr.raw_output else None
                }
                for tr in self.tool_results
            ]
        }
        
        # Save JSON file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(report_json, temp_file, indent=2, default=str)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _generate_csv_report(self) -> Tuple[str, int]:
        """Generate CSV report with vulnerability data"""
        import csv
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='')
        
        fieldnames = [
            'vulnerability_id', 'scan_id', 'scan_name', 'target_url',
            'vuln_type', 'severity', 'title', 'description',
            'affected_url', 'affected_parameter', 'cve_id', 'cvss_score',
            'remediation', 'false_positive', 'tool_source', 'created_at'
        ]
        
        writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for vuln in self.vulnerabilities:
            tool_source = next(
                (tr.tool_name for tr in self.tool_results if tr.id == vuln.tool_result_id), 
                'unknown'
            )
            
            writer.writerow({
                'vulnerability_id': vuln.id,
                'scan_id': self.scan.id,
                'scan_name': self.scan.scan_name,
                'target_url': self.scan.target_url,
                'vuln_type': vuln.vuln_type,
                'severity': vuln.severity,
                'title': vuln.title,
                'description': vuln.description or '',
                'affected_url': vuln.affected_url or '',
                'affected_parameter': vuln.affected_parameter or '',
                'cve_id': vuln.cve_id or '',
                'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else '',
                'remediation': vuln.remediation or '',
                'false_positive': vuln.false_positive,
                'tool_source': tool_source,
                'created_at': vuln.created_at.isoformat()
            })
        
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _generate_xml_report(self) -> Tuple[str, int]:
        """Generate XML report"""
        import xml.etree.ElementTree as ET
        
        # Create root element
        root = ET.Element('security_report')
        root.set('version', '1.0')
        root.set('generated_at', self.report_data['generated_at'].isoformat())
        
        # Scan information
        scan_elem = ET.SubElement(root, 'scan_information')
        scan_fields = {
            'id': str(self.scan.id),
            'name': self.scan.scan_name,
            'target_url': self.scan.target_url,
            'scan_type': self.scan.scan_type,
            'status': self.scan.status,
            'started_at': self.scan.started_at.isoformat() if self.scan.started_at else '',
            'completed_at': self.scan.completed_at.isoformat() if self.scan.completed_at else '',
            'duration_seconds': str(self.scan.duration) if self.scan.duration else ''
        }
        
        for field, value in scan_fields.items():
            elem = ET.SubElement(scan_elem, field)
            elem.text = value
        
        # Statistics
        stats_elem = ET.SubElement(root, 'statistics')
        for key, value in self.report_data['statistics'].items():
            if isinstance(value, dict):
                sub_elem = ET.SubElement(stats_elem, key)
                for sub_key, sub_value in value.items():
                    sub_sub_elem = ET.SubElement(sub_elem, sub_key)
                    sub_sub_elem.text = str(sub_value)
            else:
                elem = ET.SubElement(stats_elem, key)
                elem.text = str(value)
        
        # Executive summary
        summary_elem = ET.SubElement(root, 'executive_summary')
        summary_elem.text = self.report_data['executive_summary']
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'vulnerabilities')
        for vuln in self.vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
            vuln_elem.set('id', str(vuln.id))
            vuln_elem.set('severity', vuln.severity)
            vuln_elem.set('false_positive', str(vuln.false_positive))
            
            # Vulnerability fields
            vuln_fields = {
                'vuln_type': vuln.vuln_type,
                'title': vuln.title,
                'description': vuln.description or '',
                'affected_url': vuln.affected_url or '',
                'affected_parameter': vuln.affected_parameter or '',
                'cve_id': vuln.cve_id or '',
                'cvss_score': str(vuln.cvss_score) if vuln.cvss_score else '',
                'remediation': vuln.remediation or '',
                'created_at': vuln.created_at.isoformat()
            }
            
            for field, value in vuln_fields.items():
                elem = ET.SubElement(vuln_elem, field)
                elem.text = value
        
        # Tool results
        tools_elem = ET.SubElement(root, 'tool_results')
        for tool in self.tool_results:
            tool_elem = ET.SubElement(tools_elem, 'tool_result')
            tool_elem.set('name', tool.tool_name)
            tool_elem.set('status', tool.status)
            
            if tool.duration:
                duration_elem = ET.SubElement(tool_elem, 'duration_seconds')
                duration_elem.text = str(tool.duration)
            
            if tool.error_message:
                error_elem = ET.SubElement(tool_elem, 'error_message')
                error_elem.text = tool.error_message
        
        # Save XML file
        temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.xml')
        
        tree = ET.ElementTree(root)
        tree.write(temp_file, encoding='utf-8', xml_declaration=True)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size


class BulkReportGenerator:
    """Generate reports for multiple scans"""
    
    def __init__(self, scans: List[Scan]):
        self.scans = scans
        self.total_vulns = sum(len(scan.vulnerabilities) for scan in scans)
    
    def generate_consolidated_report(self, format_type: str = 'pdf') -> Tuple[str, int]:
        """Generate consolidated report for multiple scans"""
        if format_type == 'pdf':
            return self._generate_consolidated_pdf()
        elif format_type == 'html':
            return self._generate_consolidated_html()
        elif format_type == 'json':
            return self._generate_consolidated_json()
        else:
            raise ValueError(f"Unsupported bulk report format: {format_type}")
    
    def _generate_consolidated_json(self) -> Tuple[str, int]:
        """Generate consolidated JSON report for multiple scans"""
        consolidated_data = {
            'metadata': {
                'report_type': 'consolidated_json',
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'scans_included': len(self.scans),
                'total_vulnerabilities': self.total_vulns
            },
            'scans': []
        }
        
        for scan in self.scans:
            generator = ReportGenerator(scan, 'json')
            scan_data = {
                'scan_info': generator.report_data['scan_info'],
                'statistics': generator.report_data['statistics'],
                'vulnerabilities': [
                    {
                        'vuln_type': v.vuln_type,
                        'severity': v.severity,
                        'title': v.title,
                        'affected_url': v.affected_url,
                        'cve_id': v.cve_id,
                        'false_positive': v.false_positive
                    }
                    for v in scan.vulnerabilities
                ]
            }
            consolidated_data['scans'].append(scan_data)
        
        # Save consolidated JSON
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(consolidated_data, temp_file, indent=2, default=str)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size


# Utility functions
def generate_scan_report(scan_id: int, report_type: str = 'pdf') -> Optional[Tuple[str, int]]:
    """
    Convenience function to generate a report for a scan
    
    Args:
        scan_id: Database ID of the scan
        report_type: Type of report to generate
    
    Returns:
        Tuple of (file_path, file_size) or None if error
    """
    from app.models import Scan
    from app import db
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        logger.error(f"Scan {scan_id} not found")
        return None
    
    try:
        generator = ReportGenerator(scan, report_type)
        return generator.generate()
    except Exception as e:
        logger.error(f"Report generation failed for scan {scan_id}: {str(e)}")
        return None


def get_available_report_formats() -> List[Dict[str, str]]:
    """Get list of available report formats with descriptions"""
    formats = [
        {
            'value': 'html',
            'name': 'HTML Report',
            'description': 'Interactive web-based report',
            'icon': 'fas fa-globe'
        },
        {
            'value': 'json',
            'name': 'JSON Data',
            'description': 'Machine-readable structured data',
            'icon': 'fas fa-code'
        },
        {
            'value': 'csv',
            'name': 'CSV Export',
            'description': 'Spreadsheet-compatible vulnerability list',
            'icon': 'fas fa-table'
        },
        {
            'value': 'xml',
            'name': 'XML Report',
            'description': 'Structured XML format',
            'icon': 'fas fa-file-code'
        }
    ]
    
    # Add PDF if ReportLab is available
    try:
        import reportlab
        formats.insert(0, {
            'value': 'pdf',
            'name': 'PDF Report',
            'description': 'Professional printable report',
            'icon': 'fas fa-file-pdf'
        })
    except ImportError:
        pass
    
    return formats


def cleanup_old_reports(days_old: int = 30) -> Dict[str, int]:
    """
    Clean up old report files from the filesystem
    
    Args:
        days_old: Delete reports older than this many days
    
    Returns:
        Dictionary with cleanup statistics
    """
    from app.models import Report
    from datetime import timedelta
    import sqlalchemy as sa
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
    
    cleanup_stats = {
        'reports_processed': 0,
        'files_deleted': 0,
        'space_freed_bytes': 0,
        'errors': 0
    }
    
    try:
        # Find old reports
        old_reports = list(db.session.scalars(
            sa.select(Report)
            .where(Report.generated_at < cutoff_date)
        ))
        
        for report in old_reports:
            cleanup_stats['reports_processed'] += 1
            
            if report.file_path and os.path.exists(report.file_path):
                try:
                    file_size = os.path.getsize(report.file_path)
                    os.remove(report.file_path)
                    cleanup_stats['files_deleted'] += 1
                    cleanup_stats['space_freed_bytes'] += file_size
                    
                    # Clear file path from database
                    report.file_path = None
                    
                except OSError as e:
                    logger.warning(f"Failed to delete report file {report.file_path}: {e}")
                    cleanup_stats['errors'] += 1
        
        db.session.commit()
        
        logger.info(f"Report cleanup completed: {cleanup_stats}")
        return cleanup_stats
        
    except Exception as e:
        logger.error(f"Report cleanup failed: {str(e)}")
        cleanup_stats['errors'] += 1
        return cleanup_stats


class ReportTemplate:
    """Base class for report templates"""
    
    def __init__(self, scan: Scan):
        self.scan = scan
        self.vulnerabilities = list(scan.vulnerabilities)
        self.active_vulnerabilities = [v for v in self.vulnerabilities if not v.false_positive]
    
    def get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'critical': '#dc2626',
            'high': '#f59e0b',
            'medium': '#3b82f6',
            'low': '#6b7280',
            'info': '#9ca3af'
        }
        return colors.get(severity.lower(), '#6b7280')
    
    def format_cvss_score(self, score) -> str:
        """Format CVSS score for display"""
        if not score:
            return 'N/A'
        
        score_float = float(score)
        if score_float >= 9.0:
            return f"{score_float:.1f} (Critical)"
        elif score_float >= 7.0:
            return f"{score_float:.1f} (High)"
        elif score_float >= 4.0:
            return f"{score_float:.1f} (Medium)"
        else:
            return f"{score_float:.1f} (Low)"


class ExecutiveReportGenerator(ReportTemplate):
    """Generate executive-level summary reports"""
    
    def generate_executive_pdf(self) -> Tuple[str, int]:
        """Generate executive summary PDF (1-2 pages)"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.enums import TA_CENTER
        except ImportError:
            raise ImportError("ReportLab library required for PDF generation")
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_executive.pdf')
        temp_file.close()
        
        doc = SimpleDocTemplate(temp_file.name, pagesize=A4, topMargin=72)
        styles = getSampleStyleSheet()
        
        story = []
        
        # Executive title
        title_style = ParagraphStyle(
            'ExecutiveTitle',
            parent=styles['Title'],
            fontSize=20,
            textColor=HexColor('#1f2937'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        story.append(Paragraph("Executive Security Assessment Summary", title_style))
        
        # Key metrics table
        stats = self._calculate_exec_statistics()
        
        metrics_data = [
            ['Metric', 'Value'],
            ['Target Assessed', self._get_target_hostname()],
            ['Assessment Date', self.scan.completed_at.strftime('%B %d, %Y') if self.scan.completed_at else 'N/A'],
            ['Security Score', f"{stats['security_score']}/100"],
            ['Critical Issues', str(stats['critical_count'])],
            ['High Priority Issues', str(stats['high_count'])],
            ['Total Findings', str(stats['total_findings'])]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2.5*inch, 2.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1f2937')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 30))
        
        # Risk assessment
        story.append(Paragraph("Risk Assessment", styles['Heading2']))
        story.append(Paragraph(self._generate_risk_assessment(), styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Key recommendations
        story.append(Paragraph("Priority Recommendations", styles['Heading2']))
        recommendations = self._generate_executive_recommendations()
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
        
        doc.build(story)
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _calculate_exec_statistics(self) -> Dict:
        """Calculate executive-level statistics"""
        return {
            'security_score': max(0, 100 - sum(
                len(self.vuln_by_severity.get(sev, [])) * weight 
                for sev, weight in [('critical', 15), ('high', 10), ('medium', 5), ('low', 2), ('info', 1)]
            )),
            'critical_count': len(self.vuln_by_severity.get('critical', [])),
            'high_count': len(self.vuln_by_severity.get('high', [])),
            'total_findings': len(self.active_vulnerabilities)
        }
    
    def _generate_risk_assessment(self) -> str:
        """Generate executive risk assessment"""
        stats = self._calculate_exec_statistics()
        
        if stats['critical_count'] > 0:
            return (
                f"The assessment identified {stats['critical_count']} critical security vulnerabilities "
                f"that pose immediate risk to the organization. These issues could potentially "
                f"lead to data breaches, system compromise, or service disruption if exploited."
            )
        elif stats['high_count'] > 0:
            return (
                f"The assessment found {stats['high_count']} high-priority security issues "
                f"that should be addressed promptly to maintain security posture."
            )
        elif stats['total_findings'] > 0:
            return (
                f"The assessment identified {stats['total_findings']} security findings "
                f"of medium to low priority that should be addressed as part of regular "
                f"security maintenance."
            )
        else:
            return (
                "The assessment found no significant security vulnerabilities in the tested "
                "components, indicating strong security controls are in place."
            )
    
    def _generate_executive_recommendations(self) -> List[str]:
        """Generate executive-level recommendations"""
        stats = self._calculate_exec_statistics()
        recommendations = []
        
        if stats['critical_count'] > 0:
            recommendations.append(
                "Immediately patch or mitigate all critical vulnerabilities within 24-48 hours"
            )
            recommendations.append(
                "Implement emergency incident response procedures and monitor for exploitation attempts"
            )
        
        if stats['high_count'] > 0:
            recommendations.append(
                "Schedule remediation of high-priority vulnerabilities within 1-2 weeks"
            )
        
        # General recommendations
        recommendations.extend([
            "Establish regular security scanning as part of the development lifecycle",
            "Implement security awareness training for development and operations teams",
            "Consider penetration testing by third-party security professionals",
            "Develop and test incident response procedures for security events"
        ])
        
        return recommendations[:5]  # Limit to top 5 for executive summary


# Report scheduling and automation
class ReportScheduler:
    """Schedule and manage automated report generation"""
    
    @staticmethod
    def schedule_daily_reports():
        """Schedule daily vulnerability summary reports"""
        from app.tasks import generate_report
        from app.models import Scan
        from datetime import timedelta
        import sqlalchemy as sa
        
        # Get scans completed in the last 24 hours
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        
        recent_scans = list(db.session.scalars(
            sa.select(Scan)
            .where(Scan.completed_at >= yesterday)
            .where(Scan.status == 'completed')
        ))
        
        for scan in recent_scans:
            # Queue report generation
            generate_report.delay(scan.id, 'html')
    
    @staticmethod
    def schedule_weekly_executive_summary():
        """Generate weekly executive summary for all users"""
        from app.models import User
        import sqlalchemy as sa
        
        users_with_scans = list(db.session.scalars(
            sa.select(User)
            .join(Scan)
            .where(Scan.completed_at >= datetime.now(timezone.utc) - timedelta(days=7))
            .distinct()
        ))
        
        for user in users_with_scans:
            # Generate weekly summary report
            # This would queue a task to generate consolidated weekly reports
            pass


# Example usage and testing
if __name__ == '__main__':
    # Test report generation
    from app import create_app, db
    from app.models import Scan
    
    app = create_app()
    
    with app.app_context():
        # Get a test scan
        scan = db.session.get(Scan, 1)
        
        if scan:
            try:
                # Test HTML report
                generator = ReportGenerator(scan, 'html')
                file_path, file_size = generator.generate()
                print(f"Generated HTML report: {file_path} ({file_size} bytes)")
                
                # Test JSON report
                generator = ReportGenerator(scan, 'json')
                file_path, file_size = generator.generate()
                print(f"Generated JSON report: {file_path} ({file_size} bytes)")
                
                # Test PDF report (if ReportLab available)
                try:
                    generator = ReportGenerator(scan, 'pdf')
                    file_path, file_size = generator.generate()
                    print(f"Generated PDF report: {file_path} ({file_size} bytes)")
                except ImportError:
                    print("PDF generation requires ReportLab library")
                
            except Exception as e:
                print(f"Report generation test failed: {str(e)}")
        else:
            print("No test scan found. Create a scan first.")
            '# app/utils/report_generator.py'
"""
Report generation utilities for PentestSaaS
Generates professional security scan reports in various formats
"""

import os
import json
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
import logging

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.platypus import PageBreak, Image, KeepTogether
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
except ImportError:
    # ReportLab not available - PDF generation will be disabled
    pass

from app.models import Scan, Vulnerability, ToolResult, User


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate security scan reports in various formats
    """
    
    def __init__(self, scan: Scan, report_type: str = 'pdf'):
        self.scan = scan
        self.report_type = report_type.lower()
        self.vulnerabilities = list(scan.vulnerabilities)
        self.tool_results = list(scan.tool_results)
        self.user = scan.user
        
        # Filter out false positives for reports
        self.active_vulnerabilities = [v for v in self.vulnerabilities if not v.false_positive]
        
        # Group vulnerabilities by severity
        self.vuln_by_severity = self._group_vulnerabilities_by_severity()
        
        # Report metadata
        self.report_data = {
            'generated_at': datetime.now(timezone.utc),
            'scan_info': {
                'id': scan.id,
                'name': scan.scan_name,
                'target': scan.target_url,
                'type': scan.scan_type,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at,
                'duration': scan.duration
            },
            'statistics': self._calculate_statistics(),
            'executive_summary': self._generate_executive_summary()
        }
    
    def generate(self) -> Tuple[str, int]:
        """
        Generate report and return file path and size
        
        Returns:
            Tuple of (file_path, file_size_bytes)
        """
        if self.report_type == 'pdf':
            return self._generate_pdf_report()
        elif self.report_type == 'html':
            return self._generate_html_report()
        elif self.report_type == 'json':
            return self._generate_json_report()
        elif self.report_type == 'csv':
            return self._generate_csv_report()
        elif self.report_type == 'xml':
            return self._generate_xml_report()
        else:
            raise ValueError(f"Unsupported report type: {self.report_type}")
    
    def _group_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group active vulnerabilities by severity level"""
        groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for vuln in self.active_vulnerabilities:
            severity = vuln.severity.lower()
            if severity in groups:
                groups[severity].append(vuln)
        
        return groups
    
    def _calculate_statistics(self) -> Dict:
        """Calculate scan statistics for reporting"""
        total_vulns = len(self.active_vulnerabilities)
        
        severity_counts = {}
        vuln_type_counts = {}
        
        for vuln in self.active_vulnerabilities:
            # Count by severity
            severity = vuln.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln.vuln_type
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
        
        # Calculate security score (0-100)
        score = max(0, 100 - (
            severity_counts.get('critical', 0) * 15 +
            severity_counts.get('high', 0) * 10 +
            severity_counts.get('medium', 0) * 5 +
            severity_counts.get('low', 0) * 2 +
            severity_counts.get('info', 0) * 1
        ))
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_counts,
            'vulnerability_types': vuln_type_counts,
            'security_score': score,
            'tools_used': len(self.tool_results),
            'false_positives': len([v for v in self.vulnerabilities if v.false_positive])
        }
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary text"""
        stats = self._calculate_statistics()
        target_host = self._get_target_hostname()
        
        summary_parts = []
        
        # Opening
        summary_parts.append(
            f"A comprehensive security assessment was conducted on {target_host} "
            f"on {self.scan.completed_at.strftime('%B %d, %Y') if self.scan.completed_at else 'recently'}."
        )
        
        # Overall findings
        total_vulns = stats['total_vulnerabilities']
        if total_vulns == 0:
            summary_parts.append(
                "The assessment found no significant security vulnerabilities, "
                "indicating a strong security posture for the tested components."
            )
        else:
            critical_high = stats['severity_distribution'].get('critical', 0) + stats['severity_distribution'].get('high', 0)
            
            if critical_high > 0:
                summary_parts.append(
                    f"The assessment identified {total_vulns} security vulnerabilities, "
                    f"including {critical_high} high or critical severity issues that require immediate attention."
                )
            else:
                summary_parts.append(
                    f"The assessment identified {total_vulns} security vulnerabilities "
                    f"of medium to low severity that should be addressed as part of regular security maintenance."
                )
        
        # Security score
        score = stats['security_score']
        if score >= 90:
            score_assessment = "excellent security posture"
        elif score >= 75:
            score_assessment = "good security posture with minor improvements needed"
        elif score >= 60:
            score_assessment = "moderate security posture requiring attention"
        else:
            score_assessment = "security posture requiring significant improvements"
        
        summary_parts.append(f"The target demonstrates {score_assessment} with a security score of {score}/100.")
        
        # Tools used
        tools_used = [tr.tool_name.upper() for tr in self.tool_results if tr.status == 'completed']
        if tools_used:
            summary_parts.append(f"This assessment utilized {', '.join(tools_used)} for comprehensive coverage.")
        
        return ' '.join(summary_parts)
    
    def _get_target_hostname(self) -> str:
        """Extract clean hostname from target URL"""
        try:
            if self.scan.target_url.startswith(('http://', 'https://')):
                return urlparse(self.scan.target_url).netloc
            return self.scan.target_url
        except:
            return self.scan.target_url
    
    def _generate_pdf_report(self) -> Tuple[str, int]:
        """Generate comprehensive PDF report using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.platypus import PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            raise ImportError("ReportLab library required for PDF generation. Run: pip install reportlab")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            temp_file.name,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1f2937'),
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#dc2626'),
            keepWithNext=True
        )
        
        # Build document content
        story = []
        
        # Title page
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Report header table
        header_data = [
            ['Target:', self.scan.target_url],
            ['Scan Type:', self.scan.scan_type.title()],
            ['Generated:', self.report_data['generated_at'].strftime('%B %d, %Y at %I:%M %p UTC')],
            ['Scan Duration:', f"{self.scan.duration / 60:.1f} minutes" if self.scan.duration else "Unknown"],
            ['Security Score:', f"{self.report_data['statistics']['security_score']}/100"]
        ]
        
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(header_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(self.report_data['executive_summary'], styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Vulnerability Summary
        story.append(Paragraph("Vulnerability Summary", heading_style))
        
        if self.active_vulnerabilities:
            # Severity breakdown table
            severity_data = [['Severity', 'Count', 'Description']]
            severity_colors = {
                'critical': HexColor('#dc2626'),
                'high': HexColor('#f59e0b'),
                'medium': HexColor('#3b82f6'),
                'low': HexColor('#6b7280'),
                'info': HexColor('#9ca3af')
            }
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = len(self.vuln_by_severity[severity])
                if count > 0:
                    descriptions = {
                        'critical': 'Immediate action required',
                        'high': 'Should be addressed promptly',
                        'medium': 'Should be addressed in next cycle',
                        'low': 'Address when convenient',
                        'info': 'Informational findings'
                    }
                    severity_data.append([severity.title(), str(count), descriptions[severity]])
            
            if len(severity_data) > 1:  # Has data beyond header
                severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1f2937')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
                    ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
                ]))
                
                story.append(severity_table)
                story.append(Spacer(1, 20))
        else:
            story.append(Paragraph("No security vulnerabilities were identified during this assessment.", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Detailed Findings
        if self.active_vulnerabilities:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerability Findings", heading_style))
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                vulns = self.vuln_by_severity[severity]
                if not vulns:
                    continue
                
                # Severity section header
                section_title = f"{severity.title()} Severity Vulnerabilities ({len(vulns)})"
                story.append(Paragraph(section_title, styles['Heading3']))
                story.append(Spacer(1, 10))
                
                # Vulnerability details
                for i, vuln in enumerate(vulns, 1):
                    vuln_content = []
                    
                    # Vulnerability title
                    vuln_title = f"{i}. {vuln.title}"
                    if vuln.cve_id:
                        vuln_title += f" ({vuln.cve_id})"
                    
                    vuln_content.append(Paragraph(vuln_title, styles['Heading4']))
                    
                    # Description
                    if vuln.description:
                        vuln_content.append(Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal']))
                    
                    # Technical details
                    details = []
                    if vuln.affected_url:
                        details.append(f"<b>Affected URL:</b> {vuln.affected_url}")
                    if vuln.affected_parameter:
                        details.append(f"<b>Parameter:</b> {vuln.affected_parameter}")
                    if vuln.cvss_score:
                        details.append(f"<b>CVSS Score:</b> {vuln.cvss_score}")
                    
                    if details:
                        vuln_content.append(Paragraph("<br/>".join(details), styles['Normal']))
                    
                    # Remediation
                    if vuln.remediation:
                        vuln_content.append(Paragraph(f"<b>Remediation:</b> {vuln.remediation}", styles['Normal']))
                    
                    # Group vulnerability content
                    story.append(KeepTogether(vuln_content))
                    story.append(Spacer(1, 15))
        
        # Tool Results Summary
        story.append(PageBreak())
        story.append(Paragraph("Tool Execution Summary", heading_style))
        
        if self.tool_results:
            tool_data = [['Tool', 'Status', 'Duration', 'Findings']]
            
            for tool in self.tool_results:
                duration = f"{tool.duration / 60:.1f}m" if tool.duration else "N/A"
                vuln_count = len([v for v in self.active_vulnerabilities if v.tool_result_id == tool.id])
                
                tool_data.append([
                    tool.tool_name.upper(),
                    tool.status.title(),
                    duration,
                    str(vuln_count)
                ])
            
            tool_table = Table(tool_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            tool_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1f2937')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ]))
            
            story.append(tool_table)
        
        # Build PDF
        doc.build(story)
        
        # Get file size
        file_size = os.path.getsize(temp_file.name)
        
        return temp_file.name, file_size
    
    def _generate_html_report(self) -> Tuple[str, int]:
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {self.scan.scan_name}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background: #f8fafc;
                }}
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 2rem;
                }}
                .report-header {{
                    background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
                    color: white;
                    padding: 2rem;
                    border-radius: 12px;
                    margin-bottom: 2rem;
                }}
                .report-title {{
                    font-size: 2.5rem;
                    margin: 0 0 1rem 0;
                    text-align: center;
                }}
                .report-meta {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 1rem;
                    background: rgba(255, 255, 255, 0.1);
                    padding: 1rem;
                    border-radius: 8px;
                }}
                .meta-item {{
                    text-align: center;
                }}
                .meta-label {{
                    display: block;
                    font-size: 0.9rem;
                    opacity: 0.8;
                }}
                .meta-value {{
                    display: block;
                    font-size: 1.2rem;
                    font-weight: 600;
                }}
                .section {{
                    background: white;
                    padding: 2rem;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    margin-bottom: 2rem;
                }}
                .section h2 {{
                    color: #1f2937;
                    border-bottom: 2px solid #dc2626;
                    padding-bottom: 0.5rem;
                    margin-bottom: 1.5rem;
                }}
                .vulnerability-card {{
                    border: 1px solid #e2e8f0;
                    border-radius: 8px;
                    padding: 1rem;
                    margin-bottom: 1rem;
                    border-left: 4px solid #dc2626;
                }}
                .vulnerability-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 1rem;
                }}
                .vulnerability-title {{
                    font-size: 1.2rem;
                    font-weight: 600;
                    color: #1f2937;
                    margin: 0;
                }}
                .severity-badge {{
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    font-size: 0.8rem;
                    font-weight: 600;
                    text-transform: uppercase;
                }}
                .severity-critical {{ background: #fef2f2; color: #991b1b; }}
                .severity-high {{ background: #fffbeb; color: #92400e; }}
                .severity-medium {{ background: #eff6ff; color: #1e40af; }}
                .severity-low {{ background: #f3f4f6; color: #4b5563; }}
                .severity-info {{ background: #f9fafb; color: #6b7280; }}
                .vuln-details {{
                    margin-top: 1rem;
                }}
                .vuln-detail-item {{
                    margin-bottom: 0.5rem;
                }}
                .security-score {{
                    text-align: center;
                    padding: 2rem;
                    background: linear-gradient(135deg, #059669 0%, #10b981 100%);
                    color: white;
                    border-radius: 12px;
                    margin: 2rem 0;
                }}
                .score-value {{
                    font-size: 4rem;
                    font-weight: 700;
                    margin: 0;
                }}
                .score-label {{
                    font-size: 1.2rem;
                    opacity: 0.9;
                }}
                @media print {{
                    body {{ background: white; }}
                    .container {{ padding: 1rem; }}
                    .section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="report-header">
                    <h1 class="report-title">Security Assessment Report</h1>
                    <div class="report-meta">
                        <div class="meta-item">
                            <span class="meta-label">Target</span>
                            <span class="meta-value">{self._get_target_hostname()}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Scan Type</span>
                            <span class="meta-value">{self.scan.scan_type.title()}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Vulnerabilities</span>
                            <span class="meta-value">{len(self.active_vulnerabilities)}</span>
                        </div>
                        <div class="meta-item">
                            <span class="meta-label">Security Score</span>
                            <span class="meta-value">{self.report_data['statistics']['security_score']}/100</span>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Executive Summary</h2>
                    <p>{self.report_data['executive_summary']}</p>
                </div>
                
                {"".join(self._generate_html_vulnerability_sections())}
                
                <div class="section">
                    <h2>Recommendations</h2>
                    {self._generate_html_recommendations()}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save HTML file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html')
        temp_file.write(html_content)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _generate_html_vulnerability_sections(self) -> List[str]:
        """Generate HTML sections for vulnerabilities by severity"""
        sections = []
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = self.vuln_by_severity[severity]
            if not vulns:
                continue
            
            section_html = f"""
            <div class="section">
                <h2>{severity.title()} Severity Vulnerabilities ({len(vulns)})</h2>
                {"".join(self._generate_html_vulnerability_card(vuln) for vuln in vulns)}
            </div>
            """
            sections.append(section_html)
        
        return sections
    
    def _generate_html_vulnerability_card(self, vuln: Vulnerability) -> str:
        """Generate HTML for individual vulnerability"""
        return f"""
        <div class="vulnerability-card">
            <div class="vulnerability-header">
                <h3 class="vulnerability-title">{vuln.title}</h3>
                <span class="severity-badge severity-{vuln.severity.lower()}">{vuln.severity}</span>
            </div>
            
            {f'<p><strong>Description:</strong> {vuln.description}</p>' if vuln.description else ''}
            
            <div class="vuln-details">
                {f'<div class="vuln-detail-item"><strong>Affected URL:</strong> <code>{vuln.affected_url}</code></div>' if vuln.affected_url else ''}
                {f'<div class="vuln-detail-item"><strong>Parameter:</strong> <code>{vuln.affected_parameter}</code></div>' if vuln.affected_parameter else ''}
                {f'<div class="vuln-detail-item"><strong>CVE ID:</strong> {vuln.cve_id}</div>' if vuln.cve_id else ''}
                {f'<div class="vuln-detail-item"><strong>CVSS Score:</strong> {vuln.cvss_score}/10</div>' if vuln.cvss_score else ''}
                {f'<div class="vuln-detail-item"><strong>Remediation:</strong> {vuln.remediation}</div>' if vuln.remediation else ''}
            </div>
        </div>
        """
    
    def _generate_html_recommendations(self) -> str:
        """Generate HTML recommendations section"""
        stats = self.report_data['statistics']
        recommendations = []
        
        # Priority recommendations based on findings
        if stats['severity_distribution'].get('critical', 0) > 0:
            recommendations.append("🔴 <strong>CRITICAL:</strong> Address critical vulnerabilities immediately to prevent potential system compromise.")
        
        if stats['severity_distribution'].get('high', 0) > 0:
            recommendations.append("🟠 <strong>HIGH PRIORITY:</strong> Schedule high-severity vulnerability remediation within the next sprint.")
        
        # General recommendations
        recommendations.extend([
            "🔄 <strong>Regular Scanning:</strong> Implement regular security scanning as part of your development cycle.",
            "📚 <strong>Security Training:</strong> Ensure development teams receive security awareness training.",
            "🛡️ <strong>Defense in Depth:</strong> Implement multiple layers of security controls.",
            "📊 <strong>Monitoring:</strong> Set up continuous security monitoring and alerting."
        ])
        
        return "<ul>" + "".join(f"<li>{rec}</li>" for rec in recommendations) + "</ul>"
    
    def _generate_json_report(self) -> Tuple[str, int]:
        """Generate JSON report with complete data"""
        report_json = {
            'metadata': {
                'report_type': 'json',
                'generated_at': self.report_data['generated_at'].isoformat(),
                'generator': 'PentestSaaS Report Generator v1.0'
            },
            'scan': {
                'id': self.scan.id,
                'name': self.scan.scan_name,
                'target_url': self.scan.target_url,
                'target_ip': self.scan.target_ip,
                'scan_type': self.scan.scan_type,
                'status': self.scan.status,
                'started_at': self.scan.started_at.isoformat() if self.scan.started_at else None,
                'completed_at': self.scan.completed_at.isoformat() if self.scan.completed_at else None,
                'duration_seconds': self.scan.duration,
                'scan_config': json.loads(self.scan.scan_config) if self.scan.scan_config else None
            },
            'statistics': self.report_data['statistics'],
            'executive_summary': self.report_data['executive_summary'],
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
                    'evidence': json.loads(v.evidence) if v.evidence else None,
                    'false_positive': v.false_positive,
                    'created_at': v.created_at.isoformat(),
                    'tool_source': next((tr.tool_name for tr in self.tool_results if tr.id == v.tool_result_id), None)
                }
                for v in self.vulnerabilities  # Include all vulnerabilities, not just active ones
            ],
            'tool_results': [
                {
                    'tool_name': tr.tool_name,
                    'status': tr.status,
                    'started_at': tr.started_at.isoformat() if tr.started_at else None,
                    'completed_at': tr.completed_at.isoformat() if tr.completed_at else None,
                    'duration_seconds': tr.duration,
                    'error_message': tr.error_message,
                    'raw_output': json.loads(tr.raw_output) if tr.raw_output else None
                }
                for tr in self.tool_results
            ]
        }
        
        # Save JSON file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(report_json, temp_file, indent=2, default=str)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _generate_csv_report(self) -> Tuple[str, int]:
        """Generate CSV report with vulnerability data"""
        import csv
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='')
        
        fieldnames = [
            'vulnerability_id', 'scan_id', 'scan_name', 'target_url',
            'vuln_type', 'severity', 'title', 'description',
            'affected_url', 'affected_parameter', 'cve_id', 'cvss_score',
            'remediation', 'false_positive', 'tool_source', 'created_at'
        ]
        
        writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for vuln in self.vulnerabilities:
            tool_source = next(
                (tr.tool_name for tr in self.tool_results if tr.id == vuln.tool_result_id), 
                'unknown'
            )
            
            writer.writerow({
                'vulnerability_id': vuln.id,
                'scan_id': self.scan.id,
                'scan_name': self.scan.scan_name,
                'target_url': self.scan.target_url,
                'vuln_type': vuln.vuln_type,
                'severity': vuln.severity,
                'title': vuln.title,
                'description': vuln.description or '',
                'affected_url': vuln.affected_url or '',
                'affected_parameter': vuln.affected_parameter or '',
                'cve_id': vuln.cve_id or '',
                'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else '',
                'remediation': vuln.remediation or '',
                'false_positive': vuln.false_positive,
                'tool_source': tool_source,
                'created_at': vuln.created_at.isoformat()
            })
        
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _generate_xml_report(self) -> Tuple[str, int]:
        """Generate XML report"""
        import xml.etree.ElementTree as ET
        
        # Create root element
        root = ET.Element('security_report')
        root.set('version', '1.0')
        root.set('generated_at', self.report_data['generated_at'].isoformat())
        
        # Scan information
        scan_elem = ET.SubElement(root, 'scan_information')
        scan_fields = {
            'id': str(self.scan.id),
            'name': self.scan.scan_name,
            'target_url': self.scan.target_url,
            'scan_type': self.scan.scan_type,
            'status': self.scan.status,
            'started_at': self.scan.started_at.isoformat() if self.scan.started_at else '',
            'completed_at': self.scan.completed_at.isoformat() if self.scan.completed_at else '',
            'duration_seconds': str(self.scan.duration) if self.scan.duration else ''
        }
        
        for field, value in scan_fields.items():
            elem = ET.SubElement(scan_elem, field)
            elem.text = value
        
        # Statistics
        stats_elem = ET.SubElement(root, 'statistics')
        for key, value in self.report_data['statistics'].items():
            if isinstance(value, dict):
                sub_elem = ET.SubElement(stats_elem, key)
                for sub_key, sub_value in value.items():
                    sub_sub_elem = ET.SubElement(sub_elem, sub_key)
                    sub_sub_elem.text = str(sub_value)
            else:
                elem = ET.SubElement(stats_elem, key)
                elem.text = str(value)
        
        # Executive summary
        summary_elem = ET.SubElement(root, 'executive_summary')
        summary_elem.text = self.report_data['executive_summary']
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'vulnerabilities')
        for vuln in self.vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
            vuln_elem.set('id', str(vuln.id))
            vuln_elem.set('severity', vuln.severity)
            vuln_elem.set('false_positive', str(vuln.false_positive))
            
            # Vulnerability fields
            vuln_fields = {
                'vuln_type': vuln.vuln_type,
                'title': vuln.title,
                'description': vuln.description or '',
                'affected_url': vuln.affected_url or '',
                'affected_parameter': vuln.affected_parameter or '',
                'cve_id': vuln.cve_id or '',
                'cvss_score': str(vuln.cvss_score) if vuln.cvss_score else '',
                'remediation': vuln.remediation or '',
                'created_at': vuln.created_at.isoformat()
            }
            
            for field, value in vuln_fields.items():
                elem = ET.SubElement(vuln_elem, field)
                elem.text = value
        
        # Tool results
        tools_elem = ET.SubElement(root, 'tool_results')
        for tool in self.tool_results:
            tool_elem = ET.SubElement(tools_elem, 'tool_result')
            tool_elem.set('name', tool.tool_name)
            tool_elem.set('status', tool.status)
            
            if tool.duration:
                duration_elem = ET.SubElement(tool_elem, 'duration_seconds')
                duration_elem.text = str(tool.duration)
            
            if tool.error_message:
                error_elem = ET.SubElement(tool_elem, 'error_message')
                error_elem.text = tool.error_message
        
        # Save XML file
        temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.xml')
        
        tree = ET.ElementTree(root)
        tree.write(temp_file, encoding='utf-8', xml_declaration=True)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size


class BulkReportGenerator:
    """Generate reports for multiple scans"""
    
    def __init__(self, scans: List[Scan]):
        self.scans = scans
        self.total_vulns = sum(len(scan.vulnerabilities) for scan in scans)
    
    def generate_consolidated_report(self, format_type: str = 'pdf') -> Tuple[str, int]:
        """Generate consolidated report for multiple scans"""
        if format_type == 'pdf':
            return self._generate_consolidated_pdf()
        elif format_type == 'html':
            return self._generate_consolidated_html()
        elif format_type == 'json':
            return self._generate_consolidated_json()
        else:
            raise ValueError(f"Unsupported bulk report format: {format_type}")
    
    def _generate_consolidated_json(self) -> Tuple[str, int]:
        """Generate consolidated JSON report for multiple scans"""
        consolidated_data = {
            'metadata': {
                'report_type': 'consolidated_json',
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'scans_included': len(self.scans),
                'total_vulnerabilities': self.total_vulns
            },
            'scans': []
        }
        
        for scan in self.scans:
            generator = ReportGenerator(scan, 'json')
            scan_data = {
                'scan_info': generator.report_data['scan_info'],
                'statistics': generator.report_data['statistics'],
                'vulnerabilities': [
                    {
                        'vuln_type': v.vuln_type,
                        'severity': v.severity,
                        'title': v.title,
                        'affected_url': v.affected_url,
                        'cve_id': v.cve_id,
                        'false_positive': v.false_positive
                    }
                    for v in scan.vulnerabilities
                ]
            }
            consolidated_data['scans'].append(scan_data)
        
        # Save consolidated JSON
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(consolidated_data, temp_file, indent=2, default=str)
        temp_file.close()
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size


# Utility functions
def generate_scan_report(scan_id: int, report_type: str = 'pdf') -> Optional[Tuple[str, int]]:
    """
    Convenience function to generate a report for a scan
    
    Args:
        scan_id: Database ID of the scan
        report_type: Type of report to generate
    
    Returns:
        Tuple of (file_path, file_size) or None if error
    """
    from app.models import Scan
    from app import db
    
    scan = db.session.get(Scan, scan_id)
    if not scan:
        logger.error(f"Scan {scan_id} not found")
        return None
    
    try:
        generator = ReportGenerator(scan, report_type)
        return generator.generate()
    except Exception as e:
        logger.error(f"Report generation failed for scan {scan_id}: {str(e)}")
        return None


def get_available_report_formats() -> List[Dict[str, str]]:
    """Get list of available report formats with descriptions"""
    formats = [
        {
            'value': 'html',
            'name': 'HTML Report',
            'description': 'Interactive web-based report',
            'icon': 'fas fa-globe'
        },
        {
            'value': 'json',
            'name': 'JSON Data',
            'description': 'Machine-readable structured data',
            'icon': 'fas fa-code'
        },
        {
            'value': 'csv',
            'name': 'CSV Export',
            'description': 'Spreadsheet-compatible vulnerability list',
            'icon': 'fas fa-table'
        },
        {
            'value': 'xml',
            'name': 'XML Report',
            'description': 'Structured XML format',
            'icon': 'fas fa-file-code'
        }
    ]
    
    # Add PDF if ReportLab is available
    try:
        import reportlab
        formats.insert(0, {
            'value': 'pdf',
            'name': 'PDF Report',
            'description': 'Professional printable report',
            'icon': 'fas fa-file-pdf'
        })
    except ImportError:
        pass
    
    return formats


def cleanup_old_reports(days_old: int = 30) -> Dict[str, int]:
    """
    Clean up old report files from the filesystem
    
    Args:
        days_old: Delete reports older than this many days
    
    Returns:
        Dictionary with cleanup statistics
    """
    from app.models import Report
    from datetime import timedelta
    import sqlalchemy as sa
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
    
    cleanup_stats = {
        'reports_processed': 0,
        'files_deleted': 0,
        'space_freed_bytes': 0,
        'errors': 0
    }
    
    try:
        # Find old reports
        old_reports = list(db.session.scalars(
            sa.select(Report)
            .where(Report.generated_at < cutoff_date)
        ))
        
        for report in old_reports:
            cleanup_stats['reports_processed'] += 1
            
            if report.file_path and os.path.exists(report.file_path):
                try:
                    file_size = os.path.getsize(report.file_path)
                    os.remove(report.file_path)
                    cleanup_stats['files_deleted'] += 1
                    cleanup_stats['space_freed_bytes'] += file_size
                    
                    # Clear file path from database
                    report.file_path = None
                    
                except OSError as e:
                    logger.warning(f"Failed to delete report file {report.file_path}: {e}")
                    cleanup_stats['errors'] += 1
        
        db.session.commit()
        
        logger.info(f"Report cleanup completed: {cleanup_stats}")
        return cleanup_stats
        
    except Exception as e:
        logger.error(f"Report cleanup failed: {str(e)}")
        cleanup_stats['errors'] += 1
        return cleanup_stats


class ReportTemplate:
    """Base class for report templates"""
    
    def __init__(self, scan: Scan):
        self.scan = scan
        self.vulnerabilities = list(scan.vulnerabilities)
        self.active_vulnerabilities = [v for v in self.vulnerabilities if not v.false_positive]
    
    def get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'critical': '#dc2626',
            'high': '#f59e0b',
            'medium': '#3b82f6',
            'low': '#6b7280',
            'info': '#9ca3af'
        }
        return colors.get(severity.lower(), '#6b7280')
    
    def format_cvss_score(self, score) -> str:
        """Format CVSS score for display"""
        if not score:
            return 'N/A'
        
        score_float = float(score)
        if score_float >= 9.0:
            return f"{score_float:.1f} (Critical)"
        elif score_float >= 7.0:
            return f"{score_float:.1f} (High)"
        elif score_float >= 4.0:
            return f"{score_float:.1f} (Medium)"
        else:
            return f"{score_float:.1f} (Low)"


class ExecutiveReportGenerator(ReportTemplate):
    """Generate executive-level summary reports"""
    
    def generate_executive_pdf(self) -> Tuple[str, int]:
        """Generate executive summary PDF (1-2 pages)"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.enums import TA_CENTER
        except ImportError:
            raise ImportError("ReportLab library required for PDF generation")
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_executive.pdf')
        temp_file.close()
        
        doc = SimpleDocTemplate(temp_file.name, pagesize=A4, topMargin=72)
        styles = getSampleStyleSheet()
        
        story = []
        
        # Executive title
        title_style = ParagraphStyle(
            'ExecutiveTitle',
            parent=styles['Title'],
            fontSize=20,
            textColor=HexColor('#1f2937'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        story.append(Paragraph("Executive Security Assessment Summary", title_style))
        
        # Key metrics table
        stats = self._calculate_exec_statistics()
        
        metrics_data = [
            ['Metric', 'Value'],
            ['Target Assessed', self._get_target_hostname()],
            ['Assessment Date', self.scan.completed_at.strftime('%B %d, %Y') if self.scan.completed_at else 'N/A'],
            ['Security Score', f"{stats['security_score']}/100"],
            ['Critical Issues', str(stats['critical_count'])],
            ['High Priority Issues', str(stats['high_count'])],
            ['Total Findings', str(stats['total_findings'])]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2.5*inch, 2.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1f2937')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 30))
        
        # Risk assessment
        story.append(Paragraph("Risk Assessment", styles['Heading2']))
        story.append(Paragraph(self._generate_risk_assessment(), styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Key recommendations
        story.append(Paragraph("Priority Recommendations", styles['Heading2']))
        recommendations = self._generate_executive_recommendations()
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
        
        doc.build(story)
        
        file_size = os.path.getsize(temp_file.name)
        return temp_file.name, file_size
    
    def _calculate_exec_statistics(self) -> Dict:
        """Calculate executive-level statistics"""
        return {
            'security_score': max(0, 100 - sum(
                len(self.vuln_by_severity.get(sev, [])) * weight 
                for sev, weight in [('critical', 15), ('high', 10), ('medium', 5), ('low', 2), ('info', 1)]
            )),
            'critical_count': len(self.vuln_by_severity.get('critical', [])),
            'high_count': len(self.vuln_by_severity.get('high', [])),
            'total_findings': len(self.active_vulnerabilities)
        }
    
    def _generate_risk_assessment(self) -> str:
        """Generate executive risk assessment"""
        stats = self._calculate_exec_statistics()
        
        if stats['critical_count'] > 0:
            return (
                f"The assessment identified {stats['critical_count']} critical security vulnerabilities "
                f"that pose immediate risk to the organization. These issues could potentially "
                f"lead to data breaches, system compromise, or service disruption if exploited."
            )
        elif stats['high_count'] > 0:
            return (
                f"The assessment found {stats['high_count']} high-priority security issues "
                f"that should be addressed promptly to maintain security posture."
            )
        elif stats['total_findings'] > 0:
            return (
                f"The assessment identified {stats['total_findings']} security findings "
                f"of medium to low priority that should be addressed as part of regular "
                f"security maintenance."
            )
        else:
            return (
                "The assessment found no significant security vulnerabilities in the tested "
                "components, indicating strong security controls are in place."
            )
    
    def _generate_executive_recommendations(self) -> List[str]:
        """Generate executive-level recommendations"""
        stats = self._calculate_exec_statistics()
        recommendations = []
        
        if stats['critical_count'] > 0:
            recommendations.append(
                "Immediately patch or mitigate all critical vulnerabilities within 24-48 hours"
            )
            recommendations.append(
                "Implement emergency incident response procedures and monitor for exploitation attempts"
            )
        
        if stats['high_count'] > 0:
            recommendations.append(
                "Schedule remediation of high-priority vulnerabilities within 1-2 weeks"
            )
        
        # General recommendations
        recommendations.extend([
            "Establish regular security scanning as part of the development lifecycle",
            "Implement security awareness training for development and operations teams",
            "Consider penetration testing by third-party security professionals",
            "Develop and test incident response procedures for security events"
        ])
        
        return recommendations[:5]  # Limit to top 5 for executive summary


# Report scheduling and automation
class ReportScheduler:
    """Schedule and manage automated report generation"""
    
    @staticmethod
    def schedule_daily_reports():
        """Schedule daily vulnerability summary reports"""
        from app.tasks import generate_report
        from app.models import Scan
        from datetime import timedelta
        import sqlalchemy as sa
        
        # Get scans completed in the last 24 hours
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        
        recent_scans = list(db.session.scalars(
            sa.select(Scan)
            .where(Scan.completed_at >= yesterday)
            .where(Scan.status == 'completed')
        ))
        
        for scan in recent_scans:
            # Queue report generation
            generate_report.delay(scan.id, 'html')
    
    @staticmethod
    def schedule_weekly_executive_summary():
        """Generate weekly executive summary for all users"""
        from app.models import User
        import sqlalchemy as sa
        
        users_with_scans = list(db.session.scalars(
            sa.select(User)
            .join(Scan)
            .where(Scan.completed_at >= datetime.now(timezone.utc) - timedelta(days=7))
            .distinct()
        ))
        
        for user in users_with_scans:
            # Generate weekly summary report
            # This would queue a task to generate consolidated weekly reports
            pass


# Example usage and testing
if __name__ == '__main__':
    # Test report generation
    from app import create_app, db
    from app.models import Scan
    
    app = create_app()
    
    with app.app_context():
        # Get a test scan
        scan = db.session.get(Scan, 1)
        
        if scan:
            try:
                # Test HTML report
                generator = ReportGenerator(scan, 'html')
                file_path, file_size = generator.generate()
                print(f"Generated HTML report: {file_path} ({file_size} bytes)")
                
                # Test JSON report
                generator = ReportGenerator(scan, 'json')
                file_path, file_size = generator.generate()
                print(f"Generated JSON report: {file_path} ({file_size} bytes)")
                
                # Test PDF report (if ReportLab available)
                try:
                    generator = ReportGenerator(scan, 'pdf')
                    file_path, file_size = generator.generate()
                    print(f"Generated PDF report: {file_path} ({file_size} bytes)")
                except ImportError:
                    print("PDF generation requires ReportLab library")
                
            except Exception as e:
                print(f"Report generation test failed: {str(e)}")
        else:
            print("No test scan found. Create a scan first.")
            '# app/utils/report_generator.py
"""
Report generation utilities for PentestSaaS
Generates professional security scan reports in various formats
"""

import os
import json
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
import logging

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.platypus import PageBreak, Image, KeepTogether
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
except ImportError:
    # ReportLab not available - PDF generation will be disabled
    pass

from app.models import Scan, Vulnerability, ToolResult, User


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate security scan reports in various formats
    """
    
    def __init__(self, scan: Scan, report_type: str = 'pdf'):
        self.scan = scan
        self.report_type = report_type.lower()
        self.vulnerabilities = list(scan.vulnerabilities)
        self.tool_results = list(scan.tool_results)
        self.user = scan.user
        
        # Filter out false positives for reports
        self.active_vulnerabilities = [v for v in self.vulnerabilities if not v.false_positive]
        
        # Group vulnerabilities by severity
        self.vuln_by_severity = self._group_vulnerabilities_by_severity()
        
        # Report metadata
        self.report_data = {
            'generated_at': datetime.now(timezone.utc),
            'scan_info': {
                'id': scan.id,
                'name': scan.scan_name,
                'target': scan.target_url,
                'type': scan.scan_type,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at,
                'duration': scan.duration
            },
            'statistics': self._calculate_statistics(),
            'executive_summary': self._generate_executive_summary()
        }
    
    def generate(self) -> Tuple[str, int]:
        """
        Generate report and return file path and size
        
        Returns:
            Tuple of (file_path, file_size_bytes)
        """
        if self.report_type == 'pdf':
            return self._generate_pdf_report()
        elif self.report_type == 'html':
            return self._generate_html_report()
        elif self.report_type == 'json':
            return self._generate_json_report()
        elif self.report_type == 'csv':
            return self._generate_csv_report()
        elif self.report_type == 'xml':
            return self._generate_xml_report()
        else:
            raise ValueError(f"Unsupported report type: {self.report_type}")
    
    def _group_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group active vulnerabilities by severity level"""
        groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for vuln in self.active_vulnerabilities:
            severity = vuln.severity.lower()
            if severity in groups:
                groups[severity].append(vuln)
        
        return groups
    
    def _calculate_statistics(self) -> Dict:
        """Calculate scan statistics for reporting"""
        total_vulns = len(self.active_vulnerabilities)
        
        severity_counts = {}
        vuln_type_counts = {}
        
        for vuln in self.active_vulnerabilities:
            # Count by severity
            severity = vuln.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln.vuln_type
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
        
        # Calculate security score (0-100)
        score = max(0, 100 - (
            severity_counts.get('critical', 0) * 15 +
            severity_counts.get('high', 0) * 10 +
            severity_counts.get('medium', 0) * 5 +
            severity_counts.get('low', 0) * 2 +
            severity_counts.get('info', 0) * 1
        ))
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_counts,
            'vulnerability_types': vuln_type_counts,
            'security_score': score,
            'tools_used': len(self.tool_results),
            'false_positives': len([v for v in self.vulnerabilities if v.false_positive])
        }
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary text"""
        stats = self._calculate_statistics()
        target_host = self._get_target_hostname()
        
        summary_parts = []
        
        # Opening
        summary_parts.append(
            f"A comprehensive security assessment was conducted on {target_host} "
            f"on {self.scan.completed_at.strftime('%B %d, %Y') if self.scan.completed_at else 'recently'}."
        )
        
        # Overall findings
        total_vulns = stats['total_vulnerabilities']
        if total_vulns == 0:
            summary_parts.append(
                "The assessment found no significant security vulnerabilities, "
                "indicating a strong security posture for the tested components."
            )
        else:
            critical_high = stats['severity_distribution'].get('critical', 0) + stats['severity_distribution'].get('high', 0)
            
            if critical_high > 0:
                summary_parts.append(
                    f"The assessment identified {total_vulns} security vulnerabilities, "
                    f"including {critical_high} high or critical severity issues that require immediate attention."
                )
            else:
                summary_parts.append(
                    f"The assessment identified {total_vulns} security vulnerabilities "
                    f"of medium to low severity that should be addressed as part of regular security maintenance."
                )
        
        # Security score
        score = stats['security_score']
        if score >= 90:
            score_assessment = "excellent security posture"
        elif score >= 75:
            score_assessment = "good security posture with minor improvements needed"
        elif score >= 60:
            score_assessment = "moderate security posture requiring attention"
        else:
            score_assessment = "security posture requiring significant improvements"
        
        summary_parts.append(f"The target demonstrates {score_assessment} with a security score of {score}/100.")
        
        # Tools used
        tools_used = [tr.tool_name.upper() for tr in self.tool_results if tr.status == 'completed']
        if tools_used:
            summary_parts.append(f"This assessment utilized {', '.join(tools_used)} for comprehensive coverage.")
        
        return ' '.join(summary_parts)
    
    def _get_target_hostname(self) -> str:
        """Extract clean hostname from target URL"""
        try:
            if self.scan.target_url.startswith(('http://', 'https://')):
                return urlparse(self.scan.target_url).netloc
            return self.scan.target_url
        except:
            return self.scan.target_url
    
    def _generate_pdf_report(self) -> Tuple[str, int]:
        """Generate comprehensive PDF report using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.platypus import PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            raise ImportError("ReportLab library required for PDF generation. Run: pip install reportlab")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            temp_file.name,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1f2937'),
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#dc2626'),
            keepWithNext=True
        )
        
        # Build document content
        story = []
        
        # Title page
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Report header table
        header_data = [
            ['Target:', self.scan.target_url],
            ['Scan Type:', self.scan.scan_type.title()],
            ['Generated:', self.report_data['generated_at'].strftime('%B %d, %Y at %I:%M %p UTC')],
            ['Scan Duration:', f"{self.scan.duration / 60:.1f} minutes" if self.scan.duration else "Unknown"],
            ['Security Score:', f"{self.report_data['statistics']['security_score']}/100"]
        ]
        
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(header_table)
        
        