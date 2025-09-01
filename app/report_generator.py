# app/report_generator.py
import json
from datetime import datetime
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)


class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2563eb')
        )
        
    async def generate_pdf_report(self, results: Dict[str, Any], output_path: str):
        """Generate PDF report from scan results"""
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Title
        title = Paragraph("SecureScan Pro - Security Assessment Report", self.title_style)
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        summary_data = [
            ["Target", results.get("target", "N/A")],
            ["Scan Type", results.get("scan_type", "N/A").title()],
            ["Timestamp", results.get("timestamp", "N/A")],
            ["Duration", f"{results.get('duration_seconds', 0):.2f} seconds"],
            ["Total Issues", str(results.get("summary", {}).get("total_issues", 0))]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Severity Summary
        story.append(Paragraph("Issue Severity Breakdown", self.styles['Heading2']))
        summary = results.get("summary", {})
        severity_data = [
            ["Severity", "Count", "Description"],
            ["Critical", str(summary.get("critical", 0)), "Immediate action required"],
            ["High", str(summary.get("high", 0)), "Should be addressed soon"],
            ["Medium", str(summary.get("medium", 0)), "Address when possible"],
            ["Low", str(summary.get("low", 0)), "Informational"]
        ]
        
        severity_table = Table(severity_data)
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (0, 1), colors.red),      # Critical
            ('BACKGROUND', (0, 2), (0, 2), colors.orange),   # High  
            ('BACKGROUND', (0, 3), (0, 3), colors.yellow),   # Medium
            ('BACKGROUND', (0, 4), (0, 4), colors.lightblue), # Low
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        # Port Scan Results
        if results.get("port_scan"):
            story.append(Paragraph("Open Ports", self.styles['Heading2']))
            port_data = [["Port", "Service", "Banner"]]
            for port in results["port_scan"]:
                port_data.append([
                    str(port["port"]),
                    port["service"],
                    port.get("banner", "N/A")[:50] + "..." if port.get("banner") and len(port.get("banner", "")) > 50 else port.get("banner", "N/A")
                ])
            
            port_table = Table(port_data)
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
            story.append(Spacer(1, 20))
        
        # Security Headers
        if results.get("security_headers"):
            story.append(Paragraph("HTTP Security Headers", self.styles['Heading2']))
            header_data = [["Header", "Status", "Severity", "Recommendation"]]
            for header in results["security_headers"]:
                header_data.append([
                    header["header"],
                    header["status"],
                    header["severity"],
                    header["recommendation"][:60] + "..." if len(header["recommendation"]) > 60 else header["recommendation"]
                ])
            
            header_table = Table(header_data, colWidths=[2*inch, 1*inch, 1*inch, 3*inch])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(header_table)
            story.append(Spacer(1, 20))
        
        # TLS Analysis
        if results.get("tls_analysis"):
            story.append(Paragraph("TLS/SSL Analysis", self.styles['Heading2']))
            tls_data = [["Version", "Supported", "Vulnerabilities"]]
            for tls in results["tls_analysis"]:
                vulns = ", ".join(tls["vulnerabilities"]) if tls["vulnerabilities"] else "None"
                tls_data.append([
                    tls["version"],
                    "Yes" if tls["supported"] else "No",
                    vulns[:50] + "..." if len(vulns) > 50 else vulns
                ])
            
            tls_table = Table(tls_data)
            tls_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(tls_table)
            story.append(Spacer(1, 20))
        
        # Vulnerabilities
        if results.get("vulnerabilities"):
            story.append(Paragraph("Identified Vulnerabilities", self.styles['Heading2']))
            vuln_data = [["CVE ID", "Severity", "CVSS Score", "Affected Service", "Description"]]
            for vuln in results["vulnerabilities"]:
                vuln_data.append([
                    vuln["cve_id"],
                    vuln["severity"],
                    str(vuln["score"]),
                    vuln["affected_service"],
                    vuln["description"][:40] + "..." if len(vuln["description"]) > 40 else vuln["description"]
                ])
            
            vuln_table = Table(vuln_data, colWidths=[1.2*inch, 0.8*inch, 0.7*inch, 1.5*inch, 2.8*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", self.styles['Heading2']))
        
        recommendations = []
        
        # Collect recommendations from different sections
        for header in results.get("security_headers", []):
            if header["status"] in ["missing", "weak"]:
                recommendations.append(f"• {header['recommendation']}")
        
        for vuln in results.get("vulnerabilities", []):
            recommendations.append(f"• {vuln['recommendation']}")
        
        if not recommendations:
            recommendations.append("• No specific recommendations identified.")
        
        for rec in recommendations[:10]:  # Limit to top 10
            story.append(Paragraph(rec, self.styles['Normal']))
            story.append(Spacer(1, 6))
        
        # Footer
        story.append(Spacer(1, 30))
        footer = Paragraph(
            f"Report generated by SecureScan Pro on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Normal']
        )
        story.append(footer)
        
        # Build PDF
        doc.build(story)