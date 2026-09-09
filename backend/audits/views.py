from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from accounts.permissions import IsAuditorOrAdmin

from .services import execute_audit
from .serializers import AuditSerializer
from .models import Audit
from .api_client import ScanEngineError


class RunAuditView(APIView):
    permission_classes = [IsAuthenticated, IsAuditorOrAdmin]

    """
    POST /api/audits/scan/
    Triggers a new security scan for the provided target and mode.
    """

    def post(self, request):
        target = request.data.get("target")
        mode = request.data.get("mode", "full")

        if not target:
            return Response(
                {"error": "Target is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            audit = execute_audit(
                target,
                mode=mode,
                user=request.user if request.user.is_authenticated else None
            )
            serializer = AuditSerializer(audit)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ScanEngineError as exc:
            return Response(
                {"error": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as exc:
            return Response(
                {"error": f"An unexpected error occurred during execution: {str(exc)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AuditListView(APIView):
    permission_classes = [IsAuthenticated, IsAuditorOrAdmin]
    """
    GET /api/audits/
    Returns a list of all audits, ordered by most recent scan date.
    """

    def get(self, request):
        audits = (
            Audit.objects.all()
            .select_related("statistics", "executed_by")
            .prefetch_related("devices__findings", "recommendations", "devices__device")
            .order_by("-scan_date")
        )
        serializer = AuditSerializer(audits, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AuditDetailView(APIView):
    permission_classes = [IsAuthenticated, IsAuditorOrAdmin]
    """
    GET /api/audits/<pk>/ - Retrieve audit detail
    DELETE /api/audits/<pk>/ - Delete an audit record and its associated statistics/findings
    """

    def get(self, request, pk):
        audit = get_object_or_404(
            Audit.objects.select_related("statistics", "executed_by")
            .prefetch_related("devices__findings", "recommendations", "devices__device"),
            pk=pk
        )
        serializer = AuditSerializer(audit)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        audit = get_object_or_404(Audit, pk=pk)
        audit.delete()
        return Response(
            {"message": f"Audit #{pk} deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )


class RescanAuditView(APIView):
    permission_classes = [IsAuthenticated, IsAuditorOrAdmin]
    """
    POST /api/audits/<pk>/rescan/
    Re-runs a scan for an existing audit's target.
    """

    def post(self, request, pk):
        existing_audit = get_object_or_404(Audit, pk=pk)
        
        mode = request.data.get("mode")
        if not mode:
            if existing_audit.scan_type == "Host Discovery":
                mode = "discovery"
            elif existing_audit.scan_type == "Port Sweep":
                mode = "ports"
            else:
                mode = "full"

        try:
            new_audit = execute_audit(
                existing_audit.target,
                mode=mode,
                user=request.user if request.user.is_authenticated else None
            )
            serializer = AuditSerializer(new_audit)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ScanEngineError as exc:
            return Response(
                {"error": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as exc:
            return Response(
                {"error": f"An unexpected error occurred during rescan: {str(exc)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


from django.http import FileResponse
import io
from rest_framework.authentication import BaseAuthentication, SessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


class JWTQueryParamAuthentication(BaseAuthentication):
    """
    Authenticates via ?token=<access_token> in the URL.
    Used exclusively for the PDF download endpoint so the browser
    can open the URL directly without a custom Authorization header.
    """
    def authenticate(self, request):
        token = request.query_params.get('token')
        if not token:
            return None
        try:
            validated = JWTAuthentication().get_validated_token(token.encode())
            user = JWTAuthentication().get_user(validated)
            return (user, validated)
        except (InvalidToken, TokenError):
            return None


class AuditPDFReportView(APIView):
    authentication_classes = [JWTQueryParamAuthentication, JWTAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated, IsAuditorOrAdmin]
    """
    GET /api/audits/<pk>/pdf/
    Generates and returns a PDF report for the specified audit.
    """

    def get(self, request, pk):
        audit = get_object_or_404(
            Audit.objects.select_related("statistics", "executed_by")
            .prefetch_related("devices__findings", "recommendations", "devices__device"),
            pk=pk
        )

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Define clean, professional custom styles
        title_style = ParagraphStyle(
            name='ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=15
        )

        section_heading = ParagraphStyle(
            name='SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1e40af'),
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        )

        body_style = ParagraphStyle(
            name='ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )

        body_bold = ParagraphStyle(
            name='ReportBodyBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        code_style = ParagraphStyle(
            name='ReportCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1e293b')
        )

        story = []

        # Document Title
        story.append(Paragraph("AuditSphere — Cybersecurity Audit Report", title_style))
        story.append(Spacer(1, 10))

        # Metadata Table
        meta_data = [
            [Paragraph("Audit ID:", body_bold), Paragraph(f"#{audit.id}", body_style),
             Paragraph("Security Score:", body_bold), Paragraph(f"{audit.laboratory_security_score}/100", body_style)],
            [Paragraph("Target Subnet:", body_bold), Paragraph(audit.target, code_style),
             Paragraph("Scan Date:", body_bold), Paragraph(audit.scan_date.strftime("%Y-%m-%d %H:%M:%S UTC") if audit.scan_date else "N/A", body_style)],
            [Paragraph("Scan Type:", body_bold), Paragraph(audit.scan_type or "Network Scan", body_style),
             Paragraph("Executed By:", body_bold), Paragraph(audit.executed_by.username if audit.executed_by else "System Engine", body_style)],
        ]

        meta_table = Table(meta_data, colWidths=[100, 170, 100, 170])
        meta_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('LINEBELOW', (0,-1), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # Statistics Section
        story.append(Paragraph("Audit Summary Statistics", section_heading))
        stats = audit.statistics if hasattr(audit, 'statistics') else None

        stats_data = [
            ["Total Devices", "Critical", "High Severity", "Medium Severity", "Low Severity"],
            [
                str(stats.devices if stats else 0),
                str(stats.critical if stats else 0),
                str(stats.high if stats else 0),
                str(stats.medium if stats else 0),
                str(stats.low if stats else 0)
            ]
        ]

        stats_table = Table(stats_data, colWidths=[108, 108, 108, 108, 108])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 15))

        # Recommendations Section
        story.append(Paragraph("Remediation Recommendations", section_heading))
        recs = audit.recommendations.all()
        if recs.exists():
            for rec in recs:
                story.append(Paragraph(f"• {rec.text}", body_style))
                story.append(Spacer(1, 3))
        else:
            story.append(Paragraph("No global recommendations generated.", body_style))
        story.append(Spacer(1, 12))

        # Discovered Devices & Findings
        story.append(Paragraph("Discovered Devices & Findings Detail", section_heading))

        for audit_device in audit.devices.all():
            dev = audit_device.device
            dev_mac = dev.mac or 'N/A'
            dev_header = f"Host: {dev.ip} ({dev.hostname or 'Unknown Hostname'})"
            story.append(Paragraph(dev_header, ParagraphStyle('DevHeader', parent=body_bold, fontSize=10, textColor=colors.HexColor('#0f172a'))))
            story.append(Paragraph(f"MAC: {dev_mac} | OS: {dev.operating_system or 'Generic OS'} | Vendor: {dev.vendor or 'Unknown Vendor'} | Risk Level: {audit_device.risk_level} (Score: {audit_device.risk_score} pts)", body_style))
            story.append(Spacer(1, 4))

            findings = audit_device.findings.all()
            if findings.exists():
                findings_data = [
                    ["Service / Port", "Severity", "Description & Vulnerability", "Remediation Directive"]
                ]
                for f in findings:
                    sev_text = f.severity.upper()
                    cve_str = f"<br/><font color='#dc3545'><b>{f.cve_id}</b> (CVSS {f.cvss_score})</font>" if f.cve_id else ""
                    product_ver = f"<br/><i>{f.product or ''} {f.version or ''}</i>".strip()
                    version_info = f"<br/><font color='#475569'>{product_ver}</font>" if (f.product or f.version) else ""
                    service_col = f"<b>{f.service}</b> (Port {f.port}){version_info}{cve_str}"

                    findings_data.append([
                        Paragraph(service_col, code_style),
                        Paragraph(f"{sev_text}<br/>(-{f.points} pts)", ParagraphStyle('SevText', parent=body_bold, fontSize=8, textColor=colors.HexColor('#dc3545') if sev_text == 'CRITICAL' else colors.HexColor('#f97316') if sev_text == 'HIGH' else colors.HexColor('#d97706') if sev_text == 'MEDIUM' else colors.HexColor('#0284c7'))),
                        Paragraph(f.description, body_style),
                        Paragraph(f.recommendation, body_style)
                    ])

                findings_table = Table(findings_data, colWidths=[100, 55, 205, 180])
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,0), 8),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(findings_table)
            else:
                story.append(Paragraph("<i>No security findings identified for this host.</i>", body_style))

            story.append(Spacer(1, 10))

        # Build PDF Document
        doc.build(story)
        buffer.seek(0)

        return FileResponse(buffer, as_attachment=True, filename=f"Audit_Report_{audit.id}.pdf", content_type='application/pdf')