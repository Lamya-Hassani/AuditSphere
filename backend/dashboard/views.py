from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Avg, Sum

from audits.models import Audit, AuditStatistic
from audits.serializers import AuditSerializer
from inventory.models import Device
from .serializers import DashboardSummarySerializer


class DashboardSummaryView(APIView):
    """
    GET /api/dashboard/
    Returns high-level aggregated metrics and recent activity for the security dashboard.
    """

    def get(self, request):
        total_audits = Audit.objects.count()
        total_devices = Device.objects.count()
        online_devices = Device.objects.filter(status="up").count()

        avg_score_data = Audit.objects.filter(status="completed").aggregate(
            avg_score=Avg("laboratory_security_score")
        )
        avg_score = round(avg_score_data["avg_score"] or 0, 1)

        latest_audit_obj = (
            Audit.objects.filter(status="completed")
            .select_related("statistics")
            .order_by("-scan_date")
            .first()
        )

        if latest_audit_obj:
            latest_audit_data = {
                "id": latest_audit_obj.id,
                "target": latest_audit_obj.target,
                "scan_date": latest_audit_obj.scan_date,
                "scan_type": latest_audit_obj.scan_type,
                "laboratory_security_score": latest_audit_obj.laboratory_security_score,
                "status": latest_audit_obj.status,
            }
            latest_security_score = latest_audit_obj.laboratory_security_score

            # Vulnerability summary from latest audit stats
            if hasattr(latest_audit_obj, "statistics") and latest_audit_obj.statistics:
                stats = latest_audit_obj.statistics
                vuln_summary = {
                    "critical": stats.critical,
                    "high": stats.high,
                    "medium": stats.medium,
                    "low": stats.low,
                    "total": stats.critical + stats.high + stats.medium + stats.low,
                }
            else:
                vuln_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        else:
            latest_audit_data = None
            latest_security_score = None
            # Aggregated summary across all AuditStatistics if any exist
            aggregated = AuditStatistic.objects.aggregate(
                crit=Sum("critical"),
                h=Sum("high"),
                m=Sum("medium"),
                l=Sum("low")
            )
            c = aggregated["crit"] or 0
            h = aggregated["h"] or 0
            m = aggregated["m"] or 0
            l = aggregated["l"] or 0
            vuln_summary = {
                "critical": c,
                "high": h,
                "medium": m,
                "low": l,
                "total": c + h + m + l,
            }

        recent_audits_qs = Audit.objects.all().order_by("-scan_date")[:5]
        recent_audits_data = [
            {
                "id": a.id,
                "target": a.target,
                "scan_date": a.scan_date,
                "laboratory_security_score": a.laboratory_security_score,
                "status": a.status,
            }
            for a in recent_audits_qs
        ]

        payload = {
            "total_audits": total_audits,
            "total_devices": total_devices,
            "online_devices": online_devices,
            "average_security_score": avg_score,
            "latest_security_score": latest_security_score,
            "vulnerability_summary": vuln_summary,
            "latest_audit": latest_audit_data,
            "recent_audits": recent_audits_data,
        }

        serializer = DashboardSummarySerializer(payload)
        return Response(serializer.data, status=status.HTTP_200_OK)
