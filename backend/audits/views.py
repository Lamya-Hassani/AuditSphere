from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

from .services import execute_audit
from .serializers import AuditSerializer
from .models import Audit
from .api_client import ScanEngineError


class RunAuditView(APIView):
    """
    POST /api/audits/scan/
    Triggers a new security scan for the provided target.
    """

    def post(self, request):
        target = request.data.get("target")

        if not target:
            return Response(
                {"error": "Target is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            audit = execute_audit(
                target,
                request.user if request.user.is_authenticated else None
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
    """
    POST /api/audits/<pk>/rescan/
    Re-runs a scan for an existing audit's target.
    """

    def post(self, request, pk):
        existing_audit = get_object_or_404(Audit, pk=pk)

        try:
            new_audit = execute_audit(
                existing_audit.target,
                request.user if request.user.is_authenticated else None
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