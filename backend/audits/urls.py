from django.urls import path

from .views import (
    RunAuditView,
    AuditListView,
    AuditDetailView,
    RescanAuditView,
    AuditPDFReportView,
)

urlpatterns = [
    path(
        "scan/",
        RunAuditView.as_view(),
        name="run-audit"
    ),
    path(
        "",
        AuditListView.as_view(),
        name="audit-list"
    ),
    path(
        "<int:pk>/",
        AuditDetailView.as_view(),
        name="audit-detail"
    ),
    path(
        "<int:pk>/rescan/",
        RescanAuditView.as_view(),
        name="audit-rescan"
    ),
    path(
        "<int:pk>/pdf/",
        AuditPDFReportView.as_view(),
        name="audit-pdf"
    ),
]