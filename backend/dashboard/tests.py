from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone

from audits.models import Audit, AuditStatistic
from inventory.models import Device


from accounts.models import User


class DashboardEndpointsTestCase(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="testauditor", role="auditor", password="password123")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_dashboard_summary_empty_database(self):
        response = self.client.get("/api/dashboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_audits"], 0)
        self.assertEqual(response.data["total_devices"], 0)
        self.assertEqual(response.data["online_devices"], 0)
        self.assertEqual(response.data["average_security_score"], 0.0)
        self.assertIsNone(response.data["latest_security_score"])
        self.assertIsNone(response.data["latest_audit"])
        self.assertEqual(response.data["recent_audits"], [])

    def test_dashboard_summary_populated_database(self):
        device1 = Device.objects.create(ip="10.0.0.1", status="up")
        device2 = Device.objects.create(ip="10.0.0.2", status="down")

        audit1 = Audit.objects.create(
            target="10.0.0.0/24",
            scan_date=timezone.now(),
            engine_version="1.0",
            scanner_version="nmap",
            rules_version="1.0",
            scan_type="network",
            laboratory_security_score=80,
            status="completed"
        )
        AuditStatistic.objects.create(
            audit=audit1,
            devices=2,
            critical=1,
            high=2,
            medium=3,
            low=4
        )

        response = self.client.get("/api/dashboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_audits"], 1)
        self.assertEqual(response.data["total_devices"], 2)
        self.assertEqual(response.data["online_devices"], 1)
        self.assertEqual(response.data["average_security_score"], 80.0)
        self.assertEqual(response.data["latest_security_score"], 80)
        self.assertIsNotNone(response.data["latest_audit"])
        self.assertEqual(response.data["vulnerability_summary"]["critical"], 1)
        self.assertEqual(response.data["vulnerability_summary"]["high"], 2)
        self.assertEqual(response.data["vulnerability_summary"]["total"], 10)
