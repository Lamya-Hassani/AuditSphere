from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone

from inventory.models import Device, Port
from audits.models import Audit, AuditDevice, Finding


from accounts.models import User


class InventoryEndpointsTestCase(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="testadmin", role="admin", password="password123")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        self.device1 = Device.objects.create(
            ip="192.168.1.10",
            hostname="web-server-01",
            vendor="Dell",
            operating_system="Ubuntu 22.04",
            status="up"
        )
        self.port1 = Port.objects.create(
            device=self.device1,
            number=80,
            protocol="tcp",
            state="open",
            service="http",
            product="Apache",
            version="2.4.52"
        )
        self.port2 = Port.objects.create(
            device=self.device1,
            number=443,
            protocol="tcp",
            state="open",
            service="https",
            product="Apache",
            version="2.4.52"
        )

        self.device2 = Device.objects.create(
            ip="192.168.1.20",
            hostname="db-server-01",
            vendor="HP",
            operating_system="Debian 11",
            status="down"
        )

        # Audit finding for device1
        self.audit = Audit.objects.create(
            target="192.168.1.0/24",
            scan_date=timezone.now(),
            engine_version="1.0.0",
            scanner_version="nmap 7.92",
            rules_version="2026.01",
            scan_type="network_scan",
            laboratory_security_score=80,
            status="completed"
        )
        self.audit_device = AuditDevice.objects.create(
            audit=self.audit,
            device=self.device1,
            risk_score=20,
            security_score=80,
            risk_level="Medium",
            risk_categories=[],
            score_breakdown={}
        )
        self.finding = Finding.objects.create(
            audit_device=self.audit_device,
            service="http",
            port=80,
            severity="medium",
            description="Outdated Apache version",
            recommendation="Update Apache to latest version",
            points=20
        )

    def test_device_list_all(self):
        response = self.client.get("/api/inventory/devices/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_device_list_filter_status(self):
        response = self.client.get("/api/inventory/devices/?status=up")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["ip"], "192.168.1.10")

    def test_device_list_search_query(self):
        response = self.client.get("/api/inventory/devices/?search=db-server")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["ip"], "192.168.1.20")

    def test_device_detail_view(self):
        response = self.client.get(f"/api/inventory/devices/{self.device1.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["ip"], "192.168.1.10")
        self.assertEqual(response.data["open_ports_count"], 2)
        self.assertEqual(len(response.data["ports"]), 2)
        self.assertEqual(len(response.data["recent_findings"]), 1)
        self.assertEqual(response.data["latest_risk_level"], "Medium")

    def test_device_delete_view(self):
        response = self.client.delete(f"/api/inventory/devices/{self.device2.id}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Device.objects.filter(id=self.device2.id).exists())
