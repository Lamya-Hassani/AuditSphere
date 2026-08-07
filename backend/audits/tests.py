from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from audits.models import Audit, AuditStatistic, AuditDevice, Finding, Recommendation
from audits.api_client import ScanEngineError
from inventory.models import Device


from accounts.models import User


class AuditEndpointsTestCase(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="testauditor", role="auditor", password="password123")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.audit = Audit.objects.create(
            target="192.168.1.0/24",
            scan_date=timezone.now(),
            engine_version="1.0.0",
            scanner_version="nmap 7.92",
            rules_version="2026.01",
            scan_type="network_scan",
            laboratory_security_score=85,
            status="completed",
        )
        self.statistic = AuditStatistic.objects.create(
            audit=self.audit,
            devices=1,
            critical=0,
            high=1,
            medium=2,
            low=3,
        )
        self.device = Device.objects.create(
            ip="192.168.1.50",
            hostname="test-host",
            status="up"
        )
        self.audit_device = AuditDevice.objects.create(
            audit=self.audit,
            device=self.device,
            risk_score=15,
            security_score=85,
            risk_level="Medium",
            risk_categories=[],
            score_breakdown={}
        )
        self.finding = Finding.objects.create(
            audit_device=self.audit_device,
            service="ssh",
            port=22,
            severity="high",
            description="Weak SSH cipher enabled",
            recommendation="Disable weak ciphers",
            points=15
        )
        self.recommendation = Recommendation.objects.create(
            audit=self.audit,
            text="Upgrade SSH configuration"
        )

    def test_audit_list_view(self):
        response = self.client.get("/api/audits/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["target"], "192.168.1.0/24")

    def test_audit_detail_view_success(self):
        response = self.client.get(f"/api/audits/{self.audit.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], self.audit.id)
        self.assertEqual(response.data["laboratory_security_score"], 85)
        self.assertEqual(len(response.data["devices"]), 1)
        self.assertEqual(len(response.data["recommendations"]), 1)

    def test_audit_detail_view_not_found(self):
        response = self.client.get("/api/audits/999999/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_audit_endpoint(self):
        response = self.client.delete(f"/api/audits/{self.audit.id}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Audit.objects.filter(id=self.audit.id).exists())
        # Ensure device in inventory remains preserved
        self.assertTrue(Device.objects.filter(id=self.device.id).exists())

    @patch("audits.services.run_scan")
    def test_run_audit_success(self, mock_run_scan):
        mock_run_scan.return_value = {
            "target": "10.0.0.1",
            "scan_date": timezone.now().isoformat(),
            "engine_version": "1.0.0",
            "laboratory_security_score": 90,
            "audit_metadata": {
                "scanner": "nmap",
                "rules_version": "1.0",
                "scan_type": "quick_scan"
            },
            "statistics": {
                "devices": 1,
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0
            },
            "recommendations": ["Close unused ports"],
            "devices": [
                {
                    "device": {
                        "ip": "10.0.0.1",
                        "hostname": "gateway",
                        "mac": "00:11:22:33:44:55",
                        "vendor": "Cisco",
                        "os": "Linux",
                        "status": "up",
                        "ports": [
                            {
                                "number": 80,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "product": "nginx",
                                "version": "1.18"
                            }
                        ]
                    },
                    "risk_score": 10,
                    "security_score": 90,
                    "risk_level": "Low",
                    "risk_categories": [],
                    "score_breakdown": {},
                    "findings": [
                        {
                            "service": "http",
                            "port": 80,
                            "product": "nginx",
                            "version": "1.18",
                            "severity": "medium",
                            "description": "HTTP Header Missing",
                            "recommendation": "Add Security Headers",
                            "points": 10
                        }
                    ]
                }
            ]
        }

        response = self.client.post("/api/audits/scan/", {"target": "10.0.0.1"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["target"], "10.0.0.1")

    @patch("audits.services.run_scan")
    def test_rescan_audit_success(self, mock_run_scan):
        mock_run_scan.return_value = {
            "target": "192.168.1.0/24",
            "scan_date": timezone.now().isoformat(),
            "engine_version": "1.0.0",
            "laboratory_security_score": 95,
            "audit_metadata": {
                "scanner": "nmap",
                "rules_version": "1.0",
                "scan_type": "full_scan"
            },
            "statistics": {
                "devices": 1,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "recommendations": [],
            "devices": []
        }

        response = self.client.post(f"/api/audits/{self.audit.id}/rescan/")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["target"], "192.168.1.0/24")
        self.assertEqual(response.data["laboratory_security_score"], 95)

    @patch("audits.services.run_scan")
    def test_run_audit_engine_unreachable(self, mock_run_scan):
        mock_run_scan.side_effect = ScanEngineError("Scan engine unavaliable")

        response = self.client.post("/api/audits/scan/", {"target": "10.0.0.1"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertIn("error", response.data)
