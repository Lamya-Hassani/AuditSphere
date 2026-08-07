from django.db import models

from accounts.models import User
from inventory.models import Device


class Audit(models.Model):

    STATUS = (
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    )

    target = models.CharField(max_length=100)

    scan_date = models.DateTimeField()

    engine_version = models.CharField(max_length=20)

    scanner_version = models.CharField(max_length=20)

    rules_version = models.CharField(max_length=20)

    scan_type = models.CharField(max_length=100)

    laboratory_security_score = models.IntegerField()

    comparison_data = models.JSONField(default=dict, blank=True, null=True)

    status = models.CharField(
        max_length=20,
        choices=STATUS,
        default="completed"
    )

    executed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Audit #{self.id}"


class AuditDevice(models.Model):

    audit = models.ForeignKey(
        Audit,
        on_delete=models.CASCADE,
        related_name="devices"
    )

    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE
    )

    risk_score = models.IntegerField()

    security_score = models.IntegerField()

    risk_level = models.CharField(max_length=30)

    risk_categories = models.JSONField(default=list)

    score_breakdown = models.JSONField(default=dict)

    def __str__(self):
        return f"{self.audit.id} - {self.device.ip}"


class Finding(models.Model):

    audit_device = models.ForeignKey(
        AuditDevice,
        on_delete=models.CASCADE,
        related_name="findings"
    )

    service = models.CharField(max_length=100)

    port = models.IntegerField()

    product = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )

    version = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )

    severity = models.CharField(max_length=20)

    description = models.TextField()

    recommendation = models.TextField()

    points = models.IntegerField()

    cve_id = models.CharField(max_length=50, blank=True, null=True)

    cvss_score = models.FloatField(blank=True, null=True)

    source = models.CharField(max_length=50, default="rule")

    def __str__(self):
        return f"{self.service} ({self.severity})"

class Recommendation(models.Model):

    audit = models.ForeignKey(
        Audit,
        on_delete=models.CASCADE,
        related_name="recommendations"
    )

    text = models.TextField()

    def __str__(self):
        return self.text
    
class AuditStatistic(models.Model):

    audit = models.OneToOneField(
        Audit,
        on_delete=models.CASCADE,
        related_name="statistics"
    )

    devices = models.IntegerField()

    critical = models.IntegerField()

    high = models.IntegerField()

    medium = models.IntegerField()

    low = models.IntegerField()

    def __str__(self):
        return f"Statistics for Audit {self.audit.id}"

