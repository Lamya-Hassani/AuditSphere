from django.db import models


class Device(models.Model):

    STATUS_CHOICES = (
        ("up", "Up"),
        ("down", "Down"),
        ("unknown", "Unknown")
    )

    ip = models.GenericIPAddressField(unique=True)

    hostname = models.CharField(
        max_length=200,
        blank=True,
        null=True
    )

    mac = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )

    vendor = models.CharField(
        max_length=200,
        blank=True,
        null=True
    )

    operating_system = models.CharField(
        max_length=200,
        blank=True,
        null=True
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="unknown"
    )

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip


class Port(models.Model):

    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name="ports"
    )

    number = models.IntegerField()

    protocol = models.CharField(max_length=10)

    state = models.CharField(max_length=20)

    service = models.CharField(max_length=100)

    product = models.CharField(
        max_length=200,
        blank=True,
        null=True
    )

    version = models.CharField(
        max_length=200,
        blank=True,
        null=True
    )

    def __str__(self):
        return f"{self.device.ip}:{self.number}"