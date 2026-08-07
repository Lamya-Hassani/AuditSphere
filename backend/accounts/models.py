from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    ROLE_CHOICES = (
        ("admin", "Administrator"),
        ("auditor", "Auditor"),
    )

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default="auditor"
    )

    @property
    def is_admin_role(self):
        return self.role == "admin" or self.is_superuser

    @property
    def is_auditor_role(self):
        return self.role == "auditor"

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"