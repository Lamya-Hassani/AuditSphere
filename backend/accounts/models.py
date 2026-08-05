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