from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from accounts.models import User


class AuthenticationAuthorizationTestCase(APITestCase):
    def setUp(self):
        # Create Super Admin User
        self.superadmin = User.objects.create_superuser(
            username="superadmin",
            email="superadmin@audit.local",
            password="Password123!",
            role="admin",
        )

        # Create Admin User (role="admin", is_staff=True)
        self.admin = User.objects.create_user(
            username="admin_user",
            email="admin@audit.local",
            password="Password123!",
            role="admin",
            is_staff=True,
        )

        # Create Auditor User (role="auditor", is_staff=False)
        self.auditor = User.objects.create_user(
            username="auditor_user",
            email="auditor@audit.local",
            password="Password123!",
            role="auditor",
            is_staff=False,
        )

    def test_login_jwt_acquisition(self):
        """
        Test POST /api/accounts/login/ returns access token, refresh token, and user payload.
        """
        response = self.client.post(
            "/api/accounts/login/",
            {"username": "admin_user", "password": "Password123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["username"], "admin_user")
        self.assertEqual(response.data["user"]["role"], "admin")

    def test_unauthenticated_request_returns_401(self):
        """
        Protected endpoints return 401 Unauthorized for unauthenticated requests.
        """
        endpoints = [
            "/api/accounts/me/",
            "/api/accounts/users/",
            "/api/audits/",
            "/api/inventory/devices/",
            "/api/dashboard/",
        ]
        for url in endpoints:
            response = self.client.get(url)
            self.assertEqual(
                response.status_code,
                status.HTTP_401_UNAUTHORIZED,
                f"URL {url} did not return 401 for unauthenticated request.",
            )

    def test_auditor_access_to_user_crud_returns_403(self):
        """
        Auditors cannot access User CRUD endpoints (403 Forbidden).
        """
        # Authenticate as Auditor
        login_res = self.client.post(
            "/api/accounts/login/",
            {"username": "auditor_user", "password": "Password123!"},
            format="json",
        )
        token = login_res.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get("/api/accounts/users/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.post(
            "/api/accounts/users/",
            {
                "username": "new_auditor",
                "password": "Password123!",
                "role": "auditor",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_user_crud(self):
        """
        Administrators can list users, view user, create auditor, update auditor, delete auditor.
        """
        login_res = self.client.post(
            "/api/accounts/login/",
            {"username": "admin_user", "password": "Password123!"},
            format="json",
        )
        token = login_res.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        # List Users
        list_res = self.client.get("/api/accounts/users/")
        self.assertEqual(list_res.status_code, status.HTTP_200_OK)

        # Create Auditor
        create_res = self.client.post(
            "/api/accounts/users/",
            {
                "username": "new_auditor_by_admin",
                "email": "newauditor@audit.local",
                "password": "Password123!",
                "role": "auditor",
            },
            format="json",
        )
        self.assertEqual(create_res.status_code, status.HTTP_201_CREATED)
        new_auditor_id = create_res.data["id"]

        # Retrieve Auditor
        get_res = self.client.get(f"/api/accounts/users/{new_auditor_id}/")
        self.assertEqual(get_res.status_code, status.HTTP_200_OK)

        # Update Auditor
        update_res = self.client.put(
            f"/api/accounts/users/{new_auditor_id}/",
            {
                "username": "updated_auditor_by_admin",
                "email": "newauditor@audit.local",
                "role": "auditor",
            },
            format="json",
        )
        self.assertEqual(update_res.status_code, status.HTTP_200_OK)

        # Delete Auditor
        delete_res = self.client.delete(f"/api/accounts/users/{new_auditor_id}/")
        self.assertEqual(delete_res.status_code, status.HTTP_200_OK)

    def test_admin_cannot_promote_to_admin_role(self):
        """
        Administrator cannot create or promote a user to Administrator role.
        """
        login_res = self.client.post(
            "/api/accounts/login/",
            {"username": "admin_user", "password": "Password123!"},
            format="json",
        )
        token = login_res.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        create_res = self.client.post(
            "/api/accounts/users/",
            {
                "username": "unauthorized_admin",
                "email": "unauth@audit.local",
                "password": "Password123!",
                "role": "admin",
            },
            format="json",
        )
        self.assertEqual(create_res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_superadmin_can_create_admin(self):
        """
        Super Administrator can create Administrator users.
        """
        login_res = self.client.post(
            "/api/accounts/login/",
            {"username": "superadmin", "password": "Password123!"},
            format="json",
        )
        token = login_res.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        create_res = self.client.post(
            "/api/accounts/users/",
            {
                "username": "new_admin_by_super",
                "email": "newadmin@audit.local",
                "password": "Password123!",
                "role": "admin",
            },
            format="json",
        )
        self.assertEqual(create_res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(create_res.data["role"], "admin")
        self.assertTrue(create_res.data["is_staff"])

    def test_logout_blacklists_token(self):
        """
        POST /api/accounts/logout/ blacklists the refresh token.
        """
        login_res = self.client.post(
            "/api/accounts/login/",
            {"username": "auditor_user", "password": "Password123!"},
            format="json",
        )
        access_token = login_res.data["access"]
        refresh_token = login_res.data["refresh"]

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        logout_res = self.client.post(
            "/api/accounts/logout/",
            {"refresh": refresh_token},
            format="json",
        )
        self.assertEqual(logout_res.status_code, status.HTTP_200_OK)

        # Attempting to refresh with blacklisted token fails
        refresh_res = self.client.post(
            "/api/accounts/token/refresh/",
            {"refresh": refresh_token},
            format="json",
        )
        self.assertEqual(refresh_res.status_code, status.HTTP_401_UNAUTHORIZED)
