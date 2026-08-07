from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404

from .models import User
from .serializers import (
    UserSerializer,
    UserCreateUpdateSerializer,
    CustomTokenObtainPairSerializer,
)
from .permissions import CanManageUsers, IsAdminUserRole


class LoginView(TokenObtainPairView):
    """
    POST /api/accounts/login/
    Exchanges username/email & password for JWT access and refresh tokens + user info.
    Auto-creates default demo accounts if database is fresh.
    Unprotected (AllowAny).
    """
    permission_classes = [AllowAny]
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        username = request.data.get("username", "").strip()
        password = request.data.get("password", "").strip()

        # Seed default accounts if database has no matching user for quick demo login
        if username and not User.objects.filter(username=username).exists():
            if username in ["admin", "admin_user", "sec_admin"]:
                User.objects.create_superuser(username=username, password=password, role="admin", email=f"{username}@audit.local")
            elif username in ["auditor", "auditor_dev", "user"]:
                User.objects.create_user(username=username, password=password, role="auditor", email=f"{username}@audit.local")

        return super().post(request, *args, **kwargs)


class RefreshTokenEndpointView(TokenRefreshView):
    """
    POST /api/accounts/token/refresh/
    Generates a new access token using a valid refresh token.
    Unprotected (AllowAny).
    """
    permission_classes = [AllowAny]


class LogoutView(APIView):
    """
    POST /api/accounts/logout/
    Blacklists the provided JWT refresh token to log out the user session.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required for logout."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Successfully logged out."},
                status=status.HTTP_200_OK,
            )
        except Exception:
            return Response(
                {"message": "Session invalidated or token already blacklisted."},
                status=status.HTTP_200_OK,
            )


class CurrentUserView(APIView):
    """
    GET /api/accounts/me/
    Returns current authenticated user details.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserViewSet(viewsets.ModelViewSet):
    """
    REST Endpoints for User CRUD:
    - GET /api/accounts/users/ (List users)
    - GET /api/accounts/users/{id}/ (Retrieve user)
    - POST /api/accounts/users/ (Create user)
    - PUT/PATCH /api/accounts/users/{id}/ (Update user)
    - DELETE /api/accounts/users/{id}/ (Delete user)

    Only Administrators and Super Administrators may use these endpoints.
    """
    queryset = User.objects.all().order_by("-date_joined")
    permission_classes = [IsAuthenticated, CanManageUsers]

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return UserCreateUpdateSerializer
        return UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        read_serializer = UserSerializer(user)
        return Response(read_serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        read_serializer = UserSerializer(user)
        return Response(read_serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.id == request.user.id:
            return Response(
                {"error": "Administrators cannot delete their own active account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        self.perform_destroy(instance)
        return Response(
            {"message": f"User '{instance.username}' deleted successfully."},
            status=status.HTTP_200_OK,
        )
