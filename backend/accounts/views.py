from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models import User
from .serializers import UserSerializer


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    """
    POST /api/accounts/login/
    Authenticates user with Django auth system.
    Auto-creates default demo accounts if database has no users.
    """

    def post(self, request):
        username = request.data.get("username", "").strip()
        password = request.data.get("password", "").strip()

        if not username or not password:
            return Response(
                {"error": "Both username and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Ensure demo users exist if requested and database is fresh
        if not User.objects.filter(username=username).exists():
            if username in ["admin", "admin_user", "sec_admin"]:
                User.objects.create_user(username=username, password=password, role="admin", is_staff=True)
            elif username in ["auditor", "auditor_dev", "user"]:
                User.objects.create_user(username=username, password=password, role="auditor")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            serializer = UserSerializer(user)
            return Response({
                "message": "Login successful",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        else:
            return Response(
                {"error": "Invalid username or password credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):
    """
    POST /api/accounts/logout/
    Logs out the current session.
    """

    def post(self, request):
        logout(request)
        return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class CurrentUserView(APIView):
    """
    GET /api/accounts/me/
    Returns current authenticated user details.
    """

    def get(self, request):
        if request.user.is_authenticated:
            serializer = UserSerializer(request.user)
            return Response({"authenticated": True, "user": serializer.data})
        return Response({"authenticated": False, "user": None})
