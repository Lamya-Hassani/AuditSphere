from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    LoginView,
    RefreshTokenEndpointView,
    LogoutView,
    CurrentUserView,
    UserViewSet,
)

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")

urlpatterns = [
    path("login/", LoginView.as_view(), name="account-login"),
    path("token/refresh/", RefreshTokenEndpointView.as_view(), name="account-token-refresh"),
    path("logout/", LogoutView.as_view(), name="account-logout"),
    path("me/", CurrentUserView.as_view(), name="account-me"),
    path("", include(router.urls)),
]
