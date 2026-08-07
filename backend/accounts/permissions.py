from rest_framework.permissions import BasePermission


class IsSuperUser(BasePermission):
    """
    Allows access only to Super Administrators (is_superuser=True).
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)


class IsAdminUserRole(BasePermission):
    """
    Allows access to Administrators (role='admin' or is_superuser=True).
    """
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and (request.user.role == "admin" or request.user.is_superuser)
        )


class IsAuditorOrAdmin(BasePermission):
    """
    Allows access to Auditors, Administrators, and Super Administrators.
    """
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and (request.user.role in ["auditor", "admin"] or request.user.is_superuser)
        )


class CanManageUsers(BasePermission):
    """
    Permission for User CRUD endpoints.
    - Only Administrators (role='admin') and Super Administrators (is_superuser=True) may access.
    - Auditors are completely blocked (403 Forbidden).
    - Administrators can manage Auditor accounts.
    - Only Super Administrators can manage Administrator accounts or grant admin privileges.
    """
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        return request.user.role == "admin" or request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Superuser can manage any user object
        if request.user.is_superuser:
            return True
        
        # Admins can manage auditor objects, but NOT other admin/superuser objects
        if request.user.role == "admin":
            if obj.is_superuser or obj.role == "admin":
                # An admin editing themselves for basic profile is okay, but managing other admins is prohibited
                return obj.id == request.user.id
            return obj.role == "auditor"
        
        return False
