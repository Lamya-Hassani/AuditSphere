from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "role",
            "is_staff",
            "is_superuser",
            "date_joined",
        ]
        read_only_fields = ["id", "date_joined"]


class UserCreateUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, min_length=6)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "role",
            "password",
            "is_staff",
            "is_superuser",
        ]
        read_only_fields = ["id"]

    def validate_role(self, value):
        request = self.context.get("request")
        # If user is admin (not superuser), they cannot create or promote to admin role
        if request and request.user and not request.user.is_superuser:
            if value == "admin":
                raise serializers.ValidationError(
                    "Only Super Administrators can assign or promote users to Administrator role."
                )
        return value

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        role = validated_data.get("role", "auditor")
        
        # Admin users automatically get is_staff=True
        if role == "admin":
            validated_data["is_staff"] = True
            
        user = User(**validated_data)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        role = validated_data.get("role", instance.role)
        
        if role == "admin":
            validated_data["is_staff"] = True
            
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["username"] = user.username
        token["email"] = user.email
        token["role"] = user.role
        token["is_staff"] = user.is_staff
        token["is_superuser"] = user.is_superuser
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # Ensure is_staff is synchronized for admin role
        if self.user.role == "admin" and not self.user.is_staff:
            self.user.is_staff = True
            self.user.save(update_fields=["is_staff"])

        data["user"] = UserSerializer(self.user).data
        return data
