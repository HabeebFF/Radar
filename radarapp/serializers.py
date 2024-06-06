from rest_framework import serializers
from .models import Users

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('full_name', 'email', 'username', 'password', 'is_superuser', 'is_active', 'user_type')
        extra_kwargs = {'password': {'write_only': True}}


class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('full_name', 'email', 'username', 'password', 'is_superuser', 'is_active', 'user_type')
        extra_kwargs = {'password': {'write_only': True}}