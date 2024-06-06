from rest_framework import serializers
from .models import Users

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('email', 'username', 'full_name', 'password', 'is_superuser', 'is_active', 'user_type')
        extra_kwargs = {'password': {'write_only': True}}


class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('email', 'username', 'full_name', 'password', 'is_superuser', 'is_active', 'user_type')
        extra_kwargs = {'password': {'write_only': True}}