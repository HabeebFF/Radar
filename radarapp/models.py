from django.db import models
from django.contrib.auth.models import AbstractUser
import datetime

# Create your models here.


class Users(AbstractUser):
    user_id = models.AutoField(primary_key=True, null=False)
    username = models.CharField(unique=True, max_length=40, null=False)
    email = models.EmailField(unique=True, null=False)
    full_name = models.CharField(max_length=60, null=False)
    password = models.CharField(max_length=120, null=False)
    user_type = models.CharField(max_length=10)
    is_verified = models.BooleanField(default=False)


class Wallets(models.Model):
    wallet_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    wallet_balance = models.DecimalField(default=5000, null=False, decimal_places=2, max_digits=10)
    wallet_pin = models.CharField(max_length=128)